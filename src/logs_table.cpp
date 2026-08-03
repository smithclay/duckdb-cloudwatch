#include "logs_table.hpp"

#include "cloudwatch_client.hpp"
#include "cloudwatch_json.hpp"
#include "cloudwatch_secret.hpp"

#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/timestamp.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

#include <cerrno>
#include <cstdlib>
#include <deque>
#include <limits>

namespace duckdb {

void ValidateCloudwatchLogsSettings(const CloudwatchLogsSettings &settings, const string &error_prefix) {
	if (settings.order != "asc" && settings.order != "desc") {
		throw InvalidInputException("%s: order must be either 'asc' or 'desc'", error_prefix);
	}
	if (settings.page_size < 1 || settings.page_size > 10000) {
		throw InvalidInputException("%s: page_size must be between 1 and 10000", error_prefix);
	}
	if (settings.max_rows < 0) {
		throw InvalidInputException("%s: max_rows must be >= 0 (0 means unlimited)", error_prefix);
	}
	if (settings.retries < 0 || settings.retries > 100) {
		throw InvalidInputException("%s: retries must be between 0 and 100", error_prefix);
	}
	if (settings.timeout_seconds < 1) {
		throw InvalidInputException("%s: timeout must be >= 1 second", error_prefix);
	}

	auto endpoint = settings.endpoint;
	StringUtil::Trim(endpoint);
	auto scheme = endpoint.find("://");
	auto lower_endpoint = StringUtil::Lower(endpoint);
	if (scheme != string::npos && !StringUtil::StartsWith(lower_endpoint, "http://") &&
	    !StringUtil::StartsWith(lower_endpoint, "https://")) {
		throw InvalidInputException("%s: endpoint scheme must be HTTP or HTTPS", error_prefix);
	}
	auto authority_start = scheme == string::npos ? 0 : scheme + 3;
	while (endpoint.size() > authority_start && endpoint.back() == '/') {
		endpoint.pop_back();
	}
	lower_endpoint = StringUtil::Lower(endpoint);
	if (!endpoint.empty() && authority_start == endpoint.size()) {
		throw InvalidInputException("%s: endpoint must include a host", error_prefix);
	}
	if (endpoint.find_first_of("/?#", authority_start) != string::npos) {
		throw InvalidInputException("%s: endpoint must be an origin without a path, query, or fragment", error_prefix);
	}
	if (StringUtil::StartsWith(lower_endpoint, "http://")) {
		auto authority = lower_endpoint.substr(authority_start);
		if (authority != "localhost" && !StringUtil::StartsWith(authority, "localhost:") && authority != "127.0.0.1" &&
		    !StringUtil::StartsWith(authority, "127.0.0.1:") && authority != "[::1]" &&
		    !StringUtil::StartsWith(authority, "[::1]:")) {
			throw InvalidInputException("%s: plaintext HTTP endpoints are allowed only on loopback", error_prefix);
		}
	}
}

namespace {

static constexpr idx_t COL_TIME = 0;
static constexpr idx_t COL_OBSERVED_TIME = 1;
static constexpr idx_t COL_BODY = 10;
static constexpr idx_t COL_RESOURCE_ATTRIBUTES = 11;
static constexpr idx_t COL_LOG_ATTRIBUTES = 15;
static constexpr idx_t COLUMN_COUNT = 18;

struct CloudwatchLogsBindData : public TableFunctionData {
	string log_group;
	string filter_pattern;
	string start_time = "-15m";
	string end_time = "now";
	string log_stream_prefix;
	vector<string> log_streams;
	string order = "desc";
	int64_t page_size = 10000;
	int64_t max_rows = 0;
	bool unmask = false;
	TableCatalogEntry *table = nullptr;
	CloudwatchClient client;
};

struct CloudwatchLogsGlobalState : public GlobalTableFunctionState {
	vector<column_t> column_ids;
	std::deque<CloudwatchLogEvent> buffer;
	string next_token;
	int64_t start_time_ms = 0;
	int64_t end_time_ms = 0;
	idx_t total_emitted = 0;
	bool finished = false;

	idx_t MaxThreads() const override {
		return 1;
	}
};

int64_t CheckedSubtract(int64_t value, int64_t amount) {
	if (amount < 0 || value < std::numeric_limits<int64_t>::min() + amount) {
		throw InvalidInputException("CloudWatch time offset is outside the supported range");
	}
	return value - amount;
}

int64_t ParseRelativeTime(const string &value, int64_t now_ms, const string &parameter_name) {
	auto lower = StringUtil::Lower(value);
	StringUtil::Trim(lower);
	if (lower == "now") {
		return now_ms;
	}
	if (lower.size() < 3 || lower[0] != '-') {
		return -1;
	}
	char unit = lower.back();
	int64_t multiplier;
	switch (unit) {
	case 's':
		multiplier = 1000;
		break;
	case 'm':
		multiplier = 60 * 1000;
		break;
	case 'h':
		multiplier = 60 * 60 * 1000;
		break;
	case 'd':
		multiplier = 24 * 60 * 60 * 1000;
		break;
	case 'w':
		multiplier = 7 * 24 * 60 * 60 * 1000;
		break;
	default:
		return -1;
	}

	string number = lower.substr(1, lower.size() - 2);
	if (number.empty()) {
		return -1;
	}
	errno = 0;
	char *end = nullptr;
	auto magnitude = strtoll(number.c_str(), &end, 10);
	if (errno == ERANGE || !end || *end != '\0' || magnitude < 0 ||
	    magnitude > std::numeric_limits<int64_t>::max() / multiplier) {
		throw InvalidInputException("read_cloudwatch_logs: invalid %s value '%s'", parameter_name, value);
	}
	return CheckedSubtract(now_ms, magnitude * multiplier);
}

int64_t ParseCloudwatchTime(const string &value, int64_t now_ms, const string &parameter_name) {
	auto relative = ParseRelativeTime(value, now_ms, parameter_name);
	if (relative >= 0) {
		return relative;
	}

	errno = 0;
	char *end = nullptr;
	auto milliseconds = strtoll(value.c_str(), &end, 10);
	if (errno != ERANGE && end && end != value.c_str() && *end == '\0' && milliseconds >= 0) {
		return milliseconds;
	}

	timestamp_t timestamp;
	bool has_offset = false;
	string_t timezone;
	if (Timestamp::TryConvertTimestampTZ(value.c_str(), value.size(), timestamp, true, has_offset, timezone) ==
	    TimestampCastResult::SUCCESS) {
		auto result = Timestamp::GetEpochMs(timestamp);
		if (result >= 0) {
			return result;
		}
	}
	if (Timestamp::TryConvertTimestamp(value.c_str(), value.size(), timestamp, false) == TimestampCastResult::SUCCESS) {
		auto result = Timestamp::GetEpochMs(timestamp);
		if (result >= 0) {
			return result;
		}
	}
	throw InvalidInputException("read_cloudwatch_logs: invalid %s value '%s'; use now, -15m/-2h/-7d, epoch "
	                            "milliseconds, or an ISO-8601 timestamp",
	                            parameter_name, value);
}

void ValidateSettings(const CloudwatchLogsBindData &settings) {
	if (settings.log_group.empty()) {
		throw InvalidInputException("read_cloudwatch_logs: log_group must not be empty");
	}
	CloudwatchLogsSettings common;
	common.order = settings.order;
	common.page_size = settings.page_size;
	common.max_rows = settings.max_rows;
	common.retries = static_cast<int64_t>(settings.client.retries);
	common.timeout_seconds = static_cast<int64_t>(settings.client.timeout_seconds);
	common.endpoint = settings.client.endpoint;
	ValidateCloudwatchLogsSettings(common, "read_cloudwatch_logs");
	if (!settings.log_stream_prefix.empty() && !settings.log_streams.empty()) {
		throw InvalidInputException("read_cloudwatch_logs: log_stream_prefix and log_streams are mutually exclusive");
	}
	if (settings.log_streams.size() > 100) {
		throw InvalidInputException("read_cloudwatch_logs: log_streams accepts at most 100 names");
	}
	for (const auto &stream : settings.log_streams) {
		if (stream.empty()) {
			throw InvalidInputException("read_cloudwatch_logs: log_streams must not contain empty names");
		}
	}
}

idx_t PageLimit(const CloudwatchLogsBindData &bind, const CloudwatchLogsGlobalState &state) {
	if (bind.max_rows == 0) {
		return static_cast<idx_t>(bind.page_size);
	}
	auto buffered_and_emitted = state.total_emitted + state.buffer.size();
	if (buffered_and_emitted >= static_cast<idx_t>(bind.max_rows)) {
		return 0;
	}
	return MinValue<idx_t>(static_cast<idx_t>(bind.page_size),
	                       static_cast<idx_t>(bind.max_rows) - buffered_and_emitted);
}

void FetchNextPage(ClientContext &context, const CloudwatchLogsBindData &bind, CloudwatchLogsGlobalState &state) {
	auto page_limit = PageLimit(bind, state);
	if (page_limit == 0) {
		state.finished = true;
		return;
	}
	CloudwatchFilterRequest request;
	request.log_group = bind.log_group;
	request.filter_pattern = bind.filter_pattern;
	request.log_stream_prefix = bind.log_stream_prefix;
	request.log_streams = bind.log_streams;
	request.next_token = state.next_token;
	request.start_time_ms = state.start_time_ms;
	request.end_time_ms = state.end_time_ms;
	request.limit = static_cast<int64_t>(page_limit);
	request.ascending = bind.order == "asc";
	request.unmask = bind.unmask;

	auto response = bind.client.FilterLogEvents(context, BuildCloudwatchFilterRequest(request));
	vector<CloudwatchLogEvent> events;
	auto next_token = ParseCloudwatchFilterResponse(response, events);
	for (auto &event : events) {
		state.buffer.push_back(std::move(event));
	}

	auto previous_token = state.next_token;
	if (next_token.empty() || next_token == previous_token || PageLimit(bind, state) == 0) {
		state.finished = true;
	} else {
		state.next_token = std::move(next_token);
	}
}

Value MillisecondTimestamp(int64_t milliseconds) {
	if (milliseconds < 0 || milliseconds > std::numeric_limits<int64_t>::max() / 1000000) {
		return Value();
	}
	return Value::TIMESTAMPNS(timestamp_ns_t(milliseconds * 1000000));
}

void MapEvent(const CloudwatchLogsBindData &bind, const CloudwatchLogsGlobalState &state,
              const CloudwatchLogEvent &event, DataChunk &output, idx_t output_row) {
	for (idx_t output_column = 0; output_column < state.column_ids.size(); output_column++) {
		output.SetValue(output_column, output_row, Value());
		auto source_column = state.column_ids[output_column];
		switch (source_column) {
		case COL_TIME:
			output.SetValue(output_column, output_row, MillisecondTimestamp(event.timestamp_ms));
			break;
		case COL_OBSERVED_TIME:
			output.SetValue(output_column, output_row, MillisecondTimestamp(event.ingestion_time_ms));
			break;
		case COL_BODY:
			if (!event.message.empty()) {
				output.SetValue(output_column, output_row, Value(event.message));
			}
			break;
		case COL_RESOURCE_ATTRIBUTES:
			output.SetValue(output_column, output_row,
			                Value(BuildCloudwatchResourceAttributes(bind.client.credentials.region, bind.log_group,
			                                                        event.log_stream_name)));
			break;
		case COL_LOG_ATTRIBUTES: {
			auto attributes = BuildCloudwatchLogAttributes(event.event_id);
			if (!attributes.empty()) {
				output.SetValue(output_column, output_row, Value(attributes));
			}
			break;
		}
		default:
			break;
		}
	}
}

unique_ptr<FunctionData> CloudwatchLogsBind(ClientContext &context, TableFunctionBindInput &input,
                                            vector<LogicalType> &return_types, vector<string> &names) {
	auto result = make_uniq<CloudwatchLogsBindData>();
	result->log_group = input.inputs[0].ToString();
	string secret_name;
	string region;

	for (const auto &parameter : input.named_parameters) {
		auto key = StringUtil::Lower(parameter.first);
		if (parameter.second.IsNull()) {
			continue;
		}
		if (key == "filter") {
			result->filter_pattern = parameter.second.ToString();
		} else if (key == "start_time") {
			result->start_time = parameter.second.ToString();
		} else if (key == "end_time") {
			result->end_time = parameter.second.ToString();
		} else if (key == "log_stream_prefix") {
			result->log_stream_prefix = parameter.second.ToString();
		} else if (key == "log_streams") {
			for (const auto &child : ListValue::GetChildren(parameter.second)) {
				if (!child.IsNull()) {
					result->log_streams.push_back(child.ToString());
				}
			}
		} else if (key == "order") {
			result->order = StringUtil::Lower(parameter.second.ToString());
		} else if (key == "page_size") {
			result->page_size = parameter.second.GetValue<int64_t>();
		} else if (key == "max_rows") {
			result->max_rows = parameter.second.GetValue<int64_t>();
		} else if (key == "retries") {
			auto retries = parameter.second.GetValue<int64_t>();
			if (retries < 0) {
				throw InvalidInputException("read_cloudwatch_logs: retries must be >= 0");
			}
			result->client.retries = static_cast<uint64_t>(retries);
		} else if (key == "timeout") {
			auto timeout = parameter.second.GetValue<int64_t>();
			if (timeout < 0) {
				throw InvalidInputException("read_cloudwatch_logs: timeout must be >= 1 second");
			}
			result->client.timeout_seconds = static_cast<uint64_t>(timeout);
		} else if (key == "unmask") {
			result->unmask = parameter.second.GetValue<bool>();
		} else if (key == "secret") {
			secret_name = parameter.second.ToString();
		} else if (key == "region") {
			region = parameter.second.ToString();
		} else if (key == "endpoint") {
			result->client.endpoint = parameter.second.ToString();
		}
	}

	ValidateSettings(*result);
	result->client.credentials = GetCloudwatchCredentials(context, secret_name, region);
	GetCloudwatchLogsSchema(return_types, names);
	return std::move(result);
}

unique_ptr<GlobalTableFunctionState> CloudwatchLogsInitGlobal(ClientContext &, TableFunctionInitInput &input) {
	auto state = make_uniq<CloudwatchLogsGlobalState>();
	auto &bind = input.bind_data->Cast<CloudwatchLogsBindData>();
	state->column_ids = input.column_ids;
	auto now_ms = Timestamp::GetEpochMs(Timestamp::GetCurrentTimestamp());
	state->start_time_ms = ParseCloudwatchTime(bind.start_time, now_ms, "start_time");
	state->end_time_ms = ParseCloudwatchTime(bind.end_time, now_ms, "end_time");
	if (state->start_time_ms > state->end_time_ms) {
		throw InvalidInputException("read_cloudwatch_logs: start_time must be <= end_time");
	}
	return std::move(state);
}

void CloudwatchLogsScan(ClientContext &context, TableFunctionInput &input, DataChunk &output) {
	auto &bind = input.bind_data->Cast<CloudwatchLogsBindData>();
	auto &state = input.global_state->Cast<CloudwatchLogsGlobalState>();
	while (state.buffer.empty() && !state.finished) {
		FetchNextPage(context, bind, state);
	}

	idx_t count = 0;
	while (count < STANDARD_VECTOR_SIZE && !state.buffer.empty()) {
		MapEvent(bind, state, state.buffer.front(), output, count);
		state.buffer.pop_front();
		state.total_emitted++;
		count++;
		if (bind.max_rows > 0 && state.total_emitted >= static_cast<idx_t>(bind.max_rows)) {
			state.buffer.clear();
			state.finished = true;
			break;
		}
	}
	output.SetCardinality(count);
}

InsertionOrderPreservingMap<string> CloudwatchLogsToString(TableFunctionToStringInput &input) {
	InsertionOrderPreservingMap<string> result;
	auto &bind = input.bind_data->Cast<CloudwatchLogsBindData>();
	result["Function"] = input.table_function.name;
	result["AWS Region"] = bind.client.credentials.region;
	result["CloudWatch Log Group"] = bind.log_group;
	result["CloudWatch Order"] = bind.order;
	result["CloudWatch Page Size"] = std::to_string(bind.page_size);
	result["CloudWatch Max Rows"] = std::to_string(bind.max_rows);
	if (!bind.filter_pattern.empty()) {
		result["CloudWatch Filter"] = bind.filter_pattern;
	}
	return result;
}

} // namespace

void GetCloudwatchLogsSchema(vector<LogicalType> &types, vector<string> &names) {
	names = {"time_unix_nano",
	         "observed_time_unix_nano",
	         "trace_id",
	         "span_id",
	         "service_name",
	         "service_namespace",
	         "service_instance_id",
	         "severity_number",
	         "severity_text",
	         "event_name",
	         "body",
	         "resource_attributes",
	         "scope_name",
	         "scope_version",
	         "scope_attributes",
	         "log_attributes",
	         "dropped_attributes_count",
	         "flags"};
	types = {LogicalType::TIMESTAMP_NS, LogicalType::TIMESTAMP_NS, LogicalType::VARCHAR, LogicalType::VARCHAR,
	         LogicalType::VARCHAR,      LogicalType::VARCHAR,      LogicalType::VARCHAR, LogicalType::INTEGER,
	         LogicalType::VARCHAR,      LogicalType::VARCHAR,      LogicalType::VARCHAR, LogicalType::VARCHAR,
	         LogicalType::VARCHAR,      LogicalType::VARCHAR,      LogicalType::VARCHAR, LogicalType::VARCHAR,
	         LogicalType::INTEGER,      LogicalType::INTEGER};
	D_ASSERT(names.size() == COLUMN_COUNT && types.size() == COLUMN_COUNT);
}

void RegisterCloudwatchLogsFunction(ExtensionLoader &loader) {
	TableFunction function("read_cloudwatch_logs", {LogicalType::VARCHAR}, CloudwatchLogsScan, CloudwatchLogsBind,
	                       CloudwatchLogsInitGlobal);
	function.named_parameters["filter"] = LogicalType::VARCHAR;
	function.named_parameters["start_time"] = LogicalType::VARCHAR;
	function.named_parameters["end_time"] = LogicalType::VARCHAR;
	function.named_parameters["log_stream_prefix"] = LogicalType::VARCHAR;
	function.named_parameters["log_streams"] = LogicalType::LIST(LogicalType::VARCHAR);
	function.named_parameters["order"] = LogicalType::VARCHAR;
	function.named_parameters["page_size"] = LogicalType::BIGINT;
	function.named_parameters["max_rows"] = LogicalType::BIGINT;
	function.named_parameters["retries"] = LogicalType::BIGINT;
	function.named_parameters["timeout"] = LogicalType::BIGINT;
	function.named_parameters["unmask"] = LogicalType::BOOLEAN;
	function.named_parameters["secret"] = LogicalType::VARCHAR;
	function.named_parameters["region"] = LogicalType::VARCHAR;
	function.named_parameters["endpoint"] = LogicalType::VARCHAR;
	function.projection_pushdown = true;
	function.to_string = CloudwatchLogsToString;
	loader.RegisterFunction(function);
}

static BindInfo CloudwatchLogsGetBindInfo(const optional_ptr<FunctionData> bind_data) {
	auto &data = bind_data->Cast<CloudwatchLogsBindData>();
	D_ASSERT(data.table);
	return BindInfo(*data.table);
}

TableFunction GetCloudwatchLogsTableScan(ClientContext &context, TableCatalogEntry &table, const string &secret_name,
                                         const string &log_group, const CloudwatchLogsSettings &settings,
                                         unique_ptr<FunctionData> &bind_data) {
	auto result = make_uniq<CloudwatchLogsBindData>();
	result->log_group = log_group;
	result->filter_pattern = settings.filter_pattern;
	result->start_time = settings.start_time;
	result->end_time = settings.end_time;
	result->order = settings.order;
	result->page_size = settings.page_size;
	result->max_rows = settings.max_rows;
	result->unmask = settings.unmask;
	result->table = &table;
	result->client.endpoint = settings.endpoint;
	result->client.retries = static_cast<uint64_t>(settings.retries);
	result->client.timeout_seconds = static_cast<uint64_t>(settings.timeout_seconds);
	result->client.credentials = GetCloudwatchCredentials(context, secret_name, settings.region);
	bind_data = std::move(result);

	TableFunction function("cloudwatch_logs_scan", {}, CloudwatchLogsScan, nullptr, CloudwatchLogsInitGlobal);
	function.projection_pushdown = true;
	function.to_string = CloudwatchLogsToString;
	function.get_bind_info = CloudwatchLogsGetBindInfo;
	return function;
}

} // namespace duckdb
