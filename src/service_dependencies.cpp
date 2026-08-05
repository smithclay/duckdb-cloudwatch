#include "service_dependencies.hpp"

#include "cloudwatch_client.hpp"
#include "cloudwatch_secret.hpp"
#include "logs_table.hpp"

#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/timestamp.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

#include "yyjson.hpp"

#include <cerrno>
#include <cstdlib>
#include <deque>
#include <limits>
#include <memory>
#include <unordered_map>

using namespace duckdb_yyjson; // NOLINT

namespace duckdb {
namespace {

struct DocDeleter {
	void operator()(yyjson_doc *doc) const {
		yyjson_doc_free(doc);
	}
};
struct MutDocDeleter {
	void operator()(yyjson_mut_doc *doc) const {
		yyjson_mut_doc_free(doc);
	}
};
struct JsonStringDeleter {
	void operator()(char *value) const {
		free(value);
	}
};
using DocPtr = std::unique_ptr<yyjson_doc, DocDeleter>;
using MutDocPtr = std::unique_ptr<yyjson_mut_doc, MutDocDeleter>;
using JsonStringPtr = std::unique_ptr<char, JsonStringDeleter>;

const char *GetString(yyjson_val *object, const char *key) {
	auto value = object ? yyjson_obj_get(object, key) : nullptr;
	return value && yyjson_is_str(value) ? yyjson_get_str(value) : nullptr;
}

int64_t GetInteger(yyjson_val *object, const char *key, int64_t default_value = 0) {
	auto value = object ? yyjson_obj_get(object, key) : nullptr;
	if (!value || !yyjson_is_num(value)) {
		return default_value;
	}
	if (yyjson_is_uint(value) && yyjson_get_uint(value) > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
		throw IOException("AWS X-Ray returned an integer outside DuckDB's BIGINT range");
	}
	return yyjson_get_sint(value);
}

double GetDouble(yyjson_val *object, const char *key, double default_value = 0) {
	auto value = object ? yyjson_obj_get(object, key) : nullptr;
	return value && yyjson_is_num(value) ? yyjson_get_num(value) : default_value;
}

string WriteValue(yyjson_val *value) {
	if (!value) {
		return string();
	}
	size_t length = 0;
	JsonStringPtr json(yyjson_val_write(value, 0, &length));
	return json ? string(json.get(), length) : string();
}

string WriteDocument(yyjson_mut_doc *doc) {
	size_t length = 0;
	JsonStringPtr json(yyjson_mut_write(doc, 0, &length));
	if (!json) {
		throw InternalException("Failed to serialize X-Ray request JSON");
	}
	return string(json.get(), length);
}

struct XrayEdge {
	int64_t reference_id = -1;
	string alias_name;
	string alias_type;
	string edge_type;
	int64_t request_count = 0;
	int64_t error_count = 0;
	int64_t fault_count = 0;
	int64_t throttle_count = 0;
	double total_response_time = 0;
	bool has_statistics = false;
	string attributes;
};

struct XrayService {
	int64_t reference_id = -1;
	string name;
	string type;
	string attributes;
	vector<XrayEdge> edges;
};

string BuildAttributes(yyjson_val *object, const vector<const char *> &keys) {
	string result = "{";
	bool first = true;
	for (auto key : keys) {
		auto value = yyjson_obj_get(object, key);
		if (!value) {
			continue;
		}
		if (!first) {
			result += ",";
		}
		first = false;
		result += "\"" + string(key) + "\":" + WriteValue(value);
	}
	return first ? string() : result + "}";
}

void ParseEdge(yyjson_val *value, XrayEdge &edge) {
	edge.reference_id = GetInteger(value, "ReferenceId", -1);
	auto edge_type = GetString(value, "EdgeType");
	if (!edge_type) {
		edge_type = GetString(value, "Type");
	}
	edge.edge_type = edge_type ? edge_type : "synchronous";
	auto summary = yyjson_obj_get(value, "SummaryStatistics");
	edge.has_statistics = summary && yyjson_is_obj(summary);
	edge.request_count = GetInteger(summary, "TotalCount");
	edge.total_response_time = GetDouble(summary, "TotalResponseTime");
	auto errors = summary ? yyjson_obj_get(summary, "ErrorStatistics") : nullptr;
	auto faults = summary ? yyjson_obj_get(summary, "FaultStatistics") : nullptr;
	edge.error_count = GetInteger(errors, "TotalCount");
	edge.fault_count = GetInteger(faults, "TotalCount");
	edge.throttle_count = GetInteger(errors, "ThrottleCount") + GetInteger(faults, "ThrottleCount");
	auto aliases = yyjson_obj_get(value, "Aliases");
	if (aliases && yyjson_is_arr(aliases) && yyjson_arr_size(aliases) > 0) {
		auto alias = yyjson_arr_get_first(aliases);
		auto name = GetString(alias, "Name");
		auto type = GetString(alias, "Type");
		edge.alias_name = name ? name : string();
		edge.alias_type = type ? type : string();
	}
	edge.attributes = BuildAttributes(
	    value, {"Aliases", "ResponseTimeHistogram", "ReceivedEventAgeHistogram", "StartTime", "EndTime"});
}

void ParseService(yyjson_val *value, XrayService &service) {
	service.reference_id = GetInteger(value, "ReferenceId", -1);
	auto name = GetString(value, "Name");
	auto type = GetString(value, "Type");
	service.name = name ? name : string();
	service.type = type ? type : string();
	service.attributes = BuildAttributes(value, {"AccountId", "Root", "State", "Names", "StartTime", "EndTime",
	                                             "DurationHistogram", "ResponseTimeHistogram", "SummaryStatistics"});
	auto edges = yyjson_obj_get(value, "Edges");
	if (edges && yyjson_is_arr(edges)) {
		size_t index, count;
		yyjson_val *edge;
		yyjson_arr_foreach(edges, index, count, edge) {
			XrayEdge parsed;
			ParseEdge(edge, parsed);
			service.edges.push_back(std::move(parsed));
		}
	}
}

string ParseServiceGraphResponse(const string &response, vector<XrayService> &services) {
	DocPtr doc(yyjson_read(response.c_str(), response.size(), 0));
	if (!doc) {
		throw IOException("AWS X-Ray returned a response that is not valid JSON");
	}
	auto root = yyjson_doc_get_root(doc.get());
	if (!root || !yyjson_is_obj(root)) {
		throw IOException("AWS X-Ray returned a JSON response that is not an object");
	}
	auto json_services = yyjson_obj_get(root, "Services");
	if (json_services && yyjson_is_arr(json_services)) {
		size_t index, count;
		yyjson_val *service;
		yyjson_arr_foreach(json_services, index, count, service) {
			XrayService parsed;
			ParseService(service, parsed);
			services.push_back(std::move(parsed));
		}
	}
	auto next = GetString(root, "NextToken");
	return next ? next : string();
}

string BuildServiceGraphRequest(int64_t start_ms, int64_t end_ms, const string &group_name, const string &group_arn,
                                const string &next_token) {
	MutDocPtr doc(yyjson_mut_doc_new(nullptr));
	auto root = yyjson_mut_obj(doc.get());
	yyjson_mut_doc_set_root(doc.get(), root);
	yyjson_mut_obj_add_real(doc.get(), root, "StartTime", static_cast<double>(start_ms) / 1000.0);
	yyjson_mut_obj_add_real(doc.get(), root, "EndTime", static_cast<double>(end_ms) / 1000.0);
	if (!group_name.empty()) {
		yyjson_mut_obj_add_strncpy(doc.get(), root, "GroupName", group_name.c_str(), group_name.size());
	}
	if (!group_arn.empty()) {
		yyjson_mut_obj_add_strncpy(doc.get(), root, "GroupARN", group_arn.c_str(), group_arn.size());
	}
	if (!next_token.empty()) {
		yyjson_mut_obj_add_strncpy(doc.get(), root, "NextToken", next_token.c_str(), next_token.size());
	}
	return WriteDocument(doc.get());
}

int64_t ParseRelativeTime(const string &value, int64_t now_ms) {
	auto lower = StringUtil::Lower(value);
	StringUtil::Trim(lower);
	if (lower == "now") {
		return now_ms;
	}
	if (lower.size() < 3 || lower[0] != '-') {
		return -1;
	}
	int64_t multiplier = 0;
	switch (lower.back()) {
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
	auto number = lower.substr(1, lower.size() - 2);
	errno = 0;
	char *end = nullptr;
	auto magnitude = strtoll(number.c_str(), &end, 10);
	if (number.empty() || errno == ERANGE || !end || *end || magnitude < 0 ||
	    magnitude > std::numeric_limits<int64_t>::max() / multiplier || now_ms < magnitude * multiplier) {
		throw InvalidInputException("CloudWatch service map time is outside the supported range: '%s'", value);
	}
	return now_ms - magnitude * multiplier;
}

int64_t ParseTime(const string &value, int64_t now_ms, const string &parameter_name) {
	auto relative = ParseRelativeTime(value, now_ms);
	if (relative >= 0) {
		return relative;
	}
	errno = 0;
	char *end = nullptr;
	auto milliseconds = strtoll(value.c_str(), &end, 10);
	if (errno != ERANGE && end && end != value.c_str() && !*end && milliseconds >= 0) {
		return milliseconds;
	}
	timestamp_t timestamp;
	bool has_offset = false;
	string_t timezone;
	if (Timestamp::TryConvertTimestampTZ(value.c_str(), value.size(), timestamp, true, has_offset, timezone) ==
	    TimestampCastResult::SUCCESS) {
		return Timestamp::GetEpochMs(timestamp);
	}
	if (Timestamp::TryConvertTimestamp(value.c_str(), value.size(), timestamp, false) == TimestampCastResult::SUCCESS) {
		return Timestamp::GetEpochMs(timestamp);
	}
	throw InvalidInputException("read_cloudwatch_service_dependencies: invalid %s value '%s'", parameter_name, value);
}

struct ServiceEdgeRow {
	string source_service;
	string target_service;
	string source_type;
	string target_type;
	string edge_type;
	int64_t request_count;
	int64_t error_count;
	int64_t fault_count;
	int64_t throttle_count;
	double total_response_time;
	bool has_statistics;
	string source_attributes;
	string target_attributes;
	string edge_attributes;
};

struct ServiceDependenciesBindData : public TableFunctionData {
	CloudwatchServiceMapSettings settings;
	CloudwatchClient client;
	TableCatalogEntry *table = nullptr;
};

struct ServiceDependenciesGlobalState : public GlobalTableFunctionState {
	vector<column_t> column_ids;
	std::deque<ServiceEdgeRow> rows;
	int64_t start_ms = 0;
	int64_t end_ms = 0;
	bool loaded = false;
	idx_t MaxThreads() const override {
		return 1;
	}
};

void ResolveGraph(const vector<XrayService> &services, std::deque<ServiceEdgeRow> &rows);

void LoadGraph(ClientContext &context, const ServiceDependenciesBindData &bind, ServiceDependenciesGlobalState &state) {
	vector<XrayService> services;
	string next_token;
	for (;;) {
		auto response = bind.client.GetServiceGraph(
		    context, BuildServiceGraphRequest(state.start_ms, state.end_ms, bind.settings.group_name,
		                                      bind.settings.group_arn, next_token));
		auto next = ParseServiceGraphResponse(response, services);
		if (next.empty() || next == next_token) {
			break;
		}
		next_token = std::move(next);
	}
	ResolveGraph(services, state.rows);
	state.loaded = true;
}

void ResolveGraph(const vector<XrayService> &services, std::deque<ServiceEdgeRow> &rows) {
	std::unordered_map<int64_t, const XrayService *> by_reference;
	for (const auto &service : services)
		by_reference[service.reference_id] = &service;
	for (const auto &source : services) {
		for (const auto &edge : source.edges) {
			ServiceEdgeRow row;
			row.source_service = source.name;
			row.source_type = source.type;
			row.edge_type = edge.edge_type;
			row.request_count = edge.request_count;
			row.error_count = edge.error_count;
			row.fault_count = edge.fault_count;
			row.throttle_count = edge.throttle_count;
			row.total_response_time = edge.total_response_time;
			row.has_statistics = edge.has_statistics;
			row.source_attributes = source.attributes;
			row.edge_attributes = edge.attributes;
			auto target = by_reference.find(edge.reference_id);
			if (target != by_reference.end()) {
				row.target_service = target->second->name;
				row.target_type = target->second->type;
				row.target_attributes = target->second->attributes;
			} else {
				row.target_service = edge.alias_name;
				row.target_type = edge.alias_type;
			}
			rows.push_back(std::move(row));
		}
	}
}

Value OptionalString(const string &value) {
	return value.empty() ? Value() : Value(value);
}

void ServiceDependenciesScan(ClientContext &context, TableFunctionInput &input, DataChunk &output) {
	auto &bind = input.bind_data->Cast<ServiceDependenciesBindData>();
	auto &state = input.global_state->Cast<ServiceDependenciesGlobalState>();
	if (!state.loaded) {
		LoadGraph(context, bind, state);
	}
	idx_t count = 0;
	while (count < STANDARD_VECTOR_SIZE && !state.rows.empty()) {
		auto &row = state.rows.front();
		for (idx_t out_col = 0; out_col < state.column_ids.size(); out_col++) {
			Value value;
			switch (state.column_ids[out_col]) {
			case 0:
				value = Value("cloudwatch");
				break;
			case 1:
				value = OptionalString(row.source_service);
				break;
			case 2:
				value = OptionalString(row.target_service);
				break;
			case 3:
				value = OptionalString(row.source_type);
				break;
			case 4:
				value = OptionalString(row.target_type);
				break;
			case 5:
				value = OptionalString(row.edge_type);
				break;
			case 6:
				value = Value();
				break;
			case 7:
				value = Value::TIMESTAMPNS(timestamp_ns_t(state.start_ms * 1000000));
				break;
			case 8:
				value = Value::TIMESTAMPNS(timestamp_ns_t(state.end_ms * 1000000));
				break;
			case 9:
				value = row.has_statistics ? Value::BIGINT(row.request_count) : Value();
				break;
			case 10:
				value = row.has_statistics ? Value::BIGINT(row.error_count) : Value();
				break;
			case 11:
				value = row.has_statistics ? Value::BIGINT(row.fault_count) : Value();
				break;
			case 12:
				value = row.has_statistics ? Value::BIGINT(row.throttle_count) : Value();
				break;
			case 13:
				value = row.has_statistics ? Value::DOUBLE(row.total_response_time) : Value();
				break;
			case 14:
				value = OptionalString(row.source_attributes);
				break;
			case 15:
				value = OptionalString(row.target_attributes);
				break;
			case 16:
				value = OptionalString(row.edge_attributes);
				break;
			default:
				break;
			}
			output.SetValue(out_col, count, value);
		}
		state.rows.pop_front();
		count++;
	}
	output.SetCardinality(count);
}

unique_ptr<GlobalTableFunctionState> ServiceDependenciesInit(ClientContext &, TableFunctionInitInput &input) {
	auto state = make_uniq<ServiceDependenciesGlobalState>();
	state->column_ids = input.column_ids;
	auto &bind = input.bind_data->Cast<ServiceDependenciesBindData>();
	auto now_ms = Timestamp::GetEpochMs(Timestamp::GetCurrentTimestamp());
	state->start_ms = ParseTime(bind.settings.start_time, now_ms, "start_time");
	state->end_ms = ParseTime(bind.settings.end_time, now_ms, "end_time");
	if (state->start_ms > state->end_ms) {
		throw InvalidInputException("read_cloudwatch_service_dependencies: start_time must be <= end_time");
	}
	if (state->start_ms > std::numeric_limits<int64_t>::max() / 1000000 ||
	    state->end_ms > std::numeric_limits<int64_t>::max() / 1000000 ||
	    state->start_ms < std::numeric_limits<int64_t>::min() / 1000000 ||
	    state->end_ms < std::numeric_limits<int64_t>::min() / 1000000) {
		throw InvalidInputException("read_cloudwatch_service_dependencies: timestamp is outside TIMESTAMP_NS range");
	}
	return std::move(state);
}

unique_ptr<ServiceDependenciesBindData> MakeBindData(ClientContext &context, const string &secret_name,
                                                     const CloudwatchServiceMapSettings &settings) {
	ValidateCloudwatchServiceMapSettings(settings, "read_cloudwatch_service_dependencies");
	auto result = make_uniq<ServiceDependenciesBindData>();
	result->settings = settings;
	result->client.endpoint = settings.xray_endpoint;
	result->client.retries = static_cast<uint64_t>(settings.retries);
	result->client.timeout_seconds = static_cast<uint64_t>(settings.timeout_seconds);
	result->client.credentials = GetCloudwatchCredentials(context, secret_name, settings.region);
	return result;
}

unique_ptr<FunctionData> ServiceDependenciesBind(ClientContext &context, TableFunctionBindInput &input,
                                                 vector<LogicalType> &types, vector<string> &names) {
	CloudwatchServiceMapSettings settings;
	string secret_name;
	for (const auto &parameter : input.named_parameters) {
		if (parameter.second.IsNull())
			continue;
		auto key = StringUtil::Lower(parameter.first);
		if (key == "start_time")
			settings.start_time = parameter.second.ToString();
		else if (key == "end_time")
			settings.end_time = parameter.second.ToString();
		else if (key == "group_name")
			settings.group_name = parameter.second.ToString();
		else if (key == "group_arn")
			settings.group_arn = parameter.second.ToString();
		else if (key == "secret")
			secret_name = parameter.second.ToString();
		else if (key == "region")
			settings.region = parameter.second.ToString();
		else if (key == "xray_endpoint")
			settings.xray_endpoint = parameter.second.ToString();
		else if (key == "retries")
			settings.retries = parameter.second.GetValue<int64_t>();
		else if (key == "timeout")
			settings.timeout_seconds = parameter.second.GetValue<int64_t>();
	}
	ValidateCloudwatchServiceMapSettings(settings, "read_cloudwatch_service_dependencies");
	auto result = MakeBindData(context, secret_name, settings);
	GetCloudwatchServiceDependenciesSchema(types, names);
	return std::move(result);
}

BindInfo ServiceDependenciesGetBindInfo(const optional_ptr<FunctionData> bind_data) {
	return BindInfo(*bind_data->Cast<ServiceDependenciesBindData>().table);
}

} // namespace

void ValidateCloudwatchServiceMapSettings(const CloudwatchServiceMapSettings &settings, const string &error_prefix) {
	if (!settings.group_name.empty() && !settings.group_arn.empty()) {
		throw InvalidInputException("%s: group_name and group_arn are mutually exclusive", error_prefix);
	}
	if (settings.retries < 0 || settings.retries > 100) {
		throw InvalidInputException("%s: retries must be between 0 and 100", error_prefix);
	}
	if (settings.timeout_seconds < 1) {
		throw InvalidInputException("%s: timeout must be >= 1 second", error_prefix);
	}
	// Reuse the logs endpoint validator, whose endpoint policy is service-independent.
	CloudwatchLogsSettings endpoint_settings;
	endpoint_settings.endpoint = settings.xray_endpoint;
	ValidateCloudwatchLogsSettings(endpoint_settings, error_prefix);
}

void GetCloudwatchServiceDependenciesSchema(vector<LogicalType> &types, vector<string> &names) {
	names = {"provider",          "source_service",
	         "target_service",    "source_type",
	         "target_type",       "edge_type",
	         "environment",       "window_start",
	         "window_end",        "request_count",
	         "error_count",       "fault_count",
	         "throttle_count",    "total_response_time_seconds",
	         "source_attributes", "target_attributes",
	         "edge_attributes"};
	types = {LogicalType::VARCHAR,      LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR,
	         LogicalType::VARCHAR,      LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::TIMESTAMP_NS,
	         LogicalType::TIMESTAMP_NS, LogicalType::BIGINT,  LogicalType::BIGINT,  LogicalType::BIGINT,
	         LogicalType::BIGINT,       LogicalType::DOUBLE,  LogicalType::VARCHAR, LogicalType::VARCHAR,
	         LogicalType::VARCHAR};
}

void RegisterCloudwatchServiceDependenciesFunction(ExtensionLoader &loader) {
	TableFunction function("read_cloudwatch_service_dependencies", {}, ServiceDependenciesScan, ServiceDependenciesBind,
	                       ServiceDependenciesInit);
	function.named_parameters["start_time"] = LogicalType::VARCHAR;
	function.named_parameters["end_time"] = LogicalType::VARCHAR;
	function.named_parameters["group_name"] = LogicalType::VARCHAR;
	function.named_parameters["group_arn"] = LogicalType::VARCHAR;
	function.named_parameters["secret"] = LogicalType::VARCHAR;
	function.named_parameters["region"] = LogicalType::VARCHAR;
	function.named_parameters["xray_endpoint"] = LogicalType::VARCHAR;
	function.named_parameters["retries"] = LogicalType::BIGINT;
	function.named_parameters["timeout"] = LogicalType::BIGINT;
	function.projection_pushdown = true;
	loader.RegisterFunction(function);
}

TableFunction GetCloudwatchServiceDependenciesTableScan(ClientContext &context, TableCatalogEntry &table,
                                                        const string &secret_name,
                                                        const CloudwatchServiceMapSettings &settings,
                                                        unique_ptr<FunctionData> &bind_data) {
	auto result = MakeBindData(context, secret_name, settings);
	result->table = &table;
	bind_data = std::move(result);
	TableFunction function("cloudwatch_service_dependencies_scan", {}, ServiceDependenciesScan, nullptr,
	                       ServiceDependenciesInit);
	function.projection_pushdown = true;
	function.get_bind_info = ServiceDependenciesGetBindInfo;
	return function;
}

string BuildCloudwatchServiceGraphRequestForTest(int64_t start_ms, int64_t end_ms, const string &group_name,
                                                 const string &group_arn, const string &next_token) {
	return BuildServiceGraphRequest(start_ms, end_ms, group_name, group_arn, next_token);
}

vector<CloudwatchServiceDependencyProtocolRow>
ParseCloudwatchServiceGraphResponsesForTest(const vector<string> &responses) {
	vector<XrayService> services;
	for (const auto &response : responses) {
		ParseServiceGraphResponse(response, services);
	}
	std::deque<ServiceEdgeRow> resolved;
	ResolveGraph(services, resolved);
	vector<CloudwatchServiceDependencyProtocolRow> result;
	for (const auto &row : resolved) {
		CloudwatchServiceDependencyProtocolRow value;
		value.source_service = row.source_service;
		value.target_service = row.target_service;
		value.request_count = row.request_count;
		value.error_count = row.error_count;
		value.fault_count = row.fault_count;
		value.throttle_count = row.throttle_count;
		value.total_response_time_seconds = row.total_response_time;
		value.has_statistics = row.has_statistics;
		result.push_back(std::move(value));
	}
	return result;
}

} // namespace duckdb
