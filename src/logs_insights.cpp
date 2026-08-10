#include "logs_insights.hpp"

#include "cloudwatch_client.hpp"
#include "cloudwatch_json.hpp"
#include "cloudwatch_secret.hpp"
#include "logs_table.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

#include <algorithm>
#include <chrono>
#include <thread>
#include <unordered_map>

namespace duckdb {

namespace {

constexpr const char *FUNCTION_NAME = "read_cloudwatch_logs_insights";
//! AWS caps one StartQuery at 50 log groups.
constexpr idx_t MAX_LOG_GROUPS = 50;

struct CloudwatchInsightsBindData : public TableFunctionData {
	//! Insights has no schema until the query has run, so bind executes it and keeps the rows.
	//! Shared rather than copied: Copy() is called per plan and a result set can be large.
	shared_ptr<CloudwatchInsightsResults> results;
	vector<string> column_names;
	//! Position of each column within a row, per row, resolved once at bind time. A row may omit a
	//! field that another row carries, so this is per-row rather than a single column order.
	shared_ptr<vector<vector<int32_t>>> row_field_index;
	string query_string;

	unique_ptr<FunctionData> Copy() const override {
		auto result = make_uniq<CloudwatchInsightsBindData>();
		result->results = results;
		result->column_names = column_names;
		result->row_field_index = row_field_index;
		result->query_string = query_string;
		return std::move(result);
	}

	bool Equals(const FunctionData &other_p) const override {
		auto &other = other_p.Cast<CloudwatchInsightsBindData>();
		return results == other.results && query_string == other.query_string;
	}
};

struct CloudwatchInsightsGlobalState : public GlobalTableFunctionState {
	idx_t emitted = 0;
	vector<column_t> column_ids;

	idx_t MaxThreads() const override {
		return 1;
	}
};

int64_t NowMs() {
	return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
	    .count();
}

void SleepCheckingInterrupt(ClientContext &context, int64_t milliseconds) {
	auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(milliseconds);
	while (std::chrono::steady_clock::now() < deadline) {
		if (context.interrupted) {
			throw InterruptException();
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(50));
	}
}

vector<string> StringListValue(const Value &value, const string &parameter_name) {
	vector<string> result;
	if (value.IsNull()) {
		return result;
	}
	for (const auto &item : ListValue::GetChildren(value)) {
		if (item.IsNull()) {
			throw InvalidInputException("%s: %s must not contain NULL", FUNCTION_NAME, parameter_name);
		}
		result.push_back(item.ToString());
	}
	return result;
}

//! Run the query to completion. StopQuery is best-effort on interrupt so an abandoned query stops
//! being billed for scanning; failing to stop it must not mask the original interrupt.
CloudwatchInsightsResults RunInsightsQuery(ClientContext &context, const CloudwatchClient &client,
                                           const CloudwatchInsightsRequest &request, int64_t poll_interval_ms,
                                           int64_t max_wait_ms) {
	auto query_id = ParseCloudwatchStartQueryResponse(client.StartQuery(context, BuildCloudwatchStartQueryRequest(request)));
	const auto deadline = NowMs() + max_wait_ms;
	for (;;) {
		CloudwatchInsightsResults results;
		try {
			if (context.interrupted) {
				throw InterruptException();
			}
			results = ParseCloudwatchGetQueryResultsResponse(
			    client.GetQueryResults(context, BuildCloudwatchQueryIdRequest(query_id)));
		} catch (...) {
			try {
				client.StopQuery(context, BuildCloudwatchQueryIdRequest(query_id));
			} catch (...) { // NOLINT: the original failure is the one worth reporting
			}
			throw;
		}
		if (results.status == CloudwatchInsightsStatus::COMPLETE) {
			return results;
		}
		if (IsCloudwatchInsightsTerminal(results.status)) {
			throw IOException("%s: CloudWatch Logs Insights query %s ended with status '%s'", FUNCTION_NAME, query_id,
			                  results.status_text.empty() ? "Unknown" : results.status_text);
		}
		if (NowMs() >= deadline) {
			try {
				client.StopQuery(context, BuildCloudwatchQueryIdRequest(query_id));
			} catch (...) { // NOLINT: report the timeout, not the cleanup failure
			}
			throw IOException("%s: CloudWatch Logs Insights query %s did not complete within %lld ms (raise max_wait)",
			                  FUNCTION_NAME, query_id, static_cast<long long>(max_wait_ms));
		}
		SleepCheckingInterrupt(context, poll_interval_ms);
	}
}

//! Derive the result schema from the returned rows: column order is first-seen across rows, so a
//! field only some rows carry still gets a column (NULL elsewhere) instead of shifting values.
void DeriveSchema(CloudwatchInsightsBindData &bind) {
	std::unordered_map<string, idx_t> position;
	for (const auto &row : bind.results->rows) {
		for (const auto &field : row.fields) {
			if (position.find(field.first) == position.end()) {
				position.emplace(field.first, bind.column_names.size());
				bind.column_names.push_back(field.first);
			}
		}
	}
	// An aggregation matching nothing returns zero rows and therefore no field names. A table
	// function must still expose at least one column, so fall back to the single always-present
	// Insights field rather than binding an empty schema.
	if (bind.column_names.empty()) {
		bind.column_names.push_back("@message");
	}

	bind.row_field_index = make_shared_ptr<vector<vector<int32_t>>>();
	bind.row_field_index->reserve(bind.results->rows.size());
	for (const auto &row : bind.results->rows) {
		vector<int32_t> indices(bind.column_names.size(), -1);
		for (idx_t field_index = 0; field_index < row.fields.size(); field_index++) {
			auto entry = position.find(row.fields[field_index].first);
			if (entry != position.end()) {
				indices[entry->second] = static_cast<int32_t>(field_index);
			}
		}
		bind.row_field_index->push_back(std::move(indices));
	}
}

unique_ptr<FunctionData> CloudwatchInsightsBind(ClientContext &context, TableFunctionBindInput &input,
                                                vector<LogicalType> &return_types, vector<string> &names) {
	auto result = make_uniq<CloudwatchInsightsBindData>();
	CloudwatchInsightsRequest request;
	CloudwatchClient client;

	if (input.inputs.empty() || input.inputs[0].IsNull()) {
		throw InvalidInputException("%s: the query string must not be NULL", FUNCTION_NAME);
	}
	request.query_string = input.inputs[0].ToString();
	result->query_string = request.query_string;

	string secret_name;
	string start_time = "-15m";
	string end_time = "now";
	string region;
	string endpoint;
	int64_t poll_interval_ms = 500;
	int64_t max_wait_ms = 300000;
	for (auto &entry : input.named_parameters) {
		auto key = StringUtil::Lower(entry.first);
		if (key == "log_groups") {
			request.log_groups = StringListValue(entry.second, "log_groups");
		} else if (key == "log_group") {
			if (!entry.second.IsNull()) {
				request.log_groups.push_back(entry.second.ToString());
			}
		} else if (key == "start_time") {
			start_time = entry.second.ToString();
		} else if (key == "end_time") {
			end_time = entry.second.ToString();
		} else if (key == "max_rows" || key == "limit") {
			// `limit` is the API's own field name but a reserved word in DuckDB's parser (it needs
			// quoting), so `max_rows` is the primary spelling and matches read_cloudwatch_logs.
			request.limit = BigIntValue::Get(entry.second);
		} else if (key == "secret") {
			secret_name = entry.second.IsNull() ? string() : entry.second.ToString();
		} else if (key == "region") {
			region = entry.second.ToString();
		} else if (key == "endpoint") {
			endpoint = entry.second.ToString();
		} else if (key == "poll_interval_ms") {
			poll_interval_ms = BigIntValue::Get(entry.second);
		} else if (key == "max_wait") {
			max_wait_ms = BigIntValue::Get(entry.second) * 1000;
		} else if (key == "retries") {
			client.retries = static_cast<uint64_t>(BigIntValue::Get(entry.second));
		} else if (key == "timeout") {
			client.timeout_seconds = static_cast<uint64_t>(BigIntValue::Get(entry.second));
		} else {
			throw InvalidInputException("%s: unknown parameter '%s'", FUNCTION_NAME, entry.first);
		}
	}

	if (request.query_string.empty()) {
		throw InvalidInputException("%s: the query string must not be empty", FUNCTION_NAME);
	}
	if (request.log_groups.empty()) {
		throw InvalidInputException("%s: pass at least one log group via log_groups => ['/my/group']", FUNCTION_NAME);
	}
	if (request.log_groups.size() > MAX_LOG_GROUPS) {
		throw InvalidInputException("%s: CloudWatch Logs Insights queries at most %llu log groups per query, got %llu",
		                            FUNCTION_NAME, static_cast<unsigned long long>(MAX_LOG_GROUPS),
		                            static_cast<unsigned long long>(request.log_groups.size()));
	}
	for (const auto &group : request.log_groups) {
		if (group.empty()) {
			throw InvalidInputException("%s: log group names must not be empty", FUNCTION_NAME);
		}
	}
	if (request.limit < 0 || request.limit > 10000) {
		throw InvalidInputException("%s: max_rows must be between 0 and 10000 (0 uses the AWS default)", FUNCTION_NAME);
	}
	if (poll_interval_ms < 10) {
		throw InvalidInputException("%s: poll_interval_ms must be >= 10", FUNCTION_NAME);
	}
	if (max_wait_ms < 1000) {
		throw InvalidInputException("%s: max_wait must be >= 1 second", FUNCTION_NAME);
	}

	// Reuse the shared endpoint/retry validation so this surface rejects exactly what the scan does
	// (notably: plaintext HTTP only on loopback).
	CloudwatchLogsSettings settings;
	settings.retries = static_cast<int64_t>(client.retries);
	settings.timeout_seconds = static_cast<int64_t>(client.timeout_seconds);
	settings.endpoint = endpoint;
	ValidateCloudwatchLogsSettings(settings, FUNCTION_NAME);

	const auto now_ms = NowMs();
	request.start_time_ms = ParseCloudwatchTime(start_time, now_ms, "start_time", FUNCTION_NAME);
	request.end_time_ms = ParseCloudwatchTime(end_time, now_ms, "end_time", FUNCTION_NAME);
	if (request.end_time_ms < request.start_time_ms) {
		throw InvalidInputException("%s: end_time must not be before start_time", FUNCTION_NAME);
	}

	client.endpoint = endpoint;
	client.credentials = GetCloudwatchCredentials(context, secret_name, region);

	// Insights is asynchronous no matter who calls it, so running the query here (rather than at
	// execution) costs nothing extra and is what makes a query-dependent schema possible at all.
	result->results = make_shared_ptr<CloudwatchInsightsResults>(
	    RunInsightsQuery(context, client, request, poll_interval_ms, max_wait_ms));
	DeriveSchema(*result);

	for (const auto &name : result->column_names) {
		names.push_back(name);
		// Insights returns every value as a string, including numbers from stats aggregations.
		// Keeping them VARCHAR avoids guessing a type per column; callers cast what they need.
		return_types.push_back(LogicalType::VARCHAR);
	}
	return std::move(result);
}

unique_ptr<GlobalTableFunctionState> CloudwatchInsightsInitGlobal(ClientContext &context,
                                                                 TableFunctionInitInput &input) {
	auto state = make_uniq<CloudwatchInsightsGlobalState>();
	state->column_ids = input.column_ids;
	return std::move(state);
}

void CloudwatchInsightsScan(ClientContext &context, TableFunctionInput &data, DataChunk &output) {
	auto &bind = data.bind_data->Cast<CloudwatchInsightsBindData>();
	auto &state = data.global_state->Cast<CloudwatchInsightsGlobalState>();
	const auto &rows = bind.results->rows;

	idx_t count = 0;
	while (count < STANDARD_VECTOR_SIZE && state.emitted < rows.size()) {
		const auto &row = rows[state.emitted];
		const auto &indices = (*bind.row_field_index)[state.emitted];
		for (idx_t out_column = 0; out_column < state.column_ids.size(); out_column++) {
			auto column_id = state.column_ids[out_column];
			if (IsRowIdColumnId(column_id)) {
				output.data[out_column].SetValue(count, Value::BIGINT(static_cast<int64_t>(state.emitted)));
				continue;
			}
			auto field_index = indices[column_id];
			if (field_index < 0) {
				output.data[out_column].SetValue(count, Value(LogicalType::VARCHAR));
			} else {
				output.data[out_column].SetValue(count, Value(row.fields[field_index].second));
			}
		}
		state.emitted++;
		count++;
	}
	output.SetCardinality(count);
}

} // namespace

void RegisterCloudwatchLogsInsightsFunction(ExtensionLoader &loader) {
	TableFunction function(FUNCTION_NAME, {LogicalType::VARCHAR}, CloudwatchInsightsScan, CloudwatchInsightsBind,
	                       CloudwatchInsightsInitGlobal);
	function.named_parameters["log_groups"] = LogicalType::LIST(LogicalType::VARCHAR);
	function.named_parameters["log_group"] = LogicalType::VARCHAR;
	function.named_parameters["start_time"] = LogicalType::VARCHAR;
	function.named_parameters["end_time"] = LogicalType::VARCHAR;
	function.named_parameters["max_rows"] = LogicalType::BIGINT;
	function.named_parameters["limit"] = LogicalType::BIGINT;
	function.named_parameters["secret"] = LogicalType::VARCHAR;
	function.named_parameters["region"] = LogicalType::VARCHAR;
	function.named_parameters["endpoint"] = LogicalType::VARCHAR;
	function.named_parameters["poll_interval_ms"] = LogicalType::BIGINT;
	function.named_parameters["max_wait"] = LogicalType::BIGINT;
	function.named_parameters["retries"] = LogicalType::BIGINT;
	function.named_parameters["timeout"] = LogicalType::BIGINT;
	loader.RegisterFunction(function);
}

} // namespace duckdb
