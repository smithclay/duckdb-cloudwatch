#include "send_logs.hpp"

#include "cloudwatch_client.hpp"
#include "cloudwatch_json.hpp"
#include "cloudwatch_secret.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/timestamp.hpp"
#include "duckdb/common/types/vector.hpp"
#include "duckdb/execution/expression_executor.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/planner/expression/bound_function_expression.hpp"

#include <chrono>
#include <unordered_map>

namespace duckdb {

namespace {

struct SendLogsFieldIndices {
	int32_t message = -1;            // body | message
	int32_t timestamp = -1;          // time_unix_nano | timestamp
	int32_t observed_timestamp = -1; // observed_time_unix_nano fallback
	bool timestamp_is_nanos = false;

	bool operator==(const SendLogsFieldIndices &other) const {
		return message == other.message && timestamp == other.timestamp &&
		       observed_timestamp == other.observed_timestamp && timestamp_is_nanos == other.timestamp_is_nanos;
	}
};

struct CloudwatchSendLogsBindData : public FunctionData {
	SendLogsFieldIndices fields;
	string log_group;
	string log_stream;
	CloudwatchClient client;

	unique_ptr<FunctionData> Copy() const override {
		auto result = make_uniq<CloudwatchSendLogsBindData>();
		result->fields = fields;
		result->log_group = log_group;
		result->log_stream = log_stream;
		result->client.credentials = client.credentials;
		result->client.endpoint = client.endpoint;
		result->client.timeout_seconds = client.timeout_seconds;
		result->client.retries = client.retries;
		return std::move(result);
	}

	bool Equals(const FunctionData &other_p) const override {
		auto &other = other_p.Cast<CloudwatchSendLogsBindData>();
		return fields == other.fields && log_group == other.log_group && log_stream == other.log_stream &&
		       client.credentials.secret_name == other.client.credentials.secret_name &&
		       client.credentials.region == other.client.credentials.region;
	}
};

int32_t PickField(const std::unordered_map<string, idx_t> &by_name, const vector<const char *> &names) {
	for (const auto *name : names) {
		auto entry = by_name.find(name);
		if (entry != by_name.end()) {
			return static_cast<int32_t>(entry->second);
		}
	}
	return -1;
}

string ConstantStringArgument(ClientContext &context, const unique_ptr<Expression> &argument, const string &name,
                              bool allow_null = false) {
	if (!argument->IsFoldable()) {
		throw BinderException("send_cloudwatch_logs: %s must be a constant string", name);
	}
	auto value = ExpressionExecutor::EvaluateScalar(context, *argument);
	if (value.IsNull()) {
		if (allow_null) {
			return string();
		}
		throw BinderException("send_cloudwatch_logs: %s must not be NULL", name);
	}
	return value.ToString();
}

void ValidateDestination(const string &log_group, const string &log_stream) {
	if (log_group.empty()) {
		throw BinderException("send_cloudwatch_logs: log_group must not be empty");
	}
	if (log_group.size() > 512) {
		throw BinderException("send_cloudwatch_logs: log_group must be at most 512 bytes");
	}
	for (auto character : log_group) {
		const auto valid = (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
		                   (character >= '0' && character <= '9') || character == '.' || character == '-' ||
		                   character == '_' || character == '/' || character == '#';
		if (!valid) {
			throw BinderException("send_cloudwatch_logs: log_group contains an invalid character");
		}
	}
	if (log_stream.empty()) {
		throw BinderException("send_cloudwatch_logs: log_stream must not be empty");
	}
	if (log_stream.size() > 512) {
		throw BinderException("send_cloudwatch_logs: log_stream must be at most 512 bytes");
	}
	if (log_stream.find(':') != string::npos || log_stream.find('*') != string::npos) {
		throw BinderException("send_cloudwatch_logs: log_stream must not contain ':' or '*'");
	}
}

unique_ptr<FunctionData> CloudwatchSendLogsBind(ClientContext &context, ScalarFunction &bound_function,
                                                vector<unique_ptr<Expression>> &arguments) {
	if (arguments.empty() || arguments[0]->return_type.id() != LogicalTypeId::STRUCT) {
		throw BinderException("send_cloudwatch_logs: the first argument must be a STRUCT of OTLP-shaped log columns "
		                      "(e.g. send_cloudwatch_logs(logs, '/app/logs', 'duckdb') where 'logs' is the source "
		                      "table)");
	}

	auto result = make_uniq<CloudwatchSendLogsBindData>();
	const auto &struct_type = arguments[0]->return_type;
	std::unordered_map<string, idx_t> by_name;
	for (idx_t index = 0; index < StructType::GetChildCount(struct_type); index++) {
		by_name.emplace(StringUtil::Lower(StructType::GetChildName(struct_type, index)), index);
	}
	result->fields.message = PickField(by_name, {"body", "message"});
	result->fields.timestamp = PickField(by_name, {"time_unix_nano", "timestamp"});
	result->fields.timestamp_is_nanos = by_name.count("time_unix_nano") > 0;
	result->fields.observed_timestamp = PickField(by_name, {"observed_time_unix_nano"});

	result->log_group = ConstantStringArgument(context, arguments[1], "log_group");
	result->log_stream = ConstantStringArgument(context, arguments[2], "log_stream");
	ValidateDestination(result->log_group, result->log_stream);
	string secret_name;
	if (arguments.size() == 4) {
		secret_name = ConstantStringArgument(context, arguments[3], "secret name", true);
	}
	result->client.credentials = GetCloudwatchCredentials(context, secret_name, string());
	bound_function.return_type = LogicalType::VARCHAR;
	return std::move(result);
}

string ReadStringField(vector<unique_ptr<Vector>> &children, int32_t index, idx_t row) {
	if (index < 0) {
		return string();
	}
	auto value = children[index]->GetValue(row);
	return value.IsNull() ? string() : value.ToString();
}

bool ReadTimestampMs(vector<unique_ptr<Vector>> &children, int32_t index, bool is_nanos, idx_t row,
                     int64_t &timestamp_ms) {
	if (index < 0) {
		return false;
	}
	auto value = children[index]->GetValue(row);
	if (value.IsNull()) {
		return false;
	}
	if (value.type().IsIntegral()) {
		Value integer;
		if (!value.DefaultTryCastAs(LogicalType::BIGINT, integer, nullptr) || integer.IsNull()) {
			return false;
		}
		auto raw = integer.GetValue<int64_t>();
		timestamp_ms = is_nanos ? raw / 1000000 : raw;
		return true;
	}
	Value nanos;
	if (!value.DefaultTryCastAs(LogicalType::TIMESTAMP_NS, nanos, nullptr) || nanos.IsNull()) {
		return false;
	}
	timestamp_ms = nanos.GetValue<timestamp_ns_t>().value / 1000000;
	return true;
}

string RejectionDetail(const CloudwatchPutResponse &response) {
	string result;
	auto append = [&](const string &detail) {
		if (!result.empty()) {
			result += ", ";
		}
		result += detail;
	};
	if (response.has_expired_end) {
		append("expired through index " + std::to_string(response.expired_end));
	}
	if (response.has_too_old_end) {
		append("too old through index " + std::to_string(response.too_old_end));
	}
	if (response.has_too_new_start) {
		append("too new from index " + std::to_string(response.too_new_start));
	}
	if (response.has_rejected_entity) {
		append("entity rejected" +
		       (response.rejected_entity_error.empty() ? string() : " (" + response.rejected_entity_error + ")"));
	}
	return result;
}

void CloudwatchSendLogsFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &function = state.expr.Cast<BoundFunctionExpression>();
	auto &bind = function.bind_info->Cast<CloudwatchSendLogsBindData>();
	auto &context = state.GetContext();
	const auto count = args.size();

	auto &input = args.data[0];
	input.Flatten(count);
	auto &children = StructVector::GetEntries(input);
	auto &input_validity = FlatVector::Validity(input);
	result.SetVectorType(VectorType::FLAT_VECTOR);
	auto &result_validity = FlatVector::Validity(result);

	vector<CloudwatchPutLogEvent> events;
	events.reserve(count);
	const auto now_ms =
	    std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
	        .count();
	for (idx_t row = 0; row < count; row++) {
		if (!input_validity.RowIsValid(row)) {
			result_validity.SetInvalid(row);
			continue;
		}
		CloudwatchPutLogEvent event;
		event.source_row = row;
		event.message = ReadStringField(children, bind.fields.message, row);
		if (!ReadTimestampMs(children, bind.fields.timestamp, bind.fields.timestamp_is_nanos, row,
		                     event.timestamp_ms) &&
		    !ReadTimestampMs(children, bind.fields.observed_timestamp, true, row, event.timestamp_ms)) {
			event.timestamp_ms = now_ms;
		}
		events.push_back(std::move(event));
	}

	auto batches = SortAndPlanCloudwatchPutEvents(events);
	for (const auto &batch : batches) {
		if (context.interrupted) {
			throw InterruptException();
		}
		auto body =
		    BuildCloudwatchPutEventsRequest(bind.log_group, bind.log_stream, events.data() + batch.offset, batch.count);
		auto response = ParseCloudwatchPutEventsResponse(bind.client.PutLogEvents(context, body));
		if (response.HasRejections()) {
			throw IOException("CloudWatch PutLogEvents partially accepted a batch: %s", RejectionDetail(response));
		}
		for (idx_t index = batch.offset; index < batch.offset + batch.count; index++) {
			result.SetValue(events[index].source_row, Value("ok"));
		}
	}
}

} // namespace

void RegisterCloudwatchSendLogsFunction(ExtensionLoader &loader) {
	ScalarFunctionSet set("send_cloudwatch_logs");
	for (auto &arguments : vector<vector<LogicalType>> {
	         {LogicalType::ANY, LogicalType::VARCHAR, LogicalType::VARCHAR},
	         {LogicalType::ANY, LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR}}) {
		ScalarFunction function(arguments, LogicalType::VARCHAR, CloudwatchSendLogsFunction, CloudwatchSendLogsBind);
		function.SetStability(FunctionStability::VOLATILE);
		function.SetNullHandling(FunctionNullHandling::SPECIAL_HANDLING);
		set.AddFunction(function);
	}
	loader.RegisterFunction(set);
}

} // namespace duckdb
