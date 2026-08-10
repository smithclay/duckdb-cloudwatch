#include "log_group_admin.hpp"

#include "cloudwatch_client.hpp"
#include "cloudwatch_json.hpp"
#include "cloudwatch_secret.hpp"

#include "logs_table.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/execution/expression_executor.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/planner/expression/bound_function_expression.hpp"

namespace duckdb {

namespace {

//! Unlike send_cloudwatch_logs, whose destination must be constant so batches cannot be misrouted
//! by row data, the admin functions exist precisely to act on a computed list of names, so the
//! group and stream arguments are evaluated per row. Only the secret name is bound once.
struct CloudwatchAdminBindData : public FunctionData {
	CloudwatchClient client;

	unique_ptr<FunctionData> Copy() const override {
		auto result = make_uniq<CloudwatchAdminBindData>();
		result->client.credentials = client.credentials;
		result->client.endpoint = client.endpoint;
		result->client.timeout_seconds = client.timeout_seconds;
		result->client.retries = client.retries;
		return std::move(result);
	}

	bool Equals(const FunctionData &other_p) const override {
		auto &other = other_p.Cast<CloudwatchAdminBindData>();
		return client.credentials.secret_name == other.client.credentials.secret_name &&
		       client.credentials.region == other.client.credentials.region &&
		       client.endpoint == other.client.endpoint;
	}
};

string ConstantStringArgument(ClientContext &context, const unique_ptr<Expression> &argument, const string &name,
                              const string &function_name) {
	if (!argument->IsFoldable()) {
		throw BinderException("%s: %s must be a constant string", function_name, name);
	}
	auto value = ExpressionExecutor::EvaluateScalar(context, *argument);
	return value.IsNull() ? string() : value.ToString();
}

//! CloudWatch's own log-group name rules, checked locally so an invalid name fails with a specific
//! message instead of an opaque InvalidParameterException.
void ValidateLogGroupName(const string &log_group, const string &function_name) {
	if (log_group.empty()) {
		throw InvalidInputException("%s: log group name must not be empty", function_name);
	}
	if (log_group.size() > 512) {
		throw InvalidInputException("%s: log group name must be at most 512 bytes", function_name);
	}
	for (auto character : log_group) {
		const auto valid = (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
		                   (character >= '0' && character <= '9') || character == '.' || character == '-' ||
		                   character == '_' || character == '/' || character == '#';
		if (!valid) {
			throw InvalidInputException("%s: log group name '%s' contains an invalid character (allowed: letters, "
			                            "digits, '.', '-', '_', '/', '#')",
			                            function_name, log_group);
		}
	}
}

void ValidateLogStreamName(const string &log_stream, const string &function_name) {
	if (log_stream.empty()) {
		throw InvalidInputException("%s: log stream name must not be empty", function_name);
	}
	if (log_stream.size() > 512) {
		throw InvalidInputException("%s: log stream name must be at most 512 bytes", function_name);
	}
	if (log_stream.find(':') != string::npos || log_stream.find('*') != string::npos) {
		throw InvalidInputException("%s: log stream name must not contain ':' or '*'", function_name);
	}
}

//! SECRET_ARGUMENT is the index of the optional secret name; the endpoint override, when given,
//! follows it. Both must be constant: they select the destination account and origin, which must
//! not vary per row.
template <idx_t SECRET_ARGUMENT>
unique_ptr<FunctionData> AdminBind(ClientContext &context, ScalarFunction &bound_function,
                                   vector<unique_ptr<Expression>> &arguments) {
	auto result = make_uniq<CloudwatchAdminBindData>();
	string secret_name;
	if (arguments.size() > SECRET_ARGUMENT) {
		secret_name =
		    ConstantStringArgument(context, arguments[SECRET_ARGUMENT], "the secret name", bound_function.name);
	}
	if (arguments.size() > SECRET_ARGUMENT + 1) {
		result->client.endpoint =
		    ConstantStringArgument(context, arguments[SECRET_ARGUMENT + 1], "the endpoint", bound_function.name);
		CloudwatchLogsSettings settings;
		settings.endpoint = result->client.endpoint;
		ValidateCloudwatchLogsSettings(settings, bound_function.name);
	}
	result->client.credentials = GetCloudwatchCredentials(context, secret_name, string());
	bound_function.return_type = LogicalType::VARCHAR;
	return std::move(result);
}

//! put_cloudwatch_retention_policy additionally rejects an invalid retention value before any
//! credential lookup, matching how the scan functions validate arguments first. Only a constant
//! can be checked here; a per-row value is validated during execution.
unique_ptr<FunctionData> RetentionBind(ClientContext &context, ScalarFunction &bound_function,
                                       vector<unique_ptr<Expression>> &arguments) {
	if (arguments.size() > 1 && arguments[1]->IsFoldable()) {
		auto value = ExpressionExecutor::EvaluateScalar(context, *arguments[1]);
		if (!value.IsNull()) {
			auto days = value.GetValue<int64_t>();
			if (!IsValidCloudwatchRetentionDays(days)) {
				throw InvalidInputException(
				    "put_cloudwatch_retention_policy: retention_days must be one of %s (got %lld)",
				    CloudwatchRetentionDaysList(), static_cast<long long>(days));
			}
		}
	}
	return AdminBind<2>(context, bound_function, arguments);
}

//! Run one admin call, mapping the AWS "already exists"/"not found" errors onto an outcome string
//! so the SQL surface is idempotent. Any other error still raises.
string RunAdminCall(ClientContext &context, const CloudwatchClient &client, const string &target, const string &body,
                    const char *tolerated_exception, const char *tolerated_outcome, const char *success_outcome) {
	string response_body;
	string error_body;
	if (client.TryPostLogs(context, target, body, response_body, error_body)) {
		return success_outcome;
	}
	if (tolerated_exception && CloudwatchErrorIs(error_body, tolerated_exception)) {
		return tolerated_outcome;
	}
	throw IOException("%s failed: %s", target, error_body);
}

void CreateLogGroupFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &function = state.expr.Cast<BoundFunctionExpression>();
	auto &bind = function.bind_info->Cast<CloudwatchAdminBindData>();
	auto &context = state.GetContext();

	UnaryExecutor::Execute<string_t, string_t>(args.data[0], result, args.size(), [&](string_t group) {
		if (context.interrupted) {
			throw InterruptException();
		}
		auto log_group = group.GetString();
		ValidateLogGroupName(log_group, "create_cloudwatch_log_group");
		return StringVector::AddString(
		    result, RunAdminCall(context, bind.client, "Logs_20140328.CreateLogGroup",
		                         BuildCloudwatchCreateLogGroupRequest(log_group), "ResourceAlreadyExistsException",
		                         "exists", "created"));
	});
}

void DeleteLogGroupFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &function = state.expr.Cast<BoundFunctionExpression>();
	auto &bind = function.bind_info->Cast<CloudwatchAdminBindData>();
	auto &context = state.GetContext();

	UnaryExecutor::Execute<string_t, string_t>(args.data[0], result, args.size(), [&](string_t group) {
		if (context.interrupted) {
			throw InterruptException();
		}
		auto log_group = group.GetString();
		ValidateLogGroupName(log_group, "delete_cloudwatch_log_group");
		return StringVector::AddString(
		    result, RunAdminCall(context, bind.client, "Logs_20140328.DeleteLogGroup",
		                         BuildCloudwatchDeleteLogGroupRequest(log_group), "ResourceNotFoundException", "absent",
		                         "deleted"));
	});
}

void CreateLogStreamFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &function = state.expr.Cast<BoundFunctionExpression>();
	auto &bind = function.bind_info->Cast<CloudwatchAdminBindData>();
	auto &context = state.GetContext();

	BinaryExecutor::Execute<string_t, string_t, string_t>(
	    args.data[0], args.data[1], result, args.size(), [&](string_t group, string_t stream) {
		    if (context.interrupted) {
			    throw InterruptException();
		    }
		    auto log_group = group.GetString();
		    auto log_stream = stream.GetString();
		    ValidateLogGroupName(log_group, "create_cloudwatch_log_stream");
		    ValidateLogStreamName(log_stream, "create_cloudwatch_log_stream");
		    return StringVector::AddString(
		        result, RunAdminCall(context, bind.client, "Logs_20140328.CreateLogStream",
		                             BuildCloudwatchCreateLogStreamRequest(log_group, log_stream),
		                             "ResourceAlreadyExistsException", "exists", "created"));
	    });
}

void PutRetentionPolicyFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &function = state.expr.Cast<BoundFunctionExpression>();
	auto &bind = function.bind_info->Cast<CloudwatchAdminBindData>();
	auto &context = state.GetContext();

	BinaryExecutor::Execute<string_t, int64_t, string_t>(
	    args.data[0], args.data[1], result, args.size(), [&](string_t group, int64_t days) {
		    if (context.interrupted) {
			    throw InterruptException();
		    }
		    auto log_group = group.GetString();
		    ValidateLogGroupName(log_group, "put_cloudwatch_retention_policy");
		    if (!IsValidCloudwatchRetentionDays(days)) {
			    throw InvalidInputException(
			        "put_cloudwatch_retention_policy: retention_days must be one of %s (got %lld)",
			        CloudwatchRetentionDaysList(), static_cast<long long>(days));
		    }
		    return StringVector::AddString(
		        result, RunAdminCall(context, bind.client, "Logs_20140328.PutRetentionPolicy",
		                             BuildCloudwatchPutRetentionPolicyRequest(log_group, days), nullptr, nullptr, "ok"));
	    });
}

} // namespace

void RegisterCloudwatchLogGroupAdminFunctions(ExtensionLoader &loader) {
	// Each function takes an optional constant secret name and, after it, an optional constant
	// endpoint override (a private VPC endpoint, or a local cloudwatch_serve listener).
	{
		ScalarFunctionSet set("create_cloudwatch_log_group");
		for (auto &arguments : vector<vector<LogicalType>> {
		         {LogicalType::VARCHAR},
		         {LogicalType::VARCHAR, LogicalType::VARCHAR},
		         {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR}}) {
			ScalarFunction function(arguments, LogicalType::VARCHAR, CreateLogGroupFunction, AdminBind<1>);
			function.SetStability(FunctionStability::VOLATILE);
			set.AddFunction(function);
		}
		loader.RegisterFunction(set);
	}
	{
		ScalarFunctionSet set("delete_cloudwatch_log_group");
		for (auto &arguments : vector<vector<LogicalType>> {
		         {LogicalType::VARCHAR},
		         {LogicalType::VARCHAR, LogicalType::VARCHAR},
		         {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR}}) {
			ScalarFunction function(arguments, LogicalType::VARCHAR, DeleteLogGroupFunction, AdminBind<1>);
			function.SetStability(FunctionStability::VOLATILE);
			set.AddFunction(function);
		}
		loader.RegisterFunction(set);
	}
	{
		ScalarFunctionSet set("create_cloudwatch_log_stream");
		for (auto &arguments : vector<vector<LogicalType>> {
		         {LogicalType::VARCHAR, LogicalType::VARCHAR},
		         {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR},
		         {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR}}) {
			ScalarFunction function(arguments, LogicalType::VARCHAR, CreateLogStreamFunction, AdminBind<2>);
			function.SetStability(FunctionStability::VOLATILE);
			set.AddFunction(function);
		}
		loader.RegisterFunction(set);
	}
	{
		ScalarFunctionSet set("put_cloudwatch_retention_policy");
		for (auto &arguments : vector<vector<LogicalType>> {
		         {LogicalType::VARCHAR, LogicalType::BIGINT},
		         {LogicalType::VARCHAR, LogicalType::BIGINT, LogicalType::VARCHAR},
		         {LogicalType::VARCHAR, LogicalType::BIGINT, LogicalType::VARCHAR, LogicalType::VARCHAR}}) {
			ScalarFunction function(arguments, LogicalType::VARCHAR, PutRetentionPolicyFunction, RetentionBind);
			function.SetStability(FunctionStability::VOLATILE);
			set.AddFunction(function);
		}
		loader.RegisterFunction(set);
	}
}

} // namespace duckdb
