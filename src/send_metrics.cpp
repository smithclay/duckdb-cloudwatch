#include "send_metrics.hpp"

#include "cloudwatch_client.hpp"
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

#include "yyjson.hpp"

#include <chrono>
#include <cstdlib>
#include <unordered_map>
#include <utility>

using namespace duckdb_yyjson; // NOLINT

namespace duckdb {

namespace {

// PutMetricData accepts at most 1000 datums, and the encoded form body at most 1MB. The byte
// budget is the one that usually binds first once dimensions are attached, so both are enforced.
constexpr idx_t MAX_DATUMS_PER_REQUEST = 1000;
constexpr idx_t MAX_REQUEST_BYTES = 800000;
constexpr idx_t MAX_DIMENSIONS = 30;

struct SendMetricsFieldIndices {
	int32_t name = -1;       // name | metric_name
	int32_t value = -1;      // double_value | value
	int32_t timestamp = -1;  // time_unix_nano | timestamp
	int32_t unit = -1;       // unit
	int32_t service = -1;    // service_name
	int32_t attributes = -1; // metric_attributes | attributes
	bool timestamp_is_nanos = false;

	bool operator==(const SendMetricsFieldIndices &other) const {
		return name == other.name && value == other.value && timestamp == other.timestamp && unit == other.unit &&
		       service == other.service && attributes == other.attributes &&
		       timestamp_is_nanos == other.timestamp_is_nanos;
	}
};

struct CloudwatchSendMetricsBindData : public FunctionData {
	SendMetricsFieldIndices fields;
	string name_space;
	CloudwatchClient client;

	unique_ptr<FunctionData> Copy() const override {
		auto result = make_uniq<CloudwatchSendMetricsBindData>();
		result->fields = fields;
		result->name_space = name_space;
		result->client.credentials = client.credentials;
		result->client.endpoint = client.endpoint;
		result->client.timeout_seconds = client.timeout_seconds;
		result->client.retries = client.retries;
		return std::move(result);
	}

	bool Equals(const FunctionData &other_p) const override {
		auto &other = other_p.Cast<CloudwatchSendMetricsBindData>();
		return fields == other.fields && name_space == other.name_space &&
		       client.credentials.secret_name == other.client.credentials.secret_name &&
		       client.credentials.region == other.client.credentials.region;
	}
};

struct MetricDatum {
	idx_t source_row = 0;
	string name;
	string unit;
	double value = 0;
	int64_t timestamp_seconds = 0;
	vector<std::pair<string, string>> dimensions;
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

//! CloudWatch accepts only a fixed unit vocabulary and rejects anything else, so OTLP's UCUM-ish
//! units are translated here rather than passed through. Anything without a CloudWatch equivalent
//! -- nanoseconds, most notably, which CloudWatch cannot express -- becomes None, leaving the
//! value unscaled and unlabelled rather than silently mislabelled as a unit it is not.
string CloudwatchUnit(const string &otlp_unit) {
	static const std::unordered_map<string, string> mapping = {
	    {"s", "Seconds"},   {"ms", "Milliseconds"}, {"us", "Microseconds"}, {"By", "Bytes"},
	    {"bytes", "Bytes"}, {"KiBy", "Kilobytes"},  {"MiBy", "Megabytes"},  {"GiBy", "Gigabytes"},
	    {"Bi", "Bits"},     {"%", "Percent"},       {"1", "None"},          {"", "None"},
	};
	auto found = mapping.find(otlp_unit);
	if (found != mapping.end()) {
		return found->second;
	}
	// UCUM annotation-only units such as {request} or {error} are dimensionless counts.
	if (otlp_unit.size() >= 2 && otlp_unit.front() == '{' && otlp_unit.back() == '}') {
		return "Count";
	}
	return "None";
}

string ConstantStringArgument(ClientContext &context, const unique_ptr<Expression> &argument, const string &name,
                              bool allow_null = false) {
	if (!argument->IsFoldable()) {
		throw BinderException("send_cloudwatch_metrics: %s must be a constant string", name);
	}
	auto value = ExpressionExecutor::EvaluateScalar(context, *argument);
	if (value.IsNull()) {
		if (allow_null) {
			return string();
		}
		throw BinderException("send_cloudwatch_metrics: %s must not be NULL", name);
	}
	return value.ToString();
}

void ValidateNamespace(const string &name_space) {
	if (name_space.empty()) {
		throw BinderException("send_cloudwatch_metrics: namespace must not be empty");
	}
	if (name_space.size() > 255) {
		throw BinderException("send_cloudwatch_metrics: namespace must be at most 255 bytes");
	}
	if (StringUtil::StartsWith(name_space, "AWS/")) {
		throw BinderException("send_cloudwatch_metrics: the AWS/ namespace is reserved for AWS services");
	}
	for (auto character : name_space) {
		if (static_cast<unsigned char>(character) < 0x21 || static_cast<unsigned char>(character) > 0x7E) {
			throw BinderException("send_cloudwatch_metrics: namespace must be printable ASCII without spaces");
		}
	}
}

unique_ptr<FunctionData> CloudwatchSendMetricsBind(ClientContext &context, ScalarFunction &bound_function,
                                                   vector<unique_ptr<Expression>> &arguments) {
	if (arguments.empty() || arguments[0]->return_type.id() != LogicalTypeId::STRUCT) {
		throw BinderException(
		    "send_cloudwatch_metrics: the first argument must be a STRUCT of OTLP-shaped gauge columns "
		    "(e.g. send_cloudwatch_metrics(metrics, '/obsbench/run1') where 'metrics' is the source table)");
	}

	auto result = make_uniq<CloudwatchSendMetricsBindData>();
	const auto &struct_type = arguments[0]->return_type;
	std::unordered_map<string, idx_t> by_name;
	for (idx_t index = 0; index < StructType::GetChildCount(struct_type); index++) {
		by_name.emplace(StringUtil::Lower(StructType::GetChildName(struct_type, index)), index);
	}
	result->fields.name = PickField(by_name, {"name", "metric_name"});
	result->fields.value = PickField(by_name, {"double_value", "value"});
	result->fields.timestamp = PickField(by_name, {"time_unix_nano", "timestamp"});
	result->fields.timestamp_is_nanos = by_name.count("time_unix_nano") > 0;
	result->fields.unit = PickField(by_name, {"unit"});
	result->fields.service = PickField(by_name, {"service_name"});
	result->fields.attributes = PickField(by_name, {"metric_attributes", "attributes"});
	if (result->fields.name < 0) {
		throw BinderException("send_cloudwatch_metrics: the input struct needs a 'name' or 'metric_name' column");
	}
	if (result->fields.value < 0) {
		throw BinderException("send_cloudwatch_metrics: the input struct needs a 'double_value' or 'value' column");
	}

	result->name_space = ConstantStringArgument(context, arguments[1], "namespace");
	ValidateNamespace(result->name_space);
	string secret_name;
	if (arguments.size() >= 3) {
		secret_name = ConstantStringArgument(context, arguments[2], "secret name", true);
	}
	if (arguments.size() >= 4) {
		result->client.endpoint = ConstantStringArgument(context, arguments[3], "endpoint", true);
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

bool ReadDoubleField(vector<unique_ptr<Vector>> &children, int32_t index, idx_t row, double &out) {
	if (index < 0) {
		return false;
	}
	auto value = children[index]->GetValue(row);
	if (value.IsNull()) {
		return false;
	}
	Value number;
	if (!value.DefaultTryCastAs(LogicalType::DOUBLE, number, nullptr) || number.IsNull()) {
		return false;
	}
	out = number.GetValue<double>();
	return true;
}

bool ReadTimestampSeconds(vector<unique_ptr<Vector>> &children, int32_t index, bool is_nanos, idx_t row,
                          int64_t &timestamp_seconds) {
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
		timestamp_seconds = is_nanos ? raw / 1000000000 : raw;
		return true;
	}
	Value nanos;
	if (!value.DefaultTryCastAs(LogicalType::TIMESTAMP_NS, nanos, nullptr) || nanos.IsNull()) {
		return false;
	}
	timestamp_seconds = nanos.GetValue<timestamp_ns_t>().value / 1000000000;
	return true;
}

//! service_name becomes a `service.name` dimension, which is the key read_cloudwatch_metrics
//! already looks for when it fills its service_name column -- so a table sent through here reads
//! back with the same shape it went out with.
void CollectDimensions(const CloudwatchSendMetricsBindData &bind, vector<unique_ptr<Vector>> &children, idx_t row,
                       MetricDatum &datum) {
	auto service = ReadStringField(children, bind.fields.service, row);
	if (!service.empty()) {
		datum.dimensions.emplace_back("service.name", service);
	}
	auto attributes = ReadStringField(children, bind.fields.attributes, row);
	if (attributes.empty()) {
		return;
	}
	auto document = yyjson_read(attributes.c_str(), attributes.size(), 0);
	if (!document) {
		throw IOException("send_cloudwatch_metrics: metric_attributes is not valid JSON");
	}
	auto root = yyjson_doc_get_root(document);
	if (root && yyjson_is_obj(root)) {
		size_t index, max;
		yyjson_val *key, *child;
		yyjson_obj_foreach(root, index, max, key, child) {
			if (!yyjson_is_str(child)) {
				continue; // CloudWatch dimensions are string-valued only.
			}
			datum.dimensions.emplace_back(string(yyjson_get_str(key)), string(yyjson_get_str(child)));
		}
	}
	yyjson_doc_free(document);
	if (datum.dimensions.size() > MAX_DIMENSIONS) {
		throw IOException("send_cloudwatch_metrics: a metric may carry at most %d dimensions, got %d",
		                  static_cast<int>(MAX_DIMENSIONS), static_cast<int>(datum.dimensions.size()));
	}
}

string BuildPutMetricDataRequest(const string &name_space, const MetricDatum *datums, idx_t count) {
	auto document = yyjson_mut_doc_new(nullptr);
	auto root = yyjson_mut_obj(document);
	yyjson_mut_doc_set_root(document, root);
	yyjson_mut_obj_add_strncpy(document, root, "Namespace", name_space.c_str(), name_space.size());
	auto data = yyjson_mut_arr(document);
	for (idx_t index = 0; index < count; index++) {
		const auto &datum = datums[index];
		auto entry = yyjson_mut_obj(document);
		yyjson_mut_obj_add_strncpy(document, entry, "MetricName", datum.name.c_str(), datum.name.size());
		yyjson_mut_obj_add_sint(document, entry, "Timestamp", datum.timestamp_seconds);
		yyjson_mut_obj_add_real(document, entry, "Value", datum.value);
		yyjson_mut_obj_add_strncpy(document, entry, "Unit", datum.unit.c_str(), datum.unit.size());
		if (!datum.dimensions.empty()) {
			auto dimensions = yyjson_mut_arr(document);
			for (const auto &dimension : datum.dimensions) {
				auto pair = yyjson_mut_obj(document);
				yyjson_mut_obj_add_strncpy(document, pair, "Name", dimension.first.c_str(), dimension.first.size());
				yyjson_mut_obj_add_strncpy(document, pair, "Value", dimension.second.c_str(), dimension.second.size());
				yyjson_mut_arr_add_val(dimensions, pair);
			}
			yyjson_mut_obj_add_val(document, entry, "Dimensions", dimensions);
		}
		yyjson_mut_arr_add_val(data, entry);
	}
	yyjson_mut_obj_add_val(document, root, "MetricData", data);
	size_t length = 0;
	auto text = yyjson_mut_write(document, 0, &length);
	yyjson_mut_doc_free(document);
	if (!text) {
		throw IOException("send_cloudwatch_metrics: request serialization failed");
	}
	string result(text, length);
	free(text);
	return result;
}

//! Rough encoded size of one datum, used only to keep a batch under the 1MB body limit. The
//! constants are deliberately generous: query-protocol keys repeat a `MetricData.member.N.` prefix
//! on every field, and percent-encoding expands timestamps and dimension values further, so a
//! datum costs far more on the wire than its values suggest.
idx_t EstimateDatumBytes(const MetricDatum &datum) {
	idx_t bytes = 200 + datum.name.size() + datum.unit.size();
	for (const auto &dimension : datum.dimensions) {
		bytes += 120 + dimension.first.size() + dimension.second.size();
	}
	return bytes;
}

void CloudwatchSendMetricsFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &function = state.expr.Cast<BoundFunctionExpression>();
	auto &bind = function.bind_info->Cast<CloudwatchSendMetricsBindData>();
	auto &context = state.GetContext();
	const auto count = args.size();

	auto &input = args.data[0];
	input.Flatten(count);
	auto &children = StructVector::GetEntries(input);
	auto &input_validity = FlatVector::Validity(input);
	result.SetVectorType(VectorType::FLAT_VECTOR);
	auto &result_validity = FlatVector::Validity(result);

	const auto now_seconds =
	    std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();

	vector<MetricDatum> datums;
	datums.reserve(count);
	for (idx_t row = 0; row < count; row++) {
		if (!input_validity.RowIsValid(row)) {
			result_validity.SetInvalid(row);
			continue;
		}
		MetricDatum datum;
		datum.source_row = row;
		datum.name = ReadStringField(children, bind.fields.name, row);
		if (datum.name.empty()) {
			throw IOException("send_cloudwatch_metrics: metric name must not be empty");
		}
		if (!ReadDoubleField(children, bind.fields.value, row, datum.value)) {
			// A gauge with no reading is not a zero; skip it rather than invent a datapoint.
			result_validity.SetInvalid(row);
			continue;
		}
		if (!ReadTimestampSeconds(children, bind.fields.timestamp, bind.fields.timestamp_is_nanos, row,
		                          datum.timestamp_seconds)) {
			datum.timestamp_seconds = now_seconds;
		}
		datum.unit = CloudwatchUnit(ReadStringField(children, bind.fields.unit, row));
		CollectDimensions(bind, children, row, datum);
		datums.push_back(std::move(datum));
	}

	idx_t offset = 0;
	while (offset < datums.size()) {
		if (context.interrupted) {
			throw InterruptException();
		}
		idx_t batch = 0;
		idx_t bytes = 0;
		while (offset + batch < datums.size() && batch < MAX_DATUMS_PER_REQUEST) {
			auto next = EstimateDatumBytes(datums[offset + batch]);
			if (batch > 0 && bytes + next > MAX_REQUEST_BYTES) {
				break;
			}
			bytes += next;
			batch++;
		}
		auto body = BuildPutMetricDataRequest(bind.name_space, datums.data() + offset, batch);
		bind.client.PutMetricData(context, body);
		for (idx_t index = offset; index < offset + batch; index++) {
			result.SetValue(datums[index].source_row, Value("ok"));
		}
		offset += batch;
	}
}

} // namespace

void RegisterCloudwatchSendMetricsFunction(ExtensionLoader &loader) {
	ScalarFunctionSet set("send_cloudwatch_metrics");
	for (auto &arguments : vector<vector<LogicalType>> {
	         {LogicalType::ANY, LogicalType::VARCHAR},
	         {LogicalType::ANY, LogicalType::VARCHAR, LogicalType::VARCHAR},
	         {LogicalType::ANY, LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR}}) {
		ScalarFunction function(arguments, LogicalType::VARCHAR, CloudwatchSendMetricsFunction,
		                        CloudwatchSendMetricsBind);
		function.SetStability(FunctionStability::VOLATILE);
		function.SetNullHandling(FunctionNullHandling::SPECIAL_HANDLING);
		set.AddFunction(function);
	}
	loader.RegisterFunction(set);
}

} // namespace duckdb
