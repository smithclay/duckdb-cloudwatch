#include "cloudwatch_client.hpp"

#include "cloudwatch_signing.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/timestamp.hpp"
#include "duckdb/main/client_context.hpp"

#include "yyjson.hpp"

#ifdef __EMSCRIPTEN__
#include "duckdb/common/http_util.hpp"
#else
#include "httplib.hpp"
#endif

#include <chrono>
#include <cmath>
#include <cstdlib>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <thread>
#include <regex>

namespace duckdb {

namespace {

using namespace duckdb_yyjson; // NOLINT

string QueryEncode(const string &value) {
	static constexpr char HEX[] = "0123456789ABCDEF";
	string result;
	for (auto character : value) {
		auto byte = static_cast<unsigned char>(character);
		if ((byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') || (byte >= '0' && byte <= '9') ||
		    byte == '-' || byte == '_' || byte == '.' || byte == '~') {
			result += static_cast<char>(byte);
		} else {
			result += '%';
			result += HEX[byte >> 4];
			result += HEX[byte & 0x0F];
		}
	}
	return result;
}

string FormatQueryTimestamp(int64_t epoch_seconds) {
	auto time = std::time_t(epoch_seconds);
	std::tm utc {};
#ifdef _WIN32
	gmtime_s(&utc, &time);
#else
	gmtime_r(&time, &utc);
#endif
	std::ostringstream output;
	output << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ");
	return output.str();
}

//! Query-protocol timestamps are ISO8601, not epoch seconds. GetMetricData carries them at the
//! top level (StartTime/EndTime); PutMetricData carries one per datum, at
//! MetricData.member.N.Timestamp -- hence the suffix match rather than a fixed name.
bool IsQueryTimestampField(const string &prefix) {
	if (prefix == "StartTime" || prefix == "EndTime" || prefix == "Timestamp") {
		return true;
	}
	static const string suffix = ".Timestamp";
	return prefix.size() > suffix.size() && prefix.compare(prefix.size() - suffix.size(), suffix.size(), suffix) == 0;
}

//! Shortest representation that round-trips back to the same double. std::to_string would emit
//! six fixed decimals, which both truncates large metric values and pads every integral one.
string FormatQueryDouble(double value) {
	if (!std::isfinite(value)) {
		throw IOException("CloudWatch request contains a non-finite metric value");
	}
	for (int precision = 15; precision <= 17; precision++) {
		std::ostringstream output;
		output << std::setprecision(precision) << value;
		auto text = output.str();
		if (std::strtod(text.c_str(), nullptr) == value) {
			return text;
		}
	}
	std::ostringstream output;
	output << std::setprecision(17) << value;
	return output.str();
}

void AppendQueryValue(vector<string> &parts, yyjson_val *value, const string &prefix) {
	if (yyjson_is_obj(value)) {
		size_t index, max;
		yyjson_val *key, *child;
		yyjson_obj_foreach(value, index, max, key, child) {
			auto name = prefix.empty() ? string(yyjson_get_str(key)) : prefix + "." + yyjson_get_str(key);
			AppendQueryValue(parts, child, name);
		}
		return;
	}
	if (yyjson_is_arr(value)) {
		for (size_t index = 0; index < yyjson_arr_size(value); index++) {
			AppendQueryValue(parts, yyjson_arr_get(value, index), prefix + ".member." + std::to_string(index + 1));
		}
		return;
	}
	string text;
	if (yyjson_is_str(value)) {
		text = yyjson_get_str(value);
	} else if (yyjson_is_bool(value)) {
		text = yyjson_get_bool(value) ? "true" : "false";
	} else if (yyjson_is_int(value)) {
		auto integer = yyjson_get_sint(value);
		text = IsQueryTimestampField(prefix) ? FormatQueryTimestamp(integer) : std::to_string(integer);
	} else if (yyjson_is_real(value)) {
		text = FormatQueryDouble(yyjson_get_real(value));
	} else {
		throw IOException("CloudWatch query request contains an unsupported JSON value for %s", prefix);
	}
	parts.push_back(QueryEncode(prefix) + "=" + QueryEncode(text));
}

//! Flatten a JSON request body into an AWS query-protocol form body. The monitoring API takes no
//! JSON, so every call there is authored as JSON and encoded here.
string BuildMonitoringQueryBody(const string &action, const string &json_body) {
	auto document = yyjson_read(json_body.c_str(), json_body.size(), 0);
	if (!document) {
		throw IOException("CloudWatch %s request could not be encoded", action);
	}
	auto root = yyjson_doc_get_root(document);
	vector<string> parts = {"Action=" + action, "Version=2010-08-01"};
	try {
		if (!root || !yyjson_is_obj(root)) {
			yyjson_doc_free(document);
			throw IOException("CloudWatch %s request must be a JSON object", action);
		}
		AppendQueryValue(parts, root, string());
	} catch (...) {
		yyjson_doc_free(document);
		throw;
	}
	yyjson_doc_free(document);
	return StringUtil::Join(parts, "&");
}

string BuildGetMetricDataQueryBody(const string &json_body) {
	return BuildMonitoringQueryBody("GetMetricData", json_body);
}

string XmlText(const string &xml, const string &tag) {
	auto begin = xml.find("<" + tag + ">");
	if (begin == string::npos) {
		return string();
	}
	begin += tag.size() + 2;
	auto end = xml.find("</" + tag + ">", begin);
	return end == string::npos ? string() : xml.substr(begin, end - begin);
}

vector<string> XmlMembers(const string &xml) {
	vector<string> result;
	static const std::regex member("<member>([\\s\\S]*?)</member>");
	for (std::sregex_iterator item(xml.begin(), xml.end(), member), end; item != end; ++item) {
		result.push_back((*item)[1].str());
	}
	return result;
}

string XmlFirstMember(const string &xml) {
	auto begin = xml.find("<member>");
	if (begin == string::npos) {
		return string();
	}
	auto content_begin = begin + string("<member>").size();
	auto position = begin;
	idx_t depth = 0;
	while (position != string::npos) {
		auto open = xml.find("<member>", position);
		auto close = xml.find("</member>", position);
		if (open != string::npos && (close == string::npos || open < close)) {
			depth++;
			position = open + string("<member>").size();
		} else if (close != string::npos) {
			if (--depth == 0) {
				return xml.substr(content_begin, close - content_begin);
			}
			position = close + string("</member>").size();
		} else {
			break;
		}
	}
	throw IOException("CloudWatch GetMetricData returned malformed XML member nesting");
}

double XmlTimestampSeconds(const string &value) {
	timestamp_t timestamp;
	bool has_offset = false;
	string_t timezone;
	int32_t sub_micro_nanos = 0;
	if (Timestamp::TryConvertTimestampTZ(value.c_str(), value.size(), timestamp, true, has_offset, timezone,
	                                     &sub_micro_nanos) != TimestampCastResult::SUCCESS) {
		throw IOException("CloudWatch GetMetricData returned malformed timestamp '%s'", value);
	}
	int64_t nanos;
	if (!Timestamp::TryGetEpochNanoSeconds(timestamp, nanos)) {
		throw IOException("CloudWatch GetMetricData returned an out-of-range timestamp '%s'", value);
	}
	return static_cast<double>(nanos + sub_micro_nanos) / 1000000000.0;
}

string ConvertGetMetricDataXml(const string &response) {
	if (response.empty() || response.front() != '<') {
		return response;
	}
	auto result_container = XmlText(response, "MetricDataResults");
	if (result_container.empty()) {
		throw IOException("CloudWatch GetMetricData returned XML without MetricDataResults");
	}
	auto result = XmlFirstMember(result_container);
	if (result.empty()) {
		throw IOException("CloudWatch GetMetricData returned XML with no metric data result members");
	}

	auto document = yyjson_mut_doc_new(nullptr);
	auto root = yyjson_mut_obj(document);
	yyjson_mut_doc_set_root(document, root);
	auto result_array = yyjson_mut_arr(document);
	{
		auto timestamps = XmlMembers(XmlText(result, "Timestamps"));
		auto values = XmlMembers(XmlText(result, "Values"));
		if (timestamps.size() != values.size()) {
			yyjson_mut_doc_free(document);
			throw IOException("CloudWatch GetMetricData returned mismatched timestamp/value arrays");
		}
		auto object = yyjson_mut_obj(document);
		for (const auto &key : {"Id", "Label", "StatusCode"}) {
			auto value = XmlText(result, key);
			if (!value.empty()) {
				yyjson_mut_obj_add_strcpy(document, object, key, value.c_str());
			}
		}
		auto json_timestamps = yyjson_mut_arr(document);
		auto json_values = yyjson_mut_arr(document);
		for (idx_t index = 0; index < timestamps.size(); index++) {
			char *end = nullptr;
			auto value = std::strtod(values[index].c_str(), &end);
			if (!end || *end != '\0') {
				yyjson_mut_doc_free(document);
				throw IOException("CloudWatch GetMetricData returned malformed value '%s'", values[index]);
			}
			yyjson_mut_arr_add_real(document, json_timestamps, XmlTimestampSeconds(timestamps[index]));
			yyjson_mut_arr_add_real(document, json_values, value);
		}
		yyjson_mut_obj_add_val(document, object, "Timestamps", json_timestamps);
		yyjson_mut_obj_add_val(document, object, "Values", json_values);
		yyjson_mut_arr_add_val(result_array, object);
	}
	yyjson_mut_obj_add_val(document, root, "MetricDataResults", result_array);
	auto token = XmlText(response, "NextToken");
	if (!token.empty()) {
		yyjson_mut_obj_add_strcpy(document, root, "NextToken", token.c_str());
	}
	size_t size = 0;
	auto serialized = yyjson_mut_write(document, 0, &size);
	yyjson_mut_doc_free(document);
	if (!serialized) {
		throw IOException("CloudWatch GetMetricData XML response could not be converted");
	}
	string converted(serialized, size);
	free(serialized);
	return converted;
}

string AwsServiceName(CloudwatchService service) {
	switch (service) {
	case CloudwatchService::LOGS:
		return "logs";
	case CloudwatchService::MONITORING:
		return "monitoring";
	case CloudwatchService::XRAY:
		return "xray";
	}
	throw InternalException("Unknown CloudWatch AWS service");
}

string DefaultCloudwatchHost(const string &region, CloudwatchService service) {
	auto suffix = StringUtil::StartsWith(region, "cn-") ? "amazonaws.com.cn" : "amazonaws.com";
	return AwsServiceName(service) + "." + region + "." + suffix;
}

string TrimEndpoint(string endpoint) {
	StringUtil::Trim(endpoint);
	while (!endpoint.empty() && endpoint.back() == '/') {
		endpoint.pop_back();
	}
	return endpoint;
}

string AuthorityFromUrl(const string &url) {
	auto start = url.find("://");
	start = start == string::npos ? 0 : start + 3;
	auto end = url.find('/', start);
	return url.substr(start, end == string::npos ? string::npos : end - start);
}

string CurrentAmzDate() {
	auto now = std::chrono::system_clock::now();
	auto time = std::chrono::system_clock::to_time_t(now);
	std::tm utc {};
#ifdef _WIN32
	gmtime_s(&utc, &time);
#else
	gmtime_r(&time, &utc);
#endif
	std::ostringstream output;
	output << std::put_time(&utc, "%Y%m%dT%H%M%SZ");
	return output.str();
}

void SleepCheckingInterrupt(ClientContext &context, uint64_t seconds) {
	auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
	while (std::chrono::steady_clock::now() < deadline) {
		if (context.interrupted) {
			throw InterruptException();
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}
}

uint64_t RetryDelay(uint64_t attempt) {
	return MinValue<uint64_t>(uint64_t(1) << MinValue<uint64_t>(attempt, 6), 60);
}

bool IsRetryableStatus(int status, const string &body) {
	return status == 429 || status >= 500 || body.find("Throttling") != string::npos ||
	       body.find("ServiceUnavailable") != string::npos;
}

bool IsDefinitelyRejectedThrottle(int status, const string &body) {
	return status == 429 || body.find("Throttling") != string::npos;
}

bool IsExpiredCredentials(int status, const string &body) {
	return status == 401 || status == 403 ||
	       (status == 400 &&
	        (body.find("ExpiredToken") != string::npos || body.find("RequestExpired") != string::npos));
}

#ifndef __EMSCRIPTEN__
bool IsRetryableTransportError(duckdb_httplib_openssl::Error error) {
	switch (error) {
	case duckdb_httplib_openssl::Error::SSLLoadingCerts:
	case duckdb_httplib_openssl::Error::SSLServerVerification:
	case duckdb_httplib_openssl::Error::SSLServerHostnameVerification:
		return false;
	default:
		return true;
	}
}

bool IsPreSendTransportError(duckdb_httplib_openssl::Error error) {
	switch (error) {
	case duckdb_httplib_openssl::Error::Connection:
	case duckdb_httplib_openssl::Error::ConnectionTimeout:
	case duckdb_httplib_openssl::Error::BindIPAddress:
	case duckdb_httplib_openssl::Error::ProxyConnection:
		return true;
	default:
		return false;
	}
}
#endif

} // namespace

CloudwatchClient::CloudwatchClient() = default;
CloudwatchClient::~CloudwatchClient() {
}

string CloudwatchClient::BaseUrl(CloudwatchService service) const {
	if (endpoint.empty()) {
		return "https://" + DefaultCloudwatchHost(credentials.region, service);
	}
	auto normalized = TrimEndpoint(endpoint);
	if (StringUtil::StartsWith(normalized, "http://") || StringUtil::StartsWith(normalized, "https://")) {
		return normalized;
	}
	return "https://" + normalized;
}

string CloudwatchClient::Host(CloudwatchService service) const {
	return AuthorityFromUrl(BaseUrl(service));
}

#ifndef __EMSCRIPTEN__
duckdb_httplib_openssl::Client &CloudwatchClient::GetConnection(CloudwatchService service) const {
	if (!connection) {
		// Each client instance is dedicated to one endpoint/service by its owning scan.
		connection = make_uniq<duckdb_httplib_openssl::Client>(BaseUrl(service));
		connection->set_connection_timeout(static_cast<time_t>(timeout_seconds), 0);
		connection->set_read_timeout(static_cast<time_t>(timeout_seconds), 0);
		connection->set_keep_alive(true);
	}
	return *connection;
}
#endif

string CloudwatchClient::FilterLogEvents(ClientContext &context, const string &request_body) const {
	return Post(context, CloudwatchService::LOGS, "/", "Logs_20140328.FilterLogEvents", "application/x-amz-json-1.1",
	            request_body);
}

string CloudwatchClient::DescribeLogGroups(ClientContext &context, const string &request_body) const {
	return Post(context, CloudwatchService::LOGS, "/", "Logs_20140328.DescribeLogGroups", "application/x-amz-json-1.1",
	            request_body);
}

string CloudwatchClient::PutLogEvents(ClientContext &context, const string &request_body) const {
	std::lock_guard<std::mutex> write_guard(write_mutex);
	return Post(context, CloudwatchService::LOGS, "/", "Logs_20140328.PutLogEvents", "application/x-amz-json-1.1",
	            request_body, CloudwatchRetryPolicy(false, false));
}

string CloudwatchClient::StartQuery(ClientContext &context, const string &request_body) const {
	// Not idempotent on purpose: a duplicate StartQuery scans (and bills for) the window twice.
	// LimitExceededException here is the concurrent-query cap, which clears on its own.
	return Post(context, CloudwatchService::LOGS, "/", "Logs_20140328.StartQuery", "application/x-amz-json-1.1",
	            request_body, CloudwatchRetryPolicy(false, true));
}

string CloudwatchClient::GetQueryResults(ClientContext &context, const string &request_body) const {
	return Post(context, CloudwatchService::LOGS, "/", "Logs_20140328.GetQueryResults", "application/x-amz-json-1.1",
	            request_body);
}

string CloudwatchClient::StopQuery(ClientContext &context, const string &request_body) const {
	return Post(context, CloudwatchService::LOGS, "/", "Logs_20140328.StopQuery", "application/x-amz-json-1.1",
	            request_body);
}

string CloudwatchClient::CreateLogGroup(ClientContext &context, const string &request_body) const {
	std::lock_guard<std::mutex> write_guard(write_mutex);
	return Post(context, CloudwatchService::LOGS, "/", "Logs_20140328.CreateLogGroup", "application/x-amz-json-1.1",
	            request_body);
}

string CloudwatchClient::CreateLogStream(ClientContext &context, const string &request_body) const {
	std::lock_guard<std::mutex> write_guard(write_mutex);
	return Post(context, CloudwatchService::LOGS, "/", "Logs_20140328.CreateLogStream", "application/x-amz-json-1.1",
	            request_body);
}

string CloudwatchClient::DeleteLogGroup(ClientContext &context, const string &request_body) const {
	std::lock_guard<std::mutex> write_guard(write_mutex);
	return Post(context, CloudwatchService::LOGS, "/", "Logs_20140328.DeleteLogGroup", "application/x-amz-json-1.1",
	            request_body);
}

string CloudwatchClient::PutRetentionPolicy(ClientContext &context, const string &request_body) const {
	std::lock_guard<std::mutex> write_guard(write_mutex);
	return Post(context, CloudwatchService::LOGS, "/", "Logs_20140328.PutRetentionPolicy", "application/x-amz-json-1.1",
	            request_body);
}

string CloudwatchClient::DescribeLogStreams(ClientContext &context, const string &request_body) const {
	return Post(context, CloudwatchService::LOGS, "/", "Logs_20140328.DescribeLogStreams", "application/x-amz-json-1.1",
	            request_body);
}

bool CloudwatchClient::TryPostLogs(ClientContext &context, const string &target, const string &request_body,
                                   string &response_body, string &error_body) const {
	// Creation and deletion are the only callers, and both mutate; serialize like the other writes.
	std::lock_guard<std::mutex> write_guard(write_mutex);
	return PostInternal(context, CloudwatchService::LOGS, "/", target, "application/x-amz-json-1.1", request_body,
	                    CloudwatchRetryPolicy(), response_body, &error_body);
}

string CloudwatchClient::DescribeAlarms(ClientContext &context, const string &request_body) const {
	return Post(context, CloudwatchService::MONITORING, "/", string(),
	            "application/x-www-form-urlencoded; charset=utf-8", request_body);
}

string CloudwatchClient::GetMetricData(ClientContext &context, const string &request_body) const {
	auto response = Post(context, CloudwatchService::MONITORING, "/", string(),
	                     "application/x-www-form-urlencoded; charset=utf-8", BuildGetMetricDataQueryBody(request_body));
	return ConvertGetMetricDataXml(response);
}

string CloudwatchClient::PutMetricData(ClientContext &context, const string &request_body) const {
	// Not idempotent: PutMetricData has no request id, so a retry after a response we never saw
	// would double-count the datums it carries. Only responses proving the call was rejected
	// before doing any work may be retried.
	std::lock_guard<std::mutex> write_guard(write_mutex);
	return Post(context, CloudwatchService::MONITORING, "/", string(),
	            "application/x-www-form-urlencoded; charset=utf-8",
	            BuildMonitoringQueryBody("PutMetricData", request_body), CloudwatchRetryPolicy(false));
}

string CloudwatchClient::GetServiceGraph(ClientContext &context, const string &request_body) const {
	return Post(context, CloudwatchService::XRAY, "/ServiceGraph", string(), "application/json", request_body);
}

string CloudwatchClient::Post(ClientContext &context, CloudwatchService service, const string &path,
                              const string &target, const string &content_type, const string &request_body,
                              CloudwatchRetryPolicy policy) const {
	string response_body;
	PostInternal(context, service, path, target, content_type, request_body, policy, response_body, nullptr);
	return response_body;
}

bool CloudwatchClient::PostInternal(ClientContext &context, CloudwatchService service, const string &path,
                                    const string &target, const string &content_type, const string &request_body,
                                    CloudwatchRetryPolicy policy, string &response_body, string *error_body) const {
	const bool idempotent = policy.idempotent;
	//! Report a non-2xx either by filling the caller's buffer or by throwing.
	auto fail = [&](const string &message, const string &body) -> bool {
		if (!error_body) {
			throw IOException("%s", message);
		}
		*error_body = body.empty() ? message : body;
		return false;
	};
	auto retryable_response = [&](int status, const string &body) {
		if (policy.retry_on_limit_exceeded && body.find("LimitExceededException") != string::npos) {
			return true;
		}
		return idempotent ? IsRetryableStatus(status, body) : IsDefinitelyRejectedThrottle(status, body);
	};
	bool refreshed_credentials = false;
	for (uint64_t attempt = 0;; attempt++) {
		if (context.interrupted) {
			throw InterruptException();
		}
		CloudwatchSigningRequest signing_request;
		signing_request.service = AwsServiceName(service);
		signing_request.host = Host(service);
		signing_request.content_type = content_type;
		signing_request.target = target;
		signing_request.uri = path;
		signing_request.body = request_body;
		signing_request.amz_date = CurrentAmzDate();
		auto signed_headers = SignCloudwatchRequest(credentials, signing_request);

#ifdef __EMSCRIPTEN__
		auto url = BaseUrl(service) + path;
		auto &http_util = HTTPUtil::Get(*context.db);
		auto params = http_util.InitializeParameters(context, url);
		params->timeout = timeout_seconds;
		params->retries = 0;
		params->keep_alive = true;
		params->follow_location = false;
		HTTPHeaders headers;
		headers.Insert("Authorization", signed_headers.authorization);
		headers.Insert("X-Amz-Date", signed_headers.amz_date);
		if (!target.empty()) {
			headers.Insert("X-Amz-Target", target);
		}
		headers.Insert("Content-Type", content_type);
		if (!signed_headers.security_token.empty()) {
			headers.Insert("X-Amz-Security-Token", signed_headers.security_token);
		}
		PostRequestInfo request(url, headers, *params, reinterpret_cast<const_data_ptr_t>(request_body.data()),
		                        request_body.size());
		request.try_request = true;
		auto response = http_util.Request(request);
		if (response && response->Success()) {
			response_body = response->body;
			return true;
		}
		auto status = response ? static_cast<int>(response->status) : 0;
		auto body = response ? response->body : string();
		if (IsExpiredCredentials(status, body) && !refreshed_credentials) {
			credentials = GetCloudwatchCredentials(context, credentials.secret_name, credentials.region);
			refreshed_credentials = true;
			continue;
		}
		const bool safe_retry = response && retryable_response(status, body);
		if (attempt >= retries || !safe_retry) {
			return fail(StringUtil::Format("AWS %s request to %s failed%s%s", AwsServiceName(service), BaseUrl(service),
			                               status ? StringUtil::Format(" with HTTP %d", status) : string(),
			                               body.empty() ? string() : ": " + body),
			            body);
		}
#else
		duckdb_httplib_openssl::Headers headers = {
		    {"Authorization", signed_headers.authorization},
		    {"X-Amz-Date", signed_headers.amz_date},
		    {"Host", signing_request.host},
		    {"Content-Type", content_type},
		};
		if (!target.empty()) {
			headers.emplace("X-Amz-Target", target);
		}
		if (!signed_headers.security_token.empty()) {
			headers.emplace("X-Amz-Security-Token", signed_headers.security_token);
		}
		// Keep the transport headers byte-for-byte aligned with the values covered by SigV4. In
		// particular, cpp-httplib otherwise synthesizes Host and Content-Type after signing.
		auto response = GetConnection(service).Post(path, headers, request_body, string());
		if (response && response->status >= 200 && response->status < 300) {
			response_body = response->body;
			return true;
		}
		if (!response) {
			auto error = response.error();
			connection.reset();
			const bool safe_retry = idempotent ? IsRetryableTransportError(error) : IsPreSendTransportError(error);
			if (attempt >= retries || !safe_retry) {
				// A transport failure carries no AWS error code, so there is nothing for a
				// TryPostLogs caller to classify: surface it as an exception either way.
				throw IOException("AWS %s request to %s failed: %s", AwsServiceName(service), BaseUrl(service),
				                  duckdb_httplib_openssl::to_string(error));
			}
		} else if (IsExpiredCredentials(response->status, response->body) && !refreshed_credentials) {
			credentials = GetCloudwatchCredentials(context, credentials.secret_name, credentials.region);
			refreshed_credentials = true;
			continue;
		} else if (attempt >= retries || !retryable_response(response->status, response->body)) {
			return fail(StringUtil::Format("AWS %s returned HTTP %d: %s", AwsServiceName(service), response->status,
			                               response->body),
			            response->body);
		}
#endif
		SleepCheckingInterrupt(context, RetryDelay(attempt));
	}
}

} // namespace duckdb
