#include "cloudwatch_client.hpp"

#include "cloudwatch_signing.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/client_context.hpp"

#ifdef __EMSCRIPTEN__
#include "duckdb/common/http_util.hpp"
#else
#include "httplib.hpp"
#endif

#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <thread>

namespace duckdb {

namespace {

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
	            request_body, false);
}

string CloudwatchClient::DescribeAlarms(ClientContext &context, const string &request_body) const {
	return Post(context, CloudwatchService::MONITORING, "/", string(),
	            "application/x-www-form-urlencoded; charset=utf-8", request_body);
}

string CloudwatchClient::GetMetricData(ClientContext &context, const string &request_body) const {
	return Post(context, CloudwatchService::MONITORING, "/", "GraniteServiceVersion20100801.GetMetricData",
	            "application/x-amz-json-1.1", request_body);
}

string CloudwatchClient::GetServiceGraph(ClientContext &context, const string &request_body) const {
	return Post(context, CloudwatchService::XRAY, "/ServiceGraph", string(), "application/json", request_body);
}

string CloudwatchClient::Post(ClientContext &context, CloudwatchService service, const string &path,
                              const string &target, const string &content_type, const string &request_body,
                              bool idempotent) const {
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
			return response->body;
		}
		auto status = response ? static_cast<int>(response->status) : 0;
		auto body = response ? response->body : string();
		if (IsExpiredCredentials(status, body) && !refreshed_credentials) {
			credentials = GetCloudwatchCredentials(context, credentials.secret_name, credentials.region);
			refreshed_credentials = true;
			continue;
		}
		const bool safe_retry =
		    response && (idempotent ? IsRetryableStatus(status, body) : IsDefinitelyRejectedThrottle(status, body));
		if (attempt >= retries || !safe_retry) {
			throw IOException("AWS %s request to %s failed%s%s", AwsServiceName(service), BaseUrl(service),
			                  status ? StringUtil::Format(" with HTTP %d", status) : string(),
			                  body.empty() ? string() : ": " + body);
		}
#else
		duckdb_httplib_openssl::Headers headers = {
		    {"Authorization", signed_headers.authorization},
		    {"X-Amz-Date", signed_headers.amz_date},
		};
		if (!target.empty()) {
			headers.emplace("X-Amz-Target", target);
		}
		if (!signed_headers.security_token.empty()) {
			headers.emplace("X-Amz-Security-Token", signed_headers.security_token);
		}
		auto response = GetConnection(service).Post(path, headers, request_body, content_type);
		if (response && response->status >= 200 && response->status < 300) {
			return response->body;
		}
		if (!response) {
			auto error = response.error();
			connection.reset();
			const bool safe_retry = idempotent ? IsRetryableTransportError(error) : IsPreSendTransportError(error);
			if (attempt >= retries || !safe_retry) {
				throw IOException("AWS %s request to %s failed: %s", AwsServiceName(service), BaseUrl(service),
				                  duckdb_httplib_openssl::to_string(error));
			}
		} else if (IsExpiredCredentials(response->status, response->body) && !refreshed_credentials) {
			credentials = GetCloudwatchCredentials(context, credentials.secret_name, credentials.region);
			refreshed_credentials = true;
			continue;
		} else if (attempt >= retries ||
		           !(idempotent ? IsRetryableStatus(response->status, response->body)
		                        : IsDefinitelyRejectedThrottle(response->status, response->body))) {
			throw IOException("AWS %s returned HTTP %d: %s", AwsServiceName(service), response->status, response->body);
		}
#endif
		SleepCheckingInterrupt(context, RetryDelay(attempt));
	}
}

} // namespace duckdb
