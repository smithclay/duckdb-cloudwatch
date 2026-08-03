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

string DefaultCloudwatchHost(const string &region) {
	auto suffix = StringUtil::StartsWith(region, "cn-") ? "amazonaws.com.cn" : "amazonaws.com";
	return "logs." + region + "." + suffix;
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
#endif

} // namespace

CloudwatchClient::CloudwatchClient() = default;
CloudwatchClient::~CloudwatchClient() {
}

string CloudwatchClient::BaseUrl() const {
	if (endpoint.empty()) {
		return "https://" + DefaultCloudwatchHost(credentials.region);
	}
	auto normalized = TrimEndpoint(endpoint);
	if (StringUtil::StartsWith(normalized, "http://") || StringUtil::StartsWith(normalized, "https://")) {
		return normalized;
	}
	return "https://" + normalized;
}

string CloudwatchClient::Host() const {
	return AuthorityFromUrl(BaseUrl());
}

#ifndef __EMSCRIPTEN__
duckdb_httplib_openssl::Client &CloudwatchClient::GetConnection() const {
	if (!connection) {
		connection = make_uniq<duckdb_httplib_openssl::Client>(BaseUrl());
		connection->set_connection_timeout(static_cast<time_t>(timeout_seconds), 0);
		connection->set_read_timeout(static_cast<time_t>(timeout_seconds), 0);
		connection->set_keep_alive(true);
	}
	return *connection;
}
#endif

string CloudwatchClient::FilterLogEvents(ClientContext &context, const string &request_body) const {
	return Post(context, "Logs_20140328.FilterLogEvents", request_body);
}

string CloudwatchClient::DescribeLogGroups(ClientContext &context, const string &request_body) const {
	return Post(context, "Logs_20140328.DescribeLogGroups", request_body);
}

string CloudwatchClient::Post(ClientContext &context, const string &target, const string &request_body) const {
	bool refreshed_credentials = false;
	for (uint64_t attempt = 0;; attempt++) {
		if (context.interrupted) {
			throw InterruptException();
		}
		auto signed_headers = SignCloudwatchRequest(credentials, Host(), target, request_body, CurrentAmzDate());

#ifdef __EMSCRIPTEN__
		auto url = BaseUrl() + "/";
		auto &http_util = HTTPUtil::Get(*context.db);
		auto params = http_util.InitializeParameters(context, url);
		params->timeout = timeout_seconds;
		params->retries = 0;
		params->keep_alive = true;
		params->follow_location = false;
		HTTPHeaders headers;
		headers.Insert("Authorization", signed_headers.authorization);
		headers.Insert("X-Amz-Date", signed_headers.amz_date);
		headers.Insert("X-Amz-Target", target);
		headers.Insert("Content-Type", "application/x-amz-json-1.1");
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
		if ((status == 401 || status == 403) && !refreshed_credentials) {
			credentials = GetCloudwatchCredentials(context, credentials.secret_name, credentials.region);
			refreshed_credentials = true;
			continue;
		}
		if (attempt >= retries || !response || !IsRetryableStatus(status, body)) {
			throw IOException("CloudWatch Logs request to %s failed%s%s", BaseUrl(),
			                  status ? StringUtil::Format(" with HTTP %d", status) : string(),
			                  body.empty() ? string() : ": " + body);
		}
#else
		duckdb_httplib_openssl::Headers headers = {
		    {"Authorization", signed_headers.authorization},
		    {"X-Amz-Date", signed_headers.amz_date},
		    {"X-Amz-Target", target},
		};
		if (!signed_headers.security_token.empty()) {
			headers.emplace("X-Amz-Security-Token", signed_headers.security_token);
		}
		auto response = GetConnection().Post("/", headers, request_body, "application/x-amz-json-1.1");
		if (response && response->status >= 200 && response->status < 300) {
			return response->body;
		}
		if (!response) {
			auto error = response.error();
			connection.reset();
			if (attempt >= retries || !IsRetryableTransportError(error)) {
				throw IOException("CloudWatch Logs request to %s failed: %s", BaseUrl(),
				                  duckdb_httplib_openssl::to_string(error));
			}
		} else if ((response->status == 401 || response->status == 403) && !refreshed_credentials) {
			credentials = GetCloudwatchCredentials(context, credentials.secret_name, credentials.region);
			refreshed_credentials = true;
			continue;
		} else if (attempt >= retries || !IsRetryableStatus(response->status, response->body)) {
			throw IOException("CloudWatch Logs returned HTTP %d: %s", response->status, response->body);
		}
#endif
		SleepCheckingInterrupt(context, RetryDelay(attempt));
	}
}

} // namespace duckdb
