#include "cloudwatch_secret.hpp"
#include "cloudwatch_signing.hpp"

#include <cassert>
#include <stdexcept>

// Release builds define NDEBUG; keep these standalone test assertions active.
#undef assert
#define assert(condition)                                                                                              \
	do {                                                                                                               \
		if (!(condition)) {                                                                                            \
			throw std::runtime_error("assertion failed: " #condition);                                                 \
		}                                                                                                              \
	} while (false)

using namespace duckdb;

int main() {
	CloudwatchCredentials credentials;
	credentials.access_key_id = "AKIDEXAMPLE";
	credentials.secret_access_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
	credentials.region = "us-east-1";

	const string body = "{\"limit\":1,\"logGroupName\":\"test\"}";
	auto result = SignCloudwatchRequest(credentials, "logs.us-east-1.amazonaws.com", "Logs_20140328.FilterLogEvents",
	                                    body, "20150830T123600Z");
	assert(result.authorization == "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/logs/aws4_request, "
	                               "SignedHeaders=content-type;host;x-amz-date;x-amz-target, "
	                               "Signature=77bca1f8fee0c4d6fa23dc1662934a8fd995b9a39173d1e63ab9f14358963438");
	auto filter_authorization = result.authorization;
	result = SignCloudwatchRequest(credentials, "logs.us-east-1.amazonaws.com", "Logs_20140328.DescribeLogGroups", body,
	                               "20150830T123600Z");
	assert(result.authorization != filter_authorization);
	auto describe_authorization = result.authorization;
	result = SignCloudwatchRequest(credentials, "logs.us-east-1.amazonaws.com", "Logs_20140328.PutLogEvents", body,
	                               "20150830T123600Z");
	assert(result.authorization != filter_authorization);
	assert(result.authorization != describe_authorization);
	assert(result.authorization.find("SignedHeaders=content-type;host;x-amz-date;x-amz-target") != string::npos);

	credentials.session_token = "temporary-token";
	result = SignCloudwatchRequest(credentials, "logs.us-east-1.amazonaws.com", "Logs_20140328.FilterLogEvents", body,
	                               "20150830T123600Z");
	assert(result.security_token == "temporary-token");
	assert(result.authorization.find("x-amz-security-token;x-amz-target") != string::npos);

	credentials.session_token.clear();
	CloudwatchSigningRequest monitoring;
	monitoring.service = "monitoring";
	monitoring.host = "monitoring.us-east-1.amazonaws.com";
	monitoring.content_type = "application/x-www-form-urlencoded; charset=utf-8";
	monitoring.body = "Action=DescribeAlarms&Version=2010-08-01";
	monitoring.amz_date = "20150830T123600Z";
	result = SignCloudwatchRequest(credentials, monitoring);
	assert(result.authorization.find("/us-east-1/monitoring/aws4_request") != string::npos);
	assert(result.authorization.find("SignedHeaders=content-type;host;x-amz-date") != string::npos);
	assert(result.authorization.find("x-amz-target") == string::npos);

	CloudwatchSigningRequest xray;
	xray.service = "xray";
	xray.host = "xray.us-east-1.amazonaws.com";
	xray.content_type = "application/json";
	xray.uri = "/ServiceGraph";
	xray.body = R"({"StartTime":1,"EndTime":2})";
	xray.amz_date = "20150830T123600Z";
	auto xray_result = SignCloudwatchRequest(credentials, xray);
	assert(xray_result.authorization.find("/us-east-1/xray/aws4_request") != string::npos);
	xray.uri = "/";
	assert(SignCloudwatchRequest(credentials, xray).authorization != xray_result.authorization);
	return 0;
}
