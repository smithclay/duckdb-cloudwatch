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

	credentials.session_token = "temporary-token";
	result = SignCloudwatchRequest(credentials, "logs.us-east-1.amazonaws.com", "Logs_20140328.FilterLogEvents", body,
	                               "20150830T123600Z");
	assert(result.security_token == "temporary-token");
	assert(result.authorization.find("x-amz-security-token;x-amz-target") != string::npos);
	return 0;
}
