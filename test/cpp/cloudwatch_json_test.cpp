#include "cloudwatch_json.hpp"

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
	CloudwatchFilterRequest request;
	request.log_group = "/aws/lambda/orders";
	request.filter_pattern = "ERROR";
	request.log_streams = {"stream-a", "stream-b"};
	request.next_token = "next";
	request.start_time_ms = 1000;
	request.end_time_ms = 2000;
	request.limit = 25;
	request.ascending = true;
	request.unmask = true;
	auto body = BuildCloudwatchFilterRequest(request);
	assert(body.find("\"logGroupName\":\"/aws/lambda/orders\"") != string::npos);
	assert(body.find("\"filterPattern\":\"ERROR\"") != string::npos);
	assert(body.find("\"logStreamNames\":[\"stream-a\",\"stream-b\"]") != string::npos);
	assert(body.find("\"startFromHead\":true") != string::npos);
	assert(body.find("\"unmask\":true") != string::npos);

	request.log_group = "arn:aws:logs:us-east-1:123456789012:log-group:orders";
	body = BuildCloudwatchFilterRequest(request);
	assert(body.find("\"logGroupIdentifier\":") != string::npos);
	assert(body.find("\"logGroupName\":") == string::npos);

	const string response = R"({
  "events": [{
    "eventId": "event-1",
    "ingestionTime": 1700000000123,
    "logStreamName": "stream-a",
    "message": "hello",
    "timestamp": 1700000000000
  }],
  "nextToken": "token-2"
})";
	vector<CloudwatchLogEvent> events;
	auto token = ParseCloudwatchFilterResponse(response, events);
	assert(token == "token-2");
	assert(events.size() == 1);
	assert(events[0].event_id == "event-1");
	assert(events[0].timestamp_ms == 1700000000000);
	assert(events[0].ingestion_time_ms == 1700000000123);
	assert(events[0].log_stream_name == "stream-a");
	assert(events[0].message == "hello");

	events.clear();
	ParseCloudwatchFilterResponse(R"({"events":[{"message":"no timestamps"}]})", events);
	assert(events.size() == 1);
	assert(events[0].timestamp_ms == -1);
	assert(events[0].ingestion_time_ms == -1);

	auto describe = BuildCloudwatchDescribeGroupsRequest("group-token");
	assert(describe.find("\"nextToken\":\"group-token\"") != string::npos);
	assert(describe.find("\"limit\":50") != string::npos);
	vector<string> groups;
	auto group_token = ParseCloudwatchDescribeGroupsResponse(
	    R"({"logGroups":[{"logGroupName":"/aws/lambda/orders"},{"logGroupName":"custom"}],"nextToken":"more"})",
	    groups);
	assert(group_token == "more");
	assert(groups.size() == 2);
	assert(groups[0] == "/aws/lambda/orders");

	auto resource = BuildCloudwatchResourceAttributes("us-east-1", "/aws/lambda/orders", "stream-a");
	assert(resource.find("\"cloud.provider\":\"aws\"") != string::npos);
	assert(resource.find("\"aws.log.group.names\":[\"/aws/lambda/orders\"]") != string::npos);
	assert(resource.find("\"aws.log.stream.names\":[\"stream-a\"]") != string::npos);
	auto attributes = BuildCloudwatchLogAttributes("event-1");
	assert(attributes == "{\"aws.cloudwatch.log.event_id\":\"event-1\"}");
	return 0;
}
