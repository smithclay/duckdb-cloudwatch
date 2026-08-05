#include "cloudwatch_json.hpp"

#include <cassert>
#include <functional>
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

static bool Throws(const std::function<void()> &function) {
	try {
		function();
		return false;
	} catch (const std::exception &) {
		return true;
	}
}

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

	vector<CloudwatchPutLogEvent> put_events = {{3000, "later-a", 0}, {1000, "first", 1}, {3000, "later-b", 2}};
	auto batches = SortAndPlanCloudwatchPutEvents(put_events);
	assert(batches.size() == 1 && batches[0].offset == 0 && batches[0].count == 3);
	assert(put_events[0].source_row == 1);
	assert(put_events[1].source_row == 0);
	assert(put_events[2].source_row == 2); // stable for equal timestamps

	auto put_body = BuildCloudwatchPutEventsRequest("/app/orders", "duckdb", put_events.data(), put_events.size());
	assert(put_body.find("\"logGroupName\":\"/app/orders\"") != string::npos);
	assert(put_body.find("\"logStreamName\":\"duckdb\"") != string::npos);
	assert(put_body.find("\"timestamp\":1000") < put_body.find("\"timestamp\":3000"));
	put_events = {{1, "quote \" newline\n and é", 0}};
	put_body = BuildCloudwatchPutEventsRequest("group", "stream", put_events.data(), 1);
	assert(put_body.find("quote \\\" newline\\n and é") != string::npos);
	assert(put_events[0].message.size() == 23); // API byte accounting uses UTF-8 bytes, not JSON escaping

	// Exactly 1 MiB including AWS's 26-byte per-event charge stays in one batch; one more byte splits.
	const idx_t half_message = CLOUDWATCH_PUT_MAX_BYTES / 2 - CLOUDWATCH_PUT_EVENT_OVERHEAD;
	put_events = {{1, string(half_message, 'a'), 0}, {2, string(half_message, 'b'), 1}};
	batches = SortAndPlanCloudwatchPutEvents(put_events);
	assert(batches.size() == 1 && batches[0].count == 2);
	put_events[1].message.push_back('b');
	batches = SortAndPlanCloudwatchPutEvents(put_events);
	assert(batches.size() == 2 && batches[0].count == 1 && batches[1].count == 1);

	put_events.assign(CLOUDWATCH_PUT_MAX_EVENTS, {1, "x", 0});
	batches = SortAndPlanCloudwatchPutEvents(put_events);
	assert(batches.size() == 1 && batches[0].count == CLOUDWATCH_PUT_MAX_EVENTS);
	put_events.push_back({1, "x", CLOUDWATCH_PUT_MAX_EVENTS});
	batches = SortAndPlanCloudwatchPutEvents(put_events);
	assert(batches.size() == 2 && batches[1].count == 1);

	put_events = {{0, "a", 0}, {CLOUDWATCH_PUT_MAX_SPAN_MS, "b", 1}};
	assert(SortAndPlanCloudwatchPutEvents(put_events).size() == 1);
	put_events = {{0, "a", 0}, {CLOUDWATCH_PUT_MAX_SPAN_MS + 1, "b", 1}};
	assert(SortAndPlanCloudwatchPutEvents(put_events).size() == 2);
	put_events = {{1, "", 7}};
	assert(Throws([&] { SortAndPlanCloudwatchPutEvents(put_events); }));
	put_events = {{1, string(CLOUDWATCH_PUT_MAX_BYTES - CLOUDWATCH_PUT_EVENT_OVERHEAD + 1, 'x'), 8}};
	assert(Throws([&] { SortAndPlanCloudwatchPutEvents(put_events); }));

	auto put_response = ParseCloudwatchPutEventsResponse("{}");
	assert(!put_response.HasRejections());
	put_response = ParseCloudwatchPutEventsResponse(R"({
  "rejectedLogEventsInfo": {
    "expiredLogEventEndIndex": 1,
    "tooOldLogEventEndIndex": 2,
    "tooNewLogEventStartIndex": 9
  },
  "rejectedEntityInfo": {"errorType": "InvalidEntity"}
})");
	assert(put_response.HasRejections());
	assert(put_response.has_expired_end && put_response.expired_end == 1);
	assert(put_response.has_too_old_end && put_response.too_old_end == 2);
	assert(put_response.has_too_new_start && put_response.too_new_start == 9);
	assert(put_response.has_rejected_entity && put_response.rejected_entity_error == "InvalidEntity");
	return 0;
}
