#include "alerts_table.hpp"
#include "cloudwatch_json.hpp"
#include "service_dependencies.hpp"

#include <cassert>
#include <cmath>
#include <stdexcept>

#undef assert
#define assert(condition)                                                                                              \
	do {                                                                                                               \
		if (!(condition)) {                                                                                            \
			throw std::runtime_error("assertion failed: " #condition);                                                 \
		}                                                                                                              \
	} while (false)

using namespace duckdb;

int main() {
	auto request = BuildCloudwatchDescribeAlarmsRequestForTest("ALARM", "next token/+?");
	assert(request.find("AlarmTypes.member.1=CompositeAlarm") != string::npos);
	assert(request.find("AlarmTypes.member.2=MetricAlarm") != string::npos);
	assert(request.find("AlarmTypes.member.3=LogAlarm") != string::npos);
	assert(request.find("StateValue=ALARM") != string::npos);
	assert(request.find("NextToken=next%20token%2F%2B%3F") != string::npos);

	const string xml = R"(<?xml version="1.0"?>
<DescribeAlarmsResponse xmlns="https://monitoring.amazonaws.com/doc/2010-08-01/">
 <DescribeAlarmsResult>
  <MetricAlarms>
   <member><AlarmName>metric</AlarmName><StateValue>ALARM</StateValue><StateReason>CPU &amp; load &#65; &#x1F600;</StateReason><StateReasonData>{"value": 42}</StateReasonData></member>
   <member><AlarmName>closed</AlarmName><StateValue>OK</StateValue></member>
  </MetricAlarms>
  <CompositeAlarms><member><AlarmName>composite</AlarmName><StateValue>ALARM</StateValue></member></CompositeAlarms>
  <LogAlarms><member><AlarmName>log</AlarmName><StateValue>ALARM</StateValue></member></LogAlarms>
  <NextToken>page&#50;</NextToken>
 </DescribeAlarmsResult>
</DescribeAlarmsResponse>)";
	auto alarms = ParseCloudwatchDescribeAlarmsResponseForTest(xml, "ALARM");
	assert(alarms.next_token == "page2");
	assert(alarms.names.size() == 3);
	assert(alarms.names[0] == "metric");
	assert(alarms.types[0] == "MetricAlarm");
	assert(alarms.types[1] == "CompositeAlarm");
	assert(alarms.types[2] == "LogAlarm");
	assert(alarms.reasons[0] == "CPU & load A 😀");
	assert(alarms.reason_data[0] == R"({"value": 42})");
	auto insufficient = ParseCloudwatchDescribeAlarmsResponseForTest(
	    R"(<DescribeAlarmsResponse><DescribeAlarmsResult><MetricAlarms><member><AlarmName>waiting</AlarmName><StateValue>INSUFFICIENT_DATA</StateValue></member></MetricAlarms></DescribeAlarmsResult></DescribeAlarmsResponse>)",
	    "INSUFFICIENT_DATA");
	assert(insufficient.names.size() == 1 && insufficient.names[0] == "waiting");
	assert(!CloudwatchAlarmPaginationHasCycleForTest({"A", "B", ""}));
	assert(CloudwatchAlarmPaginationHasCycleForTest({"A", "B", "A"}));
	bool malformed_xml_failed = false;
	try {
		ParseCloudwatchDescribeAlarmsResponseForTest("<broken>", "ALARM");
	} catch (...) {
		malformed_xml_failed = true;
	}
	assert(malformed_xml_failed);

	auto graph_request = BuildCloudwatchServiceGraphRequestForTest(1000, 2500, "production", "", "page-2");
	assert(graph_request.find("\"StartTime\":1.0") != string::npos);
	assert(graph_request.find("\"EndTime\":2.5") != string::npos);
	assert(graph_request.find("\"GroupName\":\"production\"") != string::npos);
	assert(graph_request.find("\"NextToken\":\"page-2\"") != string::npos);

	const string graph_page_one = R"({
 "Services":[{"ReferenceId":1,"Name":"checkout","Type":"AWS::Lambda","Edges":[{
   "ReferenceId":2,
   "SummaryStatistics":{"TotalCount":12,"TotalResponseTime":3.5,
     "ErrorStatistics":{"TotalCount":2,"ThrottleCount":1},
     "FaultStatistics":{"TotalCount":1,"ThrottleCount":0}}
 }]}],
 "NextToken":"later"
})";
	const string graph_page_two = R"({"Services":[{"ReferenceId":2,"Name":"payments","Type":"AWS::DynamoDB"}]})";
	auto edges = ParseCloudwatchServiceGraphResponsesForTest({graph_page_one, graph_page_two});
	assert(edges.size() == 1);
	assert(edges[0].source_service == "checkout");
	assert(edges[0].target_service == "payments");
	assert(edges[0].request_count == 12);
	assert(edges[0].error_count == 2);
	assert(edges[0].fault_count == 1);
	assert(edges[0].throttle_count == 1);
	assert(std::fabs(edges[0].total_response_time_seconds - 3.5) < 0.0001);
	assert(edges[0].has_statistics);

	const string no_statistics =
	    R"({"Services":[{"ReferenceId":3,"Name":"a","Edges":[{"ReferenceId":99,"EdgeType":"link","Aliases":[{"Name":"external","Type":"remote"}]}]}]})";
	auto missing = ParseCloudwatchServiceGraphResponsesForTest({no_statistics});
	assert(missing.size() == 1);
	assert(!missing[0].has_statistics);
	assert(missing[0].target_service == "external");
	const string missing_reference_ids =
	    R"({"Services":[{"Name":"unreferenced"},{"ReferenceId":4,"Name":"source","Edges":[{"Aliases":[{"Name":"alias-target","Type":"remote"}]}]}]})";
	auto alias_backed = ParseCloudwatchServiceGraphResponsesForTest({missing_reference_ids});
	assert(alias_backed.size() == 1);
	assert(alias_backed[0].target_service == "alias-target");
	assert(!CloudwatchServiceGraphPaginationHasCycleForTest({"A", "B", ""}));
	assert(CloudwatchServiceGraphPaginationHasCycleForTest({"A", "B", "A"}));
	bool malformed_json_failed = false;
	try {
		ParseCloudwatchServiceGraphResponsesForTest({"{"});
	} catch (...) {
		malformed_json_failed = true;
	}
	assert(malformed_json_failed);

	vector<LogicalType> schema_types;
	vector<string> schema_names;
	GetCloudwatchServiceDependenciesSchema(schema_types, schema_names);
	const vector<string> expected_names = {"provider",          "source_service",
	                                       "target_service",    "source_type",
	                                       "target_type",       "edge_type",
	                                       "environment",       "window_start",
	                                       "window_end",        "request_count",
	                                       "error_count",       "fault_count",
	                                       "throttle_count",    "total_response_time_seconds",
	                                       "source_attributes", "target_attributes",
	                                       "edge_attributes"};
	assert(schema_names == expected_names);
	assert(schema_types.size() == 17);
	for (idx_t index = 0; index < 7; index++)
		assert(schema_types[index] == LogicalType::VARCHAR);
	assert(schema_types[7] == LogicalType::TIMESTAMP_NS);
	assert(schema_types[8] == LogicalType::TIMESTAMP_NS);
	for (idx_t index = 9; index <= 12; index++)
		assert(schema_types[index] == LogicalType::BIGINT);
	assert(schema_types[13] == LogicalType::DOUBLE);
	for (idx_t index = 14; index < 17; index++)
		assert(schema_types[index] == LogicalType::VARCHAR);

	GetCloudwatchAlertsSchema(schema_types, schema_names);
	assert(schema_names.size() == 15);
	assert(schema_names[0] == "alarm_arn");
	assert(schema_names[14] == "configuration");
	assert(schema_types[4] == LogicalType::TIMESTAMP);
	assert(schema_types[10] == LogicalType::LIST(LogicalType::VARCHAR));

	// --- Logs Insights ---------------------------------------------------------

	// StartQuery takes epoch SECONDS while every other Logs API this extension calls takes
	// milliseconds. The start truncates down and the end rounds up so the requested window is
	// covered rather than clipped.
	CloudwatchInsightsRequest insights;
	insights.log_groups = {"/app/one", "/app/two"};
	insights.query_string = "stats count(*) by service_name";
	insights.start_time_ms = 1754800000001;
	insights.end_time_ms = 1754800060001;
	auto start_query = BuildCloudwatchStartQueryRequest(insights);
	assert(start_query.find("\"startTime\":1754800000") != string::npos);
	assert(start_query.find("\"endTime\":1754800061") != string::npos);
	assert(start_query.find("\"logGroupNames\":[\"/app/one\",\"/app/two\"]") != string::npos);
	// limit is omitted entirely at 0 so AWS applies its own default.
	assert(start_query.find("limit") == string::npos);

	insights.limit = 25;
	assert(BuildCloudwatchStartQueryRequest(insights).find("\"limit\":25") != string::npos);

	// An ARN anywhere in the list switches the whole list to logGroupIdentifiers, because AWS
	// rejects a request carrying both keys.
	insights.log_groups = {"/app/one", "arn:aws:logs:us-east-1:1:log-group:/app/two"};
	auto arn_query = BuildCloudwatchStartQueryRequest(insights);
	assert(arn_query.find("logGroupIdentifiers") != string::npos);
	assert(arn_query.find("logGroupNames") == string::npos);

	assert(ParseCloudwatchStartQueryResponse(R"({"queryId":"abc-123"})") == "abc-123");
	bool missing_query_id = false;
	try {
		ParseCloudwatchStartQueryResponse(R"({})");
	} catch (std::exception &) {
		missing_query_id = true;
	}
	assert(missing_query_id);

	assert(BuildCloudwatchQueryIdRequest("abc-123").find("\"queryId\":\"abc-123\"") != string::npos);

	// Ragged rows are normal: the second row omits a field the first carries, and a field present
	// with no value is a real result (an aggregate over an empty group) rather than a missing one.
	auto results = ParseCloudwatchGetQueryResultsResponse(R"({
	  "status": "Complete",
	  "results": [
	    [{"field": "service_name", "value": "checkout"}, {"field": "events", "value": "12"}],
	    [{"field": "service_name", "value": "gateway"}]
	  ],
	  "statistics": {"recordsMatched": 12.0, "recordsScanned": 480.0}
	})");
	assert(results.status == CloudwatchInsightsStatus::COMPLETE);
	assert(IsCloudwatchInsightsTerminal(results.status));
	assert(results.rows.size() == 2);
	assert(results.rows[0].fields.size() == 2);
	assert(results.rows[0].fields[0].first == "service_name");
	assert(results.rows[0].fields[1].second == "12");
	assert(results.rows[1].fields.size() == 1);
	assert(results.records_matched == 12);
	assert(results.records_scanned == 480);

	assert(!IsCloudwatchInsightsTerminal(ParseCloudwatchGetQueryResultsResponse(R"({"status":"Running"})").status));
	assert(!IsCloudwatchInsightsTerminal(ParseCloudwatchGetQueryResultsResponse(R"({"status":"Scheduled"})").status));
	assert(ParseCloudwatchGetQueryResultsResponse(R"({"status":"Failed"})").status == CloudwatchInsightsStatus::FAILED);
	// An unrecognized status is treated as terminal so the poll loop cannot spin forever waiting
	// for a state it will never reach.
	auto unknown = ParseCloudwatchGetQueryResultsResponse(R"({"status":"SomethingNew"})");
	assert(unknown.status == CloudwatchInsightsStatus::UNKNOWN);
	assert(IsCloudwatchInsightsTerminal(unknown.status));
	assert(unknown.status_text == "SomethingNew");

	// --- log-group administration ----------------------------------------------

	assert(BuildCloudwatchCreateLogGroupRequest("/app/logs") == R"({"logGroupName":"/app/logs"})");
	assert(BuildCloudwatchDeleteLogGroupRequest("/app/logs") == R"({"logGroupName":"/app/logs"})");
	auto create_stream = BuildCloudwatchCreateLogStreamRequest("/app/logs", "duckdb");
	assert(create_stream.find("\"logGroupName\":\"/app/logs\"") != string::npos);
	assert(create_stream.find("\"logStreamName\":\"duckdb\"") != string::npos);
	assert(BuildCloudwatchPutRetentionPolicyRequest("/app/logs", 7).find("\"retentionInDays\":7") != string::npos);

	assert(IsValidCloudwatchRetentionDays(1));
	assert(IsValidCloudwatchRetentionDays(3653));
	assert(!IsValidCloudwatchRetentionDays(2));
	assert(!IsValidCloudwatchRetentionDays(0));
	assert(!IsValidCloudwatchRetentionDays(-1));

	// Idempotency depends on classifying AWS error codes, which appear in __type on most
	// operations and inside message on others.
	assert(CloudwatchErrorIs(R"({"__type":"ResourceAlreadyExistsException","message":"x"})",
	                         "ResourceAlreadyExistsException"));
	assert(CloudwatchErrorIs(R"({"message":"ResourceNotFoundException: nope"})", "ResourceNotFoundException"));
	assert(!CloudwatchErrorIs(R"({"__type":"ThrottlingException"})", "ResourceNotFoundException"));
	assert(!CloudwatchErrorIs("", "ResourceNotFoundException"));
	// A non-JSON error body (a proxy's HTML page, say) can still name the exception.
	assert(CloudwatchErrorIs("<html>ResourceNotFoundException</html>", "ResourceNotFoundException"));

	return 0;
}
