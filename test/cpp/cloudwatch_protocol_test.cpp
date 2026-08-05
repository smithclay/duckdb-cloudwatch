#include "alerts_table.hpp"
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
	return 0;
}
