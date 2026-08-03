#pragma once

#include "duckdb.hpp"

namespace duckdb {

struct CloudwatchFilterRequest {
	string log_group;
	string filter_pattern;
	string log_stream_prefix;
	vector<string> log_streams;
	string next_token;
	int64_t start_time_ms = 0;
	int64_t end_time_ms = 0;
	int64_t limit = 10000;
	bool ascending = false;
	bool unmask = false;
};

struct CloudwatchLogEvent {
	int64_t timestamp_ms = -1;
	int64_t ingestion_time_ms = -1;
	string event_id;
	string log_stream_name;
	string message;
};

//! Build the AWS JSON 1.1 request body for FilterLogEvents.
string BuildCloudwatchFilterRequest(const CloudwatchFilterRequest &request);

//! Parse one FilterLogEvents response. Existing events are preserved and parsed events appended.
//! Returns the next token, or an empty string when the scan is complete.
string ParseCloudwatchFilterResponse(const string &response, vector<CloudwatchLogEvent> &events);

//! Build and parse DescribeLogGroups pagination payloads used by ATTACH discovery.
string BuildCloudwatchDescribeGroupsRequest(const string &next_token, int64_t limit = 50);
string ParseCloudwatchDescribeGroupsResponse(const string &response, vector<string> &log_groups);

//! OTLP-style JSON attribute objects for one mapped event.
string BuildCloudwatchResourceAttributes(const string &region, const string &log_group, const string &log_stream);
string BuildCloudwatchLogAttributes(const string &event_id);

} // namespace duckdb
