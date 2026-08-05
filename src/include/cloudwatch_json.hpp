#pragma once

#include "duckdb.hpp"

#include <utility>

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

//! One CloudWatch Logs InputLogEvent plus its input row, retained so the sender can map successful
//! batches back to DuckDB result rows after sorting chronologically.
struct CloudwatchPutLogEvent {
	int64_t timestamp_ms = 0;
	string message;
	idx_t source_row = 0;

	CloudwatchPutLogEvent() = default;
	CloudwatchPutLogEvent(int64_t timestamp_ms, string message, idx_t source_row)
	    : timestamp_ms(timestamp_ms), message(std::move(message)), source_row(source_row) {
	}
};

struct CloudwatchPutBatch {
	idx_t offset = 0;
	idx_t count = 0;

	CloudwatchPutBatch() = default;
	CloudwatchPutBatch(idx_t offset, idx_t count) : offset(offset), count(count) {
	}
};

struct CloudwatchPutResponse {
	bool has_expired_end = false;
	int64_t expired_end = 0;
	bool has_too_old_end = false;
	int64_t too_old_end = 0;
	bool has_too_new_start = false;
	int64_t too_new_start = 0;
	bool has_rejected_entity = false;
	string rejected_entity_error;

	bool HasRejections() const {
		return has_expired_end || has_too_old_end || has_too_new_start || has_rejected_entity;
	}
};

static constexpr idx_t CLOUDWATCH_PUT_MAX_EVENTS = 10000;
static constexpr idx_t CLOUDWATCH_PUT_MAX_BYTES = 1024 * 1024;
static constexpr idx_t CLOUDWATCH_PUT_EVENT_OVERHEAD = 26;
static constexpr int64_t CLOUDWATCH_PUT_MAX_SPAN_MS = 24LL * 60 * 60 * 1000;

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

//! Stable-sort events by timestamp, validate API-native event constraints, and split them into
//! batches satisfying PutLogEvents' count, byte, and 24-hour span limits.
vector<CloudwatchPutBatch> SortAndPlanCloudwatchPutEvents(vector<CloudwatchPutLogEvent> &events);

//! Build one PutLogEvents request from a contiguous range in a sorted event vector.
string BuildCloudwatchPutEventsRequest(const string &log_group, const string &log_stream,
                                       const CloudwatchPutLogEvent *events, idx_t count);

//! Parse the HTTP-200 response, including the partial-rejection fields that AWS reports as success.
CloudwatchPutResponse ParseCloudwatchPutEventsResponse(const string &response);

} // namespace duckdb
