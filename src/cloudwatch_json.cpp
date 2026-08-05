#include "cloudwatch_json.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"

#include "yyjson.hpp"

#include <cstdlib>
#include <algorithm>
#include <limits>
#include <memory>

using namespace duckdb_yyjson; // NOLINT

namespace duckdb {

namespace {

struct MutDocDeleter {
	void operator()(yyjson_mut_doc *doc) const {
		yyjson_mut_doc_free(doc);
	}
};
struct DocDeleter {
	void operator()(yyjson_doc *doc) const {
		yyjson_doc_free(doc);
	}
};
struct JsonStringDeleter {
	void operator()(char *value) const {
		free(value);
	}
};
using MutDocPtr = std::unique_ptr<yyjson_mut_doc, MutDocDeleter>;
using DocPtr = std::unique_ptr<yyjson_doc, DocDeleter>;
using JsonStringPtr = std::unique_ptr<char, JsonStringDeleter>;

const char *GetString(yyjson_val *object, const char *key) {
	auto value = object ? yyjson_obj_get(object, key) : nullptr;
	return value && yyjson_is_str(value) ? yyjson_get_str(value) : nullptr;
}

bool GetString(yyjson_val *object, const char *key, string &result) {
	auto value = object ? yyjson_obj_get(object, key) : nullptr;
	if (!value || !yyjson_is_str(value)) {
		return false;
	}
	result.assign(yyjson_get_str(value), yyjson_get_len(value));
	return true;
}

bool GetInteger(yyjson_val *object, const char *key, int64_t &result) {
	auto value = object ? yyjson_obj_get(object, key) : nullptr;
	if (!value || !yyjson_is_int(value)) {
		return false;
	}
	result = yyjson_get_sint(value);
	return true;
}

string WriteJson(yyjson_mut_doc *doc) {
	size_t length = 0;
	JsonStringPtr json(yyjson_mut_write(doc, 0, &length));
	if (!json) {
		throw InternalException("Failed to serialize CloudWatch request JSON");
	}
	return string(json.get(), length);
}

void AddString(yyjson_mut_doc *doc, yyjson_mut_val *object, const char *key, const string &value) {
	if (!value.empty()) {
		yyjson_mut_obj_add_strncpy(doc, object, key, value.c_str(), value.size());
	}
}

} // namespace

string BuildCloudwatchFilterRequest(const CloudwatchFilterRequest &request) {
	MutDocPtr doc(yyjson_mut_doc_new(nullptr));
	auto root = yyjson_mut_obj(doc.get());
	yyjson_mut_doc_set_root(doc.get(), root);

	if (StringUtil::StartsWith(request.log_group, "arn:")) {
		AddString(doc.get(), root, "logGroupIdentifier", request.log_group);
	} else {
		AddString(doc.get(), root, "logGroupName", request.log_group);
	}
	AddString(doc.get(), root, "filterPattern", request.filter_pattern);
	AddString(doc.get(), root, "logStreamNamePrefix", request.log_stream_prefix);
	AddString(doc.get(), root, "nextToken", request.next_token);

	if (!request.log_streams.empty()) {
		auto streams = yyjson_mut_arr(doc.get());
		for (const auto &stream : request.log_streams) {
			yyjson_mut_arr_add_strncpy(doc.get(), streams, stream.c_str(), stream.size());
		}
		yyjson_mut_obj_add_val(doc.get(), root, "logStreamNames", streams);
	}
	yyjson_mut_obj_add_sint(doc.get(), root, "startTime", request.start_time_ms);
	yyjson_mut_obj_add_sint(doc.get(), root, "endTime", request.end_time_ms);
	yyjson_mut_obj_add_sint(doc.get(), root, "limit", request.limit);
	yyjson_mut_obj_add_bool(doc.get(), root, "startFromHead", request.ascending);
	if (request.unmask) {
		yyjson_mut_obj_add_bool(doc.get(), root, "unmask", true);
	}
	return WriteJson(doc.get());
}

string ParseCloudwatchFilterResponse(const string &response, vector<CloudwatchLogEvent> &events) {
	DocPtr doc(yyjson_read(response.c_str(), response.size(), 0));
	if (!doc) {
		throw IOException("CloudWatch Logs returned a response that is not valid JSON");
	}
	auto root = yyjson_doc_get_root(doc.get());
	if (!root || !yyjson_is_obj(root)) {
		throw IOException("CloudWatch Logs returned a JSON response that is not an object");
	}

	auto json_events = yyjson_obj_get(root, "events");
	if (json_events && yyjson_is_arr(json_events)) {
		size_t index, count;
		yyjson_val *item;
		yyjson_arr_foreach(json_events, index, count, item) {
			CloudwatchLogEvent event;
			GetInteger(item, "timestamp", event.timestamp_ms);
			GetInteger(item, "ingestionTime", event.ingestion_time_ms);
			GetString(item, "eventId", event.event_id);
			GetString(item, "logStreamName", event.log_stream_name);
			GetString(item, "message", event.message);
			events.push_back(std::move(event));
		}
	}

	auto token = GetString(root, "nextToken");
	return token ? string(token) : string();
}

string BuildCloudwatchDescribeGroupsRequest(const string &next_token, int64_t limit) {
	MutDocPtr doc(yyjson_mut_doc_new(nullptr));
	auto root = yyjson_mut_obj(doc.get());
	yyjson_mut_doc_set_root(doc.get(), root);
	AddString(doc.get(), root, "nextToken", next_token);
	yyjson_mut_obj_add_sint(doc.get(), root, "limit", limit);
	return WriteJson(doc.get());
}

string ParseCloudwatchDescribeGroupsResponse(const string &response, vector<string> &log_groups) {
	DocPtr doc(yyjson_read(response.c_str(), response.size(), 0));
	if (!doc) {
		throw IOException("CloudWatch Logs returned a response that is not valid JSON");
	}
	auto root = yyjson_doc_get_root(doc.get());
	if (!root || !yyjson_is_obj(root)) {
		throw IOException("CloudWatch Logs returned a JSON response that is not an object");
	}

	auto groups = yyjson_obj_get(root, "logGroups");
	if (groups && yyjson_is_arr(groups)) {
		size_t index, count;
		yyjson_val *item;
		yyjson_arr_foreach(groups, index, count, item) {
			string name;
			if (GetString(item, "logGroupName", name) && !name.empty()) {
				log_groups.push_back(std::move(name));
			}
		}
	}
	auto token = GetString(root, "nextToken");
	return token ? string(token) : string();
}

string BuildCloudwatchResourceAttributes(const string &region, const string &log_group, const string &log_stream) {
	MutDocPtr doc(yyjson_mut_doc_new(nullptr));
	auto root = yyjson_mut_obj(doc.get());
	yyjson_mut_doc_set_root(doc.get(), root);
	AddString(doc.get(), root, "cloud.provider", "aws");
	AddString(doc.get(), root, "cloud.region", region);

	auto groups = yyjson_mut_arr(doc.get());
	yyjson_mut_arr_add_strncpy(doc.get(), groups, log_group.c_str(), log_group.size());
	yyjson_mut_obj_add_val(doc.get(), root, "aws.log.group.names", groups);
	if (!log_stream.empty()) {
		auto streams = yyjson_mut_arr(doc.get());
		yyjson_mut_arr_add_strncpy(doc.get(), streams, log_stream.c_str(), log_stream.size());
		yyjson_mut_obj_add_val(doc.get(), root, "aws.log.stream.names", streams);
	}
	return WriteJson(doc.get());
}

string BuildCloudwatchLogAttributes(const string &event_id) {
	if (event_id.empty()) {
		return string();
	}
	MutDocPtr doc(yyjson_mut_doc_new(nullptr));
	auto root = yyjson_mut_obj(doc.get());
	yyjson_mut_doc_set_root(doc.get(), root);
	AddString(doc.get(), root, "aws.cloudwatch.log.event_id", event_id);
	return WriteJson(doc.get());
}

vector<CloudwatchPutBatch> SortAndPlanCloudwatchPutEvents(vector<CloudwatchPutLogEvent> &events) {
	for (const auto &event : events) {
		if (event.message.empty()) {
			throw InvalidInputException("send_cloudwatch_logs: body/message must not be empty (input row %d)",
			                            event.source_row + 1);
		}
		if (event.message.size() > CLOUDWATCH_PUT_MAX_BYTES - CLOUDWATCH_PUT_EVENT_OVERHEAD) {
			throw InvalidInputException(
			    "send_cloudwatch_logs: body/message at input row %d is too large for PutLogEvents (%d bytes; maximum "
			    "is %d after per-event overhead)",
			    event.source_row + 1, event.message.size(), CLOUDWATCH_PUT_MAX_BYTES - CLOUDWATCH_PUT_EVENT_OVERHEAD);
		}
	}

	std::stable_sort(events.begin(), events.end(),
	                 [](const CloudwatchPutLogEvent &left, const CloudwatchPutLogEvent &right) {
		                 return left.timestamp_ms < right.timestamp_ms;
	                 });

	vector<CloudwatchPutBatch> batches;
	idx_t offset = 0;
	while (offset < events.size()) {
		idx_t end = offset;
		idx_t bytes = 0;
		const auto first_timestamp = events[offset].timestamp_ms;
		while (end < events.size() && end - offset < CLOUDWATCH_PUT_MAX_EVENTS) {
			const auto event_bytes = events[end].message.size() + CLOUDWATCH_PUT_EVENT_OVERHEAD;
			if (end > offset && bytes + event_bytes > CLOUDWATCH_PUT_MAX_BYTES) {
				break;
			}
			// Avoid overflowing first_timestamp + 24h near INT64_MAX. Since events are sorted, a
			// first timestamp in the final 24h of the int64 range cannot have a later event outside
			// the span.
			if (end > offset && first_timestamp <= std::numeric_limits<int64_t>::max() - CLOUDWATCH_PUT_MAX_SPAN_MS &&
			    events[end].timestamp_ms > first_timestamp + CLOUDWATCH_PUT_MAX_SPAN_MS) {
				break;
			}
			bytes += event_bytes;
			end++;
		}
		batches.push_back({offset, end - offset});
		offset = end;
	}
	return batches;
}

string BuildCloudwatchPutEventsRequest(const string &log_group, const string &log_stream,
                                       const CloudwatchPutLogEvent *events, idx_t count) {
	MutDocPtr doc(yyjson_mut_doc_new(nullptr));
	auto root = yyjson_mut_obj(doc.get());
	yyjson_mut_doc_set_root(doc.get(), root);
	yyjson_mut_obj_add_strncpy(doc.get(), root, "logGroupName", log_group.c_str(), log_group.size());
	yyjson_mut_obj_add_strncpy(doc.get(), root, "logStreamName", log_stream.c_str(), log_stream.size());
	auto log_events = yyjson_mut_arr(doc.get());
	for (idx_t index = 0; index < count; index++) {
		auto item = yyjson_mut_obj(doc.get());
		yyjson_mut_obj_add_sint(doc.get(), item, "timestamp", events[index].timestamp_ms);
		yyjson_mut_obj_add_strncpy(doc.get(), item, "message", events[index].message.c_str(),
		                           events[index].message.size());
		yyjson_mut_arr_add_val(log_events, item);
	}
	yyjson_mut_obj_add_val(doc.get(), root, "logEvents", log_events);
	return WriteJson(doc.get());
}

CloudwatchPutResponse ParseCloudwatchPutEventsResponse(const string &response) {
	DocPtr doc(yyjson_read(response.c_str(), response.size(), 0));
	if (!doc) {
		throw IOException("CloudWatch PutLogEvents returned a response that is not valid JSON");
	}
	auto root = yyjson_doc_get_root(doc.get());
	if (!root || !yyjson_is_obj(root)) {
		throw IOException("CloudWatch PutLogEvents returned a JSON response that is not an object");
	}

	CloudwatchPutResponse result;
	auto rejected = yyjson_obj_get(root, "rejectedLogEventsInfo");
	if (rejected) {
		if (!yyjson_is_obj(rejected)) {
			throw IOException("CloudWatch PutLogEvents returned malformed rejectedLogEventsInfo");
		}
		result.has_expired_end = GetInteger(rejected, "expiredLogEventEndIndex", result.expired_end);
		result.has_too_old_end = GetInteger(rejected, "tooOldLogEventEndIndex", result.too_old_end);
		result.has_too_new_start = GetInteger(rejected, "tooNewLogEventStartIndex", result.too_new_start);
	}
	auto rejected_entity = yyjson_obj_get(root, "rejectedEntityInfo");
	if (rejected_entity) {
		if (!yyjson_is_obj(rejected_entity)) {
			throw IOException("CloudWatch PutLogEvents returned malformed rejectedEntityInfo");
		}
		result.has_rejected_entity = true;
		GetString(rejected_entity, "errorType", result.rejected_entity_error);
	}
	return result;
}

} // namespace duckdb
