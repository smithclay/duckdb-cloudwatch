#include "cloudwatch_json.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"

#include "yyjson.hpp"

#include <cstdlib>
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

} // namespace duckdb
