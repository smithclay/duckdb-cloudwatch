#include "alerts_table.hpp"

#include "cloudwatch_client.hpp"
#include "cloudwatch_secret.hpp"

#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/timestamp.hpp"
#include "duckdb/function/table_function.hpp"

#include <cctype>
#include <cstdlib>
#include <deque>
#include <map>
#include <unordered_set>

namespace duckdb {
namespace {

struct XmlNode {
	string name;
	string text;
	vector<XmlNode> children;
};

string LocalName(const string &name) {
	auto separator = name.find(':');
	return separator == string::npos ? name : name.substr(separator + 1);
}

string DecodeXml(const string &value) {
	auto append_codepoint = [](string &output, uint32_t codepoint) {
		if (codepoint <= 0x7f) {
			output.push_back(static_cast<char>(codepoint));
		} else if (codepoint <= 0x7ff) {
			output.push_back(static_cast<char>(0xc0 | (codepoint >> 6)));
			output.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
		} else if (codepoint <= 0xffff) {
			output.push_back(static_cast<char>(0xe0 | (codepoint >> 12)));
			output.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3f)));
			output.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
		} else {
			output.push_back(static_cast<char>(0xf0 | (codepoint >> 18)));
			output.push_back(static_cast<char>(0x80 | ((codepoint >> 12) & 0x3f)));
			output.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3f)));
			output.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
		}
	};
	string result;
	for (idx_t i = 0; i < value.size(); i++) {
		if (value[i] != '&') {
			result.push_back(value[i]);
			continue;
		}
		auto end = value.find(';', i + 1);
		if (end == string::npos) {
			result.push_back(value[i]);
			continue;
		}
		auto entity = value.substr(i + 1, end - i - 1);
		if (entity == "amp") {
			result.push_back('&');
		} else if (entity == "lt") {
			result.push_back('<');
		} else if (entity == "gt") {
			result.push_back('>');
		} else if (entity == "quot") {
			result.push_back('"');
		} else if (entity == "apos") {
			result.push_back('\'');
		} else if (entity.size() > 1 && entity[0] == '#') {
			bool hex = entity.size() > 2 && (entity[1] == 'x' || entity[1] == 'X');
			auto digits = entity.substr(hex ? 2 : 1);
			uint32_t parsed = 0;
			bool valid = !digits.empty();
			for (auto digit : digits) {
				uint32_t digit_value;
				if (digit >= '0' && digit <= '9')
					digit_value = static_cast<uint32_t>(digit - '0');
				else if (hex && digit >= 'a' && digit <= 'f')
					digit_value = static_cast<uint32_t>(digit - 'a' + 10);
				else if (hex && digit >= 'A' && digit <= 'F')
					digit_value = static_cast<uint32_t>(digit - 'A' + 10);
				else {
					valid = false;
					break;
				}
				auto base = hex ? 16U : 10U;
				if (parsed > (0x10ffffU - digit_value) / base) {
					valid = false;
					break;
				}
				parsed = parsed * base + digit_value;
			}
			if (valid && parsed <= 0x10ffff && !(parsed >= 0xd800 && parsed <= 0xdfff) && parsed != 0) {
				append_codepoint(result, parsed);
			} else {
				result.append(value, i, end - i + 1);
			}
		} else {
			result.append(value, i, end - i + 1);
		}
		i = end;
	}
	auto first = result.begin();
	while (first != result.end() && std::isspace(static_cast<unsigned char>(*first)))
		first++;
	auto last = result.end();
	while (last != first && std::isspace(static_cast<unsigned char>(*(last - 1))))
		last--;
	result = string(first, last);
	return result;
}

class XmlParser {
public:
	explicit XmlParser(const string &input) : input(input) {
	}

	XmlNode Parse() {
		SkipMisc();
		if (offset >= input.size() || input[offset] != '<') {
			throw IOException("CloudWatch DescribeAlarms returned invalid XML");
		}
		return ParseNode();
	}

private:
	void SkipSpace() {
		while (offset < input.size() && std::isspace(static_cast<unsigned char>(input[offset]))) {
			offset++;
		}
	}

	void SkipMisc() {
		for (;;) {
			SkipSpace();
			if (input.compare(offset, 2, "<?") == 0) {
				auto end = input.find("?>", offset + 2);
				if (end == string::npos) {
					throw IOException("CloudWatch DescribeAlarms returned invalid XML declaration");
				}
				offset = end + 2;
			} else if (input.compare(offset, 4, "<!--") == 0) {
				auto end = input.find("-->", offset + 4);
				if (end == string::npos) {
					throw IOException("CloudWatch DescribeAlarms returned an invalid XML comment");
				}
				offset = end + 3;
			} else {
				return;
			}
		}
	}

	string ParseName() {
		auto start = offset;
		while (offset < input.size() && !std::isspace(static_cast<unsigned char>(input[offset])) &&
		       input[offset] != '>' && input[offset] != '/') {
			offset++;
		}
		if (start == offset) {
			throw IOException("CloudWatch DescribeAlarms returned invalid XML element syntax");
		}
		return LocalName(input.substr(start, offset - start));
	}

	XmlNode ParseNode() {
		offset++; // <
		XmlNode result;
		result.name = ParseName();
		bool quoted = false;
		char quote = 0;
		while (offset < input.size()) {
			auto ch = input[offset];
			if (quoted) {
				if (ch == quote) {
					quoted = false;
				}
				offset++;
				continue;
			}
			if (ch == '"' || ch == '\'') {
				quoted = true;
				quote = ch;
				offset++;
				continue;
			}
			if (ch == '/' && offset + 1 < input.size() && input[offset + 1] == '>') {
				offset += 2;
				return result;
			}
			if (ch == '>') {
				offset++;
				break;
			}
			offset++;
		}

		string node_text;
		for (;;) {
			if (offset >= input.size()) {
				throw IOException("CloudWatch DescribeAlarms returned unterminated XML");
			}
			if (input.compare(offset, 2, "</") == 0) {
				offset += 2;
				auto closing = ParseName();
				SkipSpace();
				if (offset >= input.size() || input[offset] != '>' || closing != result.name) {
					throw IOException("CloudWatch DescribeAlarms returned mismatched XML elements");
				}
				offset++;
				result.text = DecodeXml(node_text);
				return result;
			}
			if (input.compare(offset, 4, "<!--") == 0 || input.compare(offset, 2, "<?") == 0) {
				SkipMisc();
				continue;
			}
			if (input[offset] == '<') {
				result.children.push_back(ParseNode());
			} else {
				node_text.push_back(input[offset++]);
			}
		}
	}

	const string &input;
	idx_t offset = 0;
};

const XmlNode *Child(const XmlNode &node, const string &name) {
	for (const auto &child : node.children) {
		if (child.name == name) {
			return &child;
		}
	}
	return nullptr;
}

const XmlNode *Descendant(const XmlNode &node, const string &name) {
	if (node.name == name) {
		return &node;
	}
	for (const auto &child : node.children) {
		auto result = Descendant(child, name);
		if (result) {
			return result;
		}
	}
	return nullptr;
}

string ChildText(const XmlNode &node, const string &name) {
	auto child = Child(node, name);
	return child ? child->text : string();
}

string JsonEscape(const string &value) {
	string result = "\"";
	for (auto ch : value) {
		switch (ch) {
		case '"':
			result += "\\\"";
			break;
		case '\\':
			result += "\\\\";
			break;
		case '\n':
			result += "\\n";
			break;
		case '\r':
			result += "\\r";
			break;
		case '\t':
			result += "\\t";
			break;
		default:
			if (static_cast<unsigned char>(ch) < 0x20) {
				result += "?";
			} else {
				result.push_back(ch);
			}
		}
	}
	return result + "\"";
}

string XmlToJson(const XmlNode &node) {
	if (node.children.empty()) {
		return JsonEscape(node.text);
	}
	std::map<string, vector<const XmlNode *>> groups;
	for (const auto &child : node.children) {
		groups[child.name].push_back(&child);
	}
	string result = "{";
	bool first = true;
	for (const auto &group : groups) {
		if (!first) {
			result += ",";
		}
		first = false;
		result += JsonEscape(group.first) + ":";
		if (group.second.size() == 1) {
			result += XmlToJson(*group.second[0]);
		} else {
			result += "[";
			for (idx_t i = 0; i < group.second.size(); i++) {
				if (i) {
					result += ",";
				}
				result += XmlToJson(*group.second[i]);
			}
			result += "]";
		}
	}
	return result + "}";
}

struct AlarmRow {
	string alarm_arn;
	string alarm_name;
	string alarm_type;
	string status;
	string state_transitioned_at;
	string state_updated_at;
	string description;
	string reason;
	string reason_data;
	bool actions_enabled = false;
	bool has_actions_enabled = false;
	vector<string> alarm_actions;
	string metric_namespace;
	string metric_name;
	string dimensions;
	string configuration;
};

vector<string> MemberTexts(const XmlNode &node, const string &container_name) {
	vector<string> result;
	auto container = Child(node, container_name);
	if (!container) {
		return result;
	}
	for (const auto &member : container->children) {
		if (member.name == "member" && !member.text.empty()) {
			result.push_back(member.text);
		}
	}
	return result;
}

string ParseDimensions(const XmlNode &alarm) {
	auto dimensions = Child(alarm, "Dimensions");
	if (!dimensions) {
		return string();
	}
	string result = "{";
	bool first = true;
	for (const auto &member : dimensions->children) {
		if (member.name != "member") {
			continue;
		}
		auto name = ChildText(member, "Name");
		if (name.empty()) {
			continue;
		}
		if (!first) {
			result += ",";
		}
		first = false;
		result += JsonEscape(name) + ":" + JsonEscape(ChildText(member, "Value"));
	}
	return result + "}";
}

AlarmRow ParseAlarm(const XmlNode &node, const string &default_type) {
	AlarmRow result;
	result.alarm_arn = ChildText(node, "AlarmArn");
	result.alarm_name = ChildText(node, "AlarmName");
	result.alarm_type = ChildText(node, "AlarmType");
	if (result.alarm_type.empty()) {
		result.alarm_type = default_type;
	}
	result.status = ChildText(node, "StateValue");
	result.state_transitioned_at = ChildText(node, "StateTransitionedTimestamp");
	result.state_updated_at = ChildText(node, "StateUpdatedTimestamp");
	result.description = ChildText(node, "AlarmDescription");
	result.reason = ChildText(node, "StateReason");
	result.reason_data = ChildText(node, "StateReasonData");
	auto enabled = StringUtil::Lower(ChildText(node, "ActionsEnabled"));
	if (!enabled.empty()) {
		result.has_actions_enabled = true;
		result.actions_enabled = enabled == "true";
	}
	result.alarm_actions = MemberTexts(node, "AlarmActions");
	result.metric_namespace = ChildText(node, "Namespace");
	result.metric_name = ChildText(node, "MetricName");
	result.dimensions = ParseDimensions(node);
	result.configuration = XmlToJson(node);
	return result;
}

string ParseDescribeAlarmsResponse(const string &response, const string &expected_state, vector<AlarmRow> &alarms) {
	auto root = XmlParser(response).Parse();
	for (const auto &container_name : {string("MetricAlarms"), string("CompositeAlarms"), string("LogAlarms")}) {
		auto container = Descendant(root, container_name);
		if (!container) {
			continue;
		}
		string type = container_name == "MetricAlarms"      ? "MetricAlarm"
		              : container_name == "CompositeAlarms" ? "CompositeAlarm"
		                                                    : "LogAlarm";
		for (const auto &member : container->children) {
			if (member.name == "member") {
				auto alarm = ParseAlarm(member, type);
				if (alarm.status == expected_state &&
				    (alarm.status == "ALARM" || alarm.status == "INSUFFICIENT_DATA")) {
					alarms.push_back(std::move(alarm));
				}
			}
		}
	}
	auto token = Descendant(root, "NextToken");
	return token ? token->text : string();
}

string BuildDescribeAlarmsRequest(const string &state, const string &next_token) {
	string result = "Action=DescribeAlarms&AlarmTypes.member.1=CompositeAlarm&AlarmTypes.member.2=MetricAlarm&"
	                "AlarmTypes.member.3=LogAlarm&MaxRecords=100";
	result += "&StateValue=" + StringUtil::URLEncode(state);
	if (!next_token.empty()) {
		result += "&NextToken=" + StringUtil::URLEncode(next_token);
	}
	return result + "&Version=2010-08-01";
}

Value TimestampValue(const string &value) {
	if (value.empty()) {
		return Value();
	}
	timestamp_t timestamp;
	bool has_offset = false;
	string_t timezone;
	if (Timestamp::TryConvertTimestampTZ(value.c_str(), value.size(), timestamp, true, has_offset, timezone) ==
	    TimestampCastResult::SUCCESS) {
		return Value::TIMESTAMP(timestamp);
	}
	return Value();
}

struct AlertsBindData : public TableFunctionData {
	CloudwatchClient client;
	TableCatalogEntry *table = nullptr;
};

struct AlertsGlobalState : public GlobalTableFunctionState {
	vector<column_t> column_ids;
	std::deque<AlarmRow> buffer;
	string next_token;
	idx_t state_index = 0;
	bool finished = false;
	std::unordered_set<string> seen;
	idx_t MaxThreads() const override {
		return 1;
	}
};

void FetchAlarmsPage(ClientContext &context, const AlertsBindData &bind, AlertsGlobalState &state) {
	static const vector<string> states = {"ALARM", "INSUFFICIENT_DATA"};
	if (state.state_index >= states.size()) {
		state.finished = true;
		return;
	}
	vector<AlarmRow> rows;
	auto next = ParseDescribeAlarmsResponse(
	    bind.client.DescribeAlarms(context, BuildDescribeAlarmsRequest(states[state.state_index], state.next_token)),
	    states[state.state_index], rows);
	for (auto &row : rows) {
		auto key = !row.alarm_arn.empty() ? row.alarm_arn : row.alarm_type + "\n" + row.alarm_name;
		if (state.seen.insert(std::move(key)).second) {
			state.buffer.push_back(std::move(row));
		}
	}
	if (next.empty() || next == state.next_token) {
		state.state_index++;
		state.next_token.clear();
		if (state.state_index >= states.size()) {
			state.finished = true;
		}
	} else {
		state.next_token = std::move(next);
	}
}

Value OptionalString(const string &value) {
	return value.empty() ? Value() : Value(value);
}

void AlertsScan(ClientContext &context, TableFunctionInput &input, DataChunk &output) {
	auto &bind = input.bind_data->Cast<AlertsBindData>();
	auto &state = input.global_state->Cast<AlertsGlobalState>();
	while (state.buffer.empty() && !state.finished) {
		FetchAlarmsPage(context, bind, state);
	}
	idx_t count = 0;
	while (count < STANDARD_VECTOR_SIZE && !state.buffer.empty()) {
		auto &row = state.buffer.front();
		for (idx_t out_col = 0; out_col < state.column_ids.size(); out_col++) {
			Value value;
			switch (state.column_ids[out_col]) {
			case 0:
				value = OptionalString(row.alarm_arn);
				break;
			case 1:
				value = OptionalString(row.alarm_name);
				break;
			case 2:
				value = OptionalString(row.alarm_type);
				break;
			case 3:
				value = OptionalString(row.status);
				break;
			case 4:
				value = TimestampValue(row.state_transitioned_at);
				break;
			case 5:
				value = TimestampValue(row.state_updated_at);
				break;
			case 6:
				value = OptionalString(row.description);
				break;
			case 7:
				value = OptionalString(row.reason);
				break;
			case 8:
				value = OptionalString(row.reason_data);
				break;
			case 9:
				value = row.has_actions_enabled ? Value::BOOLEAN(row.actions_enabled) : Value();
				break;
			case 10: {
				vector<Value> actions;
				for (const auto &action : row.alarm_actions)
					actions.emplace_back(action);
				value = Value::LIST(LogicalType::VARCHAR, actions);
				break;
			}
			case 11:
				value = OptionalString(row.metric_namespace);
				break;
			case 12:
				value = OptionalString(row.metric_name);
				break;
			case 13:
				value = OptionalString(row.dimensions);
				break;
			case 14:
				value = OptionalString(row.configuration);
				break;
			default:
				break;
			}
			output.SetValue(out_col, count, value);
		}
		state.buffer.pop_front();
		count++;
	}
	output.SetCardinality(count);
}

unique_ptr<GlobalTableFunctionState> AlertsInit(ClientContext &, TableFunctionInitInput &input) {
	auto state = make_uniq<AlertsGlobalState>();
	state->column_ids = input.column_ids;
	return std::move(state);
}

BindInfo AlertsGetBindInfo(const optional_ptr<FunctionData> bind_data) {
	return BindInfo(*bind_data->Cast<AlertsBindData>().table);
}

} // namespace

void GetCloudwatchAlertsSchema(vector<LogicalType> &types, vector<string> &names) {
	names = {"alarm_arn",        "alarm_name",  "alarm_type",  "status",      "state_transitioned_at",
	         "state_updated_at", "description", "reason",      "reason_data", "actions_enabled",
	         "alarm_actions",    "namespace",   "metric_name", "dimensions",  "configuration"};
	types = {LogicalType::VARCHAR,
	         LogicalType::VARCHAR,
	         LogicalType::VARCHAR,
	         LogicalType::VARCHAR,
	         LogicalType::TIMESTAMP,
	         LogicalType::TIMESTAMP,
	         LogicalType::VARCHAR,
	         LogicalType::VARCHAR,
	         LogicalType::VARCHAR,
	         LogicalType::BOOLEAN,
	         LogicalType::LIST(LogicalType::VARCHAR),
	         LogicalType::VARCHAR,
	         LogicalType::VARCHAR,
	         LogicalType::VARCHAR,
	         LogicalType::VARCHAR};
}

TableFunction GetCloudwatchAlertsTableScan(ClientContext &context, TableCatalogEntry &table, const string &secret_name,
                                           const CloudwatchAlertsSettings &settings,
                                           unique_ptr<FunctionData> &bind_data) {
	auto result = make_uniq<AlertsBindData>();
	result->table = &table;
	result->client.endpoint = settings.monitoring_endpoint;
	result->client.retries = static_cast<uint64_t>(settings.retries);
	result->client.timeout_seconds = static_cast<uint64_t>(settings.timeout_seconds);
	result->client.credentials = GetCloudwatchCredentials(context, secret_name, settings.region);
	bind_data = std::move(result);
	TableFunction function("cloudwatch_alerts_scan", {}, AlertsScan, nullptr, AlertsInit);
	function.projection_pushdown = true;
	function.get_bind_info = AlertsGetBindInfo;
	return function;
}

string BuildCloudwatchDescribeAlarmsRequestForTest(const string &state, const string &next_token) {
	return BuildDescribeAlarmsRequest(state, next_token);
}

CloudwatchAlarmProtocolResult ParseCloudwatchDescribeAlarmsResponseForTest(const string &response,
                                                                           const string &expected_state) {
	vector<AlarmRow> alarms;
	CloudwatchAlarmProtocolResult result;
	result.next_token = ParseDescribeAlarmsResponse(response, expected_state, alarms);
	for (const auto &alarm : alarms) {
		result.names.push_back(alarm.alarm_name);
		result.types.push_back(alarm.alarm_type);
		result.statuses.push_back(alarm.status);
		result.reasons.push_back(alarm.reason);
		result.reason_data.push_back(alarm.reason_data);
	}
	return result;
}

} // namespace duckdb
