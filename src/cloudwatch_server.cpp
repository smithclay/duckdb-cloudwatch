#include "cloudwatch_server.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/gzip_file_system.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/appender.hpp"
#include "duckdb/main/connection.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/parser/keyword_helper.hpp"
#include "duckdb/storage/storage_extension.hpp"

#ifndef __EMSCRIPTEN__
#include "httplib.hpp"
#endif
#include "yyjson.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_set>

using namespace duckdb_yyjson; // NOLINT

namespace duckdb {
namespace {

// PutLogEvents caps a request at 1 MiB, but the CloudWatch Agent may send that gzipped and
// cpp-httplib measures the compressed body, so the default leaves generous headroom.
static constexpr idx_t DEFAULT_MAX_BODY_BYTES = 16ULL * 1024ULL * 1024ULL;
static constexpr uint16_t DEFAULT_CLOUDWATCH_PORT = 10519;
static constexpr const char *TARGET_PREFIX = "Logs_20140328.";
//! Where the pre-routing hook parks the request's Content-Encoding. See the hook for why.
static constexpr const char *STASHED_ENCODING_HEADER = "X-Cloudwatch-Serve-Content-Encoding";

struct YyjsonDocDeleter {
	void operator()(yyjson_doc *doc) const {
		yyjson_doc_free(doc);
	}
};
struct YyjsonMutDocDeleter {
	void operator()(yyjson_mut_doc *doc) const {
		yyjson_mut_doc_free(doc);
	}
};
struct YyjsonFreeDeleter {
	void operator()(char *value) const {
		free(value);
	}
};
using YyjsonDocPtr = std::unique_ptr<yyjson_doc, YyjsonDocDeleter>;
using YyjsonMutDocPtr = std::unique_ptr<yyjson_mut_doc, YyjsonMutDocDeleter>;
using YyjsonStrPtr = std::unique_ptr<char, YyjsonFreeDeleter>;

//! An AWS error the handler reports as a JSON 1.1 error body. Carrying the code separately lets
//! callers of the real API (including this extension's own admin functions) branch on it.
struct AwsError : public std::exception {
	AwsError(string code_p, string message_p) : code(std::move(code_p)), message(std::move(message_p)) {
	}
	const char *what() const noexcept override {
		return message.c_str();
	}
	string code;
	string message;
};

class CloudwatchListenUri {
public:
	explicit CloudwatchListenUri(string input = "cloudwatch:localhost:10519") {
		StringUtil::Trim(input);
		string remainder;
		if (StringUtil::StartsWith(input, "cloudwatch://")) {
			remainder = input.substr(strlen("cloudwatch://"));
		} else if (StringUtil::StartsWith(input, "cloudwatch:")) {
			remainder = input.substr(strlen("cloudwatch:"));
		} else {
			throw InvalidInputException("Invalid CloudWatch listen URI: expected 'cloudwatch:host[:port]'");
		}
		if (remainder.empty()) {
			remainder = "localhost";
		}
		port = DEFAULT_CLOUDWATCH_PORT;
		if (StringUtil::StartsWith(remainder, "[")) {
			auto closing = remainder.find(']');
			if (closing == string::npos || closing == 1) {
				throw InvalidInputException("Invalid IPv6 CloudWatch listen URI");
			}
			ipv6 = true;
			host = remainder.substr(1, closing - 1);
			auto suffix = remainder.substr(closing + 1);
			if (!suffix.empty()) {
				if (suffix[0] != ':') {
					throw InvalidInputException("Invalid IPv6 CloudWatch listen URI");
				}
				port = ParsePort(suffix.substr(1));
			}
			for (auto c : host) {
				if (!isxdigit(static_cast<unsigned char>(c)) && c != ':' && c != '.' && c != '%') {
					throw InvalidInputException("Invalid character in IPv6 CloudWatch listen address");
				}
			}
		} else {
			auto colon = remainder.find(':');
			if (colon != string::npos) {
				if (remainder.find(':', colon + 1) != string::npos) {
					throw InvalidInputException("IPv6 CloudWatch listen addresses must be enclosed in brackets");
				}
				port = ParsePort(remainder.substr(colon + 1));
				remainder.resize(colon);
			}
			host = remainder;
			if (host.empty()) {
				throw InvalidInputException("Missing CloudWatch listen hostname");
			}
			for (auto c : host) {
				if (!isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '.') {
					throw InvalidInputException("Invalid character in CloudWatch listen hostname");
				}
			}
		}
		canonical = "cloudwatch:" + (ipv6 ? "[" + host + "]" : host) + ":" + std::to_string(port);
		base_url = "http://" + (ipv6 ? "[" + host + "]" : host) + ":" + std::to_string(port);
	}

	string Host() const {
		return host;
	}
	uint16_t Port() const {
		return port;
	}
	string Canonical() const {
		return canonical;
	}
	//! The value to hand to `endpoint =>` on the read/send functions, or to the CloudWatch Agent's
	//! `logs.endpoint_override`.
	string BaseUrl() const {
		return base_url;
	}
	bool IsLocal() const {
		return StringUtil::CIEquals(host, "localhost") || host == "127.0.0.1" || host == "::1";
	}

private:
	static uint16_t ParsePort(const string &text) {
		size_t parsed = 0;
		int value = 0;
		try {
			value = std::stoi(text, &parsed);
		} catch (...) {
			throw InvalidInputException("Invalid CloudWatch listen port");
		}
		if (text.empty() || parsed != text.size() || value < 1 || value > 65535) {
			throw InvalidInputException("Invalid CloudWatch listen port");
		}
		return static_cast<uint16_t>(value);
	}

	bool ipv6 = false;
	string host;
	uint16_t port;
	string canonical;
	string base_url;
};

struct CloudwatchServerConfig {
	string schema_name = "main";
	string table_name = "cloudwatch_logs";
	string groups_table_name = "cloudwatch_log_groups";
	bool allow_other_hostname = false;
	bool create_table = true;
	//! AWS rejects PutLogEvents to a group that does not exist. Keeping that behaviour by default
	//! is what makes this listener a faithful stand-in; the CloudWatch Agent creates its own groups.
	bool auto_create_groups = false;
	idx_t max_body_bytes = DEFAULT_MAX_BODY_BYTES;
	idx_t http_threads = 0;
};

int64_t NowMs() {
	return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
	    .count();
}

const char *GetString(yyjson_val *object, const char *key) {
	auto value = object ? yyjson_obj_get(object, key) : nullptr;
	return value && yyjson_is_str(value) ? yyjson_get_str(value) : nullptr;
}

string GetStringOr(yyjson_val *object, const char *key, const string &fallback = string()) {
	auto value = GetString(object, key);
	return value ? string(value) : fallback;
}

bool GetInt(yyjson_val *object, const char *key, int64_t &result) {
	auto value = object ? yyjson_obj_get(object, key) : nullptr;
	if (!value || !yyjson_is_num(value)) {
		return false;
	}
	result = static_cast<int64_t>(yyjson_get_num(value));
	return true;
}

vector<string> GetStringArray(yyjson_val *object, const char *key) {
	vector<string> result;
	auto array = object ? yyjson_obj_get(object, key) : nullptr;
	if (!array || !yyjson_is_arr(array)) {
		return result;
	}
	size_t index, count;
	yyjson_val *item;
	yyjson_arr_foreach(array, index, count, item) {
		if (yyjson_is_str(item)) {
			result.emplace_back(yyjson_get_str(item));
		}
	}
	return result;
}

idx_t DefaultHttpThreads() {
	auto cores = std::thread::hardware_concurrency();
	if (cores == 0) {
		return 8;
	}
	return std::min<idx_t>(32, std::max<idx_t>(4, static_cast<idx_t>(cores) * 2));
}

string SqlLiteral(const string &value) {
	return "'" + StringUtil::Replace(value, "'", "''") + "'";
}

//! The subset of CloudWatch filter-pattern syntax this listener understands: absent, a bare term,
//! or a quoted phrase -- all of which AWS treats as a substring match on the message. JSON
//! patterns (`{$.field = 2}`) and multi-term boolean patterns are rejected rather than silently
//! matching everything, which would make a test look like it passed.
string FilterPatternSubstring(const string &pattern) {
	auto trimmed = pattern;
	StringUtil::Trim(trimmed);
	if (trimmed.empty()) {
		return string();
	}
	if (trimmed.front() == '{' || trimmed.front() == '[') {
		throw AwsError("InvalidParameterException",
		               "cloudwatch_serve supports only substring filter patterns, not the JSON or metric-filter "
		               "syntax; filter in SQL against the received table instead");
	}
	if (trimmed.front() == '"' && trimmed.back() == '"' && trimmed.size() >= 2) {
		return trimmed.substr(1, trimmed.size() - 2);
	}
	if (trimmed.find(' ') != string::npos || trimmed.find('?') != string::npos) {
		throw AwsError("InvalidParameterException",
		               "cloudwatch_serve supports only single-term substring filter patterns");
	}
	return trimmed;
}

#ifndef __EMSCRIPTEN__
void SetJson(duckdb_httplib_openssl::Response &response, int status, const string &body) {
	response.status = status;
	response.set_content(body, "application/x-amz-json-1.1");
}

string JsonEscape(const string &input) {
	string output;
	for (auto c : input) {
		switch (c) {
		case '\\':
			output += "\\\\";
			break;
		case '"':
			output += "\\\"";
			break;
		case '\n':
			output += "\\n";
			break;
		case '\r':
			output += "\\r";
			break;
		default:
			output += c;
		}
	}
	return output;
}

class CloudwatchServer {
public:
	CloudwatchServer(ClientContext &context, CloudwatchListenUri uri_p, CloudwatchServerConfig config_p)
	    : db_ptr(context.db), uri(std::move(uri_p)), config(std::move(config_p)) {
		if (!config.allow_other_hostname && !uri.IsLocal()) {
			throw InvalidInputException("Only localhost is allowed as a CloudWatch listen hostname by default; set "
			                            "allow_other_hostname=true to accept an off-host CloudWatch Agent");
		}
		if (config.schema_name.empty() || config.table_name.empty() || config.groups_table_name.empty()) {
			throw InvalidInputException("CloudWatch target schema and table names must not be empty");
		}
		if (config.max_body_bytes == 0 || config.http_threads == 0) {
			throw InvalidInputException("max_body_bytes and http_threads must be greater than zero");
		}
		auto db = db_ptr.lock();
		if (!db) {
			throw InternalException("Database was closed");
		}
		writer = make_uniq<Connection>(*db);
		writer->context->config.enable_progress_bar = false;
		EnsureTargetTables();

		server = make_uniq<duckdb_httplib_openssl::Server>();
		auto threads = config.http_threads;
		server->new_task_queue = [threads] {
			return new duckdb_httplib_openssl::ThreadPool(static_cast<size_t>(threads));
		};
		server->set_keep_alive_max_count(128);
		server->set_keep_alive_timeout(10);
		server->set_tcp_nodelay(true);
		server->set_payload_max_length(static_cast<size_t>(config.max_body_bytes));
		// cpp-httplib answers a gzipped request body with 415 unless it was compiled against zlib,
		// and DuckDB's bundled copy is not. The CloudWatch Agent gzips every batch that compresses,
		// so the header is moved aside here -- pre-routing runs before the body is read, so the
		// bytes then arrive raw -- and the handler inflates them itself.
		server->set_pre_routing_handler([](const duckdb_httplib_openssl::Request &request,
		                                   duckdb_httplib_openssl::Response &) {
			auto encoding = request.get_header_value("Content-Encoding");
			if (!encoding.empty()) {
				// cpp-httplib hands pre-routing a const request but mutates it itself moments
				// later; this only relabels one header, before anything has read the body.
				auto &mutable_request = const_cast<duckdb_httplib_openssl::Request &>(request);
				mutable_request.headers.erase("Content-Encoding");
				mutable_request.set_header(STASHED_ENCODING_HEADER, encoding);
			}
			return duckdb_httplib_openssl::Server::HandlerResponse::Unhandled;
		});
		server->Get("/healthz",
		            [](const duckdb_httplib_openssl::Request &, duckdb_httplib_openssl::Response &response) {
			            SetJson(response, 200, "{\"status\":\"ok\"}");
		            });
		// Every CloudWatch Logs operation is a POST to "/" distinguished by X-Amz-Target. SigV4
		// signatures are not verified: this listener is a local test double and a private sink, and
		// it has no access to the caller's secret key.
		server->Post("/", [this](const duckdb_httplib_openssl::Request &request,
		                         duckdb_httplib_openssl::Response &response) { Handle(request, response); });

		if (!server->is_valid() || !server->bind_to_port(uri.Host(), uri.Port())) {
			throw IOException("Failed to bind CloudWatch HTTP server to %s", uri.BaseUrl());
		}
		listening.store(true);
		listen_thread = std::thread([this] {
			server->listen_after_bind();
			listening.store(false);
		});
		server->wait_until_ready();
	}

	~CloudwatchServer() {
		Close();
	}

	void Close() {
		std::lock_guard<std::mutex> close_lock(close_mutex);
		if (!server) {
			return;
		}
		server->stop();
		if (listen_thread.joinable()) {
			listen_thread.join();
		}
		server.reset();
		writer.reset();
		listening.store(false);
	}

	string BaseUrl() const {
		return uri.BaseUrl();
	}
	const CloudwatchServerConfig &Config() const {
		return config;
	}

private:
	void Handle(const duckdb_httplib_openssl::Request &request, duckdb_httplib_openssl::Response &response) {
		try {
			auto target = request.get_header_value("X-Amz-Target");
			if (!StringUtil::StartsWith(target, TARGET_PREFIX)) {
				throw AwsError("UnknownOperationException", "Missing or unrecognized X-Amz-Target: " + target);
			}
			auto operation = target.substr(strlen(TARGET_PREFIX));

			auto body = request.body;
			auto encoding = StringUtil::Lower(request.get_header_value(STASHED_ENCODING_HEADER));
			if (!encoding.empty() && !body.empty()) {
				if (encoding.find("gzip") == string::npos) {
					throw AwsError("InvalidParameterException",
					               "cloudwatch_serve accepts identity or gzip request bodies, not '" + encoding + "'");
				}
				body = GZipFileSystem::UncompressGZIPString(body);
			}
			YyjsonDocPtr doc(yyjson_read(body.c_str(), body.size(), 0));
			auto root = doc ? yyjson_doc_get_root(doc.get()) : nullptr;
			if (!root || !yyjson_is_obj(root)) {
				throw AwsError("InvalidParameterException", "Request body must be a JSON object");
			}

			string result;
			if (operation == "PutLogEvents") {
				result = PutLogEvents(root);
			} else if (operation == "CreateLogGroup") {
				result = CreateLogGroup(root);
			} else if (operation == "CreateLogStream") {
				result = CreateLogStream(root);
			} else if (operation == "DeleteLogGroup") {
				result = DeleteLogGroup(root);
			} else if (operation == "PutRetentionPolicy") {
				result = PutRetentionPolicy(root);
			} else if (operation == "DescribeLogGroups") {
				result = DescribeLogGroups(root);
			} else if (operation == "DescribeLogStreams") {
				result = DescribeLogStreams(root);
			} else if (operation == "FilterLogEvents") {
				result = FilterLogEvents(root);
			} else {
				// Logs Insights (StartQuery/GetQueryResults) is deliberately absent: emulating its
				// query language would give false confidence. Query the received table in SQL.
				throw AwsError("UnknownOperationException", "cloudwatch_serve does not implement " + operation);
			}
			SetJson(response, 200, result);
		} catch (AwsError &error) {
			SetJson(response, 400,
			        "{\"__type\":\"" + JsonEscape(error.code) + "\",\"message\":\"" + JsonEscape(error.message) + "\"}");
		} catch (std::exception &ex) {
			SetJson(response, 500,
			        "{\"__type\":\"InternalFailure\",\"message\":\"" + JsonEscape(ex.what()) + "\"}");
		}
	}

	string QualifiedEvents() const {
		return KeywordHelper::WriteOptionallyQuoted(config.schema_name) + "." +
		       KeywordHelper::WriteOptionallyQuoted(config.table_name);
	}
	string QualifiedGroups() const {
		return KeywordHelper::WriteOptionallyQuoted(config.schema_name) + "." +
		       KeywordHelper::WriteOptionallyQuoted(config.groups_table_name);
	}

	void EnsureTargetTables() {
		if (config.create_table) {
			// The received shape is CloudWatch's own, not OTLP: PutLogEvents carries a message and a
			// timestamp, and the group/stream are the only other addressing CloudWatch has. Callers
			// that want OTLP columns read back through read_cloudwatch_logs.
			RunOrThrow("CREATE TABLE IF NOT EXISTS " + QualifiedEvents() +
			               " (log_group VARCHAR, log_stream VARCHAR, timestamp_ms BIGINT, "
			               "ingestion_time_ms BIGINT, event_id VARCHAR, message VARCHAR)",
			           "create CloudWatch events table");
			RunOrThrow("CREATE TABLE IF NOT EXISTS " + QualifiedGroups() +
			               " (log_group VARCHAR, log_stream VARCHAR, retention_in_days BIGINT, created_ms BIGINT)",
			           "create CloudWatch log-group table");
		}
		auto result = writer->Query("SELECT log_group, log_stream, timestamp_ms, ingestion_time_ms, event_id, message "
		                            "FROM " +
		                            QualifiedEvents() + " LIMIT 0");
		if (!result || result->HasError()) {
			throw InvalidInputException("CloudWatch target table %s must have columns (log_group, log_stream, "
			                            "timestamp_ms, ingestion_time_ms, event_id, message)",
			                            QualifiedEvents());
		}
		auto groups = writer->Query("SELECT log_group, log_stream, retention_in_days, created_ms FROM " +
		                            QualifiedGroups() + " LIMIT 0");
		if (!groups || groups->HasError()) {
			throw InvalidInputException("CloudWatch log-group table %s must have columns (log_group, log_stream, "
			                            "retention_in_days, created_ms)",
			                            QualifiedGroups());
		}
	}

	void RunOrThrow(const string &sql, const string &what) {
		auto result = writer->Query(sql);
		if (!result || result->HasError()) {
			throw IOException("cloudwatch_serve could not %s: %s", what, result ? result->GetError() : "query failed");
		}
	}

	unique_ptr<MaterializedQueryResult> RunQuery(const string &sql) {
		auto result = writer->Query(sql);
		if (!result || result->HasError()) {
			throw IOException("cloudwatch_serve query failed: %s", result ? result->GetError() : "query failed");
		}
		return result;
	}

	bool GroupExists(const string &log_group) {
		auto result = RunQuery("SELECT count(*) FROM " + QualifiedGroups() + " WHERE log_group = " +
		                       SqlLiteral(log_group) + " AND log_stream IS NULL");
		return result->GetValue(0, 0).GetValue<int64_t>() > 0;
	}

	bool StreamExists(const string &log_group, const string &log_stream) {
		auto result = RunQuery("SELECT count(*) FROM " + QualifiedGroups() + " WHERE log_group = " +
		                       SqlLiteral(log_group) + " AND log_stream = " + SqlLiteral(log_stream));
		return result->GetValue(0, 0).GetValue<int64_t>() > 0;
	}

	string CreateLogGroup(yyjson_val *root) {
		auto log_group = GetStringOr(root, "logGroupName");
		if (log_group.empty()) {
			throw AwsError("InvalidParameterException", "logGroupName is required");
		}
		std::lock_guard<std::mutex> lock(writer_mutex);
		if (GroupExists(log_group)) {
			throw AwsError("ResourceAlreadyExistsException", "The specified log group already exists");
		}
		RunOrThrow("INSERT INTO " + QualifiedGroups() + " VALUES (" + SqlLiteral(log_group) + ", NULL, NULL, " +
		               std::to_string(NowMs()) + ")",
		           "record a log group");
		return "{}";
	}

	string DeleteLogGroup(yyjson_val *root) {
		auto log_group = GetStringOr(root, "logGroupName");
		if (log_group.empty()) {
			throw AwsError("InvalidParameterException", "logGroupName is required");
		}
		std::lock_guard<std::mutex> lock(writer_mutex);
		if (!GroupExists(log_group)) {
			throw AwsError("ResourceNotFoundException", "The specified log group does not exist");
		}
		// Deleting a group in CloudWatch discards its streams and events too.
		RunOrThrow("DELETE FROM " + QualifiedGroups() + " WHERE log_group = " + SqlLiteral(log_group),
		           "delete a log group");
		RunOrThrow("DELETE FROM " + QualifiedEvents() + " WHERE log_group = " + SqlLiteral(log_group),
		           "delete log group events");
		return "{}";
	}

	string CreateLogStream(yyjson_val *root) {
		auto log_group = GetStringOr(root, "logGroupName");
		auto log_stream = GetStringOr(root, "logStreamName");
		if (log_group.empty() || log_stream.empty()) {
			throw AwsError("InvalidParameterException", "logGroupName and logStreamName are required");
		}
		std::lock_guard<std::mutex> lock(writer_mutex);
		if (!GroupExists(log_group)) {
			throw AwsError("ResourceNotFoundException", "The specified log group does not exist");
		}
		if (StreamExists(log_group, log_stream)) {
			throw AwsError("ResourceAlreadyExistsException", "The specified log stream already exists");
		}
		RunOrThrow("INSERT INTO " + QualifiedGroups() + " VALUES (" + SqlLiteral(log_group) + ", " +
		               SqlLiteral(log_stream) + ", NULL, " + std::to_string(NowMs()) + ")",
		           "record a log stream");
		return "{}";
	}

	string PutRetentionPolicy(yyjson_val *root) {
		auto log_group = GetStringOr(root, "logGroupName");
		int64_t days = 0;
		if (log_group.empty() || !GetInt(root, "retentionInDays", days)) {
			throw AwsError("InvalidParameterException", "logGroupName and retentionInDays are required");
		}
		std::lock_guard<std::mutex> lock(writer_mutex);
		if (!GroupExists(log_group)) {
			throw AwsError("ResourceNotFoundException", "The specified log group does not exist");
		}
		RunOrThrow("UPDATE " + QualifiedGroups() + " SET retention_in_days = " + std::to_string(days) +
		               " WHERE log_group = " + SqlLiteral(log_group) + " AND log_stream IS NULL",
		           "set a retention policy");
		return "{}";
	}

	string PutLogEvents(yyjson_val *root) {
		auto log_group = GetStringOr(root, "logGroupName");
		auto log_stream = GetStringOr(root, "logStreamName");
		if (log_group.empty() || log_stream.empty()) {
			throw AwsError("InvalidParameterException", "logGroupName and logStreamName are required");
		}
		auto events = yyjson_obj_get(root, "logEvents");
		if (!events || !yyjson_is_arr(events)) {
			throw AwsError("InvalidParameterException", "logEvents must be an array");
		}

		vector<vector<Value>> rows;
		const auto ingestion_ms = NowMs();
		size_t index, count;
		yyjson_val *item;
		yyjson_arr_foreach(events, index, count, item) {
			int64_t timestamp_ms = 0;
			if (!GetInt(item, "timestamp", timestamp_ms)) {
				throw AwsError("InvalidParameterException", "each log event requires a timestamp");
			}
			auto message = GetString(item, "message");
			if (!message) {
				throw AwsError("InvalidParameterException", "each log event requires a message");
			}
			rows.push_back({Value(log_group), Value(log_stream), Value::BIGINT(timestamp_ms),
			                Value::BIGINT(ingestion_ms), Value(NextEventId()), Value(string(message))});
		}

		{
			std::lock_guard<std::mutex> lock(writer_mutex);
			if (!GroupExists(log_group)) {
				if (!config.auto_create_groups) {
					throw AwsError("ResourceNotFoundException", "The specified log group does not exist");
				}
				RunOrThrow("INSERT INTO " + QualifiedGroups() + " VALUES (" + SqlLiteral(log_group) + ", NULL, NULL, " +
				               std::to_string(ingestion_ms) + ")",
				           "auto-create a log group");
			}
			if (!StreamExists(log_group, log_stream)) {
				if (!config.auto_create_groups) {
					throw AwsError("ResourceNotFoundException", "The specified log stream does not exist");
				}
				RunOrThrow("INSERT INTO " + QualifiedGroups() + " VALUES (" + SqlLiteral(log_group) + ", " +
				               SqlLiteral(log_stream) + ", NULL, " + std::to_string(ingestion_ms) + ")",
				           "auto-create a log stream");
			}
			Append(rows);
		}
		total_requests++;
		total_rows += rows.size();
		return "{}";
	}

	string DescribeLogGroups(yyjson_val *root) {
		auto prefix = GetStringOr(root, "logGroupNamePrefix");
		string sql = "SELECT log_group, retention_in_days, created_ms FROM " + QualifiedGroups() +
		             " WHERE log_stream IS NULL";
		if (!prefix.empty()) {
			sql += " AND starts_with(log_group, " + SqlLiteral(prefix) + ")";
		}
		sql += " ORDER BY log_group";

		std::lock_guard<std::mutex> lock(writer_mutex);
		auto result = RunQuery(sql);

		YyjsonMutDocPtr doc(yyjson_mut_doc_new(nullptr));
		auto out_root = yyjson_mut_obj(doc.get());
		yyjson_mut_doc_set_root(doc.get(), out_root);
		auto groups = yyjson_mut_arr(doc.get());
		for (idx_t row = 0; row < result->RowCount(); row++) {
			auto object = yyjson_mut_obj(doc.get());
			auto name = result->GetValue(0, row).ToString();
			yyjson_mut_obj_add_strcpy(doc.get(), object, "logGroupName", name.c_str());
			auto retention = result->GetValue(1, row);
			if (!retention.IsNull()) {
				yyjson_mut_obj_add_sint(doc.get(), object, "retentionInDays", retention.GetValue<int64_t>());
			}
			auto created = result->GetValue(2, row);
			if (!created.IsNull()) {
				yyjson_mut_obj_add_sint(doc.get(), object, "creationTime", created.GetValue<int64_t>());
			}
			yyjson_mut_arr_add_val(groups, object);
		}
		yyjson_mut_obj_add_val(doc.get(), out_root, "logGroups", groups);
		return WriteDoc(doc.get());
	}

	string DescribeLogStreams(yyjson_val *root) {
		auto log_group = GetStringOr(root, "logGroupName");
		if (log_group.empty()) {
			throw AwsError("InvalidParameterException", "logGroupName is required");
		}
		auto prefix = GetStringOr(root, "logStreamNamePrefix");
		// Report streams that carry events as well as explicitly created ones: the CloudWatch Agent
		// calls DescribeLogStreams to decide whether it still needs to create a stream.
		string sql = "SELECT name, min(first_ms), max(last_ms) FROM ("
		             "SELECT log_stream AS name, NULL::BIGINT AS first_ms, NULL::BIGINT AS last_ms FROM " +
		             QualifiedGroups() + " WHERE log_group = " + SqlLiteral(log_group) + " AND log_stream IS NOT NULL "
		             "UNION ALL SELECT log_stream, min(timestamp_ms), max(timestamp_ms) FROM " + QualifiedEvents() +
		             " WHERE log_group = " + SqlLiteral(log_group) + " GROUP BY log_stream) ";
		sql += prefix.empty() ? "WHERE TRUE" : "WHERE starts_with(name, " + SqlLiteral(prefix) + ")";
		sql += " GROUP BY name ORDER BY name";

		std::lock_guard<std::mutex> lock(writer_mutex);
		auto result = RunQuery(sql);

		YyjsonMutDocPtr doc(yyjson_mut_doc_new(nullptr));
		auto out_root = yyjson_mut_obj(doc.get());
		yyjson_mut_doc_set_root(doc.get(), out_root);
		auto streams = yyjson_mut_arr(doc.get());
		for (idx_t row = 0; row < result->RowCount(); row++) {
			auto object = yyjson_mut_obj(doc.get());
			auto name = result->GetValue(0, row).ToString();
			yyjson_mut_obj_add_strcpy(doc.get(), object, "logStreamName", name.c_str());
			auto first = result->GetValue(1, row);
			if (!first.IsNull()) {
				yyjson_mut_obj_add_sint(doc.get(), object, "firstEventTimestamp", first.GetValue<int64_t>());
			}
			auto last = result->GetValue(2, row);
			if (!last.IsNull()) {
				yyjson_mut_obj_add_sint(doc.get(), object, "lastEventTimestamp", last.GetValue<int64_t>());
			}
			yyjson_mut_arr_add_val(streams, object);
		}
		yyjson_mut_obj_add_val(doc.get(), out_root, "logStreams", streams);
		return WriteDoc(doc.get());
	}

	string FilterLogEvents(yyjson_val *root) {
		auto log_group = GetStringOr(root, "logGroupName", GetStringOr(root, "logGroupIdentifier"));
		if (log_group.empty()) {
			throw AwsError("InvalidParameterException", "logGroupName or logGroupIdentifier is required");
		}
		int64_t start_ms = 0;
		int64_t end_ms = 0;
		int64_t limit = 10000;
		GetInt(root, "startTime", start_ms);
		GetInt(root, "endTime", end_ms);
		GetInt(root, "limit", limit);
		limit = MinValue<int64_t>(MaxValue<int64_t>(limit, 1), 10000);
		auto ascending = false;
		auto start_from_head = yyjson_obj_get(root, "startFromHead");
		if (start_from_head && yyjson_is_bool(start_from_head)) {
			ascending = yyjson_get_bool(start_from_head);
		}
		auto substring = FilterPatternSubstring(GetStringOr(root, "filterPattern"));
		auto stream_prefix = GetStringOr(root, "logStreamNamePrefix");
		auto streams = GetStringArray(root, "logStreamNames");

		// The scan is ordered and paginated by a plain offset carried in nextToken, which is enough
		// for a deterministic local double (real CloudWatch tokens are opaque anyway).
		int64_t offset = 0;
		auto token = GetStringOr(root, "nextToken");
		if (!token.empty()) {
			try {
				offset = std::stoll(token);
			} catch (...) {
				throw AwsError("InvalidParameterException", "Invalid nextToken");
			}
		}

		string sql = "SELECT log_stream, timestamp_ms, ingestion_time_ms, event_id, message FROM " + QualifiedEvents() +
		             " WHERE log_group = " + SqlLiteral(log_group);
		if (end_ms > 0) {
			// FilterLogEvents is end-exclusive and start-inclusive.
			sql += " AND timestamp_ms >= " + std::to_string(start_ms) + " AND timestamp_ms < " + std::to_string(end_ms);
		} else if (start_ms > 0) {
			sql += " AND timestamp_ms >= " + std::to_string(start_ms);
		}
		if (!substring.empty()) {
			sql += " AND contains(message, " + SqlLiteral(substring) + ")";
		}
		if (!stream_prefix.empty()) {
			sql += " AND starts_with(log_stream, " + SqlLiteral(stream_prefix) + ")";
		}
		if (!streams.empty()) {
			vector<string> quoted;
			for (const auto &stream : streams) {
				quoted.push_back(SqlLiteral(stream));
			}
			sql += " AND log_stream IN (" + StringUtil::Join(quoted, ", ") + ")";
		}
		// event_id breaks ties so pagination cannot repeat or skip rows sharing a timestamp.
		sql += ascending ? " ORDER BY timestamp_ms ASC, event_id ASC" : " ORDER BY timestamp_ms DESC, event_id DESC";
		sql += " LIMIT " + std::to_string(limit + 1) + " OFFSET " + std::to_string(offset);

		std::lock_guard<std::mutex> lock(writer_mutex);
		auto result = RunQuery(sql);

		const auto returned = MinValue<idx_t>(result->RowCount(), static_cast<idx_t>(limit));
		YyjsonMutDocPtr doc(yyjson_mut_doc_new(nullptr));
		auto out_root = yyjson_mut_obj(doc.get());
		yyjson_mut_doc_set_root(doc.get(), out_root);
		auto events = yyjson_mut_arr(doc.get());
		for (idx_t row = 0; row < returned; row++) {
			auto object = yyjson_mut_obj(doc.get());
			auto stream = result->GetValue(0, row).ToString();
			auto event_id = result->GetValue(3, row).ToString();
			auto message = result->GetValue(4, row).ToString();
			yyjson_mut_obj_add_strcpy(doc.get(), object, "logStreamName", stream.c_str());
			yyjson_mut_obj_add_sint(doc.get(), object, "timestamp", result->GetValue(1, row).GetValue<int64_t>());
			yyjson_mut_obj_add_sint(doc.get(), object, "ingestionTime", result->GetValue(2, row).GetValue<int64_t>());
			yyjson_mut_obj_add_strcpy(doc.get(), object, "eventId", event_id.c_str());
			yyjson_mut_obj_add_strcpy(doc.get(), object, "message", message.c_str());
			yyjson_mut_arr_add_val(events, object);
		}
		yyjson_mut_obj_add_val(doc.get(), out_root, "events", events);
		yyjson_mut_obj_add_val(doc.get(), out_root, "searchedLogStreams", yyjson_mut_arr(doc.get()));
		if (result->RowCount() > returned) {
			auto next = std::to_string(offset + static_cast<int64_t>(returned));
			yyjson_mut_obj_add_strcpy(doc.get(), out_root, "nextToken", next.c_str());
		}
		return WriteDoc(doc.get());
	}

	static string WriteDoc(yyjson_mut_doc *doc) {
		size_t length = 0;
		YyjsonStrPtr json(yyjson_mut_write(doc, 0, &length));
		if (!json) {
			throw InternalException("Failed to serialize a cloudwatch_serve response");
		}
		return string(json.get(), length);
	}

	string NextEventId() {
		return StringUtil::Format("%019llu", static_cast<unsigned long long>(++event_counter));
	}

	//! Caller holds writer_mutex.
	void Append(const vector<vector<Value>> &rows) {
		if (rows.empty()) {
			return;
		}
		writer->BeginTransaction();
		try {
			Appender appender(*writer, config.schema_name, config.table_name);
			for (auto &row : rows) {
				appender.BeginRow();
				for (auto &value : row) {
					appender.Append(value);
				}
				appender.EndRow();
			}
			appender.Close();
			writer->Commit();
		} catch (...) {
			writer->Rollback();
			throw;
		}
	}

	weak_ptr<DatabaseInstance> db_ptr;
	CloudwatchListenUri uri;
	CloudwatchServerConfig config;
	unique_ptr<Connection> writer;
	unique_ptr<duckdb_httplib_openssl::Server> server;
	std::thread listen_thread;
	std::mutex writer_mutex;
	std::mutex close_mutex;
	std::atomic<bool> listening {false};
	std::atomic<idx_t> total_requests {0};
	std::atomic<idx_t> total_rows {0};
	std::atomic<uint64_t> event_counter {0};
};
#endif

class CloudwatchServerExtensionInfo : public StorageExtensionInfo {
public:
	static constexpr const char *KEY = "cloudwatch_server";

	~CloudwatchServerExtensionInfo() override {
		StopAll();
	}

	static CloudwatchServerExtensionInfo &Get(DatabaseInstance &database) {
		auto extension = StorageExtension::Find(database.config, KEY);
		if (!extension || !extension->storage_info) {
			throw InternalException("CloudWatch server extension state is not registered");
		}
		return *static_cast<CloudwatchServerExtensionInfo *>(extension->storage_info.get());
	}

	string Start(ClientContext &context, const CloudwatchListenUri &uri, const CloudwatchServerConfig &config) {
#ifdef __EMSCRIPTEN__
		throw NotImplementedException("cloudwatch_serve is not implemented for the wasm platform");
#else
		std::lock_guard<std::mutex> lock(mutex);
		auto key = uri.Canonical();
		auto existing = servers.find(key);
		if (existing != servers.end()) {
			auto &current = existing->second->Config();
			if (current.schema_name != config.schema_name || current.table_name != config.table_name ||
			    current.groups_table_name != config.groups_table_name ||
			    current.allow_other_hostname != config.allow_other_hostname ||
			    current.create_table != config.create_table ||
			    current.auto_create_groups != config.auto_create_groups ||
			    current.max_body_bytes != config.max_body_bytes || current.http_threads != config.http_threads) {
				throw InvalidInputException("A CloudWatch server already exists for %s with different options", key);
			}
			return existing->second->BaseUrl();
		}
		shared_ptr<CloudwatchServer> server(new CloudwatchServer(context, uri, config));
		auto url = server->BaseUrl();
		servers.emplace(key, std::move(server));
		return url;
#endif
	}

	bool Stop(const CloudwatchListenUri &uri) {
#ifdef __EMSCRIPTEN__
		return false;
#else
		shared_ptr<CloudwatchServer> server;
		{
			std::lock_guard<std::mutex> lock(mutex);
			auto entry = servers.find(uri.Canonical());
			if (entry == servers.end()) {
				return false;
			}
			server = std::move(entry->second);
			servers.erase(entry);
		}
		server->Close();
		return true;
#endif
	}

private:
	void StopAll() {
#ifndef __EMSCRIPTEN__
		vector<shared_ptr<CloudwatchServer>> active;
		{
			std::lock_guard<std::mutex> lock(mutex);
			for (auto &entry : servers) {
				active.push_back(std::move(entry.second));
			}
			servers.clear();
		}
		for (auto &server : active) {
			server->Close();
		}
#endif
	}

	std::mutex mutex;
#ifndef __EMSCRIPTEN__
	unordered_map<string, shared_ptr<CloudwatchServer>> servers;
#endif
};

bool TryGetOption(const Value &options, const string &name, Value &result) {
	auto &type = options.type();
	if (type.id() != LogicalTypeId::STRUCT) {
		throw InvalidInputException("cloudwatch_serve options must be a STRUCT");
	}
	auto &children = StructValue::GetChildren(options);
	for (idx_t index = 0; index < children.size(); index++) {
		if (StringUtil::CIEquals(StructType::GetChildName(type, index), name)) {
			result = children[index];
			return true;
		}
	}
	return false;
}

template <class T>
bool ReadOption(const Value &options, const string &name, T &target) {
	Value value;
	if (!TryGetOption(options, name, value)) {
		return false;
	}
	if (value.IsNull()) {
		throw InvalidInputException("cloudwatch_serve option '%s' must not be NULL", name);
	}
	target = value.GetValue<T>();
	return true;
}

CloudwatchServerConfig ParseOptions(const Value &options) {
	CloudwatchServerConfig config;
	config.http_threads = DefaultHttpThreads();
	ReadOption(options, "schema_name", config.schema_name);
	ReadOption(options, "table_name", config.table_name);
	ReadOption(options, "groups_table_name", config.groups_table_name);
	ReadOption(options, "allow_other_hostname", config.allow_other_hostname);
	ReadOption(options, "create_table", config.create_table);
	ReadOption(options, "auto_create_groups", config.auto_create_groups);
	ReadOption(options, "max_body_bytes", config.max_body_bytes);
	ReadOption(options, "http_threads", config.http_threads);
	static const std::unordered_set<string> valid = {"schema_name",        "table_name",         "groups_table_name",
	                                                 "allow_other_hostname", "create_table",     "auto_create_groups",
	                                                 "max_body_bytes",     "http_threads"};
	for (idx_t index = 0; index < StructType::GetChildCount(options.type()); index++) {
		auto name = StructType::GetChildName(options.type(), index);
		if (valid.find(StringUtil::Lower(name)) == valid.end()) {
			throw InvalidInputException("Unsupported cloudwatch_serve option '%s'", name);
		}
	}
	return config;
}

void CloudwatchServe(DataChunk &arguments, ExpressionState &state, Vector &result) {
	if (!arguments.AllConstant()) {
		throw InvalidInputException("cloudwatch_serve arguments must be constant");
	}
	string uri_text = "cloudwatch:localhost:10519";
	if (arguments.ColumnCount() >= 1) {
		auto value = arguments.GetValue(0, 0);
		if (value.IsNull() || value.GetValue<string>().empty()) {
			throw InvalidInputException("CloudWatch listen URI must not be NULL or empty");
		}
		uri_text = value.GetValue<string>();
	}
	CloudwatchServerConfig config;
	config.http_threads = DefaultHttpThreads();
	if (arguments.ColumnCount() == 2) {
		auto value = arguments.GetValue(1, 0);
		if (value.IsNull()) {
			throw InvalidInputException("cloudwatch_serve options must not be NULL");
		}
		config = ParseOptions(value);
	}
	CloudwatchListenUri uri(uri_text);
	auto db = state.GetContext().db;
	if (!db) {
		throw InternalException("Database was closed");
	}
	auto url = CloudwatchServerExtensionInfo::Get(*db).Start(state.GetContext(), uri, config);
	result.SetValue(0, Value(url));
	result.SetVectorType(VectorType::CONSTANT_VECTOR);
}

void CloudwatchStop(DataChunk &arguments, ExpressionState &state, Vector &result) {
	if (!arguments.AllConstant()) {
		throw InvalidInputException("cloudwatch_stop arguments must be constant");
	}
	string uri_text = "cloudwatch:localhost:10519";
	if (arguments.ColumnCount() == 1) {
		auto value = arguments.GetValue(0, 0);
		if (value.IsNull() || value.GetValue<string>().empty()) {
			throw InvalidInputException("CloudWatch listen URI must not be NULL or empty");
		}
		uri_text = value.GetValue<string>();
	}
	CloudwatchListenUri uri(uri_text);
	auto db = state.GetContext().db;
	if (!db) {
		throw InternalException("Database was closed");
	}
	auto stopped = CloudwatchServerExtensionInfo::Get(*db).Stop(uri);
	result.SetValue(0, Value(stopped ? "stopped" : "not found"));
	result.SetVectorType(VectorType::CONSTANT_VECTOR);
}

} // namespace

void RegisterCloudwatchServerState(ExtensionLoader &loader) {
	auto extension = make_shared_ptr<StorageExtension>();
	extension->storage_info = make_shared_ptr<CloudwatchServerExtensionInfo>();
	StorageExtension::Register(loader.GetDatabaseInstance().config, CloudwatchServerExtensionInfo::KEY, extension);
}

void RegisterCloudwatchServerFunctions(ExtensionLoader &loader) {
	ScalarFunctionSet serve("cloudwatch_serve");
	for (auto &arguments :
	     vector<vector<LogicalType>> {{}, {LogicalType::VARCHAR}, {LogicalType::VARCHAR, LogicalType::ANY}}) {
		ScalarFunction function(arguments, LogicalType::VARCHAR, CloudwatchServe);
		function.SetStability(FunctionStability::VOLATILE);
		function.SetNullHandling(FunctionNullHandling::SPECIAL_HANDLING);
		serve.AddFunction(function);
	}
	loader.RegisterFunction(serve);

	ScalarFunctionSet stop("cloudwatch_stop");
	for (auto &arguments : vector<vector<LogicalType>> {{}, {LogicalType::VARCHAR}}) {
		ScalarFunction function(arguments, LogicalType::VARCHAR, CloudwatchStop);
		function.SetStability(FunctionStability::VOLATILE);
		function.SetNullHandling(FunctionNullHandling::SPECIAL_HANDLING);
		stop.AddFunction(function);
	}
	loader.RegisterFunction(stop);
}

} // namespace duckdb
