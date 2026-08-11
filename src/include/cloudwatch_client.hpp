#pragma once

#include "cloudwatch_secret.hpp"

#include <mutex>

#ifndef __EMSCRIPTEN__
namespace duckdb_httplib_openssl {
class Client;
}
#endif

namespace duckdb {

class ClientContext;

enum class CloudwatchService : uint8_t { LOGS, MONITORING, XRAY };

//! Which non-2xx responses may be retried. `idempotent` allows the full retryable set (429, 5xx,
//! throttling); otherwise only responses proving the request was rejected before doing any work are
//! retried. `retry_on_limit_exceeded` additionally retries LimitExceededException, which for
//! StartQuery is the transient concurrent-query cap rather than a permanent quota.
struct CloudwatchRetryPolicy {
	bool idempotent;
	bool retry_on_limit_exceeded;

	explicit CloudwatchRetryPolicy(bool idempotent = true, bool retry_on_limit_exceeded = false)
	    : idempotent(idempotent), retry_on_limit_exceeded(retry_on_limit_exceeded) {
	}
};

//! Small CloudWatch Logs JSON-API client. Authentication is SigV4 over credentials already
//! resolved by DuckDB's AWS extension. A keep-alive connection is reused for pagination.
struct CloudwatchClient {
	mutable CloudwatchCredentials credentials;
	string endpoint;
	uint64_t timeout_seconds = 60;
	uint64_t retries = 4;

	CloudwatchClient();
	~CloudwatchClient();

	string FilterLogEvents(ClientContext &context, const string &request_body) const;
	string DescribeLogGroups(ClientContext &context, const string &request_body) const;
	string PutLogEvents(ClientContext &context, const string &request_body) const;
	string DescribeAlarms(ClientContext &context, const string &request_body) const;
	string GetMetricData(ClientContext &context, const string &request_body) const;
	string GetServiceGraph(ClientContext &context, const string &request_body) const;

	//! Logs Insights. A scan is billed per byte, so a retry that duplicates a started query costs
	//! real money; StartQuery therefore retries only responses proving nothing was started --
	//! throttling and the concurrent-query limit.
	string StartQuery(ClientContext &context, const string &request_body) const;
	string GetQueryResults(ClientContext &context, const string &request_body) const;
	string StopQuery(ClientContext &context, const string &request_body) const;

	//! Log-group administration. AWS reports "already exists" as an error rather than a no-op, so
	//! the caller -- not this client -- decides whether that counts as idempotent success. Each
	//! returns the response body, or throws for any non-2xx.
	string CreateLogGroup(ClientContext &context, const string &request_body) const;
	string CreateLogStream(ClientContext &context, const string &request_body) const;
	string DeleteLogGroup(ClientContext &context, const string &request_body) const;
	string PutRetentionPolicy(ClientContext &context, const string &request_body) const;
	string DescribeLogStreams(ClientContext &context, const string &request_body) const;

	string BaseUrl(CloudwatchService service = CloudwatchService::LOGS) const;
	string Host(CloudwatchService service = CloudwatchService::LOGS) const;

	//! POST a Logs API target without turning a non-2xx into an exception: on failure this returns
	//! false and fills `error_body`, letting callers branch on an AWS error code such as
	//! ResourceAlreadyExistsException instead of pattern-matching an exception message. Transport
	//! failures still throw, because they carry no AWS error code to classify.
	bool TryPostLogs(ClientContext &context, const string &target, const string &request_body, string &response_body,
	                 string &error_body) const;

private:
	string Post(ClientContext &context, CloudwatchService service, const string &path, const string &target,
	            const string &content_type, const string &request_body,
	            CloudwatchRetryPolicy policy = CloudwatchRetryPolicy()) const;
	//! Shared implementation of Post/TryPostLogs. When `error_body` is non-null a non-2xx response
	//! is reported through it instead of thrown.
	bool PostInternal(ClientContext &context, CloudwatchService service, const string &path, const string &target,
	                  const string &content_type, const string &request_body, CloudwatchRetryPolicy policy,
	                  string &response_body, string *error_body) const;
	//! Function bind data is shared by DuckDB projection workers. cpp-httplib clients are not safe
	//! for concurrent use, so writes through this client are serialized. PutLogEvents no longer
	//! requires sequence-token serialization; this lock protects only the local transport object.
	mutable std::mutex write_mutex;
#ifndef __EMSCRIPTEN__
	mutable unique_ptr<duckdb_httplib_openssl::Client> connection;
	duckdb_httplib_openssl::Client &GetConnection(CloudwatchService service) const;
#endif
};

} // namespace duckdb
