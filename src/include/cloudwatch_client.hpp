#pragma once

#include "cloudwatch_secret.hpp"

#ifndef __EMSCRIPTEN__
namespace duckdb_httplib_openssl {
class Client;
}
#endif

namespace duckdb {

class ClientContext;

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
	string BaseUrl() const;
	string Host() const;

private:
	string Post(ClientContext &context, const string &target, const string &request_body) const;
#ifndef __EMSCRIPTEN__
	mutable unique_ptr<duckdb_httplib_openssl::Client> connection;
	duckdb_httplib_openssl::Client &GetConnection() const;
#endif
};

} // namespace duckdb
