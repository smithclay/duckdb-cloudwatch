#pragma once

#include "duckdb.hpp"

namespace duckdb {

class ClientContext;

//! The resolved credential material stored by DuckDB's core AWS extension in an `aws` or `s3`
//! secret. CloudWatch deliberately consumes that format instead of defining another credential
//! chain.
struct CloudwatchCredentials {
	string secret_name;
	string access_key_id;
	string secret_access_key;
	string session_token;
	string region;
};

//! Resolve a named AWS secret, or the single preferred in-scope secret (`aws`, then `s3`). Region
//! precedence matches the core AWS extension: function argument, secret, s3_region setting,
//! AWS_REGION, AWS_DEFAULT_REGION.
CloudwatchCredentials GetCloudwatchCredentials(ClientContext &context, const string &secret_name,
                                               const string &explicit_region);

} // namespace duckdb
