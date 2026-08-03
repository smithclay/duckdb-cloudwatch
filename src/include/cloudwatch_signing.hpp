#pragma once

#include "duckdb.hpp"

namespace duckdb {

struct CloudwatchCredentials;

struct CloudwatchSignedHeaders {
	string amz_date;
	string authorization;
	string security_token;
};

//! Sign one CloudWatch Logs AWS JSON 1.1 POST using Signature Version 4. `amz_date` must be
//! YYYYMMDDTHHMMSSZ. Kept independent of transport so it can be tested deterministically.
CloudwatchSignedHeaders SignCloudwatchRequest(const CloudwatchCredentials &credentials, const string &host,
                                              const string &target, const string &body, const string &amz_date);

} // namespace duckdb
