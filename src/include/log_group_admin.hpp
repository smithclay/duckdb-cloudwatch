#pragma once

#include "duckdb.hpp"

namespace duckdb {

class ExtensionLoader;

//! Register create_cloudwatch_log_group, delete_cloudwatch_log_group, create_cloudwatch_log_stream,
//! and put_cloudwatch_retention_policy.
void RegisterCloudwatchLogGroupAdminFunctions(ExtensionLoader &loader);

} // namespace duckdb
