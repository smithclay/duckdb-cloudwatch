#pragma once

#include "duckdb.hpp"

namespace duckdb {

class ExtensionLoader;

//! Register `read_cloudwatch_logs_insights(query, log_groups, ...)`.
void RegisterCloudwatchLogsInsightsFunction(ExtensionLoader &loader);

} // namespace duckdb
