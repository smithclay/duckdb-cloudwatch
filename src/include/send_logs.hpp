#pragma once

#include "duckdb.hpp"

namespace duckdb {

class ExtensionLoader;

//! Register send_cloudwatch_logs(log, log_group, log_stream [, secret]).
void RegisterCloudwatchSendLogsFunction(ExtensionLoader &loader);

} // namespace duckdb
