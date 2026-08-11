#pragma once

#include "duckdb.hpp"

namespace duckdb {

class ExtensionLoader;

//! Register the local CloudWatch Logs listener:
//!   cloudwatch_serve([uri [, options_struct]]) -> endpoint URL
//!   cloudwatch_stop([uri])                     -> status
void RegisterCloudwatchServerFunctions(ExtensionLoader &loader);

//! Register per-DatabaseInstance server state. The state owns every listener and stops them before
//! the database is destroyed.
void RegisterCloudwatchServerState(ExtensionLoader &loader);

} // namespace duckdb
