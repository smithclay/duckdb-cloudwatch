#pragma once

#include "duckdb.hpp"

namespace duckdb {

class ExtensionLoader;

//! Register send_cloudwatch_metrics(metric, namespace [, secret [, endpoint]]).
void RegisterCloudwatchSendMetricsFunction(ExtensionLoader &loader);

} // namespace duckdb
