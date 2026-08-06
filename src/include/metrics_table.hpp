#pragma once
#include "duckdb.hpp"
namespace duckdb { class ExtensionLoader; void RegisterCloudwatchMetricsFunction(ExtensionLoader &loader); }
