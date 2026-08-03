#pragma once

#include "duckdb.hpp"

namespace duckdb {

class ExtensionLoader;

//! Register ATTACH 'cloudwatch:' ... (TYPE cloudwatch).
void RegisterCloudwatchCatalog(ExtensionLoader &loader);

} // namespace duckdb
