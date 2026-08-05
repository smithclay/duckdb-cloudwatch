#define DUCKDB_EXTENSION_MAIN

#include "cloudwatch_extension.hpp"

#include "cloudwatch_catalog.hpp"
#include "logs_table.hpp"
#include "send_logs.hpp"
#include "service_dependencies.hpp"

#include "duckdb.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

namespace duckdb {

static void LoadInternal(ExtensionLoader &loader) {
	RegisterCloudwatchCatalog(loader);
	RegisterCloudwatchLogsFunction(loader);
	RegisterCloudwatchSendLogsFunction(loader);
	RegisterCloudwatchServiceDependenciesFunction(loader);
}

void CloudwatchExtension::Load(ExtensionLoader &loader) {
	LoadInternal(loader);
}

std::string CloudwatchExtension::Name() {
	return "cloudwatch";
}

std::string CloudwatchExtension::Version() const {
#ifdef EXT_VERSION_CLOUDWATCH
	return EXT_VERSION_CLOUDWATCH;
#else
	return "";
#endif
}

} // namespace duckdb

extern "C" {

DUCKDB_CPP_EXTENSION_ENTRY(cloudwatch, loader) {
	duckdb::LoadInternal(loader);
}
}
