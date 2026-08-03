#pragma once

#include "duckdb.hpp"

namespace duckdb {

class ExtensionLoader;
class ClientContext;
class FunctionData;
class TableCatalogEntry;
class TableFunction;

//! Scan settings shared by the table function and ATTACH-backed catalog tables.
struct CloudwatchLogsSettings {
	string filter_pattern;
	string start_time = "-15m";
	string end_time = "now";
	string order = "desc";
	int64_t page_size = 10000;
	int64_t max_rows = 0;
	int64_t retries = 4;
	int64_t timeout_seconds = 60;
	bool unmask = false;
	string region;
	string endpoint;
};

//! Register `read_cloudwatch_logs(log_group, ...)`.
void RegisterCloudwatchLogsFunction(ExtensionLoader &loader);

//! Stable 18-column schema shared with duckdb-otlp and the sibling observability extensions.
void GetCloudwatchLogsSchema(vector<LogicalType> &types, vector<string> &names);

//! Validate settings shared by both SQL surfaces.
void ValidateCloudwatchLogsSettings(const CloudwatchLogsSettings &settings, const string &error_prefix);

//! Build an already-bound scan for one log-group table in an attached catalog.
TableFunction GetCloudwatchLogsTableScan(ClientContext &context, TableCatalogEntry &table, const string &secret_name,
                                         const string &log_group, const CloudwatchLogsSettings &settings,
                                         unique_ptr<FunctionData> &bind_data);

} // namespace duckdb
