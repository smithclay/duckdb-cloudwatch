#pragma once

#include "duckdb.hpp"

namespace duckdb {

class ClientContext;
class ExtensionLoader;
class FunctionData;
class TableCatalogEntry;
class TableFunction;

struct CloudwatchServiceMapSettings {
	string start_time = "-1h";
	string end_time = "now";
	string group_name;
	string group_arn;
	string region;
	string xray_endpoint;
	int64_t retries = 4;
	int64_t timeout_seconds = 60;
};

struct CloudwatchServiceDependencyProtocolRow {
	string source_service;
	string target_service;
	int64_t request_count = 0;
	int64_t error_count = 0;
	int64_t fault_count = 0;
	int64_t throttle_count = 0;
	double total_response_time_seconds = 0;
	bool has_statistics = false;
};

string BuildCloudwatchServiceGraphRequestForTest(int64_t start_ms, int64_t end_ms, const string &group_name,
                                                 const string &group_arn, const string &next_token);
vector<CloudwatchServiceDependencyProtocolRow>
ParseCloudwatchServiceGraphResponsesForTest(const vector<string> &responses);

void RegisterCloudwatchServiceDependenciesFunction(ExtensionLoader &loader);
void GetCloudwatchServiceDependenciesSchema(vector<LogicalType> &types, vector<string> &names);
void ValidateCloudwatchServiceMapSettings(const CloudwatchServiceMapSettings &settings, const string &error_prefix);
TableFunction GetCloudwatchServiceDependenciesTableScan(ClientContext &context, TableCatalogEntry &table,
                                                        const string &secret_name,
                                                        const CloudwatchServiceMapSettings &settings,
                                                        unique_ptr<FunctionData> &bind_data);

} // namespace duckdb
