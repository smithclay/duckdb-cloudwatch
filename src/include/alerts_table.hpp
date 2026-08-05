#pragma once

#include "duckdb.hpp"

namespace duckdb {

class ClientContext;
class FunctionData;
class TableCatalogEntry;
class TableFunction;

struct CloudwatchAlertsSettings {
	string region;
	string monitoring_endpoint;
	int64_t retries = 4;
	int64_t timeout_seconds = 60;
};

struct CloudwatchAlarmProtocolResult {
	string next_token;
	vector<string> names;
	vector<string> types;
	vector<string> statuses;
	vector<string> reasons;
	vector<string> reason_data;
};

//! Deterministic protocol helpers used by offline tests.
string BuildCloudwatchDescribeAlarmsRequestForTest(const string &state, const string &next_token);
CloudwatchAlarmProtocolResult ParseCloudwatchDescribeAlarmsResponseForTest(const string &response,
                                                                           const string &expected_state);

void GetCloudwatchAlertsSchema(vector<LogicalType> &types, vector<string> &names);
TableFunction GetCloudwatchAlertsTableScan(ClientContext &context, TableCatalogEntry &table, const string &secret_name,
                                           const CloudwatchAlertsSettings &settings,
                                           unique_ptr<FunctionData> &bind_data);

} // namespace duckdb
