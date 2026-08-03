#include "cloudwatch_catalog.hpp"

#include "cloudwatch_client.hpp"
#include "cloudwatch_json.hpp"
#include "cloudwatch_secret.hpp"
#include "logs_table.hpp"

#include "duckdb/catalog/catalog.hpp"
#include "duckdb/catalog/catalog_entry/schema_catalog_entry.hpp"
#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/attached_database.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/parser/column_definition.hpp"
#include "duckdb/parser/parsed_data/attach_info.hpp"
#include "duckdb/parser/parsed_data/create_schema_info.hpp"
#include "duckdb/parser/parsed_data/create_table_info.hpp"
#include "duckdb/storage/database_size.hpp"
#include "duckdb/storage/storage_extension.hpp"
#include "duckdb/storage/table_storage_info.hpp"
#include "duckdb/transaction/transaction.hpp"
#include "duckdb/transaction/transaction_manager.hpp"

#include <unordered_set>

namespace duckdb {
namespace {

[[noreturn]] void ThrowReadOnly() {
	throw BinderException("CloudWatch catalogs are read-only");
}

class CloudwatchTableEntry : public TableCatalogEntry {
public:
	CloudwatchTableEntry(Catalog &catalog, SchemaCatalogEntry &schema, const string &log_group,
	                     const string &secret_name, const CloudwatchLogsSettings &settings)
	    : CloudwatchTableEntry(catalog, schema, log_group, secret_name, settings, CreateInfo(schema, log_group)) {
	}

	unique_ptr<BaseStatistics> GetStatistics(ClientContext &, column_t) override {
		return nullptr;
	}

	TableFunction GetScanFunction(ClientContext &context, unique_ptr<FunctionData> &bind_data) override {
		return GetCloudwatchLogsTableScan(context, *this, secret_name, log_group, settings, bind_data);
	}

	TableStorageInfo GetStorageInfo(ClientContext &) override {
		return TableStorageInfo();
	}

private:
	CloudwatchTableEntry(Catalog &catalog, SchemaCatalogEntry &schema, const string &log_group,
	                     const string &secret_name, const CloudwatchLogsSettings &settings, CreateTableInfo info)
	    : TableCatalogEntry(catalog, schema, info), log_group(log_group), secret_name(secret_name), settings(settings) {
	}

	static CreateTableInfo CreateInfo(SchemaCatalogEntry &schema, const string &log_group) {
		CreateTableInfo info(schema, log_group);
		vector<LogicalType> types;
		vector<string> names;
		GetCloudwatchLogsSchema(types, names);
		for (idx_t i = 0; i < names.size(); i++) {
			info.columns.AddColumn(ColumnDefinition(names[i], types[i]));
		}
		return info;
	}

	string log_group;
	string secret_name;
	CloudwatchLogsSettings settings;
};

class CloudwatchSchemaEntry : public SchemaCatalogEntry {
public:
	CloudwatchSchemaEntry(Catalog &catalog, const vector<string> &log_groups, const string &secret_name,
	                      const CloudwatchLogsSettings &settings)
	    : CloudwatchSchemaEntry(catalog, log_groups, secret_name, settings, CreateInfo()) {
	}

private:
	CloudwatchSchemaEntry(Catalog &catalog, const vector<string> &log_groups, const string &secret_name,
	                      const CloudwatchLogsSettings &settings, CreateSchemaInfo info)
	    : SchemaCatalogEntry(catalog, info) {
		for (const auto &log_group : log_groups) {
			tables.push_back(make_uniq<CloudwatchTableEntry>(catalog, *this, log_group, secret_name, settings));
		}
	}

public:
	void Scan(ClientContext &, CatalogType type, const std::function<void(CatalogEntry &)> &callback) override {
		Scan(type, callback);
	}

	void Scan(CatalogType type, const std::function<void(CatalogEntry &)> &callback) override {
		if (type != CatalogType::TABLE_ENTRY) {
			return;
		}
		for (auto &table : tables) {
			callback(*table);
		}
	}

	optional_ptr<CatalogEntry> LookupEntry(CatalogTransaction, const EntryLookupInfo &lookup_info) override {
		if (lookup_info.GetCatalogType() != CatalogType::TABLE_ENTRY) {
			return nullptr;
		}
		const auto &name = lookup_info.GetEntryName();
		for (auto &table : tables) {
			if (table->name == name) {
				return table.get();
			}
		}
		for (auto &table : tables) {
			if (StringUtil::CIEquals(table->name, name)) {
				return table.get();
			}
		}
		return nullptr;
	}

	optional_ptr<CatalogEntry> CreateIndex(CatalogTransaction, CreateIndexInfo &, TableCatalogEntry &) override {
		ThrowReadOnly();
	}
	optional_ptr<CatalogEntry> CreateFunction(CatalogTransaction, CreateFunctionInfo &) override {
		ThrowReadOnly();
	}
	optional_ptr<CatalogEntry> CreateTable(CatalogTransaction, BoundCreateTableInfo &) override {
		ThrowReadOnly();
	}
	optional_ptr<CatalogEntry> CreateView(CatalogTransaction, CreateViewInfo &) override {
		ThrowReadOnly();
	}
	optional_ptr<CatalogEntry> CreateSequence(CatalogTransaction, CreateSequenceInfo &) override {
		ThrowReadOnly();
	}
	optional_ptr<CatalogEntry> CreateTableFunction(CatalogTransaction, CreateTableFunctionInfo &) override {
		ThrowReadOnly();
	}
	optional_ptr<CatalogEntry> CreateCopyFunction(CatalogTransaction, CreateCopyFunctionInfo &) override {
		ThrowReadOnly();
	}
	optional_ptr<CatalogEntry> CreatePragmaFunction(CatalogTransaction, CreatePragmaFunctionInfo &) override {
		ThrowReadOnly();
	}
	optional_ptr<CatalogEntry> CreateCollation(CatalogTransaction, CreateCollationInfo &) override {
		ThrowReadOnly();
	}
	optional_ptr<CatalogEntry> CreateCoordinateSystem(CatalogTransaction, CreateCoordinateSystemInfo &) override {
		ThrowReadOnly();
	}
	optional_ptr<CatalogEntry> CreateType(CatalogTransaction, CreateTypeInfo &) override {
		ThrowReadOnly();
	}
	void DropEntry(ClientContext &, DropInfo &) override {
		ThrowReadOnly();
	}
	void Alter(CatalogTransaction, AlterInfo &) override {
		ThrowReadOnly();
	}

private:
	static CreateSchemaInfo CreateInfo() {
		CreateSchemaInfo info;
		info.schema = "logs";
		return info;
	}

	vector<unique_ptr<CloudwatchTableEntry>> tables;
};

class CloudwatchCatalog : public Catalog {
public:
	CloudwatchCatalog(AttachedDatabase &db, vector<string> log_groups, string secret_name,
	                  const CloudwatchLogsSettings &settings)
	    : Catalog(db), logs_schema(make_uniq<CloudwatchSchemaEntry>(*this, log_groups, secret_name, settings)) {
	}

	void Initialize(bool) override {
	}

	string GetCatalogType() override {
		return "cloudwatch";
	}

	optional_ptr<CatalogEntry> CreateSchema(CatalogTransaction, CreateSchemaInfo &) override {
		ThrowReadOnly();
	}

	void ScanSchemas(ClientContext &, std::function<void(SchemaCatalogEntry &)> callback) override {
		callback(*logs_schema);
	}

	optional_ptr<SchemaCatalogEntry> LookupSchema(CatalogTransaction, const EntryLookupInfo &schema_lookup,
	                                              OnEntryNotFound if_not_found) override {
		if (StringUtil::CIEquals(schema_lookup.GetEntryName(), "logs")) {
			return logs_schema.get();
		}
		if (if_not_found == OnEntryNotFound::THROW_EXCEPTION) {
			throw CatalogException(schema_lookup.GetErrorContext(), "Schema with name %s does not exist!",
			                       schema_lookup.GetEntryName());
		}
		return nullptr;
	}

	PhysicalOperator &PlanCreateTableAs(ClientContext &, PhysicalPlanGenerator &, LogicalCreateTable &,
	                                    PhysicalOperator &) override {
		ThrowReadOnly();
	}
	PhysicalOperator &PlanInsert(ClientContext &, PhysicalPlanGenerator &, LogicalInsert &,
	                             optional_ptr<PhysicalOperator>) override {
		ThrowReadOnly();
	}
	PhysicalOperator &PlanDelete(ClientContext &, PhysicalPlanGenerator &, LogicalDelete &,
	                             PhysicalOperator &) override {
		ThrowReadOnly();
	}
	PhysicalOperator &PlanUpdate(ClientContext &, PhysicalPlanGenerator &, LogicalUpdate &,
	                             PhysicalOperator &) override {
		ThrowReadOnly();
	}

	DatabaseSize GetDatabaseSize(ClientContext &) override {
		return DatabaseSize();
	}
	bool InMemory() override {
		return false;
	}
	string GetDBPath() override {
		return "cloudwatch:";
	}

private:
	void DropSchema(ClientContext &, DropInfo &) override {
		ThrowReadOnly();
	}

	unique_ptr<CloudwatchSchemaEntry> logs_schema;
};

class CloudwatchTransaction : public Transaction {
public:
	CloudwatchTransaction(TransactionManager &manager, ClientContext &context) : Transaction(manager, context) {
	}

	void SetReadWrite() override {
		ThrowReadOnly();
	}

	void SetModifications(DatabaseModificationType) override {
		ThrowReadOnly();
	}
};

class CloudwatchTransactionManager : public TransactionManager {
public:
	explicit CloudwatchTransactionManager(AttachedDatabase &db) : TransactionManager(db) {
	}

	Transaction &StartTransaction(ClientContext &context) override {
		auto transaction = make_uniq<CloudwatchTransaction>(*this, context);
		auto result = transaction.get();
		lock_guard<mutex> guard(transaction_lock);
		transactions.emplace(result, std::move(transaction));
		return *result;
	}

	ErrorData CommitTransaction(ClientContext &, Transaction &transaction) override {
		lock_guard<mutex> guard(transaction_lock);
		transactions.erase(&transaction);
		return ErrorData();
	}

	void RollbackTransaction(Transaction &transaction) override {
		lock_guard<mutex> guard(transaction_lock);
		transactions.erase(&transaction);
	}

	void Checkpoint(ClientContext &, bool) override {
	}

private:
	mutex transaction_lock;
	unordered_map<Transaction *, unique_ptr<Transaction>> transactions;
};

string ParseAttachString(const string &option_name, const Value &value, bool allow_empty = true) {
	if (value.IsNull() || value.type().id() != LogicalTypeId::VARCHAR) {
		throw InvalidInputException("CloudWatch ATTACH option %s must be a non-null VARCHAR", option_name);
	}
	auto result = value.GetValue<string>();
	if (!allow_empty && result.empty()) {
		throw InvalidInputException("CloudWatch ATTACH option %s must not be empty", option_name);
	}
	return result;
}

int64_t ParseAttachInteger(const string &option_name, const Value &value) {
	if (value.IsNull() || !value.type().IsIntegral()) {
		throw InvalidInputException("CloudWatch ATTACH option %s must be a non-null integer", option_name);
	}
	return value.GetValue<int64_t>();
}

vector<string> ParseExplicitLogGroups(const Value &value) {
	if (value.IsNull() || value.type().id() != LogicalTypeId::LIST ||
	    ListType::GetChildType(value.type()).id() != LogicalTypeId::VARCHAR) {
		throw InvalidInputException("CloudWatch ATTACH option LOG_GROUPS must be a VARCHAR[]");
	}
	vector<string> result;
	std::unordered_set<string> seen;
	for (const auto &child : ListValue::GetChildren(value)) {
		if (child.IsNull() || child.type().id() != LogicalTypeId::VARCHAR) {
			throw InvalidInputException("CloudWatch ATTACH option LOG_GROUPS must contain only non-null VARCHAR names");
		}
		auto name = child.GetValue<string>();
		if (name.empty()) {
			throw InvalidInputException("CloudWatch ATTACH option LOG_GROUPS must not contain empty names");
		}
		if (seen.insert(name).second) {
			result.push_back(std::move(name));
		}
	}
	return result;
}

vector<string> DiscoverLogGroups(ClientContext &context, const CloudwatchClient &client) {
	vector<string> result;
	string next_token;
	for (;;) {
		auto response = client.DescribeLogGroups(context, BuildCloudwatchDescribeGroupsRequest(next_token));
		auto new_token = ParseCloudwatchDescribeGroupsResponse(response, result);
		if (new_token.empty() || new_token == next_token) {
			break;
		}
		next_token = std::move(new_token);
	}
	return result;
}

unique_ptr<Catalog> AttachCloudwatch(optional_ptr<StorageExtensionInfo>, ClientContext &context, AttachedDatabase &db,
                                     const string &, AttachInfo &info, AttachOptions &options) {
	if (info.path != "cloudwatch:") {
		throw InvalidInputException("CloudWatch catalogs must be attached from the path 'cloudwatch:'");
	}

	string secret_name;
	vector<string> log_groups;
	CloudwatchLogsSettings settings;
	bool groups_supplied = false;
	for (const auto &option : options.options) {
		auto key = StringUtil::Lower(option.first);
		if (key == "secret") {
			secret_name = ParseAttachString("SECRET", option.second, false);
		} else if (key == "log_groups") {
			log_groups = ParseExplicitLogGroups(option.second);
			groups_supplied = true;
		} else if (key == "region") {
			settings.region = ParseAttachString("REGION", option.second, false);
		} else if (key == "endpoint") {
			settings.endpoint = ParseAttachString("ENDPOINT", option.second, false);
		} else if (key == "filter") {
			settings.filter_pattern = ParseAttachString("FILTER", option.second);
		} else if (key == "start_time") {
			settings.start_time = ParseAttachString("START_TIME", option.second, false);
		} else if (key == "end_time") {
			settings.end_time = ParseAttachString("END_TIME", option.second, false);
		} else if (key == "order") {
			settings.order = StringUtil::Lower(ParseAttachString("ORDER", option.second, false));
		} else if (key == "page_size") {
			settings.page_size = ParseAttachInteger("PAGE_SIZE", option.second);
		} else if (key == "max_rows") {
			settings.max_rows = ParseAttachInteger("MAX_ROWS", option.second);
		} else if (key == "retries") {
			settings.retries = ParseAttachInteger("RETRIES", option.second);
		} else if (key == "timeout") {
			settings.timeout_seconds = ParseAttachInteger("TIMEOUT", option.second);
		} else if (key == "unmask") {
			if (option.second.IsNull() || option.second.type().id() != LogicalTypeId::BOOLEAN) {
				throw InvalidInputException("CloudWatch ATTACH option UNMASK must be a non-null BOOLEAN");
			}
			settings.unmask = option.second.GetValue<bool>();
		} else {
			throw InvalidInputException(
			    "Unsupported CloudWatch ATTACH option '%s'; supported options are SECRET, LOG_GROUPS, REGION, "
			    "ENDPOINT, FILTER, START_TIME, END_TIME, ORDER, PAGE_SIZE, MAX_ROWS, RETRIES, TIMEOUT, and UNMASK",
			    option.first);
		}
	}
	ValidateCloudwatchLogsSettings(settings, "CloudWatch ATTACH");

	auto credentials = GetCloudwatchCredentials(context, secret_name, settings.region);
	if (secret_name.empty()) {
		secret_name = credentials.secret_name;
	}
	if (!groups_supplied) {
		CloudwatchClient client;
		client.credentials = credentials;
		client.endpoint = settings.endpoint;
		client.retries = static_cast<uint64_t>(settings.retries);
		client.timeout_seconds = static_cast<uint64_t>(settings.timeout_seconds);
		log_groups = DiscoverLogGroups(context, client);
	}

	db.SetReadOnlyDatabase();
	return make_uniq<CloudwatchCatalog>(db, std::move(log_groups), std::move(secret_name), settings);
}

unique_ptr<TransactionManager> CreateCloudwatchTransactionManager(optional_ptr<StorageExtensionInfo>,
                                                                  AttachedDatabase &db, Catalog &) {
	return make_uniq<CloudwatchTransactionManager>(db);
}

} // namespace

void RegisterCloudwatchCatalog(ExtensionLoader &loader) {
	auto storage = make_shared_ptr<StorageExtension>();
	storage->attach = AttachCloudwatch;
	storage->create_transaction_manager = CreateCloudwatchTransactionManager;
	StorageExtension::Register(DBConfig::GetConfig(loader.GetDatabaseInstance()), "cloudwatch", std::move(storage));
}

} // namespace duckdb
