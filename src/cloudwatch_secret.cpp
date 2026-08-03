#include "cloudwatch_secret.hpp"

#include "duckdb/catalog/catalog_transaction.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/secret/secret.hpp"
#include "duckdb/main/secret/secret_manager.hpp"

#include <cstdlib>

namespace duckdb {

namespace {

bool IsAwsSecretType(const string &type) {
	return type == "aws" || type == "s3";
}

string SecretString(const KeyValueSecret &secret, const string &key) {
	auto value = secret.TryGetValue(key);
	return value.IsNull() ? string() : value.ToString();
}

unique_ptr<SecretEntry> FindAwsSecret(ClientContext &context, const string &secret_name) {
	auto &manager = SecretManager::Get(context);
	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(context);

	if (!secret_name.empty()) {
		auto entry = manager.GetSecretByName(transaction, secret_name);
		if (!entry) {
			throw BinderException("Secret with name \"%s\" not found", secret_name);
		}
		auto type = entry->secret->GetType();
		if (!IsAwsSecretType(type)) {
			throw BinderException(
			    "Secret \"%s\" is of type \"%s\", but CloudWatch requires an \"aws\" or \"s3\" secret", secret_name,
			    type);
		}
		return entry;
	}

	auto all_secrets = manager.AllSecrets(transaction);
	for (const auto &wanted_type : {"aws", "s3"}) {
		vector<const SecretEntry *> matches;
		for (const auto &entry : all_secrets) {
			if (entry.secret->GetType() == wanted_type) {
				matches.push_back(&entry);
			}
		}
		if (matches.size() > 1) {
			throw BinderException("Found %d secrets of type \"%s\"; name the one to use with the SECRET parameter",
			                      matches.size(), wanted_type);
		}
		if (matches.size() == 1) {
			return make_uniq<SecretEntry>(*matches[0]);
		}
	}

	throw BinderException("No AWS credentials found. Load DuckDB's aws extension and create a secret, e.g. "
	                      "CREATE SECRET (TYPE aws, PROVIDER credential_chain, REGION 'us-east-1')");
}

} // namespace

CloudwatchCredentials GetCloudwatchCredentials(ClientContext &context, const string &secret_name,
                                               const string &explicit_region) {
	auto entry = FindAwsSecret(context, secret_name);
	auto *secret = dynamic_cast<const KeyValueSecret *>(entry->secret.get());
	if (!secret) {
		throw BinderException("AWS secret \"%s\" is not a key-value secret", entry->secret->GetName());
	}

	CloudwatchCredentials result;
	result.secret_name = secret->GetName();
	result.access_key_id = SecretString(*secret, "key_id");
	result.secret_access_key = SecretString(*secret, "secret");
	result.session_token = SecretString(*secret, "session_token");
	result.region = explicit_region.empty() ? SecretString(*secret, "region") : explicit_region;
	StringUtil::Trim(result.region);

	if (result.access_key_id.empty() || result.secret_access_key.empty()) {
		throw BinderException("AWS secret \"%s\" has no resolved KEY_ID/SECRET credentials", result.secret_name);
	}

	if (result.region.empty()) {
		Value setting;
		if (context.TryGetCurrentSetting("s3_region", setting) && !setting.IsNull()) {
			result.region = setting.ToString();
		}
	}
	if (result.region.empty()) {
		if (const char *region = getenv("AWS_REGION")) {
			result.region = region;
		} else if (const char *region = getenv("AWS_DEFAULT_REGION")) {
			result.region = region;
		}
	}
	if (result.region.empty()) {
		throw BinderException("No AWS region found. Pass REGION, set it on the AWS secret, set s3_region, or configure "
		                      "AWS_REGION/AWS_DEFAULT_REGION");
	}
	return result;
}

} // namespace duckdb
