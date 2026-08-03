#include "cloudwatch_signing.hpp"

#include "cloudwatch_secret.hpp"

#include "duckdb/common/exception.hpp"

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <iomanip>
#include <sstream>
#include <vector>

namespace duckdb {

namespace {

using Bytes = std::vector<unsigned char>;

string Hex(const unsigned char *data, size_t size) {
	std::ostringstream output;
	output << std::hex << std::setfill('0');
	for (size_t index = 0; index < size; index++) {
		output << std::setw(2) << static_cast<unsigned int>(data[index]);
	}
	return output.str();
}

string Sha256Hex(const string &value) {
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int digest_size = 0;
	if (EVP_Digest(value.data(), value.size(), digest, &digest_size, EVP_sha256(), nullptr) != 1) {
		throw InternalException("OpenSSL failed to hash a CloudWatch request");
	}
	return Hex(digest, digest_size);
}

Bytes HmacSha256(const unsigned char *key, size_t key_size, const string &value) {
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int digest_size = 0;
	if (!HMAC(EVP_sha256(), key, static_cast<int>(key_size), reinterpret_cast<const unsigned char *>(value.data()),
	          value.size(), digest, &digest_size)) {
		throw InternalException("OpenSSL failed to sign a CloudWatch request");
	}
	return Bytes(digest, digest + digest_size);
}

Bytes HmacSha256(const string &key, const string &value) {
	return HmacSha256(reinterpret_cast<const unsigned char *>(key.data()), key.size(), value);
}

Bytes HmacSha256(const Bytes &key, const string &value) {
	return HmacSha256(key.data(), key.size(), value);
}

} // namespace

CloudwatchSignedHeaders SignCloudwatchRequest(const CloudwatchCredentials &credentials, const string &host,
                                              const string &target, const string &body, const string &amz_date) {
	if (amz_date.size() != 16 || amz_date[8] != 'T' || amz_date.back() != 'Z') {
		throw InternalException("CloudWatch signing date must use YYYYMMDDTHHMMSSZ");
	}
	const auto date = amz_date.substr(0, 8);
	const auto credential_scope = date + "/" + credentials.region + "/logs/aws4_request";

	string canonical_headers = "content-type:application/x-amz-json-1.1\n";
	canonical_headers += "host:" + host + "\n";
	canonical_headers += "x-amz-date:" + amz_date + "\n";
	string signed_headers = "content-type;host;x-amz-date";
	if (!credentials.session_token.empty()) {
		canonical_headers += "x-amz-security-token:" + credentials.session_token + "\n";
		signed_headers += ";x-amz-security-token";
	}
	canonical_headers += "x-amz-target:" + target + "\n";
	signed_headers += ";x-amz-target";

	const auto canonical_request = "POST\n/\n\n" + canonical_headers + "\n" + signed_headers + "\n" + Sha256Hex(body);
	const auto string_to_sign =
	    "AWS4-HMAC-SHA256\n" + amz_date + "\n" + credential_scope + "\n" + Sha256Hex(canonical_request);

	auto date_key = HmacSha256("AWS4" + credentials.secret_access_key, date);
	auto region_key = HmacSha256(date_key, credentials.region);
	auto service_key = HmacSha256(region_key, "logs");
	auto signing_key = HmacSha256(service_key, "aws4_request");
	auto signature = HmacSha256(signing_key, string_to_sign);

	CloudwatchSignedHeaders result;
	result.amz_date = amz_date;
	result.security_token = credentials.session_token;
	result.authorization = "AWS4-HMAC-SHA256 Credential=" + credentials.access_key_id + "/" + credential_scope +
	                       ", SignedHeaders=" + signed_headers +
	                       ", Signature=" + Hex(signature.data(), signature.size());
	return result;
}

} // namespace duckdb
