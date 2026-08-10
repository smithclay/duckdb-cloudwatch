#!/usr/bin/env bash
# End-to-end round trip against a local cloudwatch_serve listener.
#
# Exercises the real request paths -- CreateLogGroup, CreateLogStream, PutRetentionPolicy,
# PutLogEvents, FilterLogEvents, DeleteLogGroup -- with the listener standing in for CloudWatch
# Logs. No AWS account, no network, no credentials beyond a dummy secret.
#
# This lives here rather than in test/sql because the aws/s3 secret types are registered by httpfs,
# which the sqllogictest unittest binary cannot autoload; the CLI can.
#
#   ./test/e2e/roundtrip.sh [path/to/duckdb] [path/to/cloudwatch.duckdb_extension]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DUCKDB="${1:-$REPO_ROOT/build/release/duckdb}"
EXTENSION="${2:-$REPO_ROOT/build/release/extension/cloudwatch/cloudwatch.duckdb_extension}"
PORT="${CLOUDWATCH_E2E_PORT:-10547}"

for path in "$DUCKDB" "$EXTENSION"; do
    if [ ! -e "$path" ]; then
        echo "missing $path; run 'make release' first" >&2
        exit 1
    fi
done

# Fixed timestamps keep the expected output stable. They sit inside the query window below and are
# unrelated to wall-clock time, so this is not sensitive to when it runs.
OUTPUT=$("$DUCKDB" -noheader -list -c "
INSTALL httpfs; LOAD httpfs; INSTALL aws; LOAD aws;
LOAD '$EXTENSION';
CREATE SECRET cw_e2e (TYPE aws, KEY_ID 'AKIAEXAMPLE', SECRET 'examplesecret', REGION 'us-east-1');
SELECT 'serve=' || cloudwatch_serve('cloudwatch:localhost:$PORT');

SELECT 'bootstrap=' || create_cloudwatch_log_group('/app/e2e', 'cw_e2e', 'http://localhost:$PORT')
     || ',' || create_cloudwatch_log_group('/app/e2e', 'cw_e2e', 'http://localhost:$PORT')
     || ',' || create_cloudwatch_log_stream('/app/e2e', 'duckdb', 'cw_e2e', 'http://localhost:$PORT')
     || ',' || put_cloudwatch_retention_policy('/app/e2e', 1, 'cw_e2e', 'http://localhost:$PORT');

CREATE TABLE src AS
    SELECT 1754800000000000000::BIGINT + i * 1000000000 AS time_unix_nano, 'event-' || i AS body
    FROM range(3) t(i);
SELECT 'sent=' || count(send_cloudwatch_logs(l, '/app/e2e', 'duckdb', 'cw_e2e', 'http://localhost:$PORT'))
FROM src l;

SELECT 'received=' || count(*) FROM cloudwatch_logs WHERE log_group = '/app/e2e' AND log_stream = 'duckdb';

SELECT 'readback=' || string_agg(body, '|' ORDER BY time_unix_nano)
FROM read_cloudwatch_logs('/app/e2e', start_time => '1754700000000', end_time => '1754900000000',
                          \"order\" => 'asc', endpoint => 'http://localhost:$PORT', secret => 'cw_e2e');

SELECT 'filtered=' || count(*)
FROM read_cloudwatch_logs('/app/e2e', filter => 'event-1', start_time => '1754700000000',
                          end_time => '1754900000000', endpoint => 'http://localhost:$PORT',
                          secret => 'cw_e2e');

SELECT 'deleted=' || delete_cloudwatch_log_group('/app/e2e', 'cw_e2e', 'http://localhost:$PORT')
     || ',' || delete_cloudwatch_log_group('/app/e2e', 'cw_e2e', 'http://localhost:$PORT');
SELECT 'remaining=' || count(*) FROM cloudwatch_logs;
SELECT 'stopped=' || cloudwatch_stop('cloudwatch:localhost:$PORT');
")

echo "$OUTPUT"

failures=0
expect() {
    if ! grep -qxF "$1" <<<"$OUTPUT"; then
        echo "FAIL: expected '$1'" >&2
        failures=$((failures + 1))
    fi
}

expect "bootstrap=created,exists,created,ok"
expect "sent=3"
expect "received=3"
expect "readback=event-0|event-1|event-2"
expect "filtered=1"
expect "deleted=deleted,absent"
expect "remaining=0"
expect "stopped=stopped"

if [ "$failures" -ne 0 ]; then
    echo "roundtrip.sh: $failures check(s) failed" >&2
    exit 1
fi
echo "roundtrip.sh: OK"
