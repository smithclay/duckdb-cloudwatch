# duckdb-cloudwatch

A native DuckDB 1.5.5 extension that reads and writes Amazon CloudWatch Logs, reads CloudWatch
alarms, and reads AWS X-Ray service dependencies.
Rows use the same flat 18-column OTLP log schema as
[`duckdb-otlp`](https://github.com/smithclay/otlp2records) and the sibling Datadog, Splunk, and
Google Cloud observability extensions, so telemetry from those sources can be combined with
`UNION ALL`.

## Quick start

```sql
INSTALL aws;
LOAD aws;
LOAD cloudwatch;

-- Reuse the AWS SDK credential chain supported by DuckDB's core AWS extension.
CREATE SECRET cw_prod (
    TYPE aws,
    PROVIDER credential_chain,
    REGION 'eu-west-1'
);

SELECT time_unix_nano, observed_time_unix_nano, body, resource_attributes
FROM read_cloudwatch_logs(
    '/aws/lambda/orders-api',
    filter     => 'ERROR',
    start_time => '-1h',
    "order"    => 'desc'
)
LIMIT 100;
```

## CloudWatch catalog

Attach an AWS account as a read-only catalog and query each log group as a table in the `logs`
schema. Log-group names normally contain slashes, so quote the table identifier:

```sql
ATTACH 'cloudwatch:' AS cw (
    TYPE cloudwatch,
    SECRET 'cw_prod',
    LOG_GROUPS ['/aws/lambda/orders-api', '/aws/lambda/payments-api']
);

SELECT time_unix_nano, body
FROM cw.logs."/aws/lambda/orders-api"
LIMIT 100;

-- Lazy API-backed operational views.
SELECT * FROM cw.alerts.open;
SELECT * FROM cw.service_map.dependencies;
```

Explicit `LOG_GROUPS` makes `ATTACH` deterministic and performs no network request. When it is
omitted, the extension calls `DescribeLogGroups`, follows every continuation token, and snapshots
the discovered names into the catalog. Discovery requires `logs:DescribeLogGroups`; reading a
table requires `logs:FilterLogEvents`.

Catalog tables use the same 18-column schema and scanning implementation as
`read_cloudwatch_logs`. Scan defaults can be fixed for the whole attachment:

```sql
ATTACH 'cloudwatch:' AS recent_errors (
    TYPE cloudwatch,
    SECRET 'cw_prod',
    FILTER 'ERROR',
    START_TIME '-1h',
    END_TIME 'now',
    "ORDER" 'desc',
    PAGE_SIZE 10000,
    MAX_ROWS 50000
);
```

Supported options are `SECRET`, `LOG_GROUPS`, `REGION`, `ENDPOINT`, `LOGS_ENDPOINT`, `MONITORING_ENDPOINT`,
`XRAY_ENDPOINT`, `FILTER`, `START_TIME`, `END_TIME`, `SERVICE_MAP_START_TIME`,
`SERVICE_MAP_END_TIME`, `XRAY_GROUP_NAME`, `XRAY_GROUP_ARN`, `ORDER`, `PAGE_SIZE`, `MAX_ROWS`,
`RETRIES`, `TIMEOUT`, and `UNMASK`. `ENDPOINT` remains a backward-compatible alias for
`LOGS_ENDPOINT`; the monitoring
and X-Ray overrides are intentionally separate. The selected AWS
secret name is pinned at `ATTACH`, while its resolved credentials are fetched again when a catalog
table is bound. The catalog rejects DDL and DML.

The AWS identity needs `logs:FilterLogEvents` on the log group. Both generic `aws` secrets and
existing `s3` secrets are accepted. Named profiles, environment credentials, SSO, assumed roles,
web identity/IRSA, instance metadata, and credential refresh remain the responsibility of the
core `aws` extension; this extension consumes the resolved `KEY_ID`, `SECRET`, `SESSION_TOKEN`, and
`REGION` fields from its secret.

When no secret name is supplied, a single `aws` secret is preferred over a single `s3` secret.
Ambiguous secrets fail with an error asking for `secret => 'name'`. Region resolution follows the
core AWS order: the function's `region`, the secret, DuckDB's `s3_region` setting, `AWS_REGION`,
then `AWS_DEFAULT_REGION`.

## `read_cloudwatch_logs`

The first argument is a log-group name or ARN. An ARN is sent as `logGroupIdentifier`; any other
value is sent as `logGroupName`.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `filter` | VARCHAR | empty | CloudWatch Logs filter pattern. |
| `start_time` | VARCHAR | `-15m` | `now`, a relative duration such as `-2h`/`-7d`, epoch milliseconds, or ISO-8601. |
| `end_time` | VARCHAR | `now` | Same forms as `start_time`. |
| `log_stream_prefix` | VARCHAR | empty | Restrict the scan to stream names with this prefix. |
| `log_streams` | VARCHAR[] | empty | Restrict the scan to at most 100 exact stream names; mutually exclusive with the prefix. |
| `order` | VARCHAR | `desc` | `desc` for newest first or `asc` for oldest first. |
| `page_size` | BIGINT | `10000` | Maximum events per request (1–10,000). CloudWatch can return fewer. |
| `max_rows` | BIGINT | `0` | Total row safety cap; 0 is unlimited. |
| `retries` | BIGINT | `4` | Retry budget for throttling, 5xx, and transport errors. |
| `timeout` | BIGINT | `60` | Per-request connect/read timeout in seconds. |
| `unmask` | BOOLEAN | `false` | Ask CloudWatch to show fields protected by a data-protection policy. Requires `logs:Unmask`. |
| `secret` | VARCHAR | inferred | Name of an `aws` or `s3` DuckDB secret. |
| `region` | VARCHAR | inferred | Explicit AWS region override. |
| `endpoint` | VARCHAR | AWS regional endpoint | Custom CloudWatch-compatible origin, primarily for test doubles and private endpoints. |

CloudWatch pages are capped by both event count and a 1 MiB response size. Partially full and even
empty pages can still contain a continuation token, so the scan follows tokens until AWS omits one,
the token stops advancing, or `max_rows` is reached. Pages stream into DuckDB rather than being
accumulated for the whole query. Retry waits check DuckDB's interrupt flag approximately every
100 ms.

The extension signs every request with AWS Signature Version 4 over HTTPS. It does not follow HTTP
redirects, which prevents forwarding signed credentials to another origin.

## `send_cloudwatch_logs`

`send_cloudwatch_logs` pushes an OTLP-shaped log table to an existing CloudWatch Logs group and
stream through [`PutLogEvents`](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutLogEvents.html).
Pass a whole row as the first argument; each accepted row returns `'ok'`:

```sql
-- Resolve the first unambiguous in-scope aws/s3 secret.
SELECT send_cloudwatch_logs(l, '/app/orders', 'duckdb-import')
FROM my_logs l;

-- Or pin a named secret as the fourth argument.
SELECT send_cloudwatch_logs(l, '/app/orders', 'duckdb-import', 'cw_prod')
FROM read_cloudwatch_logs('/archive/orders', start_time => '-1h') l;
```

The log group and stream arguments must be constant strings. That makes the destination explicit,
lets the function batch rows safely, and avoids turning row data into AWS resource names by
accident. Both resources must already exist; the sender never creates or mutates groups, streams,
or retention policies. The optional fourth argument is a constant `aws`/`s3` secret name; region
and refreshable credentials use the same resolution path as the reader.

CloudWatch exposes only a message and timestamp on each writable event, so the mapping is
deliberately narrow:

| Struct column (first match wins) | `PutLogEvents` field |
|---|---|
| `body` / `message` | `message` (required and non-empty) |
| `time_unix_nano` / `timestamp` | `timestamp` in epoch milliseconds |
| `observed_time_unix_nano` | timestamp fallback |

Integer `time_unix_nano` and `observed_time_unix_nano` values are interpreted as epoch
nanoseconds; an integer `timestamp` is epoch milliseconds. Temporal values are converted precisely
to milliseconds. If no usable timestamp is present, execution time is used. Other OTLP and unknown
fields are ignored rather than changing the original message into a JSON envelope. A `NULL` struct
returns `NULL` and sends nothing.

Rows are stable-sorted by timestamp and split into API-valid batches: at most 10,000 events and
1,048,576 bytes (UTF-8 message bytes plus AWS's 26-byte charge per event), with no batch spanning
more than 24 hours. Sequence tokens are intentionally omitted because AWS no longer uses them and
permits parallel `PutLogEvents` calls to one stream. The local HTTP connection is still serialized
because DuckDB may evaluate the scalar concurrently and the shared transport is not thread-safe.

Writes are non-idempotent. The client retries only failures known not to have sent request bytes and
definite throttling responses; ambiguous transport failures and 5xx responses are surfaced to avoid
silently duplicating logs. AWS can partially accept a request while returning HTTP 200, so any
`rejectedLogEventsInfo` or rejected entity is reported as an error instead of marking every row
`'ok'`. Earlier batches may already be stored if a later batch fails. Sending requires
`logs:PutLogEvents` on the destination stream.

## Alarms and service dependencies

`cw.alerts.open` lazily calls `DescribeAlarms` and returns metric, composite, and log alarms whose
state is `ALARM` or `INSUFFICIENT_DATA`. It includes alarm identity, timestamps, reason data,
actions, metric fields, dimensions JSON, and the complete type-specific configuration as JSON.
Scanning requires `cloudwatch:DescribeAlarms`.

X-Ray dependencies are available through both the catalog and a table function:

```sql
SELECT * FROM cw.service_map.dependencies;

SELECT *
FROM read_cloudwatch_service_dependencies(
    start_time => '-15m',
    end_time   => 'now',
    group_name => 'production',
    secret     => 'cw_prod'
);
```

The catalog defaults to the latest hour; relative times are evaluated when the table is scanned.
Set `SERVICE_MAP_START_TIME`, `SERVICE_MAP_END_TIME`, and optionally one of `XRAY_GROUP_NAME` or
`XRAY_GROUP_ARN` on `ATTACH`. The function accepts the equivalent `start_time`, `end_time`,
`group_name`, and `group_arn` parameters, plus `secret`, `region`, `xray_endpoint`, `retries`, and
`timeout`. It follows all `GetServiceGraph` pages before resolving directed edges so references to
services on later pages are preserved. Scanning requires `xray:GetServiceGraph`.

Both service-map SQL surfaces return: `provider`, `source_service`, `target_service`, `source_type`,
`target_type`, `edge_type`, `environment`, `window_start`, `window_end`, `request_count`,
`error_count`, `fault_count`, `throttle_count`, `total_response_time_seconds`, `source_attributes`,
`target_attributes`, and `edge_attributes`. Attribute columns are JSON strings; `environment` is
`NULL` for CloudWatch/X-Ray.

## Output mapping

The output columns are:

`time_unix_nano`, `observed_time_unix_nano` (TIMESTAMP_NS); `trace_id`, `span_id`, `service_name`,
`service_namespace`, `service_instance_id` (VARCHAR); `severity_number` (INTEGER),
`severity_text`, `event_name`, `body`, `resource_attributes`, `scope_name`, `scope_version`,
`scope_attributes`, `log_attributes` (VARCHAR); `dropped_attributes_count`, `flags` (INTEGER).

`FilterLogEvents` returns an opaque message rather than structured OTLP fields, so the extension
maps only fields the API defines:

| CloudWatch field | Output |
|---|---|
| `timestamp` | `time_unix_nano` |
| `ingestionTime` | `observed_time_unix_nano` |
| `message` | `body` (preserved exactly) |
| request region/group + `logStreamName` | `resource_attributes` JSON using `cloud.provider`, `cloud.region`, `aws.log.group.names`, `aws.log.stream.names` |
| `eventId` | `log_attributes` JSON as `aws.cloudwatch.log.event_id` |

The remaining OTLP columns are SQL `NULL`. The extension intentionally does not guess severity,
service, trace, or span fields from arbitrary JSON messages. Applications can parse `body` with
DuckDB's JSON functions and project their own conventions without losing the original event.

CloudWatch log transformation is not applied by `FilterLogEvents`; AWS returns the original event.
Use Logs Insights when transformed fields are required (a future extension surface).

## Build and test

```bash
make release
make test
cmake --build build/release --target cloudwatch_json_test
./build/release/extension/cloudwatch/cloudwatch_json_test
cmake --build build/release --target cloudwatch_signing_test
./build/release/extension/cloudwatch/cloudwatch_signing_test
cmake --build build/release --target cloudwatch_protocol_test
./build/release/extension/cloudwatch/cloudwatch_protocol_test
```

The extension currently targets native DuckDB builds. Its distribution workflow excludes WASM
because browser builds do not provide the OpenSSL primitives used for SigV4 and cannot safely use
the filesystem/metadata credential providers from DuckDB's AWS extension.
