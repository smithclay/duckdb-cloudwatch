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
or retention policies — use the [administration functions](#log-group-administration) for that. The
optional fourth argument is a constant `aws`/`s3` secret name; region and refreshable credentials
use the same resolution path as the reader. An optional fifth argument overrides the endpoint (a
private VPC endpoint, or a local [`cloudwatch_serve`](#cloudwatch_serve) listener):

```sql
SELECT send_cloudwatch_logs(l, '/app/orders', 'duckdb-import', 'cw_prod', 'http://localhost:10519')
FROM my_logs l;
```

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

## `send_cloudwatch_metrics`

`send_cloudwatch_metrics` writes an OTLP-shaped gauge table to CloudWatch Metrics through
[`PutMetricData`](https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricData.html).
Pass a whole row and a constant namespace; each accepted row returns `'ok'`:

```sql
SELECT send_cloudwatch_metrics(m, '/obsbench/run1') FROM my_metrics m;

-- Optional third/fourth arguments: a named aws/s3 secret and an endpoint override.
SELECT send_cloudwatch_metrics(m, '/obsbench/run1', 'cw_prod', 'http://localhost:10519') FROM my_metrics m;
```

The column mapping mirrors the 17-column gauge shape `read_cloudwatch_metrics` returns, so a table
sent through here reads back with the shape it went out with:

| Struct column (first match wins) | `PutMetricData` field |
|---|---|
| `name` / `metric_name` | `MetricName` (required, non-empty) |
| `double_value` / `value` | `Value` (required; a NULL reading is skipped, not sent as zero) |
| `time_unix_nano` / `timestamp` | `Timestamp` (defaults to now) |
| `unit` | `Unit`, translated (see below) |
| `service_name` | a `service.name` dimension |
| `metric_attributes` / `attributes` | further dimensions, from a JSON object of strings |

Three CloudWatch constraints shape the mapping:

- **Units are a closed vocabulary.** CloudWatch rejects anything outside its own enum, so OTLP units
  are translated: `s`/`ms`/`us` become `Seconds`/`Milliseconds`/`Microseconds`, `By` becomes `Bytes`,
  `%` becomes `Percent`, and UCUM annotation units such as `{request}` become `Count`. Anything with
  no CloudWatch equivalent — **nanoseconds most importantly, which CloudWatch cannot express** —
  becomes `None`, leaving the value unscaled rather than mislabelled as a unit it is not.
- **Timestamps are whole seconds** in the query protocol, and CloudWatch rejects points older than
  two weeks or more than two hours in the future.
- **A datum is billed as a custom metric per unique namespace + name + dimension combination**, and
  custom metrics cannot be deleted — they age out after 15 months. Billing is prorated hourly, so a
  short run costs cents, but dimension cardinality is a permanent footprint, not a temporary one.

Writes are non-idempotent and `PutMetricData` carries no request id, so a retry after an unseen
response would double-count. Only responses proving the call was rejected before doing any work are
retried. Batches are capped at 1000 datums and held under the 1 MB body limit; earlier batches may
already be stored if a later one fails. Sending requires `cloudwatch:PutMetricData`.

## `read_cloudwatch_logs_insights`

`FilterLogEvents` can only return whole events, so any aggregation happens after every matching row
has crossed the network. `read_cloudwatch_logs_insights` runs a
[CloudWatch Logs Insights](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_StartQuery.html)
query instead, which aggregates inside CloudWatch and returns only the result:

```sql
SELECT service_name, CAST(events AS BIGINT) AS events
FROM read_cloudwatch_logs_insights(
    'filter status_code = 2 | stats count(*) as events by service_name',
    log_groups => ['/app/checkout', '/app/gateway'],
    start_time => '-1h',
    secret     => 'cw_prod'
)
ORDER BY events DESC;
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `log_groups` | VARCHAR[] | — | One to 50 log-group names or ARNs. Required (or `log_group` for a single one). |
| `log_group` | VARCHAR | — | Convenience form for a single group; combines with `log_groups`. |
| `start_time` | VARCHAR | `-15m` | Same forms as `read_cloudwatch_logs`. |
| `end_time` | VARCHAR | `now` | Same forms as `start_time`. |
| `max_rows` | BIGINT | `0` | Row cap, 1–10,000; 0 uses the AWS default of 1,000. Also spelled `"limit"` (quoted — it is a reserved word). |
| `max_wait` | BIGINT | `300` | Seconds to wait for the query before giving up and stopping it. |
| `poll_interval_ms` | BIGINT | `500` | How often to poll `GetQueryResults`. |
| `secret` / `region` / `endpoint` / `retries` / `timeout` | | | As on `read_cloudwatch_logs`. |

The result schema depends on the query, so the query is executed during binding and its columns are
taken from the field names AWS returns, in first-seen order across rows. A field only some rows
carry still gets a column and is `NULL` elsewhere. Every column is `VARCHAR`, because Insights
returns all values — including `stats` aggregates — as strings; cast what you need. An aggregation
that matches nothing returns no rows, and the binder falls back to a single `@message` column.

Insights charges per byte scanned, so a retried `StartQuery` would bill twice: this function retries
only responses proving no query began (throttling and the concurrent-query limit). If the query is
interrupted or exceeds `max_wait`, `StopQuery` is called so the scan stops being billed. Note that
`count_distinct` is approximate above roughly 10,000 distinct values — count a field you know is
unique per row when you need an exact number.

Requires `logs:StartQuery`, `logs:GetQueryResults`, and `logs:StopQuery`.

## Log-group administration

`send_cloudwatch_logs` deliberately never creates its destination. These four functions do, and each
is idempotent — reporting the outcome rather than raising on AWS's "already exists"/"does not exist"
errors — so bootstrap and teardown are re-runnable:

```sql
-- One row per group; the name argument is evaluated per row, unlike the sender's constant
-- destination, so a whole inventory can be created from a query.
SELECT log_group, create_cloudwatch_log_group(log_group, 'cw_prod') AS created
FROM (VALUES ('/app/checkout'), ('/app/gateway')) t(log_group);

SELECT create_cloudwatch_log_stream('/app/checkout', 'duckdb', 'cw_prod');
SELECT put_cloudwatch_retention_policy('/app/checkout', 1, 'cw_prod');
SELECT delete_cloudwatch_log_group('/app/checkout', 'cw_prod');
```

| Function | Returns | Requires |
|---|---|---|
| `create_cloudwatch_log_group(name [, secret [, endpoint]])` | `'created'` / `'exists'` | `logs:CreateLogGroup` |
| `create_cloudwatch_log_stream(group, stream [, secret [, endpoint]])` | `'created'` / `'exists'` | `logs:CreateLogStream` |
| `put_cloudwatch_retention_policy(group, days [, secret [, endpoint]])` | `'ok'` | `logs:PutRetentionPolicy` |
| `delete_cloudwatch_log_group(name [, secret [, endpoint]])` | `'deleted'` / `'absent'` | `logs:DeleteLogGroup` |

The secret name and endpoint must be constants; the group, stream, and retention arguments are
evaluated per row. `retention_days` is checked against the values CloudWatch accepts (1, 3, 5, 7,
14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653) before
any request is made, because AWS's own rejection does not name them. Deleting a log group discards
its streams and events.

## `cloudwatch_serve`

`cloudwatch_serve` runs a local CloudWatch Logs endpoint inside DuckDB and stores what it receives
in a table. It speaks the AWS JSON 1.1 wire protocol, so it works as a test double for this
extension's own read/write paths **and as a real sink for the Amazon CloudWatch Agent**, which
accepts an arbitrary destination through its `logs.endpoint_override` setting:

```sql
-- Returns the endpoint URL to pass to `endpoint =>` or to the agent.
SELECT cloudwatch_serve('cloudwatch:localhost:10519');

SELECT count(*), min(timestamp_ms) FROM cloudwatch_logs;   -- received events
SELECT * FROM cloudwatch_log_groups;                       -- groups/streams and retention

SELECT cloudwatch_stop('cloudwatch:localhost:10519');
```

Received events land in `cloudwatch_logs` as `(log_group, log_stream, timestamp_ms,
ingestion_time_ms, event_id, message)` — CloudWatch's own shape rather than OTLP, because
`PutLogEvents` carries nothing else. Read them back through `read_cloudwatch_logs(...,
endpoint => 'http://localhost:10519')` to get the 18-column mapping.

Metrics land in `cloudwatch_metric_data` as `(namespace, metric_name, timestamp_ms, value, unit,
dimensions)`, one row per datum with no rollup. `dimensions` is a `MAP(VARCHAR, VARCHAR)` rather
than a JSON string, so both the listener's own filtering and your queries work in core DuckDB
without the json extension loaded:

```sql
SELECT metric_name, value, dimensions['service.name'] FROM cloudwatch_metric_data;
```

Options (second argument, a `STRUCT`): `schema_name`, `table_name`, `groups_table_name`,
`metrics_table_name`, `create_table`, `allow_other_hostname`, `auto_create_groups`,
`max_body_bytes`, `http_threads`.

Implemented operations are `CreateLogGroup`, `CreateLogStream`, `DeleteLogGroup`,
`PutRetentionPolicy`, `DescribeLogGroups`, `DescribeLogStreams`, and `PutLogEvents` — the set the
CloudWatch Agent uses — plus `FilterLogEvents` for reading back. Metrics are served on the same
port but over the AWS *query* protocol (form-encoded in, XML out) rather than the Logs JSON API,
distinguished by the absence of an `X-Amz-Target` header: `PutMetricData` and `GetMetricData` are
both implemented, the latter restricted to plain aggregation over a period with the `Sum`,
`Average`, `Maximum`, `Minimum`, and `SampleCount` statistics — no metric-math expressions, no
percentile statistics, no pagination. Behaviour is faithful where it
matters: `PutLogEvents` to an unknown group fails with `ResourceNotFoundException` rather than
creating one implicitly (set `auto_create_groups` to change that), so the agent's real
create-then-send sequence is exercised.

Deliberate limits. SigV4 signatures are accepted without verification, since the listener has no
access to the caller's secret key; binding anywhere but loopback therefore requires
`allow_other_hostname`. Logs Insights is not implemented — emulating its query language would give
false confidence, so query the received table in SQL instead. Only substring filter patterns are
honoured on `FilterLogEvents`; the JSON and metric-filter syntaxes are rejected rather than silently
matching everything.

### Receiving from a real CloudWatch Agent

```jsonc
// /etc/cwagentconfig/agent.json — the only agent-side change is endpoint_override
{
  "agent": {"region": "us-east-1"},
  "logs": {
    "endpoint_override": "http://your-host:10519",
    "logs_collected": {"files": {"collect_list": [
      {"file_path": "/var/log/app.log", "log_group_name": "/app/logs", "log_stream_name": "agent"}
    ]}}
  }
}
```

The listener must bind an address the agent can reach:

```sql
SELECT cloudwatch_serve('cloudwatch:0.0.0.0:10519', {'allow_other_hostname': true});
```

Two things to know. Off EC2 the agent runs in "onPrem" mode and reads credentials from the shared
credentials file under the `AmazonCloudWatchAgent` profile, ignoring `AWS_ACCESS_KEY_ID`; the values
are never checked, but it will not send without them. And the agent gzips any batch that compresses,
which the listener inflates itself — DuckDB's bundled cpp-httplib has no zlib decoder, so the
request's `Content-Encoding` is moved aside before the body is read.

`test/e2e/cloudwatch_agent.sh` runs this end to end against a real agent container and asserts that
it creates the group and stream and delivers its events.

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
Use [`read_cloudwatch_logs_insights`](#read_cloudwatch_logs_insights) when transformed fields are
required.

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

`make test` is offline: it covers argument and protocol validation, which happens before any
credential lookup. The two end-to-end scripts exercise the request paths for real against
`cloudwatch_serve`. They live outside `test/sql` because the `aws`/`s3` secret types are registered
by httpfs, which the sqllogictest binary cannot autoload:

```bash
./test/e2e/roundtrip.sh         # bootstrap, send, read back, tear down — no network, no Docker
./test/e2e/cloudwatch_agent.sh  # a real Amazon CloudWatch Agent shipping into DuckDB (needs Docker)
```

The extension currently targets native DuckDB builds. Its distribution workflow excludes WASM
because browser builds do not provide the OpenSSL primitives used for SigV4 and cannot safely use
the filesystem/metadata credential providers from DuckDB's AWS extension.
