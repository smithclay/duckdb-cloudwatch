#!/usr/bin/env bash
# End-to-end test: a REAL Amazon CloudWatch Agent shipping logs into cloudwatch_serve.
#
# The agent is pointed at the listener with the `logs.endpoint_override` setting it already supports
# for FIPS endpoints and VPC private links, so nothing about the agent is patched or faked. It runs
# its normal sequence -- DescribeLogStreams, CreateLogGroup, CreateLogStream, PutLogEvents (gzipped)
# -- against DuckDB, and this script asserts the lines land in the table.
#
# Requires Docker. The agent runs in a container; the listener runs in DuckDB on the host and binds
# 0.0.0.0 so the container can reach it. SigV4 signatures are not verified by the listener, so the
# dummy credentials below never leave the machine and grant nothing.
#
#   ./test/e2e/cloudwatch_agent.sh [path/to/duckdb] [path/to/cloudwatch.duckdb_extension]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DUCKDB="${1:-$REPO_ROOT/build/release/duckdb}"
EXTENSION="${2:-$REPO_ROOT/build/release/extension/cloudwatch/cloudwatch.duckdb_extension}"
PORT="${CLOUDWATCH_AGENT_E2E_PORT:-10548}"
IMAGE="${CLOUDWATCH_AGENT_IMAGE:-public.ecr.aws/cloudwatch-agent/cloudwatch-agent:latest}"
LOG_GROUP="/obsbench/agent-e2e"
LOG_STREAM="agent"
CONTAINER="cloudwatch-agent-e2e-$$"
TIMEOUT_SECONDS="${CLOUDWATCH_AGENT_E2E_TIMEOUT:-120}"

for path in "$DUCKDB" "$EXTENSION"; do
    if [ ! -e "$path" ]; then
        echo "missing $path; run 'make release' first" >&2
        exit 1
    fi
done
if ! command -v docker >/dev/null 2>&1; then
    echo "docker is required for this test" >&2
    exit 1
fi

WORKDIR="$(mktemp -d)"
DB_PATH="$WORKDIR/e2e.duckdb"
# The agent reads its config from the /etc/cwagentconfig directory, and only the log directory is
# exposed to the container -- keeping the database and config out of the tailed path.
CONFIG_DIR="$WORKDIR/cwagentconfig"
LOG_DIR="$WORKDIR/logs"
LOG_FILE="$LOG_DIR/app.log"
CONTROL_FIFO="$WORKDIR/control"
mkdir -p "$CONFIG_DIR" "$LOG_DIR"
: >"$LOG_FILE"
mkfifo "$CONTROL_FIFO"

cleanup() {
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    # Closing the FIFO ends the DuckDB session, which stops the listener with it.
    exec 3>&- 2>/dev/null || true
    wait "$DUCKDB_PID" 2>/dev/null || true
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

# The agent resolves the endpoint from inside the container. host-gateway is a no-op on Docker
# Desktop (which defines host.docker.internal already) and supplies it on Linux.
cat >"$CONFIG_DIR/agent.json" <<EOF
{
  "agent": {"region": "us-east-1", "debug": true, "logfile": ""},
  "logs": {
    "endpoint_override": "http://host.docker.internal:$PORT",
    "force_flush_interval": 5,
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/var/log/e2e/app.log",
            "log_group_name": "$LOG_GROUP",
            "log_stream_name": "$LOG_STREAM"
          }
        ]
      }
    }
  }
}
EOF

# Off an EC2 instance the agent runs in "onPrem" mode, where it loads credentials from the shared
# credentials file under the AmazonCloudWatchAgent profile and ignores AWS_ACCESS_KEY_ID. These are
# never validated -- the listener does not verify SigV4 -- but the agent refuses to send without
# them, and its retry backoff climbs to ~50s after a few failures.
mkdir -p "$WORKDIR/aws"
cat >"$WORKDIR/aws/credentials" <<EOF
[AmazonCloudWatchAgent]
aws_access_key_id = AKIAEXAMPLE
aws_secret_access_key = examplesecret
EOF

# Keep a DuckDB session alive for the whole test by holding its stdin open on a FIFO. The listener
# lives as long as the process, and the same session is queried for results at the end.
"$DUCKDB" "$DB_PATH" -noheader -list <"$CONTROL_FIFO" >"$WORKDIR/duckdb.out" 2>&1 &
DUCKDB_PID=$!
exec 3>"$CONTROL_FIFO"

cat >&3 <<EOF
INSTALL httpfs; LOAD httpfs; INSTALL aws; LOAD aws;
LOAD '$EXTENSION';
SELECT cloudwatch_serve('cloudwatch:0.0.0.0:$PORT', {'allow_other_hostname': true});
EOF

# Wait for the listener to accept connections before starting the agent.
for _ in $(seq 1 50); do
    if curl -fsS "http://localhost:$PORT/healthz" >/dev/null 2>&1; then
        break
    fi
    sleep 0.2
done
if ! curl -fsS "http://localhost:$PORT/healthz" >/dev/null 2>&1; then
    echo "listener did not come up on port $PORT" >&2
    cat "$WORKDIR/duckdb.out" >&2
    exit 1
fi
echo "listener ready on port $PORT"

docker run -d --name "$CONTAINER" \
    --add-host=host.docker.internal:host-gateway \
    -e AWS_ACCESS_KEY_ID=AKIAEXAMPLE \
    -e AWS_SECRET_ACCESS_KEY=examplesecret \
    -e AWS_REGION=us-east-1 \
    -e RUN_IN_CONTAINER=True \
    -e AWS_EC2_METADATA_DISABLED=true \
    -v "$CONFIG_DIR:/etc/cwagentconfig:ro" \
    -v "$WORKDIR/aws:/root/.aws:ro" \
    -v "$LOG_DIR:/var/log/e2e" \
    "$IMAGE" >/dev/null
# Startup is slow: the agent probes EC2/ECS metadata before translating its config.
echo "agent container $CONTAINER started; waiting for it to begin tailing..."
for _ in $(seq 1 60); do
    if docker logs "$CONTAINER" 2>&1 | grep -q "start logs plugin file paths"; then
        break
    fi
    sleep 1
done

# Written after the agent is tailing so the lines arrive as live appends, which is the path a real
# deployment uses. A unique marker keeps the assertion immune to anything else in the file.
MARKER="e2e-$(date +%s)-$$"
for i in 1 2 3 4 5; do
    echo "$MARKER line $i" >>"$LOG_FILE"
done

echo "waiting up to ${TIMEOUT_SECONDS}s for the agent to deliver..."
delivered=0
for _ in $(seq 1 "$TIMEOUT_SECONDS"); do
    echo "SELECT 'COUNT=' || count(*) FROM cloudwatch_logs WHERE log_group = '$LOG_GROUP' AND contains(message, '$MARKER');" >&3
    sleep 1
    delivered=$(grep -o 'COUNT=[0-9]*' "$WORKDIR/duckdb.out" | tail -1 | cut -d= -f2 || echo 0)
    if [ "${delivered:-0}" -ge 5 ]; then
        break
    fi
done

echo "SELECT 'GROUPS=' || count(*) FROM cloudwatch_log_groups WHERE log_group = '$LOG_GROUP' AND log_stream IS NULL;" >&3
echo "SELECT 'STREAMS=' || count(*) FROM cloudwatch_log_groups WHERE log_group = '$LOG_GROUP' AND log_stream = '$LOG_STREAM';" >&3
echo "SELECT 'SAMPLE=' || message FROM cloudwatch_logs WHERE log_group = '$LOG_GROUP' ORDER BY timestamp_ms LIMIT 1;" >&3
sleep 2

echo "--- listener state ---"
grep -E '^(COUNT|GROUPS|STREAMS|SAMPLE)=' "$WORKDIR/duckdb.out" | tail -4 || true

if [ "${delivered:-0}" -lt 5 ]; then
    echo "FAIL: expected 5 delivered events, saw ${delivered:-0}" >&2
    echo "--- duckdb session ---" >&2
    tail -20 "$WORKDIR/duckdb.out" >&2
    echo "--- agent log ---" >&2
    docker logs "$CONTAINER" 2>&1 | grep -vE "open file count" | tail -40 >&2
    exit 1
fi

# The agent created the group and stream itself, which is the part that proves the listener answers
# the agent's real bootstrap sequence and not just PutLogEvents.
if ! grep -qx 'GROUPS=1' "$WORKDIR/duckdb.out"; then
    echo "FAIL: the agent did not create log group $LOG_GROUP" >&2
    exit 1
fi
if ! grep -qx 'STREAMS=1' "$WORKDIR/duckdb.out"; then
    echo "FAIL: the agent did not create log stream $LOG_STREAM" >&2
    exit 1
fi

echo "cloudwatch_agent.sh: OK — a real CloudWatch Agent created the group/stream and delivered ${delivered} events"
