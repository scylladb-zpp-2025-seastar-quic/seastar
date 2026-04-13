#!/usr/bin/env bash
# run_tls_bench.sh - run the TLS/TCP benchmark (server + client) and print results.
#
# Usage:
#   ./run_tls_bench.sh [options]
#
# Options (all have defaults):
#   --mode          throughput|latency         (default: throughput)
#   --stream-type   bidi|uni                   (default: bidi)
#   --connections   N                          (default: 1)
#   --message-size  N   bytes                  (default: 65536)
#   --throughput-flush-messages N              (default: 0 = auto)
#   --throughput-flush-bytes    N              (default: 0 = auto)
#   --duration      N   seconds                (default: 10)
#   --address       IPv6                       (default: ::1)
#   --port          N                          (default: 4444)
#   --build-dir     path to build/dev          (default: build/dev)
#   --crt           PEM cert (server TLS)
#   --key           PEM key  (server TLS)
#   --ca            PEM CA/cert (client verify)
#   --server-name   TLS SNI/server name        (default: localhost)
#   --smp           CPU cores for each process (default: 1)
#   --stats-interval N  server stats seconds   (default: 2)
#   --no-color          disable colour output

set -euo pipefail

MODE=throughput
STREAM_TYPE=bidi
CONNECTIONS=1
MESSAGE_SIZE=65536
THROUGHPUT_FLUSH_MESSAGES=0
THROUGHPUT_FLUSH_BYTES=0
DURATION=10
ADDRESS="::1"
PORT=4444
SERVER_NAME="localhost"
SMP=1
STATS_INTERVAL=2
NO_COLOR=0

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build/dev"
CRT="${SCRIPT_DIR}/server.crt"
KEY="${SCRIPT_DIR}/server.key"
CA="${SCRIPT_DIR}/server.crt"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode)           MODE="$2";           shift 2 ;;
        --stream-type)    STREAM_TYPE="$2";    shift 2 ;;
        --connections)    CONNECTIONS="$2";    shift 2 ;;
        --message-size)   MESSAGE_SIZE="$2";   shift 2 ;;
        --throughput-flush-messages) THROUGHPUT_FLUSH_MESSAGES="$2"; shift 2 ;;
        --throughput-flush-bytes)    THROUGHPUT_FLUSH_BYTES="$2";    shift 2 ;;
        --duration)       DURATION="$2";       shift 2 ;;
        --address)        ADDRESS="$2";        shift 2 ;;
        --port)           PORT="$2";           shift 2 ;;
        --build-dir)      BUILD_DIR="$2";      shift 2 ;;
        --crt)            CRT="$2";            shift 2 ;;
        --key)            KEY="$2";            shift 2 ;;
        --ca)             CA="$2";             shift 2 ;;
        --server-name)    SERVER_NAME="$2";    shift 2 ;;
        --smp)            SMP="$2";            shift 2 ;;
        --stats-interval) STATS_INTERVAL="$2"; shift 2 ;;
        --no-color)       NO_COLOR=1;          shift   ;;
        -h|--help)
            sed -n '2,/^$/p' "$0"
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

if [[ $NO_COLOR -eq 0 ]] && [[ -t 1 ]]; then
    BOLD=$'\033[1m'; CYAN=$'\033[36m'; GREEN=$'\033[32m'
    YELLOW=$'\033[33m'; RED=$'\033[31m'; RESET=$'\033[0m'
else
    BOLD=''; CYAN=''; GREEN=''; YELLOW=''; RED=''; RESET=''
fi

info()  { echo "${CYAN}[bench]${RESET} $*"; }
ok()    { echo "${GREEN}[bench]${RESET} $*"; }
warn()  { echo "${YELLOW}[bench]${RESET} $*"; }
die()   { echo "${RED}[bench] ERROR:${RESET} $*" >&2; exit 1; }

SERVER_BIN="${BUILD_DIR}/demos/tls_bench_server_demo"
CLIENT_BIN="${BUILD_DIR}/demos/tls_bench_client_demo"

[[ -x "$SERVER_BIN" ]] || die "Server binary not found: $SERVER_BIN"
[[ -x "$CLIENT_BIN" ]] || die "Client binary not found: $CLIENT_BIN"
[[ -f "$CRT" ]]        || die "Certificate not found: $CRT"
[[ -f "$KEY" ]]        || die "Private key not found: $KEY"
[[ -f "$CA" ]]         || die "CA/certificate not found: $CA"

STALE=$(pgrep -f "tls_bench_server_demo" 2>/dev/null || true)
if [[ -n "$STALE" ]]; then
    warn "Killing stale server process(es): $STALE"
    kill -9 $STALE 2>/dev/null || true
    sleep 0.5
fi

SERVER_LOG=$(mktemp /tmp/tls_bench_server_XXXXXX.log)
trap 'rm -f "$SERVER_LOG"; kill "$SERVER_PID" 2>/dev/null || true' EXIT

info "Starting server  [${ADDRESS}]:${PORT}  smp=${SMP}"
"$SERVER_BIN" \
    --smp "$SMP" \
    --address "$ADDRESS" \
    --port "$PORT" \
    --crt "$CRT" \
    --key "$KEY" \
    --throughput-flush-bytes "$THROUGHPUT_FLUSH_BYTES" \
    --stats-interval "$STATS_INTERVAL" \
    > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!

WAIT=0
until grep -q "TLS bench server listening" "$SERVER_LOG" 2>/dev/null; do
    sleep 0.1
    WAIT=$((WAIT+1))
    if [[ $WAIT -ge 50 ]]; then
        echo "--- Server log ---"
        cat "$SERVER_LOG"
        die "Server failed to start within 5 s"
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "--- Server log ---"
        cat "$SERVER_LOG"
        die "Server process exited unexpectedly"
    fi
done
ok "Server ready"

info "Running client   mode=${MODE}  stream-type=${STREAM_TYPE}  conns=${CONNECTIONS}  msg=${MESSAGE_SIZE}B  dur=${DURATION}s"
echo ""

CLIENT_EXIT=0
"$CLIENT_BIN" \
    --smp "$SMP" \
    --address "$ADDRESS" \
    --port "$PORT" \
    --server-name "$SERVER_NAME" \
    --ca "$CA" \
    --mode "$MODE" \
    --stream-type "$STREAM_TYPE" \
    --connections "$CONNECTIONS" \
    --message-size "$MESSAGE_SIZE" \
    --throughput-flush-messages "$THROUGHPUT_FLUSH_MESSAGES" \
    --duration "$DURATION" \
    2>&1 | grep -v '^INFO\|^WARN\|^DEBUG\|^TRACE' \
    || CLIENT_EXIT=$?

echo ""
info "Server stats during run:"
grep -E "^\[server\] conns=|rx=|tx=" "$SERVER_LOG" | grep -v "rx=0.0.*tx=0.0" | grep "rx=" || true

if [[ $CLIENT_EXIT -ne 0 ]]; then
    warn "Client exited with code ${CLIENT_EXIT}"
    echo "--- Server log (last 20 lines) ---"
    tail -20 "$SERVER_LOG"
    exit "$CLIENT_EXIT"
fi

ok "Done."
