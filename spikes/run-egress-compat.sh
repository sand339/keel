#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

run_root=$(mktemp -d "$repo_root/.phase0/egress.XXXXXX")
ready_file="$run_root/ready"
ca_file="$run_root/ca.pem"
stop_file="$run_root/stop"
log_file="$run_root/server.log"
server_pid=

cleanup() {
    touch "$stop_file"
    if [ -n "$server_pid" ]; then
        wait "$server_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

cargo build -p keel-conn --bin keel-egress-spike
target/debug/keel-egress-spike \
    "$ready_file" "$ca_file" "$stop_file" >"$log_file" 2>&1 &
server_pid=$!

attempt=0
while [ ! -s "$ready_file" ]; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 100 ] || ! kill -0 "$server_pid" 2>/dev/null; then
        cat "$log_file" >&2
        echo "error: egress compatibility server did not become ready" >&2
        exit 1
    fi
    sleep 0.05
done

port=$(cat "$ready_file")
endpoint="https://localhost:$port"
without_proxy="env -u HTTPS_PROXY -u HTTP_PROXY -u ALL_PROXY -u https_proxy -u http_proxy -u all_proxy"

curl_output=$(
    $without_proxy CURL_CA_BUNDLE="$ca_file" \
        curl --silent --show-error --fail "$endpoint/curl-probe"
)
[ "$curl_output" = '{"keel":"pass"}' ]
echo "curl transparent TLS: PASS"

$without_proxy GIT_SSL_CAINFO="$ca_file" \
    git -c http.version=HTTP/1.1 ls-remote "$endpoint/repo.git" >/dev/null
echo "git smart HTTP transparent TLS: PASS"

$without_proxy NODE_EXTRA_CA_CERTS="$ca_file" \
    npm ping --registry "$endpoint" --loglevel error
echo "npm registry transparent TLS: PASS"

mkdir -p "$run_root/cargo-home"
cat >"$run_root/cargo-home/config.toml" <<EOF
[registries.keel-spike]
index = "sparse+$endpoint/"
EOF
$without_proxy \
    CARGO_HOME="$run_root/cargo-home" \
    CARGO_HTTP_CAINFO="$ca_file" \
    cargo search --registry keel-spike definitely-no-such-keel-package \
        --limit 1 >/dev/null
echo "cargo sparse registry transparent TLS: PASS"

claude_settings=$(printf \
    '{"env":{"CLAUDE_CODE_USE_BEDROCK":"0","ANTHROPIC_BASE_URL":"%s"}}' \
    "$endpoint")
claude_output=$(
    $without_proxy \
        CLAUDE_CODE_USE_BEDROCK=0 \
        ANTHROPIC_BASE_URL="$endpoint" \
        ANTHROPIC_API_KEY="keel-phase0-test-key" \
        NODE_EXTRA_CA_CERTS="$ca_file" \
        CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
        claude \
            --settings "$claude_settings" \
            --bare \
            --print \
            --no-session-persistence \
            --permission-prompts none \
            --model sonnet \
            "Reply exactly keel-pass"
)
[ "$claude_output" = "keel-pass" ]
echo "Claude Code API transparent TLS: PASS"

touch "$stop_file"
wait "$server_pid"
server_pid=

for expected in \
    "GET /curl-probe HTTP/1.1" \
    "GET /repo.git/info/refs?service=git-upload-pack HTTP/1.1" \
    "GET /-/ping HTTP/1.1" \
    "GET /config.json HTTP/1.1" \
    "POST /v1/messages?beta=true HTTP/1.1"
do
    grep -F "$expected" "$log_file" >/dev/null
done
echo "SNI classification + inbound TLS + upstream TLS relay: PASS"
echo "evidence: $log_file"
