#!/bin/sh
set -eu

if [ "${1:-}" = "keel-harness" ]; then
    shift
fi

case "${KEEL_REQUESTED_HARNESS:-}" in
    claude)
        # The launch script the host writes exports the regional provider's
        # variables before this runs. Leaving a direct key and base URL set
        # alongside them would give the harness two ways to name an endpoint,
        # only one of which the broker authorizes for this run.
        if [ "${CLAUDE_CODE_USE_BEDROCK:-}" = "1" ]; then
            unset ANTHROPIC_API_KEY ANTHROPIC_BASE_URL
        elif [ "${KEEL_MODEL_PROVIDER:-}" = "openrouter" ]; then
            # The host wrote the OpenRouter base URL and bearer sentinel.
            export ANTHROPIC_API_KEY=
        else
            export ANTHROPIC_API_KEY=keel-anthropic-credential-sentinel-v1
            export ANTHROPIC_BASE_URL=https://api.anthropic.com
        fi
        # Chromium trusts its own NSS store, not the system bundle, so the
        # run's public CA is added there for the guest browser.
        if [ -r "${SSL_CERT_FILE:-}" ] && [ ! -d "$HOME/.pki/nssdb" ]; then
            mkdir -p "$HOME/.pki/nssdb"
            certutil -N --empty-password -d "sql:$HOME/.pki/nssdb"
            certutil -A -d "sql:$HOME/.pki/nssdb" -n keel-run-ca -t "C,," -i "$SSL_CERT_FILE"
        fi
        # Build tools reach registries through Keel's proxy, so they must
        # trust the run CA. npm (Node), pip, and cargo do not all read the
        # system bundle that SSL_CERT_FILE names.
        if [ -r "${SSL_CERT_FILE:-}" ]; then
            export NODE_EXTRA_CA_CERTS="$SSL_CERT_FILE"
            export PIP_CERT="$SSL_CERT_FILE"
            export REQUESTS_CA_BUNDLE="$SSL_CERT_FILE"
            export CARGO_HTTP_CAINFO="$SSL_CERT_FILE"
        fi
        # agent-browser, for the agent's MCP tools and the analyst's CLI,
        # shares one browser through its daemon. WebMCP stays off: it would
        # surface tools defined by the untrusted page.
        export AGENT_BROWSER_EXECUTABLE_PATH=/usr/local/bin/keel-chromium
        export AGENT_BROWSER_PROXY=http://127.0.0.1:18081
        export AGENT_BROWSER_NO_WEBMCP=1
        export AGENT_BROWSER_SCREENSHOT_DIR=/workspace/.keel-browser/screenshots
        export AGENT_BROWSER_DOWNLOAD_PATH=/workspace/.keel-browser/downloads
        export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
        exec /usr/local/bin/claude \
            --bare \
            --mcp-config /etc/keel/mcp.json \
            --strict-mcp-config \
            "$@"
        ;;
    v8)
        if [ "${KEEL_ISOLATION:-}" != "vm-v8" ]; then
            echo "the guest V8 harness requires vm-v8 isolation" >&2
            exit 64
        fi
        exec /usr/bin/node \
            --no-warnings \
            --permission \
            --allow-fs-read=/workspace \
            --allow-fs-read=/usr/local/lib/keel/v8-sdk.mjs \
            --allow-fs-read=/run/keel/ca.pem \
            --allow-fs-write=/workspace \
            --import=/usr/local/lib/keel/v8-sdk.mjs \
            "$@"
        ;;
    *)
        echo "unsupported guest harness: ${KEEL_REQUESTED_HARNESS:-unset}" >&2
        exit 64
        ;;
esac
