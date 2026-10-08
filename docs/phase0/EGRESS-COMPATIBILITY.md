# Phase 0 transparent-egress compatibility

Tested 2026-09-18 on Apple silicon with macOS 26.6.2.

The test removes all HTTP, HTTPS, and ALL proxy variables. Each client opens a
direct TLS connection whose `ClientHello` is classified by `keel-conn`.
`keel-secrets` mints a `localhost` certificate under an ephemeral test CA and
terminates that connection with rustls 0.23.45. It then opens a separate rustls
client connection to `upstream.keel.test`, verifies that hostname against the
CA, and relays the HTTP response.

The test CA is supplied through each tool's documented trust-store setting
because the ephemeral key is intentionally not installed on the host. In the
guest image, the persistent Keel CA will be installed in the system trust store.

| Client | Version | Direct transparent TLS | Proxy environment needed | Test trust setting |
|---|---:|---|---|---|
| curl | 8.7.1 | Pass | No | `CURL_CA_BUNDLE` |
| Git smart HTTP | 2.51.0 | Pass | No | `GIT_SSL_CAINFO` |
| npm | 11.5.1 | Pass | No | `NODE_EXTRA_CA_CERTS` |
| Cargo sparse registry | 1.97.1 | Pass | No | `CARGO_HTTP_CAINFO` |
| Claude Code | 2.1.287 | Pass | No | `NODE_EXTRA_CA_CERTS` |

Run the matrix with:

```sh
./spikes/run-egress-compat.sh
```

The server also checks that every accepted front connection contains SNI for
`localhost`. The compatibility run fails if a client uses proxy CONNECT,
bypasses certificate verification, misses the expected protocol endpoint, or
cannot complete the separately authenticated upstream TLS leg.
