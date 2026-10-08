# Phase 0 substrate status

Host under test: Apple silicon, macOS 26.6.2.

| Acceptance item | Status | Evidence |
|---|---|---|
| Trusted/untrusted Cargo workspace; I1-I4 in CI | Passing locally | `ci/phase0.sh`, GitHub Actions |
| Native VM boots and guest calls MCP over vsock | Passing | Direct VZ guest booted and called `guest_report` on the host `rmcp` server over virtio-vsock |
| Two-sided network preflight | Passing | Guest reported no route, DNS, metadata, or RFC1918 reachability; host verified no VZ network device and accepted it. A deliberately broken guest report (`has_default_route: true`) was rejected before startup |
| Transparent egress compatibility table | Passing locally | Direct, proxy-free TLS passes for curl, Git, npm, Cargo, and Claude Code through SNI classification, an ephemeral Keel CA, inbound `rustls` termination, and a separately authenticated upstream `rustls` leg; see `EGRESS-COMPATIBILITY.md` |
| Decrypted HTTP authorization, model budgets, and durable audit | Passing locally | Trusted TLS and plaintext HTTP handlers submit the observed method and path before credential injection or upstream application bytes; model calls reserve admitted per-run token and cost ceilings (defaulting to 1,000,000 tokens and USD 10) using pinned tariffs. The kernel marks the send boundary, releases only definitely-unsent work, settles complete trusted usage, and conservatively charges ambiguous post-send outcomes. Typed denial metadata and terminal reservation outcomes are flushed through the hash-chained, run-key-authenticated single writer. |
| Three stateful Cedar rules | Passing locally | Strict Cedar schema/policy validation and boundary analysis; repeated-denial review uses three behavioral denials in the same canonical scope within 15 minutes, excluding resource/provider/budget failures. The other required stateful rules and the rejection of a pre-digested boolean remain covered. |
| Exclusive tty and trusted-screen approval | Passing locally | `keel-input` alone owns the real tty; the kernel sends exact actions and reasons over a zero-buffered in-process gate; secure attention enables one-key routine confirmation or a typed high-impact challenge with bracketed-paste rejection. Egress V2 separates the five-second pending acknowledgement from the bounded human decision, and the 4-minute-45-second kernel deadline invalidates late input and clears trusted UI before the relay's five-minute deadline. The sandboxed xterm-headless renderer keeps processing guest output while trusted input discards whole snapshots; resume requests one fresh canonical snapshot. |
| Optional V8 harness profiles | Passing locally | `vm-v8` packages Node/V8 in the no-network guest; `v8-sandboxed` packages pinned Deno with explicit trusted admission and the existing broker. The mux launcher exposes both with worktree/entry validation and visible boundary labels. CLI, launcher, raw-request admission, permission, environment, proxy-denial, and live engine smoke tests pass. |
| D1 and D9 resolved | Resolved | macOS Virtualization.framework is primary; build Keel. Docker's private libkrun 1.14 is rejected |

Phase 1 must not begin while any row is incomplete.
