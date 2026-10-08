#![doc = "Acceptance test for the MCP byte-stream transport seam."]

use keel_mcp::probe_round_trip;

#[tokio::test]
async fn calls_one_tool_over_a_full_duplex_byte_stream() {
    let (host, guest) = tokio::io::duplex(16 * 1024);

    let reply = probe_round_trip(host, guest, "vertex-ready")
        .await
        .expect("MCP initialization and tool call must succeed");

    assert_eq!(reply, "vertex-ready");
}
