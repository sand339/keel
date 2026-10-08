#![doc = "Acceptance tests for detached-session approval status."]

use keel_input::detached_output_has_pending_approval;

#[test]
fn pending_status_requires_the_trusted_approval_notice() {
    assert!(detached_output_has_pending_approval(
        b"screen\nKEEL APPROVAL PENDING\n"
    ));
    assert!(!detached_output_has_pending_approval(
        b"ordinary guest output"
    ));
}
