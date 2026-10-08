#![doc = "Acceptance tests for the terminal control channel shared with the guest."]

use keel_input::{
    TERMINAL_CONTROL, TerminalControl, TerminalControlReader, encode_floor_lift, encode_resize,
    encode_shutdown, push_keystroke,
};

fn split(reader: &mut TerminalControlReader, bytes: &[u8]) -> (Vec<u8>, Vec<TerminalControl>) {
    let mut keystrokes = Vec::new();
    let controls = reader.split(bytes, &mut keystrokes);
    (keystrokes, controls)
}

#[test]
fn a_resize_message_has_the_wire_format_the_guest_decodes() {
    // The guest half of this codec lives in `keel-mcp-guest`, which cannot be
    // compiled on the host, so the format is pinned here as literal bytes.
    assert_eq!(
        encode_resize(51, 204),
        [TERMINAL_CONTROL, b's', 0, 51, 0, 204]
    );
    assert_eq!(
        encode_resize(1024, 65_535),
        [TERMINAL_CONTROL, b's', 4, 0, 255, 255]
    );
}

#[test]
fn a_resize_message_round_trips_through_the_reader() {
    let mut reader = TerminalControlReader::new();
    let (keystrokes, controls) = split(&mut reader, &encode_resize(51, 204));

    assert!(keystrokes.is_empty());
    assert_eq!(
        controls,
        vec![TerminalControl::Resize {
            rows: 51,
            columns: 204
        }]
    );
}

#[test]
fn a_resize_message_split_one_byte_per_read_is_still_decoded() {
    let mut reader = TerminalControlReader::new();
    let message = encode_resize(40, 120);
    let mut decoded = Vec::new();
    let mut keystrokes = Vec::new();
    for byte in &message {
        decoded.extend(reader.split(&[*byte], &mut keystrokes));
    }

    assert!(keystrokes.is_empty());
    assert_eq!(
        decoded,
        vec![TerminalControl::Resize {
            rows: 40,
            columns: 120
        }]
    );
}

#[test]
fn a_size_whose_bytes_look_like_control_bytes_is_not_reparsed() {
    // 0x0707 rows puts two literal prefix bytes inside the payload. Treating
    // them as the start of new messages would drop the resize and eat the
    // keystrokes that follow it.
    let mut reader = TerminalControlReader::new();
    let mut stream = encode_resize(0x0707, 0x0772).to_vec();
    stream.extend_from_slice(b"ls");
    let (keystrokes, controls) = split(&mut reader, &stream);

    assert_eq!(keystrokes, b"ls");
    assert_eq!(
        controls,
        vec![TerminalControl::Resize {
            rows: 0x0707,
            columns: 0x0772
        }]
    );
}

#[test]
fn keystrokes_around_a_message_reach_the_guest_unchanged() {
    let mut reader = TerminalControlReader::new();
    let mut stream = b"\x1b[A".to_vec();
    stream.extend_from_slice(&encode_resize(24, 80));
    stream.extend_from_slice(b"git status\r");
    let (keystrokes, controls) = split(&mut reader, &stream);

    assert_eq!(keystrokes, b"\x1b[Agit status\r");
    assert_eq!(controls.len(), 1);
}

#[test]
fn a_literal_control_keystroke_survives_the_channel() {
    let mut forward = Vec::new();
    for byte in b"a\x07b" {
        push_keystroke(&mut forward, *byte);
    }
    let mut reader = TerminalControlReader::new();
    let (keystrokes, _controls) = split(&mut reader, &forward);

    // An operator pressing Ctrl-G must not look like the start of a message.
    assert_eq!(keystrokes, b"a\x07b");
}

#[test]
fn a_redraw_request_never_reaches_the_guest_as_keystrokes() {
    let mut reader = TerminalControlReader::new();
    let (_keystrokes, controls) = split(&mut reader, &[TERMINAL_CONTROL, b'r']);

    // Forwarding the request verbatim would ring the bell and type an `r` into
    // whatever prompt the harness is showing.
    assert_eq!(controls, vec![TerminalControl::Redraw]);
}

#[test]
fn a_floor_lift_round_trips_without_reaching_the_guest() {
    let mut reader = TerminalControlReader::new();
    let (keystrokes, controls) = split(&mut reader, &encode_floor_lift(2));

    assert!(keystrokes.is_empty());
    assert_eq!(controls, vec![TerminalControl::FloorLift(2)]);
}

#[test]
fn a_zero_floor_lift_is_dropped() {
    let mut reader = TerminalControlReader::new();
    let (keystrokes, controls) = split(&mut reader, &encode_floor_lift(0));

    assert!(keystrokes.is_empty());
    assert!(controls.is_empty());
}

#[test]
fn a_shutdown_request_round_trips_without_reaching_the_guest() {
    let mut reader = TerminalControlReader::new();
    let (keystrokes, controls) = split(&mut reader, &encode_shutdown());

    assert!(keystrokes.is_empty());
    assert_eq!(controls, vec![TerminalControl::Shutdown]);
}

#[test]
fn an_unknown_message_is_dropped_instead_of_typed() {
    let mut reader = TerminalControlReader::new();
    let (keystrokes, controls) = split(&mut reader, &[TERMINAL_CONTROL, b'z', b'k']);

    assert_eq!(keystrokes, b"k");
    assert!(controls.is_empty());
}
