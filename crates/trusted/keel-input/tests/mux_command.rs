#![doc = "Acceptance tests for trusted mux command-mode input routing."]

use keel_input::{MUX_COMMAND_KEY, MuxCommandEvent, MuxCommandInput, SECURE_ATTENTION};

fn type_command(input: &mut MuxCommandInput, text: &[u8]) {
    assert_eq!(input.accept(MUX_COMMAND_KEY), MuxCommandEvent::Render);
    for byte in text {
        assert_eq!(input.accept(*byte), MuxCommandEvent::Render);
    }
}

#[test]
fn ctrl_a_enters_command_mode_and_escape_returns_to_the_pty() {
    let mut input = MuxCommandInput::default();
    assert_eq!(input.accept(MUX_COMMAND_KEY), MuxCommandEvent::Render);
    assert_eq!(input.accept(0x1b), MuxCommandEvent::Redraw);
}

#[test]
fn command_mode_submits_text_or_enters_secure_attention() {
    let mut input = MuxCommandInput::default();
    type_command(&mut input, b"review this change");
    assert_eq!(
        input.accept(b'\r'),
        MuxCommandEvent::Submit(b"review this change".to_vec())
    );

    type_command(&mut input, b"/approve");
    assert_eq!(
        input.accept(b'\r'),
        MuxCommandEvent::Forward(SECURE_ATTENTION)
    );

    type_command(&mut input, b"/floor-lift 2");
    assert_eq!(input.accept(b'\r'), MuxCommandEvent::LiftFloor(2));

    type_command(&mut input, b"/floor-lift");
    assert_eq!(input.accept(b'\r'), MuxCommandEvent::LiftFloor(3));

    type_command(&mut input, b"/floor-lift 0");
    assert_eq!(input.accept(b'\r'), MuxCommandEvent::Redraw);
}

#[test]
fn lifecycle_commands_return_supervisor_action_codes() {
    for (command, code) in [
        ("/new", 20),
        ("/tab", 21),
        ("/close", 22),
        ("/resume", 23),
        ("/detach", 24),
    ] {
        let mut input = MuxCommandInput::default();
        type_command(&mut input, command.as_bytes());
        assert_eq!(input.accept(b'\r'), MuxCommandEvent::Detach(code));
    }
}

#[test]
fn bracketed_or_control_input_cannot_invoke_a_mux_command() {
    let mut input = MuxCommandInput::default();
    type_command(&mut input, b"/detach");
    assert_eq!(input.accept(0x1b), MuxCommandEvent::Redraw);
    assert_eq!(input.accept(b'\r'), MuxCommandEvent::Forward(b'\r'));
}
