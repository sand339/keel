#![forbid(unsafe_code)]
#![doc = "Phase 0 trusted tty owner and secure-attention takeover proof."]

use keel_input::{ApprovalMethod, GatePayload, InputEvent, InputGate, render_gate};
use std::{
    env,
    error::Error,
    io::{self, IsTerminal as _, Read as _, Write as _},
    process::{Command, Stdio},
};

const CHALLENGE: &str = "7KQ2";
const GUEST_TUI: &[u8] = b"\x1b[2J\x1b[H\x1b[1;36mKeel harness TUI\x1b[0m\r\nworkspace: demo\r\n> ";

fn render(renderer: &str, real_tty: &str, guest_frame: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut child = Command::new(renderer)
        .arg(real_tty)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("renderer stdin was not piped")?
        .write_all(guest_frame)?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(format!(
            "renderer rejected its descriptor set: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(output.stdout)
}

fn main() -> Result<(), Box<dyn Error>> {
    let renderer = env::args().nth(1).ok_or("usage: keel-tty-spike RENDERER")?;
    let real_tty = env::args()
        .nth(2)
        .ok_or("usage: keel-tty-spike RENDERER REAL_TTY")?;
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() || !io::stderr().is_terminal() {
        return Err("trusted runtime does not exclusively own terminal stdio".into());
    }
    let frame = render(&renderer, &real_tty, GUEST_TUI)?;

    let mut terminal = io::stdout().lock();
    terminal.write_all(&frame)?;
    terminal.write_all(b"\nRENDERER_NO_TTY=pass\nTTY_RUNTIME_READY\n")?;
    terminal.flush()?;

    let mut gate = InputGate::new();
    gate.set_pending(ApprovalMethod::Challenge, Some(CHALLENGE));
    for byte in io::stdin().lock().bytes() {
        match gate.accept(byte?) {
            InputEvent::Forward(_) | InputEvent::Consumed => {}
            InputEvent::EnterTrusted => {
                let screen = render_gate(
                    &GatePayload {
                        action_id: 1,
                        action_class: "GitPush".to_owned(),
                        exact_target: b"push refs/heads/main".to_vec(),
                        reasons: Vec::new(),
                        floor_history: vec![b"Host(evil.example,/issue/1)".to_vec()],
                        session_grant: None,
                    },
                    ApprovalMethod::Challenge,
                    Some(CHALLENGE),
                );
                write!(terminal, "\x1b[2J\x1b[H{screen}")?;
                terminal.flush()?;
            }
            InputEvent::ChallengeMismatch => {
                terminal.write_all(b"CHALLENGE_MISMATCH\n")?;
                terminal.flush()?;
            }
            InputEvent::Approved | InputEvent::ApprovedGrant => {
                terminal.write_all(b"APPROVED\n")?;
                terminal.flush()?;
                return Ok(());
            }
            InputEvent::Denied => return Err("operator denied tty spike".into()),
        }
    }
    Err("terminal input ended before approval".into())
}
