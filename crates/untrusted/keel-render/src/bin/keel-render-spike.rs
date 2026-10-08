#![doc = "Display-only renderer process that must never receive a real tty."]

use keel_render::{render_stream, run_launcher};
use std::{
    env,
    fs::OpenOptions,
    io::{self, IsTerminal as _},
};

fn main() -> io::Result<()> {
    if io::stdin().is_terminal() || io::stdout().is_terminal() || io::stderr().is_terminal() {
        return Err(io::Error::other(
            "renderer inherited a tty on a standard descriptor",
        ));
    }
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    let argument = arguments
        .first()
        .ok_or_else(|| io::Error::other("usage: keel-render-spike REAL_TTY|--stream|--launcher"))?;
    if argument == "--stream" {
        return render_stream(io::stdin().lock(), io::stdout().lock()).map(|_| ());
    }
    if argument == "--launcher" {
        let [_, rows, columns, start, workspace_root, result] = arguments.as_slice() else {
            return Err(io::Error::other(
                "usage: keel-render-spike --launcher ROWS COLUMNS START WORKSPACE_ROOT RESULT",
            ));
        };
        let rows = rows
            .parse::<u16>()
            .map_err(|_| io::Error::other("invalid launcher rows"))?;
        let columns = columns
            .parse::<u16>()
            .map_err(|_| io::Error::other("invalid launcher columns"))?;
        return run_launcher(
            io::stdin().lock(),
            io::stdout().lock(),
            rows,
            columns,
            start.as_ref(),
            workspace_root.as_ref(),
            result.as_ref(),
        );
    }
    let real_tty = argument;
    match OpenOptions::new().read(true).write(true).open(real_tty) {
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {}
        Err(error) => {
            return Err(io::Error::other(format!(
                "renderer tty open failed for an unexpected reason: {error}"
            )));
        }
        Ok(_) => return Err(io::Error::other("renderer could open the real tty")),
    }

    render_stream(io::stdin().lock(), io::stdout().lock()).map(|_| ())
}
