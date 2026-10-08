use serde::Serialize;
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
};
use unicode_width::UnicodeWidthChar as _;

const MIN_ROWS: u16 = 20;
const MIN_COLUMNS: u16 = 56;

#[derive(Clone, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "kebab-case")]
enum WorkspaceSelection {
    NewWorkspace(String),
    ExistingDirectory(PathBuf),
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Profile {
    ClaudeVm,
    VmV8,
    V8Sandboxed,
}

#[derive(Serialize)]
struct Selection {
    profile: Profile,
    workspace: WorkspaceSelection,
    entry: Option<String>,
}

#[derive(Clone, Copy)]
enum Screen {
    Profile { selected: usize },
    Home { selected: usize },
    NewWorkspace,
    ExistingDirectory { selected: usize },
    EntryPoint,
}

struct Launcher {
    rows: u16,
    columns: u16,
    start: PathBuf,
    workspace_root: PathBuf,
    screen: Screen,
    profile: Profile,
    pending_workspace: Option<WorkspaceSelection>,
    name: String,
    entry: String,
    directory: PathBuf,
    entries: Vec<PathBuf>,
    directory_error: Option<String>,
    message: Option<String>,
}

impl Launcher {
    fn new(rows: u16, columns: u16, start: &Path, workspace_root: &Path) -> io::Result<Self> {
        if rows < MIN_ROWS || columns < MIN_COLUMNS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Keel's start screen requires at least {MIN_COLUMNS} columns by {MIN_ROWS} rows"
                ),
            ));
        }
        if !start.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "launcher start directory must be absolute",
            ));
        }
        // The trusted launcher resolves this path before entering the renderer
        // sandbox. Resolving it again here would require granting the untrusted
        // renderer read access to every ancestor directory merely to walk it.
        let start = start.to_path_buf();
        Ok(Self {
            rows,
            columns,
            start: start.clone(),
            workspace_root: workspace_root.to_path_buf(),
            screen: Screen::Profile { selected: 0 },
            profile: Profile::ClaudeVm,
            pending_workspace: None,
            name: String::new(),
            entry: String::new(),
            directory: start,
            entries: Vec::new(),
            directory_error: None,
            message: None,
        })
    }

    fn vertical_offset(&self) -> usize {
        usize::from(self.rows >= 25 && self.columns >= 64) * 3
    }

    /// Directory entries occupy rows `16 + offset..=rows - 3`.
    fn list_capacity(&self) -> usize {
        usize::from(self.rows).saturating_sub(18 + self.vertical_offset())
    }

    fn apply(&mut self, key: Key) -> Action {
        self.message = None;
        match self.screen {
            Screen::Profile { selected } => self.apply_profile(key, selected),
            Screen::Home { selected } => self.apply_home(key, selected),
            Screen::NewWorkspace => self.apply_new_workspace(key),
            Screen::ExistingDirectory { selected } => self.apply_existing_directory(key, selected),
            Screen::EntryPoint => self.apply_entry_point(key),
        }
    }

    fn apply_profile(&mut self, key: Key, mut selected: usize) -> Action {
        match key {
            Key::Up => selected = selected.checked_sub(1).unwrap_or(2),
            Key::Down | Key::Tab => selected = (selected + 1) % 3,
            Key::Enter => {
                self.profile = match selected {
                    0 => Profile::ClaudeVm,
                    1 => Profile::VmV8,
                    _ => Profile::V8Sandboxed,
                };
                self.screen = Screen::Home { selected: 0 };
                return Action::Repaint;
            }
            Key::Escape => return Action::Cancel,
            _ => {}
        }
        self.screen = Screen::Profile { selected };
        Action::Repaint
    }

    fn apply_home(&mut self, key: Key, mut selected: usize) -> Action {
        if !matches!(self.profile, Profile::ClaudeVm) {
            match key {
                Key::Enter => {
                    self.enter_directory(self.start.clone());
                }
                Key::Escape => self.screen = Screen::Profile { selected: 0 },
                _ => self.screen = Screen::Home { selected: 0 },
            }
            return Action::Repaint;
        }
        match key {
            Key::Up | Key::Down | Key::Tab => {
                selected = 1 - selected;
                self.screen = Screen::Home { selected };
            }
            Key::Enter if selected == 0 => {
                self.screen = Screen::NewWorkspace;
            }
            Key::Enter => {
                self.enter_directory(self.start.clone());
            }
            Key::Escape => self.screen = Screen::Profile { selected: 0 },
            _ => {}
        }
        Action::Repaint
    }

    fn apply_new_workspace(&mut self, key: Key) -> Action {
        match key {
            Key::Character(character)
                if (character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
                    && self.name.len() < 64 =>
            {
                self.name.push(character);
            }
            Key::Backspace => {
                self.name.pop();
            }
            Key::Enter if valid_workspace_name(&self.name) => {
                let destination = self.workspace_root.join(&self.name);
                if destination.exists() {
                    self.message = Some(format!("{} already exists", destination.display()));
                } else {
                    return self
                        .choose_workspace(WorkspaceSelection::NewWorkspace(self.name.clone()));
                }
            }
            Key::Enter => {
                self.message =
                    Some("Use letters, numbers, dots, dashes, or underscores".to_owned());
            }
            Key::Escape => self.screen = Screen::Home { selected: 0 },
            _ => {}
        }
        Action::Repaint
    }

    fn apply_existing_directory(&mut self, key: Key, mut selected: usize) -> Action {
        let visible_directories = usize::min(self.entries.len(), self.list_capacity());
        let option_count = visible_directories + 2;
        match key {
            Key::Up => selected = selected.checked_sub(1).unwrap_or(option_count - 1),
            Key::Down | Key::Tab => selected = (selected + 1) % option_count,
            Key::Backspace => {
                self.open_parent();
                return Action::Repaint;
            }
            Key::Enter if selected == 0 => {
                return self.choose_workspace(WorkspaceSelection::ExistingDirectory(
                    self.directory.clone(),
                ));
            }
            Key::Enter if selected == 1 => {
                self.open_parent();
                return Action::Repaint;
            }
            Key::Enter => {
                let directory = self.entries[selected - 2].clone();
                self.enter_directory(directory);
                return Action::Repaint;
            }
            Key::Escape => {
                self.screen = Screen::Home { selected: 1 };
                return Action::Repaint;
            }
            _ => {}
        }
        self.screen = Screen::ExistingDirectory { selected };
        Action::Repaint
    }

    fn apply_entry_point(&mut self, key: Key) -> Action {
        match key {
            Key::Character(character) if !character.is_control() && self.entry.len() < 256 => {
                self.entry.push(character);
            }
            Key::Backspace => {
                self.entry.pop();
            }
            Key::Enter if valid_entry_point(&self.entry) => {
                let workspace = self
                    .pending_workspace
                    .take()
                    .expect("entry selection always follows a workspace");
                return Action::Select(Selection {
                    profile: self.profile,
                    workspace,
                    entry: Some(self.entry.clone()),
                });
            }
            Key::Enter => {
                self.message =
                    Some("Use a relative .js, .mjs, or .cjs path inside the workspace".to_owned());
            }
            Key::Escape => {
                self.pending_workspace = None;
                self.entry.clear();
                self.screen = Screen::Home { selected: 1 };
            }
            _ => {}
        }
        Action::Repaint
    }

    fn choose_workspace(&mut self, workspace: WorkspaceSelection) -> Action {
        match self.profile {
            Profile::ClaudeVm => Action::Select(Selection {
                profile: self.profile,
                workspace,
                entry: None,
            }),
            Profile::VmV8 | Profile::V8Sandboxed => {
                self.pending_workspace = Some(workspace);
                self.entry.clear();
                self.screen = Screen::EntryPoint;
                Action::Repaint
            }
        }
    }

    fn open_parent(&mut self) {
        let directory = self
            .directory
            .parent()
            .unwrap_or(&self.directory)
            .to_path_buf();
        self.enter_directory(directory);
    }

    fn enter_directory(&mut self, directory: PathBuf) {
        self.entries = match child_directories(&directory) {
            Ok(entries) => {
                self.directory_error = None;
                entries
            }
            Err(error) => {
                self.directory_error =
                    Some(format!("Cannot list {}: {error}", directory.display()));
                Vec::new()
            }
        };
        self.directory = directory;
        self.screen = Screen::ExistingDirectory { selected: 0 };
    }

    #[allow(clippy::too_many_lines)]
    fn render(&self, output: &mut impl Write) -> io::Result<()> {
        let mut frame = Vec::with_capacity(
            usize::from(self.rows)
                .saturating_mul(usize::from(self.columns))
                .saturating_add(512),
        );
        frame.extend_from_slice(b"\x1b[?2026h\x1b[?7l\x1b[0m\x1b[2J\x1b[H\x1b[?25l");
        let compact_logo = [
            "                 |\\",
            "                 | \\",
            "        _________|__\\________",
            "    ___/       K E E L       \\___",
            "    \\___________________________/",
            " ~~~~~~~~~~~~~~~~│~~~~~~~~~~~~~~~~",
            "                /_\\",
        ];
        let large_logo = [
            "                           ██",
            "                           ██\\",
            "                           ██ \\",
            "                           ██  \\",
            "            _______________██___\\____________",
            "       ____/          K  E  E  L             \\____",
            "      /____________________________________________\\",
            "      \\____________________________________________/",
            "~~~~~~~~~~~~~~~~~~~~~~~~~~~██~~~~~~~~~~~~~~~~~~~~~~~~~",
            "                        ████████",
        ];
        let vertical_offset = self.vertical_offset();
        let (logo, vertical_offset): (&[&str], usize) = if vertical_offset == 3 {
            (&large_logo, 3)
        } else {
            (&compact_logo, 0)
        };
        let logo_width = logo.iter().map(|line| cell_width(line)).max().unwrap_or(0);
        let left = usize::from(self.columns).saturating_sub(logo_width) / 2 + 1;
        for (index, line) in logo.iter().enumerate() {
            write!(
                frame,
                "\x1b[{};{}H\x1b[1;32m{}\x1b[0m",
                index + 1,
                left,
                line
            )?;
        }
        write!(
            frame,
            "\x1b[{};{}H\x1b[1mStart a secure session\x1b[0m",
            9 + vertical_offset,
            centered_column(self.columns, 22)
        )?;
        match self.screen {
            Screen::Profile { selected } => {
                write!(
                    frame,
                    "\x1b[{};5H\x1b[1mChoose a runtime\x1b[0m",
                    11 + vertical_offset
                )?;
                menu_line(
                    &mut frame,
                    13 + vertical_offset,
                    5,
                    self.columns,
                    "Claude Code — microVM",
                    selected == 0,
                )?;
                menu_line(
                    &mut frame,
                    14 + vertical_offset,
                    5,
                    self.columns,
                    "V8 script — microVM",
                    selected == 1,
                )?;
                menu_line(
                    &mut frame,
                    15 + vertical_offset,
                    5,
                    self.columns,
                    "V8 script — host sandbox [lower assurance]",
                    selected == 2,
                )?;
                footer(
                    &mut frame,
                    self.rows,
                    self.columns,
                    "↑/↓ choose   Enter continue   Esc quit",
                )?;
            }
            Screen::Home { selected } => {
                write!(
                    frame,
                    "\x1b[{};5H\x1b[2mRuntime: {}\x1b[0m",
                    11 + vertical_offset,
                    profile_label(self.profile)
                )?;
                if matches!(self.profile, Profile::ClaudeVm) {
                    menu_line(
                        &mut frame,
                        12 + vertical_offset,
                        5,
                        self.columns,
                        "New workspace",
                        selected == 0,
                    )?;
                    menu_line(
                        &mut frame,
                        13 + vertical_offset,
                        5,
                        self.columns,
                        "Existing directory",
                        selected == 1,
                    )?;
                    footer(
                        &mut frame,
                        self.rows,
                        self.columns,
                        "↑/↓ choose   Enter open   Esc runtime",
                    )?;
                } else {
                    menu_line(
                        &mut frame,
                        12 + vertical_offset,
                        5,
                        self.columns,
                        "Existing directory",
                        true,
                    )?;
                    footer(
                        &mut frame,
                        self.rows,
                        self.columns,
                        "Enter open   Esc runtime",
                    )?;
                }
            }
            Screen::NewWorkspace => {
                write!(
                    frame,
                    "\x1b[{};5H\x1b[1mNew workspace\x1b[0m\
                     \x1b[{};5HName\
                     \x1b[{};5H\x1b[7m {} \x1b[0m",
                    12 + vertical_offset,
                    14 + vertical_offset,
                    15 + vertical_offset,
                    visible_head(&self.name, usize::from(self.columns.saturating_sub(12)))
                )?;
                write!(
                    frame,
                    "\x1b[{};5H\x1b[2mLocation: {}\x1b[0m",
                    17 + vertical_offset,
                    visible_tail(
                        &self.workspace_root.display().to_string(),
                        usize::from(self.columns.saturating_sub(14))
                    )
                )?;
                footer(
                    &mut frame,
                    self.rows,
                    self.columns,
                    "Enter create   Esc back",
                )?;
            }
            Screen::ExistingDirectory { selected } => {
                let path = visible_tail(
                    &self.directory.display().to_string(),
                    usize::from(self.columns.saturating_sub(8)),
                );
                write!(
                    frame,
                    "\x1b[{};5H\x1b[1mExisting directory\x1b[0m\
                     \x1b[{};5H\x1b[2m{path}\x1b[0m",
                    11 + vertical_offset,
                    12 + vertical_offset
                )?;
                menu_line(
                    &mut frame,
                    14 + vertical_offset,
                    5,
                    self.columns,
                    "Use this directory",
                    selected == 0,
                )?;
                menu_line(
                    &mut frame,
                    15 + vertical_offset,
                    5,
                    self.columns,
                    "../",
                    selected == 1,
                )?;
                for (index, directory) in self.entries.iter().take(self.list_capacity()).enumerate()
                {
                    let name = directory
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("?");
                    menu_line(
                        &mut frame,
                        16 + vertical_offset + index,
                        5,
                        self.columns,
                        &format!("{name}/"),
                        selected == index + 2,
                    )?;
                }
                footer(
                    &mut frame,
                    self.rows,
                    self.columns,
                    "↑/↓ choose   Enter open/use   Bksp parent   Esc back",
                )?;
            }
            Screen::EntryPoint => {
                write!(
                    frame,
                    "\x1b[{};5H\x1b[1mJavaScript entry file\x1b[0m\
                     \x1b[{};5H\x1b[2mRuntime: {}\x1b[0m\
                     \x1b[{};5HPath relative to workspace\
                     \x1b[{};5H\x1b[7m {} \x1b[0m",
                    11 + vertical_offset,
                    12 + vertical_offset,
                    profile_label(self.profile),
                    14 + vertical_offset,
                    15 + vertical_offset,
                    visible_head(&self.entry, usize::from(self.columns.saturating_sub(12)))
                )?;
                if matches!(self.profile, Profile::V8Sandboxed) {
                    write!(
                        frame,
                        "\x1b[{};5H\x1b[33mRequires the isolation:v8-sandboxed policy grant\x1b[0m",
                        17 + vertical_offset
                    )?;
                }
                footer(
                    &mut frame,
                    self.rows,
                    self.columns,
                    "Enter start   Esc workspace",
                )?;
            }
        }
        let message = self.message.as_ref().or_else(|| {
            matches!(self.screen, Screen::ExistingDirectory { .. })
                .then_some(self.directory_error.as_ref())
                .flatten()
        });
        if let Some(message) = message {
            write!(
                frame,
                "\x1b[{};5H\x1b[31m{}\x1b[0m",
                self.rows.saturating_sub(2),
                visible_tail(message, usize::from(self.columns.saturating_sub(8)))
            )?;
        }
        match self.screen {
            Screen::NewWorkspace => {
                let shown = visible_head(&self.name, usize::from(self.columns.saturating_sub(12)));
                write!(
                    frame,
                    "\x1b[{};{}H\x1b[?25h",
                    15 + vertical_offset,
                    6 + cell_width(&shown)
                )?;
            }
            Screen::EntryPoint => {
                let shown = visible_head(&self.entry, usize::from(self.columns.saturating_sub(12)));
                write!(
                    frame,
                    "\x1b[{};{}H\x1b[?25h",
                    15 + vertical_offset,
                    6 + cell_width(&shown)
                )?;
            }
            _ => {}
        }
        frame.extend_from_slice(b"\x1b[?2026l");
        output.write_all(&frame)?;
        output.flush()
    }
}

enum Action {
    Repaint,
    Select(Selection),
    Cancel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Key {
    Up,
    Down,
    Enter,
    Escape,
    Backspace,
    Tab,
    Character(char),
    Ignore,
}

struct Keys {
    escape: Vec<u8>,
}

impl Keys {
    fn new() -> Self {
        Self { escape: Vec::new() }
    }

    fn push(&mut self, byte: u8) -> Option<Key> {
        if self.escape.is_empty() {
            return match byte {
                b'\x1b' => {
                    self.escape.push(byte);
                    None
                }
                b'\r' | b'\n' => Some(Key::Enter),
                0x7f | 0x08 => Some(Key::Backspace),
                b'\t' => Some(Key::Tab),
                0x20..=0x7e => Some(Key::Character(char::from(byte))),
                _ => Some(Key::Ignore),
            };
        }
        self.escape.push(byte);
        match self.escape.as_slice() {
            [0x1b, 0x1b] => Some(self.finish(Key::Escape)),
            [0x1b, b'[' | b'O'] => None,
            [0x1b, byte] if !matches!(byte, b'[' | b'O') => Some(self.finish(Key::Ignore)),
            [0x1b, introducer @ (b'[' | b'O'), .., last] => {
                let last = *last;
                if (0x40..=0x7e).contains(&last) {
                    let key = match (self.escape.len(), *introducer, last) {
                        (3, _, b'A') => Key::Up,
                        (3, _, b'B') => Key::Down,
                        _ => Key::Ignore,
                    };
                    Some(self.finish(key))
                } else if (0x20..=0x3f).contains(&last) && self.escape.len() < 16 {
                    None
                } else {
                    Some(self.finish(Key::Ignore))
                }
            }
            _ => Some(self.finish(Key::Ignore)),
        }
    }

    fn flush_escape(&mut self) -> Option<Key> {
        (self.escape.as_slice() == b"\x1b").then(|| self.finish(Key::Escape))
    }

    fn finish(&mut self, key: Key) -> Key {
        self.escape.clear();
        key
    }
}

fn valid_workspace_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.starts_with('.')
        && name.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
}

fn valid_entry_point(entry: &str) -> bool {
    let path = Path::new(entry);
    !entry.is_empty()
        && entry.len() <= 256
        && !path.is_absolute()
        && path.components().all(|component| {
            matches!(
                component,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )
        })
        && matches!(
            path.extension().and_then(std::ffi::OsStr::to_str),
            Some("js" | "mjs" | "cjs")
        )
}

fn profile_label(profile: Profile) -> &'static str {
    match profile {
        Profile::ClaudeVm => "Claude Code / microVM",
        Profile::VmV8 => "V8 script / microVM",
        Profile::V8Sandboxed => "V8 script / host sandbox (lower assurance)",
    }
}

fn child_directories(path: &Path) -> io::Result<Vec<PathBuf>> {
    let mut directories = fs::read_dir(path)?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            entry
                .file_type()
                .ok()
                .filter(std::fs::FileType::is_dir)
                .map(|_| entry.path())
        })
        .collect::<Vec<_>>();
    directories.sort_by_key(|path| path.file_name().map(std::ffi::OsStr::to_os_string));
    Ok(directories)
}

fn menu_line(
    output: &mut impl Write,
    row: usize,
    column: usize,
    columns: u16,
    label: &str,
    selected: bool,
) -> io::Result<()> {
    let budget = usize::from(columns)
        .saturating_sub(column)
        .saturating_sub(3);
    let label = visible_head(label, budget);
    write!(output, "\x1b[{row};{column}H")?;
    if selected {
        write!(output, "\x1b[7m > {label} \x1b[0m")
    } else {
        write!(output, "   {label} ")
    }
}

fn footer(output: &mut impl Write, rows: u16, columns: u16, value: &str) -> io::Result<()> {
    let value = visible_head(value, usize::from(columns.saturating_sub(4)));
    write!(
        output,
        "\x1b[{};3H\x1b[2m{}\x1b[0m",
        rows.saturating_sub(1),
        value
    )
}

fn centered_column(columns: u16, width: usize) -> usize {
    usize::from(columns).saturating_sub(width) / 2 + 1
}

fn safe_character(character: char) -> Option<(char, usize)> {
    if character.is_control()
        || matches!(
            character,
            '\u{00ad}'
                | '\u{0600}'..='\u{0605}'
                | '\u{061c}'
                | '\u{06dd}'
                | '\u{070f}'
                | '\u{0890}'..='\u{0891}'
                | '\u{08e2}'
                | '\u{180e}'
                | '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{206f}'
                | '\u{feff}'
                | '\u{fff9}'..='\u{fffb}'
                | '\u{110bd}'
                | '\u{110cd}'
                | '\u{13430}'..='\u{1343f}'
                | '\u{1bca0}'..='\u{1bca3}'
                | '\u{1d173}'..='\u{1d17a}'
                | '\u{e0001}'
                | '\u{e0020}'..='\u{e007f}'
        )
    {
        return None;
    }
    character
        .width()
        .filter(|width| *width > 0)
        .map(|width| (character, width))
}

fn cell_width(value: &str) -> usize {
    value
        .chars()
        .filter_map(safe_character)
        .map(|(_, width)| width)
        .sum()
}

fn visible_head(value: &str, limit: usize) -> String {
    let mut width = 0;
    value
        .chars()
        .filter_map(safe_character)
        .take_while(|(_, character_width)| {
            let fits = width + *character_width <= limit;
            if fits {
                width += *character_width;
            }
            fits
        })
        .map(|(character, _)| character)
        .collect()
}

fn visible_tail(value: &str, limit: usize) -> String {
    if limit == 0 {
        return String::new();
    }
    let characters = value.chars().filter_map(safe_character).collect::<Vec<_>>();
    let total_width = characters.iter().map(|(_, width)| width).sum::<usize>();
    if total_width <= limit {
        return characters
            .into_iter()
            .map(|(character, _)| character)
            .collect();
    }
    let mut width = 1;
    let mut start = characters.len();
    for (index, (_, character_width)) in characters.iter().enumerate().rev() {
        if width + character_width > limit {
            break;
        }
        width += character_width;
        start = index;
    }
    std::iter::once('…')
        .chain(characters[start..].iter().map(|(character, _)| *character))
        .collect()
}

fn save_selection(path: &Path, selection: &Selection) -> io::Result<()> {
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    serde_json::to_writer(&mut output, selection).map_err(io::Error::other)?;
    output.write_all(b"\n")?;
    output.sync_all()
}

/// Runs the display-only Keel workspace launcher.
///
/// # Errors
///
/// Returns an error for invalid geometry, inaccessible directories, malformed
/// input, or an unwritable result path.
pub fn run_launcher(
    mut input: impl Read,
    mut output: impl Write,
    rows: u16,
    columns: u16,
    start: &Path,
    workspace_root: &Path,
    result: &Path,
) -> io::Result<()> {
    let mut launcher = Launcher::new(rows, columns, start, workspace_root)?;
    let mut keys = Keys::new();
    launcher.render(&mut output)?;
    let mut bytes = [0_u8; 256];
    loop {
        let count = input.read(&mut bytes)?;
        if count == 0 {
            return Ok(());
        }
        for byte in &bytes[..count] {
            let Some(key) = keys.push(*byte) else {
                continue;
            };
            match launcher.apply(key) {
                Action::Repaint => launcher.render(&mut output)?,
                Action::Select(selection) => {
                    save_selection(result, &selection)?;
                    return Ok(());
                }
                Action::Cancel => return Ok(()),
            }
        }
        if let Some(key) = keys.flush_escape() {
            match launcher.apply(key) {
                Action::Repaint => launcher.render(&mut output)?,
                Action::Select(selection) => {
                    save_selection(result, &selection)?;
                    return Ok(());
                }
                Action::Cancel => return Ok(()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Key, Keys, Launcher, Screen, run_launcher, valid_entry_point, valid_workspace_name,
        visible_head, visible_tail,
    };
    use std::{
        ffi::OsString, fs, os::unix::ffi::OsStringExt as _, path::PathBuf, process::Command,
    };

    fn temporary_directory() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "keel-launcher-test-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("thread")
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(path.join("alpha")).unwrap();
        fs::create_dir_all(path.join("beta")).unwrap();
        path.canonicalize().unwrap()
    }

    #[test]
    fn home_uses_secure_session_language() {
        let root = temporary_directory();
        let launcher = Launcher::new(30, 100, &root, &root).unwrap();
        let mut output = Vec::new();
        launcher.render(&mut output).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("Start a secure session"));
        assert!(output.contains("K  E  E  L"));
        assert!(output.contains("████████"));
        assert!(output.contains("~~~~~~~~~~~~~~~~~~~~~~~~~~~██~~~~~~~~~~~~~~~~~~~~~~~~~"));
        assert!(!output.contains("waterline"));
        assert!(output.contains("Claude Code — microVM"));
        assert!(output.contains("V8 script — microVM"));
        assert!(output.contains("lower assurance"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn minimum_geometry_reserves_content_message_and_footer_rows() {
        let root = temporary_directory();
        assert!(Launcher::new(19, 56, &root, &root).is_err());
        let workspace_root = root.join("deeply-distinctive-workspace-leaf");
        let mut launcher = Launcher::new(20, 56, &root, &workspace_root).unwrap();
        launcher.screen = Screen::NewWorkspace;
        launcher.message = Some("invalid name".to_owned());
        let mut output = Vec::new();
        launcher.render(&mut output).unwrap();

        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("\x1b[17;5H\x1b[2mLocation:"));
        assert!(output.contains("distinctive-workspace-leaf"));
        assert!(output.contains("\x1b[18;5H\x1b[31minvalid name"));
        assert!(output.contains("\x1b[19;3H\x1b[2mEnter create"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn expanded_directory_navigation_matches_rendered_capacity() {
        let root = temporary_directory();
        for index in 0..8 {
            fs::create_dir(root.join(format!("entry-{index}"))).unwrap();
        }
        let mut launcher = Launcher::new(25, 64, &root, &root).unwrap();
        launcher.enter_directory(root.clone());
        assert_eq!(launcher.list_capacity(), 4);

        for _ in 0..5 {
            launcher.apply(Key::Down);
        }
        assert!(matches!(
            launcher.screen,
            Screen::ExistingDirectory { selected: 5 }
        ));
        launcher.apply(Key::Down);
        assert!(matches!(
            launcher.screen,
            Screen::ExistingDirectory { selected: 0 }
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn directory_labels_strip_terminal_controls_and_fit_the_frame() {
        let root = temporary_directory();
        let hostile = OsString::from_vec(b"safe\x1b[31mowned".to_vec());
        fs::create_dir(root.join(hostile)).unwrap();
        fs::create_dir(root.join(format!("{}tail", "界".repeat(40)))).unwrap();
        let mut launcher = Launcher::new(25, 64, &root, &root).unwrap();
        launcher.enter_directory(root.clone());
        let mut output = Vec::new();
        launcher.render(&mut output).unwrap();

        assert!(
            !output
                .windows(b"\x1b[31mowned".len())
                .any(|window| window == b"\x1b[31mowned")
        );
        let contents = String::from_utf8(output).unwrap();
        assert!(contents.contains("safe[31mowned/"));
        assert!(contents.contains("tail/") || contents.contains('界'));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn truncation_uses_terminal_cells_and_preserves_path_tails() {
        assert_eq!(visible_head("ab界c", 4), "ab界");
        assert_eq!(visible_tail("prefix/界c", 4), "…界c");
        assert_eq!(visible_tail("anything", 0), "");
        assert_eq!(visible_head("a\u{202e}b", 8), "ab");
    }

    #[test]
    fn escape_sequences_are_consumed_without_leaking_suffixes() {
        fn parsed(bytes: &[u8]) -> Vec<Key> {
            let mut keys = Keys::new();
            bytes.iter().filter_map(|byte| keys.push(*byte)).collect()
        }

        for sequence in [
            b"\x1b[3~".as_slice(),
            b"\x1b[5~".as_slice(),
            b"\x1b[1;5A".as_slice(),
            b"\x1b[15~".as_slice(),
        ] {
            assert_eq!(parsed(sequence), vec![Key::Ignore]);
        }
        assert_eq!(parsed(b"\x1b[A"), vec![Key::Up]);
        assert_eq!(parsed(b"\x1b[B"), vec![Key::Down]);
        assert_eq!(parsed(b"\x1bxa"), vec![Key::Ignore, Key::Character('a')]);
    }

    #[test]
    fn inaccessible_directory_is_a_recoverable_screen_state() {
        let root = temporary_directory();
        let missing = root.join("missing");
        let mut launcher = Launcher::new(20, 56, &root, &root).unwrap();
        launcher.enter_directory(missing.clone());
        assert_eq!(launcher.directory, missing);
        assert!(launcher.entries.is_empty());
        assert!(
            launcher
                .directory_error
                .as_deref()
                .is_some_and(|message| message.contains("Cannot list"))
        );
        launcher.apply(Key::Down);
        assert!(launcher.directory_error.is_some());
        assert!(matches!(
            launcher.screen,
            Screen::ExistingDirectory { selected: 1 }
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn workspace_names_are_bounded_and_path_safe() {
        for valid in ["project", "my-project", "repo_2", "v1.2"] {
            assert!(valid_workspace_name(valid));
        }
        for invalid in ["", ".", "..", ".hidden", "../escape", "two words"] {
            assert!(!valid_workspace_name(invalid));
        }
    }

    #[test]
    fn existing_directory_starts_at_the_requested_path() {
        let root = temporary_directory();
        let mut launcher = Launcher::new(24, 80, &root, &root).unwrap();
        launcher.screen = Screen::ExistingDirectory { selected: 0 };
        assert_eq!(launcher.directory, root.canonicalize().unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn v8_workspace_screen_only_offers_an_existing_directory() {
        let root = temporary_directory();
        let mut launcher = Launcher::new(24, 80, &root, &root).unwrap();
        launcher.apply(Key::Down);
        launcher.apply(Key::Enter);

        let mut output = Vec::new();
        launcher.render(&mut output).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("Runtime: V8 script / microVM"));
        assert!(output.contains("Existing directory"));
        assert!(!output.contains("New workspace"));

        launcher.apply(Key::Enter);
        assert!(matches!(
            launcher.screen,
            Screen::ExistingDirectory { selected: 0 }
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn entry_points_are_relative_javascript_files() {
        for valid in ["main.js", "scripts/agent.mjs", "./worker.cjs"] {
            assert!(valid_entry_point(valid));
        }
        for invalid in [
            "",
            "/tmp/agent.mjs",
            "../agent.mjs",
            "agent.ts",
            "README.md",
        ] {
            assert!(!valid_entry_point(invalid));
        }
    }

    #[test]
    fn new_workspace_selection_is_written_as_bounded_json() {
        let root = temporary_directory();
        let result = root.join("selection.json");
        let mut output = Vec::new();
        run_launcher(
            b"\r\rdemo-project\r".as_slice(),
            &mut output,
            24,
            80,
            &root,
            &root.join("workspaces"),
            &result,
        )
        .unwrap();
        let selection =
            serde_json::from_slice::<serde_json::Value>(&fs::read(&result).unwrap()).unwrap();
        assert_eq!(
            selection,
            serde_json::json!({
                "profile": "claude-vm",
                "workspace": {"kind": "new-workspace", "value": "demo-project"},
                "entry": null
            })
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn vm_v8_selection_carries_a_bounded_workspace_entry_file() {
        let root = temporary_directory();
        assert!(
            Command::new("git")
                .args(["init", "--quiet"])
                .arg(&root)
                .status()
                .unwrap()
                .success()
        );
        let result = root.join("selection.json");
        let mut output = Vec::new();
        run_launcher(
            b"\x1b[B\r\x1b[B\r\rscripts/agent.mjs\r".as_slice(),
            &mut output,
            24,
            80,
            &root,
            &root.join("workspaces"),
            &result,
        )
        .unwrap();
        let selection =
            serde_json::from_slice::<serde_json::Value>(&fs::read(&result).unwrap()).unwrap();
        assert_eq!(
            selection,
            serde_json::json!({
                "profile": "vm-v8",
                "workspace": {
                    "kind": "existing-directory",
                    "value": root.canonicalize().unwrap()
                },
                "entry": "scripts/agent.mjs"
            })
        );
        fs::remove_dir_all(root).unwrap();
    }
}
