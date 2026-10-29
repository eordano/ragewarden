use std::io::{self, Write};
use std::time::{Duration, Instant};

use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::{Frame, Terminal};

use crate::commands::{self, CmdError};
use crate::output;

/// Proof that the user pressed Enter on the TUI's confirmation overlay. The
/// field is private to this module, so `consent::require_after_confirm` -- the
/// only consent path without its own prompt -- cannot be reached from anywhere
/// that did not show that overlay.
pub struct UiConfirmed(());

#[cfg(test)]
impl UiConfirmed {
    pub(crate) fn for_test() -> Self {
        UiConfirmed(())
    }
}

pub fn run() -> Result<(), CmdError> {
    let items = commands::list_item_names()?
        .into_iter()
        .map(|name| {
            let protection = classify(&name);
            Item { name, protection }
        })
        .collect();

    enable_raw_mode().map_err(io_to_cmd)?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture).map_err(io_to_cmd)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(io_to_cmd)?;

    let mut app = App::new(items);
    let res = app.event_loop(&mut terminal);

    let _ = disable_raw_mode();
    let _ = execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    );
    let _ = terminal.show_cursor();

    res
}

fn io_to_cmd(e: io::Error) -> CmdError {
    CmdError::Io(e)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Protection {
    /// The blob names these enrolled devices; opening it takes one of them.
    Device(Vec<String>),
    /// Nothing physical is named: Enter is the only gate.
    Software,
    /// The header could not be read (no cached vault, malformed blob).
    Unknown,
}

fn classify(name: &str) -> Protection {
    match commands::load_item_blob(name).and_then(|b| commands::enrolled_devices_named_in(&b)) {
        Ok(devices) if devices.is_empty() => Protection::Software,
        Ok(devices) => Protection::Device(devices),
        Err(_) => Protection::Unknown,
    }
}

impl Protection {
    fn marker(&self) -> &'static str {
        match self {
            Protection::Device(_) => "[device]  ",
            Protection::Software => "[software]",
            Protection::Unknown => "[?]       ",
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Item {
    pub(crate) name: String,
    pub(crate) protection: Protection,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    Copy,
    Reveal,
    AgentAdd,
    Exec(Vec<String>),
}

#[derive(Clone, Debug)]
pub(crate) struct Pending {
    pub(crate) action: Action,
    pub(crate) name: String,
    pub(crate) protection: Protection,
}

impl Pending {
    fn prompt(&self) -> String {
        let name = &self.name;
        match &self.action {
            Action::Copy => format!("Copy `{name}` to clipboard?"),
            Action::Reveal => format!("Reveal `{name}` on screen?"),
            Action::AgentAdd => format!("Add `{name}` to ssh-agent?"),
            Action::Exec(argv) => format!("Pass `{name}` to `{}` on FD 3?", argv.join(" ")),
        }
    }
}

/// What the overlay promises must be what the ceremony will do: a tap only when
/// this blob names an enrolled device.
pub(crate) fn overlay_text(pending: &Pending) -> String {
    let gate = match &pending.protection {
        Protection::Device(devices) => format!(
            "Enter starts the ceremony; a tap on {} authorizes it.",
            devices.join(" or ")
        ),
        Protection::Software => {
            "SOFTWARE-ONLY: this item names no enrolled device, so Enter is the only gate."
                .to_string()
        }
        Protection::Unknown => {
            "Enter starts the ceremony; whether a device is needed is decided when the \
             item is opened."
                .to_string()
        }
    };
    format!(
        "{}\n\n{gate}\n\n[Enter] confirm   [Esc] cancel",
        pending.prompt()
    )
}

#[derive(Debug, PartialEq, Eq)]
enum Mode {
    Browse,
    Filter,
    ExecInput(String),
}

pub(crate) enum Effect {
    None,
    Quit,
    Run(Pending, UiConfirmed),
}

pub(crate) struct App {
    pub(crate) all: Vec<Item>,
    pub(crate) filter: String,
    mode: Mode,
    list_state: ListState,
    pub(crate) pending: Option<Pending>,
    pub(crate) status: String,
    clear_deadline: Option<(Instant, String)>,
}

const HELP: &str = "c=copy  r=reveal  a=ssh-agent  x=exec  /=search  q=quit";

impl App {
    pub(crate) fn new(all: Vec<Item>) -> Self {
        let mut state = ListState::default();
        if !all.is_empty() {
            state.select(Some(0));
        }
        Self {
            all,
            filter: String::new(),
            mode: Mode::Browse,
            list_state: state,
            pending: None,
            status: HELP.into(),
            clear_deadline: None,
        }
    }

    pub(crate) fn visible(&self) -> Vec<&Item> {
        let needle = self.filter.to_lowercase();
        self.all
            .iter()
            .filter(|i| needle.is_empty() || i.name.to_lowercase().contains(&needle))
            .collect()
    }

    fn selected(&self) -> Option<Item> {
        let idx = self.list_state.selected()?;
        self.visible().get(idx).map(|i| (*i).clone())
    }

    fn reset_selection(&mut self) {
        let n = self.visible().len();
        self.list_state.select(if n == 0 { None } else { Some(0) });
    }

    fn stage(&mut self, action: Action) {
        if let Some(item) = self.selected() {
            self.pending = Some(Pending {
                action,
                name: item.name,
                protection: item.protection,
            });
        }
    }

    pub(crate) fn handle_key(&mut self, key: KeyEvent) -> Effect {
        if self.pending.is_some() {
            match key.code {
                KeyCode::Enter => {
                    let pending = self.pending.take().expect("checked above");
                    return Effect::Run(pending, UiConfirmed(()));
                }
                KeyCode::Esc => {
                    self.pending = None;
                    self.status = "Cancelled.".into();
                }
                _ => {}
            }
            return Effect::None;
        }
        match &mut self.mode {
            Mode::Filter => {
                match key.code {
                    KeyCode::Esc => {
                        self.filter.clear();
                        self.mode = Mode::Browse;
                    }
                    KeyCode::Enter => self.mode = Mode::Browse,
                    KeyCode::Backspace => {
                        self.filter.pop();
                    }
                    KeyCode::Char(c) => self.filter.push(c),
                    _ => {}
                }
                self.reset_selection();
                return Effect::None;
            }
            Mode::ExecInput(buf) => {
                match key.code {
                    KeyCode::Esc => self.mode = Mode::Browse,
                    KeyCode::Backspace => {
                        buf.pop();
                    }
                    KeyCode::Char(c) => buf.push(c),
                    KeyCode::Enter => {
                        let argv: Vec<String> =
                            buf.split_whitespace().map(str::to_string).collect();
                        self.mode = Mode::Browse;
                        if argv.is_empty() {
                            self.status = "exec: no command given.".into();
                        } else {
                            self.stage(Action::Exec(argv));
                        }
                    }
                    _ => {}
                }
                return Effect::None;
            }
            Mode::Browse => {}
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return Effect::Quit,
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::Char('/') => self.mode = Mode::Filter,
            KeyCode::Char('c') => self.stage(Action::Copy),
            KeyCode::Char('r') => self.stage(Action::Reveal),
            KeyCode::Char('a') => self.stage(Action::AgentAdd),
            KeyCode::Char('x') if self.selected().is_some() => {
                self.mode = Mode::ExecInput(String::new());
            }
            _ => {}
        }
        Effect::None
    }

    fn event_loop<B: ratatui::backend::Backend<Error = io::Error> + std::io::Write>(
        &mut self,
        terminal: &mut Terminal<B>,
    ) -> Result<(), CmdError> {
        loop {
            self.tick();
            terminal.draw(|f| self.draw(f)).map_err(io_to_cmd)?;

            if !event::poll(Duration::from_millis(500)).map_err(io_to_cmd)? {
                continue;
            }
            let Event::Key(key) = event::read().map_err(io_to_cmd)? else {
                continue;
            };
            if key.kind != KeyEventKind::Press {
                continue;
            }
            match self.handle_key(key) {
                Effect::None => {}
                Effect::Quit => return Ok(()),
                Effect::Run(pending, confirmed) => {
                    match suspended(terminal, || run_action(&pending, confirmed)) {
                        Ok(Outcome::Copied(secs)) => {
                            self.clear_deadline = Some((
                                Instant::now() + Duration::from_secs(secs),
                                pending.name.clone(),
                            ));
                        }
                        Ok(Outcome::Done(msg)) => self.status = msg,
                        Err(e) => self.status = format!("`{}`: {e}", pending.name),
                    }
                }
            }
        }
    }

    fn tick(&mut self) {
        if let Some((deadline, name)) = &self.clear_deadline {
            let now = Instant::now();
            if now >= *deadline {
                self.status = format!("Clipboard cleared (`{name}`).");
                self.clear_deadline = None;
            } else {
                self.status = format!(
                    "Copied `{name}` -- clipboard clears in {}s.  {HELP}",
                    (*deadline - now).as_secs() + 1
                );
            }
        }
    }

    fn move_selection(&mut self, delta: i32) {
        let n = self.visible().len();
        if n == 0 {
            return;
        }
        let cur = self.list_state.selected().unwrap_or(0) as i32;
        let next = (cur + delta).rem_euclid(n as i32);
        self.list_state.select(Some(next as usize));
    }

    pub(crate) fn draw(&mut self, f: &mut Frame<'_>) {
        let area = f.area();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(0),
                Constraint::Length(3),
            ])
            .split(area);

        let header_text = match &self.mode {
            Mode::Filter => format!("search: {}_", self.filter),
            Mode::ExecInput(buf) => format!("exec with secret on FD 3: {buf}_"),
            Mode::Browse if !self.filter.is_empty() => {
                format!("ragewarden  (filter: {})", self.filter)
            }
            Mode::Browse => "ragewarden".to_string(),
        };
        let header = Paragraph::new(header_text)
            .style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(header, chunks[0]);

        let list_items: Vec<ListItem<'_>> = {
            let visible = self.visible();
            if self.all.is_empty() {
                vec![ListItem::new(
                    "(no items -- exit and run `rageterm set <name>`)",
                )]
            } else if visible.is_empty() {
                vec![ListItem::new("(no item matches the search)")]
            } else {
                visible
                    .iter()
                    .map(|i| ListItem::new(format!("{} {}", i.protection.marker(), i.name)))
                    .collect()
            }
        };
        let list = List::new(list_items)
            .block(Block::default().borders(Borders::ALL).title("items"))
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .highlight_symbol("> ");
        f.render_stateful_widget(list, chunks[1], &mut self.list_state);

        let footer = Paragraph::new(self.status.as_str())
            .block(Block::default().borders(Borders::ALL))
            .wrap(Wrap { trim: true });
        f.render_widget(footer, chunks[2]);

        if let Some(pending) = &self.pending {
            draw_overlay(f, pending, area);
        }
    }
}

fn draw_overlay(f: &mut Frame<'_>, pending: &Pending, area: Rect) {
    let w = area.width.clamp(20, 64);
    let h = 9u16.min(area.height);
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    let popup = Rect::new(x, y, w, h);
    f.render_widget(Clear, popup);
    let p = Paragraph::new(overlay_text(pending))
        .style(Style::default().fg(Color::Yellow))
        .block(Block::default().borders(Borders::ALL).title("Confirm"))
        .wrap(Wrap { trim: false });
    f.render_widget(p, popup);
}

/// The ceremony, PIN prompts and any child process run on the normal screen,
/// in cooked mode; the TUI comes back afterwards whatever happened.
fn suspended<B, T>(terminal: &mut Terminal<B>, f: impl FnOnce() -> T) -> T
where
    B: ratatui::backend::Backend<Error = io::Error> + std::io::Write,
{
    let _ = disable_raw_mode();
    let _ = execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    );
    let out = f();
    let _ = enable_raw_mode();
    let _ = execute!(
        terminal.backend_mut(),
        EnterAlternateScreen,
        EnableMouseCapture
    );
    let _ = terminal.clear();
    out
}

enum Outcome {
    Copied(u64),
    Done(String),
}

fn run_action(pending: &Pending, confirmed: UiConfirmed) -> Result<Outcome, CmdError> {
    use ragewarden_core::audit::AuditKind;
    let name = pending.name.as_str();
    match &pending.action {
        Action::Copy => {
            let guard =
                crate::consent::require_after_confirm("Copy", name, "clipboard", confirmed)?;
            let plaintext = crate::audit_helper::outcome(
                AuditKind::Copy,
                name,
                Some("clipboard".to_string()),
                || commands::decrypt_named(name, &guard),
            )?;
            let hash = output::hex_sha256(&plaintext);
            output::deliver_clipboard(plaintext, output::DEFAULT_CLIPBOARD_CLEAR_SECS, &hash)?;
            Ok(Outcome::Copied(output::DEFAULT_CLIPBOARD_CLEAR_SECS))
        }
        Action::Reveal => {
            if let Some(envs) = commands::detect_scrollback_hostility_from(std::env::vars()) {
                return Err(CmdError::InvalidArg(format!(
                    "refusing to reveal in {envs}; secrets may be retained in scrollback. \
                     Use copy, exec or ssh-agent instead."
                )));
            }
            let guard =
                crate::consent::require_after_confirm("Reveal", name, "this terminal", confirmed)?;
            let plaintext = crate::audit_helper::outcome(
                AuditKind::Reveal,
                name,
                Some("this terminal".to_string()),
                || commands::decrypt_named(name, &guard),
            )?;
            println!("--- {name} (press Enter to dismiss) ---");
            io::stdout().write_all(&plaintext)?;
            println!();
            println!("----------------------------------------");
            drop(plaintext);
            let mut buf = String::new();
            let _ = io::stdin().read_line(&mut buf);
            print!("\x1b[2J\x1b[3J\x1b[H");
            let _ = io::stdout().flush();
            Ok(Outcome::Done(format!(
                "Revealed `{name}`; screen and scrollback cleared."
            )))
        }
        Action::AgentAdd => {
            let guard = crate::consent::require_after_confirm("Add", name, "ssh-agent", confirmed)?;
            let added = crate::audit_helper::outcome(
                AuditKind::AgentAdd,
                name,
                Some("ssh-agent".to_string()),
                || {
                    let plaintext = commands::decrypt_named(name, &guard)?;
                    crate::agent_add::add_to_agent(crate::agent_add::AddOptions {
                        plaintext: &plaintext,
                        comment: name,
                        lifetime_secs: None,
                    })
                    .map_err(commands::CmdError::from)
                },
            )?;
            Ok(Outcome::Done(format!(
                "Added `{name}` ({}) to ssh-agent -- {}",
                added.algorithm, added.fingerprint
            )))
        }
        Action::Exec(argv) => {
            let dest = format!("FD 3 of `{}`", argv[0]);
            let guard = crate::consent::require_after_confirm("Pass", name, &dest, confirmed)?;
            let code =
                crate::audit_helper::outcome(AuditKind::Exec, name, Some(dest.clone()), || {
                    let plaintext = commands::decrypt_named(name, &guard)?;
                    output::deliver_exec(plaintext, argv, false, &output::ExecEnv::default())
                        .map_err(commands::CmdError::from)
                })?;
            println!("`{}` exited with {code}. Press Enter to return.", argv[0]);
            let mut buf = String::new();
            let _ = io::stdin().read_line(&mut buf);
            Ok(Outcome::Done(format!("`{}` exited with {code}.", argv[0])))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyModifiers;
    use ratatui::backend::TestBackend;

    fn key(c: KeyCode) -> KeyEvent {
        KeyEvent::new(c, KeyModifiers::NONE)
    }

    fn app() -> App {
        App::new(vec![
            Item {
                name: "aws/prod".into(),
                protection: Protection::Device(vec!["YubiKey 5C".into()]),
            },
            Item {
                name: "github".into(),
                protection: Protection::Software,
            },
        ])
    }

    #[test]
    fn the_overlay_promises_a_tap_only_for_a_device_named_item() {
        let device = Pending {
            action: Action::Copy,
            name: "aws/prod".into(),
            protection: Protection::Device(vec!["YubiKey 5C".into()]),
        };
        assert!(overlay_text(&device).contains("a tap on YubiKey 5C authorizes it"));
        let software = Pending {
            protection: Protection::Software,
            ..device
        };
        let text = overlay_text(&software);
        assert!(text.contains("SOFTWARE-ONLY"));
        assert!(!text.contains("tap"));
    }

    #[test]
    fn search_filters_the_list_and_escape_clears_it() {
        let mut a = app();
        a.handle_key(key(KeyCode::Char('/')));
        for c in "git".chars() {
            a.handle_key(key(KeyCode::Char(c)));
        }
        assert_eq!(a.visible().len(), 1);
        assert_eq!(a.visible()[0].name, "github");
        a.handle_key(key(KeyCode::Esc));
        assert_eq!(a.visible().len(), 2);
    }

    #[test]
    fn enter_on_the_overlay_is_the_only_way_to_a_run_effect() {
        let mut a = app();
        assert!(matches!(a.handle_key(key(KeyCode::Enter)), Effect::None));
        a.handle_key(key(KeyCode::Char('c')));
        assert!(a.pending.is_some());
        match a.handle_key(key(KeyCode::Enter)) {
            Effect::Run(p, _) => assert_eq!(p.action, Action::Copy),
            _ => panic!("Enter on the overlay must run the staged action"),
        }
    }

    #[test]
    fn exec_takes_a_command_line_before_confirming() {
        let mut a = app();
        a.handle_key(key(KeyCode::Char('x')));
        for c in "ssh host".chars() {
            a.handle_key(key(KeyCode::Char(c)));
        }
        a.handle_key(key(KeyCode::Enter));
        let p = a.pending.clone().expect("staged");
        assert_eq!(p.action, Action::Exec(vec!["ssh".into(), "host".into()]));
    }

    #[test]
    fn the_list_marks_device_and_software_items() {
        let mut a = app();
        let mut terminal = Terminal::new(TestBackend::new(60, 12)).unwrap();
        terminal.draw(|f| a.draw(f)).unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(text.contains("[device]"));
        assert!(text.contains("[software]"));
    }
}
