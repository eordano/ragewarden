use std::io;

use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::{Frame, Terminal};

use crate::commands::{self, CmdError};
use crate::output;

pub fn run() -> Result<(), CmdError> {
    let names = commands::list_item_names()?;

    enable_raw_mode().map_err(io_to_cmd)?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture).map_err(io_to_cmd)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(io_to_cmd)?;

    let mut app = App::new(names);
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

struct App {
    items: Vec<String>,
    list_state: ListState,

    pending: Option<PendingAction>,

    status: String,
}

#[derive(Clone)]
enum PendingAction {
    Copy { name: String },
    Reveal { name: String },
}

impl PendingAction {
    fn prompt(&self) -> String {
        match self {
            PendingAction::Copy { name } => format!("Copy `{name}` to clipboard?"),
            PendingAction::Reveal { name } => format!("Reveal `{name}` on screen?"),
        }
    }
}

impl App {
    fn new(items: Vec<String>) -> Self {
        let mut state = ListState::default();
        if !items.is_empty() {
            state.select(Some(0));
        }
        Self {
            items,
            list_state: state,
            pending: None,
            status: "Enter authorizes  c=copy  r=reveal  q=quit".into(),
        }
    }

    fn event_loop<B: ratatui::backend::Backend<Error = io::Error> + std::io::Write>(
        &mut self,
        terminal: &mut Terminal<B>,
    ) -> Result<(), CmdError> {
        loop {
            terminal.draw(|f| self.draw(f)).map_err(io_to_cmd)?;

            let ev = event::read().map_err(io_to_cmd)?;
            if let Event::Key(key) = ev {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                if let Some(pending) = self.pending.clone() {
                    match key.code {
                        KeyCode::Enter => {
                            self.pending = None;
                            self.run_pending(pending, terminal)?;
                        }
                        KeyCode::Esc => {
                            self.pending = None;
                            self.status = "Cancelled.".into();
                        }
                        _ => {}
                    }
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                    KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
                    KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
                    KeyCode::Char('c') => {
                        if let Some(name) = self.selected_name() {
                            self.pending = Some(PendingAction::Copy { name });
                        }
                    }
                    KeyCode::Char('r') => {
                        if let Some(name) = self.selected_name() {
                            self.pending = Some(PendingAction::Reveal { name });
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    fn move_selection(&mut self, delta: i32) {
        if self.items.is_empty() {
            return;
        }
        let cur = self.list_state.selected().unwrap_or(0) as i32;
        let next = (cur + delta).rem_euclid(self.items.len() as i32);
        self.list_state.select(Some(next as usize));
    }

    fn selected_name(&self) -> Option<String> {
        let idx = self.list_state.selected()?;
        self.items.get(idx).cloned()
    }

    fn run_pending<B: ratatui::backend::Backend<Error = io::Error> + std::io::Write>(
        &mut self,
        pending: PendingAction,
        terminal: &mut Terminal<B>,
    ) -> Result<(), CmdError> {
        match pending {
            PendingAction::Copy { name } => {
                // The overlay's [Enter] is the software-side confirmation here
                // (`--yes` is not plumbed into the TUI at all). It stands in for
                // the y/N prompt and for nothing else: a device-protected item
                // still has to be unwrapped by the device.
                let consent_guard =
                    crate::consent::require_after_confirm("Copy", &name, "clipboard")
                        .map_err(commands::CmdError::from)?;
                let plaintext = commands::decrypt_named(&name, &consent_guard)?;
                let hash = output::hex_sha256(&plaintext);
                output::deliver_clipboard(plaintext, output::DEFAULT_CLIPBOARD_CLEAR_SECS, &hash)?;
                self.status = format!(
                    "Copied `{name}` to clipboard. Auto-clearing in {}s.",
                    output::DEFAULT_CLIPBOARD_CLEAR_SECS
                );
            }
            PendingAction::Reveal { name } => {
                let consent_guard =
                    crate::consent::require_after_confirm("Reveal", &name, "this terminal")
                        .map_err(commands::CmdError::from)?;
                let plaintext = commands::decrypt_named(&name, &consent_guard)?;

                let _ = disable_raw_mode();
                let _ = crossterm::execute!(
                    terminal.backend_mut(),
                    LeaveAlternateScreen,
                    DisableMouseCapture
                );
                println!("--- {name} (press Enter to dismiss) ---");
                std::io::Write::write_all(&mut std::io::stdout(), &plaintext)?;
                println!();
                println!("----------------------------------------");
                drop(plaintext);
                let mut buf = String::new();
                let _ = std::io::stdin().read_line(&mut buf);

                let _ = enable_raw_mode();
                let _ = crossterm::execute!(
                    terminal.backend_mut(),
                    EnterAlternateScreen,
                    EnableMouseCapture
                );
                terminal.clear().map_err(io_to_cmd)?;
                self.status = format!("Revealed `{name}`.");
            }
        }
        Ok(())
    }

    fn draw(&mut self, f: &mut Frame<'_>) {
        let area = f.area();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(0),
                Constraint::Length(3),
            ])
            .split(area);

        let header = Paragraph::new("ragewarden")
            .style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(header, chunks[0]);

        let list_items: Vec<ListItem<'_>> = if self.items.is_empty() {
            vec![ListItem::new(
                "(no items -- exit and run `rageterm set <name>`)",
            )]
        } else {
            self.items
                .iter()
                .map(|n| ListItem::new(n.as_str()))
                .collect()
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
            self.draw_overlay(f, pending, area);
        }
    }

    fn draw_overlay(&self, f: &mut Frame<'_>, pending: &PendingAction, area: Rect) {
        let w = area.width.min(60).max(20);
        let h = 7u16.min(area.height);
        let x = area.x + (area.width.saturating_sub(w)) / 2;
        let y = area.y + (area.height.saturating_sub(h)) / 2;
        let popup = Rect::new(x, y, w, h);
        f.render_widget(Clear, popup);
        let body = format!(
            "{}\n\n{}\n\n[Enter] confirm   [Esc] cancel",
            pending.prompt(),
            if crate::consent::hardware_identity_enrolled().unwrap_or(false) {
                "Enter starts the ceremony; the device tap authorizes it."
            } else {
                "SOFTWARE-ONLY: no hardware identity is enrolled, so Enter is the only gate."
            }
        );
        let p = Paragraph::new(body)
            .style(Style::default().fg(Color::Yellow))
            .block(Block::default().borders(Borders::ALL).title("Confirm"))
            .wrap(Wrap { trim: false });
        f.render_widget(p, popup);
    }
}
