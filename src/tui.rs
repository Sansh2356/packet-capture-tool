use std::io::{self, Stdout};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
};
use tokio::sync::mpsc::UnboundedReceiver;

use crate::packet::{parse_ethernet, parse_ipv4};

/// A packet entry for display in the TUI
#[derive(Clone)]
pub struct PacketEntry {
    pub number: u64,
    pub timestamp: Instant,
    pub interface: String,
    pub length: usize,
    pub src: String,
    pub dst: String,
    pub protocol: String,
    pub info: String,
}

impl PacketEntry {
    pub fn from_raw(number: u64, data: &[u8], interface: String) -> Self {
        let length = data.len();
        let mut src = String::new();
        let mut dst = String::new();
        let mut protocol = String::from("???");
        let mut info = String::new();

        if let Some(eth) = parse_ethernet(data) {
            src = eth.src_mac.clone();
            dst = eth.dst_mac.clone();
            protocol = format!("0x{:04x}", eth.ethertype);

            // IPv4
            if eth.ethertype == 0x0800 && data.len() >= 34 {
                if let Some(ipv4) = parse_ipv4(&data[14..]) {
                    src = ipv4.src_ip.clone();
                    dst = ipv4.dst_ip.clone();
                    protocol = ipv4.protocol_name.to_string();
                    info = format!("{} -> {}", ipv4.src_ip, ipv4.dst_ip);
                }
            } else if eth.ethertype == 0x0806 {
                protocol = "ARP".to_string();
            } else if eth.ethertype == 0x86DD {
                protocol = "IPv6".to_string();
            }
        }

        Self {
            number,
            timestamp: Instant::now(),
            interface,
            length,
            src,
            dst,
            protocol,
            info,
        }
    }
}

/// Message for TUI updates
pub enum TuiMessage {
    Packet(PacketEntry),
    Quit,
}

/// TUI Application state
pub struct App {
    pub packets: Vec<PacketEntry>,
    pub table_state: TableState,
    pub packet_count: u64,
    pub start_time: Instant,
    pub running: Arc<AtomicBool>,
    pub auto_scroll: bool,
    pub max_packets: usize,
}

impl App {
    pub fn new(running: Arc<AtomicBool>) -> Self {
        Self {
            packets: Vec::new(),
            table_state: TableState::default(),
            packet_count: 0,
            start_time: Instant::now(),
            running,
            auto_scroll: true,
            max_packets: 1000, // Keep last 1000 packets
        }
    }

    pub fn add_packet(&mut self, entry: PacketEntry) {
        self.packet_count += 1;
        self.packets.push(entry);

        // Trim old packets if we exceed max
        if self.packets.len() > self.max_packets {
            self.packets.remove(0);
        }

        // Auto-scroll to bottom
        if self.auto_scroll && !self.packets.is_empty() {
            self.table_state.select(Some(self.packets.len() - 1));
        }
    }

    pub fn scroll_up(&mut self) {
        self.auto_scroll = false;
        let i = match self.table_state.selected() {
            Some(i) => i.saturating_sub(1),
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    pub fn scroll_down(&mut self) {
        let i = match self.table_state.selected() {
            Some(i) => {
                if i >= self.packets.len().saturating_sub(1) {
                    self.auto_scroll = true;
                    self.packets.len().saturating_sub(1)
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    pub fn scroll_to_bottom(&mut self) {
        self.auto_scroll = true;
        if !self.packets.is_empty() {
            self.table_state.select(Some(self.packets.len() - 1));
        }
    }

    pub fn packets_per_second(&self) -> f64 {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.packet_count as f64 / elapsed
        } else {
            0.0
        }
    }
}

/// Initialize terminal for TUI
pub fn init_terminal() -> io::Result<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    Terminal::new(backend)
}

/// Restore terminal to normal state
pub fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> io::Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

/// Draw the UI
pub fn draw(frame: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(0),    // Packet table
            Constraint::Length(1), // Footer
        ])
        .split(frame.area());

    // Header with stats
    let elapsed = app.start_time.elapsed();
    let header_text = format!(
        " Packets: {} | Rate: {:.1} pkt/s | Elapsed: {:02}:{:02} | Auto-scroll: {} ",
        app.packet_count,
        app.packets_per_second(),
        elapsed.as_secs() / 60,
        elapsed.as_secs() % 60,
        if app.auto_scroll { "ON" } else { "OFF" }
    );
    let header = Paragraph::new(header_text)
        .style(Style::default().fg(Color::Cyan))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" RustCapture ")
                .title_style(Style::default().fg(Color::Yellow).bold()),
        );
    frame.render_widget(header, chunks[0]);

    // Packet table
    let header_cells = ["#", "Interface", "Len", "Protocol", "Source", "Destination"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).bold()));
    let header_row = Row::new(header_cells).height(1);

    let rows = app.packets.iter().map(|p| {
        let style = match p.protocol.as_str() {
            "TCP" => Style::default().fg(Color::Green),
            "UDP" => Style::default().fg(Color::Blue),
            "ICMP" => Style::default().fg(Color::Magenta),
            "ARP" => Style::default().fg(Color::Yellow),
            "IPv6" => Style::default().fg(Color::Cyan),
            _ => Style::default(),
        };

        Row::new(vec![
            Cell::from(p.number.to_string()),
            Cell::from(p.interface.clone()),
            Cell::from(p.length.to_string()),
            Cell::from(p.protocol.clone()),
            Cell::from(p.src.clone()),
            Cell::from(p.dst.clone()),
        ])
        .style(style)
    });

    let table = Table::new(
        rows,
        [
            Constraint::Length(8),  // #
            Constraint::Length(12), // Interface
            Constraint::Length(6),  // Len
            Constraint::Length(10), // Protocol
            Constraint::Min(18),    // Source
            Constraint::Min(18),    // Destination
        ],
    )
    .header(header_row)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Packets "),
    )
    .highlight_style(Style::default().bg(Color::DarkGray))
    .highlight_symbol(">> ");

    frame.render_stateful_widget(table, chunks[1], &mut app.table_state);

    // Footer with help
    let footer = Paragraph::new(" q: Quit | ↑↓: Scroll | End: Auto-scroll | Space: Toggle auto-scroll ")
        .style(Style::default().fg(Color::Cyan));
    frame.render_widget(footer, chunks[2]);
}

/// Run the TUI event loop
pub async fn run_tui(
    mut rx: UnboundedReceiver<TuiMessage>,
    running: Arc<AtomicBool>,
) -> io::Result<()> {
    let mut terminal = init_terminal()?;
    let mut app = App::new(running.clone());

    let tick_rate = Duration::from_millis(50);
    let mut last_tick = Instant::now();

    loop {
        // Draw UI
        terminal.draw(|f| draw(f, &mut app))?;

        // Calculate timeout for event polling
        let timeout = tick_rate.saturating_sub(last_tick.elapsed());

        // Handle keyboard events
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => {
                            running.store(false, Ordering::SeqCst);
                            break;
                        }
                        KeyCode::Up | KeyCode::Char('k') => app.scroll_up(),
                        KeyCode::Down | KeyCode::Char('j') => app.scroll_down(),
                        KeyCode::End | KeyCode::Char('G') => app.scroll_to_bottom(),
                        KeyCode::Char(' ') => app.auto_scroll = !app.auto_scroll,
                        _ => {}
                    }
                }
            }
        }

        // Check for packet messages (non-blocking)
        while let Ok(msg) = rx.try_recv() {
            match msg {
                TuiMessage::Packet(entry) => app.add_packet(entry),
                TuiMessage::Quit => {
                    running.store(false, Ordering::SeqCst);
                    break;
                }
            }
        }

        // Check if we should quit
        if !running.load(Ordering::SeqCst) {
            break;
        }

        if last_tick.elapsed() >= tick_rate {
            last_tick = Instant::now();
        }
    }

    restore_terminal(&mut terminal)?;
    Ok(())
}
