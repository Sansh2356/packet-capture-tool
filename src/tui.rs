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
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Wrap},
};
use tokio::sync::mpsc::UnboundedReceiver;

use crate::packet::{parse_ethernet, parse_icmp, parse_ipv4, parse_tcp, parse_udp};

/// Packet metadata for detail view
#[derive(Clone, Default)]
pub struct PacketMetadata {
    // Ethernet
    pub src_mac: String,
    pub dst_mac: String,
    pub ethertype: String,
    // IP
    pub ttl: Option<u8>,
    pub ip_header_len: Option<u8>,
    // TCP specific
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub tcp_seq: Option<u32>,
    pub tcp_ack: Option<u32>,
    pub tcp_flags: Option<String>,
    pub tcp_window: Option<u16>,
    // UDP specific
    pub udp_length: Option<u16>,
    pub udp_checksum: Option<u16>,
    // ICMP specific
    pub icmp_type: Option<String>,
    // Payload
    pub payload_len: usize,
}

impl PacketMetadata {
    /// Format metadata as lines for display
    pub fn to_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();

        // Ethernet layer
        lines.push(format!("── Ethernet ──"));
        lines.push(format!("  Src MAC: {}", self.src_mac));
        lines.push(format!("  Dst MAC: {}", self.dst_mac));
        lines.push(format!("  Type: {}", self.ethertype));

        // IP layer
        if let Some(ttl) = self.ttl {
            lines.push(format!("── IP ──"));
            lines.push(format!("  TTL: {}", ttl));
            if let Some(hlen) = self.ip_header_len {
                lines.push(format!("  Header Len: {} bytes", hlen));
            }
        }

        // Transport layer
        if let (Some(src), Some(dst)) = (self.src_port, self.dst_port) {
            if self.tcp_seq.is_some() {
                lines.push(format!("── TCP ──"));
                lines.push(format!("  Ports: {} → {}", src, dst));
                if let Some(seq) = self.tcp_seq {
                    lines.push(format!("  Seq: {}", seq));
                }
                if let Some(ack) = self.tcp_ack {
                    lines.push(format!("  Ack: {}", ack));
                }
                if let Some(ref flags) = self.tcp_flags {
                    lines.push(format!("  Flags: [{}]", flags));
                }
                if let Some(win) = self.tcp_window {
                    lines.push(format!("  Window: {}", win));
                }
            } else if self.udp_length.is_some() {
                lines.push(format!("── UDP ──"));
                lines.push(format!("  Ports: {} → {}", src, dst));
                if let Some(len) = self.udp_length {
                    lines.push(format!("  Length: {}", len));
                }
            }
        }

        // ICMP
        if let Some(ref icmp) = self.icmp_type {
            lines.push(format!("── ICMP ──"));
            lines.push(format!("  Type: {}", icmp));
        }

        // Payload
        lines.push(format!("── Payload ──"));
        lines.push(format!("  Size: {} bytes", self.payload_len));

        lines
    }
}

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
    pub metadata: PacketMetadata,
}

impl PacketEntry {
    pub fn from_raw(number: u64, data: &[u8], interface: String) -> Self {
        let length = data.len();
        let mut src = String::new();
        let mut dst = String::new();
        let mut protocol = String::from("???");
        let mut info = String::new();
        let mut metadata = PacketMetadata::default();

        if let Some(eth) = parse_ethernet(data) {
            src = eth.src_mac.clone();
            dst = eth.dst_mac.clone();
            protocol = format!("0x{:04x}", eth.ethertype);

            metadata.src_mac = eth.src_mac;
            metadata.dst_mac = eth.dst_mac;
            metadata.ethertype = format!("0x{:04x}", eth.ethertype);

            // IPv4
            if eth.ethertype == 0x0800 && data.len() >= 34 {
                if let Some(ipv4) = parse_ipv4(&data[14..]) {
                    src = ipv4.src_ip.clone();
                    dst = ipv4.dst_ip.clone();
                    protocol = ipv4.protocol_name.to_string();

                    // IP header details
                    let ip_header = &data[14..];
                    let ihl = (ip_header[0] & 0x0F) * 4;
                    metadata.ip_header_len = Some(ihl);
                    metadata.ttl = Some(ip_header[8]);
                    metadata.ethertype = "IPv4".to_string();

                    let ip_payload = &data[(14 + ihl as usize)..];

                    // TCP (protocol 6)
                    if ipv4._protocol == 6 {
                        if let Some(tcp) = parse_tcp(ip_payload) {
                            info = format!(
                                "{}:{} → {}:{} [{}]",
                                ipv4.src_ip,
                                tcp.src_port,
                                ipv4.dst_ip,
                                tcp.dst_port,
                                tcp.flags.to_string()
                            );

                            metadata.src_port = Some(tcp.src_port);
                            metadata.dst_port = Some(tcp.dst_port);
                            metadata.tcp_seq = Some(tcp.seq_num);
                            metadata.tcp_ack = Some(tcp.ack_num);
                            metadata.tcp_flags = Some(tcp.flags.to_string());
                            metadata.tcp_window = Some(tcp.window);
                            metadata.payload_len =
                                ip_payload.len().saturating_sub(tcp.header_len as usize);
                        }
                    }
                    // UDP (protocol 17)
                    else if ipv4._protocol == 17 {
                        if let Some(udp) = parse_udp(ip_payload) {
                            info = format!(
                                "{}:{} → {}:{} len={}",
                                ipv4.src_ip, udp.src_port, ipv4.dst_ip, udp.dst_port, udp.length
                            );

                            metadata.src_port = Some(udp.src_port);
                            metadata.dst_port = Some(udp.dst_port);
                            metadata.udp_length = Some(udp.length);
                            metadata.udp_checksum = Some(udp.checksum);
                            metadata.payload_len = udp.length.saturating_sub(8) as usize;
                        }
                    }
                    // ICMP (protocol 1)
                    else if ipv4._protocol == 1 {
                        if let Some(icmp) = parse_icmp(ip_payload) {
                            info = format!(
                                "{} (type={}, code={})",
                                icmp.type_name, icmp.icmp_type, icmp.code
                            );
                            metadata.icmp_type =
                                Some(format!("{} ({})", icmp.type_name, icmp.icmp_type));
                            metadata.payload_len = ip_payload.len().saturating_sub(8);
                        }
                    } else {
                        info = format!("{} → {}", ipv4.src_ip, ipv4.dst_ip);
                        metadata.payload_len = ip_payload.len();
                    }
                }
            } else if eth.ethertype == 0x0806 {
                protocol = "ARP".to_string();
                metadata.ethertype = "ARP".to_string();
                metadata.payload_len = data.len().saturating_sub(14);
            } else if eth.ethertype == 0x86DD {
                protocol = "IPv6".to_string();
                metadata.ethertype = "IPv6".to_string();
                metadata.payload_len = data.len().saturating_sub(14);
            } else {
                metadata.payload_len = data.len().saturating_sub(14);
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
            metadata,
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
    pub show_detail: bool,
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
            max_packets: 1000,
            show_detail: false,
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

    pub fn toggle_detail(&mut self) {
        self.show_detail = !self.show_detail;
    }

    pub fn selected_packet(&self) -> Option<&PacketEntry> {
        self.table_state
            .selected()
            .and_then(|i| self.packets.get(i))
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
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(if app.show_detail {
            [Constraint::Percentage(65), Constraint::Percentage(35)]
        } else {
            [Constraint::Percentage(100), Constraint::Percentage(0)]
        })
        .split(frame.area());

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(0),    // Packet table
            Constraint::Length(1), // Footer
        ])
        .split(main_chunks[0]);

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
    let header_cells = [
        "#",
        "Interface",
        "Len",
        "Protocol",
        "Source",
        "Destination",
        "Info",
    ]
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

        // Truncate info to fit
        let info_display = if p.info.len() > 30 {
            format!("{}...", &p.info[..27])
        } else {
            p.info.clone()
        };

        Row::new(vec![
            Cell::from(p.number.to_string()),
            Cell::from(p.interface.clone()),
            Cell::from(p.length.to_string()),
            Cell::from(p.protocol.clone()),
            Cell::from(p.src.clone()),
            Cell::from(p.dst.clone()),
            Cell::from(info_display),
        ])
        .style(style)
    });

    let table = Table::new(
        rows,
        [
            Constraint::Length(6),  // #
            Constraint::Length(10), // Interface
            Constraint::Length(5),  // Len
            Constraint::Length(8),  // Protocol
            Constraint::Length(16), // Source
            Constraint::Length(16), // Destination
            Constraint::Min(20),    // Info
        ],
    )
    .header(header_row)
    .block(Block::default().borders(Borders::ALL).title(" Packets "))
    .highlight_style(Style::default().bg(Color::DarkGray))
    .highlight_symbol(">> ");

    frame.render_stateful_widget(table, chunks[1], &mut app.table_state);

    // Footer with help
    let footer_text = if app.show_detail {
        " q: Quit | ↑↓: Scroll | Enter: Hide detail | Space: Auto-scroll "
    } else {
        " q: Quit | ↑↓: Scroll | Enter: Show detail | Space: Auto-scroll "
    };
    let footer = Paragraph::new(footer_text).style(Style::default().fg(Color::Cyan));
    frame.render_widget(footer, chunks[2]);

    // Detail panel (right side)
    if app.show_detail {
        draw_detail_panel(frame, app, main_chunks[1]);
    }
}

/// Draw the packet detail panel
fn draw_detail_panel(frame: &mut Frame, app: &App, area: Rect) {
    let detail_block = Block::default()
        .borders(Borders::ALL)
        .title(" Packet Details ")
        .title_style(Style::default().fg(Color::Yellow).bold());

    if let Some(packet) = app.selected_packet() {
        let mut lines: Vec<Line> = Vec::new();

        // Header info
        lines.push(Line::from(vec![
            Span::styled("Packet Number - ", Style::default().fg(Color::Magenta)),
            Span::styled(
                packet.number.to_string(),
                Style::default().fg(Color::White).bold(),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Interface: ", Style::default().fg(Color::Magenta)),
            Span::styled(&packet.interface, Style::default().fg(Color::Cyan)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Length: ", Style::default().fg(Color::Magenta)),
            Span::styled(
                format!("{} bytes", packet.length),
                Style::default().fg(Color::White),
            ),
        ]));
        lines.push(Line::from(""));

        // Metadata lines
        for line in packet.metadata.to_lines() {
            let style = if line.starts_with("──") {
                Style::default().fg(Color::Yellow).bold()
            } else if line.starts_with("  ") {
                Style::default().fg(Color::White)
            } else {
                Style::default().fg(Color::DarkGray)
            };
            lines.push(Line::styled(line, style));
        }

        let detail = Paragraph::new(lines)
            .block(detail_block)
            .wrap(Wrap { trim: false });
        frame.render_widget(detail, area);
    } else {
        let detail = Paragraph::new("No packet selected")
            .block(detail_block)
            .style(Style::default().fg(Color::DarkGray));
        frame.render_widget(detail, area);
    }
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
                        KeyCode::Enter => app.toggle_detail(),
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
