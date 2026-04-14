use clap::{Parser, ValueEnum};

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CaptureMethod {
    /// Use raw AF_PACKET socket (requires root)
    Raw,
    /// Use libpcap for capture
    Pcap,
}

#[derive(Parser, Debug)]
#[command(name = "rustcapture")]
#[command(about = "Packet capture tool using raw sockets or pcap")]
pub struct Args {
    /// Capture method to use
    #[arg(short, long, value_enum, default_value = "raw")]
    pub method: CaptureMethod,

    /// Network interface to capture on (default: all for raw, all available for pcap)
    #[arg(short, long)]
    pub interface: Option<String>,

    /// BPF filter expression (pcap mode only)
    #[arg(short, long)]
    pub filter: Option<String>,

    /// Promiscuous mode (pcap mode only)
    #[arg(short, long, default_value = "true")]
    pub promiscuous: bool,

    /// Enable terminal UI mode
    #[arg(short = 'u', long)]
    pub tui: bool,
}
