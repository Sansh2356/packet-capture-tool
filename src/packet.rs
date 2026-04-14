use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{info, warn, debug, info_span, Span};

/// Global packet counter
static PACKET_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Captured packet with metadata
#[derive(Debug, Clone)]
pub struct CapturedPacket {
    /// Raw packet bytes 
    pub data: Vec<u8>,
}

impl CapturedPacket {
    pub fn new(data: Vec<u8>, _interface: String) -> Self {
        Self {
            data,
        }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }
}

/// Parsed Ethernet frame info
#[derive(Debug)]
pub struct EthernetInfo {
    pub src_mac: String,
    pub dst_mac: String,
    pub ethertype: u16,
}

/// Parsed IPv4 packet info
#[derive(Debug)]
pub struct Ipv4Info {
    pub src_ip: String,
    pub dst_ip: String,
    pub _protocol: u8,
    pub protocol_name: &'static str,
}

/// Parse Ethernet header from raw bytes
pub fn parse_ethernet(data: &[u8]) -> Option<EthernetInfo> {
    if data.len() < 14 {
        return None;
    }

    let dst_mac = &data[0..6];
    let src_mac = &data[6..12];
    let ethertype = u16::from_be_bytes([data[12], data[13]]);

    Some(EthernetInfo {
        src_mac: format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]
        ),
        dst_mac: format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]
        ),
        ethertype,
    })
}

/// Parse IPv4 header from raw bytes (starting after Ethernet header)
pub fn parse_ipv4(data: &[u8]) -> Option<Ipv4Info> {
    // Need at least 20 bytes for minimal IPv4 header
    if data.len() < 20 {
        return None;
    }

    let src_ip = format!(
        "{}.{}.{}.{}",
        data[12], data[13], data[14], data[15]
    );
    let dst_ip = format!(
        "{}.{}.{}.{}",
        data[16], data[17], data[18], data[19]
    );
    let protocol = data[9];
    
    let protocol_name = match protocol {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        47 => "GRE",
        50 => "ESP",
        51 => "AH",
        58 => "ICMPv6",
        _ => "OTHER",
    };

    Some(Ipv4Info {
        src_ip,
        dst_ip,
        _protocol:protocol,
        protocol_name,
    })
}

/// Get the next packet number
pub fn next_packet_number() -> u64 {
    PACKET_COUNTER.fetch_add(1, Ordering::Relaxed) + 1
}


/// Parsing a captured packet from the interface loop
pub fn handle_packet(packet: CapturedPacket, span: &Span) {
    let _guard = span.enter();
    let packet_num = next_packet_number();
    let len = packet.len();

    if len < 14 {
        warn!(packet = packet_num, len, "Packet too small");
        return;
    }

    let Some(eth) = parse_ethernet(&packet.data) else {
        warn!(packet = packet_num, len, "Failed to parse Ethernet header");
        return;
    };

    // Check if IPv4 (0x0800)
    if eth.ethertype == 0x0800 && len >= 34 {
        if let Some(ipv4) = parse_ipv4(&packet.data[14..]) {
            info!(
                packet = packet_num,
                len,
                src_mac = %eth.src_mac,
                dst_mac = %eth.dst_mac,
                ethertype = format_args!("0x{:04x}", eth.ethertype),
                src_ip = %ipv4.src_ip,
                dst_ip = %ipv4.dst_ip,
                protocol = ipv4.protocol_name,
                "IPv4 packet"
            );
            return;
        }
    }

    // Non-IPv4 or couldn't parse IPv4
    debug!(
        packet = packet_num,
        len,
        src_mac = %eth.src_mac,
        dst_mac = %eth.dst_mac,
        ethertype = format_args!("0x{:04x}", eth.ethertype),
        "Ethernet frame"
    );
}

/// Create a span for an interface
pub fn create_interface_span(interface: &str) -> Span {
    info_span!("capture", interface = %interface)
}
