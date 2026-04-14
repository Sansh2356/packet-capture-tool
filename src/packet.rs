use std::{
    fmt,
    sync::atomic::{AtomicU64, Ordering},
};
use tracing::{debug, info, info_span, warn, Span};

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
        Self { data }
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

/// Parse Ethernet header from raw bytes including preamble etc .
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

/// Parse IPv4 header from raw bytes at the network layer after parsing the physical layer
pub fn parse_ipv4(data: &[u8]) -> Option<Ipv4Info> {
    if data.len() < 20 {
        return None;
    }

    let src_ip = format!("{}.{}.{}.{}", data[12], data[13], data[14], data[15]);
    let dst_ip = format!("{}.{}.{}.{}", data[16], data[17], data[18], data[19]);
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
        _protocol: protocol,
        protocol_name,
    })
}

/// TCP header info acting as metadata
#[derive(Debug, Clone)]
pub struct TcpInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub flags: TcpFlags,
    pub window: u16,
    pub header_len: u8,
}

/// TCP flags acting as metadata
#[derive(Debug, Clone, Default)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

impl fmt::Display for TcpFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut flags = Vec::new();
        if self.syn {
            flags.push("SYN");
        }
        if self.ack {
            flags.push("ACK");
        }
        if self.fin {
            flags.push("FIN");
        }
        if self.rst {
            flags.push("RST");
        }
        if self.psh {
            flags.push("PSH");
        }
        if self.urg {
            flags.push("URG");
        }
        if self.ece {
            flags.push("ECE");
        }
        if self.cwr {
            flags.push("CWR");
        }
        if flags.is_empty() {
            "none".to_string();
        } else {
            flags.join(",");
        }
        write!(f, "{:?}", flags)
    }
}
/// Parse TCP header after the corresponding network layer PDU has been parsed and removed
pub fn parse_tcp(data: &[u8]) -> Option<TcpInfo> {
    if data.len() < 20 {
        return None;
    }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let seq_num = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack_num = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let header_len = (data[12] >> 4) * 4;
    let flags_byte = data[13];

    let flags = TcpFlags {
        fin: flags_byte & 0x01 != 0,
        syn: flags_byte & 0x02 != 0,
        rst: flags_byte & 0x04 != 0,
        psh: flags_byte & 0x08 != 0,
        ack: flags_byte & 0x10 != 0,
        urg: flags_byte & 0x20 != 0,
        ece: flags_byte & 0x40 != 0,
        cwr: flags_byte & 0x80 != 0,
    };

    let window = u16::from_be_bytes([data[14], data[15]]);

    Some(TcpInfo {
        src_port,
        dst_port,
        seq_num,
        ack_num,
        flags,
        window,
        header_len,
    })
}

/// UDP header info
#[derive(Debug, Clone)]
pub struct UdpInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

/// Parse UDP header (starting after IP header)
pub fn parse_udp(data: &[u8]) -> Option<UdpInfo> {
    if data.len() < 8 {
        return None;
    }

    Some(UdpInfo {
        src_port: u16::from_be_bytes([data[0], data[1]]),
        dst_port: u16::from_be_bytes([data[2], data[3]]),
        length: u16::from_be_bytes([data[4], data[5]]),
        checksum: u16::from_be_bytes([data[6], data[7]]),
    })
}

/// ICMP header info
#[derive(Debug, Clone)]
pub struct IcmpInfo {
    pub icmp_type: u8,
    pub code: u8,
    pub type_name: &'static str,
}

/// Parse ICMP header
pub fn parse_icmp(data: &[u8]) -> Option<IcmpInfo> {
    if data.len() < 4 {
        return None;
    }

    let icmp_type = data[0];
    let code = data[1];

    let type_name = match icmp_type {
        0 => "Echo Reply",
        3 => "Dest Unreachable",
        8 => "Echo Request",
        11 => "Time Exceeded",
        _ => "Other",
    };

    Some(IcmpInfo {
        icmp_type,
        code,
        type_name,
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
