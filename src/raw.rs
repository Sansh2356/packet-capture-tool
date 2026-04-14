use libc::{
    bind, c_int, c_void, close, recvfrom, setsockopt, sockaddr, sockaddr_ll, socket, socklen_t,
    AF_PACKET, SOCK_RAW, SOL_SOCKET, SO_RCVBUF,
};
use std::ffi::CString;
use std::io::{Error, Result};
use std::mem::{size_of, zeroed};
use std::os::unix::io::{AsRawFd, RawFd};
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, error, info, trace, warn};

use crate::packet::{next_packet_number, parse_ethernet, parse_ipv4};
use crate::tui::{PacketEntry, TuiMessage};

const ETH_P_ALL: u16 = 0x0003;
const BUFFER_SIZE: usize = 65536;
const RECV_BUF_SIZE: c_int = 1024 * 1024;

/// Raw packet socket wrapper
pub struct PacketSocket {
    fd: RawFd,
}

impl AsRawFd for PacketSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl PacketSocket {
    /// Create a new AF_PACKET socket
    pub fn new() -> Result<Self> {
        let fd = unsafe { socket(AF_PACKET, SOCK_RAW, ETH_P_ALL.to_be() as c_int) };

        if fd < 0 {
            return Err(Error::last_os_error());
        }

        // Set a larger receive buffer
        let buf_size = RECV_BUF_SIZE;
        let ret = unsafe {
            setsockopt(
                fd,
                SOL_SOCKET,
                SO_RCVBUF,
                &buf_size as *const c_int as *const c_void,
                size_of::<c_int>() as socklen_t,
            )
        };

        if ret < 0 {
            unsafe { close(fd) };
            return Err(Error::last_os_error());
        }

        Ok(PacketSocket { fd })
    }

    /// Bind to a specific interface (0 = all interfaces)
    pub fn bind_to_interface(&self, ifindex: i32) -> Result<()> {
        let mut addr: sockaddr_ll = unsafe { zeroed() };
        addr.sll_family = AF_PACKET as u16;
        addr.sll_protocol = ETH_P_ALL.to_be();
        addr.sll_ifindex = ifindex;

        let ret = unsafe {
            bind(
                self.fd,
                &addr as *const sockaddr_ll as *const sockaddr,
                size_of::<sockaddr_ll>() as socklen_t,
            )
        };

        if ret < 0 {
            return Err(Error::last_os_error());
        }

        Ok(())
    }

    /// Receive a packet (blocking)
    pub fn recv(&self, buffer: &mut [u8]) -> Result<(usize, sockaddr_ll)> {
        let mut src_addr: sockaddr_ll = unsafe { zeroed() };
        let mut addr_len = size_of::<sockaddr_ll>() as socklen_t;

        let len = unsafe {
            recvfrom(
                self.fd,
                buffer.as_mut_ptr() as *mut c_void,
                buffer.len(),
                0,
                &mut src_addr as *mut sockaddr_ll as *mut sockaddr,
                &mut addr_len,
            )
        };

        if len < 0 {
            return Err(Error::last_os_error());
        }

        Ok((len as usize, src_addr))
    }
}

impl Drop for PacketSocket {
    fn drop(&mut self) {
        unsafe { close(self.fd) };
    }
}

/// Get interface index by name
pub fn get_interface_index(name: &str) -> Option<i32> {
    let c_name = CString::new(name).ok()?;
    let idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if idx == 0 {
        None
    } else {
        Some(idx as i32)
    }
}

/// Log packet info for raw socket capture (unchanged from original)
fn log_packet_info(data: &[u8], len: usize, ifindex: i32, packet_count: u64) {
    if len < 14 {
        warn!(len, "Packet too small");
        return;
    }

    let Some(eth) = parse_ethernet(data) else {
        warn!(
            packet = packet_count,
            len, "Failed to parse Ethernet header"
        );
        return;
    };

    if eth.ethertype == 0x0800 && len >= 34 {
        if let Some(ipv4) = parse_ipv4(&data[14..]) {
            info!(
                packet = packet_count,
                interface = ifindex,
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

    debug!(
        packet = packet_count,
        interface = ifindex,
        len,
        src_mac = %eth.src_mac,
        dst_mac = %eth.dst_mac,
        ethertype = format_args!("0x{:04x}", eth.ethertype),
        "Ethernet frame"
    );
}

/// Raw socket capture loop (unchanged behavior)
pub async fn capture(
    interface: Option<String>,
    tui_tx: Option<UnboundedSender<TuiMessage>>,
) -> Result<()> {
    info!("Creating AF_PACKET socket");

    let socket = PacketSocket::new()?;
    info!(fd = socket.as_raw_fd(), "Socket created successfully");

    // Bind to interface (0 = all interfaces)
    let ifindex = if let Some(ref iface) = interface {
        get_interface_index(iface).unwrap_or_else(|| {
            warn!(interface = %iface, "Interface not found, binding to all");
            0
        })
    } else {
        0
    };

    let iface_name = interface.clone().unwrap_or_else(|| "all".to_string());

    socket.bind_to_interface(ifindex)?;
    if ifindex == 0 {
        info!("Bound to all interfaces");
    } else {
        info!(interface = ?interface, ifindex, "Bound to interface");
    }

    // Set socket to non-blocking for async I/O
    unsafe {
        let flags = libc::fcntl(socket.as_raw_fd(), libc::F_GETFL);
        libc::fcntl(socket.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    // Wrap in AsyncFd for tokio event loop
    let async_fd = AsyncFd::new(socket)?;

    info!("Listening for packets (Ctrl+C to stop)");

    let mut buffer = vec![0u8; BUFFER_SIZE];

    loop {
        // Wait for the socket to be readable
        let mut guard = async_fd.ready(Interest::READABLE).await?;

        // Try to read packets while socket is readable
        loop {
            match guard.get_inner().recv(&mut buffer) {
                Ok((len, src_addr)) => {
                    let packet_count = next_packet_number();

                    if let Some(ref tx) = tui_tx {
                        // TUI mode - send to UI
                        let entry =
                            PacketEntry::from_raw(packet_count, &buffer[..len], iface_name.clone());
                        if tx.send(TuiMessage::Packet(Box::new(entry))).is_err() {
                            // TUI closed, exit
                            return Ok(());
                        }
                    } else {
                        // Standard mode - log
                        log_packet_info(&buffer[..len], len, src_addr.sll_ifindex, packet_count);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    trace!("Socket would block, waiting for more packets");
                    guard.clear_ready();
                    break;
                }
                Err(e) => {
                    error!(error = %e, "Error receiving packet");
                    guard.clear_ready();
                    break;
                }
            }
        }
    }
}
