use pcap::{Capture, Device};
use std::collections::HashMap;
use std::io::{Error, Result};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tracing::{error, info, warn, Span};

use crate::packet::{create_interface_span, handle_packet, next_packet_number, CapturedPacket};
use crate::tui::{PacketEntry, TuiMessage};

const BUFFER_SIZE: usize = 65536;
const RECV_BUF_SIZE: i32 = 1024 * 1024;

// Packet interface containing the interface and the captured packet containing its payload
#[derive(Debug)]
pub struct PacketMessage {
    pub packet: CapturedPacket,
    pub interface: String,
}

/// Get all available capture interfaces
pub fn get_all_interfaces() -> Result<Vec<Device>> {
    Device::list().map_err(|e| Error::new(std::io::ErrorKind::Other, e.to_string()))
}

/// Filter interfaces to only include usable ones (up, not loopback unless specified)
pub fn filter_usable_interfaces(devices: Vec<Device>, include_loopback: bool) -> Vec<Device> {
    devices
        .into_iter()
        .filter(|dev| {
            // Skip "any" pseudo-device as we're capturing on all real interfaces
            if dev.name == "any" {
                return false;
            }
            // Optionally skip loopback
            if !include_loopback && dev.name.starts_with("lo") {
                return false;
            }
            true
        })
        .collect()
}

/// Thread overseeing the capturing of packets belonging to an interface
struct CaptureThread {
    handle: JoinHandle<()>,
    interface: String,
}

fn start_interface_capture(
    device: Device,
    filter: Option<String>,
    // Capture from all the interfaces
    promiscuous: bool,
    // Packet sender to sole packet handler/parser
    tx: UnboundedSender<PacketMessage>,
) -> Result<JoinHandle<()>> {
    let interface_name = device.name.clone();
    let filter_clone = filter.clone();
    // Spawning a worker thread mapped to a particular interface listening for packets
    let handle = thread::spawn(move || {
        // Span attached to each thread-trace specific to interface
        let span = create_interface_span(&interface_name);
        let _guard = span.enter();

        info!(device = %interface_name, "Starting capture thread");

        let cap_result = Capture::from_device(device)
            .map_err(|e| Error::new(std::io::ErrorKind::Other, e.to_string()))
            .and_then(|cap| {
                cap.promisc(promiscuous)
                    .snaplen(BUFFER_SIZE as i32)
                    .buffer_size(RECV_BUF_SIZE)
                    .timeout(100) // 100ms timeout for responsive shutdown
                    .open()
                    .map_err(|e| Error::new(std::io::ErrorKind::Other, e.to_string()))
            });

        let mut cap = match cap_result {
            Ok(c) => c,
            Err(e) => {
                error!(interface = %interface_name, error = %e, "Failed to open capture");
                return;
            }
        };

        // Applying BPF (berkley packet filter) filter if provided according to protocol identifier etc
        if let Some(ref filter_str) = filter_clone {
            if let Err(e) = cap.filter(filter_str, true) {
                error!(
                    interface = %interface_name,
                    filter = %filter_str,
                    error = %e,
                    "Failed to apply filter"
                );
                return;
            }
            info!(interface = %interface_name, filter = %filter_str, "Applied BPF filter");
        }

        info!(interface = %interface_name, "Capture started");

        loop {
            match cap.next_packet() {
                Ok(packet) => {
                    let captured =
                        CapturedPacket::new(packet.data.to_vec(), interface_name.clone());

                    let msg = PacketMessage {
                        packet: captured,
                        interface: interface_name.clone(),
                    };

                    if tx.send(msg).is_err() {
                        info!(interface = %interface_name, "Channel closed, stopping capture");
                        break;
                    }
                }
                Err(pcap::Error::TimeoutExpired) => {
                    // Check if channel is still open
                    if tx.is_closed() {
                        info!(interface = %interface_name, "Channel closed, stopping capture");
                        break;
                    }
                    continue;
                }
                Err(e) => {
                    error!(
                        interface = %interface_name,
                        error = %e,
                        "Capture error"
                    );
                    break;
                }
            }
        }

        info!(interface = %interface_name, "Capture thread ended");
    });

    Ok(handle)
}

/// Central packet handler that receives from all capture threads
async fn packet_handler(
    mut rx: UnboundedReceiver<PacketMessage>,
    interface_spans: Arc<HashMap<String, Span>>,
    tui_tx: Option<UnboundedSender<TuiMessage>>,
) {
    info!("Packet handler started");

    while let Some(msg) = rx.recv().await {
        if let Some(ref tx) = tui_tx {
            // Send to TUI
            let packet_num = next_packet_number();
            let entry = PacketEntry::from_raw(packet_num, &msg.packet.data, msg.interface.clone());
            if tx.send(TuiMessage::Packet(entry)).is_err() {
                break;
            }
        } else {
            // Simple logging
            let span = interface_spans
                .get(&msg.interface)
                .cloned()
                .unwrap_or_else(|| create_interface_span(&msg.interface));

            handle_packet(msg.packet, &span);
        }
    }

    info!("Packet handler stopped");
}

/// Main pcap capture function - spawns threads for all interfaces
pub async fn capture(
    interface: Option<String>,
    filter: Option<String>,
    promiscuous: bool,
    tui_tx: Option<UnboundedSender<TuiMessage>>,
) -> Result<()> {
    // Get interfaces to capture on
    let devices = if let Some(ref iface) = interface {
        // Single interface specified
        vec![Device::from(iface.as_str())]
    } else {
        // Get all interfaces
        let all_devices = get_all_interfaces()?;
        let filtered = filter_usable_interfaces(all_devices, false);

        if filtered.is_empty() {
            return Err(Error::new(
                std::io::ErrorKind::NotFound,
                "No usable capture interfaces found",
            ));
        }

        filtered
    };

    info!(count = devices.len(), "Found capture interfaces");
    for dev in &devices {
        info!(interface = %dev.name, description = ?dev.desc, "Interface");
    }

    // We use a single MPSC channel where multiple producers send to one consumer
    let (tx, rx) = mpsc::unbounded_channel::<PacketMessage>();

    // Create spans for each interface
    let mut interface_spans = HashMap::new();
    for dev in &devices {
        interface_spans.insert(dev.name.clone(), create_interface_span(&dev.name));
    }
    let interface_spans = Arc::new(interface_spans);

    // Spawn capture threads
    let mut capture_threads: Vec<CaptureThread> = Vec::new();

    for device in devices {
        let interface_name = device.name.clone();
        let tx_clone = tx.clone();
        let filter_clone = filter.clone();

        match start_interface_capture(device, filter_clone, promiscuous, tx_clone) {
            Ok(handle) => {
                capture_threads.push(CaptureThread {
                    handle,
                    interface: interface_name.clone(),
                });
                info!(interface = %interface_name, "Capture thread spawned");
            }
            Err(e) => {
                warn!(
                    interface = %interface_name,
                    error = %e,
                    "Failed to start capture thread"
                );
            }
        }
    }

    if capture_threads.is_empty() {
        return Err(Error::new(
            std::io::ErrorKind::Other,
            "Failed to start any capture threads",
        ));
    }

    // Drop the original sender so the channel closes when all threads finish
    drop(tx);

    info!(
        threads = capture_threads.len(),
        "Listening for packets (Ctrl+C to stop)"
    );

    let spans_clone = Arc::clone(&interface_spans);
    // Run packet handler as async task
    let handler_task = tokio::spawn(async move {
        packet_handler(rx, spans_clone, tui_tx).await;
    });

    // Wait for handler to complete (will happen when all senders are dropped)
    // In practice, this runs until Ctrl+C since capture threads loop indefinitely
    let _ = handler_task.await;

    // Wait for all capture threads to finish for graceful shutdown of state
    for thread in capture_threads {
        info!(interface = %thread.interface, "Waiting for capture thread to finish");
        let _ = thread.handle.join();
    }

    Ok(())
}
