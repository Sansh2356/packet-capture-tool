mod cli;
mod packet;
mod pcap;
mod raw;
mod tui;
use clap::Parser;
use std::io::Result;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::info;
use tracing_subscriber::{fmt, EnvFilter};

use cli::{Args, CaptureMethod};
use tui::{run_tui, TuiMessage};

#[tokio::main]
async fn main() -> Result<()> {
    // Parsing cli arguments provided by user
    let args = Args::parse();

    // Running flag for graceful shutdown
    let running = Arc::new(AtomicBool::new(true));

    if args.tui {
        // TUI mode
        run_with_tui(args, running).await
    } else {
        // Standard mode with tracing
        fmt()
            .with_env_filter(
                EnvFilter::from_default_env().add_directive("rustcapture=info".parse().unwrap()),
            )
            .with_target(false)
            .with_thread_ids(true)
            .init();

        info!(method = ?args.method, "Starting packet capture");

        match args.method {
            CaptureMethod::Raw => raw::capture(args.interface, None).await,
            CaptureMethod::Pcap => {
                pcap::capture(args.interface, args.filter, args.promiscuous, None).await
            }
        }
    }
}

async fn run_with_tui(args: Args, running: Arc<AtomicBool>) -> Result<()> {
    // Create channel for TUI updates
    let (tx, rx) = mpsc::unbounded_channel::<TuiMessage>();

    // Spawn capture task
    let capture_handle = tokio::spawn(async move {
        let result = match args.method {
            CaptureMethod::Raw => raw::capture(args.interface, Some(tx.clone())).await,
            CaptureMethod::Pcap => {
                pcap::capture(
                    args.interface,
                    args.filter,
                    args.promiscuous,
                    Some(tx.clone()),
                )
                .await
            }
        };

        // Signal TUI to quit if capture ends
        let _ = tx.send(TuiMessage::Quit);
        result
    });

    // Run TUI on main thread
    let tui_result = run_tui(rx, running.clone()).await;

    // Signal capture to stop
    running.store(false, Ordering::SeqCst);

    // Wait for capture task
    let _ = capture_handle.await;

    tui_result
}
