# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [0.1.0] - 2026-04-26

Initial release of `rustcapture` — a Linux-only network packet capture tool with
dual capture backends and an interactive terminal UI.

### Added

- Dual capture backends selectable via `-m, --method`:
  - `raw`: `AF_PACKET` raw socket capture (default)
  - `pcap`: libpcap-based capture
- Multi-interface capture in `pcap` mode — spawns a worker thread per interface
  and funnels packets through a single MPSC channel to a central handler.
- Single-interface or all-interface capture via `-i, --interface` (omit to
  capture on every usable interface).
- BPF filter expressions in `pcap` mode via `-f, --filter` (e.g. `tcp port 80`).
- Promiscuous mode toggle for `pcap` mode via `-p, --promiscuous`.
- Protocol parsing for Ethernet, IPv4, TCP (including flags), UDP, and ICMP,
  with src/dst, ports, sequence/ack numbers, and basic header metadata.
- Detection (without full decode) of ARP and IPv6 frames.
- Optional interactive terminal UI via `-u, --tui`, built on `ratatui` +
  `crossterm`, featuring:
  - Live packet table with protocol-based color coding.
  - Header bar with packet count, packets/sec, and elapsed time.
  - Detail side panel with per-layer metadata (toggle with `Enter`).
  - Keyboard navigation: `↑/↓` or `j/k` to scroll, `G`/`End` to jump to
    bottom, `Space` to toggle auto-scroll, `q`/`Esc` to quit.
  - Ring-buffer trimming at 1000 packets to bound memory usage.
- Structured logging via `tracing` / `tracing-subscriber` in non-TUI mode,
  with per-interface spans and `RUST_LOG`-controlled filtering.
- Async runtime via `tokio` with `AsyncFd`-driven non-blocking raw socket
  reads.
- 1 MiB receive buffer (`SO_RCVBUF`) on the raw socket to reduce kernel-side
  drops under load.
- `clap`-based CLI with `--help` output.
- GitHub Actions release workflow built on `cargo-dist` producing a shell
  installer for the `x86_64-unknown-linux-gnu` target.
- GitHub Actions check workflow running `cargo fmt --check` and `cargo clippy`
  on stable and beta toolchains for every PR.
- MIT license and README with installation and usage instructions.

### Known limitations

- Linux only — `AF_PACKET` and the release target are Linux-specific; macOS
  and Windows are not supported.
- Requires `root` or `CAP_NET_RAW` for both capture modes.
- `--filter` and `--promiscuous` are honored only in `pcap` mode and are
  silently ignored in `raw` mode.
- IPv6 and ARP frames are detected and labeled but not fully decoded.
- Capture cannot yet be written to or replayed from `.pcap` files.
- Non-TUI mode does not currently exit gracefully on `Ctrl+C`.
