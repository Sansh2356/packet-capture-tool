# RustCapture

A lightweight network packet capture tool written in Rust, featuring dual capture backends (raw `AF_PACKET` sockets and libpcap) and an interactive terminal UI built with [ratatui](https://github.com/ratatui/ratatui).

---

## Requirements

- **Linux** (raw mode uses `AF_PACKET` sockets; pcap mode requires libpcap)
- **Rust 2021 edition** (stable toolchain)
- **libpcap development headers** for pcap mode:
  ```
  # Debian/Ubuntu
  sudo apt install libpcap-dev

  # Fedora/RHEL
  sudo dnf install libpcap-devel

  # Arch
  sudo pacman -S libpcap
  ```
- **Root privileges** (or `CAP_NET_RAW` capability) — required for both capture modes

---

## Installation

```bash
git clone https://github.com/Sansh2356/packet-capture-tool.git
cd packet-capture-tool
cargo build --release
```

The binary will be at `target/release/rustcapture`.

---

## Usage

```
rustcapture [OPTIONS]
```

### Options

| Flag | Description | Default |
|---|---|---|
| `-m, --method <raw\|pcap>` | Capture backend to use | `raw` |
| `-i, --interface <NAME>` | Network interface (e.g. `eth0`). Omit to capture on all interfaces | All |
| `-f, --filter <EXPR>` | BPF filter expression (pcap mode only, e.g. `tcp port 80`) | None |
| `-p, --promiscuous` | Enable promiscuous mode (pcap mode only) | `true` |
| `-u, --tui` | Launch the interactive terminal UI | Off |

### Examples

Capture all traffic on `eth0` using raw sockets with log output:
```bash
sudo ./rustcapture -m raw -i eth0
```

---
This is a very early project so bugs are there clearly kindly use at your own risk or if want to contribute please do .

## License

[MIT](LICENSE)
