# 🛡️ Sentinel

**Lightweight network intrusion detection system — a Snort alternative in pure Rust.**

Sentinel is a fast, minimal IDS that captures and analyzes network traffic using signature-based rules. Built for performance with zero-copy packet parsing.

## Features

- **Protocol Parsing** — Ethernet, IPv4, IPv6, TCP, UDP, ICMP, ARP (zero-copy)
- **Detection Engine** — Rule matching with protocol, IP, port, TCP flags, and content checks
- **TOML Rules** — Human-readable rule format with severity levels and categories
- **Colored Alerts** — Console output with severity-colored alerts + JSON logging
- **CLI** — `monitor`, `analyze`, and `rules` subcommands

## Quick Start

```bash
cargo build --release

# List default rules
sentinel rules list

# Validate a rules file
sentinel rules validate rules.toml

# Monitor an interface (requires root/sudo)
sudo sentinel monitor --interface en0 --rules rules.toml
```

## Rule Format

```toml
[[rule]]
id = "SID-1001"
name = "TCP SYN scan detected"
severity = "high"        # low | medium | high | critical
category = "scan"        # scan | exploit | malware | policy | anomaly
protocol = "tcp"         # tcp | udp | icmp | any
dst_port = 80
tcp_flags = "S"
content = "pattern"
```

## Building

```bash
cargo build --release
cargo test
```

## License

MIT
