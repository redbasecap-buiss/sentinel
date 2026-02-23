//! Connection tracking — tracks TCP/UDP flows with statistics.

use std::collections::HashMap;
use std::fmt;
use crate::packet::{ParsedPacket, TransportLayer};

/// Unique identifier for a bidirectional flow.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct FlowKey {
    /// Lower IP (canonical ordering for bidirectional).
    pub ip_a: String,
    pub port_a: u16,
    /// Higher IP.
    pub ip_b: String,
    pub port_b: u16,
    pub protocol: FlowProtocol,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum FlowProtocol {
    Tcp,
    Udp,
}

impl fmt::Display for FlowProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
        }
    }
}

impl FlowKey {
    /// Create a canonical (bidirectional) flow key from packet fields.
    pub fn from_packet(
        src_ip: &str,
        src_port: u16,
        dst_ip: &str,
        dst_port: u16,
        proto: FlowProtocol,
    ) -> Self {
        // Canonical ordering: smaller (ip, port) first.
        let a = (src_ip, src_port);
        let b = (dst_ip, dst_port);
        if a <= b {
            Self {
                ip_a: src_ip.to_string(),
                port_a: src_port,
                ip_b: dst_ip.to_string(),
                port_b: dst_port,
                protocol: proto,
            }
        } else {
            Self {
                ip_a: dst_ip.to_string(),
                port_a: dst_port,
                ip_b: src_ip.to_string(),
                port_b: src_port,
                protocol: proto,
            }
        }
    }
}

impl fmt::Display for FlowKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {}:{} ↔ {}:{}",
            self.protocol, self.ip_a, self.port_a, self.ip_b, self.port_b
        )
    }
}

/// Per-flow statistics.
#[derive(Debug, Clone)]
pub struct FlowStats {
    /// Total packets seen (both directions).
    pub packets: u64,
    /// Total bytes (payload only, both directions).
    pub bytes: u64,
    /// Packets from A → B.
    pub packets_a_to_b: u64,
    /// Packets from B → A.
    pub packets_b_to_a: u64,
    /// Bytes from A → B.
    pub bytes_a_to_b: u64,
    /// Bytes from B → A.
    pub bytes_b_to_a: u64,
    /// First packet timestamp (epoch seconds).
    pub first_seen: u64,
    /// Last packet timestamp (epoch seconds).
    pub last_seen: u64,
    /// TCP state, if applicable.
    pub tcp_state: TcpFlowState,
}

impl FlowStats {
    fn new(now: u64) -> Self {
        Self {
            packets: 0,
            bytes: 0,
            packets_a_to_b: 0,
            packets_b_to_a: 0,
            bytes_a_to_b: 0,
            bytes_b_to_a: 0,
            first_seen: now,
            last_seen: now,
            tcp_state: TcpFlowState::New,
        }
    }

    /// Duration in seconds.
    pub fn duration_secs(&self) -> u64 {
        self.last_seen.saturating_sub(self.first_seen)
    }
}

/// Simplified TCP connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpFlowState {
    New,
    SynSent,
    Established,
    FinWait,
    Closed,
}

impl fmt::Display for TcpFlowState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::New => write!(f, "NEW"),
            Self::SynSent => write!(f, "SYN_SENT"),
            Self::Established => write!(f, "ESTABLISHED"),
            Self::FinWait => write!(f, "FIN_WAIT"),
            Self::Closed => write!(f, "CLOSED"),
        }
    }
}

/// Connection tracker — maintains flow table.
pub struct ConnectionTracker {
    flows: HashMap<FlowKey, FlowStats>,
}

impl ConnectionTracker {
    pub fn new() -> Self {
        Self {
            flows: HashMap::new(),
        }
    }

    /// Update the flow table with a parsed packet.
    pub fn track(&mut self, packet: &ParsedPacket<'_>, now: u64) {
        let (src_ip, dst_ip) = match (packet.src_ip(), packet.dst_ip()) {
            (Some(s), Some(d)) => (s, d),
            _ => return,
        };

        let (src_port, dst_port, proto, tcp_flags) = match &packet.transport {
            Some(TransportLayer::Tcp(tcp)) => (
                tcp.src_port,
                tcp.dst_port,
                FlowProtocol::Tcp,
                Some(tcp.flags),
            ),
            Some(TransportLayer::Udp(udp)) => (udp.src_port, udp.dst_port, FlowProtocol::Udp, None),
            _ => return,
        };

        let key = FlowKey::from_packet(&src_ip, src_port, &dst_ip, dst_port, proto);
        let is_a_to_b = src_ip == key.ip_a && src_port == key.port_a;

        let payload_len = match &packet.transport {
            Some(TransportLayer::Tcp(t)) => t.payload.len() as u64,
            Some(TransportLayer::Udp(u)) => u.payload.len() as u64,
            _ => 0,
        };

        let stats = self.flows.entry(key).or_insert_with(|| FlowStats::new(now));
        stats.packets += 1;
        stats.bytes += payload_len;
        stats.last_seen = now;

        if is_a_to_b {
            stats.packets_a_to_b += 1;
            stats.bytes_a_to_b += payload_len;
        } else {
            stats.packets_b_to_a += 1;
            stats.bytes_b_to_a += payload_len;
        }

        // Update TCP state machine
        if let Some(flags) = tcp_flags {
            stats.tcp_state = match stats.tcp_state {
                TcpFlowState::New if flags.syn() && !flags.ack() => TcpFlowState::SynSent,
                TcpFlowState::SynSent if flags.syn() && flags.ack() => TcpFlowState::Established,
                TcpFlowState::SynSent if flags.ack() => TcpFlowState::Established,
                TcpFlowState::Established if flags.fin() => TcpFlowState::FinWait,
                TcpFlowState::FinWait if flags.fin() || flags.ack() => TcpFlowState::Closed,
                s if flags.rst() => TcpFlowState::Closed,
                s => s,
            };
        }
    }

    /// Get all tracked flows.
    pub fn flows(&self) -> &HashMap<FlowKey, FlowStats> {
        &self.flows
    }

    /// Number of active flows.
    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    /// Get stats for a specific flow.
    pub fn get(&self, key: &FlowKey) -> Option<&FlowStats> {
        self.flows.get(key)
    }

    /// Remove flows older than `max_age_secs` from `now`.
    pub fn expire(&mut self, now: u64, max_age_secs: u64) -> usize {
        let before = self.flows.len();
        self.flows
            .retain(|_, stats| now.saturating_sub(stats.last_seen) < max_age_secs);
        before - self.flows.len()
    }

    /// Top N flows by total bytes.
    pub fn top_flows_by_bytes(&self, n: usize) -> Vec<(&FlowKey, &FlowStats)> {
        let mut entries: Vec<_> = self.flows.iter().collect();
        entries.sort_by(|a, b| b.1.bytes.cmp(&a.1.bytes));
        entries.truncate(n);
        entries
    }

    /// Per-IP traffic summary.
    pub fn ip_stats(&self) -> HashMap<String, u64> {
        let mut stats: HashMap<String, u64> = HashMap::new();
        for (key, flow) in &self.flows {
            *stats.entry(key.ip_a.clone()).or_default() += flow.bytes_a_to_b;
            *stats.entry(key.ip_b.clone()).or_default() += flow.bytes_b_to_a;
        }
        stats
    }
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::*;

    fn make_tcp_pkt(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0xaa; 6]);
        pkt.extend_from_slice(&[0xbb; 6]);
        pkt.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        let ip_start = pkt.len();
        pkt.push(0x45);
        pkt.push(0x00);
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.push(64);
        pkt.push(PROTO_TCP);
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&src_ip);
        pkt.extend_from_slice(&dst_ip);
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&1u32.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes());
        pkt.push(0x50);
        pkt.push(flags);
        pkt.extend_from_slice(&1024u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(payload);
        let total = (pkt.len() - ip_start) as u16;
        let tl = total.to_be_bytes();
        pkt[ip_start + 2] = tl[0];
        pkt[ip_start + 3] = tl[1];
        pkt
    }

    #[test]
    fn track_tcp_handshake() {
        let mut tracker = ConnectionTracker::new();

        // SYN
        let syn = make_tcp_pkt([10, 0, 0, 1], [10, 0, 0, 2], 5000, 80, 0x02, &[]);
        let p = ParsedPacket::parse(&syn).unwrap();
        tracker.track(&p, 100);
        assert_eq!(tracker.flow_count(), 1);

        // SYN-ACK
        let syn_ack = make_tcp_pkt([10, 0, 0, 2], [10, 0, 0, 1], 80, 5000, 0x12, &[]);
        let p = ParsedPacket::parse(&syn_ack).unwrap();
        tracker.track(&p, 101);

        let key = FlowKey::from_packet("10.0.0.1", 5000, "10.0.0.2", 80, FlowProtocol::Tcp);
        let stats = tracker.get(&key).unwrap();
        assert_eq!(stats.packets, 2);
        assert_eq!(stats.tcp_state, TcpFlowState::Established);

        // ACK with data
        let ack = make_tcp_pkt([10, 0, 0, 1], [10, 0, 0, 2], 5000, 80, 0x10, b"hello");
        let p = ParsedPacket::parse(&ack).unwrap();
        tracker.track(&p, 102);

        let stats = tracker.get(&key).unwrap();
        assert_eq!(stats.packets, 3);
        assert_eq!(stats.bytes, 5);
    }

    #[test]
    fn bidirectional_canonical() {
        let k1 = FlowKey::from_packet("10.0.0.1", 5000, "10.0.0.2", 80, FlowProtocol::Tcp);
        let k2 = FlowKey::from_packet("10.0.0.2", 80, "10.0.0.1", 5000, FlowProtocol::Tcp);
        assert_eq!(k1, k2);
    }

    #[test]
    fn expire_old_flows() {
        let mut tracker = ConnectionTracker::new();
        let syn = make_tcp_pkt([10, 0, 0, 1], [10, 0, 0, 2], 5000, 80, 0x02, &[]);
        let p = ParsedPacket::parse(&syn).unwrap();
        tracker.track(&p, 100);
        assert_eq!(tracker.flow_count(), 1);

        let expired = tracker.expire(500, 300);
        assert_eq!(expired, 1);
        assert_eq!(tracker.flow_count(), 0);
    }

    #[test]
    fn top_flows() {
        let mut tracker = ConnectionTracker::new();

        // Flow 1: 100 bytes
        let pkt = make_tcp_pkt([10, 0, 0, 1], [10, 0, 0, 2], 5000, 80, 0x10, &[0u8; 100]);
        let p = ParsedPacket::parse(&pkt).unwrap();
        tracker.track(&p, 100);

        // Flow 2: 50 bytes
        let pkt = make_tcp_pkt([10, 0, 0, 3], [10, 0, 0, 4], 6000, 443, 0x10, &[0u8; 50]);
        let p = ParsedPacket::parse(&pkt).unwrap();
        tracker.track(&p, 100);

        let top = tracker.top_flows_by_bytes(1);
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].1.bytes, 100);
    }

    #[test]
    fn flow_key_display() {
        let key = FlowKey::from_packet("10.0.0.1", 5000, "10.0.0.2", 80, FlowProtocol::Tcp);
        let s = key.to_string();
        assert!(s.contains("TCP"));
        assert!(s.contains("10.0.0.1"));
    }
}
