//! Detection engine — matches packets against rules.

use crate::alert::{Alert, AlertSeverity};
use crate::packet::{ParsedPacket, TransportLayer};
use crate::rule::{Protocol, Rule};

/// Check a parsed packet against a set of rules. Returns all matching alerts.
pub fn check_packet(packet: &ParsedPacket<'_>, rules: &[Rule]) -> Vec<Alert> {
    let mut alerts = Vec::new();
    for rule in rules {
        if !rule.enabled {
            continue;
        }
        if matches_rule(packet, rule) {
            alerts.push(Alert {
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                severity: AlertSeverity::from(&rule.severity),
                src_ip: packet.src_ip().unwrap_or_default(),
                dst_ip: packet.dst_ip().unwrap_or_default(),
                src_port: packet.src_port(),
                dst_port: packet.dst_port(),
                message: format!("Rule {} triggered: {}", rule.id, rule.name),
                timestamp: chrono::Utc::now(),
            });
        }
    }
    alerts
}

fn matches_rule(packet: &ParsedPacket<'_>, rule: &Rule) -> bool {
    // Protocol check
    if !matches_protocol(packet, &rule.protocol) {
        return false;
    }

    // IP checks
    if rule.src_ip != "any" {
        if let Some(src) = packet.src_ip() {
            if !ip_matches(&src, &rule.src_ip) {
                return false;
            }
        } else {
            return false;
        }
    }
    if rule.dst_ip != "any" {
        if let Some(dst) = packet.dst_ip() {
            if !ip_matches(&dst, &rule.dst_ip) {
                return false;
            }
        } else {
            return false;
        }
    }

    // Port check
    if rule.dst_port != 0 && packet.dst_port() != Some(rule.dst_port) {
        return false;
    }

    // TCP flags check
    if let Some(ref flag_str) = rule.tcp_flags {
        match &packet.transport {
            Some(TransportLayer::Tcp(tcp)) => {
                if !flags_match(&tcp.flags, flag_str) {
                    return false;
                }
            }
            _ => return false,
        }
    }

    // Content check
    if let Some(ref content) = rule.content {
        let payload = transport_payload(packet);
        if !payload
            .windows(content.len())
            .any(|w| w == content.as_bytes())
        {
            return false;
        }
    }

    true
}

fn matches_protocol(packet: &ParsedPacket<'_>, proto: &Protocol) -> bool {
    match proto {
        Protocol::Any => true,
        Protocol::Tcp => matches!(&packet.transport, Some(TransportLayer::Tcp(_))),
        Protocol::Udp => matches!(&packet.transport, Some(TransportLayer::Udp(_))),
        Protocol::Icmp => matches!(&packet.transport, Some(TransportLayer::Icmp(_))),
    }
}

fn ip_matches(actual: &str, pattern: &str) -> bool {
    // Simple exact match for now; CIDR support in future
    actual == pattern
}

fn flags_match(flags: &crate::packet::TcpFlags, pattern: &str) -> bool {
    for ch in pattern.chars() {
        match ch {
            'S' => {
                if !flags.syn() {
                    return false;
                }
            }
            'A' => {
                if !flags.ack() {
                    return false;
                }
            }
            'F' => {
                if !flags.fin() {
                    return false;
                }
            }
            'R' => {
                if !flags.rst() {
                    return false;
                }
            }
            'P' => {
                if !flags.psh() {
                    return false;
                }
            }
            'U' => {
                if !flags.urg() {
                    return false;
                }
            }
            _ => {}
        }
    }
    true
}

fn transport_payload<'a>(packet: &'a ParsedPacket<'_>) -> &'a [u8] {
    match &packet.transport {
        Some(TransportLayer::Tcp(t)) => t.payload,
        Some(TransportLayer::Udp(u)) => u.payload,
        Some(TransportLayer::Icmp(i)) => i.payload,
        None => &[],
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::*;
    use crate::rule::*;

    fn make_tcp_syn_packet() -> Vec<u8> {
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
        pkt.extend_from_slice(&[192, 168, 1, 100]);
        pkt.extend_from_slice(&[10, 0, 0, 1]);
        // TCP SYN
        pkt.extend_from_slice(&12345u16.to_be_bytes());
        pkt.extend_from_slice(&80u16.to_be_bytes());
        pkt.extend_from_slice(&1u32.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes());
        pkt.push(0x50);
        pkt.push(0x02); // SYN
        pkt.extend_from_slice(&1024u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        let total = (pkt.len() - ip_start) as u16;
        let tl = total.to_be_bytes();
        pkt[ip_start + 2] = tl[0];
        pkt[ip_start + 3] = tl[1];
        pkt
    }

    #[test]
    fn syn_scan_rule_matches() {
        let rules_str = r#"
[[rule]]
id = "SID-1001"
name = "SYN scan"
severity = "high"
category = "scan"
protocol = "tcp"
tcp_flags = "S"
"#;
        let rules = load_rules_str(rules_str).unwrap();
        let raw = make_tcp_syn_packet();
        let packet = ParsedPacket::parse(&raw).unwrap();
        let alerts = check_packet(&packet, &rules);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id, "SID-1001");
    }

    #[test]
    fn disabled_rule_skipped() {
        let rules_str = r#"
[[rule]]
id = "SID-1001"
name = "SYN scan"
severity = "high"
category = "scan"
protocol = "tcp"
tcp_flags = "S"
enabled = false
"#;
        let rules = load_rules_str(rules_str).unwrap();
        let raw = make_tcp_syn_packet();
        let packet = ParsedPacket::parse(&raw).unwrap();
        let alerts = check_packet(&packet, &rules);
        assert!(alerts.is_empty());
    }

    #[test]
    fn wrong_protocol_no_match() {
        let rules_str = r#"
[[rule]]
id = "SID-1002"
name = "UDP test"
severity = "low"
category = "policy"
protocol = "udp"
"#;
        let rules = load_rules_str(rules_str).unwrap();
        let raw = make_tcp_syn_packet();
        let packet = ParsedPacket::parse(&raw).unwrap();
        let alerts = check_packet(&packet, &rules);
        assert!(alerts.is_empty());
    }

    #[test]
    fn port_match() {
        let rules_str = r#"
[[rule]]
id = "SID-1003"
name = "HTTP traffic"
severity = "low"
category = "policy"
protocol = "tcp"
dst_port = 80
"#;
        let rules = load_rules_str(rules_str).unwrap();
        let raw = make_tcp_syn_packet();
        let packet = ParsedPacket::parse(&raw).unwrap();
        let alerts = check_packet(&packet, &rules);
        assert_eq!(alerts.len(), 1);
    }
}
