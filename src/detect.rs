//! Detection engine — matches packets against rules with Aho-Corasick multi-pattern.

use aho_corasick::AhoCorasick;

use crate::alert::{Alert, AlertSeverity};
use crate::packet::{ParsedPacket, TransportLayer};
use crate::rule::{Protocol, Rule};

/// Pre-compiled rule engine with Aho-Corasick for fast content matching.
pub struct DetectionEngine {
    rules: Vec<Rule>,
    /// Aho-Corasick automaton for rules that have content patterns.
    /// Each pattern index maps to the corresponding index in `content_rule_indices`.
    content_ac: Option<AhoCorasick>,
    /// Maps AC pattern index → rules index.
    content_rule_indices: Vec<usize>,
}

impl DetectionEngine {
    /// Build a detection engine from a set of rules.
    pub fn new(rules: Vec<Rule>) -> Self {
        let mut patterns = Vec::new();
        let mut content_rule_indices = Vec::new();

        for (i, rule) in rules.iter().enumerate() {
            if let Some(ref content) = rule.content {
                if rule.enabled && !content.is_empty() {
                    patterns.push(content.as_bytes().to_vec());
                    content_rule_indices.push(i);
                }
            }
        }

        let content_ac = if patterns.is_empty() {
            None
        } else {
            Some(AhoCorasick::new(&patterns).expect("failed to build Aho-Corasick automaton"))
        };

        Self {
            rules,
            content_ac,
            content_rule_indices,
        }
    }

    /// Check a parsed packet against all rules. Returns all matching alerts.
    pub fn check(&self, packet: &ParsedPacket<'_>) -> Vec<Alert> {
        let mut alerts = Vec::new();
        let payload = transport_payload(packet);

        // Pre-compute which content rules match via Aho-Corasick
        let mut content_matched: Vec<bool> = vec![false; self.rules.len()];
        if let Some(ref ac) = self.content_ac {
            for mat in ac.find_overlapping_iter(payload) {
                let rule_idx = self.content_rule_indices[mat.pattern().as_usize()];
                content_matched[rule_idx] = true;
            }
        }

        for (i, rule) in self.rules.iter().enumerate() {
            if !rule.enabled {
                continue;
            }
            if self.matches_rule(packet, rule, i, &content_matched) {
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

    fn matches_rule(
        &self,
        packet: &ParsedPacket<'_>,
        rule: &Rule,
        rule_idx: usize,
        content_matched: &[bool],
    ) -> bool {
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

        // Content check via pre-computed Aho-Corasick results
        if rule.content.is_some() && !content_matched[rule_idx] {
            return false;
        }

        true
    }

    /// Access the underlying rules.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }
}

/// Legacy function for simple checks (delegates to DetectionEngine).
pub fn check_packet(packet: &ParsedPacket<'_>, rules: &[Rule]) -> Vec<Alert> {
    let engine = DetectionEngine::new(rules.to_vec());
    engine.check(packet)
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

    fn make_tcp_with_payload(payload: &[u8]) -> Vec<u8> {
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
        pkt.extend_from_slice(&[10, 0, 0, 1]);
        pkt.extend_from_slice(&[10, 0, 0, 2]);
        pkt.extend_from_slice(&5000u16.to_be_bytes());
        pkt.extend_from_slice(&80u16.to_be_bytes());
        pkt.extend_from_slice(&1u32.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes());
        pkt.push(0x50);
        pkt.push(0x18); // PSH+ACK
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
        let engine = DetectionEngine::new(rules);
        let raw = make_tcp_syn_packet();
        let packet = ParsedPacket::parse(&raw).unwrap();
        let alerts = engine.check(&packet);
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
        let engine = DetectionEngine::new(rules);
        let raw = make_tcp_syn_packet();
        let packet = ParsedPacket::parse(&raw).unwrap();
        let alerts = engine.check(&packet);
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
        let engine = DetectionEngine::new(rules);
        let raw = make_tcp_syn_packet();
        let packet = ParsedPacket::parse(&raw).unwrap();
        let alerts = engine.check(&packet);
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
        let engine = DetectionEngine::new(rules);
        let raw = make_tcp_syn_packet();
        let packet = ParsedPacket::parse(&raw).unwrap();
        let alerts = engine.check(&packet);
        assert_eq!(alerts.len(), 1);
    }

    #[test]
    fn aho_corasick_content_match() {
        let rules_str = r#"
[[rule]]
id = "SID-2001"
name = "Malicious pattern"
severity = "critical"
category = "malware"
protocol = "tcp"
content = "EVIL_PAYLOAD"

[[rule]]
id = "SID-2002"
name = "Admin access"
severity = "medium"
category = "policy"
protocol = "tcp"
content = "/admin"
dst_port = 80
"#;
        let rules = load_rules_str(rules_str).unwrap();
        let engine = DetectionEngine::new(rules);

        // Packet with EVIL_PAYLOAD
        let raw = make_tcp_with_payload(b"GET /page HTTP/1.1\r\nX: EVIL_PAYLOAD here");
        let packet = ParsedPacket::parse(&raw).unwrap();
        let alerts = engine.check(&packet);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id, "SID-2001");

        // Packet with /admin on port 80
        let raw = make_tcp_with_payload(b"GET /admin HTTP/1.1\r\nHost: test\r\n\r\n");
        let packet = ParsedPacket::parse(&raw).unwrap();
        let alerts = engine.check(&packet);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id, "SID-2002");

        // Packet with no matching content
        let raw = make_tcp_with_payload(b"GET /index.html HTTP/1.1\r\n\r\n");
        let packet = ParsedPacket::parse(&raw).unwrap();
        let alerts = engine.check(&packet);
        assert!(alerts.is_empty());
    }

    #[test]
    fn multiple_content_rules_match() {
        let rules_str = r#"
[[rule]]
id = "SID-3001"
name = "Pattern A"
severity = "low"
category = "policy"
protocol = "tcp"
content = "foo"

[[rule]]
id = "SID-3002"
name = "Pattern B"
severity = "low"
category = "policy"
protocol = "tcp"
content = "bar"
"#;
        let rules = load_rules_str(rules_str).unwrap();
        let engine = DetectionEngine::new(rules);
        let raw = make_tcp_with_payload(b"this has foo and bar in it");
        let packet = ParsedPacket::parse(&raw).unwrap();
        let alerts = engine.check(&packet);
        assert_eq!(alerts.len(), 2);
    }

    #[test]
    fn legacy_check_packet() {
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
    }
}
