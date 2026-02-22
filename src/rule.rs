//! TOML-based detection rule format.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Scan,
    Exploit,
    Malware,
    Policy,
    Anomaly,
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scan => write!(f, "scan"),
            Self::Exploit => write!(f, "exploit"),
            Self::Malware => write!(f, "malware"),
            Self::Policy => write!(f, "policy"),
            Self::Anomaly => write!(f, "anomaly"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Any,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Unique rule identifier (e.g. "SID-1001").
    pub id: String,
    /// Human-readable description.
    pub name: String,
    /// Severity level.
    pub severity: Severity,
    /// Rule category.
    pub category: Category,
    /// Protocol to match.
    #[serde(default = "default_protocol")]
    pub protocol: Protocol,
    /// Source IP pattern (CIDR or "any").
    #[serde(default = "default_any")]
    pub src_ip: String,
    /// Destination IP pattern (CIDR or "any").
    #[serde(default = "default_any")]
    pub dst_ip: String,
    /// Destination port (0 = any).
    #[serde(default)]
    pub dst_port: u16,
    /// Content pattern to search in payload.
    #[serde(default)]
    pub content: Option<String>,
    /// TCP flags to match (e.g. "S", "SA", "F").
    #[serde(default)]
    pub tcp_flags: Option<String>,
    /// Whether the rule is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_protocol() -> Protocol {
    Protocol::Any
}
fn default_any() -> String {
    "any".to_string()
}
fn default_true() -> bool {
    true
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = if self.enabled { "✓" } else { "✗" };
        write!(
            f,
            "[{status}] {id} [{severity}/{category}] {name}",
            id = self.id,
            severity = self.severity,
            category = self.category,
            name = self.name,
        )
    }
}

#[derive(Debug, Deserialize)]
struct RuleFile {
    #[serde(rename = "rule", default)]
    rules: Vec<Rule>,
}

/// Load rules from a TOML file.
pub fn load_rules_file(path: &Path) -> Result<Vec<Rule>, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    load_rules_str(&content)
}

/// Parse rules from a TOML string.
pub fn load_rules_str(content: &str) -> Result<Vec<Rule>, String> {
    let rf: RuleFile = toml::from_str(content).map_err(|e| format!("parse error: {e}"))?;
    Ok(rf.rules)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_RULES: &str = r#"
[[rule]]
id = "SID-1001"
name = "SYN scan detected"
severity = "high"
category = "scan"
protocol = "tcp"
tcp_flags = "S"

[[rule]]
id = "SID-1002"
name = "DNS zone transfer"
severity = "medium"
category = "policy"
protocol = "tcp"
dst_port = 53
content = "AXFR"
"#;

    #[test]
    fn parse_rules() {
        let rules = load_rules_str(SAMPLE_RULES).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].id, "SID-1001");
        assert_eq!(rules[0].severity, Severity::High);
        assert_eq!(rules[0].category, Category::Scan);
        assert!(rules[0].enabled);
        assert_eq!(rules[1].dst_port, 53);
        assert_eq!(rules[1].content.as_deref(), Some("AXFR"));
    }

    #[test]
    fn empty_rules_file() {
        let rules = load_rules_str("").unwrap();
        assert!(rules.is_empty());
    }

    #[test]
    fn rule_display() {
        let rules = load_rules_str(SAMPLE_RULES).unwrap();
        let s = rules[0].to_string();
        assert!(s.contains("SID-1001"));
        assert!(s.contains("high"));
    }

    #[test]
    fn invalid_toml() {
        let result = load_rules_str("not valid { toml");
        assert!(result.is_err());
    }
}
