//! Alert types and colored console output.

use colored::Colorize;
use std::fmt;

use crate::rule::Severity;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl From<&Severity> for AlertSeverity {
    fn from(s: &Severity) -> Self {
        match s {
            Severity::Low => Self::Low,
            Severity::Medium => Self::Medium,
            Severity::High => Self::High,
            Severity::Critical => Self::Critical,
        }
    }
}

impl fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Alert {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: AlertSeverity,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub message: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl Alert {
    /// Format the alert with terminal colors.
    pub fn colored_string(&self) -> String {
        let severity_str = match self.severity {
            AlertSeverity::Low => self.severity.to_string().blue().to_string(),
            AlertSeverity::Medium => self.severity.to_string().yellow().to_string(),
            AlertSeverity::High => self.severity.to_string().red().to_string(),
            AlertSeverity::Critical => self.severity.to_string().red().bold().to_string(),
        };

        let src = format_endpoint(&self.src_ip, self.src_port);
        let dst = format_endpoint(&self.dst_ip, self.dst_port);

        format!(
            "[{ts}] [{severity}] {id} {src} → {dst} | {msg}",
            ts = self.timestamp.format("%H:%M:%S"),
            severity = severity_str,
            id = self.rule_id.bold(),
            src = src,
            dst = dst,
            msg = self.message,
        )
    }

    /// Serialize the alert as a JSON string.
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"timestamp":"{}","rule_id":"{}","rule_name":"{}","severity":"{}","src":"{}","dst":"{}","message":"{}"}}"#,
            self.timestamp.to_rfc3339(),
            self.rule_id,
            self.rule_name,
            self.severity,
            format_endpoint(&self.src_ip, self.src_port),
            format_endpoint(&self.dst_ip, self.dst_port),
            self.message,
        )
    }
}

impl fmt::Display for Alert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] [{}] {} {} → {} | {}",
            self.timestamp.format("%H:%M:%S"),
            self.severity,
            self.rule_id,
            format_endpoint(&self.src_ip, self.src_port),
            format_endpoint(&self.dst_ip, self.dst_port),
            self.message,
        )
    }
}

fn format_endpoint(ip: &str, port: Option<u16>) -> String {
    match port {
        Some(p) => format!("{ip}:{p}"),
        None => ip.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_alert() -> Alert {
        Alert {
            rule_id: "SID-1001".to_string(),
            rule_name: "Test".to_string(),
            severity: AlertSeverity::High,
            src_ip: "192.168.1.1".to_string(),
            dst_ip: "10.0.0.1".to_string(),
            src_port: Some(12345),
            dst_port: Some(80),
            message: "Test alert".to_string(),
            timestamp: chrono::Utc::now(),
        }
    }

    #[test]
    fn alert_display() {
        let a = sample_alert();
        let s = a.to_string();
        assert!(s.contains("SID-1001"));
        assert!(s.contains("192.168.1.1:12345"));
        assert!(s.contains("10.0.0.1:80"));
    }

    #[test]
    fn alert_json() {
        let a = sample_alert();
        let j = a.to_json();
        assert!(j.contains("\"rule_id\":\"SID-1001\""));
        assert!(j.contains("\"severity\":\"HIGH\""));
    }

    #[test]
    fn alert_colored() {
        let a = sample_alert();
        // Just ensure it doesn't panic
        let _s = a.colored_string();
    }

    #[test]
    fn severity_from_rule() {
        assert_eq!(
            AlertSeverity::from(&Severity::Critical),
            AlertSeverity::Critical
        );
    }
}
