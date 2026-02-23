//! Lightweight HTTP request/response parser for inspection.
//!
//! Parses only the first line and headers — does **not** handle chunked
//! encoding, content-length bodies, or keep-alive. This is an IDS parser,
//! not a web server.

use std::collections::HashMap;
use std::fmt;

/// Parsed HTTP request (first line + headers).
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub uri: String,
    pub version: String,
    pub headers: HashMap<String, String>,
}

/// Parsed HTTP response (status line + headers).
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub version: String,
    pub status_code: u16,
    pub reason: String,
    pub headers: HashMap<String, String>,
}

/// Either a request or response.
#[derive(Debug, Clone)]
pub enum HttpMessage {
    Request(HttpRequest),
    Response(HttpResponse),
}

impl fmt::Display for HttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.method, self.uri, self.version)
    }
}

impl fmt::Display for HttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.version, self.status_code, self.reason)
    }
}

/// Parse HTTP from a TCP payload. Returns `None` if it doesn't look like HTTP.
pub fn parse_http(data: &[u8]) -> Option<HttpMessage> {
    let text = std::str::from_utf8(data).ok()?;
    let mut lines = text.split("\r\n");
    let first_line = lines.next()?.trim();

    if first_line.is_empty() {
        return None;
    }

    if first_line.starts_with("HTTP/") {
        // Response
        let mut parts = first_line.splitn(3, ' ');
        let version = parts.next()?.to_string();
        let status_code: u16 = parts.next()?.parse().ok()?;
        let reason = parts.next().unwrap_or("").to_string();
        let headers = parse_headers(&mut lines);
        Some(HttpMessage::Response(HttpResponse {
            version,
            status_code,
            reason,
            headers,
        }))
    } else {
        // Request: METHOD URI VERSION
        let mut parts = first_line.splitn(3, ' ');
        let method = parts.next()?.to_string();
        let uri = parts.next()?.to_string();
        let version = parts.next().unwrap_or("HTTP/1.0").to_string();

        // Quick validation: method should be uppercase ASCII
        if !method.chars().all(|c| c.is_ascii_uppercase()) {
            return None;
        }

        let headers = parse_headers(&mut lines);
        Some(HttpMessage::Request(HttpRequest {
            method,
            uri,
            version,
            headers,
        }))
    }
}

fn parse_headers<'a>(lines: &mut impl Iterator<Item = &'a str>) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once(':') {
            headers.insert(key.trim().to_lowercase(), value.trim().to_string());
        }
    }
    headers
}

/// Extract the Host header from an HTTP request payload, if present.
pub fn extract_host(data: &[u8]) -> Option<String> {
    if let Some(HttpMessage::Request(req)) = parse_http(data) {
        req.headers.get("host").cloned()
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_get_request() {
        let raw = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: sentinel\r\n\r\n";
        let msg = parse_http(raw).unwrap();
        match msg {
            HttpMessage::Request(req) => {
                assert_eq!(req.method, "GET");
                assert_eq!(req.uri, "/index.html");
                assert_eq!(req.version, "HTTP/1.1");
                assert_eq!(req.headers.get("host").unwrap(), "example.com");
                assert_eq!(req.headers.get("user-agent").unwrap(), "sentinel");
            }
            _ => panic!("expected request"),
        }
    }

    #[test]
    fn parse_response() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 42\r\n\r\n";
        let msg = parse_http(raw).unwrap();
        match msg {
            HttpMessage::Response(resp) => {
                assert_eq!(resp.status_code, 200);
                assert_eq!(resp.reason, "OK");
                assert_eq!(resp.headers.get("content-type").unwrap(), "text/html");
            }
            _ => panic!("expected response"),
        }
    }

    #[test]
    fn parse_post_request() {
        let raw = b"POST /api/data HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 13\r\n\r\n{\"key\":\"val\"}";
        let msg = parse_http(raw).unwrap();
        match msg {
            HttpMessage::Request(req) => {
                assert_eq!(req.method, "POST");
                assert_eq!(req.uri, "/api/data");
            }
            _ => panic!("expected request"),
        }
    }

    #[test]
    fn not_http() {
        assert!(parse_http(b"\x00\x01\x02binary data").is_none());
    }

    #[test]
    fn extract_host_header() {
        let raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(extract_host(raw), Some("example.com".to_string()));
    }

    #[test]
    fn request_display() {
        let req = HttpRequest {
            method: "GET".into(),
            uri: "/".into(),
            version: "HTTP/1.1".into(),
            headers: HashMap::new(),
        };
        assert_eq!(req.to_string(), "GET / HTTP/1.1");
    }
}
