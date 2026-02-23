//! Zero-copy DNS packet parser.

use crate::packet::ParseError;
use std::fmt;

/// DNS header (12 bytes).
#[derive(Debug, Clone)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: u16,
    pub qd_count: u16,
    pub an_count: u16,
    pub ns_count: u16,
    pub ar_count: u16,
}

impl DnsHeader {
    /// Is this a response (QR bit set)?
    pub fn is_response(&self) -> bool {
        self.flags & 0x8000 != 0
    }

    /// Opcode (4 bits).
    pub fn opcode(&self) -> u8 {
        ((self.flags >> 11) & 0x0F) as u8
    }

    /// Response code (4 bits).
    pub fn rcode(&self) -> u8 {
        (self.flags & 0x000F) as u8
    }

    /// Recursion desired.
    pub fn rd(&self) -> bool {
        self.flags & 0x0100 != 0
    }

    /// Recursion available.
    pub fn ra(&self) -> bool {
        self.flags & 0x0080 != 0
    }
}

/// DNS record type constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRecordType {
    A,
    AAAA,
    CNAME,
    MX,
    NS,
    TXT,
    SOA,
    PTR,
    SRV,
    AXFR,
    Unknown(u16),
}

impl From<u16> for DnsRecordType {
    fn from(v: u16) -> Self {
        match v {
            1 => Self::A,
            28 => Self::AAAA,
            5 => Self::CNAME,
            15 => Self::MX,
            2 => Self::NS,
            16 => Self::TXT,
            6 => Self::SOA,
            12 => Self::PTR,
            33 => Self::SRV,
            252 => Self::AXFR,
            _ => Self::Unknown(v),
        }
    }
}

impl fmt::Display for DnsRecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::A => write!(f, "A"),
            Self::AAAA => write!(f, "AAAA"),
            Self::CNAME => write!(f, "CNAME"),
            Self::MX => write!(f, "MX"),
            Self::NS => write!(f, "NS"),
            Self::TXT => write!(f, "TXT"),
            Self::SOA => write!(f, "SOA"),
            Self::PTR => write!(f, "PTR"),
            Self::SRV => write!(f, "SRV"),
            Self::AXFR => write!(f, "AXFR"),
            Self::Unknown(v) => write!(f, "TYPE{v}"),
        }
    }
}

/// A DNS question entry.
#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: DnsRecordType,
    pub qclass: u16,
}

/// A DNS resource record.
#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: DnsRecordType,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

impl DnsRecord {
    /// If this is an A record, return the IPv4 address.
    pub fn as_ipv4(&self) -> Option<std::net::Ipv4Addr> {
        if matches!(self.rtype, DnsRecordType::A) && self.rdata.len() == 4 {
            Some(std::net::Ipv4Addr::new(
                self.rdata[0],
                self.rdata[1],
                self.rdata[2],
                self.rdata[3],
            ))
        } else {
            None
        }
    }
}

/// A fully parsed DNS message.
#[derive(Debug, Clone)]
pub struct DnsMessage {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
}

impl DnsMessage {
    /// Parse a DNS message from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < 12 {
            return Err(ParseError::TooShort {
                layer: "DNS",
                need: 12,
                got: data.len(),
            });
        }

        let header = DnsHeader {
            id: u16::from_be_bytes([data[0], data[1]]),
            flags: u16::from_be_bytes([data[2], data[3]]),
            qd_count: u16::from_be_bytes([data[4], data[5]]),
            an_count: u16::from_be_bytes([data[6], data[7]]),
            ns_count: u16::from_be_bytes([data[8], data[9]]),
            ar_count: u16::from_be_bytes([data[10], data[11]]),
        };

        let mut offset = 12;
        let mut questions = Vec::with_capacity(header.qd_count as usize);
        for _ in 0..header.qd_count {
            let (name, new_offset) = parse_name(data, offset)?;
            offset = new_offset;
            if offset + 4 > data.len() {
                return Err(ParseError::TooShort {
                    layer: "DNS question",
                    need: offset + 4,
                    got: data.len(),
                });
            }
            let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let qclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            offset += 4;
            questions.push(DnsQuestion {
                name,
                qtype: DnsRecordType::from(qtype),
                qclass,
            });
        }

        let mut answers = Vec::with_capacity(header.an_count as usize);
        for _ in 0..header.an_count {
            let (name, new_offset) = parse_name(data, offset)?;
            offset = new_offset;
            if offset + 10 > data.len() {
                return Err(ParseError::TooShort {
                    layer: "DNS answer",
                    need: offset + 10,
                    got: data.len(),
                });
            }
            let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let rclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            let ttl = u32::from_be_bytes([
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]);
            let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
            offset += 10;
            if offset + rdlength > data.len() {
                return Err(ParseError::TooShort {
                    layer: "DNS rdata",
                    need: offset + rdlength,
                    got: data.len(),
                });
            }
            let rdata = data[offset..offset + rdlength].to_vec();
            offset += rdlength;
            answers.push(DnsRecord {
                name,
                rtype: DnsRecordType::from(rtype),
                rclass,
                ttl,
                rdata,
            });
        }

        Ok(Self {
            header,
            questions,
            answers,
        })
    }
}

/// Parse a DNS name with pointer compression support.
fn parse_name(data: &[u8], mut offset: usize) -> Result<(String, usize), ParseError> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut return_offset = 0;
    let mut hops = 0;

    loop {
        if offset >= data.len() {
            return Err(ParseError::TooShort {
                layer: "DNS name",
                need: offset + 1,
                got: data.len(),
            });
        }

        let len = data[offset] as usize;

        if len == 0 {
            if !jumped {
                return_offset = offset + 1;
            }
            break;
        }

        // Pointer compression
        if len & 0xC0 == 0xC0 {
            if offset + 1 >= data.len() {
                return Err(ParseError::TooShort {
                    layer: "DNS pointer",
                    need: offset + 2,
                    got: data.len(),
                });
            }
            if !jumped {
                return_offset = offset + 2;
            }
            offset = ((len & 0x3F) << 8) | data[offset + 1] as usize;
            jumped = true;
            hops += 1;
            if hops > 64 {
                return Err(ParseError::InvalidHeaderLen {
                    layer: "DNS name",
                    value: hops,
                });
            }
            continue;
        }

        offset += 1;
        if offset + len > data.len() {
            return Err(ParseError::TooShort {
                layer: "DNS label",
                need: offset + len,
                got: data.len(),
            });
        }
        labels.push(String::from_utf8_lossy(&data[offset..offset + len]).to_string());
        offset += len;
    }

    let name = if labels.is_empty() {
        ".".to_string()
    } else {
        labels.join(".")
    };

    Ok((name, return_offset))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal DNS query for "example.com" type A.
    fn make_dns_query() -> Vec<u8> {
        let mut pkt = Vec::new();
        // Header
        pkt.extend_from_slice(&0x1234u16.to_be_bytes()); // ID
        pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD=1
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QD count
        pkt.extend_from_slice(&0u16.to_be_bytes()); // AN
        pkt.extend_from_slice(&0u16.to_be_bytes()); // NS
        pkt.extend_from_slice(&0u16.to_be_bytes()); // AR
                                                    // Question: example.com type A class IN
        pkt.push(7);
        pkt.extend_from_slice(b"example");
        pkt.push(3);
        pkt.extend_from_slice(b"com");
        pkt.push(0); // end
        pkt.extend_from_slice(&1u16.to_be_bytes()); // type A
        pkt.extend_from_slice(&1u16.to_be_bytes()); // class IN
        pkt
    }

    /// Build a DNS response with one A record.
    fn make_dns_response() -> Vec<u8> {
        let mut pkt = Vec::new();
        // Header
        pkt.extend_from_slice(&0x1234u16.to_be_bytes());
        pkt.extend_from_slice(&0x8180u16.to_be_bytes()); // QR=1, RD=1, RA=1
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QD
        pkt.extend_from_slice(&1u16.to_be_bytes()); // AN
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        // Question
        pkt.push(7);
        pkt.extend_from_slice(b"example");
        pkt.push(3);
        pkt.extend_from_slice(b"com");
        pkt.push(0);
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        // Answer: pointer to offset 12 (the question name)
        pkt.extend_from_slice(&[0xC0, 0x0C]); // pointer
        pkt.extend_from_slice(&1u16.to_be_bytes()); // type A
        pkt.extend_from_slice(&1u16.to_be_bytes()); // class IN
        pkt.extend_from_slice(&300u32.to_be_bytes()); // TTL
        pkt.extend_from_slice(&4u16.to_be_bytes()); // rdlength
        pkt.extend_from_slice(&[93, 184, 216, 34]); // 93.184.216.34
        pkt
    }

    #[test]
    fn parse_query() {
        let data = make_dns_query();
        let msg = DnsMessage::parse(&data).unwrap();
        assert_eq!(msg.header.id, 0x1234);
        assert!(!msg.header.is_response());
        assert!(msg.header.rd());
        assert_eq!(msg.questions.len(), 1);
        assert_eq!(msg.questions[0].name, "example.com");
        assert_eq!(msg.questions[0].qtype, DnsRecordType::A);
        assert!(msg.answers.is_empty());
    }

    #[test]
    fn parse_response_with_pointer() {
        let data = make_dns_response();
        let msg = DnsMessage::parse(&data).unwrap();
        assert!(msg.header.is_response());
        assert!(msg.header.ra());
        assert_eq!(msg.answers.len(), 1);
        assert_eq!(msg.answers[0].name, "example.com");
        assert_eq!(msg.answers[0].ttl, 300);
        assert_eq!(
            msg.answers[0].as_ipv4(),
            Some(std::net::Ipv4Addr::new(93, 184, 216, 34))
        );
    }

    #[test]
    fn too_short_dns() {
        assert!(DnsMessage::parse(&[0; 5]).is_err());
    }

    #[test]
    fn record_type_display() {
        assert_eq!(DnsRecordType::A.to_string(), "A");
        assert_eq!(DnsRecordType::AXFR.to_string(), "AXFR");
        assert_eq!(DnsRecordType::Unknown(999).to_string(), "TYPE999");
    }
}
