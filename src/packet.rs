//! Zero-copy packet parsing for Ethernet, IPv4, IPv6, TCP, UDP, ICMP, ARP.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    TooShort {
        layer: &'static str,
        need: usize,
        got: usize,
    },
    UnsupportedEtherType(u16),
    UnsupportedIpVersion(u8),
    InvalidHeaderLen {
        layer: &'static str,
        value: usize,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { layer, need, got } => {
                write!(f, "{layer}: need {need} bytes, got {got}")
            }
            Self::UnsupportedEtherType(t) => write!(f, "unsupported EtherType: 0x{t:04x}"),
            Self::UnsupportedIpVersion(v) => write!(f, "unsupported IP version: {v}"),
            Self::InvalidHeaderLen { layer, value } => {
                write!(f, "{layer}: invalid header length {value}")
            }
        }
    }
}

impl std::error::Error for ParseError {}

// ---------------------------------------------------------------------------
// MAC address helper
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacAddr(pub [u8; 6]);

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let m = &self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            m[0], m[1], m[2], m[3], m[4], m[5]
        )
    }
}

// ---------------------------------------------------------------------------
// Ethernet
// ---------------------------------------------------------------------------

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_IPV6: u16 = 0x86DD;
pub const ETHERTYPE_ARP: u16 = 0x0806;

#[derive(Debug, Clone)]
pub struct EthernetFrame<'a> {
    pub dst: MacAddr,
    pub src: MacAddr,
    pub ethertype: u16,
    pub payload: &'a [u8],
}

impl<'a> EthernetFrame<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        if data.len() < 14 {
            return Err(ParseError::TooShort {
                layer: "Ethernet",
                need: 14,
                got: data.len(),
            });
        }
        let dst = MacAddr(data[0..6].try_into().unwrap());
        let src = MacAddr(data[6..12].try_into().unwrap());
        let ethertype = u16::from_be_bytes([data[12], data[13]]);
        Ok(Self {
            dst,
            src,
            ethertype,
            payload: &data[14..],
        })
    }
}

// ---------------------------------------------------------------------------
// IPv4
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Ipv4Packet<'a> {
    pub version: u8,
    pub ihl: u8,
    pub dscp: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub payload: &'a [u8],
}

impl<'a> Ipv4Packet<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        if data.len() < 20 {
            return Err(ParseError::TooShort {
                layer: "IPv4",
                need: 20,
                got: data.len(),
            });
        }
        let version = data[0] >> 4;
        if version != 4 {
            return Err(ParseError::UnsupportedIpVersion(version));
        }
        let ihl = (data[0] & 0x0F) as usize;
        let header_len = ihl * 4;
        if header_len < 20 || data.len() < header_len {
            return Err(ParseError::InvalidHeaderLen {
                layer: "IPv4",
                value: header_len,
            });
        }
        let total_length = u16::from_be_bytes([data[2], data[3]]);
        let identification = u16::from_be_bytes([data[4], data[5]]);
        let flags_frag = u16::from_be_bytes([data[6], data[7]]);
        let flags = (flags_frag >> 13) as u8;
        let fragment_offset = flags_frag & 0x1FFF;
        let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let dst = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

        let payload_end = std::cmp::min(total_length as usize, data.len());
        let payload = if header_len <= payload_end {
            &data[header_len..payload_end]
        } else {
            &[]
        };

        Ok(Self {
            version,
            ihl: ihl as u8,
            dscp: data[1] >> 2,
            total_length,
            identification,
            flags,
            fragment_offset,
            ttl: data[8],
            protocol: data[9],
            checksum: u16::from_be_bytes([data[10], data[11]]),
            src,
            dst,
            payload,
        })
    }
}

// ---------------------------------------------------------------------------
// IPv6
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Ipv6Packet<'a> {
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub payload: &'a [u8],
}

impl<'a> Ipv6Packet<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        if data.len() < 40 {
            return Err(ParseError::TooShort {
                layer: "IPv6",
                need: 40,
                got: data.len(),
            });
        }
        let version = data[0] >> 4;
        if version != 6 {
            return Err(ParseError::UnsupportedIpVersion(version));
        }
        let traffic_class = ((data[0] & 0x0F) << 4) | (data[1] >> 4);
        let flow_label = ((data[1] as u32 & 0x0F) << 16) | ((data[2] as u32) << 8) | data[3] as u32;
        let payload_length = u16::from_be_bytes([data[4], data[5]]);
        let next_header = data[6];
        let hop_limit = data[7];
        let src = Ipv6Addr::from(<[u8; 16]>::try_from(&data[8..24]).unwrap());
        let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&data[24..40]).unwrap());
        let end = std::cmp::min(40 + payload_length as usize, data.len());
        Ok(Self {
            traffic_class,
            flow_label,
            payload_length,
            next_header,
            hop_limit,
            src,
            dst,
            payload: &data[40..end],
        })
    }
}

// ---------------------------------------------------------------------------
// TCP
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct TcpSegment<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub data_offset: u8,
    pub flags: TcpFlags,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpFlags(pub u8);

impl TcpFlags {
    pub fn fin(self) -> bool {
        self.0 & 0x01 != 0
    }
    pub fn syn(self) -> bool {
        self.0 & 0x02 != 0
    }
    pub fn rst(self) -> bool {
        self.0 & 0x04 != 0
    }
    pub fn psh(self) -> bool {
        self.0 & 0x08 != 0
    }
    pub fn ack(self) -> bool {
        self.0 & 0x10 != 0
    }
    pub fn urg(self) -> bool {
        self.0 & 0x20 != 0
    }
}

impl fmt::Display for TcpFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.syn() {
            write!(f, "S")?;
        }
        if self.ack() {
            write!(f, "A")?;
        }
        if self.fin() {
            write!(f, "F")?;
        }
        if self.rst() {
            write!(f, "R")?;
        }
        if self.psh() {
            write!(f, "P")?;
        }
        if self.urg() {
            write!(f, "U")?;
        }
        Ok(())
    }
}

impl<'a> TcpSegment<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        if data.len() < 20 {
            return Err(ParseError::TooShort {
                layer: "TCP",
                need: 20,
                got: data.len(),
            });
        }
        let data_offset = ((data[12] >> 4) as usize) * 4;
        if data_offset < 20 || data.len() < data_offset {
            return Err(ParseError::InvalidHeaderLen {
                layer: "TCP",
                value: data_offset,
            });
        }
        Ok(Self {
            src_port: u16::from_be_bytes([data[0], data[1]]),
            dst_port: u16::from_be_bytes([data[2], data[3]]),
            seq: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            ack: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            data_offset: data_offset as u8,
            flags: TcpFlags(data[13]),
            window: u16::from_be_bytes([data[14], data[15]]),
            checksum: u16::from_be_bytes([data[16], data[17]]),
            urgent_ptr: u16::from_be_bytes([data[18], data[19]]),
            payload: &data[data_offset..],
        })
    }
}

// ---------------------------------------------------------------------------
// UDP
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct UdpDatagram<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub payload: &'a [u8],
}

impl<'a> UdpDatagram<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        if data.len() < 8 {
            return Err(ParseError::TooShort {
                layer: "UDP",
                need: 8,
                got: data.len(),
            });
        }
        let length = u16::from_be_bytes([data[4], data[5]]);
        let end = std::cmp::min(length as usize, data.len());
        Ok(Self {
            src_port: u16::from_be_bytes([data[0], data[1]]),
            dst_port: u16::from_be_bytes([data[2], data[3]]),
            length,
            checksum: u16::from_be_bytes([data[6], data[7]]),
            payload: &data[8..end],
        })
    }
}

// ---------------------------------------------------------------------------
// ICMP
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct IcmpPacket<'a> {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub payload: &'a [u8],
}

impl<'a> IcmpPacket<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        if data.len() < 4 {
            return Err(ParseError::TooShort {
                layer: "ICMP",
                need: 4,
                got: data.len(),
            });
        }
        Ok(Self {
            icmp_type: data[0],
            code: data[1],
            checksum: u16::from_be_bytes([data[2], data[3]]),
            payload: &data[4..],
        })
    }
}

// ---------------------------------------------------------------------------
// ARP
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ArpPacket {
    pub hw_type: u16,
    pub proto_type: u16,
    pub operation: u16,
    pub sender_mac: MacAddr,
    pub sender_ip: Ipv4Addr,
    pub target_mac: MacAddr,
    pub target_ip: Ipv4Addr,
}

impl ArpPacket {
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < 28 {
            return Err(ParseError::TooShort {
                layer: "ARP",
                need: 28,
                got: data.len(),
            });
        }
        Ok(Self {
            hw_type: u16::from_be_bytes([data[0], data[1]]),
            proto_type: u16::from_be_bytes([data[2], data[3]]),
            operation: u16::from_be_bytes([data[6], data[7]]),
            sender_mac: MacAddr(data[8..14].try_into().unwrap()),
            sender_ip: Ipv4Addr::new(data[14], data[15], data[16], data[17]),
            target_mac: MacAddr(data[18..24].try_into().unwrap()),
            target_ip: Ipv4Addr::new(data[24], data[25], data[26], data[27]),
        })
    }
}

// ---------------------------------------------------------------------------
// Top-level parsed packet
// ---------------------------------------------------------------------------

/// Protocol number constants (IP header `protocol` field).
pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

/// A fully-parsed packet with all decoded layers.
#[derive(Debug, Clone)]
pub struct ParsedPacket<'a> {
    pub ethernet: EthernetFrame<'a>,
    pub network: NetworkLayer<'a>,
    pub transport: Option<TransportLayer<'a>>,
}

#[derive(Debug, Clone)]
pub enum NetworkLayer<'a> {
    Ipv4(Ipv4Packet<'a>),
    Ipv6(Ipv6Packet<'a>),
    Arp(ArpPacket),
    Unknown(&'a [u8]),
}

#[derive(Debug, Clone)]
pub enum TransportLayer<'a> {
    Tcp(TcpSegment<'a>),
    Udp(UdpDatagram<'a>),
    Icmp(IcmpPacket<'a>),
}

impl<'a> ParsedPacket<'a> {
    /// Parse a raw Ethernet frame into all available layers.
    pub fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        let ethernet = EthernetFrame::parse(data)?;

        let (network, transport_data, ip_proto) = match ethernet.ethertype {
            ETHERTYPE_IPV4 => {
                let ip = Ipv4Packet::parse(ethernet.payload)?;
                let proto = ip.protocol;
                let td = ip.payload;
                (NetworkLayer::Ipv4(ip), Some(td), Some(proto))
            }
            ETHERTYPE_IPV6 => {
                let ip = Ipv6Packet::parse(ethernet.payload)?;
                let proto = ip.next_header;
                let td = ip.payload;
                (NetworkLayer::Ipv6(ip), Some(td), Some(proto))
            }
            ETHERTYPE_ARP => {
                let arp = ArpPacket::parse(ethernet.payload)?;
                (NetworkLayer::Arp(arp), None, None)
            }
            _ => (NetworkLayer::Unknown(ethernet.payload), None, None),
        };

        let transport = match (transport_data, ip_proto) {
            (Some(td), Some(PROTO_TCP)) => Some(TransportLayer::Tcp(TcpSegment::parse(td)?)),
            (Some(td), Some(PROTO_UDP)) => Some(TransportLayer::Udp(UdpDatagram::parse(td)?)),
            (Some(td), Some(PROTO_ICMP)) => Some(TransportLayer::Icmp(IcmpPacket::parse(td)?)),
            _ => None,
        };

        Ok(Self {
            ethernet,
            network,
            transport,
        })
    }

    /// Source IP as string, if available.
    pub fn src_ip(&self) -> Option<String> {
        match &self.network {
            NetworkLayer::Ipv4(ip) => Some(ip.src.to_string()),
            NetworkLayer::Ipv6(ip) => Some(ip.src.to_string()),
            _ => None,
        }
    }

    /// Destination IP as string, if available.
    pub fn dst_ip(&self) -> Option<String> {
        match &self.network {
            NetworkLayer::Ipv4(ip) => Some(ip.dst.to_string()),
            NetworkLayer::Ipv6(ip) => Some(ip.dst.to_string()),
            _ => None,
        }
    }

    /// Source port, if TCP or UDP.
    pub fn src_port(&self) -> Option<u16> {
        match &self.transport {
            Some(TransportLayer::Tcp(t)) => Some(t.src_port),
            Some(TransportLayer::Udp(u)) => Some(u.src_port),
            _ => None,
        }
    }

    /// Destination port, if TCP or UDP.
    pub fn dst_port(&self) -> Option<u16> {
        match &self.transport {
            Some(TransportLayer::Tcp(t)) => Some(t.dst_port),
            Some(TransportLayer::Udp(u)) => Some(u.dst_port),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid Ethernet + IPv4 + TCP packet.
    fn make_tcp_packet(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        flags: u8,
    ) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Ethernet header (14 bytes)
        pkt.extend_from_slice(&[0xaa; 6]); // dst mac
        pkt.extend_from_slice(&[0xbb; 6]); // src mac
        pkt.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        // IPv4 header (20 bytes)
        let ip_start = pkt.len();
        pkt.push(0x45); // version=4, ihl=5
        pkt.push(0x00); // dscp
        pkt.extend_from_slice(&0u16.to_be_bytes()); // total length (filled later)
        pkt.extend_from_slice(&0u16.to_be_bytes()); // identification
        pkt.extend_from_slice(&0u16.to_be_bytes()); // flags + frag
        pkt.push(64); // ttl
        pkt.push(PROTO_TCP); // protocol
        pkt.extend_from_slice(&0u16.to_be_bytes()); // checksum
        pkt.extend_from_slice(&src_ip);
        pkt.extend_from_slice(&dst_ip);
        // TCP header (20 bytes)
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&1u32.to_be_bytes()); // seq
        pkt.extend_from_slice(&0u32.to_be_bytes()); // ack
        pkt.push(0x50); // data offset = 5 (20 bytes)
        pkt.push(flags);
        pkt.extend_from_slice(&1024u16.to_be_bytes()); // window
        pkt.extend_from_slice(&0u16.to_be_bytes()); // checksum
        pkt.extend_from_slice(&0u16.to_be_bytes()); // urgent

        // Fix total length
        let total = (pkt.len() - ip_start) as u16;
        let tl = total.to_be_bytes();
        pkt[ip_start + 2] = tl[0];
        pkt[ip_start + 3] = tl[1];
        pkt
    }

    fn make_udp_packet(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Ethernet
        pkt.extend_from_slice(&[0xaa; 6]);
        pkt.extend_from_slice(&[0xbb; 6]);
        pkt.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        // IPv4
        let ip_start = pkt.len();
        pkt.push(0x45);
        pkt.push(0x00);
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.push(64);
        pkt.push(PROTO_UDP);
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&[10, 0, 0, 1]);
        pkt.extend_from_slice(&[10, 0, 0, 2]);
        // UDP
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        let udp_len = (8 + payload.len()) as u16;
        pkt.extend_from_slice(&udp_len.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(payload);
        // Fix IP total length
        let total = (pkt.len() - ip_start) as u16;
        let tl = total.to_be_bytes();
        pkt[ip_start + 2] = tl[0];
        pkt[ip_start + 3] = tl[1];
        pkt
    }

    #[test]
    fn parse_tcp_syn() {
        let pkt = make_tcp_packet([192, 168, 1, 1], [10, 0, 0, 1], 12345, 80, 0x02);
        let parsed = ParsedPacket::parse(&pkt).unwrap();
        assert_eq!(parsed.src_ip().unwrap(), "192.168.1.1");
        assert_eq!(parsed.dst_ip().unwrap(), "10.0.0.1");
        assert_eq!(parsed.src_port(), Some(12345));
        assert_eq!(parsed.dst_port(), Some(80));
        if let Some(TransportLayer::Tcp(tcp)) = &parsed.transport {
            assert!(tcp.flags.syn());
            assert!(!tcp.flags.ack());
        } else {
            panic!("expected TCP");
        }
    }

    #[test]
    fn parse_udp() {
        let pkt = make_udp_packet(53, 1234, b"hello");
        let parsed = ParsedPacket::parse(&pkt).unwrap();
        assert_eq!(parsed.src_port(), Some(53));
        assert_eq!(parsed.dst_port(), Some(1234));
        if let Some(TransportLayer::Udp(udp)) = &parsed.transport {
            assert_eq!(udp.payload, b"hello");
        } else {
            panic!("expected UDP");
        }
    }

    #[test]
    fn parse_arp() {
        let mut pkt = Vec::new();
        // Ethernet
        pkt.extend_from_slice(&[0xff; 6]); // broadcast
        pkt.extend_from_slice(&[0xaa; 6]);
        pkt.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        // ARP (28 bytes)
        pkt.extend_from_slice(&1u16.to_be_bytes()); // hw type
        pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // proto type
        pkt.push(6); // hw size
        pkt.push(4); // proto size
        pkt.extend_from_slice(&1u16.to_be_bytes()); // operation (request)
        pkt.extend_from_slice(&[0xaa; 6]); // sender mac
        pkt.extend_from_slice(&[192, 168, 1, 1]); // sender ip
        pkt.extend_from_slice(&[0x00; 6]); // target mac
        pkt.extend_from_slice(&[192, 168, 1, 2]); // target ip

        let parsed = ParsedPacket::parse(&pkt).unwrap();
        if let NetworkLayer::Arp(arp) = &parsed.network {
            assert_eq!(arp.operation, 1);
            assert_eq!(arp.sender_ip, Ipv4Addr::new(192, 168, 1, 1));
            assert_eq!(arp.target_ip, Ipv4Addr::new(192, 168, 1, 2));
        } else {
            panic!("expected ARP");
        }
    }

    #[test]
    fn parse_icmp() {
        let mut pkt = Vec::new();
        // Ethernet
        pkt.extend_from_slice(&[0xaa; 6]);
        pkt.extend_from_slice(&[0xbb; 6]);
        pkt.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        // IPv4
        let ip_start = pkt.len();
        pkt.push(0x45);
        pkt.push(0x00);
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.push(64);
        pkt.push(PROTO_ICMP);
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&[8, 8, 8, 8]);
        pkt.extend_from_slice(&[10, 0, 0, 1]);
        // ICMP echo request
        pkt.push(8); // type
        pkt.push(0); // code
        pkt.extend_from_slice(&0u16.to_be_bytes()); // checksum
        pkt.extend_from_slice(b"ping");
        // Fix IP total length
        let total = (pkt.len() - ip_start) as u16;
        let tl = total.to_be_bytes();
        pkt[ip_start + 2] = tl[0];
        pkt[ip_start + 3] = tl[1];

        let parsed = ParsedPacket::parse(&pkt).unwrap();
        if let Some(TransportLayer::Icmp(icmp)) = &parsed.transport {
            assert_eq!(icmp.icmp_type, 8);
            assert_eq!(icmp.code, 0);
        } else {
            panic!("expected ICMP");
        }
    }

    #[test]
    fn too_short_ethernet() {
        let result = EthernetFrame::parse(&[0; 5]);
        assert!(result.is_err());
    }

    #[test]
    fn tcp_flags_display() {
        let f = TcpFlags(0x12); // SYN+ACK
        assert_eq!(f.to_string(), "SA");
    }
}
