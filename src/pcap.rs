//! Pcap file reader (libpcap format, not pcapng).
//!
//! Supports reading `.pcap` files with Ethernet link-layer (DLT_EN10MB = 1).

use std::io;
use std::path::Path;

/// Pcap global header magic (little-endian).
const PCAP_MAGIC_LE: u32 = 0xa1b2c3d4;
/// Pcap global header magic (big-endian / swapped).
const PCAP_MAGIC_BE: u32 = 0xd4c3b2a1;

/// Link-layer type for Ethernet.
const DLT_EN10MB: u32 = 1;

/// A pcap global file header.
#[derive(Debug, Clone)]
pub struct PcapHeader {
    pub version_major: u16,
    pub version_minor: u16,
    pub snaplen: u32,
    pub network: u32,
    #[allow(dead_code)]
    swapped: bool,
}

/// A single captured packet record.
#[derive(Debug, Clone)]
pub struct PcapRecord {
    /// Timestamp seconds.
    pub ts_sec: u32,
    /// Timestamp microseconds.
    pub ts_usec: u32,
    /// Number of bytes captured.
    pub incl_len: u32,
    /// Original packet length on wire.
    pub orig_len: u32,
    /// Raw packet data.
    pub data: Vec<u8>,
}

/// A parsed pcap file.
#[derive(Debug)]
pub struct PcapFile {
    pub header: PcapHeader,
    pub records: Vec<PcapRecord>,
}

/// Read and parse a pcap file from disk.
pub fn read_pcap(path: &Path) -> Result<PcapFile, PcapError> {
    let data = std::fs::read(path).map_err(PcapError::Io)?;
    parse_pcap(&data)
}

/// Parse pcap data from a byte slice.
pub fn parse_pcap(data: &[u8]) -> Result<PcapFile, PcapError> {
    if data.len() < 24 {
        return Err(PcapError::TooShort);
    }

    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let swapped = match magic {
        PCAP_MAGIC_LE => false,
        PCAP_MAGIC_BE => true,
        _ => return Err(PcapError::BadMagic(magic)),
    };

    let r16 = |off: usize| -> u16 {
        let b = [data[off], data[off + 1]];
        if swapped {
            u16::from_be_bytes(b)
        } else {
            u16::from_le_bytes(b)
        }
    };
    let r32 = |off: usize| -> u32 {
        let b = [data[off], data[off + 1], data[off + 2], data[off + 3]];
        if swapped {
            u32::from_be_bytes(b)
        } else {
            u32::from_le_bytes(b)
        }
    };

    let header = PcapHeader {
        version_major: r16(4),
        version_minor: r16(6),
        snaplen: r32(16),
        network: r32(20),
        swapped,
    };

    if header.network != DLT_EN10MB {
        return Err(PcapError::UnsupportedLinkType(header.network));
    }

    let mut offset = 24;
    let mut records = Vec::new();

    while offset + 16 <= data.len() {
        let ts_sec = r32(offset);
        let ts_usec = r32(offset + 4);
        let incl_len = r32(offset + 8);
        let orig_len = r32(offset + 12);
        offset += 16;

        let end = offset + incl_len as usize;
        if end > data.len() {
            break; // truncated file, stop gracefully
        }

        records.push(PcapRecord {
            ts_sec,
            ts_usec,
            incl_len,
            orig_len,
            data: data[offset..end].to_vec(),
        });
        offset = end;
    }

    Ok(PcapFile { header, records })
}

/// Write a pcap file (little-endian, Ethernet).
pub fn write_pcap<W: io::Write>(writer: &mut W, records: &[PcapRecord]) -> io::Result<()> {
    // Global header
    writer.write_all(&PCAP_MAGIC_LE.to_le_bytes())?;
    writer.write_all(&2u16.to_le_bytes())?; // version major
    writer.write_all(&4u16.to_le_bytes())?; // version minor
    writer.write_all(&0i32.to_le_bytes())?; // thiszone
    writer.write_all(&0u32.to_le_bytes())?; // sigfigs
    writer.write_all(&65535u32.to_le_bytes())?; // snaplen
    writer.write_all(&DLT_EN10MB.to_le_bytes())?; // network

    for rec in records {
        writer.write_all(&rec.ts_sec.to_le_bytes())?;
        writer.write_all(&rec.ts_usec.to_le_bytes())?;
        writer.write_all(&(rec.data.len() as u32).to_le_bytes())?;
        writer.write_all(&rec.orig_len.to_le_bytes())?;
        writer.write_all(&rec.data)?;
    }
    Ok(())
}

/// Pcap-specific errors.
#[derive(Debug)]
pub enum PcapError {
    Io(io::Error),
    TooShort,
    BadMagic(u32),
    UnsupportedLinkType(u32),
}

impl std::fmt::Display for PcapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::TooShort => write!(f, "pcap file too short"),
            Self::BadMagic(m) => write!(f, "bad pcap magic: 0x{m:08x}"),
            Self::UnsupportedLinkType(t) => write!(f, "unsupported link type: {t}"),
        }
    }
}

impl std::error::Error for PcapError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid pcap with one Ethernet frame.
    fn make_pcap(frame: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        // Global header (24 bytes)
        buf.extend_from_slice(&PCAP_MAGIC_LE.to_le_bytes());
        buf.extend_from_slice(&2u16.to_le_bytes());
        buf.extend_from_slice(&4u16.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&65535u32.to_le_bytes());
        buf.extend_from_slice(&DLT_EN10MB.to_le_bytes());
        // Record header (16 bytes)
        buf.extend_from_slice(&1000u32.to_le_bytes()); // ts_sec
        buf.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
        buf.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        buf.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        buf.extend_from_slice(frame);
        buf
    }

    fn sample_ethernet_frame() -> Vec<u8> {
        use crate::packet::*;
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0xaa; 6]);
        pkt.extend_from_slice(&[0xbb; 6]);
        pkt.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        // Minimal IPv4+TCP
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
        // TCP
        pkt.extend_from_slice(&80u16.to_be_bytes());
        pkt.extend_from_slice(&12345u16.to_be_bytes());
        pkt.extend_from_slice(&1u32.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes());
        pkt.push(0x50);
        pkt.push(0x02);
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
    fn parse_and_roundtrip() {
        let frame = sample_ethernet_frame();
        let pcap_data = make_pcap(&frame);
        let pcap = parse_pcap(&pcap_data).unwrap();

        assert_eq!(pcap.header.version_major, 2);
        assert_eq!(pcap.header.version_minor, 4);
        assert_eq!(pcap.header.network, DLT_EN10MB);
        assert_eq!(pcap.records.len(), 1);
        assert_eq!(pcap.records[0].ts_sec, 1000);
        assert_eq!(pcap.records[0].data, frame);

        // Roundtrip: write and re-read
        let mut out = Vec::new();
        write_pcap(&mut out, &pcap.records).unwrap();
        let pcap2 = parse_pcap(&out).unwrap();
        assert_eq!(pcap2.records.len(), 1);
        assert_eq!(pcap2.records[0].data, frame);
    }

    #[test]
    fn bad_magic() {
        let data = vec![0u8; 24];
        assert!(matches!(parse_pcap(&data), Err(PcapError::BadMagic(_))));
    }

    #[test]
    fn too_short() {
        assert!(matches!(parse_pcap(&[0; 4]), Err(PcapError::TooShort)));
    }

    #[test]
    fn multiple_records() {
        let frame = sample_ethernet_frame();
        let mut pcap_data = make_pcap(&frame);
        // Append a second record
        pcap_data.extend_from_slice(&2000u32.to_le_bytes());
        pcap_data.extend_from_slice(&0u32.to_le_bytes());
        pcap_data.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        pcap_data.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        pcap_data.extend_from_slice(&frame);

        let pcap = parse_pcap(&pcap_data).unwrap();
        assert_eq!(pcap.records.len(), 2);
        assert_eq!(pcap.records[1].ts_sec, 2000);
    }
}
