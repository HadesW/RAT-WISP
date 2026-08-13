// Packet wire format — MUST match Go shared/protocol/packet.go.
//   [ Magic(4) ][ Size(4) LE ][ Type(1) ][ Payload(N) ]
// Size = payload length (uint32 LE). Header = 9 bytes.

use crate::protocol::constants::{HEADER_SIZE, MAGIC, MAX_PACKET_SIZE};
use std::io::{self, Read, Write};

#[derive(Debug, Clone)]
pub struct Packet {
    pub ptype: u8,
    pub payload: Vec<u8>,
}

impl Packet {
    pub fn new(ptype: u8, payload: Vec<u8>) -> Self {
        Packet { ptype, payload }
    }

    /// Serialize to wire format.
    pub fn encode(&self) -> Vec<u8> {
        let size = self.payload.len() as u32;
        let mut buf = Vec::with_capacity(HEADER_SIZE + self.payload.len());
        buf.extend_from_slice(&MAGIC);
        buf.extend_from_slice(&size.to_le_bytes());
        buf.push(self.ptype);
        buf.extend_from_slice(&self.payload);
        buf
    }

    pub fn write_to(&self, w: &mut impl Write) -> io::Result<()> {
        w.write_all(&self.encode())
    }
}

/// Read one packet from a reader (exact framing, matching Go io.ReadFull).
pub fn read_packet(r: &mut impl Read) -> io::Result<Packet> {
    let mut header = [0u8; HEADER_SIZE];
    r.read_exact(&mut header)?;

    if header[0..4] != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid magic: {:02x?}", &header[0..4]),
        ));
    }

    let size = u32::from_le_bytes(header[4..8].try_into().unwrap()) as usize;
    if size > MAX_PACKET_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("packet too large: {} bytes", size),
        ));
    }

    let ptype = header[8];
    let mut payload = vec![0u8; size];
    if size > 0 {
        r.read_exact(&mut payload)?;
    }

    Ok(Packet {
        ptype,
        payload,
    })
}

pub fn write_packet(w: &mut impl Write, pkt: &Packet) -> io::Result<()> {
    pkt.write_to(w)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let p = Packet::new(0x05, vec![1, 2, 3, 4, 5]);
        let enc = p.encode();
        assert_eq!(&enc[0..4], b"WISP");
        assert_eq!(u32::from_le_bytes(enc[4..8].try_into().unwrap()), 5);
        assert_eq!(enc[8], 0x05);
        let mut cur = io::Cursor::new(enc);
        let q = read_packet(&mut cur).unwrap();
        assert_eq!(q.ptype, 0x05);
        assert_eq!(q.payload, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn bad_magic() {
        let bad = b"XXXX\x05\x00\x00\x00\x01abcde".to_vec();
        let mut cur = io::Cursor::new(bad);
        assert!(read_packet(&mut cur).is_err());
    }
}
