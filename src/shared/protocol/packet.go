package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// Packet represents a wire-format message.
type Packet struct {
	Type    byte
	Payload []byte
}

// Encode serializes a Packet to wire format: Magic(4) + Size(4) + Type(1) + Payload(N)
func (p *Packet) Encode() []byte {
	size := uint32(len(p.Payload))
	buf := make([]byte, HeaderSize+len(p.Payload))
	copy(buf[0:4], Magic[:])
	binary.LittleEndian.PutUint32(buf[4:8], size)
	buf[8] = p.Type
	copy(buf[HeaderSize:], p.Payload)
	return buf
}

// ReadPacket reads a single packet from a reader. Returns the decoded Packet or error.
func ReadPacket(r io.Reader) (*Packet, error) {
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	// Verify magic
	if !bytes.Equal(header[0:4], Magic[:]) {
		return nil, fmt.Errorf("invalid magic: %x", header[0:4])
	}

	size := binary.LittleEndian.Uint32(header[4:8])
	if size > MaxPacketSize {
		return nil, fmt.Errorf("packet too large: %d bytes", size)
	}

	pktType := header[8]

	payload := make([]byte, size)
	if size > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, fmt.Errorf("read payload: %w", err)
		}
	}

	return &Packet{
		Type:    pktType,
		Payload: payload,
	}, nil
}

// WritePacket writes a packet to a writer.
func WritePacket(w io.Writer, pkt *Packet) error {
	data := pkt.Encode()
	_, err := w.Write(data)
	return err
}
