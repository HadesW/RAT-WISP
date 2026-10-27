package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// Packet is the binary wire format shared by Type1-TCP / Type2 / Type3:
//
//	Magic(4) | Size(4 LE) | Type(1) | Payload(N)
type Packet struct {
	Type    byte
	Payload []byte
}

// Encode serializes a Packet to wire format.
func (p *Packet) Encode() []byte {
	buf := make([]byte, HeaderSize+len(p.Payload))
	copy(buf[0:4], Magic[:])
	binary.LittleEndian.PutUint32(buf[4:8], uint32(len(p.Payload)))
	buf[8] = p.Type
	copy(buf[HeaderSize:], p.Payload)
	return buf
}

// ReadPacket reads a single packet from r.
func ReadPacket(r io.Reader) (*Packet, error) {
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	if !bytes.Equal(header[0:4], Magic[:]) {
		return nil, fmt.Errorf("invalid magic: %x", header[0:4])
	}
	size := binary.LittleEndian.Uint32(header[4:8])
	if size > MaxPacketSize {
		return nil, fmt.Errorf("packet too large: %d bytes", size)
	}
	payload := make([]byte, size)
	if size > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, fmt.Errorf("read payload: %w", err)
		}
	}
	return &Packet{Type: header[8], Payload: payload}, nil
}

// WritePacket writes a packet to w.
func WritePacket(w io.Writer, pkt *Packet) error {
	_, err := w.Write(pkt.Encode())
	return err
}
