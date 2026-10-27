package protocol

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Envelope is the HTTP Type1 transport container.
//
// Pre-registration: Data holds plaintext JSON.
// Post-registration: Data holds a base64 string of SessionKey.Seal(innerJSON).
// Z marks the sealed inner JSON as zstd-compressed (plan P6, profile-driven;
// decompression is capped to reject bombs).
type Envelope struct {
	V     int             `json:"v"`
	Type  string          `json:"t"`
	Agent string          `json:"a,omitempty"`
	Z     bool            `json:"z,omitempty"`
	Data  json.RawMessage `json:"d,omitempty"`
}

// NewPlainEnvelope wraps a plaintext JSON payload (register only).
func NewPlainEnvelope(typ, agent string, payload any) (*Envelope, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return &Envelope{V: ProtocolVersion, Type: typ, Agent: agent, Data: raw}, nil
}

// NewSealedEnvelope wraps a payload encrypted with the session key.
func NewSealedEnvelope(typ, agent string, sk *SessionKey, payload any) (*Envelope, error) {
	return newSealedEnvelope(typ, agent, sk, payload, false)
}

// NewSealedEnvelopeZstd is NewSealedEnvelope with optional zstd compression of
// the inner JSON before sealing (plan P6). Compression is skipped when it does
// not shrink the payload, so Z is only ever set on genuinely compressed data.
func NewSealedEnvelopeZstd(typ, agent string, sk *SessionKey, payload any, zstd bool) (*Envelope, error) {
	return newSealedEnvelope(typ, agent, sk, payload, zstd)
}

func newSealedEnvelope(typ, agent string, sk *SessionKey, payload any, zstd bool) (*Envelope, error) {
	inner, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	compressed := false
	if zstd {
		if packed, ok := zstdCompress(inner); ok {
			inner = packed
			compressed = true
		}
	}
	sealed, err := sk.Seal(inner)
	if err != nil {
		return nil, err
	}
	return &Envelope{
		V:     ProtocolVersion,
		Type:  typ,
		Agent: agent,
		Z:     compressed,
		Data:  json.RawMessage(fmt.Sprintf("%q", base64.StdEncoding.EncodeToString(sealed))),
	}, nil
}

// DecodePlain unmarshals a plaintext Data into out.
func (e *Envelope) DecodePlain(out any) error {
	return json.Unmarshal(e.Data, out)
}

// OpenSealed base64-decodes, HMAC-verifies, decrypts and (when Z is set)
// zstd-decompresses Data into out.
func (e *Envelope) OpenSealed(sk *SessionKey, out any) error {
	var b64 string
	if err := json.Unmarshal(e.Data, &b64); err != nil {
		return fmt.Errorf("sealed data not a string: %w", err)
	}
	blob, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return fmt.Errorf("b64: %w", err)
	}
	plain, err := sk.Open(blob)
	if err != nil {
		return err
	}
	if e.Z {
		if plain, err = zstdDecompress(plain); err != nil {
			return err
		}
	}
	return json.Unmarshal(plain, out)
}

// Marshal serializes the envelope for the wire.
func (e *Envelope) Marshal() []byte {
	b, _ := json.Marshal(e)
	return b
}

// ReadEnvelope parses a wire envelope.
func ReadEnvelope(data []byte) (*Envelope, error) {
	e := &Envelope{}
	if err := json.Unmarshal(data, e); err != nil {
		return nil, err
	}
	if e.V != ProtocolVersion {
		return nil, fmt.Errorf("protocol: unsupported envelope version %d", e.V)
	}
	return e, nil
}
