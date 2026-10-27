package protocol

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"
)

// zstd envelope compression (plan P6): the inner plaintext JSON is compressed
// BEFORE sealing (ciphertext does not compress), and the envelope carries a
// self-describing `z` flag so receivers decompress transparently. Profile-
// driven (Profile.Zstd) — default off, zero cost when disabled.
const (
	// ZstdMinSize skips compression for tiny payloads where frame overhead
	// would dominate any saving.
	ZstdMinSize = 256
	// ZstdMaxDecompress caps decompressed size to reject compression bombs
	// (plan P6: 防压缩炸弹). Matches the framed-transport packet ceiling.
	ZstdMaxDecompress = 16 << 20
)

var errZstdBomb = errors.New("zstd: decompressed size exceeds limit (possible bomb)")

// zstdCompress compresses in at the fastest level. It returns (nil, false)
// when compression does not pay off, so the caller falls back to plaintext.
func zstdCompress(in []byte) ([]byte, bool) {
	if len(in) < ZstdMinSize {
		return nil, false
	}
	var buf bytes.Buffer
	enc, err := zstd.NewWriter(&buf, zstd.WithEncoderLevel(zstd.SpeedFastest))
	if err != nil {
		return nil, false
	}
	if _, err := enc.Write(in); err != nil {
		_ = enc.Close()
		return nil, false
	}
	if err := enc.Close(); err != nil {
		return nil, false
	}
	if buf.Len() >= len(in) {
		return nil, false // no win — keep plaintext
	}
	return buf.Bytes(), true
}

// zstdDecompress enforces ZstdMaxDecompress both on the decoder's memory
// budget (window/history) and on total output, so a bomb is rejected without
// ever buffering it whole.
func zstdDecompress(in []byte) ([]byte, error) {
	dec, err := zstd.NewReader(bytes.NewReader(in),
		zstd.WithDecoderMaxMemory(ZstdMaxDecompress))
	if err != nil {
		return nil, fmt.Errorf("zstd: %w", err)
	}
	defer dec.Close()
	out, err := io.ReadAll(io.LimitReader(dec, ZstdMaxDecompress+1))
	if err != nil {
		return nil, fmt.Errorf("zstd: %w", err)
	}
	if len(out) > ZstdMaxDecompress {
		return nil, errZstdBomb
	}
	return out, nil
}
