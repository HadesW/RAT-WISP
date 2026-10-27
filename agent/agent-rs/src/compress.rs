// Envelope zstd compression (plan P6): inner JSON is compressed BEFORE
// sealing (ciphertext does not compress), the envelope carries a `z` flag,
// and receivers decompress transparently with a bomb cap. Mirrors
// shared/protocol/compress.go — the two implementations must stay
// wire-compatible.
use std::io::Cursor;

use ruzstd::decoding::{BlockDecodingStrategy, FrameDecoder};
use ruzstd::encoding::{compress_to_vec, CompressionLevel};

/// Skip compression below this size: frame overhead would eat the saving.
pub(crate) const ZSTD_MIN_SIZE: usize = 256;
/// Reject decompressed output above this cap (bomb defence; matches Go).
pub(crate) const ZSTD_MAX_DECOMPRESS: u64 = 16 << 20;
/// Decode granularity for incremental bomb-cap enforcement.
const ZSTD_CHUNK: usize = 1 << 20;

// compress zstd-compresses src at the fastest level. Returns None when the
// payload is too small or compression does not shrink it, so the caller keeps
// plaintext and never sets the envelope flag on uncompressed data.
pub(crate) fn compress(src: &[u8]) -> Option<Vec<u8>> {
    if src.len() < ZSTD_MIN_SIZE {
        return None;
    }
    let out = compress_to_vec(Cursor::new(src), CompressionLevel::Fastest);
    if out.len() >= src.len() {
        return None;
    }
    Some(out)
}

// decompress enforces ZSTD_MAX_DECOMPRESS on both the declared window size
// (rejected at frame-header parse) and total output (checked incrementally
// while decoding), so a bomb is rejected without ever being buffered whole.
pub(crate) fn decompress(src: &[u8]) -> Result<Vec<u8>, String> {
    let mut dec = FrameDecoder::new();
    dec.set_max_window_size(ZSTD_MAX_DECOMPRESS);
    let mut reader = Cursor::new(src);
    dec.reset(&mut reader)
        .map_err(|e| format!("zstd: {e}"))?;
    let mut out = Vec::new();
    // Decode in chunks so the output cap is enforced mid-frame — the `All`
    // strategy would buffer the entire (possibly malicious) frame first.
    loop {
        let finished = dec
            .decode_blocks(&mut reader, BlockDecodingStrategy::UptoBytes(ZSTD_CHUNK))
            .map_err(|e| format!("zstd: {e}"))?;
        if let Some(chunk) = dec.collect() {
            out.extend_from_slice(&chunk);
            if out.len() as u64 > ZSTD_MAX_DECOMPRESS {
                return Err("zstd: decompressed size exceeds limit (possible bomb)".into());
            }
        }
        if finished {
            return Ok(out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        // > ZSTD_MIN_SIZE so compression actually engages.
        let mut payload = Vec::new();
        for i in 0..40 {
            payload.extend_from_slice(
                format!("{{\"task_id\":\"0123456789ab\",\"ok\":true,\"exit\":0,\"output\":\"line {i} aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}}\n").as_bytes(),
            );
        }
        let packed = compress(&payload).expect("compressible");
        assert!(packed.len() < payload.len());
        let out = decompress(&packed).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn tiny_payload_stays_plain() {
        assert!(compress(b"{\"ok\":true}").is_none());
    }

    #[test]
    fn random_payload_stays_plain_when_no_win() {
        // incompressible bytes: compression must not grow the payload.
        let mut blob = Vec::with_capacity(1024);
        let mut x = 0x243F6A8885A308D3u64;
        for _ in 0..1024 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            blob.extend_from_slice(&x.to_le_bytes());
        }
        assert!(compress(&blob).is_none());
    }

    #[test]
    fn corrupt_input_is_rejected() {
        assert!(decompress(b"not a zstd frame").is_err());
    }

    #[test]
    fn bomb_output_is_capped() {
        // 64MB of zeros compresses to a tiny frame; decompression must stop
        // at ZSTD_MAX_DECOMPRESS instead of materialising it all.
        let bomb = compress_to_vec(std::io::Cursor::new(vec![0u8; 64 << 20]), CompressionLevel::Fastest);
        assert!(bomb.len() < 1 << 20, "bomb frame unexpectedly large");
        assert!(decompress(&bomb).is_err());
    }

    #[test]
    fn oversized_window_is_rejected() {
        // zstd magic + frame header declaring a window over our cap must be
        // refused up front without allocating it.
        let mut frame = vec![0x28, 0xB5, 0x2F, 0xFD];
        frame.push(0x00); // frame header descriptor: no FCS, no single-segment
        frame.push(0x7F); // window descriptor: 1 << (10+127), way over cap
        assert!(decompress(&frame).is_err());
    }
}
