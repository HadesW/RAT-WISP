package listener

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"wispp/protocol"
	"wispp/server/internal/guard"
)

// QUICListener serves Type1 over QUIC (plan P6): one bi-directional stream per
// envelope round-trip carries the same magic-framed packets as the TCP path,
// so the Core pipeline (register hardening, PSK camo, tasks) is shared.
type QUICListener struct {
	Core

	Addr    string
	Profile *protocol.Profile

	mu     sync.Mutex
	ln     *quic.Listener
	cancel context.CancelFunc
	closed bool
}

// ListenAndServe blocks until the listener is closed (mirrors HTTPListener).
func (l *QUICListener) ListenAndServe(tlsCert, tlsKey string) error {
	cert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
	if err != nil {
		return err
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"wisp"},
		MinVersion:   tls.VersionTLS12,
	}
	cfg := &quic.Config{
		MaxIdleTimeout:  90 * time.Second,
		KeepAlivePeriod: 20 * time.Second,
		EnableDatagrams: false,
	}
	ln, err := quic.ListenAddr(l.Addr, tlsCfg, cfg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	l.mu.Lock()
	if l.closed {
		// Stop raced ahead of the bind: don't leave a live socket behind.
		l.mu.Unlock()
		cancel()
		_ = ln.Close()
		return nil
	}
	l.ln, l.cancel = ln, cancel
	l.mu.Unlock()
	defer cancel()
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, quic.ErrServerClosed) {
				return nil
			}
			return err
		}
		go l.handleConn(ctx, conn)
	}
}

func (l *QUICListener) Close() error {
	l.mu.Lock()
	l.closed = true
	ln, cancel := l.ln, l.cancel
	l.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if ln != nil {
		return ln.Close()
	}
	return nil
}

func (l *QUICListener) handleConn(ctx context.Context, conn quic.Connection) {
	defer conn.CloseWithError(0, "")
	ip := quicIP(conn.RemoteAddr())
	if l.Guard != nil && l.Guard.Blocked(ip) {
		return
	}
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go l.handleStream(stream, ip)
	}
}

// handleStream answers exactly one envelope per stream and closes it.
func (l *QUICListener) handleStream(stream quic.Stream, ip string) {
	defer stream.Close()
	_ = stream.SetReadDeadline(time.Now().Add(30 * time.Second))
	pkt, err := protocol.ReadPacket(stream)
	if err != nil || pkt.Type != protocol.TypeEnvelope {
		return
	}
	env, err := protocol.ReadEnvelope(pkt.Payload)
	if err != nil {
		return
	}
	resp, err := l.Process(env, ip)
	if err != nil {
		return // camo: a failed check gets silence, like the TCP path
	}
	_ = stream.SetWriteDeadline(time.Now().Add(30 * time.Second))
	_ = protocol.WritePacket(stream, &protocol.Packet{Type: protocol.TypeEnvelope, Payload: resp.Marshal()})
}

func quicIP(addr net.Addr) string {
	return guard.IPFromRemoteAddr(addr.String())
}
