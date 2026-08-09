package transport

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/user/wisp/shared/protocol"
)

// genSelfSigned creates a throwaway self-signed certificate, mirroring how the
// real server generates its own TLS identity.
func genSelfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "wisp-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startFakeQUICServer emulates the wisp server's QUIC listener: it accepts a
// connection, reads one packet and answers TypeRequestKey with TypeServerKey.
func startFakeQUICServer(t *testing.T) (string, int) {
	t.Helper()
	ln, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{genSelfSigned(t)},
		NextProtos:   []string{quicNextProto},
		MinVersion:   tls.VersionTLS13,
	}, nil)
	if err != nil {
		t.Fatalf("quic listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := ln.Addr().(*net.UDPAddr).Port

	go func() {
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			conn, err := ln.Accept(ctx)
			cancel()
			if err != nil {
				return
			}
			go func(c *quic.Conn) {
				stream, err := c.AcceptStream(context.Background())
				if err != nil {
					_ = c.CloseWithError(0, "no stream")
					return
				}
				a := &quicStreamAdapter{conn: c, stream: stream}
				pkt, err := protocol.ReadPacket(a)
				if err != nil {
					_ = a.Close()
					return
				}
				if pkt.Type == protocol.TypeRequestKey {
					_ = protocol.WritePacket(a, &protocol.Packet{
						Type:    protocol.TypeServerKey,
						Payload: []byte("-----BEGIN PUBLIC KEY----- test"),
					})
				}
				// Graceful close, matching the real server: wait for the client
				// to finish reading and close its side before tearing the
				// connection down.
				_ = a.stream.SetReadDeadline(time.Now().Add(5 * time.Second))
				one := make([]byte, 1)
				for {
					if _, err := a.stream.Read(one); err != nil {
						break
					}
				}
				_ = a.Close()
			}(conn)
		}
	}()

	return "127.0.0.1", port
}

// TestQUICTransportFetchKey exercises the full QUIC client path against a fake
// server: TLS 1.3 handshake (self-signed cert, verification skipped), ALPN,
// stream open and the packet protocol. Regression guard for "QUIC 不上线":
// InsecureSkipVerify must stay enabled even when a fingerprint is configured.
func TestQUICTransportFetchKey(t *testing.T) {
	host, port := startFakeQUICServer(t)

	tp := NewQUICTransport(host, port, "0123456789abcdef", "", "")
	if err := tp.fetchServerKey(); err != nil {
		t.Fatalf("fetch server key: %v", err)
	}
	if !strings.Contains(tp.RSAPubPEM, "PUBLIC KEY") {
		t.Fatalf("unexpected key payload: %q", tp.RSAPubPEM)
	}
}

// TestQUICTransportFetchKeyPinned verifies the same path with a certificate
// fingerprint pinned (the payload generator always injects one): the chain
// check stays disabled while the VerifyPeerCertificate callback still works.
func TestQUICTransportFetchKeyPinned(t *testing.T) {
	host, port := startFakeQUICServer(t)

	fp, err := fetchServerFingerprint(host, port)
	if err != nil {
		t.Fatalf("compute fingerprint: %v", err)
	}

	tp := NewQUICTransport(host, port, "0123456789abcdef", "", fp)
	if err := tp.fetchServerKey(); err != nil {
		t.Fatalf("fetch server key with pin: %v", err)
	}
	if !strings.Contains(tp.RSAPubPEM, "PUBLIC KEY") {
		t.Fatalf("unexpected key payload: %q", tp.RSAPubPEM)
	}
}

// fetchServerFingerprint dials a fresh QUIC connection and returns the SHA-256
// fingerprint of the presented certificate.
func fetchServerFingerprint(host string, port int) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tlsConfig := &tls.Config{
		NextProtos:         []string{quicNextProto},
		InsecureSkipVerify: true,
	}
	conn, err := quic.DialAddr(ctx, net.JoinHostPort(host, strconv.Itoa(port)), tlsConfig, nil)
	if err != nil {
		return "", err
	}
	defer conn.CloseWithError(0, "done")

	state := conn.ConnectionState()
	if len(state.TLS.PeerCertificates) == 0 {
		return "", errors.New("no peer certificate")
	}
	sum := sha256.Sum256(state.TLS.PeerCertificates[0].Raw)
	return fmt.Sprintf("%x", sum[:]), nil
}
