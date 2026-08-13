package transport

import (
	"crypto/tls"
	"net/http"
	"time"
)

// FireCanary performs a one-way startup lookup for the build's burn-detection
// token. The request is deliberately short-lived and errors are swallowed:
// a canary must never delay or fail agent startup. Best-effort: uses the same
// host/port as the configured listener so HTTP(S) listeners record the burn.
func FireCanary(host string, port int, useTLS bool, token string) {
	if token == "" {
		return
	}
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	url := scheme + "://" + joinHostPort(host, port) + "/canary/" + token

	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // pin check not needed for canary
	client := &http.Client{Timeout: 3 * time.Second, Transport: tr}
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

func joinHostPort(host string, port int) string {
	if host == "" {
		host = "127.0.0.1"
	}
	return host + ":" + itoa(port)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
