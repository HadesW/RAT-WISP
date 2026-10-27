// Package malleable compiles a Malleable C2 profile subset into the runtime
// protocol.Profile (plan P4). One http-get/http-post block per import:
//
//	http-get {
//	  set uri "/a"; set uri "/b";
//	  set useragent "curl/8.4.0"; set host "example.com";
//	  set sleeptime "5000"; set jitter "30";
//	  client { header "Accept" "text/html"; }
//	  metadata { base64url; prepend "data="; header "Cookie"; }
//	  output { base64url; prepend "OK"; terminate "\n"; print; }
//	  server { header "Content-Type" "text/html"; output { base64url; print; } }
//	}
//
// Transforms: base64 | base64url | xor | prepend "s" | append "s" |
// terminate "s". mask and binary response transforms are rejected until the
// runtime contract gains them.
package malleable

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"wispp/protocol"
)

// Compile turns Malleable text into a validated runtime profile.
func Compile(name, text string) (*protocol.Profile, error) {
	p, err := parse(name, text)
	if err != nil {
		return nil, err
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p, nil
}

type token struct {
	kind byte // 'i' ident, 's' string, '{', '}', ';'
	val  string
}

type parser struct {
	toks []token
	pos  int
}

func lex(text string) ([]token, error) {
	var out []token
	for i := 0; i < len(text); {
		c := text[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			i++
		case c == '/' && i+1 < len(text) && text[i+1] == '/':
			for i < len(text) && text[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(text) && text[i+1] == '*':
			j := strings.Index(text[i+2:], "*/")
			if j < 0 {
				return nil, fmt.Errorf("malleable: unterminated comment")
			}
			i += j + 4
		case c == '#':
			for i < len(text) && text[i] != '\n' {
				i++
			}
		case c == '"' || c == '\'':
			quote := c
			i++
			var sb strings.Builder
			for i < len(text) && text[i] != quote {
				if text[i] == '\\' && i+1 < len(text) {
					i++
					switch text[i] {
					case 'n':
						sb.WriteByte('\n')
					case 'r':
						sb.WriteByte('\r')
					case 't':
						sb.WriteByte('\t')
					case '\\', '"', '\'':
						sb.WriteByte(text[i])
					case 'x':
						if i+2 < len(text) {
							if v, err := strconv.ParseUint(text[i+1:i+3], 16, 8); err == nil {
								sb.WriteByte(byte(v))
								i += 2
							}
						}
					default:
						sb.WriteByte(text[i])
					}
					i++
					continue
				}
				sb.WriteByte(text[i])
				i++
			}
			if i >= len(text) {
				return nil, fmt.Errorf("malleable: unterminated string")
			}
			i++
			out = append(out, token{kind: 's', val: sb.String()})
		case c == '{' || c == '}' || c == ';':
			out = append(out, token{kind: c})
			i++
		default:
			start := i
			for i < len(text) && !strings.ContainsRune(" \t\r\n{};\"'", rune(text[i])) {
				i++
			}
			out = append(out, token{kind: 'i', val: text[start:i]})
		}
	}
	return out, nil
}

func (p *parser) peek() (token, bool) {
	if p.pos >= len(p.toks) {
		return token{}, false
	}
	return p.toks[p.pos], true
}

func (p *parser) next() (token, bool) {
	t, ok := p.peek()
	if ok {
		p.pos++
	}
	return t, ok
}

func (p *parser) acceptIdent(v string) bool {
	t, ok := p.peek()
	if ok && t.kind == 'i' && t.val == v {
		p.pos++
		return true
	}
	return false
}

// skipStmt consumes tokens until ';' (balanced braces allowed).
func (p *parser) skipStmt() {
	depth := 0
	for {
		t, ok := p.next()
		if !ok {
			return
		}
		switch t.kind {
		case '{':
			depth++
		case '}':
			if depth == 0 {
				return
			}
			depth--
		case ';':
			if depth == 0 {
				return
			}
		}
	}
}

type dataBlock struct {
	slot       string
	transforms []string
	seen       bool
}

func (p *parser) parseDataBlock() (*dataBlock, error) {
	if t, ok := p.next(); !ok || t.kind != '{' {
		return nil, fmt.Errorf("malleable: expected { after data block")
	}
	db := &dataBlock{slot: "body", seen: true}
	for {
		t, ok := p.next()
		if !ok {
			return nil, fmt.Errorf("malleable: unterminated data block")
		}
		switch t.kind {
		case '}':
			return db, nil
		case ';':
			continue
		case 'i':
			switch t.val {
			case "base64", "base64url", "xor":
				db.transforms = append(db.transforms, t.val)
			case "mask":
				return nil, fmt.Errorf("malleable: transform mask is not supported yet")
			case "prepend", "append", "terminate":
				s, ok := p.next()
				if !ok || s.kind != 's' {
					return nil, fmt.Errorf("malleable: %s needs a string", t.val)
				}
				db.transforms = append(db.transforms, t.val+":"+s.val)
			case "header":
				s, ok := p.next()
				if !ok || s.kind != 's' {
					return nil, fmt.Errorf("malleable: header needs a name")
				}
				db.slot = "header:" + s.val
			case "param", "parameter":
				s, ok := p.next()
				if !ok || s.kind != 's' {
					return nil, fmt.Errorf("malleable: param needs a name")
				}
				db.slot = "param:" + s.val
			case "print":
				db.slot = "body"
			default:
				p.skipStmt()
			}
		default:
			p.skipStmt()
		}
	}
}

type httpBlock struct {
	kind          string
	sets          map[string][]string
	headers       []protocol.KV
	serverHeaders []protocol.KV
	metadata      *dataBlock
	output        *dataBlock
}

func (p *parser) parseHTTPBlock(kind string) (*httpBlock, error) {
	if t, ok := p.next(); !ok || t.kind != '{' {
		return nil, fmt.Errorf("malleable: expected { after %s", kind)
	}
	b := &httpBlock{kind: kind, sets: map[string][]string{}}
	for {
		t, ok := p.next()
		if !ok {
			return nil, fmt.Errorf("malleable: unterminated %s block", kind)
		}
		switch t.kind {
		case '}':
			return b, nil
		case ';':
			continue
		case 'i':
			switch t.val {
			case "set":
				key, ok1 := p.next()
				val, ok2 := p.next()
				if !ok1 || !ok2 || key.kind != 'i' || (val.kind != 's' && val.kind != 'i') {
					return nil, fmt.Errorf("malleable: set needs key and string")
				}
				b.sets[strings.ToLower(key.val)] = append(b.sets[strings.ToLower(key.val)], val.val)
			case "client":
				heads, err := p.parseClientServer()
				if err != nil {
					return nil, err
				}
				b.headers = append(b.headers, heads...)
			case "server":
				heads, err := p.parseServerBlock(b)
				if err != nil {
					return nil, err
				}
				b.serverHeaders = append(b.serverHeaders, heads...)
			case "metadata":
				db, err := p.parseDataBlock()
				if err != nil {
					return nil, err
				}
				b.metadata = db
			case "output":
				db, err := p.parseDataBlock()
				if err != nil {
					return nil, err
				}
				b.output = db
			default:
				// Unknown block/statement (id, stage, http-config…): skip.
				if t2, ok2 := p.peek(); ok2 && t2.kind == '{' {
					p.next()
					if err := p.skipBalanced(); err != nil {
						return nil, err
					}
				} else {
					p.skipStmt()
				}
			}
		default:
			p.skipStmt()
		}
	}
}

func (p *parser) parseClientServer() ([]protocol.KV, error) {
	if t, ok := p.next(); !ok || t.kind != '{' {
		return nil, fmt.Errorf("malleable: expected {")
	}
	var out []protocol.KV
	for {
		t, ok := p.next()
		if !ok {
			return nil, fmt.Errorf("malleable: unterminated client block")
		}
		switch t.kind {
		case '}':
			return out, nil
		case ';':
			continue
		case 'i':
			if t.val == "header" {
				k, ok1 := p.next()
				v, ok2 := p.next()
				if !ok1 || !ok2 || k.kind != 's' || v.kind != 's' {
					return nil, fmt.Errorf("malleable: header needs two strings")
				}
				out = append(out, protocol.KV{Key: k.val, Value: v.val})
				continue
			}
			if t2, ok2 := p.peek(); ok2 && t2.kind == '{' {
				p.next()
				if err := p.skipBalanced(); err != nil {
					return nil, err
				}
			} else {
				p.skipStmt()
			}
		default:
			p.skipStmt()
		}
	}
}

func (p *parser) parseServerBlock(b *httpBlock) ([]protocol.KV, error) {
	if t, ok := p.next(); !ok || t.kind != '{' {
		return nil, fmt.Errorf("malleable: expected { after server")
	}
	var out []protocol.KV
	for {
		t, ok := p.next()
		if !ok {
			return nil, fmt.Errorf("malleable: unterminated server block")
		}
		switch t.kind {
		case '}':
			return out, nil
		case ';':
			continue
		case 'i':
			switch t.val {
			case "header":
				k, ok1 := p.next()
				v, ok2 := p.next()
				if !ok1 || !ok2 || k.kind != 's' || v.kind != 's' {
					return nil, fmt.Errorf("malleable: header needs two strings")
				}
				out = append(out, protocol.KV{Key: k.val, Value: v.val})
			case "output":
				db, err := p.parseDataBlock()
				if err != nil {
					return nil, err
				}
				if b.output == nil {
					b.output = db
				}
			default:
				p.skipStmt()
			}
		default:
			p.skipStmt()
		}
	}
}

func (p *parser) skipBalanced() error {
	depth := 1
	for {
		t, ok := p.next()
		if !ok {
			return fmt.Errorf("malleable: unterminated block")
		}
		switch t.kind {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return nil
			}
		}
	}
}

func parse(name, text string) (*protocol.Profile, error) {
	toks, err := lex(text)
	if err != nil {
		return nil, err
	}
	ps := &parser{toks: toks}
	global := map[string][]string{}
	var block *httpBlock
	for {
		t, ok := ps.next()
		if !ok {
			break
		}
		switch t.kind {
		case ';':
			continue
		case 'i':
			switch t.val {
			case "set":
				key, ok1 := ps.next()
				val, ok2 := ps.next()
				if !ok1 || !ok2 || key.kind != 'i' || (val.kind != 's' && val.kind != 'i') {
					return nil, fmt.Errorf("malleable: set needs key and string")
				}
				global[strings.ToLower(key.val)] = append(global[strings.ToLower(key.val)], val.val)
			case "http-get", "http-post":
				if block != nil {
					return nil, fmt.Errorf("malleable: multiple http blocks in one profile are not supported; import one block")
				}
				b, err := ps.parseHTTPBlock(t.val)
				if err != nil {
					return nil, err
				}
				block = b
			case "https-dns", "https-beacon", "http-stager", "process-inject", "stage", "post-ex", "http-config":
				// Unsupported sections: skip so real-world profiles still compile
				// the http block the operator cares about.
				if t2, ok2 := ps.peek(); ok2 && t2.kind == '{' {
					ps.next()
					if err := ps.skipBalanced(); err != nil {
						return nil, err
					}
				} else {
					ps.skipStmt()
				}
			default:
				ps.skipStmt()
			}
		default:
			ps.skipStmt()
		}
	}
	if block == nil {
		return nil, fmt.Errorf("malleable: no http-get/http-post block")
	}
	return compile(name, block, global)
}

func compile(name string, b *httpBlock, global map[string][]string) (*protocol.Profile, error) {
	p := &protocol.Profile{Name: name}
	p.Method = http.MethodGet
	if b.kind == "http-post" {
		p.Method = http.MethodPost
	}
	if verbs := b.sets["verb"]; len(verbs) > 0 {
		p.Method = strings.ToUpper(verbs[0])
	}
	switch p.Method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodHead, http.MethodDelete:
	default:
		return nil, fmt.Errorf("malleable: unsupported verb %q", p.Method)
	}
	for _, u := range b.sets["uri"] {
		for _, part := range strings.Split(u, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if !strings.HasPrefix(part, "/") {
				return nil, fmt.Errorf("malleable: uri must start with /: %q", part)
			}
			p.URIs = append(p.URIs, part)
		}
	}
	p.UAPool = append(p.UAPool, b.sets["useragent"]...)
	if hosts := b.sets["host"]; len(hosts) > 0 {
		p.Host = hosts[0]
	}
	p.Headers = append(p.Headers, b.headers...)

	// Request data: metadata block, else the http-post output block.
	data := b.metadata
	if data == nil && b.kind == "http-post" && b.output != nil {
		data = b.output
	}
	if data == nil {
		return nil, fmt.Errorf("malleable: %s block has no metadata/output data slot", b.kind)
	}
	p.Data = data.slot
	p.DataTransform = append(p.DataTransform, data.transforms...)

	// Response: output block unless it was consumed as the request slot.
	var resp *dataBlock
	switch {
	case b.metadata != nil:
		resp = b.output
	case b.kind == "http-post":
		resp = nil // output defined the implant request; response stays raw
	default:
		resp = b.output
	}
	if resp != nil {
		var prefix, suffix string
		urlB64 := false
		quoted := false
		for _, tr := range resp.transforms {
			name, arg, _ := strings.Cut(tr, ":")
			switch name {
			case "base64":
				quoted = true
			case "base64url":
				urlB64 = true
				quoted = true
			case "prepend":
				prefix += arg
			case "append", "terminate":
				suffix += arg
			case "xor", "mask":
				return nil, fmt.Errorf("malleable: transform %s is not supported in responses yet", name)
			}
		}
		if quoted {
			p.Response.Body = prefix + "{data}" + suffix
			p.Response.UrlBase64 = urlB64
		} else {
			p.Response.Body = "{data}" // raw envelope (M0 behaviour)
		}
	}
	for _, h := range b.serverHeaders {
		if strings.EqualFold(h.Key, "Content-Type") {
			p.Response.ContentType = h.Value
			continue
		}
		p.Response.Headers = append(p.Response.Headers, h)
	}

	if v := first(global, "sleeptime"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			p.SleepMS = n
		}
	}
	if v := first(global, "jitter"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			p.JitterPct = n
		}
	}
	return p, nil
}

func first(m map[string][]string, key string) string {
	if v := m[key]; len(v) > 0 {
		return v[0]
	}
	return ""
}
