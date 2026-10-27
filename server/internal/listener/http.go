package listener

import (
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"wispp/protocol"
	"wispp/server/internal/guard"
)

var (
	profileDebugOnce    sync.Once
	profileDebugEnabled bool
)

// profileDebug surfaces profile-mismatch details (method/URI/Host/UA) so
// operators can see why a shaped request was camoed. Off unless
// WISP_PROFILE_DEBUG=1.
func profileDebug() bool {
	profileDebugOnce.Do(func() { profileDebugEnabled = os.Getenv("WISP_PROFILE_DEBUG") != "" })
	return profileDebugEnabled
}

// HTTPListener is a Type1 HTTP(S) agent listener shaped by a Malleable profile
// (plan §2.2). With protocol.DefaultProfile() it behaves like the plain M0
// endpoint; with a builtin/custom profile the wire shape becomes camouflaged.
type HTTPListener struct {
	Core

	Addr    string
	Profile *protocol.Profile

	srv *http.Server
}

func (l *HTTPListener) Handler() http.Handler {
	prof := l.Profile
	if prof == nil {
		prof = protocol.DefaultProfile()
		l.Profile = prof
	}
	if err := prof.Validate(); err != nil {
		panic("listener: invalid profile: " + err.Error())
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", l.handle)
	return mux
}

func (l *HTTPListener) ListenAndServe(tlsCert, tlsKey string) error {
	l.srv = &http.Server{Addr: l.Addr, Handler: l.Handler(), ReadHeaderTimeout: 10 * time.Second}
	if tlsCert != "" {
		return l.srv.ListenAndServeTLS(tlsCert, tlsKey)
	}
	return l.srv.ListenAndServe()
}

func (l *HTTPListener) Close() error {
	if l.srv != nil {
		return l.srv.Close()
	}
	return nil
}

func (l *HTTPListener) handle(w http.ResponseWriter, r *http.Request) {
	prof := l.Profile
	if l.Stage != nil && strings.HasPrefix(r.URL.Path, l.Stage.Path+"/") {
		l.Stage.ServeHTTP(w, r) // Type4: token-gated fetch; 404s by themselves
		return
	}
	ip := guard.IPFromRemoteAddr(r.RemoteAddr)
	if l.Guard != nil && l.Guard.Blocked(ip) {
		prof.WriteNotFound(w)
		return
	}
	if !prof.Accepts(r) {
		if profileDebug() {
			l.Hub.Emit("warn", "listener", l.Project, "profile reject %s %s host=%q ua=%q",
				r.Method, r.URL.Path, r.Host, r.UserAgent())
		}
		prof.WriteNotFound(w)
		return
	}
	body, err := prof.Extract(r, MaxBody)
	if err != nil {
		prof.WriteNotFound(w)
		return
	}
	env, err := protocol.ReadEnvelope(body)
	if err != nil {
		prof.WriteNotFound(w)
		return
	}
	resp, err := l.Process(env, ip)
	if err != nil {
		prof.WriteNotFound(w)
		return
	}
	prof.WriteResponse(w, resp.Marshal())
}

// MaxBody caps any single request body (chunked transfers in M4 raise it).
const MaxBody = 4 << 20
