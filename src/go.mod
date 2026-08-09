module github.com/user/wisp

go 1.25.1

require (
	github.com/google/uuid v1.6.0
	github.com/mattn/go-sqlite3 v1.14.49
	github.com/user/wisp/shared/protocol v0.0.0
	github.com/wailsapp/wails/v3 v3.0.0-beta.3
)

replace github.com/user/wisp/shared/protocol => ./shared/protocol

require (
	github.com/adrg/xdg v0.5.3 // indirect
	github.com/coder/websocket v1.8.14 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/godbus/dbus/v5 v5.2.2 // indirect
	github.com/jchv/go-winloader v0.0.0-20250406163304-c1995be93bd1 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/klauspost/reedsolomon v1.12.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/quic-go/quic-go v0.61.0 // indirect
	github.com/tjfoc/gmsm v1.4.1 // indirect
	github.com/xtaci/kcp-go/v5 v5.6.72 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/time v0.14.0 // indirect
)
