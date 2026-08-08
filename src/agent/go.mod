module github.com/user/wisp/agent

go 1.25.1

require (
	github.com/user/wisp v0.0.0
	github.com/user/wisp/shared/protocol v0.0.0
	github.com/xtaci/kcp-go/v5 v5.6.72
	golang.org/x/text v0.40.0
)

require (
	github.com/google/uuid v1.6.0 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/klauspost/reedsolomon v1.12.0 // indirect
	github.com/mattn/go-sqlite3 v1.14.49 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/tjfoc/gmsm v1.4.1 // indirect
	golang.org/x/crypto v0.51.0 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/time v0.14.0 // indirect
)

replace (
	github.com/user/wisp => ../
	github.com/user/wisp/shared/protocol => ../shared/protocol
)
