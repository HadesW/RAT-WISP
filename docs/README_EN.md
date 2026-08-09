# RAT-WISP

Wisp is a cross-platform C2 management console (also usable as a Remote Administration Tool), built with Go + Wails v3 + React + TypeScript. It supports multi-protocol listeners, agent remote management, remote desktop, file management, and more.

## Screenshots

![Dashboard](../pic/2026-08-09_001034.png)

![Remote Control 1](../pic/2026-08-09_002723.png)

![Remote Control 2](../pic/2026-08-09_003817.png)

![File Manager](../pic/2026-08-09_004432.png)

![Screenshot](../pic/2026-08-09_004840.png)

## Key Features

- Multi-protocol listeners (TCP / HTTP / HTTPS / KCP)
- Remote shell & interactive shell
- Remote desktop (RDP) + dedicated RCP low-latency channel
- File management (browse, upload, download)
- One-click payload generation (DLL mode supported)
- PSK authentication & TLS certificate pinning
- RSA + AES-GCM hybrid encrypted communication

## Tech Stack

| Layer | Technology |
|-------|------------|
| Desktop | Wails v3 |
| Backend | Go 1.25 |
| Frontend | React 19 + TypeScript + Vite |
| State | Zustand |
| Database | SQLite3 |

## Quick Start

**Prerequisites**: Go 1.25+, Node.js 18+

```bash
cd src

# Install dependencies & build frontend
cd frontend && npm install && npm run build && cd ..
go mod tidy

# Dev mode
wails3 dev

# Build (Linux/macOS: make, Windows: build.bat)
make build-app          # or build.bat server
make agent              # or build.bat agent
make agent-all          # or build.bat agent-all

# Run
./bin/wisp              # macOS/Linux
bin\wisp.exe            # double-click on Windows
```

## Documentation

- [中文 README](../readme.md)

## Disclaimer

This tool is for security research and authorized testing only.
