#!/bin/bash
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$PROJECT_ROOT/bin"
FRONTEND_DIR="$PROJECT_ROOT/frontend"
AGENT_DIR="$PROJECT_ROOT/agent"

print_step() {
    echo -e "${CYAN}==>${NC} $1"
}

print_ok() {
    echo -e "${GREEN}  ✓${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}  !${NC} $1"
}

print_err() {
    echo -e "${RED}  ✗${NC} $1"
}

file_size() {
    if [[ "$(uname)" == "Darwin" ]]; then
        stat -f%z "$1" 2>/dev/null | awk '{printf "%.1f MB", $1/1048576}'
    else
        stat --printf="%s" "$1" 2>/dev/null | awk '{printf "%.1f MB", $1/1048576}'
    fi
}

build_frontend() {
    print_step "Building frontend..."
    cd "$FRONTEND_DIR"
    if [ ! -d "node_modules" ]; then
        npm install --silent
    fi
    npm run build --silent
    print_ok "Frontend built → frontend/dist/"
}

build_server() {
    print_step "Building server (wisp)..."
    mkdir -p "$BIN_DIR"
    cd "$PROJECT_ROOT"
    CGO_ENABLED=1 go build -o "$BIN_DIR/wisp" . 2>&1 | grep -v "^ld: warning" || true
    print_ok "Server built → bin/wisp ($(file_size "$BIN_DIR/wisp"))"
}

build_headless() {
    print_step "Building headless server (wisp-headless)..."
    mkdir -p "$BIN_DIR"
    cd "$PROJECT_ROOT"
    go build -o "$BIN_DIR/wisp-headless" ./cmd/headless/
    print_ok "Headless built → bin/wisp-headless ($(file_size "$BIN_DIR/wisp-headless"))"
}

build_rust_agent() {
    print_step "Building Rust agent (shellcode/stager templates)..."
    mkdir -p "$BIN_DIR/templates"
    local rust_dir="$PROJECT_ROOT/agent-rust"
    if [ ! -d "$rust_dir" ]; then
        print_warn "  agent-rust/ not found; skipping Rust templates"
        return 0
    fi
    # Locate cargo
    if [ -f "$HOME/.cargo/env" ]; then
        . "$HOME/.cargo/env"
    fi
    if ! command -v cargo >/dev/null 2>&1; then
        print_warn "  cargo not found; skipping Rust templates"
        return 0
    fi
    if ! command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
        print_warn "  x86_64-w64-mingw32-gcc not found; skipping Rust templates"
        return 0
    fi

    export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc
    cd "$rust_dir"
    cargo build --release --target x86_64-pc-windows-gnu --bin wisp-agent 2>/dev/null
    cargo build --release --target x86_64-pc-windows-gnu --lib 2>/dev/null
    cp "$rust_dir/target/x86_64-pc-windows-gnu/release/wisp-agent.exe" "$BIN_DIR/templates/agent_rust_windows_amd64.exe"
    cp "$rust_dir/target/x86_64-pc-windows-gnu/release/wisp_agent.dll" "$BIN_DIR/templates/agent_rust_windows_amd64.dll"
    print_ok "Rust templates → agent_rust_windows_amd64.exe/.dll"
}

build_agent() {
    print_step "Building agent (current platform)..."
    mkdir -p "$BIN_DIR"
    cd "$AGENT_DIR"
    CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o "$BIN_DIR/agent" .
    print_ok "Agent built → bin/agent ($(file_size "$BIN_DIR/agent"))"
}

build_agent_all() {
    print_step "Cross-compiling agent for all platforms..."
    mkdir -p "$BIN_DIR"
    cd "$AGENT_DIR"

    platforms=(
        "windows/amd64/.exe"
        "windows/arm64/.exe"
        "linux/amd64/"
        "linux/arm64/"
        "darwin/amd64/"
        "darwin/arm64/"
    )

    for platform in "${platforms[@]}"; do
        IFS='/' read -r os arch ext <<< "$platform"
        output="$BIN_DIR/agent_${os}_${arch}${ext}"
        GOOS=$os GOARCH=$arch CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o "$output" .
        print_ok "  ${os}/${arch} → $(basename "$output") ($(file_size "$output"))"
    done
}

build_templates() {
    print_step "Cross-compiling agent templates (6 platforms + DLL)..."
    mkdir -p "$BIN_DIR/templates"
    cd "$AGENT_DIR"

    platforms=(
        "windows/amd64/.exe|-H windowsgui"
        "windows/arm64/.exe|-H windowsgui"
        "linux/amd64/|"
        "linux/arm64/|"
        "darwin/amd64/|"
        "darwin/arm64/|"
    )

    for entry in "${platforms[@]}"; do
        IFS='|' read -r spec gui <<< "$entry"
        IFS='/' read -r os arch ext <<< "$spec"
        output="$BIN_DIR/templates/agent_${os}_${arch}${ext}"
        GOOS=$os GOARCH=$arch CGO_ENABLED=0 go build -ldflags="-s -w $gui" -trimpath -o "$output" .
        print_ok "  ${os}/${arch} → $(basename "$output") ($(file_size "$output"))"
    done

    if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1; then
        dll_platforms=(
            "windows/amd64"
            "windows/arm64"
        )
        for spec in "${dll_platforms[@]}"; do
            IFS='/' read -r os arch <<< "$spec"
            output="$BIN_DIR/templates/agent_${os}_${arch}.dll"
            print_step "Building DLL template agent_${os}_${arch}.dll (c-shared)..."
            case "$arch" in
                amd64) dll_cc="${MINGW_CC:-x86_64-w64-mingw32-gcc}" ;;
                arm64) dll_cc="${MINGW_CC_ARM:-aarch64-w64-mingw32-gcc}" ;;
            esac
            if ! command -v "$dll_cc" >/dev/null 2>&1; then
                for dir in /opt/llvm-mingw-*; do
                    if [ -x "$dir/bin/$dll_cc" ]; then
                        dll_cc="$dir/bin/$dll_cc"
                        break
                    fi
                done
            fi
            if command -v "$dll_cc" >/dev/null 2>&1 || [ -x "$dll_cc" ]; then
                if GOOS=$os GOARCH=$arch CGO_ENABLED=1 CC="$dll_cc" \
                   go build -buildmode=c-shared -ldflags="-s -w" -trimpath -o "$output" . 2>/tmp/wisp_dll_err; then
                    print_ok "  DLL ${os}/${arch} → $(basename "$output") ($(file_size "$output"))"
                else
                    print_warn "  DLL ${os}/${arch} failed (needs $dll_cc for that target; skipping): $(head -1 /tmp/wisp_dll_err)"
                fi
            else
                print_warn "  DLL ${os}/${arch} failed (compiler $dll_cc not found; skipping)"
            fi
            rm -f "$BIN_DIR/templates/agent_${os}_${arch}.h" /tmp/wisp_dll_err
        done
    else
        print_warn "  No mingw gcc found; skipping DLL templates"
    fi
    print_ok "Templates built → $BIN_DIR/templates/"
}

clean() {
    print_step "Cleaning..."
    rm -rf "$BIN_DIR" "$FRONTEND_DIR/dist"
    print_ok "Cleaned bin/ and frontend/dist/"
}

show_usage() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  all          Build frontend + templates + server + headless + agent + rust"
    echo "  frontend     Build frontend only"
    echo "  server       Build server only"
    echo "  headless     Build headless server only"
    echo "  agent        Build Go agent for current platform"
    echo "  templates    Cross-compile 6 agent templates + 2 DLL templates"
    echo "  rust         Build Rust agent templates (shellcode/stager)"
    echo "  agent-all    Cross-compile agent for all 6 platforms"
    echo "  clean        Remove build artifacts"
    echo ""
}

# Main
echo ""
echo -e "${CYAN}Wisp C2 Framework — Build Script${NC}"
echo "─────────────────────────────────"
echo ""

case "${1:-all}" in
    all)
        build_frontend
        build_templates
        build_rust_agent
        build_server
        build_headless
        build_agent
        ;;
    frontend)
        build_frontend
        ;;
    server)
        build_frontend
        build_server
        ;;
    headless)
        build_headless
        ;;
    agent)
        build_agent
        ;;
    templates)
        build_templates
        ;;
    rust)
        build_rust_agent
        ;;
    agent-all)
        build_agent_all
        ;;
    clean)
        clean
        ;;
    help|--help|-h)
        show_usage
        exit 0
        ;;
    *)
        print_err "Unknown command: $1"
        show_usage
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}Done.${NC}"
