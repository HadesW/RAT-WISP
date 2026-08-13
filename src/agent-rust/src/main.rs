// EXE entry point for the Rust agent.
// Build: cargo build --release
// Run:   WISP_RSA_PUB="<PEM>" ./wisp_agent   (or via build-time injection)

fn main() {
    wisp_agent::agent::agent_run(true);
}
