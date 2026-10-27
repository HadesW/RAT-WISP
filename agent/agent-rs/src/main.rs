use wisp_agent_rs as agent;

fn main() {
    agent::keep_slot_alive();
    let cfg = match agent::config::load_from_args() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("agent: {e}");
            std::process::exit(1);
        }
    };
    agent::run(cfg);
}