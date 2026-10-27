use std::net::UdpSocket;

use crate::envelope::SystemInfo;

pub fn collect() -> SystemInfo {
    SystemInfo {
        hostname: hostname(),
        os: std::env::consts::OS,
        // Keep Go runtime naming so the console renders both agents alike.
        arch: match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            "x86" => "386",
            other => other,
        },
        user: username(),
        pid: std::process::id(),
        process: std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
        agent_ver: "rs-0.2.0",
        internal_ip: local_ip(),
    }
}

fn hostname() -> String {
    #[cfg(windows)]
    if let Ok(h) = std::env::var("COMPUTERNAME") {
        return h;
    }
    if let Ok(h) = std::env::var("HOSTNAME") {
        return h;
    }
    if let Ok(h) = std::fs::read_to_string("/proc/sys/kernel/hostname") {
        return h.trim().to_string();
    }
    if let Ok(o) = std::process::Command::new("hostname").output() {
        return String::from_utf8_lossy(&o.stdout).trim().to_string();
    }
    "rust-host".into()
}

fn username() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "rust".into())
}

// Route lookup without sending traffic: the kernel picks the outbound
// interface address for the socket.
fn local_ip() -> String {
    let Ok(sock) = UdpSocket::bind("0.0.0.0:0") else {
        return String::new();
    };
    if sock.connect("8.8.8.8:80").is_err() {
        return String::new();
    }
    sock.local_addr().map(|a| a.ip().to_string()).unwrap_or_default()
}
