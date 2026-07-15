use std::net::UdpSocket;
use std::time::Duration;
use vess_node::Node;

fn fmt8(b: &[u8]) -> String {
    b.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("")
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mut listen = "0.0.0.0:9876".to_string();
    let mut mining = false;
    let mut bootstrap: Vec<String> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" => { i += 1; if i < args.len() { listen = args[i].clone(); } }
            "--mine" => { mining = true; }
            "--bootstrap" => { i += 1; if i < args.len() { bootstrap.push(args[i].clone()); } }
            _ => { eprintln!("unknown arg: {}", args[i]); }
        }
        i += 1;
    }

    let addr: std::net::SocketAddr = listen.parse().expect("invalid --listen address");
    let mut node = Node::new(addr);
    node.mining = mining;
    let socket = UdpSocket::bind(addr)?;
    socket.set_nonblocking(true)?;

    eprintln!("vess-node {} mine={} peers={}", addr, mining, bootstrap.len());

    // Bootstrap connections — args can be SocketAddr, file path, or http(s) URL
    let mut resolved: Vec<std::net::SocketAddr> = Vec::new();
    for bp in &bootstrap {
        if let Ok(addr) = bp.parse::<std::net::SocketAddr>() {
            resolved.push(addr);
        } else {
            let lines: Vec<String> = if bp.starts_with("http://") || bp.starts_with("https://") {
                eprintln!("fetching peer list from {}", bp);
                match ureq::get(bp).call() {
                    Ok(r) => r.into_string().unwrap_or_default()
                        .lines().map(|l| l.trim().to_string()).collect(),
                    Err(e) => { eprintln!("  fetch failed: {}", e); continue; }
                }
            } else {
                eprintln!("reading peer list from {}", bp);
                match std::fs::read_to_string(bp) {
                    Ok(s) => s.lines().map(|l| l.trim().to_string()).collect(),
                    Err(e) => { eprintln!("  read failed: {}", e); continue; }
                }
            };
            for line in &lines {
                if line.is_empty() || line.starts_with('#') { continue; }
                // Strip port if present in host:port format; keep as-is for SocketAddr parse
                if let Ok(addr) = line.parse::<std::net::SocketAddr>() {
                    resolved.push(addr);
                } else {
                    // Try appending default port
                    if let Ok(addr) = format!("{}:9876", line).parse::<std::net::SocketAddr>() {
                        resolved.push(addr);
                    }
                }
            }
        }
    }
    for bs in &resolved {
        eprintln!("bootstrapping to {} (solving handshake PoW)...", bs);
        let init = node.add_peer(*bs);
        if !init.is_empty() {
            let _ = socket.send_to(&init, *bs);
            eprintln!("  handshake init sent ({} bytes)", init.len());
        }
    }

    // Reconnect to known peers from previous sessions
    let reconnects = node.reconnect_peers();
    if !reconnects.is_empty() {
        eprintln!("reconnecting to {} known peers...", reconnects.len());
        for (addr, init) in reconnects {
            let _ = socket.send_to(&init, addr);
        }
    }

    eprintln!("node ready — listening on {}", addr);

    let mut buf = [0u8; 65536];
    let mut last_status = 0u64;
    loop {
        match socket.recv_from(&mut buf) {
            Ok((len, src)) => {
                if let Some(resp) = node.process(src, &buf[..len]) {
                    let _ = socket.send_to(&resp, src);
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
            Err(_) => {}
        }
        let outbound = node.cycle();
        for (dest, data) in outbound {
            let _ = socket.send_to(&data, dest);
        }

        if node.ticks.saturating_sub(last_status) >= 2000 {
            last_status = node.ticks;
            let merkle = node.merkle();
            eprintln!("[{}:{}] peers={} limbo={} utxos={} diff={} merkle={}",
                node.ticks, addr.port(), node.peer_count(), node.limbo_len(),
                node.utxo_count(), node.current_difficulty, fmt8(&merkle[..8]));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}
