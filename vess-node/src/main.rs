use std::io::BufRead;
use std::net::UdpSocket;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;
use vess_crypto::VessBlock;
use vess_network::GossipMessage;
use vess_node::Node;

fn fmt8(b: &[u8]) -> String {
    b.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("")
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mut listen = "0.0.0.0:9876".to_string();
    let mut bootstrap: Vec<String> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" => { i += 1; if i < args.len() { listen = args[i].clone(); } }
            "--bootstrap" => { i += 1; if i < args.len() { bootstrap.push(args[i].clone()); } }
            _ => { eprintln!("unknown arg: {}", args[i]); }
        }
        i += 1;
    }

    let addr: std::net::SocketAddr = listen.parse().expect("invalid --listen address");
    let node = Arc::new(Mutex::new(Node::new(addr)));
    let socket = UdpSocket::bind(addr)?;
    socket.set_nonblocking(true)?;

    eprintln!("vess-node {} peers={}", addr, bootstrap.len());

    // Bootstrap connections
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
                if let Ok(addr) = line.parse::<std::net::SocketAddr>() {
                    resolved.push(addr);
                } else if let Ok(addr) = format!("{}:9876", line).parse::<std::net::SocketAddr>() {
                    resolved.push(addr);
                }
            }
        }
    }
    {
        let mut n = node.lock().unwrap();
        for bs in &resolved {
            eprintln!("bootstrapping to {} (solving handshake PoW)...", bs);
            let init = n.add_peer(*bs);
            if !init.is_empty() {
                let _ = socket.send_to(&init, *bs);
                eprintln!("  handshake init sent ({} bytes)", init.len());
            }
        }
        let reconnects = n.reconnect_peers();
        if !reconnects.is_empty() {
            eprintln!("reconnecting to {} known peers...", reconnects.len());
            for (addr, init) in reconnects {
                let _ = socket.send_to(&init, addr);
            }
        }
    }

    // Mining pool — spawns N threads per candidate, partitioned nonce space
    let miner_node = node.clone();
    let (block_tx, block_rx) = mpsc::channel::<(VessBlock, u64, Vec<u32>)>();
    std::thread::spawn(move || loop {
        let cores = {
            let n = miner_node.lock().unwrap();
            n.mining_cores
        };
        if cores == 0 {
            std::thread::sleep(Duration::from_millis(200));
            continue;
        }
        let candidate = {
            let mut n = miner_node.lock().unwrap();
            if n.mining_cores == 0 { continue; }
            match n.prepare_block() {
                Some(b) => b,
                None => { std::thread::sleep(Duration::from_millis(200)); continue; }
            }
        };
        // Run N solver threads; first to find a solution cancels the rest
        let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (result_tx, result_rx) = mpsc::channel();
        let cores_u64 = cores as u64;
        for t in 0..cores_u64 {
            let b = candidate.clone();
            let tx = result_tx.clone();
            let c = cancel.clone();
            std::thread::spawn(move || {
                if let Some((nonce, proof)) = Node::mine_pow(&b, t, cores_u64, c.as_ref()) {
                    let _ = tx.send((nonce, proof));
                }
            });
        }
        drop(result_tx); // so recv doesn't block forever if all threads cancel
        if let Ok((nonce, proof)) = result_rx.recv() {
            cancel.store(true, std::sync::atomic::Ordering::Relaxed);
            let _ = block_tx.send((candidate, nonce, proof));
        }
    });

    // Stdin thread for runtime commands
    let cmd_node = node.clone();
    let (tx, rx) = mpsc::channel::<String>();
    let (ptx, prx) = mpsc::channel::<std::net::SocketAddr>();
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            if let Ok(l) = line {
                let trimmed = l.trim().to_string();
                if let Some(addr_str) = trimmed.strip_prefix("peer ") {
                    if let Ok(peer_addr) = addr_str.parse::<std::net::SocketAddr>() {
                        let _ = ptx.send(peer_addr);
                    } else if let Ok(peer_addr) = format!("{}:9876", addr_str).parse::<std::net::SocketAddr>() {
                        let _ = ptx.send(peer_addr);
                    }
                } else if trimmed == "mine" {
                    cmd_node.lock().unwrap().mining_cores = 1;
                    eprintln!("mining ON (1 core)");
                } else if trimmed == "mine stop" {
                    cmd_node.lock().unwrap().mining_cores = 0;
                    eprintln!("mining OFF");
                } else if let Some(n_str) = trimmed.strip_prefix("mine ") {
                    if let Ok(n) = n_str.parse::<u32>() {
                        if n > 0 {
                            cmd_node.lock().unwrap().mining_cores = n;
                            eprintln!("mining ON ({} cores)", n);
                        } else {
                            cmd_node.lock().unwrap().mining_cores = 0;
                            eprintln!("mining OFF");
                        }
                    }
                } else if trimmed == "status" {
                    let n = cmd_node.lock().unwrap();
                    let m = n.merkle();
                    eprintln!("status: peers={} limbo={} utxos={} diff={} cores={} merkle={}",
                        n.peer_count(), n.limbo_len(), n.utxo_count(),
                        n.current_difficulty, n.mining_cores, fmt8(&m[..8]));
                } else {
                    let _ = tx.send(trimmed);
                }
            }
        }
    });

    eprintln!("node ready — listening on {}", addr);
    eprintln!("  commands: mine | mine N | mine stop | peer <addr> | status");

    let mut buf = [0u8; 65536];
    let mut last_status = 0u64;
    loop {
        // Apply mined blocks from background thread
        while let Ok((block, nonce, proof)) = block_rx.try_recv() {
            node.lock().unwrap().apply_mined_block(block, nonce, proof);
            // Broadcast the new block
            if let Ok(n) = node.lock() {
                if let Some(last) = n.pending_blocks.last() {
                    let msg = GossipMessage::Block(last.clone());
                    let addrs: Vec<std::net::SocketAddr> = n.peers.iter()
                        .filter(|(_, id)| **id != [0u8; 32]).map(|(a, _)| *a).collect();
                    for a in addrs { let _ = socket.send_to(&msg.encode(), a); }
                }
            }
        }

        // Check for peer connection requests
        while let Ok(peer_addr) = prx.try_recv() {
            eprintln!("connecting to {} (solving handshake PoW)...", peer_addr);
            let init = node.lock().unwrap().add_peer(peer_addr);
            if !init.is_empty() {
                let _ = socket.send_to(&init, peer_addr);
                eprintln!("  handshake init sent ({} bytes)", init.len());
            }
        }

        // Drain any leftover stdin commands
        while let Ok(_) = rx.try_recv() {}

        match socket.recv_from(&mut buf) {
            Ok((len, src)) => {
                if let Some(resp) = node.lock().unwrap().process(src, &buf[..len]) {
                    let _ = socket.send_to(&resp, src);
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
            Err(_) => {}
        }
        let outbound = {
            let mut n = node.lock().unwrap();
            let ob = n.cycle();
            ob
        };
        for (dest, data) in outbound {
            let _ = socket.send_to(&data, dest);
        }

        {
            let n = node.lock().unwrap();
            if n.ticks.saturating_sub(last_status) >= 2000 {
                last_status = n.ticks;
                let m = n.merkle();
                eprintln!("[{}:{}] peers={} limbo={} utxos={} diff={} merkle={}",
                    n.ticks, addr.port(), n.peer_count(), n.limbo_len(),
                    n.utxo_count(), n.current_difficulty, fmt8(&m[..8]));
            }
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}
