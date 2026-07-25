use std::io::BufRead;
use std::net::UdpSocket;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;
use vess_crypto::VessBlock;
use vess_network::data_packets;
use vess_node::Node;

const MAX_MINING_CORES: u32 = 32;

fn permitted_mining_cores(requested: u32) -> u32 {
    let available = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1) as u32;
    requested.min(available.max(1)).min(MAX_MINING_CORES)
}

fn fmt8(b: &[u8]) -> String {
    b.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("")
}

fn send_datagrams(socket: &UdpSocket, dest: std::net::SocketAddr, data: &[u8]) {
    if data_packets::is_fragment(data) {
        let _ = socket.send_to(data, dest);
        return;
    }
    if let Some(fragments) = data_packets::fragment_message(data) {
        for fragment in fragments { let _ = socket.send_to(&fragment, dest); }
    }
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mut listen = "0.0.0.0:9876".to_string();
    let mut bootstrap: Vec<String> = Vec::new();
    let mut max_peers: usize = 32;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" => { i += 1; if i < args.len() { listen = args[i].clone(); } }
            "--bootstrap" => { i += 1; if i < args.len() { bootstrap.push(args[i].clone()); } }
            "--max-peers" => { i += 1; if i < args.len() { max_peers = args[i].parse().unwrap_or(32); } }
            _ => { eprintln!("unknown arg: {}", args[i]); }
        }
        i += 1;
    }

    let addr: std::net::SocketAddr = listen.parse().expect("invalid --listen address");
    let mut node_inner = Node::new(addr);
    node_inner.max_peers = max_peers;
    let node = Arc::new(Mutex::new(node_inner));
    let socket = UdpSocket::bind(addr)?;
    socket.set_nonblocking(true)?;

    eprintln!("vess-node {} peers={} max-peers={}", addr, bootstrap.len(), max_peers);

    // Bootstrap connections
    let mut resolved: Vec<std::net::SocketAddr> = Vec::new();
    for bp in &bootstrap {
        if let Ok(addr) = bp.parse::<std::net::SocketAddr>() {
            resolved.push(addr);
        } else {
            let lines: Vec<String> = if bp.starts_with("http://") || bp.starts_with("https://") {
                if bp.starts_with("http://") {
                    eprintln!("warning: bootstrap list is unauthenticated HTTP; prefer HTTPS or a local signed file");
                }
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
    resolved.sort();
    resolved.dedup();
    if resolved.len() > 100 {
        eprintln!("bootstrap list capped at 100 distinct peers");
        resolved.truncate(100);
    }
    {
        let mut n = node.lock().unwrap();
        for bs in &resolved {
            eprintln!("bootstrapping to {} (solving handshake PoW)...", bs);
            let len = n.add_peer(*bs);
            if len > 0 {
                eprintln!("  handshake init sent ({} bytes)", len);
            }
        }
        let count = n.reconnect_peers();
        if count > 0 {
            eprintln!("reconnecting to {} known peers...", count);
        }
        // Drain handshake datagrams queued during bootstrap.
        for (addr, data) in n.drain_outbox() {
            send_datagrams(&socket, addr, &data);
        }
    }

    // Block counter — increments on every processed block (mined or received).
    // The mining pool uses this to detect stale candidates.
    let block_count = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let block_count_miner = block_count.clone();
    let block_count_main = block_count.clone();

    // Hash counter — total nonces tried across all mining threads (for display).
    let hash_count = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let hash_count_status = hash_count.clone();
    let mining_since = std::sync::Arc::new(std::sync::Mutex::new(None::<std::time::Instant>));
    let mining_since_status = mining_since.clone();

    // Mining pool — spawns N threads per candidate, partitioned nonce space
    let miner_node = node.clone();
    let (block_tx, block_rx) = mpsc::channel::<(VessBlock, u64, Vec<u32>)>();
    std::thread::spawn(move || loop {
        let cores = {
            let n = miner_node.lock().unwrap();
            permitted_mining_cores(n.mining_cores)
        };
        if cores == 0 {
            std::thread::sleep(Duration::from_millis(100));
            continue;
        }
        let candidate = {
            let mut n = miner_node.lock().unwrap();
            if n.mining_cores == 0 { continue; }
            match n.prepare_block() {
                Some(b) => b,
                None => { std::thread::sleep(Duration::from_millis(50)); continue; }
            }
        };
        let started_at = block_count_miner.load(std::sync::atomic::Ordering::Relaxed);
        // Run N solver threads; first to find a solution cancels the rest.
        // DO NOT cancel immediately — let the threads run continuously until
        // one finds a solution or work becomes stale.
        let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (result_tx, result_rx) = mpsc::channel();
        let cores_u64 = cores as u64;
        let mut workers = Vec::with_capacity(cores as usize);
        for t in 0..cores_u64 {
            let b = candidate.clone();
            let tx = result_tx.clone();
            let c = cancel.clone();
            let hc = hash_count.clone();
            workers.push(std::thread::spawn(move || {
                if let Some((nonce, proof)) = Node::mine_pow(&b, t, cores_u64, c.as_ref(), hc.as_ref()) {
                    let _ = tx.send((nonce, proof));
                }
            }));
        }
        drop(result_tx);
        // Wait for solution, but check periodically for stale work / stop
        loop {
            match result_rx.recv_timeout(Duration::from_millis(500)) {
                Ok((nonce, proof)) => {
                    cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                    // Discard if a block arrived while we were mining
                    if block_count_miner.load(std::sync::atomic::Ordering::Relaxed) == started_at {
                        let _ = block_tx.send((candidate, nonce, proof));
                    }
                    break;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    // Check if mining was stopped or a new block arrived
                    let n = miner_node.lock().unwrap();
                    if n.mining_cores == 0 {
                        cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                        break;
                    }
                    if block_count_miner.load(std::sync::atomic::Ordering::Relaxed) != started_at {
                        cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                        break;
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        for worker in workers { let _ = worker.join(); }
        // Brief pause between rounds so the main loop gets the lock
        std::thread::sleep(Duration::from_millis(100));
    });

    // Stdin thread for runtime commands
    let cmd_node = node.clone();
    let mining_since_cmd = mining_since.clone();
    let (tx, rx) = mpsc::channel::<String>();
    let (ptx, prx) = mpsc::channel::<std::net::SocketAddr>();
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        for l in stdin.lock().lines().flatten() {
            let trimmed = l.trim().to_string();
            if let Some(addr_str) = trimmed.strip_prefix("peer ") {
                if let Ok(peer_addr) = addr_str.parse::<std::net::SocketAddr>() {
                    let _ = ptx.send(peer_addr);
                } else if let Ok(peer_addr) = format!("{}:9876", addr_str).parse::<std::net::SocketAddr>() {
                    let _ = ptx.send(peer_addr);
                }
            } else if trimmed == "mine" {
                cmd_node.lock().unwrap().mining_cores = 1;
                *mining_since_cmd.lock().unwrap() = Some(std::time::Instant::now());
                eprintln!("mining ON (1 core)");
            } else if trimmed == "mine stop" {
                cmd_node.lock().unwrap().mining_cores = 0;
                *mining_since_cmd.lock().unwrap() = None;
                eprintln!("mining OFF");
            } else if let Some(n_str) = trimmed.strip_prefix("mine ") {
                if let Ok(n) = n_str.parse::<u32>() {
                    if n > 0 {
                        let cores = permitted_mining_cores(n);
                        cmd_node.lock().unwrap().mining_cores = cores;
                        *mining_since_cmd.lock().unwrap() = Some(std::time::Instant::now());
                        eprintln!("mining ON ({} cores)", cores);
                    } else {
                        cmd_node.lock().unwrap().mining_cores = 0;
                        *mining_since_cmd.lock().unwrap() = None;
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
    });

    eprintln!("node ready — listening on {}", addr);
    eprintln!("  commands: mine | mine N | mine stop | peer <addr> | status");

    let mut buf = [0u8; 65536];
    let mut last_status = 0u64;
    loop {
        // Apply mined blocks from background thread
        while let Ok((block, nonce, proof)) = block_rx.try_recv() {
            node.lock().unwrap().apply_mined_block(block, nonce, proof);
            last_status = 0; // force status on next cycle
        }

        // Check for peer connection requests
        while let Ok(peer_addr) = prx.try_recv() {
            eprintln!("connecting to {} (solving handshake PoW)...", peer_addr);
            let len = node.lock().unwrap().add_peer(peer_addr);
            if len > 0 {
                eprintln!("  handshake init sent ({} bytes)", len);
            }
        }

        // Drain any leftover stdin commands
        while rx.try_recv().is_ok() {}

        // Drain discovered peers — solve PoW outside the lock so the
        // 1-3s cuckatoo solve doesn't stall the main loop.
        let pending: Vec<std::net::SocketAddr> = {
            let mut n = node.lock().unwrap();
            std::mem::take(&mut n.pending_discovered)
        };
        for peer_addr in pending {
            eprintln!("connecting to {} (solving handshake PoW)...", peer_addr);
            let len = node.lock().unwrap().add_peer(peer_addr);
            if len > 0 {
                eprintln!("  handshake init sent ({} bytes)", len);
            }
        }

        match socket.recv_from(&mut buf) {
            Ok((len, src)) => {
                if let Some(resp) = node.lock().unwrap().process(src, &buf[..len]) {
                    send_datagrams(&socket, src, &resp);
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
            Err(_) => {}
        }
        let outbound = {
            let mut n = node.lock().unwrap();
            let ob = n.cycle();
            // Sync block counter so the mining pool detects new blocks (mined or received).
            block_count_main.store(n.accepted_blocks, std::sync::atomic::Ordering::Relaxed);
            // Status — do it here while we hold the lock, no second acquisition
            if n.ticks.saturating_sub(last_status) >= 400 {
                last_status = n.ticks;
                let m = n.merkle();
                if n.mining_cores > 0 {
                    let h = hash_count_status.load(std::sync::atomic::Ordering::Relaxed);
                    let elapsed = mining_since_status.lock().unwrap()
                        .map(|t| t.elapsed().as_secs().max(1))
                        .unwrap_or(1);
                    eprintln!("[{}:{}] peers={} limbo={} utxos={} diff={} mine={}c tries={} {}/s merkle={}",
                        n.ticks, addr.port(), n.peer_count(), n.limbo_len(),
                        n.utxo_count(), n.current_difficulty, n.mining_cores,
                        h, h / elapsed, fmt8(&m[..8]));
                } else {
                    eprintln!("[{}:{}] peers={} limbo={} utxos={} diff={} merkle={}",
                        n.ticks, addr.port(), n.peer_count(), n.limbo_len(),
                        n.utxo_count(), n.current_difficulty, fmt8(&m[..8]));
                }
            }
            ob
        };
        for (dest, data) in outbound {
            send_datagrams(&socket, dest, &data);
        }

        std::thread::sleep(Duration::from_millis(5));
    }
}
