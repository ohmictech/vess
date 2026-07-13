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

    // Bootstrap connections
    for bp in &bootstrap {
        if let Ok(bs) = bp.parse::<std::net::SocketAddr>() {
            eprintln!("bootstrapping to {} (solving handshake PoW)...", bs);
            let init = node.add_peer(bs);
            if !init.is_empty() {
                let _ = socket.send_to(&init, bs);
                eprintln!("  handshake init sent ({} bytes)", init.len());
            }
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
