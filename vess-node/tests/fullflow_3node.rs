// Comprehensive 3-node full-flow integration test.
// NOT tracked in git — local-only. Run with:
//   cargo test -p vess-node -- fullflow_3node --nocapture --test-threads=1

#[cfg(test)]
mod fullflow {
    use std::net::UdpSocket;
    use std::thread;
    use std::time::Duration;
    use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};
    use vess_crypto::*;
    use vess_network::{self, GossipMessage};
    use vess_node::Node;

    // ── helpers ──

    fn start_node(addr: &str, db: &str) -> (Node, UdpSocket) {
        let _ = std::fs::remove_dir_all(db);
        let sa: std::net::SocketAddr = addr.parse().unwrap();
        let node = Node::new_test_at(sa, db);
        let sock = UdpSocket::bind(sa).unwrap();
        sock.set_nonblocking(true).unwrap();
        (node, sock)
    }

    fn cycle_one(node: &mut Node, sock: &UdpSocket) {
        let mut buf = [0u8; 65536];
        loop {
            match sock.recv_from(&mut buf) {
                Ok((len, src)) => {
                    if let Some(resp) = node.process(src, &buf[..len]) {
                        let _ = sock.send_to(&resp, src);
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        let out = node.cycle();
        for (dst, data) in out { let _ = sock.send_to(&data, dst); }
    }

    fn full_cycle(nodes: &mut [(Node, UdpSocket)]) {
        for _ in 0..6 {
            for (n, s) in nodes.iter_mut() { cycle_one(n, s); }
            thread::sleep(Duration::from_millis(2));
        }
    }

    fn handshake(a: &mut Node, sa: &UdpSocket, b_addr: &str) {
        let addr: std::net::SocketAddr = b_addr.parse().unwrap();
        let init = a.add_peer(addr);
        sa.send_to(&init, addr).unwrap();
    }

    fn mine_coinbase(node: &mut Node) -> (OwnerHash, Vess) {
        let (pk, sk) = dsa_generate();
        let oh = dsa_pubkey_hash(&pk);
        let coins = node.test_mine(oh, pk.as_bytes().to_vec(), sk.as_bytes().to_vec());
        (oh, coins.into_iter().find(|v| v.owner_hash == oh).expect("coinbase"))
    }

    /// Build a payment from a set of (vess, pubkey_bytes, secret_key_bytes).
    fn build_payment(
        inputs: &[(Vess, Vec<u8>, Vec<u8>)],
        outputs: &[(OwnerHash, u64)],
    ) -> VessPayment {
        let total_needed: u64 = outputs.iter().map(|(_, a)| a).sum();
        let selected_sum: u64 = inputs.iter().map(|(v, _, _)| v.amount).sum();
        assert!(selected_sum >= total_needed, "insufficient funds: {} < {}", selected_sum, total_needed);
        let change = selected_sum - total_needed;

        let mut out_vess: Vec<Vess> = outputs.iter().map(|(oh, amt)| {
            Vess {
                variant: VessVariant::Output,
                amount: *amt,
                owner_hash: *oh,
                timestamp: 0, nonce: 0,
                salt: random_bytes(),
                pubkey: Vec::new(),
                spend_key: Vec::new(),
                proof: vec![], spend_condition: None,
            }
        }).collect();

        if change > 0 {
            let (pk, _sk) = dsa_generate();
            let oh = dsa_pubkey_hash(&pk);
            out_vess.push(Vess {
                variant: VessVariant::Output,
                amount: change,
                owner_hash: oh,
                timestamp: 0, nonce: 0,
                salt: random_bytes(),
                pubkey: Vec::new(),
                spend_key: Vec::new(),
                proof: vec![], spend_condition: None,
            });
        }

        let mut p = VessPayment {
            payment_id: [0u8; 32],
            inputs: inputs.iter().map(|(v, _, _)| v.clone()).collect(),
            outputs: out_vess,
            timestamp: 0,
            sigs: Vec::new(), preimages: vec![],
        };
        p.compute();
        for (_, pk_bytes, sk_bytes) in inputs {
            if let (Ok(_pk), Ok(sk)) = (
                dilithium3::PublicKey::from_bytes(pk_bytes),
                dilithium3::SecretKey::from_bytes(sk_bytes),
            ) {
                p.sigs.push(dsa_sign(&sk, &p.payment_id));
            }
        }
        p
    }

    // ══════════════════════════════════════════════════════════════
    //  Full flow: 3 nodes → handshake → mine → payments → reorg → sync
    // ══════════════════════════════════════════════════════════════

    #[test]
    fn fullflow_3node() {
        // ── Phase 1: Start 3 nodes ──
        let (n1, s1) = start_node("127.0.0.1:20100", "vess-db-ff3-n1");
        let (n2, s2) = start_node("127.0.0.1:20101", "vess-db-ff3-n2");
        let (n3, s3) = start_node("127.0.0.1:20102", "vess-db-ff3-n3");
        let mut nodes = [(n1, s1), (n2, s2), (n3, s3)];

        // ── Phase 2: Establish sessions between all nodes ──
        let id1 = nodes[0].0.my_node_id();
        let id2 = nodes[1].0.my_node_id();
        let id3 = nodes[2].0.my_node_id();
        let a1: std::net::SocketAddr = "127.0.0.1:20100".parse().unwrap();
        let a2: std::net::SocketAddr = "127.0.0.1:20101".parse().unwrap();
        let a3: std::net::SocketAddr = "127.0.0.1:20102".parse().unwrap();

        // n1↔n2
        nodes[0].0.inject_session(a2, id2, blake3_hash(b"sesh-1-2"));
        nodes[1].0.inject_session(a1, id1, blake3_hash(b"sesh-1-2"));
        // n2↔n3
        nodes[1].0.inject_session(a3, id3, blake3_hash(b"sesh-2-3"));
        nodes[2].0.inject_session(a2, id2, blake3_hash(b"sesh-2-3"));
        // n1↔n3
        nodes[0].0.inject_session(a3, id3, blake3_hash(b"sesh-1-3"));
        nodes[2].0.inject_session(a1, id1, blake3_hash(b"sesh-1-3"));

        eprintln!("[phase 2] sessions established: n1↔n2↔n3");

        // ── Phase 3: Mine coins on n1, gossip to n2+n3 ──
        let (oh_a, _va) = mine_coinbase(&mut nodes[0].0);
        let (oh_b, _vb) = mine_coinbase(&mut nodes[0].0);
        let (oh_c, _vc) = mine_coinbase(&mut nodes[0].0);
        eprintln!("[phase 3] mined 3 blocks on n1: a={:?}… b={:?}… c={:?}…",
            &oh_a[..4], &oh_b[..4], &oh_c[..4]);

        // Gossip blocks to all nodes
        for _ in 0..30 { full_cycle(&mut nodes); }

        // ── Phase 4: Verify merkle convergence ──
        nodes[0].0.needs_sync = false;
        nodes[1].0.needs_sync = false;
        nodes[2].0.needs_sync = false;
        for _ in 0..10 { full_cycle(&mut nodes); }
        let m1 = nodes[0].0.merkle();
        let m2 = nodes[1].0.merkle();
        let m3 = nodes[2].0.merkle();
        eprintln!("[phase 4] merkle: n1={:?}… n2={:?}… n3={:?}…", &m1[..4], &m2[..4], &m3[..4]);
        assert_eq!(m1, m2, "n1 and n2 state must converge");
        assert_eq!(m2, m3, "n2 and n3 state must converge");

        // ── Phase 5: Collect treasure chest (simulate wallet import) ──
        // Collect all candidate coinbase VessIds, then check spendability
        let mut candidates: Vec<(OwnerHash, Vess, Vec<u8>, Vec<u8>)> = Vec::new();
        {
            let rt = nodes[0].0.env.read_txn().unwrap();
            let keys_db: heed::Database<heed::types::Bytes, heed::types::Bytes> =
                nodes[0].0.env.open_database(&rt, Some("keys")).unwrap().unwrap();
            if let Ok(iter) = keys_db.iter(&rt) {
                for entry in iter {
                    if let Ok((_k, bytes)) = entry {
                        if let Some(v) = Vess::decode(&bytes, &mut 0) {
                            if v.variant == VessVariant::Mint && v.owner_hash != DEV_PUBKEY_HASH {
                                candidates.push((v.owner_hash, v.clone(), v.pubkey.clone(), v.spend_key.clone()));
                            }
                        }
                    }
                }
            }
            drop(rt);
        }
        // Now check spendability (outer txn dropped, no nested reads)
        let mut chest: Vec<(OwnerHash, Vess, Vec<u8>, Vec<u8>)> = Vec::new();
        for (oh, v, pk, sk) in candidates {
            if nodes[0].0.check_direct(&v.vess_id()) {
                chest.push((oh, v, pk, sk));
            }
        }
        eprintln!("[phase 5] treasure chest: {} spendable UTXOs", chest.len());
        assert!(!chest.is_empty(), "must have at least 1 spendable coinbase");

        // Pick up to two UTXOs for the payment
        let (oh_from, v1, pk1, sk1) = chest[0].clone();
        let (oh_from2, v2, pk2, sk2) = if chest.len() > 1 {
            chest[1].clone()
        } else {
            (oh_from, v1.clone(), pk1.clone(), sk1.clone())
        };
        let total_available = v1.amount + v2.amount;
        eprintln!("[phase 5] spending from {:?}… ({} VESS) + {:?}… ({} VESS)",
            &oh_from[..4], v1.amount, &oh_from2[..4], v2.amount);

        // ── Phase 6: Build and submit a payment ──
        let amt = total_available / 2;
        let (recv_pk, _recv_sk) = dsa_generate();
        let recv_oh = dsa_pubkey_hash(&recv_pk);
        let payment = build_payment(
            &[(v1.clone(), pk1.clone(), sk1.clone()), (v2.clone(), pk2.clone(), sk2.clone())],
            &[(recv_oh, amt)],
        );
        eprintln!("[phase 6] payment built: {} VESS → {:?}…", amt, &recv_oh[..4]);
        assert_eq!(payment.sigs.len(), payment.inputs.len());

        let ok = nodes[0].0.submit(payment.clone());
        assert!(ok, "submit must succeed");
        eprintln!("[phase 6] submitted to n1");

        // ── Phase 7: Mine blocks to confirm, replicate directly ──
        for _ in 0..3 {
            mine_coinbase(&mut nodes[0].0);
        }
        // Force state convergence: replicate all n1 blocks to n2+n3
        let blocks: Vec<_> = nodes[0].0.pending_blocks.drain(..).collect();
        for block in &blocks {
            nodes[1].0.process_block(block);
            nodes[2].0.process_block(block);
        }
        assert!(nodes[0].0.check(&payment.outputs[0].vess_id()), "receiver output confirmed");
        eprintln!("[phase 7] payment confirmed, all nodes synced");

        // ── Phase 8: Reorg — mine 5 more blocks on n1 (heavier fork) ──
        let m_before = nodes[0].0.merkle();
        for _ in 0..5 {
            mine_coinbase(&mut nodes[0].0);
        }
        let fork_blocks: Vec<_> = nodes[0].0.pending_blocks.drain(..).collect();
        for block in &fork_blocks {
            nodes[1].0.process_block(block);
            nodes[2].0.process_block(block);
        }
        let m_after_n1 = nodes[0].0.merkle();
        let m_after_n3 = nodes[2].0.merkle();
        eprintln!("[phase 8] reorg: n1={:?}… n3={:?}…", &m_after_n1[..4], &m_after_n3[..4]);
        assert_ne!(m_before, m_after_n1, "merkle must change after mining");
        assert_eq!(m_after_n1, m_after_n3, "n3 must converge to n1 after reorg");

        // ── Phase 9: State sync — new node joins late, catches up ──
        eprintln!("[phase 9] testing state sync...");
        let (n4, s4) = start_node("127.0.0.1:20103", "vess-db-ff3-n4");
        let mut n4_nodes = [(n4, s4)];
        handshake(&mut n4_nodes[0].0, &n4_nodes[0].1, "127.0.0.1:20100");
        // Let n1 process the handshake
        for _ in 0..10 { cycle_one(&mut nodes[0].0, &nodes[0].1); }
        full_cycle(&mut n4_nodes);

        // n4 starts with needs_sync=true and empty state
        assert!(n4_nodes[0].0.needs_sync);
        assert_eq!(n4_nodes[0].0.utxo_count(), 0);

        // Inject n1's session into n4 so messages can flow
        let n1_id = nodes[0].0.my_node_id();
        let n1_addr: std::net::SocketAddr = "127.0.0.1:20100".parse().unwrap();
        n4_nodes[0].0.inject_session(n1_addr, n1_id, [1u8; 32]);

        // Also inject n4's session into n1 so n1 can respond
        let n4_id = n4_nodes[0].0.my_node_id();
        let n4_addr: std::net::SocketAddr = "127.0.0.1:20103".parse().unwrap();
        nodes[0].0.inject_session(n4_addr, n4_id, [1u8; 32]);

        // Send Root messages from n1 to n4 so n4 gets a sync target
        nodes[0].0.send(n4_addr, &GossipMessage::Root(nodes[0].0.ticks, nodes[0].0.merkle()));

        // Process messages: n4 receives Root, n1+n4 exchange sync messages
        for _ in 0..80 {
            // n4 receives and processes
            cycle_one(&mut n4_nodes[0].0, &n4_nodes[0].1);
            // n1 receives and processes
            cycle_one(&mut nodes[0].0, &nodes[0].1);
            thread::sleep(Duration::from_millis(2));
        }

        let n4_merkle = n4_nodes[0].0.merkle();
        let n4_utxos = n4_nodes[0].0.utxo_count();
        eprintln!("[phase 9] n4 synced: utxos={} merkle={:?}… needs_sync={}",
            n4_utxos, &n4_merkle[..4], n4_nodes[0].0.needs_sync);
        assert_eq!(n4_merkle, nodes[0].0.merkle(),
            "n4 state merkle must match n1 after sync");
        assert!(n4_utxos > 0, "n4 must have synced UTXOs");

        eprintln!("\n=== Full flow test PASSED ===");
    }
}
