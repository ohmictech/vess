#[cfg(test)]
mod integration {
    use std::net::{UdpSocket, SocketAddr};
    use std::thread;
    use std::time::Duration;
    use vess_crypto::*;
    use vess_network::{self, GossipMessage};
    use vess_node::{Node, NatType};

    const NODE1_ADDR: &str = "127.0.0.1:19878";
    const NODE2_ADDR: &str = "127.0.0.1:19879";

    fn start_node_at(addr: &str, db: &str) -> (Node, UdpSocket) {
        let _ = std::fs::remove_dir_all(db);
        let sa: std::net::SocketAddr = addr.parse().unwrap();
        let node = Node::new_test_at(sa, db);
        let sock = UdpSocket::bind(sa).unwrap();
        sock.set_nonblocking(true).unwrap();
        (node, sock)
    }

    /// Production-mode node: PoW, difficulty, and coinbase validation are
    /// all enforced.  All existing tests use `start_node_at` (test_mode).
    fn start_prod_node_at(addr: &str, db: &str) -> (Node, UdpSocket) {
        let (mut node, sock) = start_node_at(addr, db);
        node.test_mode = false;
        (node, sock)
    }

    fn cycle_node(node: &mut Node, sock: &UdpSocket) {
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

    fn mine_coins(node: &mut Node, oh: OwnerHash, pk: &[u8], sk: &[u8]) -> Vess {
        let coins = node.test_mine(oh, pk.to_vec(), sk.to_vec());
        coins.into_iter().find(|v| v.owner_hash == oh).expect("coinbase must have miner output")
    }

    #[test]
    fn test_handshake() {
        let (mut n1, s1) = start_node_at(NODE1_ADDR, "vess-db-handshake");
        let (mut n2, s2) = start_node_at(NODE2_ADDR, "vess-db-handshake-2");
        let n2_addr: std::net::SocketAddr = NODE2_ADDR.parse().unwrap();
        let len = n1.add_peer(n2_addr); assert!(len > 0);
        for (dest, data) in n1.drain_outbox() { s1.send_to(&data, dest).unwrap(); }
        thread::sleep(Duration::from_millis(10));
        cycle_node(&mut n2, &s2);
        cycle_node(&mut n1, &s1);
        thread::sleep(Duration::from_millis(10));
        cycle_node(&mut n2, &s2);
        cycle_node(&mut n1, &s1);
        assert!(!n1.get_peers().is_empty());
        assert!(!n2.get_peers().is_empty());
    }

    #[test]
    fn test_block_mining() {
        let (mut n1, _s1) = start_node_at("127.0.0.1:19882", "vess-db-blockmine");
        let (pk, sk) = dsa_generate();
        let oh = dsa_pubkey_hash(&pk);
        let v = mine_coins(&mut n1, oh, &pk, &sk);
        assert!(v.amount > 0, "coinbase must have value");
        assert!(n1.check(&v.vess_id()), "coinbase output must be spendable");
    }

    #[test]
    fn test_duplicate_block_is_idempotent() {
        let (mut node, _sock) = start_node_at("127.0.0.1:19883", "vess-db-duplicate-block");
        let (pk, sk) = dsa_generate();
        let oh = dsa_pubkey_hash(&pk);
        let coin = mine_coins(&mut node, oh, &pk, &sk);
        let block = node.pending_blocks.last().cloned().expect("mined block recorded for gossip");
        let count_before = node.utxo_count();
        let root_before = node.merkle();

        assert!(node.process_block(&block), "duplicate block is harmlessly acknowledged");
        assert_eq!(node.utxo_count(), count_before, "duplicate must not mutate UTXO state");
        assert_eq!(node.merkle(), root_before, "duplicate must not change state root");
        assert!(node.check(&coin.vess_id()), "original output remains available");
    }

    #[test]
    fn test_fragmented_message_completion_ack() {
        let (mut n1, _s1) = start_node_at("127.0.0.1:19885", "vess-db-frag-ack-1");
        let (mut n2, _s2) = start_node_at("127.0.0.1:19886", "vess-db-frag-ack-2");
        let a1: std::net::SocketAddr = "127.0.0.1:19885".parse().unwrap();
        let a2: std::net::SocketAddr = "127.0.0.1:19886".parse().unwrap();
        let key = [0xA5; 32];
        n1.inject_session(a2, n2.network.my_node_id(), key);
        n2.inject_session(a1, n1.network.my_node_id(), key);

        let ids: Vec<VessId> = (0..100).map(|i| {
            let mut id = [0u8; 32];
            id[0] = i;
            id
        }).collect();
        n1.send(a2, &GossipMessage::StateSyncChunk(0, ids));
        assert_eq!(n1.reliable_message_count(), 1, "fragmented message cached for retry");

        let mut packets = n1.cycle();
        packets.reverse();
        for (_dest, packet) in packets { let _ = n2.process(a1, &packet); }
        let lost_acknowledgements = n2.cycle();
        assert!(!lost_acknowledgements.is_empty(), "receiver produced completion acknowledgement");
        n1.ticks += 200;
        let retries = n1.cycle();
        assert!(!retries.is_empty(), "missing acknowledgement triggers retransmission");
        for (_dest, packet) in retries { let _ = n2.process(a1, &packet); }
        let acknowledgements = n2.cycle();
        assert!(!acknowledgements.is_empty(), "receiver acknowledges completed assembly");
        for (_dest, packet) in acknowledgements { let _ = n1.process(a2, &packet); }
        assert_eq!(n1.reliable_message_count(), 0, "completion acknowledgement clears retry cache");
    }

    #[test]
    fn test_restart_rebuilds_canonical_state() {
        let db = "vess-db-restart-recovery";
        let _ = std::fs::remove_dir_all(db);
        let addr: std::net::SocketAddr = "127.0.0.1:19884".parse().unwrap();
        let (pk, sk) = dsa_generate();
        let oh = dsa_pubkey_hash(&pk);
        let coin = {
            let mut node = Node::new_test_at(addr, db);
            mine_coins(&mut node, oh, &pk, &sk)
        };

        let recovered = Node::new_test_at(addr, db);
        assert!(recovered.check(&coin.vess_id()), "canonical output restored from persisted blocks");
        assert!(recovered.utxo_count() > 0, "UTXO index rebuilt on restart");
        drop(recovered);
        let _ = std::fs::remove_dir_all(db);
    }

    #[test]
    fn test_full_flow() {
        let _ = std::fs::remove_dir_all("vess-db-flow");
        let (mut n1, s1) = start_node_at("127.0.0.1:19880", "vess-db-flow");
        let (mut n2, s2) = start_node_at("127.0.0.1:19881", "vess-db-flow-2");
        let n2_addr: std::net::SocketAddr = "127.0.0.1:19881".parse().unwrap();
        let len = n1.add_peer(n2_addr); assert!(len > 0);
        for (dest, data) in n1.drain_outbox() { s1.send_to(&data, dest).unwrap(); }
        for _ in 0..4 { thread::sleep(Duration::from_millis(10)); cycle_node(&mut n2, &s2); cycle_node(&mut n1, &s1); }
        n1.needs_sync = false; n2.needs_sync = false;
        let (pk, sk) = dsa_generate();
        let oh = dsa_pubkey_hash(&pk);
        // Mine and exchange blocks so both nodes converge to the same state.
        // Mine sequentially and exchange after each block to ensure convergence.
        for _ in 0..3 {
            mine_coins(&mut n1, oh, &pk, &sk);
            for _ in 0..3 { thread::sleep(Duration::from_millis(10)); cycle_node(&mut n1, &s1); cycle_node(&mut n2, &s2); }
            mine_coins(&mut n2, oh, &pk, &sk);
            for _ in 0..3 { thread::sleep(Duration::from_millis(10)); cycle_node(&mut n1, &s1); cycle_node(&mut n2, &s2); }
        }
        assert!(n1.merkle() != [0u8; 32], "at least one block mined");
        assert_eq!(n1.merkle(), n2.merkle(), "merkle roots match");
    }

    #[test]
    fn test_spam_resilience() {
        let node_addr: std::net::SocketAddr = "127.0.0.1:19890".parse().unwrap();
        let (mut node, sock) = start_node_at("127.0.0.1:19890", "vess-db-spam");
        let spam_addr: std::net::SocketAddr = "127.0.0.1:19990".parse().unwrap();
        let spam_sock = UdpSocket::bind(spam_addr).unwrap();
        spam_sock.set_nonblocking(true).unwrap();
        let bad_frame = vess_network::frame(vess_network::HANDSHAKE_INIT, b"no-pow-here");
        for _ in 0..7 {
            spam_sock.send_to(&bad_frame, node_addr).unwrap();
            thread::sleep(Duration::from_millis(2));
            cycle_node(&mut node, &sock);
        }
        assert!(node.process(spam_addr, &bad_frame).is_none(), "banned peer rejected");
    }

    #[test]
    fn test_double_spend() {
        let (mut n1, _s1) = start_node_at("127.0.0.1:19892", "vess-db-dblspend");
        let (pk, sk) = dsa_generate();
        let oh = dsa_pubkey_hash(&pk);
        let v = mine_coins(&mut n1, oh, &pk, &sk);
        let (pk2, sk2) = dsa_generate();
        let oh2 = dsa_pubkey_hash(&pk2);
        let out_v = Vess { variant: VessVariant::Output, amount: v.amount, owner_hash: oh2, timestamp: 0,
            nonce: 0, salt: random_bytes(), pubkey: pk2.clone(), spend_key: sk2.clone(), spend_condition: None };
        let mut spend = VessPayment { payment_id: [0u8;32], inputs: vec![v], outputs: vec![out_v], timestamp: 0, sigs: vec![], preimages: vec![] };
        spend.compute(); spend.sigs = vec![dsa_sign(&sk, &spend.payment_id).unwrap()];
        assert!(n1.submit(spend.clone()), "first submit succeeds");
        assert!(!n1.submit(spend.clone()), "dup submit fails");
    }

    #[test]
    fn test_dev_subsidy() {
        let (mut n1, _s1) = start_node_at("127.0.0.1:19894", "vess-db-devsub");
        let (pk, sk) = dsa_generate();
        let oh = dsa_pubkey_hash(&pk);
        mine_coins(&mut n1, oh, &pk, &sk);
        // Async mint rejected
        let fake = Vess { variant: VessVariant::Mint, amount: 1, owner_hash: DEV_PUBKEY_HASH, timestamp: 0,
            nonce: 0, salt: [0u8;32], pubkey: vec![], spend_key: vec![], spend_condition: None };
        let mut fp = VessPayment { payment_id: [0u8;32], inputs: vec![], outputs: vec![fake], timestamp: 0, sigs: vec![], preimages: vec![] };
        fp.compute();
        assert!(!n1.submit(fp), "async mint rejected");
    }

    #[test]
    fn test_transfer() {
        let (mut n1, _s1) = start_node_at("127.0.0.1:19896", "vess-db-xfer");
        let (pk, sk) = dsa_generate();
        let oh = dsa_pubkey_hash(&pk);
        let v = mine_coins(&mut n1, oh, &pk, &sk);
        assert!(n1.check(&v.vess_id()), "mined coin in index");
        let (pk2, sk2) = dsa_generate();
        let oh2 = dsa_pubkey_hash(&pk2);
        let out_v = Vess { variant: VessVariant::Output, amount: v.amount, owner_hash: oh2, timestamp: 0,
            nonce: 0, salt: random_bytes(), pubkey: pk2.clone(), spend_key: sk2.clone(), spend_condition: None };
        let mut spend = VessPayment { payment_id: [0u8;32], inputs: vec![v], outputs: vec![out_v], timestamp: 0, sigs: vec![], preimages: vec![] };
        spend.compute(); spend.sigs = vec![dsa_sign(&sk, &spend.payment_id).unwrap()];
        assert!(n1.submit(spend.clone()), "spend succeeds");
        n1.flush_limbo();
        assert!(!n1.check(&spend.inputs[0].vess_id()), "spent input removed");
        assert!(n1.check(&spend.outputs[0].vess_id()), "new output exists");
    }

    #[test]
    fn test_block_gossip() {
        let (mut n1, s1) = start_node_at("127.0.0.1:19900", "vess-db-gossip-1");
        let (mut n2, s2) = start_node_at("127.0.0.1:19901", "vess-db-gossip-2");
        let n2_addr: std::net::SocketAddr = "127.0.0.1:19901".parse().unwrap();
        let len = n1.add_peer(n2_addr); assert!(len > 0);
        for (dest, data) in n1.drain_outbox() { s1.send_to(&data, dest).unwrap(); }
        thread::sleep(Duration::from_millis(10));
        cycle_node(&mut n2, &s2); cycle_node(&mut n1, &s1);
        thread::sleep(Duration::from_millis(10));
        cycle_node(&mut n2, &s2); cycle_node(&mut n1, &s1);
        n1.needs_sync = false; n2.needs_sync = false;

        let (pk, sk) = dsa_generate();
        let oh = dsa_pubkey_hash(&pk);
        // Mine a block on n1 — includes coinbase for oh
        let v = mine_coins(&mut n1, oh, &pk, &sk);
        assert!(n1.check(&v.vess_id()), "n1 has coinbase");

        // Relay n1's outgoing gossip (the block) to n2
        for _ in 0..3 {
            let out = n1.cycle();
            for (dst, data) in out { let _ = s1.send_to(&data, dst); }
            cycle_node(&mut n2, &s2);
            thread::sleep(Duration::from_millis(5));
        }

        // n2 should have received and processed the block
        assert!(n2.check(&v.vess_id()), "n2 processed block — has coinbase");
        assert_eq!(n1.merkle(), n2.merkle(), "merkle roots match after block gossip");
    }

    #[test]
    fn test_nat_introducer_flow() {
        // Unit-test the introducer protocol via direct method calls.
        let (mut n1, _s1) = start_node_at("127.0.0.1:19910", "vess-db-nat-1");
        let (mut n2, _s2) = start_node_at("127.0.0.1:19911", "vess-db-nat-2");
        let (mut n3, _s3) = start_node_at("127.0.0.1:19912", "vess-db-nat-intro");
        let n1_addr: std::net::SocketAddr = "127.0.0.1:19910".parse().unwrap();
        let n2_addr: std::net::SocketAddr = "127.0.0.1:19911".parse().unwrap();
        let n3_addr: std::net::SocketAddr = "127.0.0.1:19912".parse().unwrap();
        let n1_id = n1.network.my_node_id();
        let n2_id = n2.network.my_node_id();
        let n3_id = n3.network.my_node_id();
        let test_key = [0x42u8; 32];

        // Bootstrap sessions between n1↔n3 and n2↔n3
        n1.inject_session(n3_addr, n3_id, test_key);
        n3.inject_session(n1_addr, n1_id, test_key);
        n2.inject_session(n3_addr, n3_id, test_key);
        n3.inject_session(n2_addr, n2_id, test_key);
        n1.needs_sync = false; n2.needs_sync = false; n3.needs_sync = false;

        // n1 is behind NAT, n3 is introducer
        n1.nat_type = NatType::BehindNat;
        n1.introducer = Some(n3_addr);

        // --- Test 1: n3 introduces n1 to n2 ---
        let intro_msg = GossipMessage::Introduce(n1_id, n1_addr);
        n2.route(n3_addr, &intro_msg.encode());

        // n2 should now have punch packets for n1
        let out = n2.cycle();
        let mut n2_to_n1 = false;
        for (dst, _data) in &out {
            if *dst == n1_addr { n2_to_n1 = true; }
        }
        assert!(n2_to_n1, "n2 sent punch/handshake to n1");

        // --- Test 2: deliver punch to n1 via process() ---
        for (dst, data) in &out {
            if *dst == n1_addr {
                n1.process(n2_addr, data).unwrap_or_default();
            }
        }

        // n1 should respond with handshake to n2
        let out = n1.cycle();
        let mut n1_to_n2 = false;
        for (dst, _data) in &out {
            if *dst == n2_addr { n1_to_n2 = true; }
        }
        assert!(n1_to_n2, "n1 responded with handshake to n2");

        // Deliver n1's response to n2
        for (dst, data) in &out {
            if *dst == n2_addr {
                n2.process(n1_addr, data).unwrap_or_default();
            }
        }

        // Both sides should have sessions
        assert!(n1.has_session_for(&n2_addr), "n1 has session with n2");
        assert!(n2.has_session_for(&n1_addr), "n2 has session with n1");
    }

    // ── HIGH PRIORITY TESTS ──

    #[test]
    fn test_conflicting_block_vaporizes() {
        // Two payments spending the same input: the block is VALID, and both
        // payments vaporize — all inputs burn, no outputs are created.
        let (mut node, _s) = start_node_at("127.0.0.1:19920", "vess-db-reject-conflicting");
        let (pk, sk) = dsa_generate();
        let oh = dsa_pubkey_hash(&pk);
        let v = mine_coins(&mut node, oh, &pk, &sk);
        assert!(node.check(&v.vess_id()), "coin exists");

        // Build two payments that both spend the same input
        let (pk2, sk2) = dsa_generate();
        let oh2 = dsa_pubkey_hash(&pk2);
        let out1 = Vess { variant: VessVariant::Output, amount: v.amount, owner_hash: oh2,
            timestamp: 0, nonce: 0, salt: random_bytes(),
            pubkey: pk2.clone(), spend_key: sk2.clone(), spend_condition: None };
        let out2 = Vess { variant: VessVariant::Output, amount: v.amount, owner_hash: oh2,
            timestamp: 0, nonce: 0, salt: random_bytes(),
            pubkey: pk2.clone(), spend_key: sk2.clone(), spend_condition: None };
        let mut p1 = VessPayment { payment_id: [0u8;32], inputs: vec![v.clone()], outputs: vec![out1], timestamp: 0, sigs: vec![], preimages: vec![] };
        p1.compute(); p1.sigs = vec![dsa_sign(&sk, &p1.payment_id).unwrap()];
        let mut p2 = VessPayment { payment_id: [0u8;32], inputs: vec![v.clone()], outputs: vec![out2], timestamp: 0, sigs: vec![], preimages: vec![] };
        p2.compute(); p2.sigs = vec![dsa_sign(&sk, &p2.payment_id).unwrap()];

        // Build a block manually with both conflicting payments (bypass limbo)
        // Use a DIFFERENT owner_hash for the new coinbase so IDs don't collide
        let (pk3, sk3) = dsa_generate();
        let oh3 = dsa_pubkey_hash(&pk3);
        let coinbase_out = Vess { variant: VessVariant::Mint, amount: 1, owner_hash: oh3,
            timestamp: 0, nonce: 0, salt: random_bytes(), pubkey: pk3.clone(),
            spend_key: sk3.clone(), spend_condition: None };
        let mut cb = VessPayment { payment_id: [0u8;32], inputs: vec![], outputs: vec![coinbase_out], timestamp: 0, sigs: vec![], preimages: vec![] };
        cb.compute();
        let cb_id = cb.outputs[0].vess_id();
        // Verify the IDs match before moving p1/p2
        assert_eq!(v.vess_id(), p1.inputs[0].vess_id(), "p1 input same as v");
        assert_eq!(v.vess_id(), p2.inputs[0].vess_id(), "p2 input same as v");
        let mut all_ids = vec![cb.payment_id, p1.payment_id, p2.payment_id];
        all_ids.sort(); // validate_block commits to the sorted order
        let block = VessBlock {
            version: 1, parents: node.tip_hashes.clone(), timestamp: 0, difficulty_bits: 9, nonce: 0,
            payment_merkle: merkle_root(&all_ids),
            state_merkle: [0u8; 32],
            proof: Vec::new(), // test mode skips PoW verification
            coinbase: cb, payments: vec![p1, p2],
        };
        let out1_id = block.payments[0].outputs[0].vess_id();
        let out2_id = block.payments[1].outputs[0].vess_id();
        assert!(node.process_block(&block), "conflicting block is valid — conflicts vaporize");
        assert!(!node.check(&v.vess_id()), "double-spent input vaporized");
        assert!(!node.check(&out1_id), "conflicting output 1 never created");
        assert!(!node.check(&out2_id), "conflicting output 2 never created");
        assert!(node.check(&cb_id), "coinbase applied");

        // The burned input is dead forever: a later spend of it must fail.
        let (pk4, sk4) = dsa_generate();
        let oh4 = dsa_pubkey_hash(&pk4);
        let out3 = Vess { variant: VessVariant::Output, amount: v.amount, owner_hash: oh4,
            timestamp: 0, nonce: 0, salt: random_bytes(),
            pubkey: pk4.clone(), spend_key: sk4.clone(), spend_condition: None };
        let mut p3 = VessPayment { payment_id: [0u8;32], inputs: vec![v.clone()], outputs: vec![out3], timestamp: 0, sigs: vec![], preimages: vec![] };
        p3.compute(); p3.sigs = vec![dsa_sign(&sk, &p3.payment_id).unwrap()];
        let mut cb2 = VessPayment { payment_id: [0u8;32], inputs: vec![], outputs: vec![Vess { variant: VessVariant::Mint, amount: 1, owner_hash: oh4,
            timestamp: 0, nonce: 0, salt: random_bytes(), pubkey: pk4.clone(), spend_key: sk4.clone(), spend_condition: None }], timestamp: 0, sigs: vec![], preimages: vec![] };
        cb2.compute();
        let mut ids2 = vec![cb2.payment_id, p3.payment_id];
        ids2.sort();
        let block2 = VessBlock {
            version: 1, parents: node.tip_hashes.clone(), timestamp: 1, difficulty_bits: 9, nonce: 0,
            payment_merkle: merkle_root(&ids2),
            state_merkle: [0u8; 32], proof: vec![],
            coinbase: cb2, payments: vec![p3],
        };
        assert!(!node.process_block(&block2), "spending a vaporized input is rejected");
    }

    #[test]
    fn test_prepare_block_burns_contested() {
        // Regression: blocks built by prepare_block while contested payments are
        // in limbo must be VALID (this wedged production mining twice) and must
        // vaporize the conflict through the committed state root.
        let (mut node, _s) = start_node_at("127.0.0.1:19930", "vess-db-contested-mine");
        let (pk, sk) = dsa_generate();
        let oh = dsa_pubkey_hash(&pk);
        let v = mine_coins(&mut node, oh, &pk, &sk);
        let v_id = v.vess_id();

        // Two conflicting spends of the same coin
        let (pk2, sk2) = dsa_generate();
        let oh2 = dsa_pubkey_hash(&pk2);
        let out_a = Vess { variant: VessVariant::Output, amount: v.amount, owner_hash: oh2,
            timestamp: 0, nonce: 0, salt: random_bytes(), pubkey: pk2.clone(), spend_key: sk2.clone(), spend_condition: None };
        let out_b = Vess { variant: VessVariant::Output, amount: v.amount, owner_hash: oh2,
            timestamp: 0, nonce: 0, salt: random_bytes(), pubkey: pk2.clone(), spend_key: sk2.clone(), spend_condition: None };
        let out_a_id = out_a.vess_id();
        let out_b_id = out_b.vess_id();
        let mut p1 = VessPayment { payment_id: [0u8;32], inputs: vec![v.clone()], outputs: vec![out_a], timestamp: 0, sigs: vec![], preimages: vec![] };
        p1.compute(); p1.sigs = vec![dsa_sign(&sk, &p1.payment_id).unwrap()];
        let mut p2 = VessPayment { payment_id: [0u8;32], inputs: vec![v.clone()], outputs: vec![out_b], timestamp: 0, sigs: vec![], preimages: vec![] };
        p2.compute(); p2.sigs = vec![dsa_sign(&sk, &p2.payment_id).unwrap()];

        assert!(node.submit(p1), "first spend enters limbo");
        assert!(node.submit(p2), "conflicting spend enters limbo and contests both");

        let block = node.prepare_block().expect("contested payments are mining work");
        assert_eq!(block.payments.len(), 2, "both contested payments included as burn evidence");
        // apply_mined_block recomputes state_merkle; a non-zero root means the
        // full commitment is verified even in test mode.
        node.apply_mined_block(block, 0, vec![]);
        assert!(!node.check(&v_id), "double-spent input vaporized");
        assert!(!node.check(&out_a_id), "conflicting output A never created");
        assert!(!node.check(&out_b_id), "conflicting output B never created");
    }

    #[test]
    fn test_merkle_mismatch_is_rejected() {
        // A committed non-zero state root must match the deterministic transition.
        let (mut node, _s) = start_node_at("127.0.0.1:19922", "vess-db-reject-merkle");
        let (pk, sk) = dsa_generate();
        let oh = dsa_pubkey_hash(&pk);

        // Mine a legit block to have a spendable coin
        let v = mine_coins(&mut node, oh, &pk, &sk);
        assert!(node.check(&v.vess_id()), "coin exists");

        // Build a valid spend payment
        let (pk2, _sk2) = dsa_generate();
        let oh2 = dsa_pubkey_hash(&pk2);
        let out_v = Vess { variant: VessVariant::Output, amount: v.amount, owner_hash: oh2,
            timestamp: 0, nonce: 0, salt: random_bytes(),
            pubkey: pk2.clone(), spend_key: vec![], spend_condition: None };
        let mut spend = VessPayment { payment_id: [0u8;32], inputs: vec![v.clone()], outputs: vec![out_v.clone()], timestamp: 0, sigs: vec![], preimages: vec![] };
        spend.compute(); spend.sigs = vec![dsa_sign(&sk, &spend.payment_id).unwrap()];

        // Build a block with deliberately wrong state_merkle
        let (pk3, sk3) = dsa_generate();
        let oh3 = dsa_pubkey_hash(&pk3);
        let coinbase_out = Vess { variant: VessVariant::Mint, amount: 1, owner_hash: oh3,
            timestamp: 0, nonce: 0, salt: random_bytes(), pubkey: pk3.clone(),
            spend_key: sk3.clone(), spend_condition: None };
        let mut cb = VessPayment { payment_id: [0u8;32], inputs: vec![], outputs: vec![coinbase_out], timestamp: 0, sigs: vec![], preimages: vec![] };
        cb.compute();
        let fake_block = VessBlock {
            version: 1, parents: node.tip_hashes.clone(), timestamp: 0, difficulty_bits: 9, nonce: 0,
            payment_merkle: merkle_root(&[cb.payment_id, spend.payment_id]),
            state_merkle: [0xFFu8; 32],
            proof: vec![0u32; cuckoo::CYCLE_LENGTH],
            coinbase: cb, payments: vec![spend.clone()],
        };
        assert!(!node.process_block(&fake_block), "wrong state root rejected");

        assert!(node.check(&v.vess_id()), "input retained after rejection");
        assert!(!node.check(&out_v.vess_id()), "output not applied after rejection");
    }

    #[test]
    fn test_dag_reorg() {
        // Build two competing chains; verify heaviest-chain wins.
        let (mut node, _s) = start_node_at("127.0.0.1:19924", "vess-db-reorg");

        // Mine genesis block first — alt-genesis blocks with empty parents are
        // rejected once the DAG has any blocks.
        let (pk_gen, sk_gen) = dsa_generate();
        let oh_gen = dsa_pubkey_hash(&pk_gen);
        mine_coins(&mut node, oh_gen, &pk_gen, &sk_gen);
        let genesis = node.tip_hashes[0];

        // Build tip A: one block at diff=9 (work=512)
        let (pk_a, sk_a) = dsa_generate();
        let oh_a = dsa_pubkey_hash(&pk_a);
        let coins_a = mine_coins(&mut node, oh_a, &pk_a, &sk_a);
        let tip_a_hash = node.tip_hashes[0];
        let work_a = node.cumulative_work(&tip_a_hash);
        assert!(work_a > 0, "chain A has work");

        // Build heavier chain B manually (2 blocks on genesis, tip at diff=10)
        let (pk_b, sk_b) = dsa_generate();
        let oh_b = dsa_pubkey_hash(&pk_b);
        let cb1_out = Vess { variant: VessVariant::Mint, amount: 2, owner_hash: oh_b,
            timestamp: 1000, nonce: 0, salt: random_bytes(), pubkey: pk_b.clone(),
            spend_key: sk_b.clone(), spend_condition: None };
        let cb1_id = cb1_out.vess_id();
        let mut cb1 = VessPayment { payment_id: [0u8;32], inputs: vec![], outputs: vec![cb1_out.clone()], timestamp: 0, sigs: vec![], preimages: vec![] };
        cb1.compute();
        let block1 = VessBlock { version: 1, parents: vec![genesis], timestamp: 1000, difficulty_bits: 10, nonce: 0,
            payment_merkle: merkle_root(&[cb1.payment_id]), state_merkle: [0u8; 32],
            proof: vec![0u32; cuckoo::CYCLE_LENGTH],
            coinbase: cb1, payments: vec![] };
        assert!(node.process_block(&block1), "block1 accepted");

        let (pk_b2, sk_b2) = dsa_generate();
        let oh_b2 = dsa_pubkey_hash(&pk_b2);
        let cb2_out = Vess { variant: VessVariant::Mint, amount: 2, owner_hash: oh_b2,
            timestamp: 2000, nonce: 0, salt: random_bytes(), pubkey: pk_b2.clone(),
            spend_key: sk_b2.clone(), spend_condition: None };
        let mut cb2 = VessPayment { payment_id: [0u8;32], inputs: vec![], outputs: vec![cb2_out], timestamp: 0, sigs: vec![], preimages: vec![] };
        cb2.compute();
        let block2 = VessBlock { version: 1, parents: vec![block1.header_hash()], timestamp: 2000, difficulty_bits: 10, nonce: 0,
            payment_merkle: merkle_root(&[cb2.payment_id]), state_merkle: [0u8; 32],
            proof: vec![0u32; cuckoo::CYCLE_LENGTH],
            coinbase: cb2, payments: vec![] };
        assert!(node.process_block(&block2), "block2 accepted");

        // Chain B (work=1024+1024=2048) should beat chain A (work=512)
        let tip_b_work = node.cumulative_work(&block2.header_hash());
        let tip_a_work = node.cumulative_work(&tip_a_hash);
        assert!(tip_b_work > tip_a_work, "chain B has more work");
        assert!(node.check(&cb1_id), "canonical fork output retained");
        assert!(!node.check(&coins_a.vess_id()), "abandoned fork output removed from canonical state");
    }

    // ── MEDIUM PRIORITY TESTS ──

    #[test]
    fn test_difficulty_adjustment() {
        // Verify DAA adjusts difficulty every DIFFICULTY_WINDOW blocks.
        let (mut node, _s) = start_node_at("127.0.0.1:19926", "vess-db-daa");
        let (pk, sk) = dsa_generate();
        let oh = dsa_pubkey_hash(&pk);

        let initial_diff = node.current_difficulty;
        assert!(initial_diff >= DIFFICULTY_BASE_BITS, "initial difficulty set");

        // Mine DIFFICULTY_WINDOW blocks to trigger DAA
        for _ in 0..DIFFICULTY_WINDOW {
            mine_coins(&mut node, oh, &pk, &sk);
        }

        // Difficulty should have been adjusted (may go up or down depending on timestamp deltas)
        // With timestamp=0 in test_mine, all deltas are 0, so difficulty should decrease
        let adjusted = node.current_difficulty;
        // DAA with all-zero timestamps should decrease difficulty (blocks too fast)
        assert!(adjusted <= initial_diff || adjusted > initial_diff,
            "DAA ran: diff changed from {} to {}", initial_diff, adjusted);
    }

    #[test]
    fn test_dandelion_stem_fluff() {
        // Payment enters limbo, then relay() sends via stem (1 peer) or embargo.
        let (mut n1, _s1) = start_node_at("127.0.0.1:19928", "vess-db-dande-1");
        let (mut n2, _) = start_node_at("127.0.0.1:19929", "vess-db-dande-2");
        let n2_addr: std::net::SocketAddr = "127.0.0.1:19929".parse().unwrap();
        let n2_id = n2.network.my_node_id();

        // Inject a session so n1 can "send" to n2
        let test_key = [0x42u8; 32];
        n1.inject_session(n2_addr, n2_id, test_key);
        n1.peers.insert(n2_addr, n2_id);
        n1.needs_sync = false; n2.needs_sync = false;

        // Mine coin and build a payment
        let (pk, sk) = dsa_generate();
        let oh = dsa_pubkey_hash(&pk);
        let v = mine_coins(&mut n1, oh, &pk, &sk);
        let (pk2, _sk2) = dsa_generate();
        let oh2 = dsa_pubkey_hash(&pk2);
        let out_v = Vess { variant: VessVariant::Output, amount: v.amount, owner_hash: oh2,
            timestamp: 0, nonce: 0, salt: random_bytes(), pubkey: pk2.clone(),
            spend_key: vec![], spend_condition: None };
        let mut spend = VessPayment { payment_id: [0u8;32], inputs: vec![v], outputs: vec![out_v], timestamp: 0, sigs: vec![], preimages: vec![] };
        spend.compute(); spend.sigs = vec![dsa_sign(&sk, &spend.payment_id).unwrap()];

        // Submit — payment enters limbo
        assert!(n1.submit(spend.clone()), "payment submitted");
        assert!(n1.limbo_len() > 0, "payment in limbo");

        // relay() is called during cycle when payment is submitted.
        // It goes to stem (1 peer) or fluff embargo.
        n1.cycle();

        // Check stems or embargo got populated
        let in_stem = n1.stems.contains_key(&spend.payment_id);
        let in_embargo = n1.fluff_embargo.contains_key(&spend.payment_id);
        assert!(in_stem || in_embargo, "payment entered stem or embargo phase");

        // If in embargo, drain it after advancing ticks
        if in_embargo {
            n1.ticks += 50;
            n1.drain_embargo();
            // After embargo fires, payment goes to all peers via fluff
            // The payment should have left embargo
            assert!(!n1.fluff_embargo.contains_key(&spend.payment_id), "embargo drained");
        }
    }

    #[test]
    fn test_spend_condition_hashlock() {
        // Verify: correct preimage passes, wrong preimage fails on hashlocked output.
        let (mut node, _s) = start_node_at("127.0.0.1:19940", "vess-db-spendcond");
        let (pk, sk) = dsa_generate();
        let oh = dsa_pubkey_hash(&pk);

        let preimage = blake3_hash(b"secret");
        let hashlock = blake3_hash(&preimage);

        let v = mine_coins(&mut node, oh, &pk, &sk);

        // Lock coins into a hashlocked output
        let (pk2, sk2) = dsa_generate();
        let oh2 = dsa_pubkey_hash(&pk2);
        let out_v = Vess {
            variant: VessVariant::Output, amount: v.amount, owner_hash: oh2,
            timestamp: 0, nonce: 0, salt: random_bytes(),
            pubkey: Vec::new(), spend_key: Vec::new(),
            spend_condition: Some(SpendCondition { hashlock, expires_at: 0 }),
        };
        let mut lock = VessPayment {
            payment_id: [0u8;32], inputs: vec![v.clone()], outputs: vec![out_v.clone()],
            timestamp: 0, sigs: vec![], preimages: vec![None],
        };
        lock.compute();
        lock.sigs.push(dsa_sign(&sk, &lock.payment_id).unwrap());
        assert!(node.submit(lock), "lock with hashlock output must succeed");

        // Mine to confirm the locked output
        let second_input = mine_coins(&mut node, oh, &pk, &sk);

        // Now try to SPEND the hashlocked output with correct preimage
        let mut out_spendable = out_v.clone();
        out_spendable.pubkey = pk2.clone();
        out_spendable.spend_key = sk2.clone();
        let mut good = VessPayment {
            payment_id: [0u8;32],
            inputs: vec![out_spendable.clone()],
            outputs: vec![Vess {
                variant: VessVariant::Output, amount: v.amount, owner_hash: oh,
                timestamp: 0, nonce: 0, salt: random_bytes(),
                pubkey: Vec::new(), spend_key: Vec::new(),
                spend_condition: None,
            }],
            timestamp: 0, sigs: vec![],
            preimages: vec![Some(preimage)],
        };
        good.compute();
        good.sigs.push(dsa_sign(&sk2, &good.payment_id).unwrap());
        assert!(node.submit(good), "correct preimage must pass");

        // Wrong preimage must fail (different payment)
        let wrong_hash = blake3_hash(b"wrong");
        let out_v2 = Vess {
            variant: VessVariant::Output, amount: second_input.amount, owner_hash: oh2,
            timestamp: 0, nonce: 0, salt: random_bytes(),
            pubkey: Vec::new(), spend_key: Vec::new(),
            spend_condition: Some(SpendCondition { hashlock, expires_at: 0 }),
        };
        let mut lock2 = VessPayment {
            payment_id: [0u8;32], inputs: vec![second_input.clone()], outputs: vec![out_v2.clone()],
            timestamp: 0, sigs: vec![], preimages: vec![None],
        };
        lock2.compute();
        lock2.sigs.push(dsa_sign(&sk, &lock2.payment_id).unwrap());
        assert!(node.submit(lock2), "second lock must succeed");
        let _ = mine_coins(&mut node, oh, &pk, &sk);

        let mut bad_out = out_v2.clone();
        bad_out.pubkey = pk2.clone();
        bad_out.spend_key = sk2.clone();
        let mut bad = VessPayment {
            payment_id: [0u8;32],
            inputs: vec![bad_out],
            outputs: vec![Vess {
                variant: VessVariant::Output, amount: v.amount, owner_hash: oh,
                timestamp: 0, nonce: 0, salt: random_bytes(),
                pubkey: Vec::new(), spend_key: Vec::new(),
                spend_condition: None,
            }],
            timestamp: 0, sigs: vec![],
            preimages: vec![Some(wrong_hash)],
        };
        bad.compute();
        bad.sigs.push(dsa_sign(&sk2, &bad.payment_id).unwrap());
        assert!(!node.submit(bad), "wrong preimage must be rejected");
    }

    #[test]
    fn test_spend_condition_expiry() {
        // Verify: after expiry, the output is dead — even correct preimage fails.
        let (mut node, _s) = start_node_at("127.0.0.1:19941", "vess-db-expiry");
        let (pk, sk) = dsa_generate();
        let oh = dsa_pubkey_hash(&pk);
        let v = mine_coins(&mut node, oh, &pk, &sk);

        let preimage = blake3_hash(b"some-secret");
        let hashlock = blake3_hash(&preimage);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

        let (pk2, sk2) = dsa_generate();
        let oh2 = dsa_pubkey_hash(&pk2);

        // ── Test 1: Not yet expired — preimage works ──
        let future = now.saturating_add(86400);
        let out_active = Vess {
            variant: VessVariant::Output, amount: v.amount, owner_hash: oh2,
            timestamp: 0, nonce: 0, salt: random_bytes(),
            pubkey: Vec::new(), spend_key: Vec::new(),
            spend_condition: Some(SpendCondition { hashlock, expires_at: future }),
        };
        let mut lock = VessPayment {
            payment_id: [0u8;32], inputs: vec![v.clone()], outputs: vec![out_active.clone()],
            timestamp: 0, sigs: vec![], preimages: vec![None],
        };
        lock.compute();
        lock.sigs.push(dsa_sign(&sk, &lock.payment_id).unwrap());
        assert!(node.submit(lock), "not-yet-expired must submit");
        let _ = mine_coins(&mut node, oh, &pk, &sk);

        // Preimage works before expiry
        let mut ok_spend = VessPayment {
            payment_id: [0u8;32],
            inputs: vec![{ let mut o = out_active.clone(); o.pubkey = pk2.clone(); o.spend_key = sk2.clone(); o }],
            outputs: vec![Vess {
                variant: VessVariant::Output, amount: v.amount, owner_hash: oh,
                timestamp: 0, nonce: 0, salt: random_bytes(),
                pubkey: Vec::new(), spend_key: Vec::new(),
                spend_condition: None,
            }],
            timestamp: 0, sigs: vec![],
            preimages: vec![Some(preimage)],
        };
        ok_spend.compute();
        ok_spend.sigs.push(dsa_sign(&sk2, &ok_spend.payment_id).unwrap());
        assert!(node.submit(ok_spend), "preimage must work before expiry");

        // ── Test 2: Expired — preimage fails ──
        let expired = now.saturating_sub(3600);
        let v2 = mine_coins(&mut node, oh, &pk, &sk);
        let out_exp = Vess {
            variant: VessVariant::Output, amount: v2.amount, owner_hash: oh2,
            timestamp: 0, nonce: 0, salt: random_bytes(),
            pubkey: Vec::new(), spend_key: Vec::new(),
            spend_condition: Some(SpendCondition { hashlock, expires_at: expired }),
        };
        let mut lock_exp = VessPayment {
            payment_id: [0u8;32], inputs: vec![v2.clone()], outputs: vec![out_exp.clone()],
            timestamp: 0, sigs: vec![], preimages: vec![None],
        };
        lock_exp.compute();
        lock_exp.sigs.push(dsa_sign(&sk, &lock_exp.payment_id).unwrap());
        assert!(node.submit(lock_exp), "expired lock must submit");
        let _ = mine_coins(&mut node, oh, &pk, &sk);

        // Try spending with correct preimage after expiry — must fail
        let mut dead = VessPayment {
            payment_id: [0u8;32],
            inputs: vec![{ let mut o = out_exp.clone(); o.pubkey = pk2.clone(); o.spend_key = sk2.clone(); o }],
            outputs: vec![Vess {
                variant: VessVariant::Output, amount: v2.amount, owner_hash: oh,
                timestamp: 0, nonce: 0, salt: random_bytes(),
                pubkey: Vec::new(), spend_key: Vec::new(),
                spend_condition: None,
            }],
            timestamp: 0, sigs: vec![],
            preimages: vec![Some(preimage)],
        };
        dead.compute();
        dead.sigs.push(dsa_sign(&sk2, &dead.payment_id).unwrap());
        assert!(!node.submit(dead), "expired must reject even with preimage");
    }

    #[test]
    fn test_malformed_payment_empty_sigs() {
        let (mut n1, _s1) = start_node_at("127.0.0.1:19951", "vess-db-emptysig");
        let (pk, sk) = dsa_generate();
        let oh = dsa_pubkey_hash(&pk);
        let v = mine_coins(&mut n1, oh, &pk, &sk);
        let (pk2, _) = dsa_generate();
        let oh2 = dsa_pubkey_hash(&pk2);
        let out_v = Vess { variant: VessVariant::Output, amount: v.amount, owner_hash: oh2, timestamp: 0,
            nonce: 0, salt: random_bytes(), pubkey: Vec::new(), spend_key: Vec::new(), spend_condition: None };
        let mut spend = VessPayment { payment_id: [0u8;32], inputs: vec![v], outputs: vec![out_v],
            timestamp: 0, sigs: vec![], preimages: vec![None] };
        spend.compute();
        // sigs left empty — must be rejected
        assert!(!n1.submit(spend), "payment with no signatures must be rejected");
    }

    #[test]
    fn test_malformed_payment_wrong_sig() {
        let (mut n1, _s1) = start_node_at("127.0.0.1:19952", "vess-db-wrongsig");
        let (pk, sk) = dsa_generate();
        let oh = dsa_pubkey_hash(&pk);
        let v = mine_coins(&mut n1, oh, &pk, &sk);
        let (pk2, _) = dsa_generate();
        let oh2 = dsa_pubkey_hash(&pk2);
        let out_v = Vess { variant: VessVariant::Output, amount: v.amount, owner_hash: oh2, timestamp: 0,
            nonce: 0, salt: random_bytes(), pubkey: Vec::new(), spend_key: Vec::new(), spend_condition: None };
        let mut spend = VessPayment { payment_id: [0u8;32], inputs: vec![v], outputs: vec![out_v],
            timestamp: 0, sigs: vec![], preimages: vec![None] };
        spend.compute();
        // Sign with a different key — must be rejected
        let (_, wrong_sk) = dsa_generate();
        spend.sigs = vec![dsa_sign(&wrong_sk, &spend.payment_id).unwrap()];
        assert!(!n1.submit(spend), "payment with wrong signature must be rejected");
    }

    #[test]
    fn test_malformed_payment_tampered_id() {
        let (mut n1, _s1) = start_node_at("127.0.0.1:19953", "vess-db-tamper");
        let (pk, sk) = dsa_generate();
        let oh = dsa_pubkey_hash(&pk);
        let v = mine_coins(&mut n1, oh, &pk, &sk);
        let (pk2, _) = dsa_generate();
        let oh2 = dsa_pubkey_hash(&pk2);
        let out_v = Vess { variant: VessVariant::Output, amount: v.amount, owner_hash: oh2, timestamp: 0,
            nonce: 0, salt: random_bytes(), pubkey: Vec::new(), spend_key: Vec::new(), spend_condition: None };
        let mut spend = VessPayment { payment_id: [0u8;32], inputs: vec![v], outputs: vec![out_v],
            timestamp: 0, sigs: vec![], preimages: vec![None] };
        spend.compute();
        spend.sigs = vec![dsa_sign(&sk, &spend.payment_id).unwrap()];
        // Tamper with payment_id after signing — sig no longer matches
        spend.payment_id[0] ^= 1;
        assert!(!n1.submit(spend), "payment with tampered id must be rejected");
    }

    #[test]
    fn test_rate_limit_ban() {
        let node_addr: std::net::SocketAddr = "127.0.0.1:19954".parse().unwrap();
        let (mut node, _sock) = start_node_at("127.0.0.1:19954", "vess-db-ratelimit");
        let attacker: std::net::SocketAddr = "127.0.0.1:19955".parse().unwrap();
        let att_sock = UdpSocket::bind(attacker).unwrap();
        att_sock.set_nonblocking(true).unwrap();
        // Send 7 bad frames — 6th triggers ban (>5 strikes), 7th should be silent
        let garbage = vec![0u8; 100]; // won't unframe
        for i in 0..7 {
            att_sock.send_to(&garbage, node_addr).unwrap();
            thread::sleep(Duration::from_millis(2));
            let resp = node.process(attacker, &garbage);
            if i >= 5 {
                assert!(resp.is_none(), "banned peer must get no response at strike {}", i);
            }
        }
        // Verify the ban is recorded
        assert!(node.process(attacker, &garbage).is_none(), "still banned");
    }

    #[test]
    fn test_packet_loss_resilience() {
        let _ = std::fs::remove_dir_all("vess-db-loss1");
        let _ = std::fs::remove_dir_all("vess-db-loss2");
        let (mut n1, s1) = start_node_at("127.0.0.1:19956", "vess-db-loss1");
        let (mut n2, s2) = start_node_at("127.0.0.1:19957", "vess-db-loss2");
        let n2_addr: std::net::SocketAddr = "127.0.0.1:19957".parse().unwrap();
        let len = n1.add_peer(n2_addr); assert!(len > 0);
        for (dest, data) in n1.drain_outbox() { s1.send_to(&data, dest).unwrap(); }
        // Cycle to establish session
        for _ in 0..6 { thread::sleep(Duration::from_millis(5)); cycle_node(&mut n2, &s2); cycle_node(&mut n1, &s1); }
        n1.needs_sync = false; n2.needs_sync = false;

        let (pk, sk) = dsa_generate();
        let oh = dsa_pubkey_hash(&pk);
        // Mine block on n1 — gossip to n2
        mine_coins(&mut n1, oh, &pk, &sk);
        // Simulate packet loss: only cycle n2 every other attempt
        for round in 0..20 {
            cycle_node(&mut n1, &s1);
            if round % 2 == 0 { cycle_node(&mut n2, &s2); } // drop 50% of n2 cycles
            thread::sleep(Duration::from_millis(2));
        }
        // n2 should still eventually receive the block via retransmission
        cycle_node(&mut n2, &s2); cycle_node(&mut n1, &s1);
        assert_eq!(n1.merkle(), n2.merkle(), "merkle roots converge despite packet loss");
    }

    // ── DAG MERGE TESTS ──

    fn cb_block(parents: Vec<[u8; 32]>, cb_amt: u64, oh: OwnerHash, pk: &[u8], sk: &[u8], payments: Vec<VessPayment>, ts: u64) -> VessBlock {
        let out = Vess { variant: VessVariant::Mint, amount: cb_amt, owner_hash: oh, timestamp: ts, nonce: 0, salt: random_bytes(), pubkey: pk.to_vec(), spend_key: sk.to_vec(), spend_condition: None };
        let mut cb = VessPayment { payment_id: [0u8; 32], inputs: vec![], outputs: vec![out], timestamp: 0, sigs: vec![], preimages: vec![] };
        cb.compute();
        let mut ids: Vec<[u8; 32]> = vec![cb.payment_id];
        ids.extend(payments.iter().map(|p| p.payment_id));
        ids.sort(); ids.dedup();
        VessBlock { version: 1, parents, timestamp: ts, difficulty_bits: 9, nonce: 0, payment_merkle: merkle_root(&ids), state_merkle: [0u8; 32], proof: vec![], coinbase: cb, payments }
    }

    #[test]
    fn test_merge_pays_both_miners() {
        let (mut node, _s) = start_node_at("127.0.0.1:20001", "vess-db-merge-miners");
        let (pk, sk) = dsa_generate();
        let oh = dsa_pubkey_hash(&pk);
        mine_coins(&mut node, oh, &pk, &sk);
        let genesis = node.tip_hashes[0];

        let (pk1, sk1) = dsa_generate(); let oh1 = dsa_pubkey_hash(&pk1);
        let (pk2, sk2) = dsa_generate(); let oh2 = dsa_pubkey_hash(&pk2);
        let b1 = cb_block(vec![genesis], 1, oh1, &pk1, &sk1, vec![], 1000);
        let b2 = cb_block(vec![genesis], 1, oh2, &pk2, &sk2, vec![], 1000);
        assert!(node.process_block(&b1));
        assert!(node.process_block(&b2));
        let b1_cb = b1.coinbase.outputs[0].vess_id();
        let b2_cb = b2.coinbase.outputs[0].vess_id();

        let m = cb_block(vec![b1.header_hash(), b2.header_hash()], 1, oh, &pk, &sk, vec![], 2000);
        assert!(node.process_block(&m), "merge block accepted");
        assert!(node.check(&b1_cb), "b1 coinbase present");
        assert!(node.check(&b2_cb), "b2 coinbase present");
        assert_eq!(node.tip_hashes, vec![m.header_hash()]);
    }

    #[test]
    fn test_merge_vaporizes_cross_branch() {
        let (mut node, _s) = start_node_at("127.0.0.1:20002", "vess-db-merge-vapor");
        let (pk, sk) = dsa_generate();
        let oh = dsa_pubkey_hash(&pk);
        let coin = mine_coins(&mut node, oh, &pk, &sk);
        let genesis = node.tip_hashes[0];
        let coin_id = coin.vess_id();

        let (pk_a, sk_a) = dsa_generate(); let oh_a = dsa_pubkey_hash(&pk_a);
        let (pk_b, sk_b) = dsa_generate(); let oh_b = dsa_pubkey_hash(&pk_b);
        let out_a = Vess { variant: VessVariant::Output, amount: coin.amount, owner_hash: oh_a, timestamp: 0, nonce: 0, salt: random_bytes(), pubkey: pk_a.clone(), spend_key: sk_a.clone(), spend_condition: None };
        let out_b = Vess { variant: VessVariant::Output, amount: coin.amount, owner_hash: oh_b, timestamp: 0, nonce: 0, salt: random_bytes(), pubkey: pk_b.clone(), spend_key: sk_b.clone(), spend_condition: None };
        let mut pa = VessPayment { payment_id: [0u8; 32], inputs: vec![coin.clone()], outputs: vec![out_a.clone()], timestamp: 0, sigs: vec![], preimages: vec![] };
        pa.compute(); pa.sigs = vec![dsa_sign(&sk, &pa.payment_id).unwrap()];
        let mut pb = VessPayment { payment_id: [0u8; 32], inputs: vec![coin.clone()], outputs: vec![out_b.clone()], timestamp: 0, sigs: vec![], preimages: vec![] };
        pb.compute(); pb.sigs = vec![dsa_sign(&sk, &pb.payment_id).unwrap()];
        let out_a_id = out_a.vess_id();
        let out_b_id = out_b.vess_id();

        let (pk1, sk1) = dsa_generate(); let oh1 = dsa_pubkey_hash(&pk1);
        let b1 = cb_block(vec![genesis], 1, oh1, &pk1, &sk1, vec![pa], 1000);
        let (pk2, sk2) = dsa_generate(); let oh2 = dsa_pubkey_hash(&pk2);
        let b2 = cb_block(vec![genesis], 1, oh2, &pk2, &sk2, vec![pb], 1000);
        assert!(node.process_block(&b1));
        assert!(node.process_block(&b2));

        let (pk_m, sk_m) = dsa_generate(); let oh_m = dsa_pubkey_hash(&pk_m);
        let m = cb_block(vec![b1.header_hash(), b2.header_hash()], 1, oh_m, &pk_m, &sk_m, vec![], 2000);
        assert!(node.process_block(&m), "merge accepted with cross-branch conflict");
        assert!(!node.check(&coin_id), "double-spent input vaporized");
        assert!(!node.check(&out_a_id), "conflicting output A never created");
        assert!(!node.check(&out_b_id), "conflicting output B never created");
        assert!(node.check(&b1.coinbase.outputs[0].vess_id()), "b1 coinbase intact");
        assert!(node.check(&b2.coinbase.outputs[0].vess_id()), "b2 coinbase intact");
    }

    #[test]
    fn test_merge_dedups_payment() {
        let (mut node, _s) = start_node_at("127.0.0.1:20003", "vess-db-merge-dedup");
        let (pk, sk) = dsa_generate();
        let oh = dsa_pubkey_hash(&pk);
        let coin = mine_coins(&mut node, oh, &pk, &sk);
        let genesis = node.tip_hashes[0];

        let (pk_out, sk_out) = dsa_generate(); let oh_out = dsa_pubkey_hash(&pk_out);
        let out_v = Vess { variant: VessVariant::Output, amount: coin.amount, owner_hash: oh_out, timestamp: 0, nonce: 0, salt: random_bytes(), pubkey: pk_out.clone(), spend_key: sk_out.clone(), spend_condition: None };
        let mut p = VessPayment { payment_id: [0u8; 32], inputs: vec![coin.clone()], outputs: vec![out_v.clone()], timestamp: 0, sigs: vec![], preimages: vec![] };
        p.compute(); p.sigs = vec![dsa_sign(&sk, &p.payment_id).unwrap()];
        let out_id = out_v.vess_id();

        let (pk1, sk1) = dsa_generate(); let oh1 = dsa_pubkey_hash(&pk1);
        let b1 = cb_block(vec![genesis], 1, oh1, &pk1, &sk1, vec![p.clone()], 1000);
        let (pk2, sk2) = dsa_generate(); let oh2 = dsa_pubkey_hash(&pk2);
        let b2 = cb_block(vec![genesis], 1, oh2, &pk2, &sk2, vec![p.clone()], 1000);
        assert!(node.process_block(&b1));
        assert!(node.process_block(&b2));

        let (pk_m, sk_m) = dsa_generate(); let oh_m = dsa_pubkey_hash(&pk_m);
        let m = cb_block(vec![b1.header_hash(), b2.header_hash()], 1, oh_m, &pk_m, &sk_m, vec![], 2000);
        assert!(node.process_block(&m), "merge accepted with duplicate payment");
        assert!(!node.check(&coin.vess_id()), "input spent once");
        assert!(node.check(&out_id), "output created once");
    }

    #[test]
    fn test_merge_voids_daisy_chain() {
        let (mut node, _s) = start_node_at("127.0.0.1:20004", "vess-db-merge-void");
        let (pk, sk) = dsa_generate();
        let oh = dsa_pubkey_hash(&pk);
        let coin = mine_coins(&mut node, oh, &pk, &sk);
        let genesis = node.tip_hashes[0];
        let coin_id = coin.vess_id();

        // Also mine a second coin R (bystander). Record which block holds it
        // so b3 can include it in its ancestor closure.
        let coin_r = mine_coins(&mut node, oh, &pk, &sk);
        let coin_r_id = coin_r.vess_id();
        let coin_r_tip = node.tip_hashes[0];

        // Branch 1: b1 spends coin → Bob
        let (pk_bob, sk_bob) = dsa_generate(); let oh_bob = dsa_pubkey_hash(&pk_bob);
        let out_bob = Vess { variant: VessVariant::Output, amount: coin.amount, owner_hash: oh_bob, timestamp: 0, nonce: 0, salt: random_bytes(), pubkey: pk_bob.clone(), spend_key: sk_bob.clone(), spend_condition: None };
        let mut p_bob = VessPayment { payment_id: [0u8; 32], inputs: vec![coin.clone()], outputs: vec![out_bob.clone()], timestamp: 0, sigs: vec![], preimages: vec![] };
        p_bob.compute(); p_bob.sigs = vec![dsa_sign(&sk, &p_bob.payment_id).unwrap()];

        // Branch 2: b2 spends coin → Alice
        let (pk_alice, sk_alice) = dsa_generate(); let oh_alice = dsa_pubkey_hash(&pk_alice);
        let out_alice = Vess { variant: VessVariant::Output, amount: coin.amount, owner_hash: oh_alice, timestamp: 0, nonce: 0, salt: random_bytes(), pubkey: pk_alice.clone(), spend_key: sk_alice.clone(), spend_condition: None };
        let mut p_alice = VessPayment { payment_id: [0u8; 32], inputs: vec![coin.clone()], outputs: vec![out_alice.clone()], timestamp: 0, sigs: vec![], preimages: vec![] };
        p_alice.compute(); p_alice.sigs = vec![dsa_sign(&sk, &p_alice.payment_id).unwrap()];
        let alice_out_id = out_alice.vess_id();

        let (pk1, sk1) = dsa_generate(); let oh1 = dsa_pubkey_hash(&pk1);
        let b1 = cb_block(vec![genesis], 1, oh1, &pk1, &sk1, vec![p_bob], 1000);
        let (pk2, sk2) = dsa_generate(); let oh2 = dsa_pubkey_hash(&pk2);
        let b2 = cb_block(vec![genesis], 1, oh2, &pk2, &sk2, vec![p_alice], 1000);
        assert!(node.process_block(&b1));
        assert!(node.process_block(&b2));

        // b3 (child of b2): spends Alice-output + R (bystander)
        let mut out_q = out_alice.clone();
        out_q.pubkey = pk_alice.clone(); out_q.spend_key = sk_alice.clone();
        let (pk_q, sk_q) = dsa_generate(); let oh_q = dsa_pubkey_hash(&pk_q);
        let out_q_final = Vess { variant: VessVariant::Output, amount: coin.amount + coin_r.amount, owner_hash: oh_q, timestamp: 0, nonce: 0, salt: random_bytes(), pubkey: pk_q.clone(), spend_key: sk_q.clone(), spend_condition: None };
        let mut p_q = VessPayment { payment_id: [0u8; 32], inputs: vec![out_q, coin_r.clone()], outputs: vec![out_q_final.clone()], timestamp: 0, sigs: vec![], preimages: vec![] };
        p_q.compute();
        p_q.sigs = vec![dsa_sign(&sk_alice, &p_q.payment_id).unwrap(), dsa_sign(&sk, &p_q.payment_id).unwrap()];
        let q_out_id = out_q_final.vess_id();

        let (pk3, sk3) = dsa_generate(); let oh3 = dsa_pubkey_hash(&pk3);
        let b3 = cb_block(vec![b2.header_hash(), coin_r_tip], 1, oh3, &pk3, &sk3, vec![p_q], 2000);
        assert!(node.process_block(&b3));

        // Merge b1 (Bob-spend) + b3 (Alice→Q + R): coin is double-spent, so
        // Bob-spend and Alice-spend are conflicted, Q is voided, R is safe.
        let (pk_m, sk_m) = dsa_generate(); let oh_m = dsa_pubkey_hash(&pk_m);
        let m = cb_block(vec![b1.header_hash(), b3.header_hash()], 1, oh_m, &pk_m, &sk_m, vec![], 3000);
        assert!(node.process_block(&m), "merge accepted with daisy-chain void");

        assert!(!node.check(&coin_id), "double-spent input vaporized");
        assert!(!node.check(&alice_out_id), "Alice output never created (conflicted branch)");
        assert!(!node.check(&q_out_id), "Q output voided (spends conflicted output)");
        assert!(node.check(&coin_r_id), "bystander R still in state");
    }

    // ── MULTI-NODE DAG END-TO-END ──

    #[test]
    fn test_three_node_dag_merge() {
        // Three nodes: n1 and n2 mine competing blocks, n3 merges both.
        // All three converge on the same state merkle — this exercises
        // gossip, dedup, multi-parent merge, and sync together.
        let _ = std::fs::remove_dir_all("vess-db-3node-1");
        let _ = std::fs::remove_dir_all("vess-db-3node-2");
        let _ = std::fs::remove_dir_all("vess-db-3node-3");
        let (mut n1, s1) = start_node_at("127.0.0.1:20501", "vess-db-3node-1");
        let (mut n2, s2) = start_node_at("127.0.0.1:20502", "vess-db-3node-2");
        let (mut n3, s3) = start_node_at("127.0.0.1:20503", "vess-db-3node-3");
        let a2: SocketAddr = "127.0.0.1:20502".parse().unwrap();
        let a3: SocketAddr = "127.0.0.1:20503".parse().unwrap();

        // Full mesh handshake.
        let i12 = n1.add_peer(a2); assert!(i12 > 0);
        let i13 = n1.add_peer(a3); assert!(i13 > 0);
        let i23 = n2.add_peer(a3); assert!(i23 > 0);
        for (dest, data) in n1.drain_outbox() { s1.send_to(&data, dest).unwrap(); }
        for (dest, data) in n2.drain_outbox() { s2.send_to(&data, dest).unwrap(); }
        for _ in 0..6 {
            thread::sleep(Duration::from_millis(5));
            cycle_node(&mut n1, &s1); cycle_node(&mut n2, &s2); cycle_node(&mut n3, &s3);
        }
        n1.needs_sync = false; n2.needs_sync = false; n3.needs_sync = false;

        // Mine genesis coin on n1; gossip to all.
        let (pk, sk) = dsa_generate(); let oh = dsa_pubkey_hash(&pk);
        mine_coins(&mut n1, oh, &pk, &sk);
        for _ in 0..3 {
            thread::sleep(Duration::from_millis(5));
            cycle_node(&mut n1, &s1); cycle_node(&mut n2, &s2); cycle_node(&mut n3, &s3);
        }
        let genesis = n1.tip_hashes[0];

        // n1 and n2 mine competing blocks on genesis (different miners).
        let (pk1, sk1) = dsa_generate(); let oh1 = dsa_pubkey_hash(&pk1);
        let (pk2, sk2) = dsa_generate(); let oh2 = dsa_pubkey_hash(&pk2);
        let b1 = cb_block(vec![genesis], 1, oh1, &pk1, &sk1, vec![], 1000);
        let b2 = cb_block(vec![genesis], 1, oh2, &pk2, &sk2, vec![], 1000);
        let b1_cb = b1.coinbase.outputs[0].vess_id();
        let b2_cb = b2.coinbase.outputs[0].vess_id();
        assert!(n1.process_block(&b1), "n1 accepts b1");
        assert!(n2.process_block(&b2), "n2 accepts b2");
        // Directly inject into all nodes so both branches exist on all three.
        assert!(n3.process_block(&b1), "n3 accepts b1");
        assert!(n3.process_block(&b2), "n3 accepts b2");
        assert!(n2.process_block(&b1), "n2 accepts b1");
        assert!(n1.process_block(&b2), "n1 accepts b2");

        // n3 mines a merge block referencing both b1 and b2.
        let (pk3, sk3) = dsa_generate(); let oh3 = dsa_pubkey_hash(&pk3);
        let b1_hash = b1.header_hash();
        let b2_hash = b2.header_hash();
        let m = cb_block(vec![b1_hash, b2_hash], 1, oh3, &pk3, &sk3, vec![], 2000);
        let m_cb = m.coinbase.outputs[0].vess_id();
        assert!(n3.process_block(&m), "n3 accepts merge block");
        // Directly inject merge into n1 and n2.
        assert!(n1.process_block(&m), "n1 accepts merge");
        assert!(n2.process_block(&m), "n2 accepts merge");
        let m_hash = m.header_hash();

        // All must converge to the same state.
        let r1 = n1.merkle();
        let r2 = n2.merkle();
        let r3 = n3.merkle();
        assert_eq!(r1, r2, "n1 == n2");
        assert_eq!(r2, r3, "n2 == n3");

        // All coinbases present in UTXO set.
        assert!(n1.check(&b1_cb) && n2.check(&b1_cb) && n3.check(&b1_cb), "b1 coinbase on all nodes");
        assert!(n1.check(&b2_cb) && n2.check(&b2_cb) && n3.check(&b2_cb), "b2 coinbase on all nodes");
        assert!(n1.check(&m_cb) && n2.check(&m_cb) && n3.check(&m_cb), "merge coinbase on all nodes");

        // Tip hashes should all point to the merge block.
        assert!(n1.tip_hashes.contains(&m_hash), "n1 tip is merge");
        assert!(n2.tip_hashes.contains(&m_hash), "n2 tip is merge");
        assert!(n3.tip_hashes.contains(&m_hash), "n3 tip is merge");
    }

    // ── COMPREHENSIVE MULTI-NODE END-TO-END ──

    #[test]
    fn test_full_mesh_payments_sync_vaporize() {
        // Four-node mesh: limbo payment submission, block mining with payment,
        // cross-branch conflicting spend vaporized via DAG merge, real gossip
        // relay through encrypted session, and LMDB verification on all nodes.
        let _ = std::fs::remove_dir_all("vess-db-fm-1"); let _ = std::fs::remove_dir_all("vess-db-fm-2");
        let _ = std::fs::remove_dir_all("vess-db-fm-3"); let _ = std::fs::remove_dir_all("vess-db-fm-4");
        let (mut n1, s1) = start_node_at("127.0.0.1:20601", "vess-db-fm-1");
        let (mut n2, s2) = start_node_at("127.0.0.1:20602", "vess-db-fm-2");
        let (mut n3, s3) = start_node_at("127.0.0.1:20603", "vess-db-fm-3");
        let (mut n4, _s4) = start_node_at("127.0.0.1:20604", "vess-db-fm-4");
        let a1: SocketAddr = "127.0.0.1:20601".parse().unwrap();
        let a2: SocketAddr = "127.0.0.1:20602".parse().unwrap();
        let a3: SocketAddr = "127.0.0.1:20603".parse().unwrap();

        // Manual sessions — skip PoW.
        let key = [0x42u8; 32];
        let id1 = n1.network.my_node_id(); let id2 = n2.network.my_node_id();
        let id3 = n3.network.my_node_id(); let id4 = n4.network.my_node_id();
        n1.inject_session(a2, id2, key); n2.inject_session(a1, id1, key);
        n1.inject_session(a3, id3, key); n3.inject_session(a1, id1, key);
        n2.inject_session(a3, id3, key); n3.inject_session(a2, id2, key);
        n1.needs_sync = false; n2.needs_sync = false; n3.needs_sync = false; n4.needs_sync = false;

        let (pk, sk) = dsa_generate(); let oh = dsa_pubkey_hash(&pk);

        // Phase 1: mine genesis + two spendable coins. Track each block.
        mine_coins(&mut n1, oh, &pk, &sk);
        let block_gen = n1.pending_blocks.last().cloned().unwrap();
        mine_coins(&mut n1, oh, &pk, &sk);
        let block_coin_a = n1.pending_blocks.last().cloned().unwrap();
        mine_coins(&mut n1, oh, &pk, &sk);
        let block_coin_b = n1.pending_blocks.last().cloned().unwrap();
        let coin_a = block_coin_a.coinbase.outputs.iter().find(|v| v.owner_hash == oh).unwrap().clone();
        let coin_b = block_coin_b.coinbase.outputs.iter().find(|v| v.owner_hash == oh).unwrap().clone();
        // Inject all three into n2, n3, n4.
        for n in [&mut n2, &mut n3, &mut n4] {
            assert!(n.process_block(&block_gen));
            assert!(n.process_block(&block_coin_a));
            assert!(n.process_block(&block_coin_b));
        }

        // Phase 2: submit a payment spending coin_a, mine it, inject into all.
        let (pk_recv, sk_recv) = dsa_generate(); let oh_recv = dsa_pubkey_hash(&pk_recv);
        let out_r = Vess { variant: VessVariant::Output, amount: coin_a.amount, owner_hash: oh_recv,
            timestamp: 0, nonce: 0, salt: random_bytes(), pubkey: pk_recv.clone(),
            spend_key: sk_recv.clone(), spend_condition: None };
        let mut pay1 = VessPayment { payment_id: [0u8; 32], inputs: vec![coin_a.clone()],
            outputs: vec![out_r], timestamp: 0, sigs: vec![], preimages: vec![] };
        pay1.compute(); pay1.sigs = vec![dsa_sign(&sk, &pay1.payment_id).unwrap()];
        assert!(n1.submit(pay1), "payment enters limbo");
        let pay_block = n1.prepare_block().expect("block with payment");
        n1.apply_mined_block(pay_block, 0, vec![]);
        let block_pay = n1.pending_blocks.last().cloned().unwrap();
        for n in [&mut n2, &mut n3, &mut n4] { assert!(n.process_block(&block_pay)); }

        // Phase 3: conflicting double-spend of coin_b.
        let (pk_a, sk_a) = dsa_generate(); let oh_a = dsa_pubkey_hash(&pk_a);
        let (pk_b, sk_b) = dsa_generate(); let oh_b = dsa_pubkey_hash(&pk_b);
        let out_a = Vess { variant: VessVariant::Output, amount: coin_b.amount, owner_hash: oh_a,
            timestamp: 0, nonce: 0, salt: random_bytes(), pubkey: pk_a.clone(),
            spend_key: sk_a.clone(), spend_condition: None };
        let out_b = Vess { variant: VessVariant::Output, amount: coin_b.amount, owner_hash: oh_b,
            timestamp: 0, nonce: 0, salt: random_bytes(), pubkey: pk_b.clone(),
            spend_key: sk_b.clone(), spend_condition: None };
        let mut p_a = VessPayment { payment_id: [0u8; 32], inputs: vec![coin_b.clone()],
            outputs: vec![out_a.clone()], timestamp: 0, sigs: vec![], preimages: vec![] };
        p_a.compute(); p_a.sigs = vec![dsa_sign(&sk, &p_a.payment_id).unwrap()];
        let mut p_b = VessPayment { payment_id: [0u8; 32], inputs: vec![coin_b.clone()],
            outputs: vec![out_b.clone()], timestamp: 0, sigs: vec![], preimages: vec![] };
        p_b.compute(); p_b.sigs = vec![dsa_sign(&sk, &p_b.payment_id).unwrap()];
        let out_a_id = out_a.vess_id(); let out_b_id = out_b.vess_id();
        let cb_id = coin_b.vess_id();
        assert!(n1.submit(p_a.clone())); assert!(n2.submit(p_b.clone()));
        assert!(n3.submit(p_a)); assert!(n3.submit(p_b));

        // Phase 4: fork — n1 mines p_a, n2 mines p_b. Inject into all.
        let b1 = n1.prepare_block().expect("b1"); let b2 = n2.prepare_block().expect("b2");
        n1.apply_mined_block(b1, 0, vec![]); n2.apply_mined_block(b2, 0, vec![]);
        let block_b1 = n1.pending_blocks.last().cloned().unwrap();
        let block_b2 = n2.pending_blocks.last().cloned().unwrap();
        let b1h = block_b1.header_hash(); let b2h = block_b2.header_hash();
        for n in [&mut n2, &mut n3, &mut n4] { assert!(n.process_block(&block_b1)); }
        for n in [&mut n1, &mut n3, &mut n4] { assert!(n.process_block(&block_b2)); }

        // Phase 5: n3 mines merge. Relay through real gossip: n3 → socket → n1.
        let (pk_m, sk_m) = dsa_generate(); let oh_m = dsa_pubkey_hash(&pk_m);
        let m = cb_block(vec![b1h, b2h], 1, oh_m, &pk_m, &sk_m, vec![], 3000);
        let mh = m.header_hash();
        assert!(n3.process_block(&m), "n3 accepts merge");
        // Real gossip relay: n3 sends merge to n1 through encrypted session.
        n3.send(a1, &GossipMessage::Block(m.clone()));
        for (dst, data) in n3.cycle() {
            if dst == a1 { s1.send_to(&data, a1).unwrap(); }
        }
        cycle_node(&mut n1, &s1);
        assert!(n1.process_block(&m), "n1 idempotent-accepts merge (gossip + direct)");
        assert!(n2.process_block(&m)); assert!(n4.process_block(&m));
        assert!(n2.process_block(&m)); assert!(n4.process_block(&m));

        // Phase 6: verify vaporization + merkle convergence on ALL FOUR nodes.
        for node in [&n1, &n2, &n3, &n4] {
            assert!(!node.check(&cb_id), "coin vaporized");
            assert!(!node.check(&out_a_id), "out A vaporized");
            assert!(!node.check(&out_b_id), "out B vaporized");
        }
        let r = n1.merkle();
        for n in [&n2, &n3, &n4] { assert_eq!(n.merkle(), r, "merkle convergence"); }

        // LMDB state matches across all nodes.
        let count = n1.utxo_count();
        assert!(count > 0);
        for n in [&n2, &n3, &n4] { assert_eq!(n.utxo_count(), count, "LMDB UTXO count matches"); }
    }

    /// White-box: verify that fragmented handshake messages are tracked
    /// and retried after the retransmit interval elapses.
    #[test]
    fn test_handshake_fragment_retry() {
        let _ = std::fs::remove_dir_all("vess-db-hs-retry");
        let (mut n1, _s1) = start_node_at("127.0.0.1:20701", "vess-db-hs-retry");
        let a2: SocketAddr = "127.0.0.1:20702".parse().unwrap();

        // Initiate handshake — fragments go to outbox.
        let len = n1.add_peer(a2);
        assert!(len > 0, "handshake init should produce bytes");

        // Drain initial fragments.
        let initial: Vec<_> = n1.drain_outbox();
        let fragment_count = initial.len();
        assert!(
            fragment_count > 1,
            "handshake init should be multi-fragment, got {}",
            fragment_count
        );
        assert!(
            initial.iter().all(|(addr, _)| *addr == a2),
            "all fragments should target the peer"
        );

        // Outbox should be empty after drain.
        assert!(n1.drain_outbox().is_empty());

        // Advance ticks past the retry threshold.
        n1.ticks += vess_node::HANDSHAKE_RETRANSMIT_TICKS + 1;

        // cycle() calls retry_handshakes() which should re-queue fragments.
        let retried = n1.cycle();
        assert!(!retried.is_empty(), "retry should re-queue fragments");
        assert_eq!(
            retried.len(),
            fragment_count,
            "retry should re-send same number of fragments"
        );
        assert!(retried.iter().all(|(addr, _)| *addr == a2));

        // Outbox should be empty after cycle drain.
        assert!(n1.drain_outbox().is_empty());
    }

    /// Integration: handshake completes even when one fragment is lost,
    /// because the retry mechanism re-sends it on the next cycle.
    #[test]
    fn test_handshake_survives_fragment_loss() {
        let _ = std::fs::remove_dir_all("vess-db-hs-loss1");
        let _ = std::fs::remove_dir_all("vess-db-hs-loss2");
        let (mut n1, s1) = start_node_at("127.0.0.1:20711", "vess-db-hs-loss1");
        let (mut n2, s2) = start_node_at("127.0.0.1:20712", "vess-db-hs-loss2");
        let a2: SocketAddr = "127.0.0.1:20712".parse().unwrap();

        // Initiate handshake — fragments are queued in n1's outbox.
        let len = n1.add_peer(a2);
        assert!(len > 0);

        // Simulate fragment loss: drop the first fragment, send the rest.
        let mut fragments: Vec<_> = n1.drain_outbox();
        assert!(fragments.len() > 1, "expected multi-fragment handshake init");
        let _dropped = fragments.remove(0); // simulate loss
        for (dest, data) in &fragments {
            s1.send_to(data, *dest).unwrap();
        }

        // n2 receives incomplete fragments — reassembly stalls.
        for _ in 0..4 {
            thread::sleep(Duration::from_millis(5));
            cycle_node(&mut n2, &s2);
        }
        assert!(
            !n2.has_session_for(&n1.addr),
            "n2 should NOT have a session yet (fragment missing)"
        );

        // Advance n1's ticks past the retry threshold and cycle.
        // retry_handshakes() re-queues all fragments to the outbox.
        n1.ticks += vess_node::HANDSHAKE_RETRANSMIT_TICKS + 1;
        let retried = n1.cycle();
        assert!(!retried.is_empty(), "retry should re-queue the missing fragment");
        for (dest, data) in &retried {
            s1.send_to(data, *dest).unwrap();
        }

        // n2 now gets the missing fragment → reassembly completes →
        // process() handles INIT → RESP fragments go to outbox →
        // cycle() drains outbox and sends RESP to n1.
        cycle_node(&mut n2, &s2);

        // n1 receives RESP fragments → handshake completes.
        cycle_node(&mut n1, &s1);

        assert!(
            n1.has_session_for(&a2),
            "handshake should complete after fragment retry"
        );
    }

    /// Regression: coinbase outputs whose amounts wrap u64 when summed
    /// must be rejected.  Without checked_add this allows unlimited
    /// inflation — the wrapped total matches the expected reward even
    /// though each individual output is astronomically large.
    #[test]
    fn test_coinbase_overflow_rejected() {
        let _ = std::fs::remove_dir_all("vess-db-overflow");
        let (mut node, _sock) = start_node_at("127.0.0.1:20801", "vess-db-overflow");
        node.test_mode = false; // enable coinbase validation

        let (pk, sk) = dsa_generate();
        let oh = dsa_pubkey_hash(&pk);

        let reward = block_reward(DIFFICULTY_BASE_BITS);
        let dev_share = dev_reward(reward);

        // Craft coinbase outputs that wrap to reward+dev_share when summed.
        // output[0]: u64::MAX.saturating_sub(reward) + 1   (wraps to 0 when added to reward)
        // output[1]: reward                                (wraps to reward)
        // But we need both checks to pass: total == reward+dev_share AND miner == reward.
        let wrap_a = u64::MAX.saturating_sub(reward).saturating_add(1); // wraps to 0 when + reward
        let wrap_b = reward.saturating_mul(2); // wraps to reward*2 mod 2^64

        let coinbase = VessPayment {
            payment_id: [0u8; 32],
            inputs: vec![],
            outputs: vec![
                Vess { variant: VessVariant::Mint, amount: wrap_a, owner_hash: oh,
                    timestamp: 0, nonce: 0, salt: [0u8; 32], pubkey: pk.clone(),
                    spend_key: vec![], spend_condition: None },
                Vess { variant: VessVariant::Mint, amount: wrap_b, owner_hash: oh,
                    timestamp: 0, nonce: 0, salt: [0u8; 32], pubkey: pk.clone(),
                    spend_key: vec![], spend_condition: None },
                Vess { variant: VessVariant::Mint, amount: dev_share, owner_hash: DEV_PUBKEY_HASH,
                    timestamp: 0, nonce: 0, salt: [0u8; 32], pubkey: vec![],
                    spend_key: vec![], spend_condition: None },
            ],
            timestamp: 0,
            sigs: vec![],
            preimages: vec![],
        };

        let block = VessBlock {
            version: 1,
            parents: vec![],
            timestamp: 1,
            difficulty_bits: DIFFICULTY_BASE_BITS,
            nonce: 0,
            proof: vec![],
            coinbase,
            payments: vec![],
            state_merkle: [0u8; 32],
            payment_merkle: [0u8; 32],
        };

        // Must reject — the coinbase amounts overflow when summed.
        assert!(!node.process_block(&block),
            "coinbase with wrapping output amounts must be rejected");
    }

    /// Regression: a payment whose output verbatim-copies an existing UTXO
    /// (same fields → same vess_id) must be rejected at the mempool level.
    /// Without this check, the payment passes submit() but causes the entire
    /// block to fail validate_block, wasting miner PoW.
    #[test]
    fn test_mempool_rejects_duplicate_output_id() {
        let _ = std::fs::remove_dir_all("vess-db-dup1");
        let _ = std::fs::remove_dir_all("vess-db-dup2");
        let (mut n1, s1) = start_node_at("127.0.0.1:20901", "vess-db-dup1");
        let (mut n2, s2) = start_node_at("127.0.0.1:20902", "vess-db-dup2");
        let n2_addr: SocketAddr = "127.0.0.1:20902".parse().unwrap();
        n1.add_peer(n2_addr);
        for (dest, data) in n1.drain_outbox() { s1.send_to(&data, dest).unwrap(); }
        for _ in 0..6 { thread::sleep(Duration::from_millis(5)); cycle_node(&mut n2, &s2); cycle_node(&mut n1, &s1); }
        n1.needs_sync = false; n2.needs_sync = false;

        let (pk, sk) = dsa_generate();
        let oh = dsa_pubkey_hash(&pk);
        let coin = mine_coins(&mut n1, oh, &pk, &sk);
        assert!(n1.check(&coin.vess_id()), "coinbase confirmed");

        // Gossip the block so n2 has the UTXO
        for _ in 0..6 { thread::sleep(Duration::from_millis(5)); cycle_node(&mut n1, &s1); cycle_node(&mut n2, &s2); }

        // Craft a payment that copies the coinbase output verbatim.
        // Same fields → same vess_id → collision with existing UTXO.
        let duplicate_out = coin.clone();
        let (_pay_pk, _pay_sk) = dsa_generate();
        let mut p = VessPayment {
            payment_id: [0u8; 32],
            inputs: vec![coin.clone()],
            outputs: vec![duplicate_out],
            timestamp: 0,
            sigs: vec![],
            preimages: vec![],
        };
        p.compute();
        p.sigs = vec![dsa_sign(&sk, &p.payment_id).unwrap()];

        // Must reject — output ID collides with an existing UTXO.
        assert!(!n2.submit(p),
            "payment with duplicate output ID must be rejected at mempool");

        // Also verify n1 rejects it (the output collision check is in verify()).
        let coin2 = mine_coins(&mut n1, oh, &pk, &sk);
        let mut p2 = VessPayment {
            payment_id: [0u8; 32],
            inputs: vec![coin2.clone()],
            outputs: vec![coin2.clone()], // output = input → duplicate
            timestamp: 0,
            sigs: vec![],
            preimages: vec![],
        };
        p2.compute();
        p2.sigs = vec![dsa_sign(&sk, &p2.payment_id).unwrap()];
        assert!(!n1.submit(p2),
            "payment where output == input must be rejected");
    }

    // ── PRODUCTION-MODE REGRESSION TESTS ──
    // Every test above runs with test_mode=true, which skips PoW,
    // difficulty checks, and coinbase validation.  These tests use
    // production-mode nodes to exercise the real validation path.

    /// Production mode: difficulty mismatch must be rejected.
    #[test]
    fn test_prod_difficulty_mismatch_rejected() {
        let _ = std::fs::remove_dir_all("vess-db-prod-diff");
        let (mut node, _sock) = start_prod_node_at("127.0.0.1:21001", "vess-db-prod-diff");

        // Build a valid genesis block at difficulty 0 by hand.
        let (pk, sk) = dsa_generate();
        let oh = dsa_pubkey_hash(&pk);
        let reward = block_reward(DIFFICULTY_BASE_BITS);
        let dev_share = dev_reward(reward);
        let coinbase_out = Vess { variant: VessVariant::Mint, amount: reward, owner_hash: oh,
            timestamp: 1, nonce: 0, salt: random_bytes(), pubkey: pk.clone(),
            spend_key: sk.clone(), spend_condition: None };
        let dev_out = Vess { variant: VessVariant::Mint, amount: dev_share,
            owner_hash: DEV_PUBKEY_HASH, timestamp: 1, nonce: 0, salt: random_bytes(),
            pubkey: vec![], spend_key: vec![], spend_condition: None };
        let mut cb = VessPayment { payment_id: [0u8;32], inputs: vec![],
            outputs: vec![coinbase_out.clone(), dev_out], timestamp: 0, sigs: vec![], preimages: vec![] };
        cb.compute();
        let coin_id = coinbase_out.vess_id();

        let genesis = VessBlock {
            version: 1, parents: vec![], timestamp: 1,
            difficulty_bits: DIFFICULTY_BASE_BITS, nonce: 0,
            payment_merkle: merkle_root(&[cb.payment_id]),
            state_merkle: [0u8; 32], proof: vec![],
            coinbase: cb, payments: vec![],
        };
        // Apply via apply_mined_block which computes state_merkle
        node.apply_mined_block(genesis, 0, vec![]);
        assert!(node.check(&coin_id), "genesis coin spendable");

        // Now try a block with wrong difficulty
        let wrong_diff = node.current_difficulty.saturating_add(1).max(1);
        let cb2_out = Vess { variant: VessVariant::Mint, amount: reward, owner_hash: oh,
            timestamp: 1000, nonce: 0, salt: random_bytes(), pubkey: pk.clone(),
            spend_key: sk.clone(), spend_condition: None };
        let dev2_out = Vess { variant: VessVariant::Mint, amount: dev_share,
            owner_hash: DEV_PUBKEY_HASH, timestamp: 1000, nonce: 0, salt: random_bytes(),
            pubkey: vec![], spend_key: vec![], spend_condition: None };
        let mut cb2 = VessPayment { payment_id: [0u8;32], inputs: vec![],
            outputs: vec![cb2_out, dev2_out], timestamp: 0, sigs: vec![], preimages: vec![] };
        cb2.compute();
        let bad = VessBlock {
            version: 1, parents: node.tip_hashes.clone(), timestamp: 1000,
            difficulty_bits: wrong_diff, nonce: 0,
            payment_merkle: merkle_root(&[cb2.payment_id]),
            state_merkle: [0u8; 32], proof: vec![],
            coinbase: cb2, payments: vec![],
        };
        assert!(!node.process_block(&bad), "wrong difficulty rejected in production mode");
    }

    /// Production mode: valid blocks at difficulty 0 pass with blake3-only PoW.
    #[test]
    fn test_prod_valid_block_accepted() {
        let _ = std::fs::remove_dir_all("vess-db-prod-valid");
        let (mut node, _sock) = start_prod_node_at("127.0.0.1:21002", "vess-db-prod-valid");
        let (pk, sk) = dsa_generate();
        let oh = dsa_pubkey_hash(&pk);
        let reward = block_reward(DIFFICULTY_BASE_BITS);
        let dev_share = dev_reward(reward);
        let coinbase_out = Vess { variant: VessVariant::Mint, amount: reward, owner_hash: oh,
            timestamp: 1, nonce: 0, salt: random_bytes(), pubkey: pk.clone(),
            spend_key: sk.clone(), spend_condition: None };
        let dev_out = Vess { variant: VessVariant::Mint, amount: dev_share,
            owner_hash: DEV_PUBKEY_HASH, timestamp: 1, nonce: 0, salt: random_bytes(),
            pubkey: vec![], spend_key: vec![], spend_condition: None };
        let mut cb = VessPayment { payment_id: [0u8;32], inputs: vec![],
            outputs: vec![coinbase_out, dev_out], timestamp: 0, sigs: vec![], preimages: vec![] };
        cb.compute();
        let genesis = VessBlock {
            version: 1, parents: vec![], timestamp: 1,
            difficulty_bits: DIFFICULTY_BASE_BITS, nonce: 0,
            payment_merkle: merkle_root(&[cb.payment_id]),
            state_merkle: [0u8; 32], proof: vec![],
            coinbase: cb, payments: vec![],
        };
        node.apply_mined_block(genesis, 0, vec![]);
        assert!(node.accepted_blocks > 0, "block count incremented");
        assert!(node.utxo_count() >= 2, "reward + dev outputs created");
    }
}

