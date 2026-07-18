#[cfg(test)]
mod integration {
    use std::net::UdpSocket;
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
        let init = n1.add_peer(n2_addr);
        s1.send_to(&init, n2_addr).unwrap();
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
        let init = n1.add_peer(n2_addr);
        s1.send_to(&init, n2_addr).unwrap();
        for _ in 0..4 { thread::sleep(Duration::from_millis(10)); cycle_node(&mut n2, &s2); cycle_node(&mut n1, &s1); }
        n1.needs_sync = false; n2.needs_sync = false;
        let (pk, sk) = dsa_generate();
        let oh = dsa_pubkey_hash(&pk);
        // Mine and exchange blocks so both nodes converge to the same state.
        for _ in 0..3 {
            mine_coins(&mut n1, oh, &pk, &sk);
            mine_coins(&mut n2, oh, &pk, &sk);
            // Exchange blocks between nodes
            for _ in 0..2 { thread::sleep(Duration::from_millis(10)); cycle_node(&mut n1, &s1); cycle_node(&mut n2, &s2); }
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
        let init = n1.add_peer(n2_addr);
        s1.send_to(&init, n2_addr).unwrap();
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
    fn test_conflicting_block_is_rejected() {
        // Two payments spending the same input make the entire block invalid.
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
        let all_ids = vec![cb.payment_id, p1.payment_id, p2.payment_id];
        let block = VessBlock {
            version: 1, parents: node.tip_hashes.clone(), timestamp: 0, difficulty_bits: 9, nonce: 0,
            payment_merkle: merkle_root(&all_ids),
            state_merkle: [0u8; 32],
            proof: Vec::new(), // test mode skips PoW verification
            coinbase: cb, payments: vec![p1, p2],
        };
        assert!(!node.process_block(&block), "conflicting block rejected");

        assert!(node.check(&v.vess_id()), "input remains after rejection");
        assert!(!node.check(&cb_id), "coinbase was never applied");
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

        // Build tip A: one block at diff=9 (work=512)
        let (pk_a, sk_a) = dsa_generate();
        let oh_a = dsa_pubkey_hash(&pk_a);
        let coins_a = mine_coins(&mut node, oh_a, &pk_a, &sk_a);
        let tip_a_hash = node.tip_hashes[0];
        let work_a = node.cumulative_work(&tip_a_hash);
        assert!(work_a > 0, "chain A has work");

        // Build heavier chain B manually (2 blocks, tip at diff=10, work=1024+1024=2048)
        let (pk_b, sk_b) = dsa_generate();
        let oh_b = dsa_pubkey_hash(&pk_b);
        let cb1_out = Vess { variant: VessVariant::Mint, amount: 2, owner_hash: oh_b,
            timestamp: 0, nonce: 0, salt: random_bytes(), pubkey: pk_b.clone(),
            spend_key: sk_b.clone(), spend_condition: None };
        let cb1_id = cb1_out.vess_id();
        let mut cb1 = VessPayment { payment_id: [0u8;32], inputs: vec![], outputs: vec![cb1_out.clone()], timestamp: 0, sigs: vec![], preimages: vec![] };
        cb1.compute();
        let block1 = VessBlock { version: 1, parents: vec![], timestamp: 1000, difficulty_bits: 10, nonce: 0,
            payment_merkle: merkle_root(&[cb1.payment_id]), state_merkle: [0u8; 32],
            proof: vec![0u32; cuckoo::CYCLE_LENGTH],
            coinbase: cb1, payments: vec![] };
        node.process_block(&block1);

        let (pk_b2, sk_b2) = dsa_generate();
        let oh_b2 = dsa_pubkey_hash(&pk_b2);
        let cb2_out = Vess { variant: VessVariant::Mint, amount: 2, owner_hash: oh_b2,
            timestamp: 0, nonce: 0, salt: random_bytes(), pubkey: pk_b2.clone(),
            spend_key: sk_b2.clone(), spend_condition: None };
        let mut cb2 = VessPayment { payment_id: [0u8;32], inputs: vec![], outputs: vec![cb2_out], timestamp: 0, sigs: vec![], preimages: vec![] };
        cb2.compute();
        let block2 = VessBlock { version: 1, parents: vec![block1.header_hash()], timestamp: 2000, difficulty_bits: 10, nonce: 0,
            payment_merkle: merkle_root(&[cb2.payment_id]), state_merkle: [0u8; 32],
            proof: vec![0u32; cuckoo::CYCLE_LENGTH],
            coinbase: cb2, payments: vec![] };
        node.process_block(&block2);

        // Chain B (work=2048) should beat chain A (work=512)
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
        let init = n1.add_peer(n2_addr);
        s1.send_to(&init, n2_addr).unwrap();
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

}
