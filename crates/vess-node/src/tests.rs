//! End-to-end node tests: mine, persist, transfer, and snapshot through the RPC surface.

use std::sync::{Arc, Mutex};

use vess_core::Transaction;
use vess_core::constants::{GENESIS_REWARD, NetworkProfile};

/// What a block at genesis difficulty pays its miner: the reward minus the 1% dev fee.
const MINED: u64 = GENESIS_REWARD - GENESIS_REWARD / 100;
use vess_net::rpc::{ReplyBody, Request};
use vess_wallet::Wallet;

use crate::{Node, NodeError, bind_rpc, serve};
use vess_net::SnapshotFrame;

struct TempDir {
    path: std::path::PathBuf,
}

impl TempDir {
    fn new() -> TempDir {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "vess-node-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        TempDir { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn node() -> (TempDir, Node) {
    let dir = TempDir::new();
    let node = Node::open(&dir.path, NetworkProfile::DEVNET).unwrap();
    (dir, node)
}

#[test]
fn mining_timestamp_tracks_clock_within_median_window() {
    let median = 1_000;
    assert_eq!(Node::timestamp_for_clock(1_005, median), 1_005);
    assert_eq!(Node::timestamp_for_clock(1_005, median), 1_005);
    assert_eq!(Node::timestamp_for_clock(1_000, median), 1_001);
    assert_eq!(Node::timestamp_for_clock(900, median), 1_001);
    assert_eq!(Node::timestamp_for_clock(121_000, median), 121_000);
    assert_eq!(Node::timestamp_for_clock(200_000, median), 200_000);
}

#[test]
fn future_timestamp_rejected_for_header_and_block_until_clock_catches_up() {
    let (_dir, mut node) = node();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let timestamp = now + vess_core::constants::MAX_FUTURE_DRIFT_MS + 60_000;
    let (mut template, _) = node.template(&[0x21; 32], timestamp).unwrap();
    assert!(template.mine(20_000_000));
    assert!(matches!(
        node.insert_header_only(template.header),
        Err(NodeError::Consensus(_))
    ));
    assert!(matches!(
        node.accept_block(&template.encode()),
        Err(NodeError::Consensus(_))
    ));
    assert_eq!(node.height(), 0);
    assert!(Node::future_timestamp_allowed(
        timestamp,
        (timestamp - vess_core::constants::MAX_FUTURE_DRIFT_MS).into()
    ));
    assert!(!Node::future_timestamp_allowed(
        timestamp,
        (timestamp - vess_core::constants::MAX_FUTURE_DRIFT_MS - 1).into()
    ));
    let boundary = u128::from(timestamp - vess_core::constants::MAX_FUTURE_DRIFT_MS);
    assert!(matches!(
        node.insert_header_only_at(template.header, boundary - 1),
        Err(NodeError::Consensus(_))
    ));
    node.insert_header_only_at(template.header, boundary)
        .unwrap();
    assert!(matches!(
        node.accept_block_at(&template.encode(), boundary - 1),
        Err(NodeError::Consensus(_))
    ));
    node.accept_block_at(&template.encode(), boundary).unwrap();
    assert_eq!(node.height(), 1);
}

#[test]
fn invalid_header_is_reported_and_not_counted() {
    let (_dir, mut node) = node();
    let (mut template, _) = node
        .template(&[0x21; 32], node.next_timestamp_ms())
        .unwrap();
    template.header.version += 1;
    assert!(matches!(
        node.insert_header_only(template.header),
        Err(NodeError::Consensus(_))
    ));
    assert_eq!(node.height(), 0);
}

#[test]
fn stalled_chain_resumes_after_restart_at_current_time() {
    let dir = TempDir::new();
    let payout = [0x21; 32];
    let genesis = NetworkProfile::DEVNET.genesis_timestamp_ms;
    {
        let mut node = Node::open(&dir.path, NetworkProfile::DEVNET).unwrap();
        let (mut template, _) = node.template(&payout, genesis + 1_000).unwrap();
        assert!(template.mine(20_000_000));
        node.accept_block(&template.encode()).unwrap();
    }
    let mut node = Node::open(&dir.path, NetworkProfile::DEVNET).unwrap();
    let now = node.next_timestamp_ms();
    assert!(now > genesis + 120_000);
    let (mut template, _) = node.template(&payout, now).unwrap();
    assert!(template.mine(20_000_000));
    node.accept_block(&template.encode()).unwrap();
    assert_eq!(node.height(), 2);
    assert_eq!(node.tip().timestamp_unix_ms, now);
}

#[test]
fn mining_discards_stale_work_and_accepts_fresh_work() {
    let (_dir, node) = node();
    let (template, _) = node
        .template(&[0x21; 32], node.next_timestamp_ms())
        .unwrap();
    let mut stale = template.header;
    let old = std::time::Instant::now() - crate::MINING_REFRESH_INTERVAL;
    assert!(matches!(
        crate::mine_fresh(&mut stale, 20_000_000, old),
        crate::MiningResult::Refresh
    ));
    let mut fresh = template.header;
    let mut result = crate::MiningResult::Refresh;
    for _ in 0..10 {
        result = crate::mine_fresh(&mut fresh, 20_000_000, std::time::Instant::now());
        if matches!(result, crate::MiningResult::Found) {
            break;
        }
    }
    assert!(matches!(result, crate::MiningResult::Found));
    assert!(fresh.meets_target());
}
#[test]
fn clock_driven_mining_changes_difficulty() {
    let (_dir, mut node) = node();
    let genesis = node.tip().timestamp_unix_ms;
    for height in 1_u64..=128 {
        let median =
            vess_consensus::chain::median_time_past(node.chain(), &node.chain().best_id()).unwrap();
        let timestamp = Node::timestamp_for_clock(genesis + height * 500, median);
        let (mut template, _) = node.template(&[0x21; 32], timestamp).unwrap();
        assert!(template.mine(20_000_000));
        node.accept_block(&template.encode()).unwrap();
    }
    let target = node.tip().target;
    assert_eq!(
        target,
        NetworkProfile::DEVNET
            .genesis_target
            .div_rem(vess_core::U256::from_u64(2))
            .unwrap()
            .0
    );
}

/// Mine a block from the node's own mempool and submit it through the RPC handler.
fn mine_one(node: &mut Node, payout: &[u8; 32]) -> vess_core::Hash {
    let timestamp = node.next_timestamp_ms();
    let (mut template, _) = node.template(payout, timestamp).unwrap();
    assert!(template.mine(20_000_000));
    let bytes = template.encode();
    let reply = node.handle_rpc(Request::SubmitBlock(bytes));
    match reply.body {
        ReplyBody::Accepted(id) => id,
        other => panic!("block was rejected: {other:?} (reason {})", reply.reason),
    }
}

#[test]
fn mine_persist_and_reopen() {
    let dir = TempDir::new();
    let payout = [0x21u8; 32];
    let root;
    let tip;
    {
        let mut node = Node::open(&dir.path, NetworkProfile::DEVNET).unwrap();
        assert_eq!(node.height(), 0);
        tip = mine_one(&mut node, &payout);
        assert_eq!(node.height(), 1);
        assert_eq!(node.balance(&payout), MINED);
        root = node.root();
        assert_eq!(node.tip().id(), tip);
    }

    let mut reopened = Node::open(&dir.path, NetworkProfile::DEVNET).unwrap();
    assert_eq!(reopened.height(), 1);
    assert_eq!(reopened.tip().id(), tip);
    assert_eq!(reopened.root(), root);

    // The chain keeps advancing after a restart.
    mine_one(&mut reopened, &payout);
    assert_eq!(reopened.height(), 2);
    assert_eq!(reopened.balance(&payout), 2 * MINED);
}

#[test]
fn a_transfer_flows_from_wallet_to_block_to_balance() {
    let (_dir, mut node) = node();
    let alice = Wallet::from_seed(0, [0x31u8; 32]);
    let bob = [0xB4u8; 32];

    for _ in 0..5 {
        mine_one(&mut node, &alice.account_id());
    }
    let funded = 5 * MINED;
    assert_eq!(node.balance(&alice.account_id()), funded);

    let tx = alice.build_transfer(bob, 3, 1, 0, 0);
    let reply = node.handle_rpc(Request::SubmitTransfer(tx));
    assert!(reply.is_ok(), "transfer rejected: reason {}", reply.reason);
    assert_eq!(node.mempool().transaction_count(), 1);

    // The template must include the pending transfer.
    let timestamp = node.next_timestamp_ms();
    let (template, height) = node.template(&alice.account_id(), timestamp).unwrap();
    let txs = vess_consensus::decode_body(&template.body).unwrap();
    assert_eq!(txs.len(), 1);
    assert!(matches!(txs[0], Transaction::Transfer(_)));
    assert_eq!(height, node.height() + 1);

    mine_one(&mut node, &alice.account_id());
    assert_eq!(node.balance(&bob), 3);
    // The funded balance, minus amount + fee, plus one reward and the fee paid back to the miner.
    assert_eq!(node.balance(&alice.account_id()), funded - 4 + MINED + 1);
    assert_eq!(node.mempool().transaction_count(), 0);
    assert_eq!(node.account_info(&alice.account_id()).next_nonce, 1);
}

/// A block pays its miner `reward - dev_fee`, and the fee lands on the hard-coded dev account.
#[test]
fn the_dev_fee_reporting_matches_consensus() {
    let (_dir, mut node) = node();
    let miner = [0x7Au8; 32];
    assert_eq!(node.next_reward(), MINED);
    assert_eq!(node.next_dev_fee(), 1);

    mine_one(&mut node, &miner);

    assert_eq!(node.balance(&miner), MINED);
    assert_eq!(node.balance(&vess_core::constants::DEV_FEE_ACCOUNT), 1);
    assert_eq!(node.state().total_supply(), GENESIS_REWARD as u128);
}

/// `BALANCE` must tell "does not exist" apart from "exists with nothing", and `PROOF` must hand back
/// something a verifier can check against the state root.
#[test]
fn account_lookup_reports_existence_and_a_verifiable_proof() {
    let (_dir, mut node) = node();
    let wallet = Wallet::from_seed(0, [0x77u8; 32]);
    let absent = [0x78u8; 32];

    let before = node.account_info(&wallet.account_id());
    assert!(!before.exists, "a fresh chain has no such account");
    assert_eq!(node.account_info(&absent).next_nonce, 0);

    mine_one(&mut node, &wallet.account_id());

    let after = node.account_info(&wallet.account_id());
    assert!(after.exists);
    assert_eq!(after.balance, MINED);
    assert!(!node.account_info(&absent).exists);

    // The proof verifies against the account root the node reports, for both inclusion and absence.
    for (account, expected) in [(wallet.account_id(), true), (absent, false)] {
        let proof = node.proof(&account);
        assert_eq!(proof.siblings.len(), 256);
        assert_eq!(proof.value.is_some(), expected);
        assert!(
            vess_state::SparseMerkle::verify_proof(
                &proof.root,
                &account,
                proof.value.as_deref(),
                &proof.siblings,
            ),
            "proof for {account:?} must verify against its own root"
        );
    }
}

#[test]
fn a_replayed_transfer_is_refused_by_the_mempool() {
    let (_dir, mut node) = node();
    let alice = Wallet::from_seed(0, [0x32u8; 32]);
    mine_one(&mut node, &alice.account_id());

    let tx = alice.build_transfer([0xB5u8; 32], 1, 1, 0, 0);
    assert!(node.handle_rpc(Request::SubmitTransfer(tx.clone())).is_ok());
    // The identical object is a duplicate, not a second pending transaction.
    assert!(!node.handle_rpc(Request::SubmitTransfer(tx.clone())).is_ok());
    mine_one(&mut node, &alice.account_id());

    // After inclusion the same transaction carries a stale nonce: refused at admission.
    let reply = node.handle_rpc(Request::SubmitTransfer(tx));
    assert!(!reply.is_ok());
}

#[test]
fn an_unsigned_transfer_is_refused_at_admission() {
    let (_dir, mut node) = node();
    let alice = Wallet::from_seed(0, [0x33u8; 32]);
    mine_one(&mut node, &alice.account_id());

    let mut tx = alice.build_transfer([0xB6u8; 32], 1, 1, 0, 0);
    tx.signature[10] ^= 0xFF;
    let reply = node.handle_rpc(Request::SubmitTransfer(tx));
    assert!(!reply.is_ok());
}

#[test]
fn an_unaffordable_pending_transfer_does_not_stall_mining() {
    let (_dir, mut node) = node();
    let wallet = Wallet::from_seed(0, [0x56u8; 32]);
    mine_one(&mut node, &wallet.account_id());

    // Admission only checks the nonce, so a transfer larger than the balance gets in.
    let tx = wallet.build_transfer([0xDDu8; 32], 500_000_000, 4, 0, 0);
    node.submit_transfer(tx).unwrap();
    assert_eq!(node.mempool().transaction_count(), 1);

    // Building a block must skip it instead of failing.
    let timestamp = node.next_timestamp_ms();
    let (template, _) = node
        .template(&wallet.account_id(), timestamp)
        .expect("template should still build");
    assert!(template.header.transaction_root == vess_core::hash::tx_root(&[]));

    // The stale entry is collected rather than lingering forever.
    assert_eq!(node.prune_stale().unwrap(), 1);
    assert_eq!(node.mempool().transaction_count(), 0);

    // And a block mined without it is valid.
    mine_one(&mut node, &wallet.account_id());
    assert_eq!(node.height(), 2);
}

#[test]
fn blocks_and_transactions_can_be_looked_up() {
    let (_dir, node) = node();
    let wallet = Wallet::from_seed(0, [0x75u8; 32]);
    let bob = [0xD3u8; 32];
    let shared = Arc::new(Mutex::new(node));

    let listener = bind_rpc("127.0.0.1:0").unwrap();
    let addr = crate::addr_of(&listener).unwrap();
    let served = shared.clone();
    std::thread::spawn(move || {
        let _ = serve(served, listener);
    });

    // A transfer that is pending: known, but not mined.
    let funded = mine_one(&mut shared.lock().unwrap(), &wallet.account_id());
    let tx = wallet.build_transfer(bob, 1, 0, 0, 0);
    let txid = tx.tx_id();
    let mut client = vess_wallet::NodeClient::connect(&addr).unwrap();
    client.submit_transfer(tx).unwrap();

    let pending = client.transaction(txid).unwrap();
    assert!(pending.in_mempool, "the node should be holding it");
    assert_eq!(pending.status, vess_net::tx_status::PENDING);
    assert_eq!(pending.block_id, None);
    assert_eq!(pending.confirmations, 0);
    // Content is reported for a pending transaction too, not just a mined one.
    assert_eq!(pending.kind, 1, "a transfer");
    assert_eq!(pending.sender_id, wallet.account_id());
    assert_eq!(pending.recipient_id, bob);
    assert_eq!(pending.amount, 1);
    assert_eq!(pending.fee, 0);

    // Mine it, then the same lookup reports the block and its depth.
    mine_one(&mut shared.lock().unwrap(), &wallet.account_id());
    let mined = client.transaction(txid).unwrap();
    assert!(!mined.in_mempool);
    assert_eq!(mined.status, vess_net::tx_status::MINED);
    assert_eq!(mined.height, Some(2));
    assert_eq!(mined.confirmations, 1);
    // The body is still in the store, so the content survives being mined.
    assert_eq!(mined.sender_id, wallet.account_id());
    assert_eq!(mined.recipient_id, bob);
    assert_eq!(mined.amount, 1);

    // A transaction nobody has seen reports no content at all, rather than zeros that look real.
    let unknown = client.transaction([0xEEu8; 32]).unwrap();
    assert_eq!(unknown.kind, 0);
    assert_eq!(unknown.status, vess_net::tx_status::UNKNOWN);
    assert_eq!(unknown.block_id, None);
    assert_eq!(unknown.sender_id, [0u8; 32]);

    // A second block deepens it.
    mine_one(&mut shared.lock().unwrap(), &wallet.account_id());
    assert_eq!(client.transaction(txid).unwrap().confirmations, 2);

    // Blocks by height and by id agree, and carry the transaction ids.
    let by_height = client.block(vess_net::rpc::BlockQuery::Height(2)).unwrap();
    assert_eq!(by_height.transaction_ids, vec![txid]);
    let by_id = client
        .block(vess_net::rpc::BlockQuery::Id(by_height.id))
        .unwrap();
    assert_eq!(by_id, by_height);
    assert!(by_height.chain_work > 0);

    // The funding block has no transactions; an unknown height is a rejection.
    let funding = client.block(vess_net::rpc::BlockQuery::Id(funded)).unwrap();
    assert_eq!(funding.height, 1);
    assert!(funding.transaction_ids.is_empty());
    assert!(
        client
            .block(vess_net::rpc::BlockQuery::Height(999))
            .is_err()
    );
}

#[test]
fn a_pruned_node_still_answers_questions_about_old_transactions() {
    // The failure this guards: the transaction index is the only record of where an old transaction
    // was mined, and the header can be pruned away. Without the height stored beside the block id,
    // a fully buried deposit reported zero confirmations and looked like a transaction the node had
    // never seen.
    let (_dir, mut node) = node();
    let wallet = Wallet::from_seed(0, [0x7Bu8; 32]);
    let bob = [0xD8u8; 32];
    mine_one(&mut node, &wallet.account_id());
    let tx = wallet.build_transfer(bob, 1, 0, 0, 0);
    let txid = tx.tx_id();
    node.submit_transfer(tx).unwrap();
    mine_one(&mut node, &wallet.account_id());
    let mined = node.transaction_info(&txid);
    assert_eq!(mined.status, vess_net::tx_status::MINED);
    let mined_height = mined.height.expect("mined at a height");

    // Then outrun the prune floor (256 blocks), which is what keeps the recent window intact.
    while node.height() < 262 {
        mine_one(&mut node, &wallet.account_id());
    }
    node.set_prune_policy(vess_storage::PrunePolicy::new(2, 2))
        .unwrap();
    let report = node.prune_now().unwrap();
    assert!(report.headers_removed > 0, "the header really went away");
    assert!(
        node.block_body(&node.tip().id()).is_some(),
        "the tip is still there, so this is not a torn state"
    );

    let pruned = node.transaction_info(&txid);
    assert_eq!(
        pruned.status,
        vess_net::tx_status::PRUNED,
        "a buried transaction must not look unknown"
    );
    assert_eq!(pruned.height, Some(mined_height));
    assert!(pruned.block_id.is_some(), "the block id is still known");
    assert_eq!(
        pruned.confirmations,
        node.height() - mined_height + 1,
        "confirmations are still countable from the stored height"
    );
    // The content is gone with the body, and saying so is better than inventing it.
    assert_eq!(pruned.kind, 0);
}

#[test]
fn a_state_update_reports_its_new_commitment() {
    let (_dir, mut node) = node();
    let wallet = Wallet::from_seed(0, [0x76u8; 32]);
    mine_one(&mut node, &wallet.account_id());
    let commitment = [0x5Au8; 32];
    let tx = wallet.build_state_update(commitment, 1, 0, 0);
    let txid = tx.tx_id();
    node.submit_state_update(tx).unwrap();

    let info = node.transaction_info(&txid);
    assert_eq!(info.kind, 2, "a state update");
    assert_eq!(info.sender_id, wallet.account_id());
    assert_eq!(info.fee, 1);
    assert_eq!(info.new_state_hash, commitment);
    assert_eq!(info.recipient_id, [0u8; 32], "a state update pays nobody");
    assert_eq!(info.amount, 0);
}

#[test]
fn bans_are_persisted_and_expire() {
    let dir = TempDir::new();
    std::fs::create_dir_all(&dir.path).unwrap();
    let path = dir.path.join("bans.txt");
    let bad: std::net::IpAddr = "203.0.113.9".parse().unwrap();
    let loopback: std::net::IpAddr = "127.0.0.1".parse().unwrap();

    {
        let mut conn = crate::p2p::Connections::default();
        conn.load_bans(path.clone());
        conn.ban(bad);
        conn.ban(loopback);
        assert!(conn.is_banned(bad));
        assert!(!conn.is_banned(loopback), "a local cluster must stay local");
        assert_eq!(conn.ban_count(), 1);
    }

    // The file outlives the process, so a restarted node still refuses the address.
    let text = std::fs::read_to_string(&path).expect("bans.txt was written");
    assert!(text.contains("203.0.113.9"), "{text:?}");
    assert!(!text.contains("127.0.0.1"), "loopback is never written");

    let mut reopened = crate::p2p::Connections::default();
    reopened.load_bans(path.clone());
    assert!(
        reopened.is_banned(bad),
        "a ban a restart forgets is barely a ban"
    );

    // An entry that has already expired is neither honoured nor kept.
    std::fs::write(&path, format!("{bad} 1\n")).unwrap();
    let mut stale = crate::p2p::Connections::default();
    stale.load_bans(path.clone());
    assert!(!stale.is_banned(bad));
    assert_eq!(stale.ban_count(), 0);
    assert!(
        std::fs::read_to_string(&path).unwrap().trim().is_empty(),
        "the expired entry was dropped from the file too"
    );

    // A garbage line is ignored rather than fatal.
    std::fs::write(&path, "not-an-ip 99\n\n").unwrap();
    let mut tolerant = crate::p2p::Connections::default();
    tolerant.load_bans(path);
    assert_eq!(tolerant.ban_count(), 0);
}

#[test]
fn wait_for_tip_blocks_until_the_chain_moves_then_returns_at_once() {
    let dir = TempDir::new();
    let payout = [0x77u8; 32];
    let shared = Arc::new(Mutex::new(
        Node::open(&dir.path, NetworkProfile::DEVNET).unwrap(),
    ));
    let listener = bind_rpc("127.0.0.1:0").unwrap();
    let addr = crate::addr_of(&listener).unwrap();
    let served = shared.clone();
    std::thread::spawn(move || {
        let _ = serve(served, listener);
    });

    let mut client = vess_wallet::NodeClient::connect(&addr).unwrap();
    let genesis = client.status().unwrap().tip;

    // Nothing has happened yet, so a short wait must time out and report the same tip.
    let started = std::time::Instant::now();
    let reply = client
        .call_raw(Request::WaitForTip {
            after: genesis,
            timeout_ms: 400,
        })
        .unwrap();
    assert!(reply.is_ok());
    match reply.body {
        ReplyBody::Tip { tip, height } => {
            assert_eq!(tip, genesis);
            assert_eq!(height, 0);
        }
        other => panic!("expected a tip reply, got {other:?}"),
    }
    assert!(
        started.elapsed() >= std::time::Duration::from_millis(300),
        "the wait should have blocked, not returned immediately"
    );

    // A miner thread produces a block; the waiter is woken rather than polling.
    let miner = shared.clone();
    std::thread::spawn(move || {
        mine_one(&mut miner.lock().unwrap(), &payout);
    });
    let reply = client
        .call_raw(Request::WaitForTip {
            after: genesis,
            timeout_ms: 10_000,
        })
        .unwrap();
    match reply.body {
        ReplyBody::Tip { tip, height } => {
            assert_ne!(tip, genesis, "the new block woke the waiter");
            assert_eq!(height, 1);
        }
        other => panic!("expected a tip reply, got {other:?}"),
    }

    // Asking about a tip that is already stale is answered immediately, so the caller can catch up
    // without waiting for the next block.
    let started = std::time::Instant::now();
    let reply = client
        .call_raw(Request::WaitForTip {
            after: genesis,
            timeout_ms: 10_000,
        })
        .unwrap();
    assert!(matches!(reply.body, ReplyBody::Tip { height: 1, .. }));
    assert!(
        started.elapsed() < std::time::Duration::from_secs(2),
        "a stale `after` must not block"
    );
}

#[test]
fn wait_for_account_stays_quiet_until_the_account_moves() {
    let dir = TempDir::new();
    let payout = [0x78u8; 32];
    let alice = Wallet::from_seed(0, [0x79u8; 32]);
    let shared = Arc::new(Mutex::new(
        Node::open(&dir.path, NetworkProfile::DEVNET).unwrap(),
    ));
    let listener = bind_rpc("127.0.0.1:0").unwrap();
    let addr = crate::addr_of(&listener).unwrap();
    let served = shared.clone();
    std::thread::spawn(move || {
        let _ = serve(served, listener);
    });
    let mut client = vess_wallet::NodeClient::connect(&addr).unwrap();

    // Alice does not exist yet, which is itself the state a wallet starts from.
    let since = match client
        .call_raw(Request::Balance(alice.account_id()))
        .unwrap()
        .body
    {
        ReplyBody::Account(info) => info,
        other => panic!("expected an account reply, got {other:?}"),
    };
    assert!(!since.exists);

    // Blocks that never touch alice must not report a change.
    mine_one(&mut shared.lock().unwrap(), &payout);
    let reply = client
        .call_raw(Request::WaitForAccount {
            account: alice.account_id(),
            since: since.clone(),
            timeout_ms: 400,
        })
        .unwrap();
    match reply.body {
        ReplyBody::Account(info) => assert_eq!(info, since, "an unrelated block is not an event"),
        other => panic!("expected an account reply, got {other:?}"),
    }

    // Once her account appears, the wait returns promptly rather than waiting out the clock.
    mine_one(&mut shared.lock().unwrap(), &alice.account_id());
    let started = std::time::Instant::now();
    let reply = client
        .call_raw(Request::WaitForAccount {
            account: alice.account_id(),
            since,
            timeout_ms: 10_000,
        })
        .unwrap();
    match reply.body {
        ReplyBody::Account(info) => {
            assert!(info.exists, "the account now exists");
            assert_eq!(info.balance, MINED, "and holds the block reward");
        }
        other => panic!("expected an account reply, got {other:?}"),
    }
    assert!(
        started.elapsed() < std::time::Duration::from_secs(2),
        "an account change must return promptly, not when the timeout expires"
    );
}

#[test]
fn the_rpc_surface_answers_over_loopback() {
    let dir = TempDir::new();
    let payout = [0x35u8; 32];
    let mut node = Node::open(&dir.path, NetworkProfile::DEVNET).unwrap();
    mine_one(&mut node, &payout);

    let listener = bind_rpc("127.0.0.1:0").unwrap();
    let addr = crate::addr_of(&listener).unwrap();
    let shared = Arc::new(Mutex::new(node));
    let served = shared.clone();
    std::thread::spawn(move || {
        let _ = serve(served, listener);
    });

    let mut client = vess_wallet::NodeClient::connect(&addr).unwrap();
    let status = client.status().unwrap();
    assert_eq!(status.height, 1);
    assert_eq!(status.network, 0);

    let info = client.balance(payout).unwrap();
    assert_eq!(info.balance, MINED);

    // A full transfer round trip over the wire.
    let alice = Wallet::from_seed(0, [0x36u8; 32]);
    {
        let mut guard = shared.lock().unwrap();
        mine_one(&mut guard, &alice.account_id());
    }
    let tx = alice.build_transfer([0xB7u8; 32], 10, 5, 0, 0);
    let id = client.submit_transfer(tx).unwrap();
    let status = client.status().unwrap();
    assert_eq!(status.mempool_transactions, 1);
    assert_ne!(id, [0u8; 32]);

    // The client can also read the nonce itself: mine the pending transfer, then send again.
    {
        let mut guard = shared.lock().unwrap();
        mine_one(&mut guard, &alice.account_id());
    }
    let bob = [0xB9u8; 32];
    let id = client.transfer(&alice, bob, 1, 0).unwrap();
    assert_ne!(id, [0u8; 32]);
    {
        let mut guard = shared.lock().unwrap();
        mine_one(&mut guard, &alice.account_id());
    }
    assert_eq!(shared.lock().unwrap().balance(&bob), 1);

    let id = client.update_state(&alice, [0x5Au8; 32], 1).unwrap();
    assert_ne!(id, [0u8; 32]);
    assert_eq!(client.status().unwrap().mempool_transactions, 1);
}

// ---------------------------------------------------------------- edge cases

#[test]
fn a_block_with_an_unknown_parent_is_refused() {
    let (_dir_a, mut a) = node();
    let (_dir_b, mut b) = node();
    let payout = [0x61u8; 32];

    let mut ids = Vec::new();
    for _ in 0..3 {
        ids.push(mine_one(&mut a, &payout));
    }
    assert_eq!(a.height(), 3);

    // B has only genesis, so the third block's parent is unknown to it.
    let bytes = a.block_body(&ids[2]).expect("stored block");
    assert!(matches!(
        b.accept_block(&bytes),
        Err(crate::NodeError::UnknownParent)
    ));
    assert_eq!(b.height(), 0);
    assert_eq!(b.balance(&payout), 0);
}

#[test]
fn accepting_the_same_block_twice_changes_nothing() {
    let (_dir, mut node) = node();
    let payout = [0x62u8; 32];
    let id = mine_one(&mut node, &payout);
    let bytes = node.block_body(&id).expect("stored block");

    assert_eq!(node.accept_block(&bytes).unwrap(), id);
    assert_eq!(node.accept_block(&bytes).unwrap(), id);
    assert_eq!(node.height(), 1);
    assert_eq!(node.balance(&payout), MINED);
    assert_eq!(node.state().total_supply(), GENESIS_REWARD as u128);
}

#[test]
fn replaying_a_stored_best_block_resumes_reconciliation() {
    use vess_consensus::chain::HeaderSource;

    let (_source_dir, mut source) = node();
    let (_target_dir, mut target) = node();
    let payout = [0x64u8; 32];
    let id = mine_one(&mut source, &payout);
    let bytes = source.block_body(&id).unwrap();
    let (header, _) = vess_consensus::split_block(&bytes).unwrap();
    target.insert_header_only(header).unwrap();
    let meta = target.chain.meta(&id).unwrap();
    target
        .store
        .put_block_index(&header, meta.height, meta.chain_work, &bytes)
        .unwrap();
    assert_eq!(target.state_height(), 0);

    assert_eq!(target.accept_block(&bytes).unwrap(), id);
    assert_eq!(target.state_height(), 1);
    assert_eq!(target.balance(&payout), MINED);
}

#[test]
fn garbage_on_the_wire_leaves_the_node_healthy() {
    use std::io::Write;

    let (dir_a, mut a) = node();
    let (_dir_b, b) = node();
    let b = Arc::new(Mutex::new(b));
    let payout = [0x63u8; 32];
    mine_one(&mut a, &payout);
    mine_one(&mut a, &payout);

    let shared = Arc::new(Mutex::new(a));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = crate::addr_of(&listener).unwrap();
    let served = shared.clone();
    std::thread::spawn(move || p2p::serve(served, listener, 0));
    let _ = dir_a;

    // Junk that never completes a handshake, junk that is a random frame, and an HTTP request.
    for payload in [
        vec![0u8; 64],
        vec![0xFFu8; 512],
        b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(),
        vess_core::constants::P2P_MAGIC.to_be_bytes().to_vec(),
    ] {
        if let Ok(mut stream) = std::net::TcpStream::connect(addr.as_str()) {
            let _ = stream.write_all(&payload);
        }
    }

    // The node still serves a normal peer and its chain is intact.
    let applied = p2p::sync_once(&b, &addr, 0).unwrap();
    assert_eq!(applied, 2);
    assert_eq!(b.lock().unwrap().height(), 2);
    assert_eq!(
        b.lock().unwrap().tip().id(),
        shared.lock().unwrap().tip().id()
    );
    assert_eq!(shared.lock().unwrap().height(), 2);
}

// ---------------------------------------------------------------- multi-node

use std::net::TcpListener;

use crate::p2p;

struct Network {
    nodes: Vec<Arc<Mutex<Node>>>,
    ports: Vec<u16>,
    _dirs: Vec<TempDir>,
}

impl Network {
    fn new(count: usize) -> Network {
        let dirs: Vec<TempDir> = (0..count).map(|_| TempDir::new()).collect();
        let mut nodes = Vec::new();
        let mut ports = Vec::new();
        for dir in &dirs {
            let node = Arc::new(Mutex::new(
                Node::open(&dir.path, NetworkProfile::DEVNET).unwrap(),
            ));
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            ports.push(port);
            let served = node.clone();
            std::thread::spawn(move || p2p::serve(served, listener, port));
            nodes.push(node);
        }
        Network {
            nodes,
            ports,
            _dirs: dirs,
        }
    }

    fn addr(&self, index: usize) -> String {
        format!("127.0.0.1:{}", self.ports[index])
    }

    /// One pass in each direction between every pair.
    fn sync_all(&self) -> usize {
        let mut total = 0;
        for i in 0..self.nodes.len() {
            for j in 0..self.nodes.len() {
                if i == j {
                    continue;
                }
                total += p2p::sync_once(&self.nodes[i], &self.addr(j), self.ports[i]).unwrap_or(0);
            }
        }
        total
    }

    fn mine(&self, index: usize, payout: &[u8; 32]) -> vess_core::Hash {
        let mut guard = self.nodes[index].lock().unwrap();
        let timestamp = guard.next_timestamp_ms();
        let (mut template, _) = guard.template(payout, timestamp).unwrap();
        assert!(template.mine(20_000_000));
        let bytes = template.encode();
        guard.accept_block(&bytes).unwrap()
    }

    fn heights(&self) -> Vec<u64> {
        self.nodes
            .iter()
            .map(|node| node.lock().unwrap().height())
            .collect()
    }

    fn tips(&self) -> Vec<vess_core::Hash> {
        self.nodes
            .iter()
            .map(|node| node.lock().unwrap().tip().id())
            .collect()
    }

    fn roots(&self) -> Vec<vess_core::Hash> {
        self.nodes
            .iter()
            .map(|node| node.lock().unwrap().root())
            .collect()
    }

    /// (state height, chain height) per node, for diagnosing a divergence.
    fn watermarks(&self) -> Vec<(u64, u64)> {
        self.nodes
            .iter()
            .map(|node| {
                let guard = node.lock().unwrap();
                (guard.state_height(), guard.height())
            })
            .collect()
    }
}

fn assert_converged(network: &Network, expected_height: u64) {
    let heights = network.heights();
    let tips = network.tips();
    let roots = network.roots();
    assert!(
        heights.iter().all(|h| *h == expected_height),
        "heights {heights:?}"
    );
    assert!(
        tips.iter().all(|t| *t == tips[0]),
        "tips diverged: {tips:?}"
    );
    assert!(
        roots.iter().all(|r| *r == roots[0]),
        "state roots diverged: {:?} at height {heights:?} watermarks {:?}",
        &roots[0],
        network.watermarks()
    );
}

#[test]
fn three_nodes_sync_mine_and_agree() {
    let network = Network::new(3);
    let payout = [0x51u8; 32];

    network.mine(0, &payout);
    network.mine(0, &payout);
    assert_eq!(network.heights(), vec![2, 0, 0]);

    network.sync_all();
    assert_converged(&network, 2);
    assert_eq!(network.nodes[2].lock().unwrap().balance(&payout), 2 * MINED);
}

#[test]
fn a_lighter_fork_is_abandoned_for_a_heavier_branch() {
    let network = Network::new(3);
    let payout = [0x52u8; 32];

    // Common history: height 2 everywhere.
    network.mine(0, &payout);
    network.mine(0, &payout);
    network.sync_all();
    assert_converged(&network, 2);

    // Node 1 mines one block of its own...
    let lonely = network.mine(1, &payout);
    assert_eq!(network.heights(), vec![2, 3, 2]);

    // ...while node 2 builds a two-block branch from the same parent, which is heavier.
    network.mine(2, &payout);
    network.mine(2, &payout);
    assert_eq!(network.heights(), vec![2, 3, 4]);

    // Node 1 must rewind its own block and adopt node 2's branch.
    network.sync_all();
    assert_converged(&network, 4);
    assert_ne!(network.tips()[1], lonely);
    assert_eq!(network.tips()[1], network.tips()[2]);

    // Node 0 agrees too, and the heavy branch's payouts are what exists.
    network.sync_all();
    assert_converged(&network, 4);
    assert_eq!(network.nodes[0].lock().unwrap().balance(&payout), 4 * MINED);

    // The abandoned block is still indexed as a side branch, not lost.
    assert!(network.nodes[1].lock().unwrap().chain().contains(&lonely));
}

#[test]
fn transfers_propagate_across_the_network() {
    let network = Network::new(3);
    let alice = Wallet::from_seed(0, [0x53u8; 32]);
    let bob = [0xB9u8; 32];

    // Fund Alice on node 0 and spread the chain.
    network.mine(0, &alice.account_id());
    network.sync_all();
    assert_converged(&network, 1);

    // Submit over RPC to node 2, mine on node 0, and check every node.
    let listener = bind_rpc("127.0.0.1:0").unwrap();
    let addr = crate::addr_of(&listener).unwrap();
    let served = network.nodes[2].clone();
    std::thread::spawn(move || {
        let _ = serve(served, listener);
    });

    let mut client = vess_wallet::NodeClient::connect(&addr).unwrap();
    let tx = alice.build_transfer(bob, 1, 0, 0, 0);
    client.submit_transfer(tx).unwrap();
    assert_eq!(
        network.nodes[2]
            .lock()
            .unwrap()
            .mempool()
            .transaction_count(),
        1
    );

    // Node 0 does not have that transaction, so it mines an empty block. Node 2 adopts that block
    // and then mines the transaction on top of it: same branch, one block higher, so the outcome
    // does not depend on a fork-choice tie-break.
    network.mine(0, &alice.account_id());
    network.sync_all();
    {
        let mut guard = network.nodes[2].lock().unwrap();
        let timestamp = guard.next_timestamp_ms();
        let (mut template, _) = guard.template(&alice.account_id(), timestamp).unwrap();
        assert!(template.mine(20_000_000));
        let bytes = template.encode();
        guard.accept_block(&bytes).unwrap();
    }
    network.sync_all();
    network.sync_all();

    let height = network.heights()[0];
    assert_converged(&network, height);
    assert_eq!(network.heights(), vec![height, height, height]);
    for node in &network.nodes {
        let guard = node.lock().unwrap();
        assert_eq!(guard.balance(&bob), 1, "bob missing");
        assert_eq!(guard.account_info(&alice.account_id()).next_nonce, 1);
    }

    // Mining pays the same reward on every node that shares the same target.
    {
        let mut guard = network.nodes[1].lock().unwrap();
        let timestamp = guard.next_timestamp_ms();
        let (mut template, _) = guard.template(&alice.account_id(), timestamp).unwrap();
        assert!(template.mine(20_000_000));
        let bytes = template.encode();
        guard.accept_block(&bytes).unwrap();
    }
    network.sync_all();
    network.sync_all();

    let height = network.heights()[0];
    assert_converged(&network, height);
    for node in &network.nodes {
        let guard = node.lock().unwrap();
        assert_eq!(guard.status().next_reward, MINED);
    }
}

#[test]
fn a_transaction_adopted_through_a_reorg_leaves_the_mempool() {
    let network = Network::new(3);
    let wallet = Wallet::from_seed(0, [0x55u8; 32]);
    let bob = [0xCCu8; 32];

    // Common history at height 2, funded by node 0.
    network.mine(0, &wallet.account_id());
    network.mine(0, &wallet.account_id());
    network.sync_all();
    assert_converged(&network, 2);

    // Node 1 mines its own block, so node 2's branch starts as a side branch for it.
    network.mine(1, &wallet.account_id());
    assert_eq!(network.heights(), vec![2, 3, 2]);

    // Node 2 mines the transfer on its own branch. Node 1 is not holding the transaction yet,
    // so accepting that block has nothing to prune.
    let tx = wallet.build_transfer(bob, 1, 0, 0, 0);
    network.nodes[2]
        .lock()
        .unwrap()
        .submit_transfer(tx.clone())
        .unwrap();
    network.mine(2, &wallet.account_id());

    // The same transaction reaches node 1 afterwards, from node 0.
    network.nodes[0]
        .lock()
        .unwrap()
        .submit_transfer(tx.clone())
        .unwrap();
    p2p::sync_once(&network.nodes[1], &network.addr(0), network.ports[1]).unwrap();
    assert_eq!(
        network.nodes[1]
            .lock()
            .unwrap()
            .mempool()
            .transaction_count(),
        1,
        "node 1 should be holding the transaction"
    );

    // One more block on node 2's branch makes it heavier, so node 1 replays both blocks and
    // adopts the transfer it was still holding.
    network.mine(2, &wallet.account_id());
    network.sync_all();
    assert_converged(&network, 4);

    let guard = network.nodes[1].lock().unwrap();
    assert_eq!(guard.balance(&bob), 1);
    assert_eq!(
        guard.mempool().transaction_count(),
        0,
        "an adopted transaction must not stay pending"
    );
    // A stale entry would make the nonce already-used and break template building.
    let timestamp = guard.next_timestamp_ms();
    assert!(guard.template(&wallet.account_id(), timestamp).is_ok());
}

/// A block that loses fork choice is stored as a side branch, but it must not remove the
/// transactions it contains from the mempool: they were never mined on the chain this node follows.
#[test]
fn a_side_branch_block_does_not_evict_its_transactions() {
    let (_dir, mut node) = node();
    let alice = Wallet::from_seed(0, [0x57u8; 32]);
    let bob = [0xE1u8; 32];

    // Fund Alice, then advance the main chain past the height the side branch will fork from.
    for _ in 0..2 {
        mine_one(&mut node, &alice.account_id());
    }
    let fork = node.tip().id();
    for _ in 0..2 {
        mine_one(&mut node, &alice.account_id());
    }

    let tx = alice.build_transfer(bob, 1, 0, 0, 0);
    node.submit_transfer(tx.clone()).unwrap();
    assert_eq!(node.mempool().transaction_count(), 1);

    // Build a block on the fork point that includes the pending transfer, as an attacking miner can.
    let parent_state = node.state_at(&fork).unwrap();
    let timestamp = node.next_timestamp_ms();
    let mut template = vess_consensus::build_template(
        node.chain(),
        &node.network,
        &fork,
        &parent_state,
        &alice.account_id(),
        timestamp,
        &[Transaction::Transfer(tx)],
    )
    .unwrap();
    assert!(template.mine(20_000_000));
    let side = node.accept_block(&template.encode()).unwrap();

    assert!(
        !node.chain().is_ancestor(&side, &node.tip().id()),
        "the block must stay a side branch"
    );
    assert_eq!(
        node.mempool().transaction_count(),
        1,
        "a losing side branch must not evict its transactions"
    );
}

#[test]
fn transactions_from_an_abandoned_block_return_to_the_mempool() {
    let network = Network::new(2);
    let wallet = Wallet::from_seed(0, [0x54u8; 32]);
    let bob = [0xBBu8; 32];

    // Fund the wallet on node 0 and share the chain.
    network.mine(0, &wallet.account_id());
    network.sync_all();
    assert_converged(&network, 1);

    // Node 1 puts a transfer in a block of its own...
    let tx = wallet.build_transfer(bob, 1, 0, 0, 0);
    network.nodes[1]
        .lock()
        .unwrap()
        .submit_transfer(tx)
        .unwrap();
    network.mine(1, &wallet.account_id());
    assert_eq!(network.nodes[1].lock().unwrap().balance(&bob), 1);

    // ...while node 0 builds a heavier branch that does not include it.
    network.mine(0, &wallet.account_id());
    network.mine(0, &wallet.account_id());

    // Node 1 abandons its block; the transfer must come back to its mempool, not vanish.
    network.sync_all();
    assert_converged(&network, 3);
    assert_eq!(
        network.nodes[1]
            .lock()
            .unwrap()
            .mempool()
            .transaction_count(),
        1
    );
    assert_eq!(network.nodes[1].lock().unwrap().balance(&bob), 0);
}

/// Decode the frames a node would send for `GET_STATE` back into a state.
fn decode_snapshot(frames: &[Vec<u8>]) -> (u64, vess_state::State) {
    let mut start: Option<(u64, u32)> = None;
    let mut accounts = Vec::new();
    for payload in frames {
        match SnapshotFrame::decode(payload).expect("frame decodes") {
            SnapshotFrame::Start {
                height,
                accounts: total_accounts,
            } => start = Some((height, total_accounts)),
            SnapshotFrame::Accounts(items) => accounts.extend(items),
            SnapshotFrame::End { .. } => {}
        }
    }
    let (height, total_accounts) = start.expect("start frame");
    assert_eq!(accounts.len() as u32, total_accounts);
    (height, vess_state::State::restore(accounts))
}

#[test]
fn a_snapshot_reproduces_the_state_of_the_block_it_claims() {
    let dir_a = TempDir::new();
    let dir_b = TempDir::new();
    let a = Arc::new(Mutex::new(
        Node::open(&dir_a.path, NetworkProfile::DEVNET).unwrap(),
    ));
    let mut b = Node::open(&dir_b.path, NetworkProfile::DEVNET).unwrap();

    let wallet = Wallet::from_seed(0, [0x61u8; 32]);
    let payout = wallet.account_id();
    for _ in 0..3 {
        let timestamp = a.lock().unwrap().next_timestamp_ms();
        let (mut template, _) = a.lock().unwrap().template(&payout, timestamp).unwrap();
        assert!(template.mine(20_000_000));
        let bytes = template.encode();
        a.lock().unwrap().accept_block(&bytes).unwrap();
    }
    let transfer = wallet.build_transfer([0x62u8; 32], 1, 0, 0, 0);
    a.lock().unwrap().submit_transfer(transfer).unwrap();
    let timestamp = a.lock().unwrap().next_timestamp_ms();
    let (mut template, _) = a.lock().unwrap().template(&payout, timestamp).unwrap();
    assert!(template.mine(20_000_000));
    let bytes = template.encode();
    a.lock().unwrap().accept_block(&bytes).unwrap();

    let frames = a.lock().unwrap().snapshot_frames();
    let (height, snapshot) = decode_snapshot(&frames);
    assert_eq!(height, a.lock().unwrap().height());

    // B learns the header chain the way a snapshot sync does: headers first, no bodies.
    let headers = a.lock().unwrap().headers_from(0, 64);
    for header in headers {
        b.insert_header_only(header).unwrap();
    }
    assert_eq!(b.height(), height);
    assert_eq!(b.state_height(), 0, "bodies were never fetched");

    b.set_trust_snapshots(true);
    b.install_snapshot(height, snapshot).unwrap();
    assert_eq!(b.state_height(), height);
    assert_eq!(b.root(), a.lock().unwrap().root());
    assert_eq!(b.balance(&payout), a.lock().unwrap().balance(&payout));
    assert_eq!(
        b.balance(&[0x62u8; 32]),
        1,
        "the snapshot carries the transfer"
    );
}

/// Without `--trust-snapshot` a snapshot for a block we never validated is refused: a peer could
/// otherwise mine one header with an invented `state_root` and rewrite our whole account set.
#[test]
fn an_unverifiable_snapshot_is_refused_unless_trusted() {
    let dir_a = TempDir::new();
    let dir_b = TempDir::new();
    let a = Arc::new(Mutex::new(
        Node::open(&dir_a.path, NetworkProfile::DEVNET).unwrap(),
    ));
    let mut b = Node::open(&dir_b.path, NetworkProfile::DEVNET).unwrap();

    let payout = [0x64u8; 32];
    for _ in 0..2 {
        let timestamp = a.lock().unwrap().next_timestamp_ms();
        let (mut template, _) = a.lock().unwrap().template(&payout, timestamp).unwrap();
        assert!(template.mine(20_000_000));
        let bytes = template.encode();
        a.lock().unwrap().accept_block(&bytes).unwrap();
    }
    for header in a.lock().unwrap().headers_from(0, 64) {
        b.insert_header_only(header).unwrap();
    }
    let height = a.lock().unwrap().height();
    let frames = a.lock().unwrap().snapshot_frames();
    let (_, snapshot) = decode_snapshot(&frames);

    assert!(!b.trust_snapshots(), "the default must be opt-out");
    assert!(matches!(
        b.install_snapshot(height, snapshot.clone()),
        Err(NodeError::SnapshotUnproven)
    ));
    assert_eq!(b.state_height(), 0, "a refused snapshot changes nothing");

    // Opting in does not skip the root check, so the snapshot is still honoured when it matches.
    b.set_trust_snapshots(true);
    b.install_snapshot(height, snapshot).unwrap();
    assert_eq!(b.state_height(), height);
    assert_eq!(b.root(), a.lock().unwrap().root());
}

#[test]
fn a_snapshot_that_does_not_match_its_header_is_refused() {
    let dir_a = TempDir::new();
    let dir_b = TempDir::new();
    let a = Arc::new(Mutex::new(
        Node::open(&dir_a.path, NetworkProfile::DEVNET).unwrap(),
    ));
    let mut b = Node::open(&dir_b.path, NetworkProfile::DEVNET).unwrap();

    let payout = [0x63u8; 32];
    for _ in 0..2 {
        let timestamp = a.lock().unwrap().next_timestamp_ms();
        let (mut template, _) = a.lock().unwrap().template(&payout, timestamp).unwrap();
        assert!(template.mine(20_000_000));
        let bytes = template.encode();
        a.lock().unwrap().accept_block(&bytes).unwrap();
    }
    for header in a.lock().unwrap().headers_from(0, 64) {
        b.insert_header_only(header).unwrap();
    }
    let height = a.lock().unwrap().height();

    assert_eq!(a.lock().unwrap().headers_from(0, 64).len(), 3);

    // A state that is plausible but not the one at that height: one account with extra coins.
    let forged = vess_core::Account {
        balance: 1,
        ..Default::default()
    };
    let wrong = vess_state::State::restore([(payout, forged)]);
    // The forged root is refused either way, but only a trusted node gets as far as comparing it.
    assert!(matches!(
        b.install_snapshot(height, wrong.clone()),
        Err(NodeError::SnapshotUnproven)
    ));
    b.set_trust_snapshots(true);
    assert!(matches!(
        b.install_snapshot(height, wrong),
        Err(NodeError::SnapshotMismatch)
    ));
    assert_eq!(b.state_height(), 0, "a refused snapshot changes nothing");

    // The honest snapshot is accepted, and only at the tip of the chain we validated.
    let frames = a.lock().unwrap().snapshot_frames();
    let (_, snapshot) = decode_snapshot(&frames);
    assert!(matches!(
        b.install_snapshot(height - 1, snapshot.clone()),
        Err(NodeError::SnapshotNotAtTip)
    ));
    assert!(matches!(
        b.install_snapshot(height + 5, snapshot.clone()),
        Err(NodeError::UnknownParent)
    ));
    b.install_snapshot(height, snapshot.clone()).unwrap();
    assert_eq!(b.root(), a.lock().unwrap().root());
    assert!(
        matches!(
            b.install_snapshot(height, snapshot),
            Err(NodeError::SnapshotNotNewer)
        ),
        "installing the same snapshot twice is refused"
    );
}
