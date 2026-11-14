//! Consensus tests: genesis, block validation, transfers, fork choice, and retargeting.

use std::collections::HashSet;

use vess_core::constants::*;

/// What a block at genesis difficulty pays its miner: the full reward minus the 1% dev fee.
const MINED: u64 = GENESIS_REWARD - GENESIS_REWARD / 100;
use vess_core::hash::{self, DOM_TRANSFER};
use vess_core::{AccountId, BlockHeader, Hash, Transaction, Transfer};
use vess_state::State;

use crate::block::{apply_body, build_template, validate_block};
use crate::chain::{Chain, median_time_past, required_target};
use crate::error::ConsensusError;

fn devnet() -> NetworkProfile {
    NetworkProfile::DEVNET
}

fn testnet() -> NetworkProfile {
    NetworkProfile::TESTNET
}

struct Harness {
    chain: Chain,
    state: State,
    network: NetworkProfile,
}

impl Harness {
    fn new(network: NetworkProfile) -> Self {
        Harness {
            chain: Chain::new(network),
            state: State::new(),
            network,
        }
    }

    /// A harness whose chain carries an explicit checkpoint list.
    fn with_checkpoints(network: NetworkProfile, checkpoints: Vec<crate::Checkpoint>) -> Self {
        Harness {
            chain: Chain::with_checkpoints(network, checkpoints),
            state: State::new(),
            network,
        }
    }

    fn timestamp(&self) -> u64 {
        self.chain.best_header().timestamp_unix_ms + 1
    }

    /// Build, mine, validate, and insert a block. Panics on any rejection.
    fn mine_block(&mut self, payout: &AccountId, timestamp: u64, txs: &[Transaction]) -> Hash {
        let mut template = build_template(
            &self.chain,
            &self.network,
            &self.chain.best_id(),
            &self.state,
            payout,
            timestamp,
            txs,
        )
        .expect("template");
        assert!(
            template.mine(20_000_000),
            "devnet difficulty should be trivially mineable"
        );
        let bytes = template.encode();
        let validated =
            validate_block(&self.chain, &self.network, &self.state, &bytes).expect("valid block");
        self.state = validated.state;
        let id = validated.header.id();
        self.chain.insert(validated.header).expect("insert");
        id
    }
}

impl Harness {
    /// Mine `blocks` empty blocks to `who`, so a test can start from a known balance.
    fn fund(&mut self, who: &AccountId, blocks: u64) {
        for _ in 0..blocks {
            let ts = self.timestamp();
            self.mine_block(who, ts, &[]);
        }
    }
}

fn key(seed: u8) -> vess_crypto::Key {
    vess_crypto::key_from_seed([seed; 32])
}

fn account(key: &vess_crypto::Key) -> AccountId {
    vess_crypto::account_id(&vess_crypto::public_key_bytes(key))
}

fn signed_transfer(
    key: &vess_crypto::Key,
    recipient: AccountId,
    amount: u64,
    fee: u64,
    nonce: u64,
) -> Transfer {
    let mut tx = Transfer {
        version: PROTOCOL_VERSION,
        chain_id: hash::chain_id(NETWORK_DEVNET),
        sender_public_key: vess_crypto::public_key_bytes(key),
        recipient_account_id: recipient,
        amount,
        fee,
        nonce,
        expiry_unix: 0,
        signature: [0u8; ML_DSA_SIG_BYTES],
    };
    tx.signature = vess_crypto::sign(key, DOM_TRANSFER, &tx.unsigned_bytes()).unwrap();
    tx
}

#[test]
fn genesis_matches_the_specification() {
    let chain = Chain::new(devnet());
    let genesis = chain.best_header();

    assert_eq!(genesis.version, PROTOCOL_VERSION);
    assert_eq!(genesis.chain_id, hash::chain_id(NETWORK_DEVNET));
    assert_eq!(genesis.previous_block_id, [0u8; 32]);
    assert_eq!(genesis.transaction_root, hash::empty_tx_root());
    assert_eq!(genesis.state_root, crate::chain::empty_state_root());
    assert_eq!(
        genesis.timestamp_unix_ms,
        NetworkProfile::DEVNET.genesis_timestamp_ms
    );
    assert_eq!(genesis.target, NetworkProfile::DEVNET.genesis_target);
    assert_eq!(genesis.payout_account_id, [0u8; 32]);
    assert_eq!(genesis.security_nonce, [0u8; 32]);

    assert_eq!(chain.best_height(), 0);
    assert_eq!(chain.main_height(), 0);
    assert_eq!(chain.best_work(), 65_535);
}

#[test]
fn empty_block_pays_the_reward_and_advances_the_chain() {
    let mut h = Harness::new(devnet());
    let miner = account(&key(1));
    let ts = h.timestamp();

    h.mine_block(&miner, ts, &[]);

    assert_eq!(h.chain.best_height(), 1);
    assert_eq!(h.chain.best_work(), 2 * 65_535);
    assert_eq!(h.state.balance(&miner), MINED);
    assert_eq!(h.state.total_supply(), GENESIS_REWARD as u128);
}

#[test]
fn a_checkpoint_rejects_any_other_block_at_its_height() {
    // A long-range fork is not detectable by work alone, so the checkpoint decides: whatever work a
    // competing history has, only one id is allowed at a settled height.
    let miner = account(&key(1));
    let mut honest = Harness::new(devnet());
    let mut ids = Vec::new();
    for _ in 0..3 {
        let ts = honest.timestamp();
        ids.push(honest.mine_block(&miner, ts, &[]));
    }

    // Replaying the same history with its block 2 checkpointed changes nothing.
    let mut settled = Harness::with_checkpoints(
        devnet(),
        vec![crate::Checkpoint {
            height: 2,
            id: ids[1],
        }],
    );
    for _ in 0..3 {
        let ts = settled.timestamp();
        settled.mine_block(&miner, ts, &[]);
    }
    assert_eq!(
        settled.chain.best_id(),
        ids[2],
        "the honest history still passes"
    );

    // A checkpoint naming another block makes exactly that history unacceptable.
    let mut fork = Harness::with_checkpoints(
        devnet(),
        vec![crate::Checkpoint {
            height: 2,
            id: [0xABu8; 32],
        }],
    );
    let ts = fork.timestamp();
    fork.mine_block(&miner, ts, &[]);
    let timestamp = fork.timestamp();
    let template = build_template(
        &fork.chain,
        &fork.network,
        &fork.chain.best_id(),
        &fork.state,
        &miner,
        timestamp,
        &[],
    )
    .unwrap();
    let mut header = template.header;
    assert!(crate::mine_header(&mut header, 20_000_000));
    assert_eq!(
        fork.chain.insert(header),
        Err(ConsensusError::CheckpointMismatch),
        "a checkpointed height holds one block and no other"
    );
    assert_eq!(fork.chain.best_height(), 1, "the fork was not adopted");
}

#[test]
fn checkpoint_lookup_is_exact_and_ignores_other_heights() {
    let checkpoints = [crate::Checkpoint {
        height: 10,
        id: [3u8; 32],
    }];
    assert!(crate::check_checkpoint(&checkpoints, 10, &[3u8; 32]).is_ok());
    assert_eq!(
        crate::check_checkpoint(&checkpoints, 10, &[4u8; 32]),
        Err(ConsensusError::CheckpointMismatch)
    );
    // Heights without a checkpoint are unaffected, and an empty list settles nothing.
    assert!(crate::check_checkpoint(&checkpoints, 11, &[4u8; 32]).is_ok());
    assert!(crate::check_checkpoint(&[], 10, &[4u8; 32]).is_ok());
}

/// The reward is a function of the block's own target, so a block mined at twice the difficulty
/// pays twice as much and revenue per hash is unchanged.
#[test]
fn a_harder_target_pays_proportionally() {
    let network = devnet();
    let miner = account(&key(1));
    let mut previous = 0u64;
    for exp in [240u32, 239, 238] {
        let target = vess_core::U256::pow2(exp);
        let mut state = State::new();
        apply_body(
            &mut state,
            &hash::chain_id(NETWORK_DEVNET),
            &network,
            target,
            &[],
            network.genesis_timestamp_ms,
            &miner,
        )
        .expect("empty body applies");
        let (miner_share, dev_fee) = vess_emission::split(network, target);
        assert_eq!(state.balance(&miner), miner_share);
        assert_eq!(state.balance(&DEV_FEE_ACCOUNT), dev_fee);
        if exp != 240 {
            assert_eq!(
                miner_share,
                2 * previous,
                "2^{exp} must pay twice 2^{}",
                exp + 1
            );
        }
        previous = miner_share;
    }
}

/// The development fee is taken out of the reward, not added to it: the miner gets 99%, the dev
/// account 1% (floored), and total issuance is exactly the reward.
#[test]
fn the_dev_fee_is_one_percent_of_the_reward() {
    let network = devnet();
    let miner = account(&key(1));
    let dev = vess_core::constants::DEV_FEE_ACCOUNT;
    // 100 * 2^240 / 2^233 = 12 800, so the split is 128 / 12 672.
    let target = vess_core::U256::pow2(233);
    let reward = vess_emission::reward(network, target);
    assert_eq!(reward, 12_800);

    let mut state = State::new();
    apply_body(
        &mut state,
        &hash::chain_id(NETWORK_DEVNET),
        &network,
        target,
        &[],
        network.genesis_timestamp_ms,
        &miner,
    )
    .expect("empty body applies");

    assert_eq!(state.balance(&dev), 128);
    assert_eq!(state.balance(&miner), 12_672);
    assert_eq!(state.total_supply(), reward as u128);
}

/// At genesis difficulty the split is exactly 99 / 1: the fee is a whole unit from the first block.
#[test]
fn genesis_blocks_pay_exactly_one_unit_of_dev_fee() {
    let network = devnet();
    let miner = account(&key(1));
    let mut state = State::new();
    apply_body(
        &mut state,
        &hash::chain_id(NETWORK_DEVNET),
        &network,
        network.genesis_target,
        &[],
        network.genesis_timestamp_ms,
        &miner,
    )
    .expect("empty body applies");

    assert_eq!(state.balance(&miner), GENESIS_REWARD - 1);
    assert_eq!(state.balance(&DEV_FEE_ACCOUNT), 1);
    assert_eq!(state.account_count(), 2);
}

/// If difficulty eases 2x below genesis the reward halves to 50, which floors the fee to zero: the dev
/// account is not created, and the miner keeps the whole reward.
#[test]
fn no_dev_fee_is_charged_below_one_hundred_units() {
    let network = devnet();
    let miner = account(&key(1));
    let target = vess_core::U256::pow2(241); // twice as easy as genesis
    let mut state = State::new();
    apply_body(
        &mut state,
        &hash::chain_id(NETWORK_DEVNET),
        &network,
        target,
        &[],
        network.genesis_timestamp_ms,
        &miner,
    )
    .expect("empty body applies");

    assert_eq!(state.balance(&miner), 50);
    assert_eq!(state.balance(&DEV_FEE_ACCOUNT), 0);
    assert_eq!(state.account_count(), 1, "the dev account must not exist");
}

#[test]
fn transfer_moves_funds_and_pays_the_fee() {
    let mut h = Harness::new(devnet());
    let alice_key = key(2);
    let alice = account(&alice_key);
    let bob = [0xB0u8; 32];

    h.fund(&alice, 20);
    let funded = h.state.balance(&alice);
    assert_eq!(funded, 20 * MINED);

    let tx = signed_transfer(&alice_key, bob, 5, 2, 0);
    let t2 = h.timestamp();
    h.mine_block(&alice, t2, &[Transaction::Transfer(tx)]);

    // Funded balance, minus amount + fee, plus the second reward and the fee paid back to the miner.
    let reward = MINED;
    assert_eq!(h.state.balance(&alice), funded - 7 + reward + 2);
    assert_eq!(h.state.balance(&bob), 5);
    assert_eq!(h.state.next_nonce(&alice), Some(1));
}

#[test]
fn a_replayed_transfer_is_rejected_by_consensus() {
    let mut h = Harness::new(devnet());
    let alice_key = key(3);
    let alice = account(&alice_key);
    let bob = [0xB1u8; 32];

    h.fund(&alice, 2);

    let tx = signed_transfer(&alice_key, bob, 1, 1, 0);
    let pre_transfer_state = h.state.clone();
    let t2 = h.timestamp();
    h.mine_block(&alice, t2, &[Transaction::Transfer(tx.clone())]);

    // The same transaction again, built against the state where it was still valid (which is how a
    // peer that had not seen the first inclusion would assemble it), then validated against the
    // state that already consumed nonce 0.
    let template = build_template(
        &h.chain,
        &h.network,
        &h.chain.best_id(),
        &pre_transfer_state,
        &alice,
        h.timestamp(),
        &[Transaction::Transfer(tx)],
    )
    .expect("a stale peer can still assemble this block");
    let mut template = template;
    assert!(template.mine(20_000_000));
    let err = validate_block(&h.chain, &h.network, &h.state, &template.encode()).unwrap_err();
    match err {
        ConsensusError::BadTransaction { reason, .. } => {
            assert!(matches!(
                reason,
                crate::error::TxReject::InvalidState(vess_state::StateError::BadNonce)
            ));
        }
        other => panic!("unexpected: {other}"),
    }
}

#[test]
fn a_forged_signature_is_rejected() {
    let mut h = Harness::new(devnet());
    let alice_key = key(4);
    let alice = account(&alice_key);
    let bob = [0xB2u8; 32];

    let t1 = h.timestamp();
    h.mine_block(&alice, t1, &[]);

    // Sign with Alice's key, then substitute a different sender key: the id binding breaks.
    let mut tx = signed_transfer(&alice_key, bob, 1, 1, 0);
    let mallory = key(5);
    tx.sender_public_key = vess_crypto::public_key_bytes(&mallory);
    let t2 = h.timestamp();
    let built = build_template(
        &h.chain,
        &h.network,
        &h.chain.best_id(),
        &h.state,
        &alice,
        t2,
        &[Transaction::Transfer(tx)],
    );
    assert!(
        built.is_err() || {
            let mut t = built.unwrap();
            t.mine(20_000_000);
            matches!(
                validate_block(&h.chain, &h.network, &h.state, &t.encode()),
                Err(ConsensusError::BadTransaction {
                    reason: crate::error::TxReject::BadSignature,
                    ..
                })
            )
        }
    );
}

#[test]
fn header_validation_rejects_bad_fields() {
    let h = Harness::new(devnet());
    let genesis = h.chain.best_header();

    let header = BlockHeader {
        version: PROTOCOL_VERSION,
        chain_id: hash::chain_id(NETWORK_DEVNET),
        previous_block_id: genesis.id(),
        transaction_root: hash::empty_tx_root(),
        state_root: genesis.state_root,
        timestamp_unix_ms: genesis.timestamp_unix_ms + 1,
        target: genesis.target,
        payout_account_id: [1u8; 32],
        security_nonce: [0u8; 32],
    };

    // Wrong version.
    let mut bad = header;
    bad.version = PROTOCOL_VERSION + 1;
    assert_eq!(
        h.chain.validate_header(&bad),
        Err(ConsensusError::BadVersion)
    );

    // Wrong chain.
    let mut bad = header;
    bad.chain_id = hash::chain_id(NETWORK_TESTNET);
    assert_eq!(
        h.chain.validate_header(&bad),
        Err(ConsensusError::BadChainId)
    );

    // Unknown parent.
    let mut bad = header;
    bad.previous_block_id = [9u8; 32];
    assert_eq!(
        h.chain.validate_header(&bad),
        Err(ConsensusError::UnknownParent)
    );

    // Wrong target.
    let mut bad = header;
    bad.target = bad.target.checked_sub(vess_core::U256::ONE).unwrap();
    assert_eq!(
        h.chain.validate_header(&bad),
        Err(ConsensusError::BadTarget)
    );

    // Timestamp equal to the median time past.
    let mut bad = header;
    bad.timestamp_unix_ms = genesis.timestamp_unix_ms;
    assert_eq!(
        h.chain.validate_header(&bad),
        Err(ConsensusError::BadTimestamp)
    );

    // Insufficient work.
    let mut bad = header;
    loop {
        if !bad.meets_target() {
            break;
        }
        bad.security_nonce[31] = bad.security_nonce[31].wrapping_add(1);
    }
    assert_eq!(h.chain.validate_header(&bad), Err(ConsensusError::BadPow));
}

#[test]
fn block_validation_rejects_tampering() {
    let h = Harness::new(devnet());
    let miner = account(&key(6));
    let ts = h.timestamp();

    let mut template = build_template(
        &h.chain,
        &h.network,
        &h.chain.best_id(),
        &h.state,
        &miner,
        ts,
        &[],
    )
    .unwrap();
    assert!(template.mine(20_000_000));
    let good = template.encode();
    assert!(validate_block(&h.chain, &h.network, &h.state, &good).is_ok());

    // State root tampered. The PoW covers the header, so re-mine to reach the root check.
    let mut bad = template.clone();
    bad.header.state_root[0] ^= 0xFF;
    assert!(bad.mine(20_000_000));
    assert_eq!(
        validate_block(&h.chain, &h.network, &h.state, &bad.encode()).unwrap_err(),
        ConsensusError::BadStateRoot
    );

    // Transaction root tampered.
    let mut bad = template.clone();
    bad.header.transaction_root[0] ^= 0xFF;
    assert!(bad.mine(20_000_000));
    assert_eq!(
        validate_block(&h.chain, &h.network, &h.state, &bad.encode()).unwrap_err(),
        ConsensusError::BadTxRoot
    );

    // Body unsealed from the header (an extra empty count).
    let mut bytes = good.clone();
    bytes[BLOCK_HEADER_BYTES..BLOCK_HEADER_BYTES + 4].copy_from_slice(&1u32.to_be_bytes());
    assert_eq!(
        validate_block(&h.chain, &h.network, &h.state, &bytes).unwrap_err(),
        ConsensusError::BadTxEncoding
    );
}

#[test]
fn duplicate_transactions_in_one_block_are_rejected() {
    let mut h = Harness::new(devnet());
    let alice_key = key(7);
    let alice = account(&alice_key);
    let bob = [0xB3u8; 32];

    let t1 = h.timestamp();
    h.mine_block(&alice, t1, &[]);

    let tx = signed_transfer(&alice_key, bob, 1, 1, 0);
    let tx = Transaction::Transfer(tx);
    let err = build_template(
        &h.chain,
        &h.network,
        &h.chain.best_id(),
        &h.state,
        &alice,
        h.timestamp(),
        &[tx.clone(), tx],
    )
    .unwrap_err();
    assert_eq!(err, ConsensusError::DuplicateInBlock);
}

#[test]
fn fork_choice_prefers_work_then_the_lower_id() {
    let mut h = Harness::new(devnet());
    let miner = account(&key(8));
    let genesis = h.chain.best_header();
    let ts = genesis.timestamp_unix_ms + 1;

    // Two competing blocks at height 1, identical work.
    let mut ids = HashSet::new();
    let mut headers = Vec::new();
    for extra in 0..2u64 {
        let mut template = build_template(
            &h.chain,
            &h.network,
            &genesis.id(),
            &h.state,
            &miner,
            ts + extra,
            &[],
        )
        .unwrap();
        assert!(template.mine(20_000_000));
        ids.insert(template.header.id());
        headers.push(template.header);
    }
    assert_eq!(ids.len(), 2);

    h.chain.insert(headers[0]).unwrap();
    let first_best = h.chain.best_id();
    let outcome = h.chain.insert(headers[1]).unwrap();

    let expected = if headers[1].id() < first_best {
        headers[1].id()
    } else {
        first_best
    };
    assert_eq!(h.chain.best_id(), expected);
    assert!(matches!(
        outcome,
        crate::chain::InsertOutcome::SideBranch | crate::chain::InsertOutcome::Reorg
    ));
}

/// Build a synthetic chain of `count` blocks without spending PoW.
fn synthetic(network: NetworkProfile, count: u64, ts_step: impl Fn(u64) -> u64) -> Chain {
    let mut chain = Chain::new(network);
    for height in 1..=count {
        let parent = chain.best_header();
        let parent_id = parent.id();
        let target = required_target(&chain, &network, &parent_id, height).unwrap();
        let ts = ts_step(height);
        let header = BlockHeader {
            version: PROTOCOL_VERSION,
            chain_id: hash::chain_id(network.network),
            previous_block_id: parent_id,
            transaction_root: hash::empty_tx_root(),
            state_root: parent.state_root,
            timestamp_unix_ms: ts,
            target,
            payout_account_id: [0u8; 32],
            security_nonce: [0u8; 32],
        };
        chain.insert_unmined(header).expect("synthetic header");
    }
    chain
}

#[test]
fn retarget_eases_when_blocks_arrive_slowly() {
    let network = testnet();
    let base = network.genesis_timestamp_ms;
    // Four seconds per block: the window clamps to 256, i.e. 4x easier.
    let chain = synthetic(network, 128, |h| base + 4_000 * h);
    let retargeted = chain.main_header_at(128).unwrap().target;
    let expected = crate::chain::clamp_target(
        network
            .genesis_target
            .checked_mul_u64(MAX_RETARGET_ELAPSED_MS)
            .unwrap()
            .div_rem(vess_core::U256::from_u64(
                DIFFICULTY_WINDOW_BLOCKS * TARGET_BLOCK_MS,
            ))
            .unwrap()
            .0,
    );
    assert_eq!(retargeted, expected);
    assert!(retargeted > network.genesis_target);
}

#[test]
fn retarget_is_unchanged_at_the_target_rate() {
    let network = testnet();
    let base = network.genesis_timestamp_ms;
    let chain = synthetic(network, 128, |h| base + 1_000 * h);
    assert_eq!(
        chain.main_header_at(128).unwrap().target,
        network.genesis_target
    );
}

#[test]
fn retarget_preserves_subsecond_resolution() {
    let network = testnet();
    let base = network.genesis_timestamp_ms;
    let chain = synthetic(network, 128, |h| base + 1_250 * h);
    let expected = network
        .genesis_target
        .div_rem(vess_core::U256::from_u64(4))
        .unwrap()
        .0
        .checked_mul_u64(5)
        .unwrap();
    assert_eq!(chain.main_header_at(128).unwrap().target, expected);

    let fast = synthetic(network, 128, |h| base + 750 * h);
    let expected_fast = network
        .genesis_target
        .div_rem(vess_core::U256::from_u64(4))
        .unwrap()
        .0
        .checked_mul_u64(3)
        .unwrap();
    assert_eq!(fast.main_header_at(128).unwrap().target, expected_fast);
}

#[test]
fn stalled_timestamps_make_the_chain_harder_never_cheaper() {
    let network = testnet();
    let base = network.genesis_timestamp_ms;
    // Timestamps advance once every two blocks, the slowest cadence the median rule allows.
    let chain = synthetic(network, 128, |h| base + h.div_ceil(2));

    // Recompute the window sum independently from the stored headers.
    let mut elapsed: u64 = 0;
    for i in 64..=127u64 {
        let current = chain.main_header_at(i).unwrap().timestamp_unix_ms;
        let previous = chain.main_header_at(i - 1).unwrap().timestamp_unix_ms;
        elapsed +=
            (current as i64 - previous as i64).clamp(0, MAX_PER_BLOCK_ELAPSED_MS as i64) as u64;
    }
    assert!(
        elapsed < DIFFICULTY_WINDOW_BLOCKS,
        "the window should look fast"
    );

    let elapsed = elapsed.clamp(MIN_RETARGET_ELAPSED_MS, MAX_RETARGET_ELAPSED_MS);
    let expected = crate::chain::clamp_target(
        network
            .genesis_target
            .checked_mul_u64(elapsed)
            .unwrap()
            .div_rem(vess_core::U256::from_u64(
                DIFFICULTY_WINDOW_BLOCKS * TARGET_BLOCK_MS,
            ))
            .unwrap()
            .0,
    );
    let retargeted = chain.main_header_at(128).unwrap().target;
    assert_eq!(retargeted, expected);
    assert!(
        retargeted < network.genesis_target,
        "stalled timestamps must harden the chain"
    );
}
#[test]
fn target_never_leaves_the_permitted_bounds() {
    let network = testnet();
    let base = network.genesis_timestamp_ms;
    // Extremely slow blocks repeatedly push the target up; it must stop at MAXIMUM_TARGET.
    let chain = synthetic(network, 512, |h| base + 4_000 * h);
    for height in 0..=512 {
        let target = chain.main_header_at(height).unwrap().target;
        assert!(target >= MINIMUM_TARGET, "height {height}");
        assert!(target <= MAXIMUM_TARGET, "height {height}");
    }
}

// ---------------------------------------------------------------- edge cases

/// A stale chain can advance to the present while retaining the median-time lower bound.
#[test]
fn timestamp_bounds_are_exact() {
    let mut h = Harness::new(devnet());
    let miner = account(&key(1));
    for _ in 0..3 {
        let ts = h.timestamp();
        h.mine_block(&miner, ts, &[]);
    }

    let best = h.chain.best_id();
    let mtp = median_time_past(&h.chain, &best).unwrap();
    let template = |ts: u64| build_template(&h.chain, &h.network, &best, &h.state, &miner, ts, &[]);

    // At the median there is no progress in time: refused.
    assert!(template(mtp).is_err());
    // One millisecond past the median is the oldest legal block.
    assert!(template(mtp + 1).is_ok());
    assert!(template(mtp + 14 * 24 * 60 * 60 * 1_000).is_ok());

    let id = h.mine_block(&miner, mtp + 14 * 24 * 60 * 60 * 1_000, &[]);
    assert_eq!(h.chain.best_id(), id);
}

/// Two spends from one account can share a block, but the nonces must be sequential.
#[test]
fn one_account_can_spend_twice_in_one_block_if_the_nonces_are_in_order() {
    let mut h = Harness::new(devnet());
    let alice_key = key(1);
    let alice = account(&alice_key);
    let bob = account(&key(2));

    h.fund(&alice, 10);
    assert_eq!(h.state.balance(&alice), 10 * MINED);

    let first = signed_transfer(&alice_key, bob, 2, 1, 0);
    let second = signed_transfer(&alice_key, bob, 3, 1, 1);
    let ts = h.timestamp();
    h.mine_block(
        &alice,
        ts,
        &[Transaction::Transfer(first), Transaction::Transfer(second)],
    );

    assert_eq!(h.state.balance(&bob), 5);
    assert_eq!(h.state.next_nonce(&alice), Some(2));

    // The same pair with the second nonce reused is not a valid block.
    let replay_a = signed_transfer(&alice_key, bob, 1, 1, 0);
    let replay_b = signed_transfer(&alice_key, bob, 1, 1, 0);
    let ts = h.timestamp();
    let rejected = build_template(
        &h.chain,
        &h.network,
        &h.chain.best_id(),
        &h.state,
        &alice,
        ts,
        &[
            Transaction::Transfer(replay_a),
            Transaction::Transfer(replay_b),
        ],
    );
    assert!(rejected.is_err(), "a nonce may only be used once");
}

/// Spending `balance` exactly works once; spending one more unit never does.
#[test]
fn an_account_can_be_emptied_but_not_overdrawn() {
    let mut h = Harness::new(devnet());
    let alice_key = key(1);
    let alice = account(&alice_key);
    let bob = account(&key(2));

    h.fund(&alice, 8);
    let balance = h.state.balance(&alice);
    assert_eq!(balance, 8 * MINED);

    // amount + fee == balance. The block is mined by someone else, so alice really ends at zero.
    let drain = signed_transfer(&alice_key, bob, balance - 3, 3, 0);
    let miner = account(&key(9));
    let ts = h.timestamp();
    h.mine_block(&miner, ts, &[Transaction::Transfer(drain)]);

    assert_eq!(h.state.balance(&alice), 0);
    assert_eq!(h.state.next_nonce(&alice), Some(1));

    // Now one unit past the balance, with the next nonce.
    let greedy = signed_transfer(&alice_key, bob, 1, 0, 1);
    let ts = h.timestamp();
    let rejected = build_template(
        &h.chain,
        &h.network,
        &h.chain.best_id(),
        &h.state,
        &alice,
        ts,
        &[Transaction::Transfer(greedy)],
    );
    assert!(rejected.is_err(), "an empty account cannot pay");
}

/// Expiry uses whole Unix seconds, inclusive of the entire expiration second.
#[test]
fn transfer_expiry_boundary_is_inclusive() {
    let mut h = Harness::new(devnet());
    let alice_key = key(1);
    let alice = account(&alice_key);
    let bob = account(&key(2));

    h.fund(&alice, 4);

    let block_ts = (h.timestamp() / 1_000) * 1_000 + 999;
    let mut exactly = signed_transfer(&alice_key, bob, 2, 1, 0);
    exactly.expiry_unix = block_ts / 1_000;
    exactly.signature =
        vess_crypto::sign(&alice_key, DOM_TRANSFER, &exactly.unsigned_bytes()).unwrap();
    h.mine_block(&alice, block_ts, &[Transaction::Transfer(exactly.clone())]);
    assert_eq!(h.state.balance(&bob), 2);

    let block_ts = h.timestamp();
    let mut one_second_late = signed_transfer(&alice_key, bob, 10, 1, 1);
    one_second_late.expiry_unix = block_ts / 1_000 - 1;
    one_second_late.signature =
        vess_crypto::sign(&alice_key, DOM_TRANSFER, &one_second_late.unsigned_bytes()).unwrap();
    let rejected = build_template(
        &h.chain,
        &h.network,
        &h.chain.best_id(),
        &h.state,
        &alice,
        block_ts,
        &[Transaction::Transfer(one_second_late)],
    );
    assert!(
        rejected.is_err(),
        "an expired transfer must not be mineable"
    );
}

/// Inserting the same block twice is a no-op, and a block below the tip does not rewind it.
#[test]
fn reinserting_a_known_block_is_idempotent() {
    let mut h = Harness::new(devnet());
    let miner = account(&key(1));
    let ts = h.timestamp();
    let first = h.mine_block(&miner, ts, &[]);
    let ts = h.timestamp();
    let second = h.mine_block(&miner, ts, &[]);
    assert_eq!(h.chain.best_height(), 2);

    let work = h.chain.best_work();
    let header = h.chain.main_header_at(1).unwrap();
    assert_eq!(header.id(), first);
    h.chain.insert(header).unwrap();
    assert_eq!(h.chain.best_id(), second);
    assert_eq!(h.chain.best_work(), work);
    assert_eq!(h.chain.best_height(), 2);
}
