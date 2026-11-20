//! Consensus tests: genesis, block validation, transfers, fork choice, and retargeting.

use std::collections::HashSet;

use vess_core::constants::*;

/// What a block at genesis difficulty pays its miner: the full reward minus the 1% dev fee.
const MINED: u64 = GENESIS_REWARD - GENESIS_REWARD / 100;
use vess_core::hash::{self, DOM_TRANSFER};
use vess_core::{AccountId, BlockHeader, BlockWitness, Hash, Transaction, Transfer};
use vess_state::State;

use crate::block::{
    apply_body, build_template, split_block, touched_accounts, validate_block, verify_witness,
};
use crate::chain::{Chain, median_time_past, required_target};
use crate::error::{ConsensusError, TxReject};

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
        recipient_account_id: recipient,
        amount,
        fee,
        nonce,
        expiry_unix: 0,
        payload: None,
        authority: vess_core::TransferAuthority::Signature {
            sender_public_key: vess_crypto::public_key_bytes(key),
            signature: [0u8; ML_DSA_SIG_BYTES],
        },
    };
    let signature = vess_crypto::sign(key, DOM_TRANSFER, &tx.unsigned_bytes()).unwrap();
    tx.authority = vess_core::TransferAuthority::Signature {
        sender_public_key: vess_crypto::public_key_bytes(key),
        signature,
    };
    tx
}

/// Re-sign a transfer after mutating its body.
fn resign(key: &vess_crypto::Key, tx: &mut Transfer) {
    let signature = vess_crypto::sign(key, DOM_TRANSFER, &tx.unsigned_bytes()).unwrap();
    tx.authority = vess_core::TransferAuthority::Signature {
        sender_public_key: vess_crypto::public_key_bytes(key),
        signature,
    };
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

/// Fork choice is cumulative work; equal work is broken by the lower block id, deterministically, so
/// every node lands on the same tip without needing to agree on arrival order.
#[test]
fn equal_work_is_broken_by_the_lower_block_id() {
    let h = Harness::new(devnet());
    let miner = account(&key(1));
    let genesis = h.chain.best_header();

    let mut headers = Vec::new();
    for byte in 0..2u8 {
        let mut template = build_template(
            &h.chain,
            &h.network,
            &genesis.id(),
            &h.state,
            &miner,
            genesis.timestamp_unix_ms + 1,
            &[],
        )
        .unwrap();
        // Same parent, target and timestamp: identical work, different id.
        template.header.security_nonce = [byte; 32];
        assert!(template.mine(20_000_000));
        headers.push(template.header);
    }
    assert_ne!(headers[0].id(), headers[1].id());

    let mut chain = Chain::new(devnet());
    for header in &headers {
        chain.insert(*header).unwrap();
    }
    let lower = headers[0].id().min(headers[1].id());
    assert_eq!(chain.best_height(), 1, "a tie never adds height");
    assert_eq!(
        chain.best_id(),
        lower,
        "the lower id wins, whatever order they arrived in"
    );

    // Re-inserting in the opposite order reaches the same tip.
    let mut reversed = Chain::new(devnet());
    for header in headers.iter().rev() {
        reversed.insert(*header).unwrap();
    }
    assert_eq!(reversed.best_id(), lower);
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
            0,
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
        0,
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
        0,
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
        0,
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
fn transaction_versions_gate_the_payload() {
    let mut h = Harness::new(devnet());
    let alice_key = key(6);
    let alice = account(&alice_key);
    h.fund(&alice, 2);

    // Version 3 was written before the payload existed: no presence byte, no payload.
    let legacy = signed_transfer(&alice_key, [0x21u8; 32], 1, 0, 0);
    assert_eq!(legacy.version, PROTOCOL_VERSION);
    assert!(legacy.payload.is_none());

    let mut carrier = Transfer {
        version: TRANSACTION_VERSION,
        payload: Some([0x5Au8; 32]),
        ..signed_transfer(&alice_key, [0x22u8; 32], 1, 0, 1)
    };
    resign(&alice_key, &mut carrier);

    let ts = h.timestamp();
    h.mine_block(
        &alice,
        ts,
        &[
            Transaction::Transfer(legacy),
            Transaction::Transfer(carrier.clone()),
        ],
    );
    assert_eq!(h.state.account(&[0x21u8; 32]).unwrap().balance, 1);
    assert_eq!(h.state.account(&[0x22u8; 32]).unwrap().balance, 1);

    let rejection = |h: &Harness, tx: Transfer| {
        let built = build_template(
            &h.chain,
            &h.network,
            &h.chain.best_id(),
            &h.state,
            &alice,
            h.timestamp(),
            &[Transaction::Transfer(tx)],
        );
        match built {
            Ok(mut template) => {
                assert!(template.mine(20_000_000));
                validate_block(&h.chain, &h.network, &h.state, &template.encode()).unwrap_err()
            }
            Err(error) => error,
        }
    };

    // The payload sits inside the signed body, so changing it invalidates the signature.
    let tampered = Transfer {
        version: TRANSACTION_VERSION,
        payload: Some([0x5Bu8; 32]),
        ..carrier
    };
    assert!(matches!(
        rejection(&h, tampered),
        ConsensusError::BadTransaction {
            reason: crate::error::TxReject::BadSignature,
            ..
        }
    ));

    // A version the protocol does not know is refused outright. One past the joint-transfer version,
    // which is the highest defined.
    let mut future = signed_transfer(&alice_key, [0x23u8; 32], 1, 0, 2);
    future.version = TRANSACTION_VERSION_JOINT + 1;
    assert!(matches!(
        rejection(&h, future),
        ConsensusError::BadTransaction {
            reason: crate::error::TxReject::BadVersion,
            ..
        }
    ));
}

fn rules(
    preimage: &[u8; 32],
    recipient: AccountId,
    owner: AccountId,
    refund_height: u64,
    max_fee: u64,
) -> vess_core::Rules {
    vess_core::Rules {
        version: RULES_VERSION,
        hash_lock: hash::hash_lock(preimage),
        refund_height,
        recipient_account_id: recipient,
        owner_account_id: owner,
        max_fee,
    }
}

fn rules_spend(
    rules: &vess_core::Rules,
    preimage: Option<[u8; PREIMAGE_BYTES]>,
    fee: u64,
    nonce: u64,
    balance: u64,
) -> Transfer {
    let recipient_account_id = if preimage.is_some() {
        rules.recipient_account_id
    } else {
        rules.owner_account_id
    };
    Transfer {
        version: TRANSACTION_VERSION,
        chain_id: hash::chain_id(NETWORK_DEVNET),
        recipient_account_id,
        amount: balance - fee,
        fee,
        nonce,
        expiry_unix: 0,
        payload: None,
        authority: vess_core::TransferAuthority::Rules {
            rules: rules.clone(),
            preimage,
        },
    }
}

/// The rejection a single-transaction block earns, whether it is refused while being assembled or
/// while being validated.
fn block_rejection(h: &Harness, payout: &AccountId, tx: Transfer) -> ConsensusError {
    let built = build_template(
        &h.chain,
        &h.network,
        &h.chain.best_id(),
        &h.state,
        payout,
        h.timestamp(),
        &[Transaction::Transfer(tx)],
    );
    match built {
        Ok(mut template) => {
            assert!(template.mine(20_000_000));
            validate_block(&h.chain, &h.network, &h.state, &template.encode()).unwrap_err()
        }
        Err(error) => error,
    }
}

fn rejected_with(reason: crate::error::TxReject) -> impl Fn(&ConsensusError) -> bool {
    move |error| {
        matches!(
            error,
            ConsensusError::BadTransaction { reason: actual, .. } if *actual == reason
        )
    }
}

/// An escrow is a plain account whose id is the hash of its rules: funding it is an ordinary
/// transfer, and only the preimage can move the balance before the refund height.
#[test]
fn an_escrow_claim_pays_the_recipient_and_nothing_else() {
    let mut h = Harness::new(devnet());
    let alice_key = key(8);
    let alice = account(&alice_key);
    let bob = account(&key(9));
    h.fund(&alice, 2);

    let secret = [0x7Au8; 32];
    let rules = rules(&secret, bob, alice, h.chain.best_height() + 100, 5);
    let escrow = rules.account_id();
    assert_ne!(escrow, alice);

    let deposit = signed_transfer(&alice_key, escrow, 100, 0, 0);
    let ts = h.timestamp();
    h.mine_block(&alice, ts, &[Transaction::Transfer(deposit)]);
    assert_eq!(h.state.balance(&escrow), 100);
    assert_eq!(h.state.balance(&bob), 0);

    // A wrong preimage lands nowhere.
    let wrong = rules_spend(&rules, Some([0x7Bu8; 32]), 0, 0, 100);
    assert!(rejected_with(TxReject::PreimageMismatch)(&block_rejection(
        &h, &alice, wrong
    )));

    // A reveal cannot be redirected.
    let mut elsewhere = rules_spend(&rules, Some(secret), 0, 0, 100);
    elsewhere.recipient_account_id = [0xEEu8; 32];
    assert!(rejected_with(TxReject::WrongDestination)(&block_rejection(
        &h, &alice, elsewhere
    )));

    // The balance is spent whole, and the fee is capped by the rules.
    let partial = rules_spend(&rules, Some(secret), 0, 0, 99);
    assert!(rejected_with(TxReject::PartialSpend)(&block_rejection(
        &h, &alice, partial
    )));
    let greedy = rules_spend(&rules, Some(secret), 6, 0, 100);
    assert!(rejected_with(TxReject::FeeTooHigh)(&block_rejection(
        &h, &alice, greedy
    )));

    // The owner cannot pull it back while the claim window is open.
    let early_refund = rules_spend(&rules, None, 0, 0, 100);
    assert!(rejected_with(TxReject::PreimageMismatch)(&block_rejection(
        &h,
        &alice,
        early_refund
    )));

    let claim = rules_spend(&rules, Some(secret), 2, 0, 100);
    let ts = h.timestamp();
    h.mine_block(&alice, ts, &[Transaction::Transfer(claim)]);
    assert_eq!(h.state.balance(&bob), 98);
    assert_eq!(h.state.balance(&escrow), 0);
}

/// Past `refund_height` the preimage is worthless and only the owner can be paid, whoever submits.
#[test]
fn an_escrow_refund_opens_at_the_refund_height_and_closes_the_claim() {
    let mut h = Harness::new(devnet());
    let alice_key = key(10);
    let alice = account(&alice_key);
    let bob = account(&key(11));
    h.fund(&alice, 2);

    let secret = [0xC3u8; 32];
    let refund_height = h.chain.best_height() + 3;
    let rules = rules(&secret, bob, alice, refund_height, 3);
    let escrow = rules.account_id();

    let deposit = signed_transfer(&alice_key, escrow, 50, 0, 0);
    let ts = h.timestamp();
    h.mine_block(&alice, ts, &[Transaction::Transfer(deposit)]);
    assert!(h.chain.best_height() < refund_height);

    // Still claimable here.
    let claim = rules_spend(&rules, Some(secret), 1, 0, 50);
    assert_eq!(
        build_template(
            &h.chain,
            &h.network,
            &h.chain.best_id(),
            &h.state,
            &alice,
            h.timestamp(),
            &[Transaction::Transfer(claim)],
        )
        .map(|_| ())
        .map_err(|_| ()),
        Ok(())
    );

    // Move to the first refundable height.
    while h.chain.best_height() + 1 < refund_height {
        let ts = h.timestamp();
        h.mine_block(&alice, ts, &[]);
    }
    assert_eq!(h.chain.best_height() + 1, refund_height);

    // The same preimage no longer buys anything.
    let late_claim = rules_spend(&rules, Some(secret), 0, 0, 50);
    assert!(rejected_with(TxReject::ClaimWindowClosed)(
        &block_rejection(&h, &alice, late_claim)
    ));

    // Nor can the refund be redirected away from the owner.
    let mut misdirected = rules_spend(&rules, None, 0, 0, 50);
    misdirected.recipient_account_id = bob;
    assert!(rejected_with(TxReject::WrongDestination)(&block_rejection(
        &h,
        &alice,
        misdirected
    )));

    let refund = rules_spend(&rules, None, 0, 0, 50);
    let before = h.state.balance(&alice);
    let ts = h.timestamp();
    h.mine_block(&alice, ts, &[Transaction::Transfer(refund)]);
    assert_eq!(h.state.balance(&escrow), 0);
    assert!(h.state.balance(&alice) > before);
}

#[test]
fn a_witness_validates_a_block_without_state() {
    let mut h = Harness::new(devnet());
    let alice_key = key(12);
    let alice = account(&alice_key);
    let bob = [0xB7u8; 32];
    h.fund(&alice, 3);

    let mut checked = 0;
    for nonce in 0..3 {
        let root_before = h.state.root();
        let transfer = signed_transfer(&alice_key, bob, 1, 1, nonce);
        let transactions = [Transaction::Transfer(transfer)];
        let payout = alice;
        let timestamp = h.timestamp();

        let mut template = build_template(
            &h.chain,
            &h.network,
            &h.chain.best_id(),
            &h.state,
            &payout,
            timestamp,
            &transactions,
        )
        .expect("template");
        assert!(template.mine(20_000_000));
        let bytes = template.encode();
        let (header, decoded) = split_block(&bytes).unwrap();
        let height = h.chain.best_height() + 1;

        // The witness is derived from the parent state, exactly as a serving node would.
        let witness = BlockWitness {
            account_root: h.state.account_root(),
            total_supply: h.state.total_supply(),
            accounts: touched_accounts(&decoded, &header.payout_account_id)
                .into_iter()
                .map(|id| h.state.witness(&id))
                .collect(),
        };

        let root_after = verify_witness(
            &h.network,
            &root_before,
            &header,
            &decoded,
            height,
            &witness,
        )
        .expect("a complete witness validates the block");
        assert_eq!(
            root_after, header.state_root,
            "stateless agrees with stateful"
        );

        // Commit it for real, then check the stateful path landed on the same root.
        let validated = validate_block(&h.chain, &h.network, &h.state, &bytes).unwrap();
        assert_eq!(validated.state.root(), root_after);
        h.state = validated.state;
        h.chain.insert(validated.header).unwrap();
        checked += 1;
    }
    assert_eq!(checked, 3);
    assert_eq!(h.state.balance(&bob), 3);
}

#[test]
fn a_witness_cannot_lie_about_the_parent_state() {
    let mut h = Harness::new(devnet());
    let alice_key = key(13);
    let alice = account(&alice_key);
    let bob = [0xB8u8; 32];
    h.fund(&alice, 3);

    let root_before = h.state.root();
    let transfer = signed_transfer(&alice_key, bob, 1, 1, 0);
    let transactions = [Transaction::Transfer(transfer)];
    let timestamp = h.timestamp();
    let mut template = build_template(
        &h.chain,
        &h.network,
        &h.chain.best_id(),
        &h.state,
        &alice,
        timestamp,
        &transactions,
    )
    .unwrap();
    assert!(template.mine(20_000_000));
    let (header, decoded) = split_block(&template.encode()).unwrap();
    let height = h.chain.best_height() + 1;
    let touched = touched_accounts(&decoded, &header.payout_account_id);
    let honest = BlockWitness {
        account_root: h.state.account_root(),
        total_supply: h.state.total_supply(),
        accounts: touched.iter().map(|id| h.state.witness(id)).collect(),
    };

    // A richer Alice: the proof for the inflated account cannot open the real root.
    let mut richer = honest.clone();
    let index = touched.iter().position(|id| *id == alice).unwrap();
    richer.accounts[index].account.as_mut().unwrap().balance = 1_000_000;
    assert!(matches!(
        verify_witness(&h.network, &root_before, &header, &decoded, height, &richer),
        Err(ConsensusError::BadWitness)
    ));

    // Omitting an account leaves the partial tree short of the root.
    let mut short = honest.clone();
    short.accounts.pop();
    assert!(matches!(
        verify_witness(&h.network, &root_before, &header, &decoded, height, &short),
        Err(ConsensusError::BadWitness)
    ));

    // Extra accounts are refused by the completeness check rather than silently ignored.
    let mut padded = honest.clone();
    padded.accounts.push(h.state.witness(&[0xEEu8; 32]));
    assert!(matches!(
        verify_witness(&h.network, &root_before, &header, &decoded, height, &padded),
        Err(ConsensusError::BadWitness)
    ));

    // Claiming a different account root is refused, because it does not hash to the header's.
    let mut wrong_root = honest.clone();
    wrong_root.account_root = [1u8; 32];
    let _ = &mut wrong_root;
    assert!(matches!(
        verify_witness(
            &h.network,
            &root_before,
            &header,
            &decoded,
            height,
            &wrong_root
        ),
        Err(ConsensusError::BadWitness)
    ));

    // A witness against the wrong parent state is refused, so a block cannot be replayed.
    assert!(matches!(
        verify_witness(&h.network, &[0u8; 32], &header, &decoded, height, &honest),
        Err(ConsensusError::BadWitness)
    ));

    // With the honest witness everything is consistent.
    assert!(verify_witness(&h.network, &root_before, &header, &decoded, height, &honest).is_ok());
}

/// A recipient that does not exist yet is proven by non-inclusion, so account creation works
/// statelessly too.
#[test]
fn a_witness_proves_non_inclusion_for_a_new_account() {
    let mut h = Harness::new(devnet());
    let alice_key = key(14);
    let alice = account(&alice_key);
    let fresh = [0x99u8; 32];
    h.fund(&alice, 2);
    assert!(h.state.account(&fresh).is_none());

    let root_before = h.state.root();
    let transfer = signed_transfer(&alice_key, fresh, 5, 0, 0);
    let transactions = [Transaction::Transfer(transfer)];
    let timestamp = h.timestamp();
    let mut template = build_template(
        &h.chain,
        &h.network,
        &h.chain.best_id(),
        &h.state,
        &alice,
        timestamp,
        &transactions,
    )
    .unwrap();
    assert!(template.mine(20_000_000));
    let (header, decoded) = split_block(&template.encode()).unwrap();
    let height = h.chain.best_height() + 1;

    let witness = BlockWitness {
        account_root: h.state.account_root(),
        total_supply: h.state.total_supply(),
        accounts: touched_accounts(&decoded, &header.payout_account_id)
            .into_iter()
            .map(|id| h.state.witness(&id))
            .collect(),
    };
    let entry = witness
        .accounts
        .iter()
        .find(|w| w.id == fresh)
        .expect("the recipient");
    assert!(entry.account.is_none(), "absence is what gets proven");
    assert!(!entry.siblings.is_empty(), "and it still needs a path");

    let root_after = verify_witness(
        &h.network,
        &root_before,
        &header,
        &decoded,
        height,
        &witness,
    )
    .unwrap();
    assert_eq!(root_after, header.state_root);
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
    if let vess_core::TransferAuthority::Signature {
        sender_public_key, ..
    } = &mut tx.authority
    {
        *sender_public_key = vess_crypto::public_key_bytes(&mallory);
    }
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
    resign(&alice_key, &mut exactly);
    h.mine_block(&alice, block_ts, &[Transaction::Transfer(exactly.clone())]);
    assert_eq!(h.state.balance(&bob), 2);

    let block_ts = h.timestamp();
    let mut one_second_late = signed_transfer(&alice_key, bob, 10, 1, 1);
    one_second_late.expiry_unix = block_ts / 1_000 - 1;
    resign(&alice_key, &mut one_second_late);
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

// ------------------------------------------------------------------ futures

fn joint_input(key: &vess_crypto::Key, amount: u64, nonce: u64) -> vess_core::TransferInput {
    vess_core::TransferInput {
        authority: vess_core::InputAuthority::Signature {
            public_key: vess_crypto::public_key_bytes(key),
            signature: [0u8; ML_DSA_SIG_BYTES],
        },
        amount,
        nonce,
    }
}

/// Sign every input the given keys own. Every signature covers the whole body.
fn sign_joint(keys: &[&vess_crypto::Key], tx: &mut vess_core::JointTransfer) {
    let body = tx.unsigned_bytes();
    for input in tx.inputs.iter_mut() {
        if let vess_core::InputAuthority::Signature {
            public_key,
            signature,
        } = &mut input.authority
        {
            for key in keys {
                if *public_key == vess_crypto::public_key_bytes(key) {
                    *signature =
                        vess_crypto::sign(key, vess_core::hash::DOM_JOINT_TRANSFER, &body).unwrap();
                }
            }
        }
    }
}

/// Two equal contributions into one pot, signed by both parties.
fn joint_funding(
    alice_key: &vess_crypto::Key,
    alice_nonce: u64,
    bob_key: &vess_crypto::Key,
    bob_nonce: u64,
    pot: AccountId,
    amount: u64,
) -> vess_core::JointTransfer {
    let mut inputs = vec![
        joint_input(alice_key, amount, alice_nonce),
        joint_input(bob_key, amount, bob_nonce),
    ];
    inputs.sort_by_key(vess_core::TransferInput::account_id);
    let mut tx = vess_core::JointTransfer {
        version: TRANSACTION_VERSION_JOINT,
        chain_id: hash::chain_id(NETWORK_DEVNET),
        inputs,
        fee: 0,
        expiry_unix: 0,
        outputs: vec![vess_core::Output {
            account_id: pot,
            amount: amount * 2,
        }],
    };
    sign_joint(&[alice_key, bob_key], &mut tx);
    tx
}

fn futures_terms(
    start_supply: u64,
    target_delta: u64,
    earliest_settle_height: u64,
    owner: AccountId,
    recipient: AccountId,
) -> vess_core::FuturesRules {
    vess_core::FuturesRules {
        version: RULES_VERSION_FUTURES,
        start_supply,
        target_delta,
        earliest_settle_height,
        recipient_account_id: recipient,
        owner_account_id: owner,
        max_fee: 5,
    }
}

/// The settlement consensus would accept, built from the state the block will enter.
fn settlement(h: &Harness, rules: &vess_core::FuturesRules, fee: u64) -> vess_core::JointTransfer {
    let pot = rules.account_id();
    let balance = h.state.balance(&pot);
    let supply = h.state.total_supply();
    let (owner, recipient) = rules.split(balance - fee, supply).unwrap();
    let mut outputs = vec![
        vess_core::Output {
            account_id: rules.owner_account_id,
            amount: owner,
        },
        vess_core::Output {
            account_id: rules.recipient_account_id,
            amount: recipient,
        },
    ];
    outputs.retain(|output| output.amount > 0);
    outputs.sort_unstable_by(|a, b| a.account_id.cmp(&b.account_id));
    vess_core::JointTransfer {
        version: TRANSACTION_VERSION_JOINT,
        chain_id: hash::chain_id(NETWORK_DEVNET),
        inputs: vec![vess_core::TransferInput {
            authority: vess_core::InputAuthority::Futures { rules: *rules },
            amount: balance,
            nonce: h.state.next_nonce(&pot).unwrap_or(0),
        }],
        fee,
        expiry_unix: 0,
        outputs,
    }
}

fn joint_block_rejection(
    h: &Harness,
    payout: &AccountId,
    tx: vess_core::JointTransfer,
) -> ConsensusError {
    let built = build_template(
        &h.chain,
        &h.network,
        &h.chain.best_id(),
        &h.state,
        payout,
        h.timestamp(),
        &[Transaction::JointTransfer(tx)],
    );
    match built {
        Ok(mut template) => {
            assert!(template.mine(20_000_000));
            validate_block(&h.chain, &h.network, &h.state, &template.encode()).unwrap_err()
        }
        Err(error) => error,
    }
}

/// Both deposits land in one block or neither does, and at maturity the pot is split by the delta.
#[test]
fn a_futures_pot_is_funded_atomically_then_settled_by_the_delta() {
    let mut h = Harness::new(devnet());
    let alice_key = key(21);
    let alice = account(&alice_key);
    let bob_key = key(22);
    let bob = account(&bob_key);
    let miner = account(&key(1));
    h.fund(&alice, 2);
    h.fund(&bob, 2);

    let start_supply = h.state.total_supply() as u64;
    let settle_height = h.chain.best_height() + 3;
    // Wide enough that three blocks of emission land the split strictly inside the pot rather than
    // at either clamp.
    let rules = futures_terms(start_supply, 500, settle_height, alice, bob);
    let pot = rules.account_id();
    assert_ne!(pot, alice);
    assert_ne!(pot, bob);

    let alice_before = h.state.balance(&alice);
    let bob_before = h.state.balance(&bob);
    let funding = joint_funding(&alice_key, 0, &bob_key, 0, pot, 40);
    let ts = h.timestamp();
    h.mine_block(&miner, ts, &[Transaction::JointTransfer(funding)]);
    assert_eq!(h.state.balance(&pot), 80);
    assert_eq!(h.state.balance(&alice), alice_before - 40);
    assert_eq!(h.state.balance(&bob), bob_before - 40);

    while h.chain.best_height() + 1 < settle_height {
        let ts = h.timestamp();
        h.mine_block(&miner, ts, &[]);
    }

    // Mining issued reward after reward, so the measured delta is well past the strike.
    let supply = h.state.total_supply();
    assert!(supply > start_supply as u128);
    let (expected_owner, expected_recipient) = rules.split(80, supply).unwrap();
    assert!(
        expected_owner > 0 && expected_recipient > 0,
        "the split should be interior, not clamped"
    );
    let tx = settlement(&h, &rules, 0);
    let ts = h.timestamp();
    h.mine_block(&miner, ts, &[Transaction::JointTransfer(tx)]);

    assert_eq!(h.state.balance(&pot), 0);
    assert_eq!(h.state.balance(&alice), alice_before - 40 + expected_owner);
    assert_eq!(h.state.balance(&bob), bob_before - 40 + expected_recipient);
}

/// A settlement presented before the terms open is refused, and nothing moves.
#[test]
fn a_settlement_before_maturity_is_rejected() {
    let mut h = Harness::new(devnet());
    let alice_key = key(23);
    let alice = account(&alice_key);
    let bob_key = key(24);
    let bob = account(&bob_key);
    h.fund(&alice, 2);
    h.fund(&bob, 2);

    let start_supply = h.state.total_supply() as u64;
    let rules = futures_terms(start_supply, 50, h.chain.best_height() + 50, alice, bob);
    let pot = rules.account_id();
    let funding = joint_funding(&alice_key, 0, &bob_key, 0, pot, 40);
    let ts = h.timestamp();
    h.mine_block(&alice, ts, &[Transaction::JointTransfer(funding)]);

    let tx = settlement(&h, &rules, 0);
    let error = joint_block_rejection(&h, &alice, tx);
    assert!(rejected_with(TxReject::SettleTooEarly)(&error), "{error}");
    assert_eq!(h.state.balance(&pot), 80);
}

/// The split is not the submitter's to choose: a payout that differs from the measured one is
/// refused rather than rewritten.
#[test]
fn a_tampered_settlement_split_is_rejected() {
    let mut h = Harness::new(devnet());
    let alice_key = key(25);
    let alice = account(&alice_key);
    let bob_key = key(26);
    let bob = account(&bob_key);
    h.fund(&alice, 2);
    h.fund(&bob, 2);

    let start_supply = h.state.total_supply() as u64;
    let settle_height = h.chain.best_height() + 2;
    let rules = futures_terms(start_supply, 50, settle_height, alice, bob);
    let pot = rules.account_id();
    let funding = joint_funding(&alice_key, 0, &bob_key, 0, pot, 40);
    let ts = h.timestamp();
    h.mine_block(&alice, ts, &[Transaction::JointTransfer(funding)]);
    while h.chain.best_height() + 1 < settle_height {
        let ts = h.timestamp();
        h.mine_block(&alice, ts, &[]);
    }

    let mut tx = settlement(&h, &rules, 0);
    // Force a split consensus would not compute, keeping the pot conserved so only the split differs.
    let pot = h.state.balance(&rules.account_id());
    let mut outputs = vec![
        vess_core::Output {
            account_id: rules.owner_account_id,
            amount: pot / 2 + 1,
        },
        vess_core::Output {
            account_id: rules.recipient_account_id,
            amount: pot - (pot / 2 + 1),
        },
    ];
    outputs.sort_unstable_by(|a, b| a.account_id.cmp(&b.account_id));
    tx.outputs = outputs;
    let error = joint_block_rejection(&h, &alice, tx);
    assert!(rejected_with(TxReject::BadSettlement)(&error), "{error}");
}
