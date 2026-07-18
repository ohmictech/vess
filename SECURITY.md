# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Vess, please **do not** open a public issue. Instead, report it privately to the maintainers.

**Contact:** Open a security advisory on the GitHub repository: https://github.com/vess-project/vess/security/advisories/new

We aim to acknowledge reports within 48 hours and provide an initial assessment within 5 days.

## Supported Versions

Vess is currently pre-mainnet (testnet). All users should run the latest commit from `main`.

| Version | Supported          |
| ------- | ------------------ |
| main    | :white_check_mark: |
| < main  | :x:                |

## Cryptographic Assumptions

Vess relies on:

- **ML-DSA-65 (FIPS 204)** for digital signatures — 1952-byte public keys, 3309-byte signatures
- **ML-KEM-512 (FIPS 203)** for session key encapsulation — 800-byte encapsulation keys, 768-byte ciphertexts
- **Blake3** for hashing (node IDs, payment IDs, block headers, UTXO commitments)
- **ChaCha20-Poly1305** for authenticated symmetric encryption (wallet persistence, session payloads)
- **Argon2id** for wallet password-based key derivation
- **Cuckatoo27** (siphash-2-4 edge generation, 42-cycle) for proof-of-work

All secret key material is handled as 32-byte (ML-DSA) or 64-byte (ML-KEM) seeds. Expanded signing/decapsulation keys are derived deterministically and never serialized. The `zeroize` crate is used to wipe plaintext buffers and secret key material on drop.

## Known Testnet Limitations

- **Reorg replay is O(n²)**: full-genesis replay per tip. Acknowledged testnet limitation; incremental tip-state apply is planned.
- **No incremental block sync**: nodes >40 blocks behind rely on state sync (UTXO set transfer) rather than block-by-block catch-up. BlockReq/BlockResp provides minimal parent-fetch for orphan resolution.
- **Handshake PoW** is bound to `blake3("vess-handshake" || initiator_id || responder_addr)` — not yet bound to a Unix minute for anti-replay.
- **No peer scoring beyond strike/ban**: Sybil resistance is basic. Multi-peer consensus-verified state sync mitigates eclipse attacks on bootstrapping nodes.
- **UDP amplification**: handshake/holepunch responses are ~4.5× larger than requests. PoW gating and pending-introduction checks address most of the amplification surface.

## Responsible Disclosure

We follow a 90-day disclosure deadline. After the vulnerability is resolved, we will publish a security advisory with credit to the reporter (unless anonymity is requested).
