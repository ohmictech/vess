# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Vess, please **do not** open a public issue. Instead, report it privately to the maintainers.

**Contact:** Open a security advisory on the GitHub repository: https://github.com/vess-project/vess/security/advisories/new

We aim to acknowledge reports within 48 hours and provide an initial assessment within 5 days.

## Supported Versions

All users should run the latest commit from `main`.

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

## Responsible Disclosure

We follow a 90-day disclosure deadline. After the vulnerability is resolved, we will publish a security advisory with credit to the reporter (unless anonymity is requested).
