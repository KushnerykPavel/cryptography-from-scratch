---
title: ZK Voting System Security Audit Checklist
version: 1.0.0
source: cryptography-from-scratch / phase 20 capstone 02
applies_to: E-voting systems using homomorphic ElGamal encryption + ZK ballot validity proofs
---

# ZK Voting System Security Audit Checklist

Use this checklist when reviewing an e-voting system built on homomorphic encryption and zero-knowledge proofs. Each item maps to a specific attack or failure mode. Mark each item Pass / Fail / N/A and add a note explaining the finding.

---

## 1. Group and Key Setup

| # | Check | Pass/Fail/N/A | Notes |
|---|-------|--------------|-------|
| 1.1 | Prime p is a safe prime (p = 2q+1, both prime) or an equivalent strong prime | | |
| 1.2 | Subgroup order q is prime and at least 256 bits (elliptic curve) or 2048+ bits (DH) | | |
| 1.3 | Generator g has order exactly q (verify g^q ≡ 1 mod p and g ≠ 1) | | |
| 1.4 | Private key x is generated with a cryptographically secure RNG, x ∈ [1, q-1] | | |
| 1.5 | The election public key h is published and verifiable before voting begins | | |
| 1.6 | For threshold elections: key generation ceremony is audited; no single party learns x | | |
| 1.7 | Group parameters are standardized (RFC 3526, NIST P-256, Ristretto255, etc.), not ad-hoc | | |

---

## 2. Ballot Encryption

| # | Check | Pass/Fail/N/A | Notes |
|---|-------|--------------|-------|
| 2.1 | Randomness r for each ballot is drawn from a CSPRNG, never from a seeded PRNG | | |
| 2.2 | r is discarded after proof generation — not stored, logged, or transmitted | | |
| 2.3 | r is sampled from [1, q-1], not [0, q-1] (r=0 leaks the vote: C2 = g^vote directly) | | |
| 2.4 | Encrypt-then-prove: the ciphertext is created first, then the proof is derived from the same r | | |
| 2.5 | The vote domain is enforced in the encryption API (e.g. ValueError for vote ∉ {0,1}) | | |
| 2.6 | Ciphertexts are checked for group membership before any processing (C1, C2 ∈ subgroup) | | |

---

## 3. Ballot Validity Proofs (Or-Proof)

| # | Check | Pass/Fail/N/A | Notes |
|---|-------|--------------|-------|
| 3.1 | Each ballot includes a disjunctive proof that the ciphertext encrypts a value in the valid set (e.g. {0,1}) | | |
| 3.2 | Proof branches are in canonical order (e.g. vote=0 always first) — not real/sim order | | |
| 3.3 | The Fiat-Shamir hash includes all commitments from all branches simultaneously | | |
| 3.4 | The Fiat-Shamir hash includes the election public key, the ciphertext (C1, C2), and group parameters | | |
| 3.5 | The Fiat-Shamir hash includes a domain separator or election ID to prevent cross-election replay | | |
| 3.6 | The Fiat-Shamir hash includes the voter identity or a per-ballot nonce to prevent ballot copying | | |
| 3.7 | Challenge split is verified: (c0 + c1) mod q == H(...) mod q | | |
| 3.8 | Both branches are fully verified — not just one | | |
| 3.9 | Proof nonces (k, c_false, z_false) are generated freshly per ballot with a CSPRNG | | |
| 3.10 | A rejected proof causes the entire ballot submission to fail atomically — no partial acceptance | | |

---

## 4. Bulletin Board

| # | Check | Pass/Fail/N/A | Notes |
|---|-------|--------------|-------|
| 4.1 | The board is append-only — submitted ballots cannot be modified or deleted after acceptance | | |
| 4.2 | All proofs are verified before a ballot is accepted onto the board | | |
| 4.3 | Ballots are accepted only during the designated voting window; timestamps are checked | | |
| 4.4 | Each voter can verify their own ballot appears on the board with the correct ciphertext | | |
| 4.5 | Duplicate voter IDs are detected and rejected | | |
| 4.6 | The board is publicly accessible for universal verifiability during and after the election | | |
| 4.7 | Board contents are integrity-protected (e.g. hash chain or Merkle tree) against post-hoc tampering | | |

---

## 5. Homomorphic Tally

| # | Check | Pass/Fail/N/A | Notes |
|---|-------|--------------|-------|
| 5.1 | All ballots on the board are proof-verified before being included in the tally product | | |
| 5.2 | The tally multiplies all C1 components and all C2 components separately (not concatenated) | | |
| 5.3 | The tally computation is reproducible: any observer can re-multiply the bulletin board and obtain the same tally ciphertext | | |
| 5.4 | The tally ciphertext is published before decryption begins | | |
| 5.5 | Decryption of the tally ciphertext is the only decryption step — no individual ballots are decrypted | | |

---

## 6. Decryption

| # | Check | Pass/Fail/N/A | Notes |
|---|-------|--------------|-------|
| 6.1 | For single-authority: the private key is deleted immediately after tally decryption | | |
| 6.2 | For threshold: each trustee produces a partial decryption g^(x_i * C1) with a proof of correct partial decryption | | |
| 6.3 | Partial decryption proofs are verified before combining | | |
| 6.4 | The tally result is the discrete log of the decrypted value, computed in [0, num_voters] | | |
| 6.5 | The decryption ceremony is conducted in public or is recorded and auditable | | |
| 6.6 | The private key (or key shares) are never transmitted over the network in cleartext | | |

---

## 7. Implementation Security

| # | Check | Pass/Fail/N/A | Notes |
|---|-------|--------------|-------|
| 7.1 | All modular arithmetic uses the standard library or a vetted big-integer library — no hand-rolled mod functions | | |
| 7.2 | Modular inverse uses pow(a, -1, m) or extended Euclidean — not a trial division loop | | |
| 7.3 | No secret-dependent branches or memory access patterns in cryptographic code paths | | |
| 7.4 | The codebase has no network calls or file reads inside the proof generation or verification path | | |
| 7.5 | Dependencies are pinned and audited; no transitive dependency pulls in a weaker RNG | | |
| 7.6 | The system has been tested against a "vote=2" ciphertext to confirm the or-proof rejects it | | |
| 7.7 | The system has been tested against a replay of a valid ballot from a prior election | | |
| 7.8 | Test vectors exist for encrypt, decrypt, tally, prove, and verify with known-good inputs | | |

---

## 8. Operational Security

| # | Check | Pass/Fail/N/A | Notes |
|---|-------|--------------|-------|
| 8.1 | Voter authentication is separate from and stronger than ballot submission (avoids stuffing) | | |
| 8.2 | The system is not susceptible to denial-of-service via proof verification (rate limits in place) | | |
| 8.3 | The election setup, voting period, and decryption ceremony are each time-bounded | | |
| 8.4 | An independent auditor has run the universal verifiability check against the published bulletin board | | |
| 8.5 | The audit log (board + proofs + tally ciphertext + decryption proof) is archived and publicly accessible after the election | | |

---

## Summary

| Category | Total | Pass | Fail | N/A |
|----------|-------|------|------|-----|
| 1. Group and Key Setup | 7 | | | |
| 2. Ballot Encryption | 6 | | | |
| 3. Ballot Validity Proofs | 10 | | | |
| 4. Bulletin Board | 7 | | | |
| 5. Homomorphic Tally | 5 | | | |
| 6. Decryption | 6 | | | |
| 7. Implementation Security | 8 | | | |
| 8. Operational Security | 5 | | | |
| **Total** | **54** | | | |

**Auditor:** ___________________________  **Date:** ___________  **System version:** ___________
