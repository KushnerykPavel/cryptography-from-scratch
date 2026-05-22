---
name: bls-aggregation-audit-checklist
description: Checklist for reviewing BLS signature aggregation implementations in production systems — validator clients, threshold signers, bridge custody backends, and smart contract bridges.
phase: 18-applied-blockchain-and-identity
lesson: 03-bls-aggregation-eth2
---

# BLS Aggregation — Production Audit Checklist

Use this checklist when reviewing any codebase that aggregates BLS signatures: Ethereum validator clients, threshold wallets, BLS-based bridges, or multi-party signing protocols.

---

## 1. Key Registration and Proof-of-Possession

- [ ] Every public key is accompanied by a proof-of-possession (PoP) before it is accepted into any aggregate set.
- [ ] The PoP is verified before the key is stored or used — not deferred to aggregation time.
- [ ] The PoP domain tag (`"BLS-POP"` or equivalent) is distinct from all other signing contexts in the application.
- [ ] The PoP signs a deterministic encoding of the public key, not an arbitrary nonce or session ID.
- [ ] Re-registration of an existing key forces a fresh PoP verification — stale PoPs from a different key generation round are rejected.

## 2. Aggregate Public Key Construction

- [ ] The aggregate public key is recomputed (or incrementally updated) only from keys whose PoPs have been verified.
- [ ] The code explicitly rejects the identity element (point at infinity / zero) as a participant's public key.
- [ ] Duplicate public keys in the same aggregate are either rejected or handled explicitly (doubling a key changes the aggregate weight).
- [ ] The order in which keys are summed does not affect the result — the code does not rely on insertion order for security.
- [ ] After any participant is removed or their key rotates, the aggregate public key is recomputed from scratch or the removed contribution is subtracted correctly.

## 3. Aggregate Signature Construction

- [ ] Signatures are aggregated only when all signers signed the same message (for single-message aggregation) or when the verifier has access to all (pk_i, message_i) pairs (for multi-message aggregation).
- [ ] The code distinguishes same-message aggregation from multi-message aggregation — they have different verification equations.
- [ ] Aggregation is not performed across different protocol contexts (e.g., attestations must not be mixed with sync committee signatures).
- [ ] Partial aggregates from sub-committees are combined correctly — a sum of sums equals the total sum only if no key is counted twice.

## 4. Signature Verification

- [ ] The verification equation used matches the aggregation mode: `e(agg_sig, G2) == e(H(m), agg_pk)` for same-message; per-pair pairing for multi-message.
- [ ] The verifier checks that the aggregate signature is a valid curve point (not the identity, not a point with invalid coordinates) before invoking the pairing.
- [ ] The verifier checks that each individual public key used in multi-message verification is a valid point on the curve.
- [ ] Batch verification (if used) applies random linear combination scalars to prevent forgery by mixing valid and invalid signatures.
- [ ] The verification result is checked as a boolean — the code does not proceed on `None` or exception instead of `False`.

## 5. Curve and Group Parameters

- [ ] The implementation uses BLS12-381 with the parameter set specified in IETF draft-irtf-cfrg-bls-signature (not an ad-hoc curve or a modified parameter).
- [ ] Public keys live in G1 (48 bytes compressed) or G2 (96 bytes compressed) as specified by the chosen variant — the two variants are not mixed.
- [ ] The cofactor is applied when hashing to G1 or G2 — raw SHA-256 output is not used as a curve point without the hash-to-curve step.
- [ ] The hash-to-curve implementation follows RFC 9380 (hash_to_field + map_to_curve + clear_cofactor) — not a custom construction.

## 6. Secret Key Handling

- [ ] Secret keys are validated to be in the range `[1, r-1]` where r is the curve order — sk = 0 is explicitly rejected.
- [ ] Secret keys are stored and transmitted in a secure enclave, HSM, or encrypted keystore — they are never logged or included in error messages.
- [ ] Key derivation follows EIP-2333 (BLS12-381 Key Generation) if the keys are HD-derived from a mnemonic.
- [ ] The code clears secret key material from memory after use (where the language runtime allows it).

## 7. Signing Context and Domain Separation

- [ ] The signing domain (domain separation tag / DST) is set per the application protocol — Ethereum uses a fork-aware domain from the beacon chain spec.
- [ ] The same key is never used to sign across incompatible domains (e.g., mainnet and testnet, or two different application protocols).
- [ ] The message passed to `Sign` is the protocol-specified pre-image (e.g., SSZ hash tree root), not raw transaction bytes or an arbitrary string.

## 8. Multi-Party and Threshold Signing

- [ ] In threshold BLS, partial signatures are verified before being combined — an invalid partial signature causes the aggregation to silently produce a wrong result.
- [ ] The Lagrange coefficients for threshold reconstruction are computed in the correct field (the curve order r) and not in the base field.
- [ ] Participant indices used in Lagrange interpolation are distinct and non-zero — duplicate indices cause a division-by-zero or incorrect reconstruction.
- [ ] The threshold signing protocol protects against a malicious coordinator who submits forged partial signatures from absent participants.

## 9. Dependencies and Supply Chain

- [ ] The BLS library version is pinned and audited — `blst`, `py_ecc`, or `blspy` are the commonly reviewed options.
- [ ] The library's hash-to-curve implementation has been reviewed against the RFC 9380 test vectors.
- [ ] No custom or hand-rolled BLS arithmetic is used in production paths — use an audited library.
- [ ] The dependency has an active maintainer and a disclosed security contact.

## 10. Common Findings in Past Audits

| Finding | Severity | Root cause |
|---------|----------|------------|
| Missing PoP check | Critical | Keys aggregated before PoP verified; rogue key forgery possible |
| Identity key accepted | High | pk = point-at-infinity passes curve check but breaks aggregation |
| Wrong aggregation variant | High | Same-message verify used for multi-message data |
| sk=0 not rejected | High | Zero secret key produces universally valid signatures |
| Cofactor not cleared | Medium | Hash-to-G1 skips cofactor multiplication; result not in correct subgroup |
| Cross-domain signing | Medium | Same key signs both mainnet and testnet messages |
| Lagrange in wrong field | Medium | Threshold reconstruction uses base field p instead of curve order r |
| Library version unpinned | Low | Supply chain risk; breaking change or vulnerability not caught |
