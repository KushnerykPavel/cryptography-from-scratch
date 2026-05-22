---
name: vrf-audit-checklist
description: Checklist for reviewing VRF implementations in production systems — blockchain randomness beacons, leader election protocols, DNSSEC, and on-chain lottery or NFT reveal mechanisms.
phase: 18-applied-blockchain-and-identity
lesson: 04-vrfs
---

# VRF — Production Audit Checklist

Use this checklist when reviewing any system that uses a Verifiable Random Function for unpredictable-but-verifiable randomness: slot leader election, randomness beacons, DNSSEC NSEC5, or Chainlink-style on-chain VRF.

---

## 1. Nonce / Witness Safety

- [ ] The nonce `k` (also called the witness or blinding factor) is derived deterministically from `(sk, message, optional_randomness)` — never hardcoded, never a simple counter.
- [ ] RFC 9381 §5.4.2 nonce generation is used for ECVRF: `k = ECVRF_nonce_generation(sk, H_string)`.
- [ ] The nonce is never reused across two evaluations with the same secret key, regardless of whether the messages differ.
- [ ] The nonce derivation function is seeded with sufficient entropy when fresh randomness is mixed in (≥128 bits).
- [ ] Unit tests confirm that `evaluate(sk, m1, k)` and `evaluate(sk, m2, k)` with the same `k` but different messages produce different `c` and `s` values — reuse is detectable.

## 2. Proof Structure and Verification

- [ ] The verifier recomputes `U' = g^s * pk^c` and `V' = H^s * gamma^c` independently — it does not reuse values from the prover's transcript.
- [ ] The Fiat-Shamir challenge `c` is computed over a fixed, canonical encoding of `(pk, gamma, U, V)` — variable-length encodings are not used.
- [ ] The verifier checks `c_recomputed == c_claimed` as the final step, not as an early return that could be bypassed.
- [ ] The proof is verified before the beta output is consumed — the application does not use `vrf_proof_to_hash(gamma)` before calling `vrf_verify`.
- [ ] A failing proof causes explicit rejection — the code does not fall through to use gamma anyway on verification error.

## 3. Group Membership Checks

- [ ] `gamma` is checked to be a valid group element before verification: for MODP groups, `pow(gamma, q, p) == 1`; for EC groups, the point is on the curve and in the correct subgroup.
- [ ] `pk` is checked to be a valid group element — the identity element is explicitly rejected.
- [ ] `H = hash_to_group(m)` is validated to be non-trivial (not 0 or 1 in MODP; not the point at infinity on EC).
- [ ] The cofactor clearing step in hash_to_group is present and matches the group's cofactor.

## 4. Output Handling (beta)

- [ ] `beta = proof_to_hash(gamma)` is used as the final pseudorandom output, not `gamma` directly.
- [ ] `beta` is not treated as a secret after the proof `(gamma, c, s)` is published — once the proof is public, beta is deterministically computable by anyone.
- [ ] The application does not attempt to re-use `beta` as a signing key or derive long-term secrets from it without additional key derivation.
- [ ] If multiple independent outputs are needed per evaluation, they are derived from beta with a KDF (e.g., `HKDF-Expand(beta, info_1)`, `HKDF-Expand(beta, info_2)`) — not by truncating or XOR-splitting beta.

## 5. Key Management

- [ ] The VRF secret key `sk` is in the valid range `[1, q-1]` — sk = 0 is rejected at key generation.
- [ ] `sk` is stored securely (HSM, encrypted keystore, sealed enclave) and never logged or transmitted in plaintext.
- [ ] Key rotation invalidates all previously issued proofs — the verifier uses the current pk, not a cached old one.
- [ ] If the VRF key is derived from a master key, the derivation follows a documented standard (e.g., BIP-32-style HKDF, or the key derivation specified by the protocol).

## 6. Uniqueness and Bias Resistance

- [ ] The protocol ensures that the VRF holder cannot selectively withhold the output — there must be a commitment or liveness requirement that forces publication.
- [ ] The VRF output for a future slot cannot be predicted by anyone other than the key holder before the evaluation message (e.g., previous block hash) is fixed.
- [ ] If multiple parties each contribute a VRF output to a shared randomness beacon, the protocol is resistant to last-revealer bias (e.g., via commit-reveal, or threshold VRF).
- [ ] The message `m` passed to the VRF includes sufficient entropy that cannot be influenced by the key holder — typically a hash of previous chain state.

## 7. Protocol Integration

- [ ] The VRF is evaluated over a canonical, deterministic encoding of the input message — floating-point values, timestamps, or locale-sensitive strings are not used.
- [ ] The domain separation tag (DST) or input prefix is unique to this application and this VRF key's role — it cannot collide with tags used in other contexts.
- [ ] Proof size and verification time are within the protocol's latency budget — for blockchain use, pairing-based ECVRF may require ~1 ms per proof on commodity hardware.
- [ ] The VRF scheme matches the security level of the rest of the protocol — using a 1024-bit MODP VRF in a 256-bit-security protocol is a mismatch.

## 8. Smart Contract / On-chain VRF Considerations

- [ ] The on-chain verifier checks the full proof — not just that a trusted oracle submitted a value.
- [ ] The request–fulfill model (Chainlink VRF pattern) prevents the oracle from seeing the request seed and grinding their key rotation to bias the output.
- [ ] The contract stores the request block hash and verifies that the fulfill transaction references it — preventing the oracle from fulfilling an outdated request.
- [ ] Random outputs are not directly used as indices into arrays without range reduction — modular bias may exist if the output space is not a multiple of the array length.

## 9. Dependencies

- [ ] The VRF library is pinned to a specific version with a known audit history.
- [ ] The hash-to-group / hash-to-curve implementation is tested against RFC 9380 or RFC 9381 test vectors.
- [ ] No custom elliptic curve arithmetic or MODP exponentiation is used in production paths — use an audited library.
- [ ] The library's randomness source for nonce generation is seeded from the OS CSPRNG (`os.urandom`, `/dev/urandom`, `getrandom`).

## 10. Common Findings in Past Audits

| Finding | Severity | Root cause |
|---------|----------|------------|
| Nonce k reused | Critical | Static nonce in tests left in production; sk extractable from two proofs |
| Proof not verified before beta used | Critical | Application reads gamma immediately; forgery not detected |
| gamma not checked in subgroup | High | Malicious prover submits out-of-group gamma that bypasses proof |
| Variable-length challenge input | High | Two different (pk, gamma) tuples hash to same c; proof accepted for wrong gamma |
| Beta treated as secret post-publication | Medium | Protocol sends beta as a secret channel; anyone with the proof can compute it |
| Identity key accepted | Medium | pk = identity verifies any gamma; key generation not validated |
| Last-revealer bias | Medium | Multi-party beacon allows last contributor to withhold if output is unfavorable |
| 1024-bit group in high-security context | Low | Below 128-bit security; use ECVRF over curve25519 instead |
