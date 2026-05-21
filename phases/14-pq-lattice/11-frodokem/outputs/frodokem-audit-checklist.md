---
name: "LWE / FrodoKEM Audit Checklist"
description: "A practical checklist for reviewing LWE-matrix KEM code (FrodoKEM-style): dimensions, sampling, encode/decode, FO check, and side-channels."
phase: "14-pq-lattice"
lesson: "11-frodokem"
---

# LWE / FrodoKEM Audit Checklist

Use this when reviewing or designing an LWE-matrix KEM (FrodoKEM-style). It is written for PR reviews and design docs: skim top-to-bottom and leave comments where a box is unchecked.

## 1) Parameters & Shapes

- [ ] Write down shapes for every matrix (including transposes) and verify they match the spec:
  - `A ∈ Z_q^{n×n}`
  - `S, E ∈ Z^{n×n̄}`
  - `B = A*S + E (mod q) ∈ Z_q^{n×n̄}`
  - `S' , E' ∈ Z^{n̄×n}`
  - `B' = S'*A + E' (mod q) ∈ Z_q^{n̄×n}`
  - `E'' ∈ Z^{n̄×n̄}`
  - `C = S'*B + E'' + Encode(μ) (mod q) ∈ Z_q^{n̄×n̄}`
- [ ] Confirm every multiply `X*Y` has matching inner dimension and the result is reduced mod `q`.
- [ ] Confirm `q` and packing widths: if the implementation assumes `q = 2^D`, ensure the parameter set actually satisfies it.

## 2) PRG / XOF Expansion (A, noise, coins)

- [ ] `A` is generated deterministically from a seed exactly as specified (byte order, rejection sampling rules, endian, etc.).
- [ ] Domain separation is explicit: `seedA` expansion cannot collide with noise sampling or “coins” expansion.
- [ ] For non-power-of-two `q`, uniform sampling is unbiased (rejection sampling) — no `word % q` shortcuts unless `q` is `2^D`.
- [ ] All secret-dependent expansions use a cryptographic XOF/PRG (SHAKE, AES-CTR, etc.), not `random` or platform RNG directly.

## 3) Error Distribution

- [ ] Error distribution matches the parameter set (e.g., discrete Gaussian / centered binomial parameters).
- [ ] Sampling is deterministic given the seed (required for test vectors / reproducibility).
- [ ] The implementation never accidentally reuses the same noise stream for multiple matrices.
- [ ] Values are interpreted with the correct sign convention (centered vs. `0..q-1` representation).

## 4) Encode / Decode (Reconciliation)

- [ ] You can point to the exact `ec(k)` and `dc(c)` formulas used (including rounding rule).
- [ ] Bit packing order is specified and tested (endianness within bytes, symbol packing).
- [ ] `Decode(Encode(μ) + small_noise) == μ` holds with high probability under the scheme’s noise distribution.
- [ ] Encoding is constant-time with respect to secret values (no secret-dependent branches or table lookups).

## 5) KEM Layer (FO / re-encryption check)

- [ ] Encapsulation derives encryption randomness (“coins”) from `μ` (and context like `pk`), not from ambient RNG alone (needed for re-encryption checks).
- [ ] Decapsulation does:
  1) decrypt to `μ̂`
  2) re-derive coins from `μ̂`
  3) re-encrypt to `ct̂`
  4) constant-time compare `ct̂` vs `ct`
  5) if mismatch, use a secret fallback `μ_fail` (or a secret seed) for KDF input
- [ ] The ciphertext comparison is constant-time (no early-exit, no length leaks).
- [ ] The implementation is careful about what is hashed into the shared secret: typically includes `μ` and `ct` (and sometimes `pk`), per spec.

## 6) Serialization & Interop

- [ ] All serialization uses the spec’s byte order and packing (especially for 16-bit words).
- [ ] Inputs are validated: malformed ciphertext sizes / matrix sizes are rejected safely.
- [ ] There are deterministic test vectors from a stated source (spec / reference impl / known-answer tests).

## 7) Side-Channel & Operational Concerns

- [ ] No secret-dependent branches on `μ̂`, noise, or intermediate values in decapsulation.
- [ ] Any failure paths (FO mismatch) are indistinguishable from success paths in timing and behavior as much as possible.
- [ ] Memory clearing / secret handling is considered (especially in C/C++).
- [ ] Fuzzing and negative tests exist for malformed ciphertexts.

## 8) Reviewer “Red Flags”

- “We don’t need the re-encryption check; decryption already gives μ.”
- “We can compare ciphertexts with `memcmp` and return early.”
- “Uniform sampling is just `word % q` for any q.”
- “Noise streams can be reused; it’s all random anyway.”
- “Encode/Decode doesn’t matter; any mapping should work.”

