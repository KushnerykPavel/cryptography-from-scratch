---
name: inner-product-argument-review
description: Review checklist for Inner Product Argument (IPA) implementations (Bulletproofs / Halo-style)
version: 1.0.0
phase: 11
lesson: 9
tags: [zk, ipa, bulletproofs, halo2, audit]
---

# Inner Product Argument (IPA) Review Checklist

Use this when reviewing code that implements (or wraps) an Inner Product Argument, including:
- Bulletproofs-style IPA proofs (inner product of committed vectors),
- IPA-based polynomial commitments (Halo / Halo2 style),
- any custom “log-size” inner product proof inside a proving system.

This checklist is about correctness and soundness hygiene. It is not a substitute for a full cryptographic review.

## 1) Statement binding (Fiat–Shamir transcript)

Confirm the transcript hashes the full public statement, not just the per-round messages:
- The group description / curve ID / domain separator
- The generator vectors `G` and `H` (or a commitment to them, or a known CRS digest)
- The extra generator `Q` (or equivalent)
- The statement point(s) `P`, `P'`, commitments, and any scalars the proof is about

Red flags:
- Transcript starts empty and only absorbs `L,R` per round
- No explicit domain separation string
- Transcript reused across different sub-protocols without a label

## 2) Challenge safety (u must be invertible)

Per round, confirm:
- `u` is derived from transcript hashing (verifier-side deterministic)
- `u != 0` (or `u ∈ F*`) is enforced before computing `u^{-1}`

Red flags:
- Code computes `inv(u)` without checking `u` can be inverted
- “If u == 0: continue” (skips a round rather than fixing transcript / rehashing)

## 3) Vector length rules

Confirm the implementation defines and enforces how it handles length:
- `n` is a power of two (or the scheme specifies padding)
- If padding is used: both prover and verifier pad identically and transcript binds `n`
- Proof length matches `log2(n)` (number of `L,R` pairs)

Red flags:
- Prover pads but verifier assumes exact power-of-two
- Proof accepts arbitrary number of rounds for a fixed statement

## 4) Folding equations (the core algebra)

Check the folding formulas match the paper / spec your system claims to implement.

Typical Bulletproofs-style folding uses:
- `a' = a_lo * u + a_hi * u^{-1}`
- `b' = b_lo * u^{-1} + b_hi * u`
- `G' = G_lo * u^{-1} + G_hi * u`
- `H' = H_lo * u + H_hi * u^{-1}`
- statement update like `P' := P' + u^2 * L + u^{-2} * R` (group ops)

Red flags:
- Mixed-up `u` vs `u^{-1}` in `G` / `H` folds
- Using `u` where `u^2` is required in the statement update
- Implementations that “work” only because tests don’t include adversarial tampering

## 5) Generator independence (security assumption)

Confirm your system’s CRS / generator derivation ensures:
- `G` and `H` are independent generators with unknown discrete log relation
- the extra generator `Q` is independent of both (or derived in a domain-separated way)

Red flags:
- `H[i] = x * G[i]` for known `x`
- generators derived from the same hash seed without domain separation

## 6) Constant-time and side-channel hygiene (production)

This course implementation is not constant-time. Production code should consider:
- constant-time scalar multiplication / MSM routines
- avoiding secret-dependent branches and memory access
- safe transcript implementations (no accidental state reuse)

Red flags:
- Big-int / variable-time scalar ops on secrets (in languages like Python)
- “Debug prints” of witness data enabled in release builds

## 7) Quick adversarial tests to demand

Ask for tests that flip one bit and ensure verification fails:
- modify a single `L_j` or `R_j`
- modify the final `a` or `b`
- swap `L_j` and `R_j`
- verify under different generators (should fail if statement binding is correct)

If the library supports batch verification or aggregation, also test:
- mixed valid/invalid proofs in a batch (batch must reject)

