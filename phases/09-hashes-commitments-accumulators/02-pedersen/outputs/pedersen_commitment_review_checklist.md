---
name: Pedersen Commitment Review Checklist
description: A practical checklist for reviewing Pedersen commitment usage (setup, randomness, membership, homomorphism, and proof integration).
phase: 09-hashes-commitments-accumulators
lesson: 02-pedersen
---

# Pedersen Commitment Review Checklist

Use this in PR reviews and design docs whenever you see “Pedersen commitment”, “blinding factor”, “generators G/H”, “commitment key”, or “range proof”.

## 1) Group and parameter setup

- What is the group?
  - Curve group (preferred): prime-order subgroup (e.g., Ristretto / decaf / prime-order curve subgroup).
  - Finite field subgroup: a prime-order subgroup of `Z_p*` with explicit `p, q` and membership checks.
- Is the group order prime (or effectively prime via cofactor clearing / Ristretto)?
- Are `G` and `H` derived safely?
  - If `H` is derived from `G` with a known scalar `α` (i.e., `H = α·G`), binding is broken for whoever knows `α`.
  - If there is a trusted setup ceremony, how is “toxic waste” handled and audited?
  - If transparent setup: is `H` derived via hash-to-curve with domain separation and a fixed, documented string?

## 2) Membership / subgroup checks

- Does the code validate that a received commitment is on-curve / in the correct subgroup?
  - For curves: reject invalid encodings and perform subgroup checks (or use an encoding that guarantees prime-order).
  - For `Z_p*` style groups: check `0 < C < p` and `C^q ≡ 1 (mod p)` when applicable.
- Are public parameters validated on startup (including `G != identity`, `H != identity`, `G != H`)?

## 3) Randomness (`r`) and nonce hygiene

- Is `r` sampled uniformly from `Z_q` (full-width)?
- Is `r` unique per commitment?
  - Reusing `r` can create linkability; in some protocols it enables algebraic leakage when combined with other data.
- Is randomness source appropriate (CSPRNG, no `rand()` / predictable seeds)?
- Is `r` ever truncated (e.g., “use 32-bit random for speed”)? If yes: hiding is likely compromised.

## 4) Message encoding (`m`)

- What exactly is being committed?
  - Integer amounts: is `m` interpreted modulo `q`?
  - Byte strings: is there a hash-to-scalar step with domain separation?
- Are range constraints proven where required?
  - Pedersen commitments alone do not prevent committing to negative/overflow values mod `q`.
  - For amounts/balances, you almost always need a range proof (or equivalent constraint system).

## 5) Homomorphism usage (intended malleability)

- Is the additive homomorphism used intentionally?
  - Adding commitments is easy: `C1 + C2` (additive groups) or `C1 * C2` (multiplicative groups).
  - This also means commitments are malleable. Is that acceptable in the protocol?
- Are “equal value” checks done safely?
  - Usually you prove equality with a ZK proof rather than opening.
- If rerandomization is used:
  - Is it implemented as `C' = C + Δr·H` (additive) / `C' = C * H^{Δr}` (multiplicative)?
  - Is `Δr` sampled uniformly and independently?

## 6) Binding threat model

Ask explicitly: who might know `log_G(H)` (or the discrete-log relation)?

- If a single party generated parameters, do we trust them not to keep `α`?
- If parameters come from a file / constants:
  - Are they from a widely reviewed standard?
  - Is the derivation documented and reproducible?

## 7) Side channels and implementation hazards

- Is scalar multiplication / exponentiation constant-time?
- Are secret scalars (`m`, `r`) ever logged, serialized to analytics, or included in panic traces?
- Are there timing differences in validation or rejection paths?

## 8) Quick “red flag” questions

If you can answer “yes” to any, stop and investigate.

- “We set `H = α·G` and store `α` somewhere.”
- “We reuse `r` for performance.”
- “We don’t do subgroup checks because ‘it’s probably fine’.”
- “We commit to 64-bit amounts but don’t prove a range.”
- “We accept user-provided commitments without validating encoding/membership.”

## Copy/paste PR comment template

> **Pedersen commitment review**
> - [ ] Group is prime-order (or uses prime-order encoding) and membership checks are enforced.
> - [ ] `G`/`H` setup is transparent or trusted setup is documented; no party can cheat by knowing `log_G(H)`.
> - [ ] Blinding `r` is uniform, unique per commitment, and comes from a CSPRNG.
> - [ ] Message encoding is explicit (`m` lives in `Z_q`); range constraints are proven where needed.
> - [ ] Homomorphism and rerandomization are used intentionally (malleability accounted for).

