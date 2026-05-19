---
name: "ZK OR/AND Proof Review Checklist (Sigma Protocols)"
description: "A paste-ready checklist for designing/reviewing Schnorr-like AND/OR proof compositions (statement binding, domain separation, soundness, WI)."
phase: 11-zero-knowledge-foundations
lesson: 06-or-and-proofs
---

# ZK OR/AND Proof Review Checklist (Sigma Protocols)

Use this as a PR review template or protocol design checklist when you see:
- Schnorr-style sigma protocols (commit / challenge / response)
- Fiat–Shamir transforms (hash to challenge)
- AND composition (“prove multiple relations at once”)
- OR composition (“prove one-of-N without revealing which”)

## 1) Decide what security property you need
- **Soundness**: a cheater can’t convince the verifier without knowing a witness.
- **Zero-knowledge / HVZK**: transcript reveals nothing beyond “statement is true”.
- **Witness indistinguishability (WI)** (OR proofs): verifier can’t tell which witness branch was used.

Write down which you need and under what model:
- interactive (honest-verifier?) vs non-interactive (Fiat–Shamir / ROM)
- public-coin vs private-coin
- single statement vs batch/multi-statement

## 2) Statement binding (must-have)
Challenges must be bound to the statement being proven.

Checklist:
- Challenge is `c = H(label, protocol_id, group_id, statement, commitments, context...) mod q`
- “statement” includes **every public value** the verifier uses (e.g., `g`, `y`, `p/q` or curve id)
- If multiple statements: include them in a **canonical order** (or include an explicit ordering tag)
- Include an **application context** (session id / user id / domain string) to prevent cross-protocol replay

Red flags:
- `c = H(t)` only (commitment-only hashing)
- Statement fields not hashed (e.g., `y` omitted, or only hashed sometimes)

## 3) Group / field correctness (must-have)
- Challenges and responses live in `Z_q` where `q` is the group order (prime-order subgroup).
- Verify all public inputs are in the right group/subgroup (curve point checks, subgroup checks, non-identity).
- Avoid mixing groups (e.g., `g` on one curve, `y` on another) by hashing a strong group identifier.

## 4) AND composition review
Goal: prove knowledge for multiple statements using one shared challenge.

Checklist:
- Commitments `t_i` are computed independently with fresh randomness `r_i`.
- A single challenge `c` is derived from the full transcript (all `t_i` and all statements).
- Responses are `s_i = r_i + c·x_i (mod q)`.
- Verification checks **every** equation `g^{s_i} = t_i · y_i^c`.

Red flags:
- Different challenges per branch (“two independent proofs glued together”) when you intended a single AND proof.
- Reusing randomness between branches (`r1 == r2`) or across sessions.

## 5) OR composition review
Goal: prove knowledge of at least one witness without revealing which.

Checklist:
- One branch is real (uses the actual witness).
- All other branches are **simulated** by choosing `(c_i, s_i)` first and back-computing `t_i`.
- Global challenge is derived as `c = H(label, statement(s), t_1, ..., t_n) mod q`.
- Challenge split condition holds: `Σ c_i = c (mod q)`.
- Verification checks both:
  - `Σ c_i = c (mod q)`
  - each sub-equation `g^{s_i} = t_i · y_i^{c_i}`

Red flags:
- Missing the sum-of-challenges check.
- Simulation uses the wrong equation (e.g., wrong inverse, wrong modulus, wrong base).
- The transcript doesn’t bind the ordering of branches (swapping `(y1, y2)` shouldn’t be allowed unless explicitly canonicalized).

## 6) Randomness hygiene
- Every proof instance uses fresh randomness (`r`, simulated `s_i`, simulated `c_i`).
- Never reuse `r` across proofs; Schnorr-style protocols can leak the witness under reuse.
- If using deterministic nonces, ensure they are derived from a secret + full statement + domain separation.

## 7) Implementation details that often bite
- Use constant-time group operations in production (educational code is not enough).
- Serialization: define one canonical encoding for transcript hashing; avoid ambiguous concatenation.
- Hash-to-scalar: reduce mod `q`, not mod `p`, and handle edge cases (e.g., `c=0` is fine).
- Validate inverses exist (in prime-order groups it’s safe; in generic groups you must handle non-invertible elements).

## 8) Reviewer questions (fast triage)
- What exactly is being proven (formal statement), and is that statement hashed into `c`?
- What is the security goal: soundness, ZK, WI, or all three?
- What are the trust assumptions (ROM for Fiat–Shamir, subgroup assumptions, etc.)?
- Can the transcript be replayed in another context (different app / different statement)?
- If this is an OR proof: can the verifier tell which branch was used (linkability)?

