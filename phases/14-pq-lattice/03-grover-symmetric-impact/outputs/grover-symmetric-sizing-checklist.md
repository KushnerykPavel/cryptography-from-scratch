---
name: Grover Symmetric Sizing Checklist
description: Decision guide + review checklist for choosing AES and hash parameters under Grover/BHT post-quantum scaling assumptions.
phase: 14-pq-lattice
lesson: 03-grover-symmetric-impact
---

# Grover Symmetric Sizing Checklist

Use this when reviewing a design doc or PR that changes:

- AES key sizes / AEAD choices
- hash functions and output sizes
- claims like “128-bit security” in a post-quantum context

This checklist assumes **idealized** quantum cost models (good for sizing, not for wall-clock promises):

- Key search / preimage (Grover): work ~ `2^(k/2)` or `2^(n/2)`
- Collisions (BHT): work ~ `2^(n/3)`

## 1) First: what security target is being claimed?

Write down:

- Target security bits `t` (e.g., 128)
- Attacker model: offline brute force? online rate-limited? side channels?
- Whether the claim is **classical only** or **post-quantum sizing**

If the doc doesn’t say these explicitly, ask for clarification before approving.

## 2) Key search sizing (AES / MAC keys)

Rule of thumb:

- To get `t` Grover bits against key search, aim for **~`2t` key bits**.

Quick mapping:

| Post-quantum target `t` | Recommended AES key |
|-------------------------|---------------------|
| ~64 bits | AES-128 |
| ~96 bits | AES-192 |
| ~128 bits | AES-256 |

Review questions:

- Does the system actually need `t=128` post-quantum for symmetric components, or is a lower target acceptable given the threat model?
- Are there any places where keys are smaller than the intended target (tokens, KDF outputs, truncated tags, etc.)?

## 3) Hash sizing: preimage vs collision (don’t mix them)

Write down which property matters for each use:

- **Preimage-style:** password hashing targets, some commitment openings, “invert this digest”
- **Collision-style:** signature hash collisions, transcript collisions, multi-target collision games

Idealized work factors:

- Preimage classical ~ `2^n`, Grover ~ `2^(n/2)`
- Collision classical ~ `2^(n/2)`, quantum(BHT) ~ `2^(n/3)`

Review questions:

- Is the design relying on preimage resistance or collision resistance (or both)?
- Are any digests truncated (e.g., “use SHA-256 but only keep 128 bits”)? If yes, recompute both preimage and collision margins.

## 4) Parallelism sanity check

If the design argues about “attack time”, ask:

- What parallelism budget is assumed (`P` workers)?
- Did they adjust `log2(work)` by `-log2(P)`?
- Are they assuming perfect parallelization and cheap oracles? If yes, treat as a *best-case attacker* estimate.

## 5) Common red flags

- “Quantum breaks AES-128” (binary claim) without stating the model (“~64 Grover bits” is the precise statement).
- Hash choice justified only by “SHA-512 is stronger” without specifying whether the goal is preimage or collision strength.
- Security-bit claims presented as time guarantees (“X years”) without circuit-depth / oracle-cost assumptions.
- Truncating outputs (hashes/tags/keys) without redoing the math for both preimage and collision margins.

## 6) Minimal review comment template

Copy/paste:

> For post-quantum sizing, please state the target `t` security bits and which model you’re using. Under the usual idealized assumptions, Grover makes key search and preimages scale like `2^(k/2)` / `2^(n/2)` (so “t bits PQ” often maps to ~`2t` key/output bits), while hash collisions scale like `2^(n/3)` (BHT). Based on that, please justify the chosen AES key size and hash output size for the claimed target.

