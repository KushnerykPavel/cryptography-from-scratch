---
name: SPDZ(-style) MPC Review Checklist
description: Practical checklist for reviewing SPDZ-family MPC implementations (authenticated shares, MAC checks, preprocessing, and triple discipline).
phase: 17-fhe-and-mpc
lesson: 09-spdz
---

# SPDZ(-style) MPC Review Checklist

Use this when reviewing an MPC system (or PR) that claims “SPDZ-like malicious security” or “dishonest majority with active security”.

## 0) Identify the exact security model

- What is the adversary model: semi-honest, covert, malicious (active)?
- Is it dishonest majority (up to `n-1` corrupt) or honest majority?
- Is it secure-with-abort (most SPDZ-family systems) or does it claim fairness/robustness?
- What is the computation domain: prime field (mod `p`) vs ring (mod `2^k`)?

If the PR doesn’t state these explicitly, it’s impossible to review security claims.

## 1) Authenticated share representation

Check the code’s internal representation for shared values:

- Each secret value should carry both:
  - a **value share** (`x_i`), and
  - a **MAC/tag share** (`m_i`),
  consistent with some global MAC key `α` such that `Σ m_i = α · x`.
- Confirm the MAC key is **not known fully** to any single party.
  - Typical: each party holds `α_i` with `α = Σ α_i`.

Red flags:

- MAC/tag stored only on one coordinator.
- MAC/tag is computed with a key that is reconstructed or logged.

## 2) Opening must always be MAC-checked

Any time a value is opened/revealed (even if it’s “masked” like `x - a`):

- Ensure the implementation runs the MAC check and aborts on failure.
- Ensure callers cannot “forget” to run the check (API should make it hard to misuse).

Red flags:

- A function named like `open()` that returns the value without verifying.
- Separate “open” and “check” calls where callers can accidentally omit `check()`.

## 3) Preprocessing / offline material discipline

SPDZ-family protocols rely on preprocessing (triples, random shares, bits, etc.).

- Verify there is a clear boundary between:
  - preprocessing generation/consumption, and
  - online computation.
- Verify preprocessing items are **consumed exactly once** and never reused.
- Ensure preprocessing is bound to the correct domain/parameters:
  - modulus/field/ring,
  - party count,
  - security parameter / statistical security.

Red flags:

- “Replay” or caching logic that can resend old triples after restart.
- “Optimization” that reuses a triple across multiplications.

## 4) Multiplication logic (Beaver-style)

When multiplying secrets, check the protocol structure matches the expected pattern:

- open `d = x - a` and `e = y - b`
- compute `z = c + d·b + e·a + d·e`

For authenticated shares, ensure MACs/tags are updated consistently under:

- addition/subtraction of shares,
- multiplication by a public scalar,
- adding a public constant (often done by adjusting exactly one party’s value share).

Red flags:

- Using a triple but not opening both `d` and `e`.
- Updating value shares but forgetting the corresponding MAC/tag update.

## 5) Commit-and-open and fairness of opening (real deployments)

In real multi-party deployments, openings typically need commit-and-open (or equivalent) to prevent “last message wins” adaptation.

- Check whether parties commit to their shares (or messages) before opening.
- Check that the open protocol prevents a party from waiting to see others’ shares before choosing theirs.

If a codebase omits this, it might still be correct for a *simulation*, but not for a real adversarial network.

## 6) Concurrency and statefulness hazards

SPDZ implementations are stateful (triple counters, MAC checks, batch openings).

- Verify that multithreading cannot:
  - skip a required MAC check,
  - reuse preprocessing across threads,
  - interleave openings in a way that breaks assumptions.
- Verify crash/restart behavior:
  - Can preprocessing be replayed?
  - Are counters persisted safely?

## 7) Side-channel and “production-unsafe” assumptions

Even if the protocol is cryptographically sound:

- arithmetic should avoid leaking via timing where it matters (often hard in high-level languages),
- network message sizes and patterns can leak,
- conversions (fixed-point, truncation, comparisons) are frequent leakage points.

If the system is “for production”, demand:

- a threat model document,
- a constant-time strategy (or justification why not needed),
- a test plan for negative/adversarial cases.

