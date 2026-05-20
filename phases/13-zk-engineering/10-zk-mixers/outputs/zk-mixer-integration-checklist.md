name: zk-mixer-integration-checklist
description: A practical PR checklist for Tornado-style mixers (or any “Merkle membership + nullifier” spend system), focused on proof binding, root management, and real-world privacy failures.
version: 1.0.0
phase: 13
lesson: 10
tags: [zk, privacy, mixer, merkle, nullifier, threat-model]
---

Use this as a PR review template for:
- Tornado-style mixers
- “Private membership” withdrawals (Merkle membership proofs)
- Nullifier-based claims (airdrops, voting, rate limits)

Goal: catch bugs where a proof verifies but the system is still exploitable or privacy-breaking.

1) Statement (write this first)
- What exactly is being proven? (membership in what set, on what chain, at what denomination)
- Public inputs: list them explicitly (root, nullifier hash, recipient, relayer, fee, refund, chain-id, pool-id, …)
- Private witness: list it explicitly (secret/nullifier, Merkle path, leaf index, …)
- What does “spent” mean? (one-time spend, per-action spend, per-epoch spend)

2) Proof binding (the “don’t get robbed in the mempool” section)
- Recipient is bound inside the proven statement (changing it makes verification fail).
- If relayers exist: relayer address + fee are bound inside the proven statement.
- Any “refund” or token transfer parameters are bound (otherwise a proof can be replayed with different economics).
- Domain separation includes: chain-id, contract address, and pool id (if multiple pools/denominations exist).

3) Root management (UX vs safety tradeoffs)
- Which roots are accepted?
  - On-chain incremental tree? (root is implied)
  - Root registry? (explicit list)
- Root history window is documented (e.g., accept last N roots).
- Reorg behavior is defined:
  - what happens if a root becomes invalid after a reorg?
  - do users have retry logic / root refresh in the client?
- Deposits have a clear finality rule (e.g., “wait X blocks before withdrawing”).

4) Nullifier semantics (double-spend prevention done right)
- Nullifier hash is unique per note (no construction that can collide by design).
- Nullifier hash length and encoding are fixed and validated (reject malformed values).
- Spent-nullifier storage is correct across upgrades/migrations (no reset-to-zero footguns).
- There is a test proving the system rejects:
  - exact double spend (same nullifier hash twice)
  - “near-miss” encodings (leading zeros, different byte representation)

5) Circuit soundness checks (what must be constrained)
- Commitment recomputation is constrained: `commitment = H(secret, nullifier)` inside the circuit.
- Merkle membership is constrained against the provided root.
- Nullifier hash is constrained: `nullifier_hash = H(nullifier)` inside the circuit.
- All public inputs are range-checked / field-checked (no “uint256 outside scalar field” issues).
- Hash function choice is explicit and consistent between:
  - circuit implementation
  - off-chain note generation
  - on-chain verifier expectations

6) On-chain integration checks
- Verifier wrapper checks:
  - field bounds for public inputs (if required by the verifier)
  - correct ordering of public inputs (ABI correctness)
  - correct proof length and encoding
- Token/ETH transfer logic:
  - reentrancy considered (especially if the contract sends ETH)
  - failure modes are safe (no partial state updates that lose funds)
- Events do not leak note secrets (obvious, but check “debug logs”).

7) Privacy reality checks (non-cryptographic leaks)
- Default client behavior avoids easy timing links (no “deposit then withdraw immediately” defaults).
- Relayer and RPC metadata risks are documented (IP logs, user agent leaks).
- Fee policies don’t create unique fingerprints (e.g., odd fee patterns).
- Withdrawal batching strategy is considered (batching can help or hurt depending on assumptions).

8) Test plan (minimum bar)
- Happy path: deposit → withdraw works against an accepted root.
- Theft attempt: replay proof with changed recipient fails.
- Double spend: second spend with same nullifier hash fails.
- Root-window edge cases: withdraw against an older-but-accepted root passes; against a too-old root fails.
- Fuzz/negative tests for malformed inputs (wrong lengths, wrong encodings).

Deliverable for a PR:
- A filled “Statement” section.
- Links to tests covering: theft attempt + double spend + root edge case.
- A short “Privacy assumptions” note (what you assume about relayers, RPCs, and user behavior).

