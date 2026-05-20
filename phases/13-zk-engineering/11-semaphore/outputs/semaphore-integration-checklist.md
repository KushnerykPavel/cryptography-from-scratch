---
name: Semaphore Integration Checklist
description: PR-review checklist for implementing Semaphore-style anonymous signaling (group roots + nullifiers + verifiers) safely.
phase: 13-zk-engineering
lesson: 11-semaphore
---

# Semaphore Integration Checklist

Use this when reviewing or implementing Semaphore-style anonymous signaling:

- users prove “I’m in the group” without revealing which member
- verifiers prevent double-signaling per scope using nullifiers
- the system stays consistent across clients, circuits, and contracts/services

## 1) Define your public inputs (and treat them as an API)

Write down the exact public inputs your verifier consumes. Typical set:

- `root` (Merkle root of the group)
- `externalNullifier` (scope identifier; sometimes its hash)
- `signalHash` (hash of the message)
- `nullifierHash` (one-time tag in this scope)

If two components disagree on any of these (encoding, hashing, field mapping), proofs “verify locally” but fail in production.

## 2) Scope rules: external nullifier naming must be canonical

Most “it works on my machine” breakage is scope mismatch.

Checklist:

- Is `externalNullifier` a string, an integer, a field element, or a hash?
- Is there exactly one canonical serialization (UTF-8, JSON, ABI encoding)?
- Is the scope stable across time (e.g., proposal id), and does it avoid collisions?
- Is the scope unique per action type (`vote:42` vs `mint:42`)?

Add vectors that prove the same scope string produces the same hash in every environment.

## 3) Merkle tree compatibility (root + proof format)

Treat the Merkle tree as a protocol, not a data structure.

Confirm agreement on:

- leaf encoding (length prefix? fixed-width field elements?)
- domain separation (leaf vs node)
- odd-node rule (duplicate-last? zero-pad? left-carry?)
- proof format (sibling list + path bits ordering)

Require “golden vectors”:

- same leaves → same root
- proof roundtrip for every index in a small test tree
- tamper tests (wrong sibling, wrong side, wrong leaf)

## 4) Nullifier registry semantics (what does “double” mean?)

Decide what state you store and what it means:

- Store `nullifierHash` only (common): blocks a second signal for the same identity+scope forever.
- Store `(externalNullifier, nullifierHash)` if you allow multiple nullifier domains in one registry.
- Do not key by `(root, nullifierHash)` unless you explicitly want “you can resignal after group changes.”

Write tests for your intended semantics.

## 5) Root acceptance policy (staleness and updates)

Production systems need a clear policy:

- accept only the latest root (simple, but user proofs can race)
- accept the latest `k` roots (handles propagation delays)
- accept any root in an on-chain root history (common on-chain pattern)

Also define:

- how roots are published (event log, API, signed checkpoint)
- how often users refresh group state

## 6) Message hashing and encoding

For `signalHash`, define:

- what exact bytes are hashed (raw string? JSON? ABI encoding?)
- normalization rules (whitespace, key order, Unicode normalization)
- whether the hash is inside the circuit or computed outside and treated as a public input

Add cross-language vectors that lock the encoding.

## 7) Security “gotchas” to check explicitly

- Replay protection: is `externalNullifier` doing the job you think it is?
- Front-running: can an observer reuse someone’s proof to publish the same signal first?
- Denial-of-service: is proof verification bounded and rate-limited?
- Privacy leaks: does your API accidentally reveal the Merkle path index or a stable identifier?

## 8) Production note

Educational code is for understanding and test vectors, not for production. Production Semaphore requires:

- a real SNARK proof system + audited circuits
- a SNARK-friendly hash (usually Poseidon)
- careful encoding consistency across prover/verifier/contract
