---
name: proof-aggregation-recursion-checklist
description: PR review checklist + design template for proof aggregation / recursion pipelines (commitment formats, binding, topology, DA, pitfalls).
phase: 13-zk-engineering
lesson: 09-proof-aggregation-recursion
---

# Proof Aggregation & Recursion — Design / Audit Checklist

Use this as a copy-paste template for:
- an aggregation service (batching proofs off-chain + publishing one on-chain proof),
- a recursive proving pipeline (proof-of-proofs / IVC / folding),
- a smart contract verifier that must support inclusion proofs.

## 1) Goal and threat model

- What is the verifier budget? (e.g., EVM gas, mobile CPU, API QPS)
- Who is trusted, if anyone? (sequencer, aggregator operator, DA layer)
- What must be public? (state root, program ID, batch id, step counter)
- What attacks matter most?
  - accepting a valid proof for the **wrong statement**
  - censoring / excluding leaf proofs from a published batch root
  - replaying old proofs / old batch roots
  - mixing proofs from different circuits / versions

## 2) Define the proof commitment format (do this first)

Write a one-line commitment definition that every component uses.

Example template:

```
commitment = H(
  proof_system_id ||
  protocol_version ||
  verifier_id (vk_hash / program_id / params_digest) ||
  public_inputs_bytes ||
  proof_bytes_hash
)
```

Checklist:
- Commitment binds **verifier identity** (vk hash / program ID).
- Commitment binds **public inputs** exactly as the verifier interprets them.
- Commitment binds **protocol versioning** (encoding, hash function, domain tags).
- Commitment uses **unambiguous encoding** (length-prefix or typed serialization).
- If there are multiple proof types, commitment includes a **type tag**.

## 3) Aggregation topology and batching rules

- Choose a topology:
  - binary fold tree (depth ≈ `ceil(log2(n))`)
  - k-ary fan-in tree (shallower depth, bigger per-step circuit)
  - linear IVC chain (best for time-ordered state machines)
- Define odd-count behavior:
  - carry-forward the last node?
  - fold with a neutral element?
  - require power-of-two batch sizes?
- Define ordering:
  - are leaves ordered (by time / index) or sorted (by digest)?
  - if sorted, specify stable ordering and tie-breaking.

## 4) Public inputs for the aggregated/recursive proof

Your outer proof should expose a small, explicit public interface.

Common minimal set:
- `verifier_id` (vk hash / program id digest)
- `batch_root` (Merkle root of leaf commitments)
- `count` (number of leaves proven)
- optional: `start_state`, `end_state`, `step_counter`, `epoch`, `chain_id`

Checklist:
- Every public value is actually checked by the contract / verifier.
- No “witness-provided public inputs” are trusted without recomputation.
- The verifier rejects unknown `verifier_id` / `protocol_version`.

## 5) Inclusion proofs and data availability (DA)

If users need to prove “my proof was included”:
- publish `batch_root` somewhere canonical (contract storage, L1 event, blob/DA)
- define the Merkle tree rules (leaf hash, node hash, padding, ordering)
- define what the user must present:
  - leaf commitment
  - leaf index (if ordering matters)
  - Merkle path

Checklist:
- The Merkle construction is pinned (no “implementation-defined” behavior).
- Padding rule is explicit (duplicate-last vs carry vs power-of-two splits).
- Leaf value is the **commitment**, not raw proof bytes (unless required).

## 6) Transcript / Fiat–Shamir binding (recursion-specific)

If your recursion step produces challenges from a transcript:
- domain-separate by protocol version and verifier id
- include old accumulator state + new accumulator state in the transcript
- include the batch root and any counters in the transcript

Checklist:
- Transcript input encoding is stable and length-delimited.
- Challenges depend on the actual statement (no missing fields).

## 7) “Red flag” questions for reviewers

- Can I swap in a proof from a different circuit and still pass?
- Can I change the public inputs without changing the commitment?
- Can I permute/reorder leaves without changing the batch root (should I be able to)?
- What happens if the batch has an odd number of leaves?
- Are we relying on an implicit encoding (endianness, field packing, JSON order)?
- Does the contract pin the verifier id / program id, or accept it from calldata?

## 8) What to pin in the repo (to avoid drift)

- commitment spec (as text)
- Merkle spec (as text) + 2–3 frozen test vectors
- verifier id / vk hash derivation method
- protocol_version constant
- end-to-end tests that fail on:
  - byte order changes
  - hash/tag changes
  - Merkle padding rule changes

