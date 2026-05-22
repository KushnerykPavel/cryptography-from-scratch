---
phase: 20
lesson: 05
title: ZK Rollup Architecture Decision Guide
type: reference
---

# ZK Rollup Architecture Decision Guide

Five structural decisions every ZK rollup implementation must make.
Paste this into a design review, ADR, or architecture doc.

---

## Decision 1: State Representation

**Question:** How is L2 state stored and committed on-chain?

| Option | Tradeoffs |
|--------|-----------|
| Sparse Merkle tree (fixed depth) | Constant-size inclusion proofs; empty leaves waste storage; standard in zkSync, StarkEx |
| Append-only Merkle tree | Efficient insertion; no deletion; used in Aztec's note model |
| Verkle tree | Smaller proofs via polynomial commitments; not yet battle-tested at scale |
| Flat balance map (no tree) | Simple; no inclusion proofs; cannot prove individual account state to L1 |

**Recommendation for new systems:** Sparse Merkle tree with SHA-256 (or Poseidon for circuit efficiency). Fix tree depth at 32 for 2^32 accounts.

---

## Decision 2: Transaction Format and Serialization

**Question:** What is the canonical wire format for transactions?

Canonical encoding requirements:
- Fixed-width fields (no variable-length integers unless length-prefixed)
- Big-endian byte order for cross-platform compatibility
- All fields that affect state must be covered by the signature
- Nonce prevents replay attacks; include it in both signature and leaf hash

Minimal transfer payload (this lesson):
```
sender   : 4 bytes (uint32 BE)
receiver : 4 bytes (uint32 BE)
amount   : 8 bytes (uint64 BE)
nonce    : 2 bytes (uint16 BE)
           ──────────────────
total    : 18 bytes
```

Production additions to cover: chain ID (prevents cross-rollup replay), fee, token ID, expiry timestamp.

---

## Decision 3: Proof System Choice

**Question:** Which ZK proof system generates the validity proof?

| System | Proof size | Verify time (L1 gas) | Prover time | Trusted setup? |
|--------|-----------|----------------------|-------------|----------------|
| Groth16 | ~200 bytes | ~200k gas | Fast | Yes (per circuit) |
| PLONK / UltraPlonk | ~400 bytes | ~300k gas | Medium | Universal SRS |
| STARK | ~100 KB | ~3M gas | Slow | No |
| Recursive SNARK (Nova, Halo2) | ~1 KB | ~500k gas | Fast amortized | No |

**Tradeoffs:**
- Groth16: smallest proof, cheapest verification, but requires a trusted setup ceremony per circuit change.
- PLONK: universal setup (one ceremony covers all circuits), flexible, used by most production zkEVMs.
- STARK: no trusted setup, quantum-resistant hash-based security, but large on-chain proof footprint.
- Recursive: batch many proofs into one; excellent for high-throughput rollups; higher engineering complexity.

**Recommendation:** Use PLONK (or a PLONK variant like Halo2) for new projects. Universal setup reduces operational risk from circuit upgrades.

---

## Decision 4: L1 Submission Format

**Question:** What data is posted to L1 and what does the verifier contract check?

Minimum on-chain data:
```
old_root       : 32 bytes  (previous state commitment)
new_root       : 32 bytes  (new state commitment)
validity_proof : variable  (ZK proof of correct transition)
compressed_txs : variable  (calldata for data availability)
```

Data availability options:

| Option | Cost | Trust assumption |
|--------|------|-----------------|
| Full calldata on L1 (rollup) | ~16 gas/byte | None — anyone can reconstruct L2 state |
| EIP-4844 blobs | ~1 gas/byte | None — blobs available for ~2 weeks |
| Off-chain DA (validium) | Minimal | DA committee or external chain must be honest |

**Recommendation:** Use EIP-4844 blobs for new Ethereum rollups. Validium is only appropriate when data availability assumptions are explicitly accepted by users.

---

## Decision 5: Sequencer Trust Model

**Question:** Who orders L2 transactions and what happens if they misbehave?

| Model | Liveness guarantee | Censorship resistance |
|-------|-------------------|----------------------|
| Single centralized sequencer | High throughput, low latency | Sequencer can censor indefinitely |
| Decentralized sequencer set (PoS/BFT) | Tolerates f<n/3 failures | Censorship requires majority collusion |
| Forced transaction inclusion (escape hatch) | Users can always exit via L1 | Sequencer cannot block L1-forced txs |
| Based rollup (L1 proposers sequence L2) | Same liveness as L1 | Same censorship resistance as L1 |

**Minimum safety requirement:** Any rollup must provide a forced-exit mechanism so users can withdraw funds to L1 even if the sequencer is unresponsive or malicious. Without it, user funds are at the sequencer's mercy regardless of proof validity.

---

## Checklist: Before Shipping a ZK Rollup

- [ ] State root transitions are verified by an on-chain smart contract (not trusted off-chain)
- [ ] Validity proof covers: signature validity, balance non-negativity, correct Merkle root update
- [ ] L1 contract checks `old_root` matches its stored state before accepting any batch
- [ ] Transaction nonces prevent replay within and across batches
- [ ] Data availability is guaranteed (calldata, blobs, or audited DA layer)
- [ ] Forced-exit / escape hatch mechanism exists for censorship resistance
- [ ] Proof system trusted setup (if any) was run with a ceremony, not a single party
- [ ] Circuit has been audited; any circuit upgrade requires re-audit and new setup
- [ ] Leaf encoding is canonical and documented (endianness, field widths)
- [ ] No secret keys or balance values are revealed to L1 (true ZK, not this demo's simplified version)
