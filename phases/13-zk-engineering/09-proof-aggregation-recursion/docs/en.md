# Proof Aggregation & Recursion in Practice

> Commit to many checks with one digest — then prove the digest is correct.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 13 · 08 (On-Chain Verifiers), plus comfort with hashes/Merkle trees
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** why recursion turns “verify N proofs” into “verify 1 proof”
- **Distinguish** aggregation vs recursion vs accumulation (and when each wins)
- **Implement** statement-binding commitments using domain-separated hashes
- **Compute** a Merkle root + inclusion proof for a batch of proof digests
- **Apply** an engineering checklist to avoid “verified the wrong statement” bugs

## The Problem

You build a zk system that produces lots of proofs: per-block rollup proofs, per-shard zkVM proofs, per-user credential proofs, per-transaction validity proofs. Your verifier budget is tiny (on-chain gas, mobile/light-client CPU, or an API rate limit). If you verify every proof individually, your system either becomes too expensive to run or too slow to finalize.

Proof aggregation and recursion are the standard escape hatch: you verify *one* compact artifact that attests “I verified all the others.” But in real systems, the cryptography is only half the story: most production failures come from **binding mistakes** (wrong public inputs, wrong verifier key, wrong program ID), **ambiguous encodings**, and **aggregation tree edge cases** (ordering, padding, mixed proof types).

This lesson gives you a runnable, stdlib-only toy that mirrors the *interfaces* and *failure modes* of production aggregation/recursion systems, without requiring Halo2/Plonky2/Groth16 tooling.

## The Concept

Think in two layers:

1. **Leaf proofs**: each proof attests to one small statement (e.g., “this state transition is valid”).
2. **A commitment** to many leaf proofs: a single digest that “stands in” for a whole batch (typically a Merkle root).

Then recursion (or an aggregation circuit) proves:

> “Given the leaf proofs as private inputs, I verified them and I output the correct commitment digest as a public input.”

### Aggregation vs recursion vs accumulation (engineering view)

| Pattern | What you get | What it’s best for |
|--------|--------------|--------------------|
| **Batch aggregation** | one proof for many independent proofs | “verify N user proofs with 1 verifier call” |
| **Recursion / folding** | one proof for a long *chain* of steps | “prove a long computation / state machine over time” |
| **Accumulation** | a compact “running state” updated per step | “keep recursion step small; finalize occasionally” |

### The crucial invariant: statement binding

A proof is only meaningful if it’s tied to:
- the **public inputs** (what is being proven),
- the **verifier identity** (vk hash / program ID / parameters),
- the **protocol version** (domain separation, encoding, hash function).

In this lesson, we model that binding with domain-separated SHA-256 commitments.

## Build It

### Step 1: Statement binding with tagged hashes
```python
def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(data):
    return hashlib.sha256(data).digest()


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def u32be(n):
    if n < 0 or n >= 2**32:
        raise ValueError("u32 out of range")
    return int(n).to_bytes(4, "big")


def tagged_hash(tag, *parts):
    h = hashlib.sha256()
    h.update(tag.encode("utf-8"))
    h.update(b"\x00")
    for p in parts:
        if not isinstance(p, (bytes, bytearray)):
            raise TypeError("tagged_hash parts must be bytes")
        h.update(u32be(len(p)))
        h.update(p)
    return h.digest()


def tagged_hash_hex(tag, *parts):
    return tagged_hash(tag, *parts).hex()


def state_step(start_state_hex, message):
    start = bytes.fromhex(start_state_hex)
    msg = message.encode("utf-8")
    return tagged_hash_hex("state.step.v1", start, msg)


@dataclass(frozen=True)
class StepProof:
    start_state_hex: str
    message: str
    end_state_hex: str
    digest_hex: str


def prove_step(start_state_hex, message):
    end_state_hex = state_step(start_state_hex, message)
    digest_hex = tagged_hash_hex(
        "proof.step.v1",
        bytes.fromhex(start_state_hex),
        message.encode("utf-8"),
        bytes.fromhex(end_state_hex),
    )
    return StepProof(
        start_state_hex=start_state_hex,
        message=message,
        end_state_hex=end_state_hex,
        digest_hex=digest_hex,
    )


def verify_step(proof):
    if not isinstance(proof, StepProof):
        return False
    expected_end = state_step(proof.start_state_hex, proof.message)
    if expected_end != proof.end_state_hex:
        return False
    expected_digest = tagged_hash_hex(
        "proof.step.v1",
        bytes.fromhex(proof.start_state_hex),
        proof.message.encode("utf-8"),
        bytes.fromhex(proof.end_state_hex),
    )
    return expected_digest == proof.digest_hex
```
This is a toy “state transition proof”: each step is a hash-chained state update. The important part is the **digest**: it binds a statement to a protocol version tag and unambiguous byte encoding.

### Step 2: Batch aggregation with a Merkle root
```python
def merkle_leaf_hash(leaf_bytes):
    if not isinstance(leaf_bytes, (bytes, bytearray)):
        raise TypeError("leaf must be bytes")
    return sha256(b"\x00" + bytes(leaf_bytes))


def merkle_node_hash(left, right):
    return sha256(b"\x01" + left + right)


def merkle_root(leaf_bytes_list):
    if len(leaf_bytes_list) == 0:
        return sha256(b"")
    level = [merkle_leaf_hash(b) for b in leaf_bytes_list]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level = level + [level[-1]]
        nxt = []
        for i in range(0, len(level), 2):
            nxt.append(merkle_node_hash(level[i], level[i + 1]))
        level = nxt
    return level[0]


def merkle_inclusion_proof(leaf_bytes_list, index):
    if index < 0 or index >= len(leaf_bytes_list):
        raise IndexError("leaf index out of range")
    level = [merkle_leaf_hash(b) for b in leaf_bytes_list]
    idx = index
    proof = []
    while len(level) > 1:
        if len(level) % 2 == 1:
            level = level + [level[-1]]
        sibling_idx = idx ^ 1
        sibling = level[sibling_idx]
        side = "L" if sibling_idx < idx else "R"
        proof.append((side, sibling))
        nxt = []
        for i in range(0, len(level), 2):
            nxt.append(merkle_node_hash(level[i], level[i + 1]))
        level = nxt
        idx //= 2
    return proof


def verify_merkle_inclusion(leaf_bytes, index, proof, expected_root):
    h = merkle_leaf_hash(leaf_bytes)
    idx = index
    for side, sib in proof:
        if side == "L":
            h = merkle_node_hash(sib, h)
        elif side == "R":
            h = merkle_node_hash(h, sib)
        else:
            return False
        idx //= 2
    return h == expected_root
```
Aggregation in production usually commits to each proof via a **proof commitment** (often `H(vk_hash || public_inputs || proof_bytes)`). A Merkle root compresses “N commitments” into “1 digest,” enabling cheap inclusion proofs.

### Step 3: Recursion as “segment proofs” over sequential steps
```python
@dataclass(frozen=True)
class SegmentProof:
    start_state_hex: str
    end_state_hex: str
    step_count: int
    commitment_root_hex: str
    digest_hex: str


def prove_segment(step_proofs):
    if len(step_proofs) == 0:
        raise ValueError("segment needs at least 1 step")
    for p in step_proofs:
        if not verify_step(p):
            raise ValueError("invalid step proof in segment")
    for a, b in zip(step_proofs, step_proofs[1:]):
        if a.end_state_hex != b.start_state_hex:
            raise ValueError("segment is not sequentially linked")
    leaves = [bytes.fromhex(p.digest_hex) for p in step_proofs]
    root = merkle_root(leaves).hex()
    start_state_hex = step_proofs[0].start_state_hex
    end_state_hex = step_proofs[-1].end_state_hex
    step_count = len(step_proofs)
    digest_hex = tagged_hash_hex(
        "proof.segment.v1",
        bytes.fromhex(start_state_hex),
        bytes.fromhex(end_state_hex),
        u32be(step_count),
        bytes.fromhex(root),
    )
    return SegmentProof(
        start_state_hex=start_state_hex,
        end_state_hex=end_state_hex,
        step_count=step_count,
        commitment_root_hex=root,
        digest_hex=digest_hex,
    )


def verify_segment(segment, step_proofs):
    if not isinstance(segment, SegmentProof):
        return False
    if len(step_proofs) != segment.step_count:
        return False
    try:
        expected = prove_segment(step_proofs)
    except Exception:
        return False
    return expected == segment
```
This models a recursion “checkpoint”: the public interface is compact (`start_state`, `end_state`, `count`, `digest`), while the leaf proofs are private inputs to the recursive step.

### Step 4: A binary aggregation tree (folding segments)
```python
def fold_two_segments(left, right):
    if left.end_state_hex != right.start_state_hex:
        raise ValueError("segments are not sequentially linked")
    combined_root = merkle_root([bytes.fromhex(left.digest_hex), bytes.fromhex(right.digest_hex)]).hex()
    step_count = left.step_count + right.step_count
    digest_hex = tagged_hash_hex(
        "proof.segment_fold.v1",
        bytes.fromhex(left.start_state_hex),
        bytes.fromhex(right.end_state_hex),
        u32be(step_count),
        bytes.fromhex(combined_root),
        bytes.fromhex(left.digest_hex),
        bytes.fromhex(right.digest_hex),
    )
    return SegmentProof(
        start_state_hex=left.start_state_hex,
        end_state_hex=right.end_state_hex,
        step_count=step_count,
        commitment_root_hex=combined_root,
        digest_hex=digest_hex,
    )


def fold_segments_binary(segments):
    if len(segments) == 0:
        raise ValueError("need at least 1 segment")
    level = list(segments)
    while len(level) > 1:
        nxt = []
        i = 0
        while i + 1 < len(level):
            nxt.append(fold_two_segments(level[i], level[i + 1]))
            i += 2
        if i < len(level):
            nxt.append(level[i])
        level = nxt
    return level[0]
```
This is the “log-depth aggregation tree” mental model: you fold many segments into one, reducing the number of verifier calls at the outermost layer.

Run it:
`python3 code/main.py`

## Use It

Production equivalents (not exhaustive):

- **Merkle roots for commitments**: commit to `(vk_hash, public_inputs, proof_bytes)` and publish the root as the batch identifier; users prove inclusion with a Merkle path.
- **zkVM recursion + aggregation**: RISC Zero / SP1 / Jolt-style pipelines often prove many shards/blocks, then run an aggregation guest that verifies inner proofs and outputs a single proof whose public inputs include a commitment root.
- **Recursive SNARKs**: Halo-style recursion (and modern descendants) lets a proof verify another proof in-circuit; folding/IVC systems (e.g., Nova) focus on “update a running proof” for long computations.
- **SNARK aggregation**: schemes like SnarkPack aggregate many pairing-based proofs into one for fast verification.

## Pitfalls

1. **Not binding the verifier identity**: your “proof commitment” must include a vk hash / program ID / parameters digest, or you can accept a proof for the wrong circuit.
2. **Ambiguous encodings**: if you hash “a || b” without lengths/tags, you can get collisions like `("ab","c")` vs `("a","bc")`.
3. **Merkle tree mismatch**: different padding rules (duplicate-last vs power-of-two splits), leaf hashing rules, or sorting choices produce different roots for the same leaves.
4. **Mixed proof types in one batch**: if you aggregate heterogeneous proofs, you must tag each leaf with a type ID and enforce it inside the aggregation circuit.
5. **Odd-count edge cases**: “pad by duplicating a segment” is not safe for sequential recursion; you need a defined carry rule (or a neutral element) that preserves the state transition semantics.

## Ship It

Use `outputs/proof-aggregation-recursion-checklist.md` as a PR review checklist or a design doc template when you build:
- a proof-aggregation service,
- a recursive proving pipeline,
- an on-chain verifier that must support proof inclusion proofs.

Copy it into your repo and fill in the blanks (commitment format, transcript binding, Merkle conventions, and topology).

## Exercises

1. Easy. Run `python3 code/main.py`. Observe how a list of step proofs turns into one Merkle root and one segment digest.
2. Medium. Change the Merkle padding rule (e.g., “carry last node” instead of “duplicate last hash”) and update the vectors/tests so your implementation is consistent and deterministic.
3. Hard. Design a production-proof commitment format for your favorite ZK stack (Groth16 / Halo2 / zkVM) that binds: `(proof_system_id, vk_hash, public_inputs, protocol_version)`. Write it as a short spec and review it with the checklist in `outputs/`.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Proof aggregation | “one proof for many proofs” | A protocol that verifies multiple proofs and outputs one proof attesting all verified |
| Recursion | “a proof verifies a proof” | A proving step whose *statement* includes “the inner proof verified” |
| Accumulator | “a running digest” | A compact state that summarizes many checks; updated each step; proven correct periodically |
| Statement binding | “hash the inputs” | An unambiguous encoding that ties the proof to public inputs + verifier identity + version |
| Inclusion proof | “Merkle proof” | A short path of sibling hashes proving a leaf is in a committed batch root |

## Further Reading

- Bowe, Grigg, Hopwood, *Halo: Recursive Proof Composition without a Trusted Setup* (2019) — classic “proofs verifying proofs” blueprint.
- Kothapalli, Setty, Tzialla, *Nova: Recursive Zero-Knowledge Arguments from Folding Schemes* (2021) — practical IVC/folding perspective on recursion.
- Fisch et al., *SnarkPack: Practical SNARK Aggregation* (2021) — a concrete aggregation scheme for pairing-based SNARKs.
- Gabizon, Williamson, Ciobotaru, *PLONK* (2019) — widely used proving system family; recursion/aggregation often wraps PLONK-like proofs.
