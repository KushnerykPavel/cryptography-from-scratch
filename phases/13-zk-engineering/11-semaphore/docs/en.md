# ZK Identity — Semaphore

> Membership is private; double-signaling is public.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 09 · 04 (Merkle Trees), Phase 13 · 10 (ZK mixers)
**Time:** ~60 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain how Semaphore splits “who you are” (secret) from “you are in the group” (Merkle root).
- Compute identity commitments and group roots using domain-separated hashes.
- Implement a Merkle inclusion proof generator and verifier for group membership.
- Distinguish an external nullifier (scope) from a nullifier hash (one-time tag in that scope).
- Apply a nullifier registry to reject double-signaling without tracking user identities.

## The Problem

You want to let members of a group send a message (vote, endorsement, “I’m eligible”) without revealing *which* member they are. At the same time, you must stop a single member from sending the same kind of message twice (“one person, one vote”) even though you are not allowed to learn who they are.

Naively, you can solve one of these goals but not both. If you require a signature, you can stop double-voting, but you identify the signer. If you accept anonymous messages, you can preserve privacy, but you cannot prevent spam and sybil behavior within the group.

Semaphore is a protocol pattern that gets you both: a member proves membership in a group (committed by a Merkle root) and produces a *nullifier hash* that is unique per “scope” (the *external nullifier*). Verifiers only store nullifier hashes to prevent double-signaling; they never store identities.

## The Concept

Semaphore has three moving parts:

1. **Identity (private):** two secrets `(trapdoor, nullifier)`.
2. **Group (public state):** a Merkle tree of **identity commitments** (public leaves), with a **Merkle root** that commits to the current membership set.
3. **Signal (public action):** a message bound to a **scope** (external nullifier). The verifier stores a **nullifier hash** to prevent a member from reusing the same identity in the same scope.

The verifier’s job is a gate:

| Check | What the verifier learns | Why it matters |
|------|---------------------------|----------------|
| “This identity commitment is in the group committed by `root`.” | Only that the sender is *some* member | Sybil resistance / eligibility |
| “This sender hasn’t signaled in this scope before.” | Only a one-time tag (`nullifier_hash`) | One-person-one-action |

In real Semaphore, the user produces a zk-SNARK proof that ties these together **without revealing** their identity secrets or which Merkle leaf they are. In this lesson, we implement the same *dataflow and verification gates* with SHA-256 so you can test it with stdlib only. We intentionally make the proof *transparent* so you can audit every step. Production replaces this transparent proof with a SNARK proof, and replaces SHA-256 with a SNARK-friendly hash (usually Poseidon).

## Build It

### Step 1: Identities and commitments

An identity is two 32-byte secrets. The identity commitment is a public hash of those secrets. In production Semaphore, this is typically Poseidon over field elements; here we use SHA-256 with a domain-separation prefix.

```python
IDENTITY_COMMITMENT_PREFIX = b"\x02"


def _require_32(name: str, v: object) -> bytes:
    b = _require_byteslike(name, v)
    if len(b) != 32:
        raise ValueError(f"{name} must be 32 bytes")
    return b


def identity_commitment(*, trapdoor: bytes, nullifier: bytes) -> bytes:
    td = _require_32("trapdoor", trapdoor)
    nf = _require_32("nullifier", nullifier)
    return sha256(IDENTITY_COMMITMENT_PREFIX + td + nf)


@dataclass(frozen=True)
class Identity:
    trapdoor: bytes
    nullifier: bytes
    commitment: bytes


def make_identity(*, trapdoor: bytes, nullifier: bytes) -> Identity:
    td = _require_32("trapdoor", trapdoor)
    nf = _require_32("nullifier", nullifier)
    return Identity(trapdoor=td, nullifier=nf, commitment=identity_commitment(trapdoor=td, nullifier=nf))
```

This gives you a public leaf value (`commitment`) that can be put into a Merkle tree without revealing the secrets.

### Step 2: Group Merkle root and membership proofs

The group is a Merkle tree whose leaves are identity commitments. The root is the group’s public state. A membership proof is the sibling hashes along the path from a leaf to the root.

```python
def merkle_root(*, leaves: Sequence[bytes]) -> bytes:
    return build_merkle_levels(leaves=leaves)[-1][0]


def merkle_proof(*, leaves: Sequence[bytes], index: int) -> list[tuple[str, bytes]]:
    if not isinstance(index, int):
        raise TypeError("index must be int")
    if index < 0:
        raise ValueError("index must be non-negative")
    if index >= len(leaves):
        raise ValueError("index out of range")

    levels = build_merkle_levels(leaves=leaves)
    proof: list[tuple[str, bytes]] = []
    idx = index

    for level in levels[:-1]:
        if idx % 2 == 0:
            sib_idx = idx + 1
            if sib_idx >= len(level):
                sibling = level[idx]
            else:
                sibling = level[sib_idx]
            proof.append(("right", sibling))
        else:
            sibling = level[idx - 1]
            proof.append(("left", sibling))
        idx //= 2

    return proof


def verify_merkle_proof(
    *,
    leaf_value: bytes,
    proof: Sequence[tuple[str, bytes]],
    root: bytes,
) -> bool:
    if not isinstance(proof, Sequence):
        raise TypeError("proof must be a sequence")
    r = _require_byteslike("root", root)

    cur = hash_leaf(value=_require_byteslike("leaf_value", leaf_value))
    for side, sibling in proof:
        if side not in ("left", "right"):
            raise ValueError("proof side must be 'left' or 'right'")
        sib = _require_byteslike("proof sibling", sibling)
        if side == "left":
            cur = hash_node(left=sib, right=cur)
        else:
            cur = hash_node(left=cur, right=sib)

    return hmac.compare_digest(cur, r)
```

This gives you the exact gate a verifier uses: “is this identity commitment in the set committed by `root`?”

### Step 3: Scopes (external nullifiers) and nullifier hashes

An external nullifier is a **scope identifier** like `"vote:proposal-42"` or `"mint:drop-7"`. The nullifier hash is derived from the identity’s nullifier secret and the scope. It is stable for the same identity+scope, and different across scopes.

```python
EXTERNAL_NULLIFIER_PREFIX = b"\x03"
NULLIFIER_HASH_PREFIX = b"\x04"


def external_nullifier_hash(*, external_nullifier: str) -> bytes:
    if not isinstance(external_nullifier, str):
        raise TypeError("external_nullifier must be str")
    payload = external_nullifier.encode("utf-8")
    return sha256(EXTERNAL_NULLIFIER_PREFIX + encode_leaf_value(value=payload))


def nullifier_hash(*, nullifier: bytes, external_nullifier: str) -> bytes:
    nf = _require_32("nullifier", nullifier)
    scope = external_nullifier_hash(external_nullifier=external_nullifier)
    return sha256(NULLIFIER_HASH_PREFIX + nf + scope)
```

The verifier does not need to know who you are — it only stores your `nullifier_hash` to prevent a second signal in the same scope.

### Step 4: Verify signals and block double-signaling

We now tie it together with a verifier-side nullifier registry. Our “proof” is intentionally transparent (it carries secrets) so we can verify it with stdlib. Production replaces this with a SNARK proof that reveals only public inputs.

```python
class NullifierRegistry:
    def __init__(self) -> None:
        self._seen: set[bytes] = set()

    def seen(self, nf_hash: bytes) -> bool:
        h = _require_32("nf_hash", nf_hash)
        return h in self._seen

    def record(self, nf_hash: bytes) -> None:
        h = _require_32("nf_hash", nf_hash)
        self._seen.add(h)


def semaphore_verify_and_record(
    *,
    registry: NullifierRegistry,
    proof: TransparentSemaphoreProof,
) -> tuple[bool, str]:
    if not verify_transparent_proof(proof=proof):
        return False, "invalid proof (membership or commitment mismatch)"

    nf_h = nullifier_hash(nullifier=proof.nullifier, external_nullifier=proof.external_nullifier)
    if registry.seen(nf_h):
        return False, "nullifier already seen (double-signal)"

    registry.record(nf_h)
    return True, "accepted"
```

This is the whole engineering loop: verify membership under a root, derive a scope-bound nullifier hash, and reject reuse.

Run it:
`python3 code/main.py`

## Use It

Production Semaphore implementations are a stack:

- **Circuits:** constraints for membership + nullifier correctness (Circom / Noir / halo2 / arkworks).
- **Hash function:** Poseidon (or another SNARK-friendly hash) instead of SHA-256.
- **Group management:** an incremental Merkle tree that supports inserts/updates efficiently.
- **Verifier:** a contract or service that checks proofs against a published Merkle root and records nullifier hashes.

Practical equivalents to look for:

- Semaphore protocol SDKs (identity creation, group trees, proof generation).
- Circom circuits for Semaphore (membership + nullifier constraints).
- On-chain verifiers for Groth16 / Plonk depending on your proving system.

## Pitfalls

1. **Scope mismatch:** client and verifier disagree on the exact external nullifier string/encoding (e.g., `"proposal-42"` vs `"vote:proposal-42"`), causing unexpected “already voted” or “can’t verify” failures.
2. **Stale group roots:** users prove against an old Merkle root while the verifier only accepts the latest root (or vice versa). Decide your root acceptance policy (latest only vs. recent window).
3. **Incorrect domain separation:** reusing the same hash domain for commitments, nullifiers, and signals risks cross-protocol collisions and “hash mismatch” bugs across components.
4. **Nullifier registry keyed wrong:** storing the external nullifier itself, or storing `(root, nullifier_hash)` instead of just `nullifier_hash` (or the other way around) changes the security semantics.
5. **Non-canonical message hashing:** different UTF-8 normalization, whitespace, or serialization rules for the signal lead to different `signal_hash` across client/circuit/verifier.

## Ship It

Save the reusable checklist in `outputs/semaphore-integration-checklist.md` and use it when reviewing or implementing:

- group membership systems (Merkle roots + proofs),
- one-person-one-action gates (nullifiers),
- zk app endpoints (public inputs and state updates).

The checklist is designed to be pasted into a PR review or an audit doc.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe that the second signal in the same scope is rejected, but signaling in a different scope is accepted.
2. Medium. Extend `NullifierRegistry` to support a “recent scopes” window (e.g., allow voting only for the latest 10 proposals) and add tests for the policy.
3. Hard. Production integration: sketch the public inputs your on-chain verifier would store (`root`, `nullifier_hash`, `external_nullifier_hash`, `signal_hash`) and the minimum state transitions needed to keep the system consistent under reorgs / retries.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Identity | “My anonymous key” | Two secrets used to derive a public commitment and scope-bound nullifiers |
| Identity commitment | “My public identity” | A hash leaf stored in the group Merkle tree |
| Group | “The set of members” | A Merkle tree whose root commits to all identity commitments |
| Merkle root | “The group state” | A single hash that commits to all leaves under fixed hashing rules |
| External nullifier | “The context” | A scope identifier that makes nullifiers per-action (vote vs. mint vs. login) |
| Nullifier hash | “One-time tag” | A deterministic hash that is reused on double-signal and is safe to store publicly |
| Signal | “The message” | The user’s action payload, typically hashed before entering a circuit |

## Further Reading

- Semaphore docs — concept overview and SDK usage.
- Semaphore whitepaper — protocol details and threat model.
- “Nullifiers” in ZK systems — how “one-time tags” appear across mixers, rollups, and credential systems.
