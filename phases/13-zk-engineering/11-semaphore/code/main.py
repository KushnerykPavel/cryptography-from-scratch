"""Phase 13 Lesson 11 - Semaphore (anonymous signaling: identity + group + nullifiers).

This lesson is a stdlib-only, engineering-focused model of Semaphore:

- An identity is two private 32-byte secrets: (trapdoor, nullifier).
- An identity commitment is a public hash of those secrets.
- A group is a Merkle tree of identity commitments; the Merkle root is the group state.
- A signal is bound to an external nullifier (scope). A nullifier hash prevents
  double-signaling in the same scope while preserving anonymity in the real protocol.

Important: this file does NOT implement a zk-SNARK. In production, a Semaphore proof
cryptographically shows membership and correct nullifier computation without revealing
the identity secrets or the leaf index. Here, we model the public inputs and the
verification gates, and we intentionally keep the "proof" transparent so it is
auditable with stdlib primitives.

Run:
  python3 code/main.py
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import struct
from dataclasses import dataclass
from typing import Iterable, Sequence


LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"

IDENTITY_COMMITMENT_PREFIX = b"\x02"
EXTERNAL_NULLIFIER_PREFIX = b"\x03"
NULLIFIER_HASH_PREFIX = b"\x04"
SIGNAL_HASH_PREFIX = b"\x05"


def _u32be(n: int) -> bytes:
    if not isinstance(n, int):
        raise TypeError("n must be int")
    if n < 0 or n > 0xFFFFFFFF:
        raise ValueError("n out of range for u32")
    return struct.pack(">I", n)


def _require_byteslike(name: str, v: object) -> bytes:
    if not isinstance(v, (bytes, bytearray, memoryview)):
        raise TypeError(f"{name} must be bytes-like")
    return bytes(v)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(_require_byteslike("data", data)).digest()


def sha256_hex(data: bytes) -> str:
    return sha256(data).hex()


def encode_leaf_value(*, value: bytes) -> bytes:
    v = _require_byteslike("value", value)
    return _u32be(len(v)) + v


def hash_leaf(*, value: bytes) -> bytes:
    return sha256(LEAF_PREFIX + encode_leaf_value(value=_require_byteslike("value", value)))


def hash_node(*, left: bytes, right: bytes) -> bytes:
    l = _require_byteslike("left", left)
    r = _require_byteslike("right", right)
    return sha256(NODE_PREFIX + l + r)


def build_merkle_levels(*, leaves: Sequence[bytes]) -> list[list[bytes]]:
    if not isinstance(leaves, Sequence):
        raise TypeError("leaves must be a sequence")
    if len(leaves) == 0:
        raise ValueError("leaves must be non-empty")

    level0 = [hash_leaf(value=v) for v in leaves]
    levels: list[list[bytes]] = [level0]

    while len(levels[-1]) > 1:
        cur = levels[-1]
        nxt: list[bytes] = []
        i = 0
        while i < len(cur):
            left = cur[i]
            if i + 1 < len(cur):
                right = cur[i + 1]
            else:
                right = cur[i]
            nxt.append(hash_node(left=left, right=right))
            i += 2
        levels.append(nxt)

    return levels


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


def _require_32(name: str, v: object) -> bytes:
    b = _require_byteslike(name, v)
    if len(b) != 32:
        raise ValueError(f"{name} must be 32 bytes")
    return b


def identity_commitment(*, trapdoor: bytes, nullifier: bytes) -> bytes:
    td = _require_32("trapdoor", trapdoor)
    nf = _require_32("nullifier", nullifier)
    return sha256(IDENTITY_COMMITMENT_PREFIX + td + nf)


def external_nullifier_hash(*, external_nullifier: str) -> bytes:
    if not isinstance(external_nullifier, str):
        raise TypeError("external_nullifier must be str")
    payload = external_nullifier.encode("utf-8")
    return sha256(EXTERNAL_NULLIFIER_PREFIX + encode_leaf_value(value=payload))


def nullifier_hash(*, nullifier: bytes, external_nullifier: str) -> bytes:
    nf = _require_32("nullifier", nullifier)
    scope = external_nullifier_hash(external_nullifier=external_nullifier)
    return sha256(NULLIFIER_HASH_PREFIX + nf + scope)


def signal_hash(*, signal: str) -> bytes:
    if not isinstance(signal, str):
        raise TypeError("signal must be str")
    payload = signal.encode("utf-8")
    return sha256(SIGNAL_HASH_PREFIX + encode_leaf_value(value=payload))


@dataclass(frozen=True)
class Identity:
    trapdoor: bytes
    nullifier: bytes
    commitment: bytes


def make_identity(*, trapdoor: bytes, nullifier: bytes) -> Identity:
    td = _require_32("trapdoor", trapdoor)
    nf = _require_32("nullifier", nullifier)
    return Identity(trapdoor=td, nullifier=nf, commitment=identity_commitment(trapdoor=td, nullifier=nf))


@dataclass(frozen=True)
class TransparentSemaphoreProof:
    merkle_root: bytes
    identity_commitment: bytes
    merkle_proof: list[tuple[str, bytes]]
    external_nullifier: str
    signal: str
    trapdoor: bytes
    nullifier: bytes

    def public_inputs(self) -> dict[str, str]:
        return {
            "merkle_root_hex": self.merkle_root.hex(),
            "nullifier_hash_hex": nullifier_hash(nullifier=self.nullifier, external_nullifier=self.external_nullifier).hex(),
            "signal_hash_hex": signal_hash(signal=self.signal).hex(),
            "external_nullifier_hash_hex": external_nullifier_hash(external_nullifier=self.external_nullifier).hex(),
        }


def make_transparent_proof(
    *,
    group_identity_commitments: Sequence[bytes],
    member_index: int,
    identity: Identity,
    external_nullifier: str,
    signal: str,
) -> TransparentSemaphoreProof:
    if not isinstance(group_identity_commitments, Sequence):
        raise TypeError("group_identity_commitments must be a sequence")
    if group_identity_commitments[member_index] != identity.commitment:
        raise ValueError("member_index does not match identity commitment at that position")

    root = merkle_root(leaves=group_identity_commitments)
    proof = merkle_proof(leaves=group_identity_commitments, index=member_index)
    return TransparentSemaphoreProof(
        merkle_root=root,
        identity_commitment=identity.commitment,
        merkle_proof=proof,
        external_nullifier=external_nullifier,
        signal=signal,
        trapdoor=identity.trapdoor,
        nullifier=identity.nullifier,
    )


def verify_transparent_proof(*, proof: TransparentSemaphoreProof) -> bool:
    if not isinstance(proof, TransparentSemaphoreProof):
        raise TypeError("proof must be TransparentSemaphoreProof")

    recomputed_commitment = identity_commitment(trapdoor=proof.trapdoor, nullifier=proof.nullifier)
    if not hmac.compare_digest(recomputed_commitment, proof.identity_commitment):
        return False
    return verify_merkle_proof(
        leaf_value=proof.identity_commitment,
        proof=proof.merkle_proof,
        root=proof.merkle_root,
    )


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


def _print_step(n: int, name: str) -> None:
    print(f"=== Step {n}: {name} ===")


def _derive_secret(*, label: str) -> bytes:
    if not isinstance(label, str):
        raise TypeError("label must be str")
    return sha256(b"demo:" + label.encode("utf-8"))


def step1_identities_and_commitments() -> list[Identity]:
    _print_step(1, "Identities and commitments")
    alice = make_identity(trapdoor=_derive_secret(label="alice:trapdoor"), nullifier=_derive_secret(label="alice:nullifier"))
    bob = make_identity(trapdoor=_derive_secret(label="bob:trapdoor"), nullifier=_derive_secret(label="bob:nullifier"))
    carol = make_identity(trapdoor=_derive_secret(label="carol:trapdoor"), nullifier=_derive_secret(label="carol:nullifier"))

    for name, ident in [("alice", alice), ("bob", bob), ("carol", carol)]:
        print(f"{name} commitment: {ident.commitment.hex()}")
    return [alice, bob, carol]


def step2_group_merkle_root_and_proofs(*, identities: Sequence[Identity]) -> tuple[list[bytes], bytes]:
    _print_step(2, "Group Merkle root and membership proofs")
    leaves = [i.commitment for i in identities]
    root = merkle_root(leaves=leaves)
    print(f"group size: {len(leaves)}")
    print(f"group root: {root.hex()}")

    idx = 1
    p = merkle_proof(leaves=leaves, index=idx)
    print(f"prove member index {idx}")
    for i, (side, sib) in enumerate(p, start=1):
        print(f"  step {i}: sibling on {side}: {sib.hex()}")
    ok = verify_merkle_proof(leaf_value=leaves[idx], proof=p, root=root)
    print(f"verify proof: {ok}")
    return leaves, root


def step3_nullifiers_and_scopes(*, identity: Identity) -> None:
    _print_step(3, "Scopes (external nullifiers) and nullifier hashes")
    scope = "vote:proposal-42"
    other_scope = "vote:proposal-99"

    nf1 = nullifier_hash(nullifier=identity.nullifier, external_nullifier=scope)
    nf2 = nullifier_hash(nullifier=identity.nullifier, external_nullifier=scope)
    nf3 = nullifier_hash(nullifier=identity.nullifier, external_nullifier=other_scope)
    print(f"scope:       {scope!r}")
    print(f"nullifier H: {nf1.hex()}")
    print(f"same scope -> same hash: {hmac.compare_digest(nf1, nf2)}")
    print(f"other scope -> different: {not hmac.compare_digest(nf1, nf3)}")


def step4_verify_signals_and_block_double_use(*, group_leaves: Sequence[bytes], identity: Identity) -> None:
    _print_step(4, "Verify signals and block double-signaling")
    registry = NullifierRegistry()

    scope = "vote:proposal-42"
    signal = "YES"
    member_index = 0

    proof1 = make_transparent_proof(
        group_identity_commitments=group_leaves,
        member_index=member_index,
        identity=identity,
        external_nullifier=scope,
        signal=signal,
    )
    ok1, reason1 = semaphore_verify_and_record(registry=registry, proof=proof1)
    print(f"signal #1: ok={ok1} reason={reason1}")
    print(json.dumps(proof1.public_inputs(), indent=2))

    proof2 = make_transparent_proof(
        group_identity_commitments=group_leaves,
        member_index=member_index,
        identity=identity,
        external_nullifier=scope,
        signal="NO",
    )
    ok2, reason2 = semaphore_verify_and_record(registry=registry, proof=proof2)
    print(f"signal #2 (same scope): ok={ok2} reason={reason2}")

    proof3 = make_transparent_proof(
        group_identity_commitments=group_leaves,
        member_index=member_index,
        identity=identity,
        external_nullifier="vote:proposal-99",
        signal="NO",
    )
    ok3, reason3 = semaphore_verify_and_record(registry=registry, proof=proof3)
    print(f"signal #3 (other scope): ok={ok3} reason={reason3}")


def main() -> None:
    identities = step1_identities_and_commitments()
    group_leaves, _root = step2_group_merkle_root_and_proofs(identities=identities)
    step3_nullifiers_and_scopes(identity=identities[0])
    step4_verify_signals_and_block_double_use(group_leaves=group_leaves, identity=identities[0])


if __name__ == "__main__":
    main()
