"""
Merkle signatures (MSS) demo from scratch.

Implements:
- Lamport one-time signatures (OTS) as the leaf signature scheme
- A Merkle tree over OTS public keys
- A Merkle-signature wrapper that signs with one OTS key + an auth path

Run:
  python3 code/main.py
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Iterable, List, Sequence, Tuple


Hash = bytes  # 32 bytes (sha256)
LamportSecretKey = List[Tuple[bytes, bytes]]  # 256 pairs of 32-byte secrets
LamportPublicKey = List[Tuple[Hash, Hash]]  # 256 pairs of 32-byte hashes
LamportSignature = List[bytes]  # 256 revealed secrets


def sha256(data: bytes) -> Hash:
    return hashlib.sha256(data).digest()


def h(label: bytes, *parts: bytes) -> Hash:
    return sha256(label + b"".join(parts))


def prg(seed: bytes, label: bytes, out_len: int) -> bytes:
    """
    Deterministic byte generator based on SHA-256(seed || label || counter).

    Educational PRG: good enough for determinism in this lesson, not a DRBG spec.
    """
    if out_len < 0:
        raise ValueError("out_len must be non-negative")
    out = bytearray()
    counter = 0
    while len(out) < out_len:
        block = sha256(seed + label + counter.to_bytes(4, "big"))
        out.extend(block)
        counter += 1
    return bytes(out[:out_len])


def bytes_to_bits_be(data: bytes) -> List[int]:
    bits: List[int] = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def lamport_keygen(seed: bytes) -> Tuple[LamportSecretKey, LamportPublicKey]:
    """
    Lamport OTS key generation.

    - Secret key: 256 pairs of 32-byte strings
    - Public key: SHA-256 of each secret string
    """
    raw = prg(seed, b"LAMPORT_SK", 256 * 2 * 32)
    sk: LamportSecretKey = []
    pk: LamportPublicKey = []
    off = 0
    for _ in range(256):
        s0 = raw[off : off + 32]
        s1 = raw[off + 32 : off + 64]
        off += 64
        sk.append((s0, s1))
        pk.append((sha256(s0), sha256(s1)))
    return sk, pk


def lamport_pk_hash(pk: LamportPublicKey) -> Hash:
    """
    Compress a Lamport public key to a single 32-byte hash (the Merkle-tree leaf).
    """
    flat = b"".join(x for pair in pk for x in pair)
    return h(b"LAMPORT_PK", flat)


def lamport_sign(sk: LamportSecretKey, message: bytes) -> LamportSignature:
    """
    Sign a message with Lamport OTS.

    We sign the 256-bit digest SHA-256(message). For each digest bit, reveal
    one of the two corresponding secret values.
    """
    digest = sha256(message)
    bits = bytes_to_bits_be(digest)
    sig: LamportSignature = []
    for i, bit in enumerate(bits):
        s0, s1 = sk[i]
        sig.append(s1 if bit else s0)
    return sig


def lamport_verify(pk: LamportPublicKey, message: bytes, sig: LamportSignature) -> bool:
    if len(sig) != 256:
        return False
    digest = sha256(message)
    bits = bytes_to_bits_be(digest)
    for i, bit in enumerate(bits):
        expected = pk[i][bit]
        if sha256(sig[i]) != expected:
            return False
    return True


def lamport_signature_fingerprint(sig: LamportSignature) -> Hash:
    """
    Compact, deterministic fingerprint for a Lamport signature (for tests/logging).
    """
    return h(b"LAMPORT_SIG", b"".join(sig))


def merkle_parent(left: Hash, right: Hash) -> Hash:
    return h(b"MERKLE_NODE", left, right)


def _is_power_of_two(n: int) -> bool:
    return n > 0 and (n & (n - 1)) == 0


def merkle_build(leaves: Sequence[Hash]) -> List[List[Hash]]:
    """
    Build a full binary Merkle tree.

    Returns levels bottom-up: levels[0] are leaves, levels[-1][0] is the root.
    """
    if not _is_power_of_two(len(leaves)):
        raise ValueError("number of leaves must be a power of two")
    if any(len(x) != 32 for x in leaves):
        raise ValueError("all leaves must be 32-byte hashes")

    levels: List[List[Hash]] = [list(leaves)]
    cur = list(leaves)
    while len(cur) > 1:
        nxt: List[Hash] = []
        for i in range(0, len(cur), 2):
            nxt.append(merkle_parent(cur[i], cur[i + 1]))
        levels.append(nxt)
        cur = nxt
    return levels


def merkle_root(leaves: Sequence[Hash]) -> Hash:
    return merkle_build(leaves)[-1][0]


def merkle_auth_path(levels: Sequence[Sequence[Hash]], leaf_index: int) -> List[Hash]:
    """
    Authentication path for a leaf: list of sibling hashes from leaf-level up.
    """
    if leaf_index < 0 or leaf_index >= len(levels[0]):
        raise IndexError("leaf_index out of range")
    path: List[Hash] = []
    idx = leaf_index
    for level in levels[:-1]:
        sib = idx ^ 1
        path.append(level[sib])
        idx //= 2
    return path


def merkle_verify_path(leaf: Hash, leaf_index: int, auth_path: Sequence[Hash], root: Hash) -> bool:
    if leaf_index < 0:
        return False
    if any(len(x) != 32 for x in auth_path):
        return False
    acc = leaf
    idx = leaf_index
    for sib in auth_path:
        if idx & 1:
            acc = merkle_parent(sib, acc)
        else:
            acc = merkle_parent(acc, sib)
        idx //= 2
    return acc == root


def mss_leaf_seed(master_seed: bytes, leaf_index: int) -> bytes:
    return h(b"MSS_LEAF_SEED", master_seed, leaf_index.to_bytes(4, "big"))


@dataclass(frozen=True)
class MerklePublicKey:
    height: int
    root: Hash


@dataclass(frozen=True)
class MerklePrivateKey:
    height: int
    master_seed: bytes


@dataclass(frozen=True)
class MerkleSignature:
    leaf_index: int
    lamport_pk_hash: Hash
    lamport_pk: LamportPublicKey
    lamport_sig: LamportSignature
    auth_path: List[Hash]


def mss_keygen(master_seed: bytes, height: int) -> Tuple[MerklePrivateKey, MerklePublicKey, List[List[Hash]]]:
    """
    Generate an MSS keypair with 2^height Lamport leaves.

    Returns (sk, pk, merkle_levels). Keeping levels is convenient for signing.
    """
    if height < 1 or height > 20:
        raise ValueError("height must be between 1 and 20 for this demo")
    leaf_count = 1 << height
    leaves: List[Hash] = []
    for i in range(leaf_count):
        seed_i = mss_leaf_seed(master_seed, i)
        _, pk_i = lamport_keygen(seed_i)
        leaves.append(lamport_pk_hash(pk_i))
    levels = merkle_build(leaves)
    root = levels[-1][0]
    return MerklePrivateKey(height=height, master_seed=master_seed), MerklePublicKey(height=height, root=root), levels


def mss_sign(sk: MerklePrivateKey, merkle_levels: Sequence[Sequence[Hash]], leaf_index: int, message: bytes) -> MerkleSignature:
    if leaf_index < 0 or leaf_index >= (1 << sk.height):
        raise IndexError("leaf_index out of range")
    if len(merkle_levels[0]) != (1 << sk.height):
        raise ValueError("merkle_levels do not match sk.height")

    seed_i = mss_leaf_seed(sk.master_seed, leaf_index)
    lamport_sk, lamport_pk = lamport_keygen(seed_i)
    lpkh = lamport_pk_hash(lamport_pk)
    if lpkh != merkle_levels[0][leaf_index]:
        raise ValueError("leaf mismatch: lamport_pk_hash does not match Merkle tree")

    ots_sig = lamport_sign(lamport_sk, message)
    path = merkle_auth_path(merkle_levels, leaf_index)
    return MerkleSignature(
        leaf_index=leaf_index,
        lamport_pk_hash=lpkh,
        lamport_pk=lamport_pk,
        lamport_sig=ots_sig,
        auth_path=path,
    )


def mss_verify(pk: MerklePublicKey, message: bytes, sig: MerkleSignature) -> bool:
    if sig.leaf_index < 0 or sig.leaf_index >= (1 << pk.height):
        return False
    if len(sig.auth_path) != pk.height:
        return False
    if sig.lamport_pk_hash != lamport_pk_hash(sig.lamport_pk):
        return False
    if not lamport_verify(sig.lamport_pk, message, sig.lamport_sig):
        return False
    return merkle_verify_path(sig.lamport_pk_hash, sig.leaf_index, sig.auth_path, pk.root)


def mss_signature_fingerprint(sig: MerkleSignature) -> Hash:
    """
    Compact fingerprint for the whole MSS signature object (for tests/logging).
    """
    pk_flat = b"".join(x for pair in sig.lamport_pk for x in pair)
    return h(
        b"MSS_SIG",
        sig.leaf_index.to_bytes(4, "big"),
        sig.lamport_pk_hash,
        pk_flat,
        b"".join(sig.lamport_sig),
        b"".join(sig.auth_path),
    )


def format_hash(x: bytes) -> str:
    return x.hex()


def truncate_hex(hx: str, n: int = 16) -> str:
    if len(hx) <= n:
        return hx
    return hx[:n] + "…"


def _demo_step_1() -> None:
    print("=== Step 1: Lamport OTS ===")
    seed = b"\x00" * 32
    sk, pk = lamport_keygen(seed)
    msg = b"post-quantum: sign once"
    sig = lamport_sign(sk, msg)
    ok = lamport_verify(pk, msg, sig)
    print("message:", msg)
    print("lamport_pk_hash:", truncate_hex(format_hash(lamport_pk_hash(pk))))
    print("verify:", ok)
    print()


def _demo_step_2() -> None:
    print("=== Step 2: Merkle tree of OTS public keys ===")
    master_seed = b"\x11" * 32
    height = 3  # 8 leaves
    _, pk, levels = mss_keygen(master_seed, height)
    print("height:", height)
    print("leaf_count:", 1 << height)
    print("merkle_root:", truncate_hex(format_hash(pk.root)))
    leaf_index = 5
    path = merkle_auth_path(levels, leaf_index)
    ok = merkle_verify_path(levels[0][leaf_index], leaf_index, path, pk.root)
    print("auth_path_len:", len(path))
    print("verify_path:", ok)
    print()


def _demo_step_3() -> None:
    print("=== Step 3: Merkle signature (OTS + auth path) ===")
    master_seed = b"\x22" * 32
    height = 3
    sk, pk, levels = mss_keygen(master_seed, height)
    leaf_index = 2
    msg = b"ship the release"
    msig = mss_sign(sk, levels, leaf_index, msg)
    ok = mss_verify(pk, msg, msig)
    print("leaf_index:", leaf_index)
    print("message:", msg)
    print("merkle_root:", truncate_hex(format_hash(pk.root)))
    print("leaf_hash:", truncate_hex(format_hash(msig.lamport_pk_hash)))
    print("verify:", ok)

    tampered = b"ship the rel3ase"
    ok2 = mss_verify(pk, tampered, msig)
    print("verify(tampered_message):", ok2)
    print()


def _demo_step_4() -> None:
    print("=== Step 4: Why OTS must be one-time ===")
    seed = b"\x33" * 32
    sk, pk = lamport_keygen(seed)
    m1 = b"message one"
    m2 = b"message two"
    s1 = lamport_sign(sk, m1)
    s2 = lamport_sign(sk, m2)
    leaked = sum(1 for a, b in zip(s1, s2) if a != b)
    print("Two signatures with the same Lamport key leak secrets.")
    print("revealed_positions_with_different_secrets:", leaked, "/ 256")
    print("verify(m1):", lamport_verify(pk, m1, s1))
    print("verify(m2):", lamport_verify(pk, m2, s2))
    print()


def main() -> None:
    _demo_step_1()
    _demo_step_2()
    _demo_step_3()
    _demo_step_4()


if __name__ == "__main__":
    main()
