"""
Sparse Merkle Trees and a toy Verkle-style tree.

This script implements:
- A binary Sparse Merkle Tree (SMT) with inclusion + non-inclusion proofs.
- A toy "vector commitment" using an RSA-accumulator-style construction.
- A toy Verkle-style tree that replaces Merkle sibling lists with per-node openings.

Run:
  python3 code/main.py
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def h_leaf(value: bytes) -> bytes:
    return sha256(b"L" + len(value).to_bytes(4, "big") + value)


def h_node(left: bytes, right: bytes) -> bytes:
    return sha256(b"N" + left + right)


def default_hashes(bit_length: int) -> List[bytes]:
    if bit_length < 1:
        raise ValueError("bit_length must be >= 1")

    defaults = [h_leaf(b"")]
    for _ in range(bit_length):
        defaults.append(h_node(defaults[-1], defaults[-1]))
    return defaults


def key_to_leaf_index(key: bytes, bit_length: int) -> int:
    if bit_length < 1 or bit_length > 256:
        raise ValueError("bit_length must be in [1, 256]")
    digest = sha256(b"K" + key)
    value = int.from_bytes(digest, "big")
    return value >> (256 - bit_length)


@dataclass(frozen=True)
class SparseMerkleProof:
    bit_length: int
    leaf_index: int
    siblings: Tuple[bytes, ...]

    def size_bytes(self) -> int:
        return sum(len(s) for s in self.siblings)


class SparseMerkleTree:
    def __init__(self, bit_length: int):
        self.bit_length = bit_length
        self._defaults = default_hashes(bit_length)
        self._nodes: Dict[Tuple[int, int], bytes] = {}

    def _get(self, level: int, index: int) -> bytes:
        value = self._nodes.get((level, index))
        if value is None:
            return self._defaults[level]
        return value

    def _set(self, level: int, index: int, value: bytes) -> None:
        if value == self._defaults[level]:
            self._nodes.pop((level, index), None)
            return
        self._nodes[(level, index)] = value

    def root(self) -> bytes:
        return self._get(self.bit_length, 0)

    def non_default_node_count(self) -> int:
        return len(self._nodes)

    def update(self, key: bytes, value: Optional[bytes]) -> None:
        if value is not None and len(value) == 0:
            raise ValueError("empty values are reserved for 'absent'")

        leaf_index = key_to_leaf_index(key, self.bit_length)
        current_hash = self._defaults[0] if value is None else h_leaf(value)
        idx = leaf_index

        self._set(0, idx, current_hash)

        for level in range(1, self.bit_length + 1):
            sibling_idx = idx ^ 1
            sibling_hash = self._get(level - 1, sibling_idx)
            if (idx & 1) == 0:
                parent_hash = h_node(current_hash, sibling_hash)
            else:
                parent_hash = h_node(sibling_hash, current_hash)

            idx >>= 1
            current_hash = parent_hash
            self._set(level, idx, parent_hash)

    def prove(self, key: bytes) -> SparseMerkleProof:
        leaf_index = key_to_leaf_index(key, self.bit_length)
        siblings: List[bytes] = []
        idx = leaf_index
        for level in range(0, self.bit_length):
            siblings.append(self._get(level, idx ^ 1))
            idx >>= 1
        return SparseMerkleProof(
            bit_length=self.bit_length,
            leaf_index=leaf_index,
            siblings=tuple(siblings),
        )


def smt_verify(
    root: bytes,
    key: bytes,
    value: Optional[bytes],
    proof: SparseMerkleProof,
) -> bool:
    if proof.bit_length < 1 or len(proof.siblings) != proof.bit_length:
        return False

    if value is not None and len(value) == 0:
        return False

    idx = key_to_leaf_index(key, proof.bit_length)
    if idx != proof.leaf_index:
        return False

    current_hash = h_leaf(b"") if value is None else h_leaf(value)

    for sibling_hash in proof.siblings:
        if (idx & 1) == 0:
            current_hash = h_node(current_hash, sibling_hash)
        else:
            current_hash = h_node(sibling_hash, current_hash)
        idx >>= 1

    return current_hash == root


def _miller_rabin_witness(a: int, s: int, d: int, n: int) -> bool:
    x = pow(a, d, n)
    if x == 1 or x == n - 1:
        return False
    for _ in range(s - 1):
        x = (x * x) % n
        if x == n - 1:
            return False
    return True


def is_prime_64(n: int) -> bool:
    if n < 2:
        return False
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    if n in small_primes:
        return True
    for p in small_primes:
        if n % p == 0:
            return False

    d = n - 1
    s = 0
    while (d & 1) == 0:
        s += 1
        d >>= 1

    for a in small_primes:
        if a % n == 0:
            continue
        if _miller_rabin_witness(a, s, d, n):
            return False
    return True


def hash_to_prime_64(data: bytes, bits: int = 61) -> int:
    if bits < 16 or bits > 63:
        raise ValueError("bits must be in [16, 63]")

    mask = (1 << bits) - 1
    x = int.from_bytes(sha256(b"P" + data), "big") & mask
    x |= 1
    x |= 1 << (bits - 1)

    while not is_prime_64(x):
        x += 2
        x &= mask
        x |= 1
        x |= 1 << (bits - 1)
    return x


def int_to_bytes(x: int, length: int) -> bytes:
    if x < 0:
        raise ValueError("x must be non-negative")
    return x.to_bytes(length, "big")


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


@dataclass(frozen=True)
class RSAParams:
    n: int
    g: int

    @property
    def byte_len(self) -> int:
        return (self.n.bit_length() + 7) // 8


def rsa_params_for_demo() -> RSAParams:
    p = hash_to_prime_64(b"rsa-p", bits=61)
    q = hash_to_prime_64(b"rsa-q", bits=61)
    n = p * q
    g = 5
    if math.gcd(g, n) != 1:
        g = 7
    return RSAParams(n=n, g=g)


def vc_element_prime(index: int, value: bytes) -> int:
    if index < 0 or index > 0xFFFF:
        raise ValueError("index out of range for demo encoding")
    payload = b"E" + index.to_bytes(2, "big") + len(value).to_bytes(2, "big") + value
    return hash_to_prime_64(payload, bits=61)


def vc_commit(params: RSAParams, values: Sequence[bytes]) -> int:
    exp = 1
    for i, v in enumerate(values):
        exp *= vc_element_prime(i, v)
    return pow(params.g, exp, params.n)


def vc_open(params: RSAParams, values: Sequence[bytes], index: int) -> Tuple[bytes, int]:
    if index < 0 or index >= len(values):
        raise ValueError("index out of range")
    exp = 1
    for i, v in enumerate(values):
        if i == index:
            continue
        exp *= vc_element_prime(i, v)
    witness = pow(params.g, exp, params.n)
    return values[index], witness


def vc_verify(params: RSAParams, commitment: int, index: int, value: bytes, witness: int) -> bool:
    p_i = vc_element_prime(index, value)
    return pow(witness, p_i, params.n) == (commitment % params.n)


def _is_power_of_two(x: int) -> bool:
    return x > 0 and (x & (x - 1)) == 0


def key_to_base_w_path(key: bytes, width: int, depth: int) -> List[int]:
    if not _is_power_of_two(width):
        raise ValueError("width must be a power of two")
    bits_per_digit = int(math.log2(width))
    total_bits = bits_per_digit * depth
    if total_bits > 256:
        raise ValueError("depth * log2(width) must be <= 256 for this demo")
    digest = sha256(b"V" + key)
    v = int.from_bytes(digest, "big") >> (256 - total_bits)
    digits: List[int] = []
    for i in range(depth):
        shift = (depth - 1 - i) * bits_per_digit
        digits.append((v >> shift) & (width - 1))
    return digits


def leaf_value_hash(value: bytes) -> bytes:
    return sha256(b"val" + len(value).to_bytes(4, "big") + value)


@dataclass(frozen=True)
class ToyVerkleProof:
    width: int
    depth: int
    indices: Tuple[int, ...]
    values: Tuple[bytes, ...]
    witnesses: Tuple[int, ...]

    def size_bytes(self, params: RSAParams) -> int:
        return sum(len(v) for v in self.values) + len(self.witnesses) * params.byte_len


class ToyVerkleTree:
    def __init__(self, width: int, depth: int, params: RSAParams):
        if width < 2 or not _is_power_of_two(width):
            raise ValueError("width must be a power of two and >= 2")
        if depth < 1:
            raise ValueError("depth must be >= 1")
        self.width = width
        self.depth = depth
        self.params = params
        self._nodes: Dict[Tuple[int, Tuple[int, ...]], Tuple[bytes, ...]] = {}
        self._default_commitments: List[int] = self._compute_default_commitments()

    def _compute_default_commitments(self) -> List[int]:
        commit_bytes_len = self.params.byte_len
        zeros = b"\x00" * 32

        defaults: List[int] = [0 for _ in range(self.depth)]
        values = [zeros for _ in range(self.width)]
        defaults[self.depth - 1] = vc_commit(self.params, values)

        for level in range(self.depth - 2, -1, -1):
            child_value = int_to_bytes(defaults[level + 1], commit_bytes_len)
            values = [child_value for _ in range(self.width)]
            defaults[level] = vc_commit(self.params, values)
        return defaults

    def root_commitment(self) -> int:
        return self._default_commitments[0] if not self._nodes else self._node_commitment(0, ())

    def _default_child_value(self, level: int) -> bytes:
        if level == self.depth - 1:
            return b"\x00" * 32
        return int_to_bytes(self._default_commitments[level + 1], self.params.byte_len)

    def _node_values(self, level: int, prefix: Tuple[int, ...]) -> Tuple[bytes, ...]:
        current = self._nodes.get((level, prefix))
        if current is not None:
            return current
        default_child = self._default_child_value(level)
        return tuple(default_child for _ in range(self.width))

    def _store_node_values(self, level: int, prefix: Tuple[int, ...], values: Sequence[bytes]) -> None:
        default_child = self._default_child_value(level)
        if all(v == default_child for v in values):
            self._nodes.pop((level, prefix), None)
        else:
            self._nodes[(level, prefix)] = tuple(values)

    def _node_commitment(self, level: int, prefix: Tuple[int, ...]) -> int:
        values = self._node_values(level, prefix)
        if level < self.depth - 1:
            return vc_commit(self.params, values)
        return vc_commit(self.params, values)

    def update(self, key: bytes, value: Optional[bytes]) -> None:
        if value is not None and len(value) == 0:
            raise ValueError("empty values are reserved for 'absent'")

        path = key_to_base_w_path(key, self.width, self.depth)
        leaf_bytes = b"\x00" * 32 if value is None else leaf_value_hash(value)

        prefix: Tuple[int, ...] = tuple(path[:-1])
        level = self.depth - 1
        node_values = list(self._node_values(level, prefix))
        node_values[path[-1]] = leaf_bytes
        self._store_node_values(level, prefix, node_values)

        commit = vc_commit(self.params, node_values)
        for level in range(self.depth - 2, -1, -1):
            parent_prefix = tuple(path[:level])
            parent_values = list(self._node_values(level, parent_prefix))
            parent_values[path[level]] = int_to_bytes(commit, self.params.byte_len)
            self._store_node_values(level, parent_prefix, parent_values)
            commit = vc_commit(self.params, parent_values)

    def prove(self, key: bytes) -> ToyVerkleProof:
        path = key_to_base_w_path(key, self.width, self.depth)
        indices: List[int] = []
        values: List[bytes] = []
        witnesses: List[int] = []

        prefix: Tuple[int, ...] = ()
        commit = self._node_commitment(0, prefix)
        for level in range(0, self.depth):
            idx = path[level]
            node_values = self._node_values(level, prefix)
            value_bytes, witness = vc_open(self.params, node_values, idx)
            indices.append(idx)
            values.append(value_bytes)
            witnesses.append(witness)
            prefix = tuple(path[: level + 1])
            if level < self.depth - 1:
                commit = bytes_to_int(value_bytes)

        return ToyVerkleProof(
            width=self.width,
            depth=self.depth,
            indices=tuple(indices),
            values=tuple(values),
            witnesses=tuple(witnesses),
        )


def toy_verkle_verify(
    params: RSAParams,
    root_commitment: int,
    key: bytes,
    expected_value: Optional[bytes],
    proof: ToyVerkleProof,
) -> bool:
    if proof.depth < 1 or proof.width < 2:
        return False
    if len(proof.indices) != proof.depth:
        return False
    if len(proof.values) != proof.depth:
        return False
    if len(proof.witnesses) != proof.depth:
        return False
    if expected_value is not None and len(expected_value) == 0:
        return False

    path = key_to_base_w_path(key, proof.width, proof.depth)

    commit = root_commitment % params.n
    for level in range(proof.depth):
        idx = proof.indices[level]
        if idx != path[level]:
            return False
        if not vc_verify(params, commit, idx, proof.values[level], proof.witnesses[level]):
            return False
        if level < proof.depth - 1:
            commit = bytes_to_int(proof.values[level]) % params.n

    leaf_expected = b"\x00" * 32 if expected_value is None else leaf_value_hash(expected_value)
    return proof.values[-1] == leaf_expected


def _hex(b: bytes) -> str:
    return b.hex()


def _print_step(title: str) -> None:
    print(f"=== {title} ===")


def step_1_defaults_and_domain_separation() -> None:
    _print_step("Step 1: Empty hashes and domain separation")
    d = 8
    defaults = default_hashes(d)
    print("bit_length:", d)
    print("default leaf:", _hex(defaults[0])[:16] + "…")
    print("default root:", _hex(defaults[-1])[:16] + "…")


def step_2_sparse_merkle_tree_proofs() -> None:
    _print_step("Step 2: Sparse Merkle tree updates + proofs")
    bit_length = 16
    smt = SparseMerkleTree(bit_length)
    print("empty root:", _hex(smt.root())[:16] + "…")

    k1 = b"alice"
    v1 = b"100"
    k2 = b"bob"
    v2 = b"250"
    smt.update(k1, v1)
    smt.update(k2, v2)
    root = smt.root()
    print("root after 2 inserts:", _hex(root)[:16] + "…")
    print("stored non-default nodes:", smt.non_default_node_count())

    proof_k1 = smt.prove(k1)
    ok = smt_verify(root, k1, v1, proof_k1)
    print("inclusion proof verifies:", ok, "| proof bytes:", proof_k1.size_bytes())

    proof_missing = smt.prove(b"carol")
    ok2 = smt_verify(root, b"carol", None, proof_missing)
    print("non-inclusion proof verifies:", ok2, "| proof bytes:", proof_missing.size_bytes())


def step_3_vector_commitment_demo() -> None:
    _print_step("Step 3: Toy vector commitment (RSA accumulator style)")
    params = rsa_params_for_demo()
    values = [b"A", b"B", b"C", b"D"]
    c = vc_commit(params, values)
    v, w = vc_open(params, values, 2)
    ok = vc_verify(params, c, 2, v, w)
    print("commitment:", hex(c))
    print("open index 2:", v, "| witness bytes:", params.byte_len)
    print("verifies:", ok)


def step_4_toy_verkle_tree() -> None:
    _print_step("Step 4: Toy Verkle-style tree (openings, no siblings)")
    params = rsa_params_for_demo()
    width = 16
    depth = 4
    tree = ToyVerkleTree(width=width, depth=depth, params=params)
    empty_root = tree.root_commitment()
    print("empty root commitment:", hex(empty_root))

    key = b"alice"
    value = b"100"
    tree.update(key, value)
    root = tree.root_commitment()
    proof = tree.prove(key)
    ok = toy_verkle_verify(params, root, key, value, proof)
    print("root after insert:", hex(root))
    print("proof verifies:", ok)

    smt = SparseMerkleTree(bit_length=16)
    smt.update(key, value)
    smt_proof = smt.prove(key)
    print("SMT proof bytes (sha256 siblings):", smt_proof.size_bytes())
    print("Toy Verkle proof bytes (witnesses + values):", proof.size_bytes(params))


def main() -> None:
    step_1_defaults_and_domain_separation()
    step_2_sparse_merkle_tree_proofs()
    step_3_vector_commitment_demo()
    step_4_toy_verkle_tree()


if __name__ == "__main__":
    main()
