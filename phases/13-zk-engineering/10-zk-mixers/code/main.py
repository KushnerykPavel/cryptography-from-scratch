"""ZK mixers: Tornado-style privacy via commitments + Merkle roots + nullifiers.

This is a stdlib-only, educational model of the *engineering* components behind
Tornado Cash-like mixers:
  - deposits are commitments added to an append-only Merkle tree
  - withdrawals prove membership (without revealing which leaf) and mark a
    nullifier as spent to prevent double spends
  - the withdrawal statement binds the recipient/relayer/fee to prevent proof
    theft in the mempool

This file does NOT implement a real ZK proof system. Our "proof" includes the
Merkle path and leaf index, so it is not private. The point is to make the data
flow and invariants runnable.

Run:
  python3 code/main.py
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import random
from typing import Dict, Iterable, List, Sequence, Tuple


def u32be(n: int) -> bytes:
    if not isinstance(n, int):
        raise TypeError("u32be expects int")
    if n < 0 or n >= 2**32:
        raise ValueError("u32 out of range")
    return int(n).to_bytes(4, "big")


def sha256(data: bytes) -> bytes:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("sha256 expects bytes")
    return hashlib.sha256(data).digest()


def tagged_hash(tag: str, *parts: bytes) -> bytes:
    if not isinstance(tag, str) or tag == "":
        raise ValueError("tag must be a non-empty string")
    h = hashlib.sha256()
    h.update(tag.encode("utf-8"))
    h.update(b"\x00")
    for p in parts:
        if not isinstance(p, (bytes, bytearray)):
            raise TypeError("tagged_hash parts must be bytes")
        b = bytes(p)
        h.update(u32be(len(b)))
        h.update(b)
    return h.digest()


def pseudo_random_bytes(seed: int, n: int) -> bytes:
    if not isinstance(seed, int):
        raise TypeError("seed must be int")
    if not isinstance(n, int) or n < 0:
        raise ValueError("n must be a non-negative int")
    rng = random.Random(seed)
    return bytes(rng.randrange(0, 256) for _ in range(n))


NOTE_PREFIX = "mixer-v1"
NOTE_PART_LEN = 32  # bytes (256-bit secrets / nullifiers)


def format_note(secret: bytes, nullifier: bytes) -> str:
    if not isinstance(secret, (bytes, bytearray)) or not isinstance(nullifier, (bytes, bytearray)):
        raise TypeError("secret and nullifier must be bytes")
    secret_b = bytes(secret)
    nullifier_b = bytes(nullifier)
    if len(secret_b) != NOTE_PART_LEN or len(nullifier_b) != NOTE_PART_LEN:
        raise ValueError(f"secret/nullifier must be {NOTE_PART_LEN} bytes")
    return f"{NOTE_PREFIX}:{secret_b.hex()}:{nullifier_b.hex()}"


def parse_note(note: str) -> Tuple[bytes, bytes]:
    if not isinstance(note, str):
        raise TypeError("note must be str")
    parts = note.split(":")
    if len(parts) != 3 or parts[0] != NOTE_PREFIX:
        raise ValueError("invalid note prefix/format")
    secret_hex, nullifier_hex = parts[1], parts[2]
    try:
        secret = bytes.fromhex(secret_hex)
        nullifier = bytes.fromhex(nullifier_hex)
    except Exception as e:
        raise ValueError("note hex decode failed") from e
    if len(secret) != NOTE_PART_LEN or len(nullifier) != NOTE_PART_LEN:
        raise ValueError("invalid note component length")
    return secret, nullifier


def commitment(secret: bytes, nullifier: bytes) -> bytes:
    if not isinstance(secret, (bytes, bytearray)) or not isinstance(nullifier, (bytes, bytearray)):
        raise TypeError("secret and nullifier must be bytes")
    secret_b = bytes(secret)
    nullifier_b = bytes(nullifier)
    if len(secret_b) != NOTE_PART_LEN or len(nullifier_b) != NOTE_PART_LEN:
        raise ValueError(f"secret/nullifier must be {NOTE_PART_LEN} bytes")
    return tagged_hash("mixer.commitment.v1", secret_b, nullifier_b)


def nullifier_hash(nullifier: bytes) -> bytes:
    if not isinstance(nullifier, (bytes, bytearray)):
        raise TypeError("nullifier must be bytes")
    nullifier_b = bytes(nullifier)
    if len(nullifier_b) != NOTE_PART_LEN:
        raise ValueError(f"nullifier must be {NOTE_PART_LEN} bytes")
    return tagged_hash("mixer.nullifier.v1", nullifier_b)


def merkle_leaf_hash(leaf: bytes) -> bytes:
    if not isinstance(leaf, (bytes, bytearray)):
        raise TypeError("leaf must be bytes")
    return sha256(b"\x00" + bytes(leaf))


def merkle_node_hash(left: bytes, right: bytes) -> bytes:
    if not isinstance(left, (bytes, bytearray)) or not isinstance(right, (bytes, bytearray)):
        raise TypeError("node children must be bytes")
    return sha256(b"\x01" + bytes(left) + bytes(right))


def merkle_root(leaves: Sequence[bytes]) -> bytes:
    if not isinstance(leaves, (list, tuple)):
        raise TypeError("leaves must be a list/tuple of bytes")
    if len(leaves) == 0:
        return sha256(b"")

    level = [merkle_leaf_hash(leaf) for leaf in leaves]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level = level + [level[-1]]
        nxt = []
        for i in range(0, len(level), 2):
            nxt.append(merkle_node_hash(level[i], level[i + 1]))
        level = nxt
    return level[0]


MerklePathElem = Tuple[str, bytes]  # ("L" or "R", sibling_hash)


def merkle_inclusion_proof(leaves: Sequence[bytes], index: int) -> List[MerklePathElem]:
    if not isinstance(index, int):
        raise TypeError("index must be int")
    if index < 0 or index >= len(leaves):
        raise IndexError("leaf index out of range")

    level = [merkle_leaf_hash(leaf) for leaf in leaves]
    idx = index
    proof: List[MerklePathElem] = []
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


def verify_merkle_inclusion(leaf: bytes, index: int, proof: Sequence[MerklePathElem], expected_root: bytes) -> bool:
    if not isinstance(index, int) or index < 0:
        return False
    if not isinstance(expected_root, (bytes, bytearray)):
        return False
    h = merkle_leaf_hash(leaf)
    idx = index
    for side, sib in proof:
        if side == "L":
            h = merkle_node_hash(sib, h)
        elif side == "R":
            h = merkle_node_hash(h, sib)
        else:
            return False
        idx //= 2
    return h == bytes(expected_root)


def address_bytes(addr: str) -> bytes:
    if not isinstance(addr, str):
        raise TypeError("address must be str")
    if not addr.startswith("0x"):
        raise ValueError("address must start with 0x")
    hx = addr[2:]
    if len(hx) != 40:
        raise ValueError("address must be 20 bytes hex (40 nybbles)")
    try:
        b = bytes.fromhex(hx)
    except Exception as e:
        raise ValueError("address hex decode failed") from e
    if len(b) != 20:
        raise ValueError("address must decode to 20 bytes")
    return b


def parse_amount_wei(value: str) -> int:
    if not isinstance(value, str):
        raise TypeError("value must be str")
    if value == "" or any(c not in "0123456789" for c in value):
        raise ValueError("amount must be a base-10 non-negative integer string")
    n = int(value, 10)
    if n < 0:
        raise ValueError("amount must be non-negative")
    return n


@dataclass(frozen=True)
class WithdrawalStatement:
    root_hex: str
    nullifier_hash_hex: str
    recipient: str
    relayer: str
    fee_wei: int


@dataclass(frozen=True)
class WithdrawalProof:
    statement: WithdrawalStatement
    leaf_index: int
    merkle_path: List[Dict[str, str]]  # [{"side": "L|R", "hash_hex": "..."}]
    proof_digest_hex: str


def withdrawal_digest(statement: WithdrawalStatement) -> str:
    root = bytes.fromhex(statement.root_hex)
    nf = bytes.fromhex(statement.nullifier_hash_hex)
    recipient_b = address_bytes(statement.recipient)
    relayer_b = address_bytes(statement.relayer)
    fee_b = int(statement.fee_wei).to_bytes(32, "big")
    return tagged_hash("mixer.withdraw_statement.v1", root, nf, recipient_b, relayer_b, fee_b).hex()


def prove_withdrawal(
    leaves: Sequence[bytes],
    secret: bytes,
    nullifier: bytes,
    leaf_index: int,
    recipient: str,
    relayer: str,
    fee_wei: int,
) -> WithdrawalProof:
    com = commitment(secret, nullifier)
    if leaf_index < 0 or leaf_index >= len(leaves):
        raise IndexError("leaf_index out of range")
    if leaves[leaf_index] != com:
        raise ValueError("leaf at index does not match commitment(secret,nullifier)")

    root_hex = merkle_root(leaves).hex()
    statement = WithdrawalStatement(
        root_hex=root_hex,
        nullifier_hash_hex=nullifier_hash(nullifier).hex(),
        recipient=recipient,
        relayer=relayer,
        fee_wei=int(fee_wei),
    )
    proof_digest_hex = withdrawal_digest(statement)
    path = merkle_inclusion_proof(leaves, leaf_index)
    path_json = [{"side": side, "hash_hex": sib.hex()} for side, sib in path]
    return WithdrawalProof(
        statement=statement,
        leaf_index=leaf_index,
        merkle_path=path_json,
        proof_digest_hex=proof_digest_hex,
    )


def verify_withdrawal(leaves: Sequence[bytes], proof: WithdrawalProof) -> bool:
    if not isinstance(proof, WithdrawalProof):
        return False
    st = proof.statement
    try:
        digest = withdrawal_digest(st)
    except Exception:
        return False
    if digest != proof.proof_digest_hex:
        return False
    try:
        root = bytes.fromhex(st.root_hex)
        nf = bytes.fromhex(st.nullifier_hash_hex)
    except Exception:
        return False
    if len(root) != 32 or len(nf) != 32:
        return False
    expected_root = merkle_root(leaves)
    if expected_root.hex() != st.root_hex:
        return False
    path: List[MerklePathElem] = []
    for el in proof.merkle_path:
        if not isinstance(el, dict):
            return False
        side = el.get("side")
        hh = el.get("hash_hex")
        if side not in ("L", "R") or not isinstance(hh, str):
            return False
        try:
            sib = bytes.fromhex(hh)
        except Exception:
            return False
        if len(sib) != 32:
            return False
        path.append((side, sib))
    if proof.leaf_index < 0 or proof.leaf_index >= len(leaves):
        return False
    leaf = leaves[proof.leaf_index]
    if not verify_merkle_inclusion(leaf, proof.leaf_index, path, root):
        return False
    return True


class Mixer:
    def __init__(self):
        self._leaves: List[bytes] = []
        self._spent_nullifiers: set[bytes] = set()

    @property
    def leaves(self) -> List[bytes]:
        return list(self._leaves)

    def root_hex(self) -> str:
        return merkle_root(self._leaves).hex()

    def deposit(self, com: bytes) -> int:
        if not isinstance(com, (bytes, bytearray)) or len(bytes(com)) != 32:
            raise ValueError("commitment must be 32 bytes")
        self._leaves.append(bytes(com))
        return len(self._leaves) - 1

    def is_spent(self, nf_hash: bytes) -> bool:
        return bytes(nf_hash) in self._spent_nullifiers

    def mark_spent(self, nf_hash: bytes) -> None:
        self._spent_nullifiers.add(bytes(nf_hash))

    def withdraw(self, proof: WithdrawalProof) -> Dict[str, object]:
        if not verify_withdrawal(self._leaves, proof):
            raise ValueError("invalid withdrawal proof")
        nf = bytes.fromhex(proof.statement.nullifier_hash_hex)
        if self.is_spent(nf):
            raise ValueError("nullifier already spent (double spend)")
        self.mark_spent(nf)
        return {
            "recipient": proof.statement.recipient,
            "relayer": proof.statement.relayer,
            "fee_wei": proof.statement.fee_wei,
            "root_hex": proof.statement.root_hex,
            "nullifier_hash_hex": proof.statement.nullifier_hash_hex,
            "proof_digest_hex": proof.proof_digest_hex,
        }


def _pp(obj: object) -> str:
    return json.dumps(obj, sort_keys=True, indent=2)


def main() -> None:
    print("=== Step 1: Notes, commitments, nullifiers ===")
    secret = pseudo_random_bytes(seed=1337, n=NOTE_PART_LEN)
    null = pseudo_random_bytes(seed=7331, n=NOTE_PART_LEN)
    note = format_note(secret, null)
    com = commitment(secret, null)
    nf = nullifier_hash(null)
    print("note:", note[:32] + "...")  # don't spam the terminal with 128 hex chars
    print("commitment_hex:", com.hex())
    print("nullifier_hash_hex:", nf.hex())

    print("\n=== Step 2: Merkle tree of deposits ===")
    mixer = Mixer()
    leaves = []
    for i, seed in enumerate([1, 2, 3, 4]):
        s = pseudo_random_bytes(seed=1000 + seed, n=NOTE_PART_LEN)
        n = pseudo_random_bytes(seed=2000 + seed, n=NOTE_PART_LEN)
        leaves.append(commitment(s, n))
        idx = mixer.deposit(leaves[-1])
        print(f"deposit index={idx} commitment={leaves[-1].hex()[:16]}... root={mixer.root_hex()[:16]}...")
    root_hex = mixer.root_hex()
    print("current root:", root_hex)
    proof_path = merkle_inclusion_proof(leaves, 2)
    ok = verify_merkle_inclusion(leaves[2], 2, proof_path, merkle_root(leaves))
    print("inclusion proof for index 2 verifies:", ok)

    print("\n=== Step 3: Withdrawals (membership + nullifier) ===")
    recipient = "0x1111111111111111111111111111111111111111"
    relayer = "0x2222222222222222222222222222222222222222"
    fee = 10_000_000_000_000_000  # 0.01 ETH in wei, as an example
    s2 = pseudo_random_bytes(seed=1000 + 3, n=NOTE_PART_LEN)
    n2 = pseudo_random_bytes(seed=2000 + 3, n=NOTE_PART_LEN)
    withdraw_proof = prove_withdrawal(leaves=mixer.leaves, secret=s2, nullifier=n2, leaf_index=2, recipient=recipient, relayer=relayer, fee_wei=fee)
    receipt = mixer.withdraw(withdraw_proof)
    print("withdraw receipt:", _pp(receipt))

    print("\n=== Step 4: What ZK hides (our proof leaks the leaf) ===")
    print("proof.leaf_index:", withdraw_proof.leaf_index)
    print("proof.merkle_path_len:", len(withdraw_proof.merkle_path))
    print("In a real SNARK/PLONK proof, leaf_index and merkle_path stay private witness.")

    print("\n=== Step 5: Proof theft prevention (bind recipient/relayer/fee) ===")
    stolen = WithdrawalProof(
        statement=WithdrawalStatement(
            root_hex=withdraw_proof.statement.root_hex,
            nullifier_hash_hex=withdraw_proof.statement.nullifier_hash_hex,
            recipient="0x9999999999999999999999999999999999999999",
            relayer=withdraw_proof.statement.relayer,
            fee_wei=withdraw_proof.statement.fee_wei,
        ),
        leaf_index=withdraw_proof.leaf_index,
        merkle_path=withdraw_proof.merkle_path,
        proof_digest_hex=withdraw_proof.proof_digest_hex,
    )
    print("verify original proof:", verify_withdrawal(mixer.leaves, withdraw_proof))
    print("verify stolen-with-recipient-changed:", verify_withdrawal(mixer.leaves, stolen))
    print("Attempting to withdraw again (double spend) should fail:")
    try:
        mixer.withdraw(withdraw_proof)
    except Exception as e:
        print("double spend rejected:", str(e))


if __name__ == "__main__":
    main()
