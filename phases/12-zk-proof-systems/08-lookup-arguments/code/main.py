"""
Toy lookup arguments (Plookup/Halo2-style intuition) in pure Python.

This script demonstrates the core *idea* behind lookup arguments:
prove that some witness values come from an allowed table, without
encoding a giant pile of boolean constraints.

Run:
  python3 code/main.py
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Iterable, Sequence


MODULUS = 2**61 - 1  # a convenient Mersenne prime for toy finite-field arithmetic


def inv_mod(a: int, p: int = MODULUS) -> int:
    a %= p
    if a == 0:
        raise ZeroDivisionError("inverse of 0 does not exist")
    return pow(a, p - 2, p)


def _u64be(x: int) -> bytes:
    if x < 0:
        raise ValueError("expected non-negative int")
    return x.to_bytes(8, "big", signed=False)


def _hash256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _hash_list(label: str, xs: Sequence[int]) -> bytes:
    h = hashlib.sha256()
    h.update(b"list-v1\x00")
    h.update(label.encode("utf-8"))
    h.update(b"\x00")
    h.update(_u64be(len(xs)))
    for x in xs:
        h.update(_u64be(x % MODULUS))
    return h.digest()


def _hash_rows(label: str, rows: Sequence[Sequence[int]]) -> bytes:
    h = hashlib.sha256()
    h.update(b"rows-v1\x00")
    h.update(label.encode("utf-8"))
    h.update(b"\x00")
    h.update(_u64be(len(rows)))
    for row in rows:
        h.update(_u64be(len(row)))
        for v in row:
            h.update(_u64be(v % MODULUS))
    return h.digest()


class Transcript:
    def __init__(self, label: str):
        self._state = _hash256(b"transcript-v1\x00" + label.encode("utf-8"))

    def append(self, label: str, data: bytes) -> None:
        self._state = _hash256(self._state + b"\x00" + label.encode("utf-8") + b"\x00" + data)

    def challenge(self, label: str, p: int = MODULUS) -> int:
        out = _hash256(self._state + b"\x00" + label.encode("utf-8"))
        c = int.from_bytes(out, "big") % p
        self.append(f"challenge:{label}", out)
        return c


def poly_product_at(roots: Sequence[int], x: int, p: int = MODULUS) -> int:
    acc = 1 % p
    x %= p
    for r in roots:
        acc = (acc * ((x - (r % p)) % p)) % p
    return acc


def multiset_difference(table: Sequence[int], witness: Sequence[int]) -> list[int]:
    """
    Returns a multiset difference table - witness as a sorted list.

    Raises ValueError if witness is not a multiset subset of table.
    """
    counts: dict[int, int] = {}
    for t in table:
        counts[t] = counts.get(t, 0) + 1

    for w in witness:
        c = counts.get(w, 0)
        if c <= 0:
            raise ValueError(f"witness value not in table (or too many copies): {w}")
        if c == 1:
            del counts[w]
        else:
            counts[w] = c - 1

    remainder: list[int] = []
    for v, c in counts.items():
        remainder.extend([v] * c)
    remainder.sort()
    return remainder


def compress_row(row: Sequence[int], theta: int, p: int = MODULUS) -> int:
    """
    Compresses a multi-column row into one field element:
      row[0] + theta*row[1] + theta^2*row[2] + ...
    """
    theta %= p
    acc = 0
    power = 1
    for v in row:
        acc = (acc + (v % p) * power) % p
        power = (power * theta) % p
    return acc


def compress_rows(rows: Sequence[Sequence[int]], theta: int, p: int = MODULUS) -> list[int]:
    return [compress_row(r, theta=theta, p=p) for r in rows]


@dataclass(frozen=True)
class ToyLookupProof:
    """
    A *non-ZK* proof object:
    - we include witness and remainder directly (so verification is meaningful without commitments)
    - we still mimic the Fiat–Shamir flow and the “check at a random point” product test
    """

    witness: tuple[int, ...]
    remainder: tuple[int, ...]
    r: int
    eval_witness: int
    eval_remainder: int
    commit_witness: str
    commit_remainder: str

    def to_json(self) -> dict:
        return {
            "witness": list(self.witness),
            "remainder": list(self.remainder),
            "r": self.r,
            "eval_witness": self.eval_witness,
            "eval_remainder": self.eval_remainder,
            "commit_witness": self.commit_witness,
            "commit_remainder": self.commit_remainder,
        }

    @staticmethod
    def from_json(obj: dict) -> "ToyLookupProof":
        return ToyLookupProof(
            witness=tuple(obj["witness"]),
            remainder=tuple(obj["remainder"]),
            r=int(obj["r"]),
            eval_witness=int(obj["eval_witness"]),
            eval_remainder=int(obj["eval_remainder"]),
            commit_witness=str(obj["commit_witness"]),
            commit_remainder=str(obj["commit_remainder"]),
        )


def prove_lookup_membership(
    *,
    table: Sequence[int],
    witness: Sequence[int],
    p: int = MODULUS,
    label: str = "toy-lookup-v1",
) -> ToyLookupProof:
    remainder = multiset_difference(table, witness)

    cw = _hash_list("witness", list(witness)).hex()
    cr = _hash_list("remainder", remainder).hex()
    ct = _hash_list("table", list(table)).hex()

    tr = Transcript(label)
    tr.append("commit_table", bytes.fromhex(ct))
    tr.append("commit_witness", bytes.fromhex(cw))
    tr.append("commit_remainder", bytes.fromhex(cr))
    r = tr.challenge("r", p=p)

    eval_w = poly_product_at(witness, r, p=p)
    eval_r = poly_product_at(remainder, r, p=p)

    return ToyLookupProof(
        witness=tuple(witness),
        remainder=tuple(remainder),
        r=r,
        eval_witness=eval_w,
        eval_remainder=eval_r,
        commit_witness=cw,
        commit_remainder=cr,
    )


def verify_lookup_membership(
    *,
    table: Sequence[int],
    proof: ToyLookupProof,
    p: int = MODULUS,
    label: str = "toy-lookup-v1",
) -> bool:
    try:
        if _hash_list("witness", list(proof.witness)).hex() != proof.commit_witness:
            return False
        if _hash_list("remainder", list(proof.remainder)).hex() != proof.commit_remainder:
            return False

        ct = _hash_list("table", list(table)).hex()
        tr = Transcript(label)
        tr.append("commit_table", bytes.fromhex(ct))
        tr.append("commit_witness", bytes.fromhex(proof.commit_witness))
        tr.append("commit_remainder", bytes.fromhex(proof.commit_remainder))
        r = tr.challenge("r", p=p)
        if r != proof.r % p:
            return False

        eval_w = poly_product_at(proof.witness, r, p=p)
        eval_r = poly_product_at(proof.remainder, r, p=p)
        if eval_w != proof.eval_witness % p:
            return False
        if eval_r != proof.eval_remainder % p:
            return False

        eval_t = poly_product_at(table, r, p=p)
        return (eval_w * eval_r) % p == eval_t
    except Exception:
        return False


def _print_table(rows: Sequence[Sequence[int]], headers: Sequence[str]) -> None:
    widths = [len(h) for h in headers]
    for r in rows:
        for i, v in enumerate(r):
            widths[i] = max(widths[i], len(str(v)))
    fmt = " | ".join("{:>" + str(w) + "}" for w in widths)
    print(fmt.format(*headers))
    print("-+-".join("-" * w for w in widths))
    for r in rows:
        print(fmt.format(*[str(v) for v in r]))


def main() -> None:
    print("=== Step 1: Field + transcript helpers ===")
    a = 7
    inv_a = inv_mod(a)
    print(f"modulus p = {MODULUS}")
    print(f"a = {a}, inv(a) mod p = {inv_a}, a*inv(a) mod p = {(a * inv_a) % MODULUS}")

    print("\n=== Step 2: Multiset remainder + roots product evaluation ===")
    table = [2, 3, 3, 5, 8, 13, 21]
    witness_ok = [3, 5, 3]
    remainder = multiset_difference(table, witness_ok)
    print(f"table   = {table}")
    print(f"witness = {witness_ok}")
    print(f"remainder (table - witness) = {remainder}")

    print("\n=== Step 3: Prove/verify the toy lookup membership ===")
    proof = prove_lookup_membership(table=table, witness=witness_ok)
    ok = verify_lookup_membership(table=table, proof=proof)
    print("proof =", json.dumps(proof.to_json(), indent=2, sort_keys=True))
    print("verify(proof) =", ok)

    bad = ToyLookupProof(
        witness=proof.witness,
        remainder=proof.remainder,
        r=proof.r,
        eval_witness=(proof.eval_witness + 1) % MODULUS,
        eval_remainder=proof.eval_remainder,
        commit_witness=proof.commit_witness,
        commit_remainder=proof.commit_remainder,
    )
    print("verify(tampered proof) =", verify_lookup_membership(table=table, proof=bad))

    print("\n=== Step 4: Multi-column lookups via row compression (theta) ===")
    rows_table = [(0, 0), (1, 1), (2, 4), (3, 9), (4, 16)]
    rows_witness = [(2, 4), (4, 16), (1, 1)]

    tr = Transcript("theta-demo")
    tr.append("commit_table_rows", _hash_rows("rows_table", rows_table))
    theta = tr.challenge("theta")

    compressed_table = compress_rows(rows_table, theta=theta)
    compressed_witness = compress_rows(rows_witness, theta=theta)

    _print_table(rows_table, headers=("x", "x^2"))
    print(f"theta = {theta}")
    print(f"compressed table   = {compressed_table}")
    print(f"compressed witness = {compressed_witness}")

    proof2 = prove_lookup_membership(table=compressed_table, witness=compressed_witness, label="toy-lookup-v1/rows")
    print("verify(row lookup proof) =", verify_lookup_membership(table=compressed_table, proof=proof2, label="toy-lookup-v1/rows"))


if __name__ == "__main__":
    main()
