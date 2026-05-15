import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (
    ct_eq_bytes,
    leaky_equals,
    leaky_prefix_match_len,
    recover_secret_from_prefix_oracle,
    stdlib_compare_digest,
)


def _from_hex(s: str) -> bytes:
    return bytes.fromhex(s)


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]
        if op == "leaky_prefix_match_len":
            expected = _from_hex(v["expected_hex"])
            provided = _from_hex(v["provided_hex"])
            got = leaky_prefix_match_len(expected, provided)
            assert got == v["prefix_len"], f"leaky_prefix_match_len failed: got {got}, expected {v['prefix_len']}"
        elif op == "leaky_equals":
            expected = _from_hex(v["expected_hex"])
            provided = _from_hex(v["provided_hex"])
            got = leaky_equals(expected, provided)
            assert got == v["expected"], f"leaky_equals failed: got {got}, expected {v['expected']}"
        elif op == "ct_eq_bytes":
            a = _from_hex(v["a_hex"])
            b = _from_hex(v["b_hex"])
            got = ct_eq_bytes(a, b)
            assert got == v["expected"], f"ct_eq_bytes failed: got {got}, expected {v['expected']}"
        elif op == "compare_digest":
            a = _from_hex(v["a_hex"])
            b = _from_hex(v["b_hex"])
            got = stdlib_compare_digest(a, b)
            assert got == v["expected"], f"compare_digest failed: got {got}, expected {v['expected']}"
        else:
            raise AssertionError(f"unknown op {op}")


def test_recover_secret_from_prefix_oracle():
    secret = bytes.fromhex("0011223344556677")

    def oracle(guess: bytes) -> int:
        return leaky_prefix_match_len(secret, guess)

    recovered = recover_secret_from_prefix_oracle(oracle, secret_len=len(secret))
    assert recovered == secret


if __name__ == "__main__":
    test_vectors()
    test_recover_secret_from_prefix_oracle()
    print("all tests pass")

