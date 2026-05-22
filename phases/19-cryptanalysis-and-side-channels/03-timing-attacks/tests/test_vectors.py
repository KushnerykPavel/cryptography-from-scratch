import json
import os
import sys

HERE = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as ta  # noqa: E402


def _b(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


def test_vectors():
    with open(os.path.join(HERE, "vectors.json"), "r", encoding="utf-8") as f:
        data = json.load(f)

    for vec in data["vectors"]:
        op = vec["op"]
        if op == "insecure_prefix_compare":
            got = list(ta.insecure_prefix_compare(_b(vec["a_hex"]), _b(vec["b_hex"])))
        elif op == "constant_time_compare":
            got = list(ta.constant_time_compare(_b(vec["a_hex"]), _b(vec["b_hex"])))
        else:
            raise ValueError(f"unknown op in vectors.json: {op}")
        assert got == vec["expected"], f"vector failed: op={op}"


def test_timing_oracle_attack_recovers_secret():
    secret = b"SECRET_TOKEN"
    alphabet = list(range(ord("A"), ord("Z") + 1)) + [ord("_")]
    oracle = ta.make_timing_oracle(secret, ta.insecure_prefix_compare)
    recovered = ta.recover_secret_from_timing_oracle(oracle, len(secret), alphabet)
    assert recovered == secret


def test_constant_time_compare_steps_do_not_depend_on_prefix():
    secret = b"AAAAAA"
    g1 = b"BAAAAA"
    g2 = b"ABAAAA"
    _, t1 = ta.constant_time_compare(secret, g1)
    _, t2 = ta.constant_time_compare(secret, g2)
    assert t1 == t2 == len(secret)


if __name__ == "__main__":
    tests = [
        test_vectors,
        test_timing_oracle_attack_recovers_secret,
        test_constant_time_compare_steps_do_not_depend_on_prefix,
    ]
    for t in tests:
        t()
    print("all tests pass")

