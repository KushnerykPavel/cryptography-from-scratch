import json
import os
import sys

HERE = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as cop  # noqa: E402


def test_vectors():
    with open(os.path.join(HERE, "vectors.json"), "r", encoding="utf-8") as f:
        data = json.load(f)

    for vec in data["vectors"]:
        op = vec["op"]
        if op == "poly_eval_mod":
            got = cop.poly_eval_mod([int(x) for x in vec["coeffs"]], int(vec["x"]), int(vec["n"]))
        elif op == "find_small_root_bruteforce":
            got = cop.find_small_root_bruteforce([int(x) for x in vec["coeffs"]], int(vec["n"]), int(vec["x_bound"]))
        else:
            raise ValueError(f"unknown op in vectors.json: {op}")
        assert got == vec["expected"], f"vector failed: op={op}"


def test_toy_stereotyped_message_recovery():
    key = cop._toy_key()
    m0 = 1234567890000
    x0 = 4242
    c = cop.rsa_encrypt(m0 + x0, key.n, key.e)
    coeffs = cop.build_stereotyped_message_polynomial(m0, key.e, c, key.n)
    x = cop.find_small_root_bruteforce(coeffs, key.n, 1 << 16)
    assert x == x0


if __name__ == "__main__":
    tests = [
        test_vectors,
        test_toy_stereotyped_message_recovery,
    ]
    for t in tests:
        t()
    print("all tests pass")

