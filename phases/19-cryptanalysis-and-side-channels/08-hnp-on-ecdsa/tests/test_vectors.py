import json
import os
import sys

HERE = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as hnp  # noqa: E402


def test_vectors():
    with open(os.path.join(HERE, "vectors.json"), "r", encoding="utf-8") as f:
        data = json.load(f)

    for vec in data["vectors"]:
        op = vec["op"]
        if op == "toy_ecdsa_sign":
            got = list(
                hnp.toy_ecdsa_sign(int(vec["h"]), int(vec["x"]), int(vec["k"]), int(vec["q"]))
            )
        else:
            raise ValueError(f"unknown op in vectors.json: {op}")
        assert got == vec["expected"], f"vector failed: op={op}"


def test_recover_secret_key_from_prefix_leaks():
    q = 65537
    x = 4242
    leak_bits = 8
    sigs = []
    for i, k_i in enumerate([40000, 41000, 42000, 43000]):
        h_i = 1000 + i
        r_i, s_i = hnp.toy_ecdsa_sign(h_i, x, k_i, q)
        sigs.append(hnp.ToySig(r=r_i, s=s_i, h=h_i, k_prefix=(k_i >> leak_bits)))
    got = hnp.recover_secret_key_from_leaked_nonce_prefixes(sigs, q, leak_bits)
    assert got == x


if __name__ == "__main__":
    tests = [
        test_vectors,
        test_recover_secret_key_from_prefix_leaks,
    ]
    for t in tests:
        t()
    print("all tests pass")

