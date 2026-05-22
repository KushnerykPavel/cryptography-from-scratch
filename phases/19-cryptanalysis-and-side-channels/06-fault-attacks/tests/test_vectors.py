import json
import os
import sys

HERE = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as fa  # noqa: E402


def test_vectors():
    with open(os.path.join(HERE, "vectors.json"), "r", encoding="utf-8") as f:
        data = json.load(f)

    for vec in data["vectors"]:
        op = vec["op"]
        if op == "rsa_encrypt":
            got = fa.rsa_encrypt(int(vec["m"]), int(vec["n"]), int(vec["e"]))
        elif op == "factor_from_faulty_pair":
            got = list(fa.factor_from_faulty_pair(int(vec["n"]), int(vec["correct"]), int(vec["faulty"])))
        else:
            raise ValueError(f"unknown op in vectors.json: {op}")
        assert got == vec["expected"], f"vector failed: op={op}"


def test_fault_attack_factors_modulus():
    key = fa._toy_key()
    msg = 123456789
    c = fa.rsa_encrypt(msg, key.n, key.e)
    ok = fa.rsa_decrypt_crt(c, key)
    faulty = fa.rsa_decrypt_crt(c, key, fault_mod_p=(ok + 1) % key.p)
    p, q = fa.factor_from_faulty_pair(key.n, ok, faulty)
    assert p * q == key.n


if __name__ == "__main__":
    tests = [
        test_vectors,
        test_fault_attack_factors_modulus,
    ]
    for t in tests:
        t()
    print("all tests pass")

