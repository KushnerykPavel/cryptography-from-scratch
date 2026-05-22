import json
import os
import sys

HERE = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as ca  # noqa: E402


def test_vectors():
    with open(os.path.join(HERE, "vectors.json"), "r", encoding="utf-8") as f:
        data = json.load(f)

    for vec in data["vectors"]:
        op = vec["op"]
        if op == "cache_access":
            cache = ca.DirectMappedCache(int(vec["num_sets"]))
            got = [cache.access(int(a)) for a in vec["accesses"]]
        elif op == "recover_secret_prime_probe":
            got = ca.recover_secret_prime_probe(int(vec["cache_sets"]), int(vec["secret_index"]))
        else:
            raise ValueError(f"unknown op in vectors.json: {op}")
        assert got == vec["expected"], f"vector failed: op={op}"


def test_prime_probe_recovers_all_indices():
    for s in range(16):
        got = ca.recover_secret_prime_probe(cache_sets=16, secret_index=s)
        assert got == s


if __name__ == "__main__":
    tests = [
        test_vectors,
        test_prime_probe_recovers_all_indices,
    ]
    for t in tests:
        t()
    print("all tests pass")

