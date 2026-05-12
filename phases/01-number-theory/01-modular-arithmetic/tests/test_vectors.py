import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import mod_add, mod_sub, mod_mul, mod_pow

OPS = {"mod_add": mod_add, "mod_sub": mod_sub, "mod_mul": mod_mul, "mod_pow": mod_pow}


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)
    for v in data["vectors"]:
        op = v["op"]
        n = v["n"]
        if op == "mod_pow":
            got = mod_pow(v["base"], v["exp"], n)
        else:
            got = OPS[op](v["a"], v["b"], n)
        assert got == v["expected"], f"{op} failed: got {got}, expected {v['expected']}"


if __name__ == "__main__":
    test_vectors()
    print("all vectors pass")
