import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import extended_gcd, gcd


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        if v["op"] == "gcd":
            got = gcd(v["a"], v["b"])
            assert got == v["expected"], f"gcd failed: got {got}, expected {v['expected']}"
        elif v["op"] == "extended_gcd":
            g, s, t = extended_gcd(v["a"], v["b"])
            assert g == v["expected_gcd"], (
                f"extended_gcd gcd failed: got {g}, expected {v['expected_gcd']}"
            )
            assert s * v["a"] + t * v["b"] == g, (
                f"Bezout identity failed for ({v['a']}, {v['b']}): "
                f"{s}*{v['a']} + {t}*{v['b']} != {g}"
            )
        else:
            raise AssertionError(f"unknown op {v['op']}")


if __name__ == "__main__":
    test_vectors()
    print("all vectors pass")
