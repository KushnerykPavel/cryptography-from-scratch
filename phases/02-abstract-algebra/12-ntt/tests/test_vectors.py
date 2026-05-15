import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (
    cyclic_convolution,
    find_primitive_nth_root,
    intt,
    negacyclic_convolution,
    ntt,
    ntt_slow,
)


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        try:
            if op == "find_primitive_nth_root":
                got = find_primitive_nth_root(v["n"], v["p"])
            elif op == "ntt_slow":
                got = ntt_slow(v["a"], v["p"], v["omega"])
            elif op == "ntt":
                got = ntt(v["a"], v["p"], v["omega"])
            elif op == "intt_roundtrip":
                got = intt(ntt(v["a"], v["p"], v["omega"]), v["p"], v["omega"])
            elif op == "cyclic_convolution":
                got = cyclic_convolution(v["a"], v["b"], v["p"], v["omega"])
            elif op == "negacyclic_convolution":
                got = negacyclic_convolution(v["a"], v["b"], v["p"], v["psi"])
            else:
                raise AssertionError(f"unknown op {op}")
        except ValueError as exc:
            assert v.get("expected_error") == str(exc), (
                f"{op} wrong error: got {exc!s}, expected {v.get('expected_error')}"
            )
            continue

        assert got == v["expected"], f"{op} failed: got {got}, expected {v['expected']}"


if __name__ == "__main__":
    test_vectors()
    print("all vectors pass")

