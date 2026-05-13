import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (
    euler_holds,
    euler_residue,
    euler_totient_naive,
    fermat_holds,
    fermat_primality_test,
    fermat_residue,
    is_carmichael_naive,
    reduce_exponent_euler,
    reduce_exponent_prime,
)


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        try:
            if op == "euler_totient_naive":
                got = euler_totient_naive(v["n"])
            elif op == "fermat_residue":
                got = fermat_residue(v["a"], v["p"])
            elif op == "fermat_holds":
                got = fermat_holds(v["a"], v["p"])
            elif op == "euler_residue":
                got = euler_residue(v["a"], v["n"])
            elif op == "euler_holds":
                got = euler_holds(v["a"], v["n"])
            elif op == "reduce_exponent_prime":
                got = reduce_exponent_prime(v["base"], v["exp"], v["p"])
            elif op == "reduce_exponent_euler":
                got = reduce_exponent_euler(v["base"], v["exp"], v["n"])
            elif op == "fermat_primality_test":
                got = fermat_primality_test(v["n"], v["bases"])
            elif op == "is_carmichael_naive":
                got = is_carmichael_naive(v["n"])
            else:
                raise AssertionError(f"unknown op {op}")
        except ValueError as exc:
            assert v.get("expected_error") == str(exc), (
                f"{op} wrong error: got {exc!s}, expected {v.get('expected_error')}"
            )
            continue

        assert "expected" in v, f"{op} missing expected result"
        assert got == v["expected"], f"{op} failed: got {got}, expected {v['expected']}"


if __name__ == "__main__":
    test_vectors()
    print("all vectors pass")
