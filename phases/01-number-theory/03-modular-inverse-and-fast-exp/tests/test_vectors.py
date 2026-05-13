import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import mod_inverse, mod_inverse_prime, mod_pow


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        if op == "mod_pow":
            got = mod_pow(v["base"], v["exp"], v["n"])
        elif op == "mod_inverse":
            try:
                got = mod_inverse(v["a"], v["n"])
            except ValueError as exc:
                assert v.get("expected_error") == str(exc), (
                    f"mod_inverse wrong error: got {exc!s}, expected {v.get('expected_error')}"
                )
                continue
        elif op == "mod_inverse_prime":
            try:
                got = mod_inverse_prime(v["a"], v["p"])
            except ValueError as exc:
                assert v.get("expected_error") == str(exc), (
                    f"mod_inverse_prime wrong error: got {exc!s}, expected {v.get('expected_error')}"
                )
                continue
        else:
            raise AssertionError(f"unknown op {op}")

        assert "expected" in v, f"{op} missing expected result"
        assert got == v["expected"], f"{op} failed: got {got}, expected {v['expected']}"


if __name__ == "__main__":
    test_vectors()
    print("all vectors pass")
