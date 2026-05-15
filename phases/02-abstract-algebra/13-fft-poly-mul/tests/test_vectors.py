import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import next_power_of_two, poly_mul_fft, poly_mul_naive


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        try:
            if op == "next_power_of_two":
                got = next_power_of_two(v["n"])
            elif op == "poly_mul_fft":
                got = poly_mul_fft(v["a"], v["b"])
            else:
                raise AssertionError(f"unknown op {op}")
        except ValueError as exc:
            assert v.get("expected_error") == str(exc), (
                f"{op} wrong error: got {exc!s}, expected {v.get('expected_error')}"
            )
            continue

        assert got == v["expected"], f"{op} failed: got {got}, expected {v['expected']}"

        if op == "poly_mul_fft":
            naive = poly_mul_naive(v["a"], v["b"])
            assert got == naive, f"{op} mismatch vs naive: got {got}, naive {naive}"


if __name__ == "__main__":
    test_vectors()
    print("all vectors pass")

