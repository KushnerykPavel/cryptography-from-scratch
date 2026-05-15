import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import is_lll_reduced, lll_reduce


def _basis(v):
    return tuple(tuple(b) for b in v)


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        try:
            if op == "lll_reduce":
                delta = v.get("delta")
                max_iters = v.get("max_iters", 100_000)
                if delta is None:
                    got = lll_reduce(_basis(v["basis"]), max_iters=max_iters)
                else:
                    from fractions import Fraction

                    got = lll_reduce(_basis(v["basis"]), delta=Fraction(delta[0], delta[1]), max_iters=max_iters)
                got = [list(col) for col in got]
            elif op == "is_lll_reduced":
                delta = v.get("delta")
                if delta is None:
                    got = is_lll_reduced(_basis(v["basis"]))
                else:
                    from fractions import Fraction

                    got = is_lll_reduced(_basis(v["basis"]), delta=Fraction(delta[0], delta[1]))
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

