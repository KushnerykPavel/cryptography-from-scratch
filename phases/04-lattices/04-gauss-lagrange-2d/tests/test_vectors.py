import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import gauss_lagrange_reduce_2d, is_gauss_reduced_2d, shortest_vector_gauss_2d


def _basis(v):
    b1, b2 = v
    return (tuple(b1), tuple(b2))


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        try:
            if op == "gauss_lagrange_reduce_2d":
                max_iters = v.get("max_iters", 10_000)
                got = gauss_lagrange_reduce_2d(_basis(v["basis"]), max_iters=max_iters)
                got = [list(got[0]), list(got[1])]
            elif op == "is_gauss_reduced_2d":
                got = is_gauss_reduced_2d(_basis(v["basis"]))
            elif op == "shortest_vector_gauss_2d":
                got = shortest_vector_gauss_2d(_basis(v["basis"]))
                got_norm2 = got[0] * got[0] + got[1] * got[1]
                expected_norm2 = v.get("expected_norm2")
                if expected_norm2 is None:
                    raise AssertionError("missing expected_norm2 for shortest_vector_gauss_2d")
                assert got_norm2 == expected_norm2, (
                    f"{op} wrong norm^2: got {got_norm2}, expected {expected_norm2}"
                )
                continue
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

