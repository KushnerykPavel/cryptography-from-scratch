import json
import os
import sys
from fractions import Fraction

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import coppersmith_howgrave_univariate, stereotyped_rsa_polynomial


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        try:
            if op == "recover_stereotyped_rsa_suffix":
                N = v["N"]
                e = v["e"]
                A = v["A"]
                c = v["c"]
                X = v["X"]
                beta = v.get("beta", [1, 1])
                m = v.get("m", 3)
                t = v.get("t", 0)

                pol = stereotyped_rsa_polynomial(A=A, e=e, c=c, N=N)
                got = coppersmith_howgrave_univariate(pol, N, Fraction(beta[0], beta[1]), m=m, t=t, X=X)
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
