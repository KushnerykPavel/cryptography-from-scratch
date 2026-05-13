import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (
    factor_pair,
    factor_with_pollard,
    is_b_smooth,
    lcm_upto,
    pollard_p_minus_one,
    pollard_rho_brent,
    pollard_rho_floyd,
    rho_polynomial,
)


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for vector in data["vectors"]:
        op = vector["op"]

        try:
            if op == "rho_polynomial":
                got = rho_polynomial(vector["x"], vector["n"], vector["c"])
            elif op == "pollard_rho_floyd":
                got = pollard_rho_floyd(
                    vector["n"], vector["x0"], vector["c"], vector["max_steps"]
                )
            elif op == "pollard_rho_brent":
                got = pollard_rho_brent(
                    vector["n"],
                    vector["x0"],
                    vector["c"],
                    vector["batch_size"],
                    vector["max_steps"],
                )
            elif op == "lcm_upto":
                got = lcm_upto(vector["bound"])
            elif op == "is_b_smooth":
                got = is_b_smooth(vector["value"], vector["bound"])
            elif op == "pollard_p_minus_one":
                got = pollard_p_minus_one(vector["n"], vector["bound"], vector["a"])
            elif op == "factor_pair":
                got = factor_pair(vector["n"], vector["factor"])
            elif op == "factor_with_pollard":
                got = factor_with_pollard(vector["n"], vector["bound"])
            else:
                raise AssertionError(f"unknown op {op}")
        except ValueError as exc:
            assert vector.get("expected_error") == str(exc), (
                f"{op} wrong error: got {exc!s}, expected {vector.get('expected_error')}"
            )
            continue

        expected = vector["expected"]
        if op in (
            "pollard_rho_floyd",
            "pollard_rho_brent",
            "pollard_p_minus_one",
            "factor_pair",
            "factor_with_pollard",
        ) and expected is not None:
            expected = tuple(expected)
        assert got == expected, f"{op} failed: got {got}, expected {expected}"


if __name__ == "__main__":
    test_vectors()
    print("all vectors pass")
