import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (
    build_congruence,
    ceil_sqrt,
    collect_relations,
    dependency_masks,
    extract_factor,
    factor_base,
    factor_over_base,
    is_square,
    legendre_symbol,
    mask_indices,
    parity_vector,
    primes_up_to,
    quadratic_sieve,
    roots_for_factor_base,
    tonelli_shanks,
)


def normalize(value):
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, dict):
        return {str(k): normalize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [normalize(v) for v in value]
    return value


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for vector in data["vectors"]:
        op = vector["op"]

        try:
            if op == "ceil_sqrt":
                got = ceil_sqrt(vector["n"])
            elif op == "is_square":
                got = is_square(vector["n"])
            elif op == "primes_up_to":
                got = primes_up_to(vector["limit"])
            elif op == "legendre_symbol":
                got = legendre_symbol(vector["a"], vector["p"])
            elif op == "tonelli_shanks":
                got = tonelli_shanks(vector["n"], vector["p"])
            elif op == "factor_base":
                got = factor_base(vector["n"], vector["bound"])
            elif op == "roots_for_factor_base":
                got = roots_for_factor_base(vector["n"], vector["base"])
            elif op == "factor_over_base":
                got = factor_over_base(vector["value"], vector["base"])
            elif op == "parity_vector":
                got = parity_vector(vector["exponents"])
            elif op == "collect_relations":
                got = collect_relations(vector["n"], vector["bound"], vector["interval"])
            elif op == "dependency_masks":
                got = dependency_masks(vector["vectors"])
            elif op == "mask_indices":
                got = mask_indices(vector["mask"])
            elif op == "build_congruence":
                relations = collect_relations(
                    vector["n"], vector["bound"], vector["interval"]
                )
                got = build_congruence(
                    vector["n"],
                    factor_base(vector["n"], vector["bound"]),
                    relations,
                    vector["indices"],
                )
            elif op == "extract_factor":
                got = extract_factor(vector["n"], vector["x"], vector["y"])
            elif op == "quadratic_sieve":
                got = quadratic_sieve(vector["n"], vector["bound"], vector["interval"])
            else:
                raise AssertionError(f"unknown op {op}")
        except ValueError as exc:
            assert vector.get("expected_error") == str(exc), (
                f"{op} wrong error: got {exc!s}, expected {vector.get('expected_error')}"
            )
            continue

        assert normalize(got) == vector["expected"], (
            f"{op} failed: got {normalize(got)}, expected {vector['expected']}"
        )


if __name__ == "__main__":
    test_vectors()
    print("all vectors pass")
