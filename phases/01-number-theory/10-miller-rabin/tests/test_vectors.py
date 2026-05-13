import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (
    decompose_n_minus_one,
    deterministic_bases_for,
    find_miller_rabin_liars,
    generate_probable_prime,
    is_prime_deterministic,
    is_probable_prime,
    miller_rabin_witness,
    normalize_odd_candidate,
    strong_liar_sequence,
)


def make_randbits(values):
    sequence = iter(values)

    def randbits(_bits):
        return next(sequence)

    return randbits


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        try:
            if op == "decompose_n_minus_one":
                got = decompose_n_minus_one(v["n"])
            elif op == "strong_liar_sequence":
                got = strong_liar_sequence(v["a"], v["n"])
            elif op == "miller_rabin_witness":
                got = miller_rabin_witness(v["a"], v["n"])
            elif op == "is_probable_prime":
                got = is_probable_prime(v["n"], v["bases"])
            elif op == "deterministic_bases_for":
                got = deterministic_bases_for(v["n"])
            elif op == "is_prime_deterministic":
                got = is_prime_deterministic(v["n"])
            elif op == "find_miller_rabin_liars":
                got = find_miller_rabin_liars(v["n"])
            elif op == "normalize_odd_candidate":
                got = normalize_odd_candidate(v["raw"], v["bits"])
            elif op == "generate_probable_prime":
                randbits = make_randbits(v["raw_values"])
                got = generate_probable_prime(v["bits"], randbits)
            else:
                raise AssertionError(f"unknown op {op}")
        except ValueError as exc:
            assert v.get("expected_error") == str(exc), (
                f"{op} wrong error: got {exc!s}, expected {v.get('expected_error')}"
            )
            continue

        expected = v["expected"]
        if op in ("decompose_n_minus_one", "generate_probable_prime"):
            expected = tuple(expected)
        assert got == expected, f"{op} failed: got {got}, expected {expected}"


if __name__ == "__main__":
    test_vectors()
    print("all vectors pass")
