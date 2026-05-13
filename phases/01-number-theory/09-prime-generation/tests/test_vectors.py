import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (
    generate_prime_by_trial,
    is_prime_trial,
    next_prime,
    normalize_odd_candidate,
    nth_prime,
    prime_count,
    primes_in_segment,
    sieve_primes_up_to,
    trial_division_factor,
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
            if op == "trial_division_factor":
                got = trial_division_factor(v["n"])
            elif op == "is_prime_trial":
                got = is_prime_trial(v["n"])
            elif op == "sieve_primes_up_to":
                got = sieve_primes_up_to(v["limit"])
            elif op == "prime_count":
                got = prime_count(v["limit"])
            elif op == "nth_prime":
                got = nth_prime(v["index"])
            elif op == "primes_in_segment":
                got = primes_in_segment(v["low"], v["high"])
            elif op == "next_prime":
                got = next_prime(v["n"])
            elif op == "normalize_odd_candidate":
                got = normalize_odd_candidate(v["raw"], v["bits"])
            elif op == "generate_prime_by_trial":
                randbits = make_randbits(v["raw_values"])
                got = generate_prime_by_trial(v["bits"], randbits)
            else:
                raise AssertionError(f"unknown op {op}")
        except ValueError as exc:
            assert v.get("expected_error") == str(exc), (
                f"{op} wrong error: got {exc!s}, expected {v.get('expected_error')}"
            )
            continue

        expected = v["expected"]
        if isinstance(expected, list) and op == "generate_prime_by_trial":
            expected = tuple(expected)
        assert got == expected, f"{op} failed: got {got}, expected {expected}"


if __name__ == "__main__":
    test_vectors()
    print("all vectors pass")
