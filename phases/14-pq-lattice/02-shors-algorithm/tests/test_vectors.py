import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (
    continued_fraction_rational,
    convergents,
    gcd,
    mod_pow,
    multiplicative_order,
    recover_order_from_phase,
    shor_factor_toy,
    simulate_phase_measurement,
)


def clean(value):
    if isinstance(value, tuple):
        return [clean(v) for v in value]
    if isinstance(value, list):
        return [clean(v) for v in value]
    if isinstance(value, dict):
        return {str(k): clean(v) for k, v in value.items()}
    return value


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        try:
            if op == "gcd":
                got = gcd(v["a"], v["b"])
            elif op == "mod_pow":
                got = mod_pow(v["base"], v["exponent"], v["modulus"])
            elif op == "continued_fraction_rational":
                got = continued_fraction_rational(v["numerator"], v["denominator"])
            elif op == "convergents":
                got = convergents(v["coefficients"])
            elif op == "multiplicative_order":
                got = multiplicative_order(v["a"], v["n"], max_r=v.get("max_r"))
            elif op == "simulate_phase_measurement":
                got = simulate_phase_measurement(v["s"], v["r"], v["Q"])
            elif op == "recover_order_from_phase":
                got = recover_order_from_phase(**v["inputs"])
            elif op == "shor_factor_toy":
                got = shor_factor_toy(**v["inputs"])
            else:
                raise AssertionError(f"unknown op {op}")
        except ValueError as exc:
            assert v.get("expected_error") == str(exc), (
                f"{op} wrong error: got {exc!s}, expected {v.get('expected_error')}"
            )
            continue

        assert clean(got) == clean(v["expected"]), (
            f"{op} failed: got {clean(got)}, expected {clean(v['expected'])}"
        )


def test_mod_pow_matches_builtin():
    for modulus in range(2, 50):
        for base in range(-50, 51, 7):
            for exponent in range(0, 40, 5):
                assert mod_pow(base, exponent, modulus) == pow(base, exponent, modulus)


def test_continued_fraction_roundtrip():
    cases = [(0, 7), (7, 22), (32, 64), (17, 31), (10, 1)]
    for numerator, denominator in cases:
        cf = continued_fraction_rational(numerator, denominator)
        p, q = convergents(cf)[-1]
        g = gcd(numerator, denominator)
        assert (p, q) == (numerator // g, denominator // g)


def test_multiplicative_order_properties():
    for N in (15, 21, 33, 35):
        for a in range(2, N):
            if gcd(a, N) != 1:
                continue
            r = multiplicative_order(a, N, max_r=N)
            assert mod_pow(a, r, N) == 1
            for k in range(1, r):
                assert mod_pow(a, k, N) != 1


def test_recover_order_handles_non_coprime_s():
    N = 15
    a = 2
    r = multiplicative_order(a, N, max_r=N)
    Q = 64
    for s in range(1, r):
        measurement = simulate_phase_measurement(s, r, Q)
        got = recover_order_from_phase(
            measurement=measurement,
            Q=Q,
            a=a,
            N=N,
            max_denominator=N,
            max_multiplier=10,
        )
        assert got == r


def test_shor_factor_toy_deterministic():
    assert shor_factor_toy(15, seed=0, max_attempts=30) == (3, 5)
    assert shor_factor_toy(21, seed=0, max_attempts=30) == (3, 7)


if __name__ == "__main__":
    test_vectors()
    test_mod_pow_matches_builtin()
    test_continued_fraction_roundtrip()
    test_multiplicative_order_properties()
    test_recover_order_handles_non_coprime_s()
    test_shor_factor_toy_deterministic()
    print("all tests pass")

