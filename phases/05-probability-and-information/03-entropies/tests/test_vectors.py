import json
import math
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (  # noqa: E402
    collision_entropy,
    conditional_entropy,
    extractable_bits,
    guessing_probability,
    kl_divergence,
    max_entropy,
    min_entropy,
    mutual_information,
    renyi_entropy,
    shannon_entropy,
)


_OPS = {
    "shannon_entropy": lambda v: shannon_entropy(v["pmf"]),
    "min_entropy": lambda v: min_entropy(v["pmf"]),
    "collision_entropy": lambda v: collision_entropy(v["pmf"]),
    "max_entropy": lambda v: max_entropy(v["pmf"]),
    "kl_divergence": lambda v: kl_divergence(v["p"], v["q"]),
}


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]
        if op not in _OPS:
            raise AssertionError(f"unknown op {op}")
        got = _OPS[op](v)
        assert math.isclose(got, v["expected"], rel_tol=0, abs_tol=1e-9), v


def test_uniform_entropy_equals_log2_n():
    for n in (2, 4, 8, 16):
        pmf = {i: 1 / n for i in range(n)}
        assert math.isclose(shannon_entropy(pmf), math.log2(n), abs_tol=1e-12)
        assert math.isclose(min_entropy(pmf), math.log2(n), abs_tol=1e-12)
        assert math.isclose(collision_entropy(pmf), math.log2(n), abs_tol=1e-12)
        assert math.isclose(max_entropy(pmf), math.log2(n), abs_tol=1e-12)


def test_renyi_monotone_in_alpha():
    pmf = {"a": 0.5, "b": 0.25, "c": 0.125, "d": 0.125}
    alphas = [0.0, 0.5, 1.0, 2.0, 4.0, math.inf]
    values = [renyi_entropy(pmf, a) for a in alphas]
    for prev, curr in zip(values, values[1:]):
        assert curr <= prev + 1e-12, f"Renyi must decrease in alpha: {values}"


def test_renyi_dispatch_matches_named():
    pmf = {"a": 0.5, "b": 0.25, "c": 0.125, "d": 0.125}
    assert math.isclose(renyi_entropy(pmf, 0), max_entropy(pmf), abs_tol=1e-12)
    assert math.isclose(renyi_entropy(pmf, 1), shannon_entropy(pmf), abs_tol=1e-12)
    assert math.isclose(renyi_entropy(pmf, 2), collision_entropy(pmf), abs_tol=1e-12)
    assert math.isclose(renyi_entropy(pmf, math.inf), min_entropy(pmf), abs_tol=1e-12)


def test_kl_zero_iff_equal():
    p = {"a": 0.3, "b": 0.7}
    assert kl_divergence(p, p) == 0.0


def test_kl_infinite_when_q_zero_on_p_support():
    p = {"a": 0.5, "b": 0.5}
    q = {"a": 1.0, "b": 0.0}
    assert math.isinf(kl_divergence(p, q))


def test_kl_nonnegative():
    p = {"a": 0.3, "b": 0.7}
    q = {"a": 0.6, "b": 0.4}
    assert kl_divergence(p, q) >= -1e-12


def test_mutual_information_independent_is_zero():
    px = {0: 0.5, 1: 0.5}
    py = {0: 0.5, 1: 0.5}
    pxy = {(x, y): px[x] * py[y] for x in px for y in py}
    assert math.isclose(mutual_information(pxy), 0.0, abs_tol=1e-12)


def test_mutual_information_perfect_correlation():
    pxy = {(0, 0): 0.5, (1, 1): 0.5}
    assert math.isclose(mutual_information(pxy), 1.0, abs_tol=1e-12)
    assert math.isclose(conditional_entropy(pxy), 0.0, abs_tol=1e-12)


def test_guessing_probability_matches_min_entropy():
    pmf = {"a": 0.6, "b": 0.3, "c": 0.1}
    g = guessing_probability(pmf)
    assert math.isclose(-math.log2(g), min_entropy(pmf), abs_tol=1e-12)


def test_extractable_bits_leftover_hash():
    assert math.isclose(extractable_bits(256, security=80), 96.0, abs_tol=1e-12)
    assert extractable_bits(100, security=80) == 0.0


def test_rejects_non_pmf():
    try:
        shannon_entropy({"a": 0.6, "b": 0.6})
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


if __name__ == "__main__":
    test_vectors()
    test_uniform_entropy_equals_log2_n()
    test_renyi_monotone_in_alpha()
    test_renyi_dispatch_matches_named()
    test_kl_zero_iff_equal()
    test_kl_infinite_when_q_zero_on_p_support()
    test_kl_nonnegative()
    test_mutual_information_independent_is_zero()
    test_mutual_information_perfect_correlation()
    test_guessing_probability_matches_min_entropy()
    test_extractable_bits_leftover_hash()
    test_rejects_non_pmf()
    print("all tests pass")
