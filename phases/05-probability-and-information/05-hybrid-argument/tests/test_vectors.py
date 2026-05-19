import json
import math
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (  # noqa: E402
    hybrid_advantage_bound,
    is_poly_sum_negligible,
    make_hybrid_otp_samplers,
    negligible_sum,
    reduction_advantage,
    run_hybrid_chain,
)


def _run_vector(v):
    op = v["op"]
    if op == "hybrid_advantage_bound":
        return hybrid_advantage_bound(v["per_hop"])
    if op == "negligible_sum":
        return negligible_sum(v["epsilon"], v["k"])
    if op == "reduction_advantage":
        return reduction_advantage(v["total_adv"], v["k"])
    if op == "is_poly_sum_negligible":
        return is_poly_sum_negligible(v["epsilon"], v["k"], v["n"], poly_degree=v["d"])
    raise AssertionError(f"unknown op {op!r}")


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        got = _run_vector(v)
        expected = v["expected"]
        if isinstance(expected, bool):
            assert got == expected, f"vector {v}: got {got!r}, want {expected!r}"
        else:
            assert math.isclose(got, expected, rel_tol=1e-9, abs_tol=1e-12), (
                f"vector {v}: got {got!r}, want {expected!r}"
            )


def test_hybrid_bound_empty():
    assert hybrid_advantage_bound([]) == 0.0


def test_hybrid_bound_is_sum():
    hops = [0.05, 0.10, 0.03, 0.07]
    assert math.isclose(hybrid_advantage_bound(hops), sum(hops), abs_tol=1e-12)


def test_hybrid_bound_rejects_negative():
    try:
        hybrid_advantage_bound([0.1, -0.01])
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for negative advantage")


def test_negligible_sum_zero_hops():
    assert negligible_sum(0.5, 0) == 0.0


def test_negligible_sum_scales_linearly():
    for k in (1, 5, 100):
        assert math.isclose(negligible_sum(0.01, k), 0.01 * k, abs_tol=1e-12)


def test_reduction_advantage_equals_total_over_k():
    for adv, k in [(0.3, 3), (0.5, 10), (1.0, 4)]:
        assert math.isclose(reduction_advantage(adv, k), adv / k, abs_tol=1e-12)


def test_reduction_advantage_zero():
    assert reduction_advantage(0.0, 5) == 0.0


def test_is_poly_sum_negligible_boundary():
    n = 50
    threshold = 1.0 / n
    eps = (threshold - 1e-12) / 10
    assert is_poly_sum_negligible(eps, 10, n, poly_degree=1)
    assert not is_poly_sum_negligible(threshold / 10, 11, n, poly_degree=1)


def test_run_hybrid_chain_triangle_holds():
    rng = random.Random(42)
    messages = [1, 0, 1]
    n = len(messages)
    samplers = [
        make_hybrid_otp_samplers(messages, n_real, rng=random.Random(i * 7))
        for i, n_real in enumerate(range(n + 1))
    ]

    def dist(ct):
        return 1 if sum(ct) % 2 == 0 else 0

    result = run_hybrid_chain(samplers, dist, n_rounds=2_000, rng=random.Random(99))

    assert len(result["per_hop"]) == n
    assert math.isclose(result["triangle_bound"], sum(result["per_hop"]), abs_tol=1e-12)
    assert result["endpoint_advantage"] <= result["triangle_bound"] + 0.05


def test_run_hybrid_chain_perfect_samplers():
    """Identical samplers at each hop → all per-hop advantages ≈ 0."""
    rng_src = random.Random(1)
    sampler = lambda: rng_src.randint(0, 1)  # noqa: E731
    samplers = [sampler] * 4

    result = run_hybrid_chain(
        samplers,
        lambda x: x,
        n_rounds=2_000,
        rng=random.Random(2),
    )
    for adv in result["per_hop"]:
        assert adv < 0.1, f"expected near-zero per-hop advantage, got {adv}"


def test_run_hybrid_chain_requires_two_samplers():
    try:
        run_hybrid_chain([lambda: 0], lambda x: x, 100)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for single sampler")


def test_make_hybrid_otp_samplers_length():
    messages = [0, 1, 1, 0]
    for n_real in range(len(messages) + 1):
        sampler = make_hybrid_otp_samplers(messages, n_real, rng=random.Random(n_real))
        ct = sampler()
        assert len(ct) == len(messages)


def test_make_hybrid_otp_ideal_uniform():
    """H_0 (all true random pads): ciphertext should be uniformly distributed."""
    messages = [0, 0, 0, 0]
    sampler = make_hybrid_otp_samplers(messages, n_real=0, rng=random.Random(123))
    counts = {}
    for _ in range(8_000):
        ct = sampler()
        counts[ct] = counts.get(ct, 0) + 1
    n_outcomes = 2 ** len(messages)
    for ct, cnt in counts.items():
        expected = 8_000 / n_outcomes
        assert abs(cnt - expected) < 4 * (expected ** 0.5) + 50, (
            f"ciphertext {ct} count {cnt} too far from uniform"
        )


if __name__ == "__main__":
    test_vectors()
    test_hybrid_bound_empty()
    test_hybrid_bound_is_sum()
    test_hybrid_bound_rejects_negative()
    test_negligible_sum_zero_hops()
    test_negligible_sum_scales_linearly()
    test_reduction_advantage_equals_total_over_k()
    test_reduction_advantage_zero()
    test_is_poly_sum_negligible_boundary()
    test_run_hybrid_chain_triangle_holds()
    test_run_hybrid_chain_perfect_samplers()
    test_run_hybrid_chain_requires_two_samplers()
    test_make_hybrid_otp_samplers_length()
    test_make_hybrid_otp_ideal_uniform()
    print("all tests pass")
