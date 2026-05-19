import json
import math
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (  # noqa: E402
    advantage_bernoulli,
    advantage_uniform_vs_biased,
    estimate_advantage,
    is_negligible,
    negligible_bound,
    run_ind_game,
    statistical_distance_upper_bound,
)

_IDENTITY_DIST = lambda x: x  # noqa: E731


def _run_vector(v):
    op = v["op"]
    if op == "advantage_bernoulli":
        return advantage_bernoulli(v["p0"], v["p1"])
    if op == "negligible_bound":
        return negligible_bound(v["n"], poly_degree=v["d"])
    if op == "is_negligible":
        return is_negligible(v["epsilon"], v["n"], poly_degree=v["d"])
    if op == "advantage_uniform_vs_biased":
        return advantage_uniform_vs_biased(v["n"], v["delta"])
    if op == "estimate_advantage_deterministic":
        return estimate_advantage(_IDENTITY_DIST, v["samples_0"], v["samples_1"])
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
            assert math.isclose(got, expected, rel_tol=0, abs_tol=1e-9), (
                f"vector {v}: got {got!r}, want {expected!r}"
            )


def test_advantage_bernoulli_symmetric():
    assert math.isclose(advantage_bernoulli(0.3, 0.7), advantage_bernoulli(0.7, 0.3))


def test_advantage_bernoulli_zero_for_equal():
    for p in (0.0, 0.25, 0.5, 0.75, 1.0):
        assert advantage_bernoulli(p, p) == 0.0


def test_advantage_bernoulli_bounded():
    for p0, p1 in [(0.0, 1.0), (0.1, 0.9), (0.5, 0.5)]:
        adv = advantage_bernoulli(p0, p1)
        assert 0.0 <= adv <= 1.0


def test_negligible_bound_decreasing_in_n():
    for d in (1, 2, 3):
        bounds = [negligible_bound(n, poly_degree=d) for n in (10, 50, 100, 1000)]
        for prev, curr in zip(bounds, bounds[1:]):
            assert curr < prev


def test_negligible_bound_decreasing_in_d():
    n = 100
    bounds = [negligible_bound(n, poly_degree=d) for d in (1, 2, 3, 4)]
    for prev, curr in zip(bounds, bounds[1:]):
        assert curr < prev


def test_is_negligible_threshold():
    n = 50
    bound = negligible_bound(n, poly_degree=2)
    assert is_negligible(bound - 1e-15, n, poly_degree=2)
    assert not is_negligible(bound, n, poly_degree=2)
    assert not is_negligible(bound + 1e-15, n, poly_degree=2)


def test_advantage_uniform_vs_biased_zero_delta():
    for n in (2, 8, 256):
        assert advantage_uniform_vs_biased(n, 0.0) == 0.0


def test_advantage_uniform_vs_biased_full_delta():
    assert math.isclose(advantage_uniform_vs_biased(4, 1.0), 0.75, abs_tol=1e-12)
    assert math.isclose(advantage_uniform_vs_biased(2, 1.0), 0.5, abs_tol=1e-12)


def test_estimate_advantage_identical_samples():
    dist = lambda x: x  # noqa: E731
    samples = [0, 1, 0, 1, 1, 0]
    assert estimate_advantage(dist, samples, samples) == 0.0


def test_estimate_advantage_disjoint_samples():
    dist = lambda x: x  # noqa: E731
    s0 = [0] * 100
    s1 = [1] * 100
    assert math.isclose(estimate_advantage(dist, s0, s1), 1.0, abs_tol=1e-12)


def test_estimate_advantage_constant_distinguisher():
    dist_always_1 = lambda x: 1  # noqa: E731
    s0 = [0, 1, 2, 3]
    s1 = [4, 5, 6, 7]
    assert estimate_advantage(dist_always_1, s0, s1) == 0.0


def test_run_ind_game_perfect_distinguisher():
    import random

    rng = random.Random(0)
    adv = run_ind_game(
        lambda: 0,
        lambda: 1,
        lambda x: x,
        5000,
        rng=rng,
    )
    assert adv > 0.95


def test_run_ind_game_random_distinguisher():
    import random

    rng = random.Random(1)
    rand_dist_rng = random.Random(2)
    adv = run_ind_game(
        lambda: rng.randint(0, 1),
        lambda: rng.randint(0, 1),
        lambda x: rand_dist_rng.randint(0, 1),
        10000,
        rng=rng,
    )
    assert adv < 0.1


def test_statistical_distance_upper_bound():
    assert statistical_distance_upper_bound(0.05) == 0.05
    assert statistical_distance_upper_bound(0.0) == 0.0
    assert statistical_distance_upper_bound(1.0) == 1.0


if __name__ == "__main__":
    test_vectors()
    test_advantage_bernoulli_symmetric()
    test_advantage_bernoulli_zero_for_equal()
    test_advantage_bernoulli_bounded()
    test_negligible_bound_decreasing_in_n()
    test_negligible_bound_decreasing_in_d()
    test_is_negligible_threshold()
    test_advantage_uniform_vs_biased_zero_delta()
    test_advantage_uniform_vs_biased_full_delta()
    test_estimate_advantage_identical_samples()
    test_estimate_advantage_disjoint_samples()
    test_estimate_advantage_constant_distinguisher()
    test_run_ind_game_perfect_distinguisher()
    test_run_ind_game_random_distinguisher()
    test_statistical_distance_upper_bound()
    print("all tests pass")
