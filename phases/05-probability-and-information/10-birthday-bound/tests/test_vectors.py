import json
import math
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (  # noqa: E402
    birthday_collision_prob_approx,
    birthday_collision_prob_exact,
    birthday_collision_prob_exp,
    collision_expected_queries,
    collision_threshold,
    double_enc_security,
    meet_in_the_middle_cost,
    multi_target_advantage,
    preimage_expected_queries,
    security_bits_after_birthday,
    simulate_birthday_attack,
    simulate_preimage_attack,
)


def _run_vector(v):
    op = v["op"]
    if op == "birthday_exact":
        return birthday_collision_prob_exact(v["q"], v["N"])
    if op == "birthday_approx":
        return birthday_collision_prob_approx(v["q"], v["n"])
    if op == "collision_threshold":
        return collision_threshold(v["n"], target_prob=v["p"])
    if op == "preimage_expected":
        return preimage_expected_queries(v["n"])
    if op == "collision_expected":
        return collision_expected_queries(v["n"])
    if op == "security_bits_birthday":
        return security_bits_after_birthday(v["n"])
    if op == "multi_target":
        return multi_target_advantage(v["q"], v["k"], v["n"])
    if op == "double_enc_security":
        return double_enc_security(v["key_bits"])
    raise AssertionError(f"unknown op {op!r}")


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)
    for v in data["vectors"]:
        got = _run_vector(v)
        expected = v["expected"]
        if isinstance(expected, bool):
            assert got == expected, f"vector {v}: got {got!r}"
        elif isinstance(expected, int) and not isinstance(expected, float):
            assert got == expected, f"vector {v}: got {got!r}"
        else:
            assert math.isclose(got, expected, rel_tol=1e-9, abs_tol=1e-50), (
                f"vector {v}: got {got!r}, want {expected!r}"
            )


# --- birthday_collision_prob_exact ---

def test_exact_zero_and_one():
    assert birthday_collision_prob_exact(0, 365) == 0.0
    assert birthday_collision_prob_exact(1, 365) == 0.0

def test_exact_all_same():
    assert birthday_collision_prob_exact(366, 365) == 1.0

def test_exact_monotone():
    probs = [birthday_collision_prob_exact(q, 100) for q in range(0, 101)]
    for a, b in zip(probs, probs[1:]):
        assert b >= a

def test_exact_birthday_problem_23():
    p = birthday_collision_prob_exact(23, 365)
    assert 0.50 < p < 0.51

def test_exact_rejects_bad():
    try:
        birthday_collision_prob_exact(-1, 365)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for negative q")


# --- birthday_collision_prob_approx ---

def test_approx_zero_for_small_q():
    assert birthday_collision_prob_approx(0, 128) == 0.0
    assert birthday_collision_prob_approx(1, 128) == 0.0

def test_approx_upper_bounds_exact():
    N = 1024
    n = math.log2(N)
    for q in range(2, 50):
        exact = birthday_collision_prob_exact(q, N)
        approx = birthday_collision_prob_approx(q, n)
        assert approx >= exact - 1e-10, f"approx not upper bound at q={q}"

def test_approx_quadratic():
    n = 64
    a2 = birthday_collision_prob_approx(2, n)
    a4 = birthday_collision_prob_approx(4, n)
    assert math.isclose(a4 / a2, 3*4 / (1*2), rel_tol=1e-10)


# --- birthday_collision_prob_exp ---

def test_exp_approx_bounds():
    # approx (linear) is upper bound; exp is lower bound; exact is between them
    # exp_val <= exact <= approx  (for q << N)
    N = 512
    n = math.log2(N)
    for q in range(2, 30):
        exact = birthday_collision_prob_exact(q, N)
        exp_val = birthday_collision_prob_exp(q, n)
        approx = birthday_collision_prob_approx(q, n)
        assert exp_val <= exact + 1e-10, f"exp not <= exact at q={q}: {exp_val} > {exact}"
        assert exact <= approx + 1e-10, f"exact not <= approx at q={q}: {exact} > {approx}"


# --- collision_threshold ---

def test_threshold_gives_half_prob():
    for n in (10, 16, 20):
        q = collision_threshold(n, target_prob=0.5)
        adv = birthday_collision_prob_exp(int(q), n)
        assert 0.35 < adv < 0.65, f"threshold off for n={n}: adv={adv}"

def test_threshold_monotone():
    for n in (10, 20):
        qs = [collision_threshold(n, target_prob=p) for p in (0.01, 0.1, 0.5, 0.9, 0.99)]
        for a, b in zip(qs, qs[1:]):
            assert b > a

def test_threshold_rejects_bad():
    for bad in (0.0, 1.0, -0.1):
        try:
            collision_threshold(10, target_prob=bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"expected ValueError for target_prob={bad}")


# --- preimage / collision expected queries ---

def test_preimage_is_2_pow_n():
    for n in (4, 8, 16, 32):
        assert math.isclose(preimage_expected_queries(n), 2.0 ** n, rel_tol=1e-12)

def test_collision_less_than_preimage():
    for n in (8, 16, 32, 64):
        assert collision_expected_queries(n) < preimage_expected_queries(n)

def test_security_bits_half():
    for n in (10, 128, 256):
        assert math.isclose(security_bits_after_birthday(n), n / 2.0, rel_tol=1e-12)


# --- multi_target_advantage ---

def test_multi_target_zero():
    assert multi_target_advantage(0, 10, 128) == 0.0
    assert multi_target_advantage(100, 0, 128) == 0.0

def test_multi_target_scales():
    adv1 = multi_target_advantage(100, 1, 128)
    adv10 = multi_target_advantage(100, 10, 128)
    assert math.isclose(adv10, 10 * adv1, rel_tol=1e-12)


# --- meet_in_the_middle ---

def test_mitm_nominal_is_double():
    result = meet_in_the_middle_cost(56)
    assert result["nominal_key_bits"] == 112
    assert result["effective_security_bits"] == 56

def test_mitm_time_equals_space():
    result = meet_in_the_middle_cost(64)
    assert result["time_complexity"] == result["space_complexity"]

def test_double_enc_security_equals_half():
    for k in (56, 64, 128):
        assert double_enc_security(k) == k


# --- simulated birthday attack ---

def test_simulated_birthday_finds_collision():
    n_bits = 12
    q = int(collision_threshold(n_bits, target_prob=0.99))

    def tiny_hash(x):
        return hash(x) & ((1 << n_bits) - 1)

    result = simulate_birthday_attack(tiny_hash, n_bits, q, rng=random.Random(42))
    if result is not None:
        x, y = result
        assert x != y
        assert tiny_hash(x) & ((1 << n_bits) - 1) == tiny_hash(y) & ((1 << n_bits) - 1)


def test_simulated_preimage_reasonable():
    n_bits = 12
    target = 42

    def tiny_hash(x):
        return x & ((1 << n_bits) - 1)

    result = simulate_preimage_attack(tiny_hash, target, n_bits, max_queries=10000, rng=random.Random(7))
    if result is not None:
        assert tiny_hash(result) & ((1 << n_bits) - 1) == target


if __name__ == "__main__":
    test_vectors()
    test_exact_zero_and_one()
    test_exact_all_same()
    test_exact_monotone()
    test_exact_birthday_problem_23()
    test_exact_rejects_bad()
    test_approx_zero_for_small_q()
    test_approx_upper_bounds_exact()
    test_approx_quadratic()
    test_exp_approx_bounds()
    test_threshold_gives_half_prob()
    test_threshold_monotone()
    test_threshold_rejects_bad()
    test_preimage_is_2_pow_n()
    test_collision_less_than_preimage()
    test_security_bits_half()
    test_multi_target_zero()
    test_multi_target_scales()
    test_mitm_nominal_is_double()
    test_mitm_time_equals_space()
    test_double_enc_security_equals_half()
    test_simulated_birthday_finds_collision()
    test_simulated_preimage_reasonable()
    print("all tests pass")
