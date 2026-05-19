import json
import math
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (  # noqa: E402
    best_distinguisher_advantage,
    biased_bit_sd,
    is_statistically_close,
    sd_from_event_max,
    sd_to_uniform,
    statistical_distance,
    triangle_inequality_gap,
)


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]
        if op == "statistical_distance":
            got = statistical_distance(v["p"], v["q"])
            assert math.isclose(got, v["expected"], rel_tol=0, abs_tol=1e-12), v
        elif op == "biased_bit_sd":
            got = biased_bit_sd(v["epsilon"])
            assert math.isclose(got, v["expected"], rel_tol=0, abs_tol=1e-12), v
        else:
            raise AssertionError(f"unknown op {op}")


def test_symmetry():
    p = {"a": 0.5, "b": 0.3, "c": 0.2}
    q = {"a": 0.2, "b": 0.5, "c": 0.3}
    assert math.isclose(statistical_distance(p, q), statistical_distance(q, p), abs_tol=1e-12)


def test_identity_zero():
    p = {"a": 0.5, "b": 0.5}
    assert statistical_distance(p, p) == 0.0


def test_disjoint_support_is_one():
    p = {"a": 1.0}
    q = {"b": 1.0}
    assert math.isclose(statistical_distance(p, q), 1.0, abs_tol=1e-12)


def test_sd_equals_max_event_identity():
    p = {"a": 0.5, "b": 0.3, "c": 0.2}
    q = {"a": 0.2, "b": 0.5, "c": 0.3}
    assert math.isclose(statistical_distance(p, q), sd_from_event_max(p, q), abs_tol=1e-12)


def test_best_distinguisher_equals_sd():
    p = {0: 0.5, 1: 0.5}
    q = {0: 0.4, 1: 0.6}
    assert math.isclose(best_distinguisher_advantage(p, q), statistical_distance(p, q), abs_tol=1e-12)


def test_triangle_inequality_holds():
    p = {0: 0.5, 1: 0.5}
    q = {0: 0.4, 1: 0.6}
    r = {0: 0.45, 1: 0.55}
    assert triangle_inequality_gap(p, q, r) >= -1e-12


def test_sd_to_uniform_loaded_die():
    loaded = {1: 0.1, 2: 0.1, 3: 0.1, 4: 0.1, 5: 0.1, 6: 0.5}
    got = sd_to_uniform(loaded, [1, 2, 3, 4, 5, 6])
    assert math.isclose(got, 1 / 3, abs_tol=1e-12)


def test_is_statistically_close():
    p = {0: 0.5, 1: 0.5}
    q = {0: 0.4, 1: 0.6}
    assert is_statistically_close(p, q, epsilon=0.2)
    assert not is_statistically_close(p, q, epsilon=0.05)


def test_rejects_non_pmf():
    try:
        statistical_distance({"a": 0.5, "b": 0.4}, {"a": 0.5, "b": 0.5})
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for non-normalized input")


def test_biased_bit_rejects_out_of_range():
    try:
        biased_bit_sd(0.7)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for epsilon out of [-1/2, 1/2]")


if __name__ == "__main__":
    test_vectors()
    test_symmetry()
    test_identity_zero()
    test_disjoint_support_is_one()
    test_sd_equals_max_event_identity()
    test_best_distinguisher_equals_sd()
    test_triangle_inequality_holds()
    test_sd_to_uniform_loaded_die()
    test_is_statistically_close()
    test_rejects_non_pmf()
    test_biased_bit_rejects_out_of_range()
    print("all tests pass")
