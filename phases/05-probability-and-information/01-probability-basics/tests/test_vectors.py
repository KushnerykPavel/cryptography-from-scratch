import json
import math
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (  # noqa: E402
    bayes_posterior,
    condition_pmf,
    conditional_probability,
    distinguishing_advantage,
    is_independent,
    pmf_from_counts,
    prob_event,
    union_bound,
)


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]
        if op == "conditional_probability":
            got = conditional_probability(v["p_a_and_b"], v["p_b"])
            assert math.isclose(got, v["expected"], rel_tol=0, abs_tol=1e-12)
        elif op == "union_bound":
            got = union_bound(v["probs"])
            assert math.isclose(got, v["expected"], rel_tol=0, abs_tol=1e-12)
        elif op == "distinguishing_advantage":
            got = distinguishing_advantage(v["p_real"], v["p_ideal"])
            assert math.isclose(got, v["expected"], rel_tol=0, abs_tol=1e-12)
        elif op == "bayes_posterior":
            got = bayes_posterior(
                prior=v["prior"],
                likelihood=v["likelihood"],
                false_positive_rate=v["false_positive_rate"],
            )
            assert math.isclose(got, v["expected"], rel_tol=0, abs_tol=1e-12)
        else:
            raise AssertionError(f"unknown op {op}")


def test_condition_pmf_die_given_even():
    die = pmf_from_counts({1: 1, 2: 1, 3: 1, 4: 1, 5: 1, 6: 1})
    p_even = prob_event(die, lambda x: x % 2 == 0)
    assert math.isclose(p_even, 0.5, rel_tol=0, abs_tol=1e-12)

    die_given_even = condition_pmf(die, lambda x: x % 2 == 0)
    assert set(die_given_even.keys()) == {2, 4, 6}
    assert math.isclose(sum(die_given_even.values()), 1.0, rel_tol=0, abs_tol=1e-12)
    assert math.isclose(die_given_even[2], 1 / 3, rel_tol=0, abs_tol=1e-12)
    assert math.isclose(die_given_even[4], 1 / 3, rel_tol=0, abs_tol=1e-12)
    assert math.isclose(die_given_even[6], 1 / 3, rel_tol=0, abs_tol=1e-12)


def test_is_independent_examples():
    assert is_independent(0.25, 0.5, 0.5)
    assert not is_independent(0.5, 0.5, 0.5)


def test_pmf_from_counts_rejects_all_zero():
    try:
        pmf_from_counts({"a": 0, "b": 0})
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for all-zero counts")


def test_conditional_probability_rejects_zero_denominator():
    try:
        conditional_probability(0.1, 0.0)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for P(B)=0")


if __name__ == "__main__":
    test_vectors()
    test_condition_pmf_die_given_even()
    test_is_independent_examples()
    test_pmf_from_counts_rejects_all_zero()
    test_conditional_probability_rejects_zero_denominator()
    print("all tests pass")

