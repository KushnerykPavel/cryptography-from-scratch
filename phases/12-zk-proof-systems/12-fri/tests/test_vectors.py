import json
import random
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "code"))

import main as fri  # noqa: E402


def _load_vectors():
    with open(ROOT / "tests" / "vectors.json", "r", encoding="utf-8") as f:
        data = json.load(f)
    assert "source" in data
    assert "vectors" in data
    return data["vectors"]


def _run_vector(vec):
    op = vec["op"]
    inputs = vec.get("inputs", {})
    expected = vec.get("expected")

    if op == "find_primitive_root":
        got = fri.find_primitive_root(inputs["p"])
    elif op == "get_root_of_unity":
        got = fri.get_root_of_unity(inputs["p"], inputs["n"])
    elif op == "roots_of_unity_domain":
        got = fri.roots_of_unity_domain(inputs["p"], inputs["n"])
    elif op == "mod_inv":
        got = fri.mod_inv(inputs["a"], inputs["p"])
    elif op == "poly_degree":
        got = fri.poly_degree(inputs["coeffs"])
    elif op == "poly_eval":
        got = fri.poly_eval(inputs["coeffs"], inputs["x"], inputs["p"])
    elif op == "poly_eval_all":
        got = fri.poly_eval_all(inputs["coeffs"], inputs["xs"], inputs["p"])
    elif op == "fri_fold_layer":
        got = fri.fri_fold_layer(inputs["evals"], inputs["beta"], inputs["p"])
    elif op == "challenges_from_seed":
        got = fri.challenges_from_seed(inputs["seed"], inputs["rounds"], inputs["p"])
    elif op == "expected_degree_after_fri_rounds":
        got = fri.expected_degree_after_fri_rounds(inputs["initial_degree"], inputs["rounds"])
    else:
        raise ValueError(f"unknown op: {op}")

    assert got == expected, {"op": op, "inputs": inputs, "got": got, "expected": expected}


def test_vectors():
    for vec in _load_vectors():
        _run_vector(vec)


def test_root_of_unity_order_constraints():
    p = 97
    n = 16
    omega = fri.get_root_of_unity(p, n)
    assert pow(omega, n, p) == 1
    assert pow(omega, n // 2, p) == p - 1


def test_mod_inv_roundtrip_random():
    p = 97
    rng = random.Random(1337)
    for _ in range(50):
        a = rng.randrange(1, p)
        inv = fri.mod_inv(a, p)
        assert (a * inv) % p == 1


def test_fri_fold_layer_length_halves():
    p = 97
    rng = random.Random(2026)
    for n in (2, 4, 8, 16, 32):
        evals = [rng.randrange(p) for _ in range(n)]
        beta = rng.randrange(1, p)
        folded = fri.fri_fold_layer(evals, beta, p)
        assert len(folded) == n // 2


def test_fri_fold_layer_rejects_odd_length():
    p = 97
    try:
        fri.fri_fold_layer([1, 2, 3], beta=5, p=p)
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_fri_fold_rounds_ends_with_single_value():
    p = 97
    n = 16
    coeffs = (3, 1, 4, 1, 5, 9)
    evals = fri.poly_eval_all(coeffs, fri.roots_of_unity_domain(p, n), p)
    betas = fri.challenges_from_seed("fri-demo-v1", rounds=4, p=p)
    layers = fri.fri_fold_rounds(evals, betas, p)
    assert len(layers) == 5
    assert len(layers[-1]) == 1


def test_expected_degree_after_fri_rounds_monotone():
    d = 23
    prev = d
    for r in range(1, 8):
        cur = fri.expected_degree_after_fri_rounds(d, r)
        assert cur <= prev
        prev = cur


def _run_all_tests_as_script():
    test_vectors()
    test_root_of_unity_order_constraints()
    test_mod_inv_roundtrip_random()
    test_fri_fold_layer_length_halves()
    test_fri_fold_layer_rejects_odd_length()
    test_fri_fold_rounds_ends_with_single_value()
    test_expected_degree_after_fri_rounds_monotone()
    print("all tests pass")


if __name__ == "__main__":
    _run_all_tests_as_script()

