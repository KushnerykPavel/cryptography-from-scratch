import json
import os
import random
import sys


HERE = os.path.dirname(__file__)
CODE_DIR = os.path.normpath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

from main import (  # noqa: E402
    default_toy_group,
    forge_opening_with_toxic_waste,
    kzg_commit,
    kzg_open,
    kzg_setup,
    kzg_trim,
    kzg_verify,
    mod_inv,
    poly_div_by_linear,
    poly_eval,
    pot_apply_updates,
)


def _load_vectors():
    path = os.path.join(HERE, "vectors.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def test_vectors():
    data = _load_vectors()
    group = default_toy_group()

    for case in data["vectors"]:
        op = case["op"]
        inputs = case["inputs"]
        expected = case["expected"]

        if op == "mod_inv":
            out = mod_inv(inputs["a"], inputs["m"])
        elif op == "poly_eval":
            out = poly_eval(inputs["coeffs"], inputs["x"], inputs["mod"])
        elif op == "poly_div_by_linear":
            q, r = poly_div_by_linear(inputs["coeffs"], inputs["x0"], inputs["mod"])
            out = {"quotient": q, "remainder": r}
        elif op == "kzg_commit":
            params = kzg_setup(inputs["max_degree"], inputs["tau"], group)
            out = kzg_commit(inputs["poly"], params)
        elif op == "kzg_open":
            params = kzg_setup(inputs["max_degree"], inputs["tau"], group)
            y, proof = kzg_open(inputs["poly"], inputs["x"], params)
            out = {"y": y, "proof": proof}
        elif op == "kzg_verify_open":
            params = kzg_setup(inputs["max_degree"], inputs["tau"], group)
            C = kzg_commit(inputs["poly"], params)
            y, proof = kzg_open(inputs["poly"], inputs["x"], params)
            out = kzg_verify(C, inputs["x"], y, proof, params)
        elif op == "kzg_forge_proof":
            params = kzg_setup(inputs["max_degree"], inputs["tau"], group)
            C = kzg_commit(inputs["poly"], params)
            out = forge_opening_with_toxic_waste(C, inputs["x"], inputs["y_fake"], inputs["tau"], params)
        elif op == "kzg_verify_forged":
            params = kzg_setup(inputs["max_degree"], inputs["tau"], group)
            C = kzg_commit(inputs["poly"], params)
            proof = forge_opening_with_toxic_waste(C, inputs["x"], inputs["y_fake"], inputs["tau"], params)
            out = kzg_verify(C, inputs["x"], inputs["y_fake"], proof, params)
        elif op == "pot_updated_commit":
            params = kzg_setup(inputs["max_degree"], inputs["tau"], group)
            params_u = pot_apply_updates(params, inputs["deltas"])
            out = kzg_commit(inputs["poly"], params_u)
        elif op == "pot_updated_open":
            params = kzg_setup(inputs["max_degree"], inputs["tau"], group)
            params_u = pot_apply_updates(params, inputs["deltas"])
            y, proof = kzg_open(inputs["poly"], inputs["x"], params_u)
            out = {"y": y, "proof": proof}
        elif op == "pot_updated_verify_open":
            params = kzg_setup(inputs["max_degree"], inputs["tau"], group)
            params_u = pot_apply_updates(params, inputs["deltas"])
            C = kzg_commit(inputs["poly"], params_u)
            y, proof = kzg_open(inputs["poly"], inputs["x"], params_u)
            out = kzg_verify(C, inputs["x"], y, proof, params_u)
        elif op == "trimmed_open_verify":
            params = kzg_setup(inputs["max_degree"], inputs["tau"], group)
            trimmed = kzg_trim(params, inputs["trim_degree"])
            C = kzg_commit(inputs["poly"], trimmed)
            y, proof = kzg_open(inputs["poly"], inputs["x"], trimmed)
            ok = kzg_verify(C, inputs["x"], y, proof, trimmed)
            out = {"commitment": C, "y": y, "proof": proof, "ok": ok}
        else:
            raise AssertionError(f"unknown op: {op!r}")

        assert out == expected, f"op={op} inputs={inputs} got={out} expected={expected}"


def test_poly_div_by_linear_matches_remainder_theorem():
    group = default_toy_group()
    rng = random.Random(0)
    for degree in range(0, 8):
        for _ in range(50):
            coeffs = [rng.randrange(group.q) for _ in range(degree + 1)]
            x0 = rng.randrange(group.q)
            q, r = poly_div_by_linear(coeffs, x0, group.q)
            assert r == poly_eval(coeffs, x0, group.q)
            if degree == 0:
                assert q == []


def test_kzg_open_verify_roundtrip_random():
    group = default_toy_group()
    rng = random.Random(0)
    params = kzg_setup(max_degree=6, tau=321, group=group)

    for degree in range(0, 7):
        for _ in range(50):
            coeffs = [rng.randrange(group.q) for _ in range(degree + 1)]
            x = rng.randrange(group.q)
            C = kzg_commit(coeffs, params)
            y, proof = kzg_open(coeffs, x, params)
            assert kzg_verify(C, x, y, proof, params)


def test_forgery_requires_correct_tau():
    group = default_toy_group()
    poly = [7, 3, 5]
    x = 11
    tau = 123
    params = kzg_setup(max_degree=4, tau=tau, group=group)
    C = kzg_commit(poly, params)
    y, _ = kzg_open(poly, x, params)
    y_fake = (y + 1) % group.q

    proof = forge_opening_with_toxic_waste(C, x, y_fake, tau=tau, params=params)
    assert kzg_verify(C, x, y_fake, proof, params)

    wrong = forge_opening_with_toxic_waste(C, x, y_fake, tau=(tau + 1) % group.q, params=params)
    assert not kzg_verify(C, x, y_fake, wrong, params)


def test_pot_updates_compose_by_multiplication():
    group = default_toy_group()
    tau = 123
    params = kzg_setup(max_degree=6, tau=tau, group=group)

    deltas1 = [17, 222]
    deltas2 = [501]
    combined = 1
    for d in deltas1 + deltas2:
        combined = (combined * (d % group.q)) % group.q

    a = pot_apply_updates(params, deltas1 + deltas2)
    b = pot_apply_updates(params, [combined])

    assert a.g1_powers_of_tau == b.g1_powers_of_tau
    assert a.g2_tau == b.g2_tau


if __name__ == "__main__":
    test_vectors()
    test_poly_div_by_linear_matches_remainder_theorem()
    test_kzg_open_verify_roundtrip_random()
    test_forgery_requires_correct_tau()
    test_pot_updates_compose_by_multiplication()
    print("all tests pass")

