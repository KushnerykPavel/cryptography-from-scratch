import json
import os
import random
import sys


HERE = os.path.abspath(os.path.dirname(__file__))
CODE_DIR = os.path.abspath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as pinocchio  # noqa: E402


def _load_vectors():
    with open(os.path.join(HERE, "vectors.json"), "r", encoding="utf-8") as f:
        return json.load(f)


def _dispatch(op: str, inputs: dict):
    if op == "mod_inv":
        return pinocchio.mod_inv(inputs["a"], inputs["p"])
    if op == "poly_mul":
        return pinocchio.poly_mul(inputs["a"], inputs["b"], inputs["p"])
    if op == "poly_divmod":
        q, r = pinocchio.poly_divmod(inputs["numer"], inputs["denom"], inputs["p"])
        return {"quotient": q, "remainder": r}
    if op == "lagrange_interpolate":
        return pinocchio.lagrange_interpolate([tuple(pt) for pt in inputs["points"]], inputs["p"])
    if op == "vanishing_poly":
        return pinocchio.vanishing_poly(inputs["num_constraints"], inputs["p"])

    if op == "r1cs_is_satisfied_example":
        r1cs, witness = pinocchio.example_r1cs_x3_plus_x_plus_5_eq_35(inputs["p"])
        return pinocchio.r1cs_is_satisfied(r1cs, witness)
    if op == "qap_is_satisfied_example":
        r1cs, witness = pinocchio.example_r1cs_x3_plus_x_plus_5_eq_35(inputs["p"])
        qap = pinocchio.r1cs_to_qap(r1cs)
        return pinocchio.qap_is_satisfied(qap, witness)
    if op == "qap_is_satisfied_example_wrong_x":
        r1cs, witness = pinocchio.example_r1cs_x3_plus_x_plus_5_eq_35(inputs["p"])
        qap = pinocchio.r1cs_to_qap(r1cs)
        bad = list(witness)
        bad[1] = (bad[1] + 1) % inputs["p"]
        return pinocchio.qap_is_satisfied(qap, bad)
    if op == "pinocchio_toy_verify_example":
        r1cs, witness = pinocchio.example_r1cs_x3_plus_x_plus_5_eq_35(inputs["p"])
        qap = pinocchio.r1cs_to_qap(r1cs)
        proof = pinocchio.pinocchio_toy_prove(qap, witness, inputs["s"])
        return pinocchio.pinocchio_toy_verify(proof)

    raise ValueError(f"unknown op: {op}")


def test_vectors():
    data = _load_vectors()
    for vec in data["vectors"]:
        got = _dispatch(vec["op"], vec["inputs"])
        assert got == vec["expected"], (vec["op"], vec["inputs"], got, vec["expected"])


def test_mod_inv_roundtrip():
    p = 101
    for a in range(1, p):
        inv = pinocchio.mod_inv(a, p)
        assert (a * inv) % p == 1


def test_poly_divmod_roundtrip():
    p = 101
    rng = random.Random(0)
    for _ in range(200):
        deg_n = rng.randint(0, 8)
        deg_d = rng.randint(1, 6)

        numer = [rng.randrange(p) for _ in range(deg_n + 1)]
        denom = [rng.randrange(p) for _ in range(deg_d + 1)]
        if all(c % p == 0 for c in denom):
            denom[0] = 1
        if denom[-1] % p == 0:
            denom[-1] = 1

        q, r = pinocchio.poly_divmod(numer, denom, p)
        recomposed = pinocchio.poly_add(pinocchio.poly_mul(q, denom, p), r, p)
        assert recomposed == pinocchio._poly_trim(numer, p)

        if not (len(r) == 1 and r[0] % p == 0):
            assert len(r) < len(pinocchio._poly_trim(denom, p))


def test_vanishing_poly_roots():
    p = 101
    z = pinocchio.vanishing_poly(7, p)
    for x in range(1, 8):
        assert pinocchio.poly_eval(z, x, p) == 0
    assert pinocchio.poly_eval(z, 9, p) != 0


def test_r1cs_and_qap_agree_on_example():
    p = 101
    r1cs, witness = pinocchio.example_r1cs_x3_plus_x_plus_5_eq_35(p)
    qap = pinocchio.r1cs_to_qap(r1cs)
    assert pinocchio.r1cs_is_satisfied(r1cs, witness)
    assert pinocchio.qap_is_satisfied(qap, witness)


def test_bad_witness_fails_r1cs_and_qap():
    p = 101
    r1cs, witness = pinocchio.example_r1cs_x3_plus_x_plus_5_eq_35(p)
    qap = pinocchio.r1cs_to_qap(r1cs)
    bad = list(witness)
    bad[1] = (bad[1] + 1) % p
    assert not pinocchio.r1cs_is_satisfied(r1cs, bad)
    assert not pinocchio.qap_is_satisfied(qap, bad)


def test_toy_proof_verifies_and_forgery_possible():
    p = 101
    s = 42
    r1cs, witness = pinocchio.example_r1cs_x3_plus_x_plus_5_eq_35(p)
    qap = pinocchio.r1cs_to_qap(r1cs)
    proof = pinocchio.pinocchio_toy_prove(qap, witness, s)
    assert pinocchio.pinocchio_toy_verify(proof)

    forged = pinocchio.ToyProof(
        p=p,
        s=s,
        A_s=7,
        B_s=9,
        H_s=3,
        Z_s=proof.Z_s,
        C_s=(7 * 9 - 3 * proof.Z_s) % p,
    )
    assert pinocchio.pinocchio_toy_verify(forged)


if __name__ == "__main__":
    test_vectors()
    test_mod_inv_roundtrip()
    test_poly_divmod_roundtrip()
    test_vanishing_poly_roots()
    test_r1cs_and_qap_agree_on_example()
    test_bad_witness_fails_r1cs_and_qap()
    test_toy_proof_verifies_and_forgery_possible()
    print("all tests pass")

