import json
import os
import random
import sys


HERE = os.path.dirname(__file__)
CODE_DIR = os.path.normpath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

from main import (  # noqa: E402
    AndProof,
    OrProof,
    SchnorrProof,
    and_prove_nizk,
    and_verify_nizk,
    hash_to_scalar,
    inv_mod,
    or_prove_nizk,
    or_verify_nizk,
    schnorr_prove_nizk,
    schnorr_simulate_commitment,
    schnorr_verify_nizk,
    toy_group,
)


def _load_vectors():
    path = os.path.join(HERE, "vectors.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def test_vectors():
    data = _load_vectors()
    for case in data["vectors"]:
        op = case["op"]
        inputs = case["inputs"]
        expected = case["expected"]

        if op == "inv_mod":
            out = inv_mod(inputs["a"], inputs["m"])
        elif op == "schnorr_simulate_commitment":
            out = schnorr_simulate_commitment(
                p=inputs["p"], g=inputs["g"], y=inputs["y"], c=inputs["c"], s=inputs["s"]
            )
        elif op == "schnorr_verify_nizk":
            proof = SchnorrProof(**inputs["proof"])
            out = schnorr_verify_nizk(
                p=inputs["p"], q=inputs["q"], g=inputs["g"], y=inputs["y"], proof=proof, label=inputs["label"]
            )
        elif op == "and_verify_nizk":
            proof = AndProof(**inputs["proof"])
            out = and_verify_nizk(
                p=inputs["p"],
                q=inputs["q"],
                g=inputs["g"],
                y1=inputs["y1"],
                y2=inputs["y2"],
                proof=proof,
                label=inputs["label"],
            )
        elif op == "or_verify_nizk":
            proof = OrProof(**inputs["proof"])
            out = or_verify_nizk(
                p=inputs["p"],
                q=inputs["q"],
                g=inputs["g"],
                y1=inputs["y1"],
                y2=inputs["y2"],
                proof=proof,
                label=inputs["label"],
            )
        else:
            raise AssertionError(f"unknown op: {op!r}")

        assert out == expected, f"op={op} inputs={inputs} got={out} expected={expected}"


def test_inv_mod_properties():
    p, _, _ = toy_group()
    rng = random.Random(0)
    for _ in range(200):
        a = rng.randrange(1, p)
        inv = inv_mod(a, p)
        assert (a * inv) % p == 1


def test_schnorr_tamper_fails():
    p, q, g = toy_group()
    x = 42
    y = pow(g, x, p)
    rng = random.Random(0)
    proof = schnorr_prove_nizk(p=p, q=q, g=g, y=y, x=x, label="schnorr", rng=rng)
    assert schnorr_verify_nizk(p=p, q=q, g=g, y=y, proof=proof, label="schnorr")

    bad = SchnorrProof(t=proof.t, c=proof.c, s=(proof.s + 1) % q)
    assert not schnorr_verify_nizk(p=p, q=q, g=g, y=y, proof=bad, label="schnorr")


def test_and_or_binding_to_statement():
    p, q, g = toy_group()
    x1 = 42
    x2 = 99
    y1 = pow(g, x1, p)
    y2 = pow(g, x2, p)
    rng = random.Random(0)

    and_proof = and_prove_nizk(p=p, q=q, g=g, y1=y1, x1=x1, y2=y2, x2=x2, label="bind", rng=rng)
    assert and_verify_nizk(p=p, q=q, g=g, y1=y1, y2=y2, proof=and_proof, label="bind")
    assert not and_verify_nizk(p=p, q=q, g=g, y1=y2, y2=y1, proof=and_proof, label="bind")

    rng = random.Random(0)
    or_proof = or_prove_nizk(p=p, q=q, g=g, y1=y1, y2=y2, x1=x1, x2=None, label="bind", rng=rng)
    assert or_verify_nizk(p=p, q=q, g=g, y1=y1, y2=y2, proof=or_proof, label="bind")
    assert not or_verify_nizk(p=p, q=q, g=g, y1=y2, y2=y1, proof=or_proof, label="bind")


def test_hash_to_scalar_domain():
    _, q, _ = toy_group()
    a = hash_to_scalar(q, [b"demo", 1, 2, 3])
    b = hash_to_scalar(q, [b"demo", 1, 2, 4])
    assert 0 <= a < q
    assert 0 <= b < q
    assert a != b


if __name__ == "__main__":
    test_vectors()
    test_inv_mod_properties()
    test_schnorr_tamper_fails()
    test_and_or_binding_to_statement()
    test_hash_to_scalar_domain()
    print("all tests pass")

