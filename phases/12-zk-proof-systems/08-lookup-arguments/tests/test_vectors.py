import json
import os
import random
import sys


HERE = os.path.dirname(__file__)
CODE_DIR = os.path.normpath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

from main import (  # noqa: E402
    MODULUS,
    ToyLookupProof,
    compress_row,
    inv_mod,
    multiset_difference,
    poly_product_at,
    prove_lookup_membership,
    verify_lookup_membership,
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
            out = inv_mod(inputs["a"], inputs["p"])
        elif op == "multiset_difference":
            out = multiset_difference(inputs["table"], inputs["witness"])
        elif op == "poly_product_at":
            out = poly_product_at(inputs["roots"], inputs["x"], inputs["p"])
        elif op == "compress_row":
            out = compress_row(inputs["row"], inputs["theta"], inputs["p"])
        elif op == "prove_lookup_membership":
            proof = prove_lookup_membership(
                table=inputs["table"],
                witness=inputs["witness"],
                p=inputs["p"],
                label=inputs["label"],
            )
            out = proof.to_json()
        elif op == "verify_lookup_membership":
            proof = ToyLookupProof.from_json(inputs["proof"])
            out = verify_lookup_membership(table=inputs["table"], proof=proof, p=inputs["p"], label=inputs["label"])
        else:
            raise AssertionError(f"unknown op: {op!r}")

        assert out == expected, f"op={op} inputs={inputs} got={out} expected={expected}"


def test_multiset_difference_roundtrip():
    rng = random.Random(0)
    for _ in range(200):
        table = [rng.randrange(0, 50) for _ in range(rng.randrange(0, 20))]
        witness = []
        for x in table:
            if rng.random() < 0.4:
                witness.append(x)

        remainder = multiset_difference(table, witness)
        assert sorted(witness + remainder) == sorted(table)


def test_multiset_difference_rejects_missing_value():
    table = [1, 1, 2]
    witness = [1, 3]
    try:
        multiset_difference(table, witness)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_lookup_proof_accepts_and_rejects():
    rng = random.Random(0)
    for _ in range(100):
        table = [rng.randrange(0, 40) for _ in range(rng.randrange(0, 25))]

        witness = []
        for x in table:
            if rng.random() < 0.3:
                witness.append(x)

        proof = prove_lookup_membership(table=table, witness=witness)
        assert verify_lookup_membership(table=table, proof=proof)

        tampered = ToyLookupProof(
            witness=proof.witness,
            remainder=proof.remainder,
            r=proof.r,
            eval_witness=(proof.eval_witness + 1) % MODULUS,
            eval_remainder=proof.eval_remainder,
            commit_witness=proof.commit_witness,
            commit_remainder=proof.commit_remainder,
        )
        assert not verify_lookup_membership(table=table, proof=tampered)


def test_lookup_proof_rejects_non_member():
    table = [2, 4, 6, 8]
    witness = [2, 5]
    try:
        prove_lookup_membership(table=table, witness=witness)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_inv_mod_properties():
    rng = random.Random(0)
    for _ in range(200):
        a = rng.randrange(1, MODULUS)
        inv = inv_mod(a, MODULUS)
        assert (a * inv) % MODULUS == 1


def test_empty_witness_is_ok():
    table = [1, 2, 3]
    proof = prove_lookup_membership(table=table, witness=[])
    assert verify_lookup_membership(table=table, proof=proof)


if __name__ == "__main__":
    test_vectors()
    test_multiset_difference_roundtrip()
    test_multiset_difference_rejects_missing_value()
    test_lookup_proof_accepts_and_rejects()
    test_lookup_proof_rejects_non_member()
    test_inv_mod_properties()
    test_empty_witness_is_ok()
    print("all tests pass")

