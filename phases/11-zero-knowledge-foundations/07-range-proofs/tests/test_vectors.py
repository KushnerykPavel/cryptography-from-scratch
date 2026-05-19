import json
import os
import random
import sys


HERE = os.path.dirname(__file__)
CODE_DIR = os.path.normpath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

from main import (  # noqa: E402
    OrProof,
    RangeProof,
    SchnorrProof,
    bit_commitment_verify_nizk,
    combine_bit_commitments,
    compose_bits,
    decompose_bits,
    inv_mod,
    pedersen_commit,
    range_prove_nizk,
    range_verify_nizk,
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
        elif op == "pedersen_commit":
            out = pedersen_commit(p=inputs["p"], q=inputs["q"], g=inputs["g"], h=inputs["h"], m=inputs["m"], r=inputs["r"])
        elif op == "decompose_bits":
            out = decompose_bits(inputs["value"], inputs["n_bits"])
        elif op == "compose_bits":
            out = compose_bits(inputs["bits"])
        elif op == "combine_bit_commitments":
            out = combine_bit_commitments(p=inputs["p"], q=inputs["q"], bit_commitments=inputs["bit_commitments"])
        elif op == "bit_commitment_verify_nizk":
            proof = OrProof(**inputs["proof"])
            out = bit_commitment_verify_nizk(
                p=inputs["p"],
                q=inputs["q"],
                g=inputs["g"],
                h=inputs["h"],
                bit_commitment=inputs["bit_commitment"],
                proof=proof,
                label=inputs["label"],
            )
        elif op == "range_verify_nizk":
            link = SchnorrProof(**inputs["proof"]["link_proof"])
            bit_proofs = tuple(OrProof(**bp) for bp in inputs["proof"]["bit_proofs"])
            rp = RangeProof(
                n_bits=inputs["proof"]["n_bits"],
                bit_commitments=tuple(inputs["proof"]["bit_commitments"]),
                bit_proofs=bit_proofs,
                link_proof=link,
            )
            out = range_verify_nizk(
                p=inputs["p"],
                q=inputs["q"],
                g=inputs["g"],
                h=inputs["h"],
                commitment=inputs["commitment"],
                proof=rp,
                label=inputs["label"],
            )
        else:
            raise AssertionError(f"unknown op: {op!r}")

        assert out == expected, f"op={op} inputs={inputs} got={out} expected={expected}"


def test_bit_roundtrip():
    rng = random.Random(0)
    for n_bits in range(1, 8):
        for _ in range(50):
            v = rng.randrange(0, 1 << n_bits)
            bits = decompose_bits(v, n_bits)
            assert len(bits) == n_bits
            assert compose_bits(bits) == v


def test_pedersen_commit_rejects_out_of_range_message():
    p, q, g, h = toy_group()
    try:
        pedersen_commit(p=p, q=q, g=g, h=h, m=q, r=0)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_range_proof_accepts_and_rejects():
    p, q, g, h = toy_group()
    n_bits = 4
    rng = random.Random(0)
    for value in range(0, 1 << n_bits):
        rng_i = random.Random(rng.randrange(0, 1 << 30))
        commitment, proof = range_prove_nizk(p=p, q=q, g=g, h=h, value=value, n_bits=n_bits, label="t", rng=rng_i)
        assert range_verify_nizk(p=p, q=q, g=g, h=h, commitment=commitment, proof=proof, label="t")
        assert not range_verify_nizk(p=p, q=q, g=g, h=h, commitment=commitment, proof=proof, label="t2")


def test_range_proof_tamper_fails():
    p, q, g, h = toy_group()
    commitment, proof = range_prove_nizk(p=p, q=q, g=g, h=h, value=13, n_bits=4, label="tamper", rng=random.Random(0))
    assert range_verify_nizk(p=p, q=q, g=g, h=h, commitment=commitment, proof=proof, label="tamper")

    bit_proofs = list(proof.bit_proofs)
    last = bit_proofs[-1]
    bit_proofs[-1] = OrProof(t1=last.t1, t2=last.t2, c1=last.c1, c2=last.c2, s1=last.s1, s2=(last.s2 + 1) % q)
    bad = RangeProof(n_bits=proof.n_bits, bit_commitments=proof.bit_commitments, bit_proofs=tuple(bit_proofs), link_proof=proof.link_proof)
    assert not range_verify_nizk(p=p, q=q, g=g, h=h, commitment=commitment, proof=bad, label="tamper")


def test_inv_mod_properties():
    p, _, _, _ = toy_group()
    rng = random.Random(0)
    for _ in range(200):
        a = rng.randrange(1, p)
        inv = inv_mod(a, p)
        assert (a * inv) % p == 1


if __name__ == "__main__":
    test_vectors()
    test_bit_roundtrip()
    test_pedersen_commit_rejects_out_of_range_message()
    test_range_proof_accepts_and_rejects()
    test_range_proof_tamper_fails()
    test_inv_mod_properties()
    print("all tests pass")

