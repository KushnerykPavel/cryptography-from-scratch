import json
import os
import random
import sys


HERE = os.path.dirname(__file__)
CODE_DIR = os.path.join(HERE, "..", "code")
sys.path.insert(0, CODE_DIR)

import main as ipa  # noqa: E402


def _load_vectors():
    with open(os.path.join(HERE, "vectors.json"), "r", encoding="utf-8") as f:
        return json.load(f)


def _proof_from_dict(d):
    return ipa.InnerProductProof(Ls=list(d["Ls"]), Rs=list(d["Rs"]), a=int(d["a"]), b=int(d["b"]))


def test_vectors():
    data = _load_vectors()
    vectors = data["vectors"]
    assert isinstance(vectors, list)

    for case in vectors:
        op = case["op"]
        p = case.get("p", ipa.P)

        if op == "modinv":
            got = ipa.modinv(case["x"], p)
            assert got == case["expected"]
        elif op == "inner_product":
            got = ipa.inner_product(case["a"], case["b"], p)
            assert got == case["expected"]
        elif op == "msm":
            got = ipa.msm(case["scalars"], case["bases"], p)
            assert got == case["expected"]
        elif op == "commit_pprime":
            got = ipa.commit_pprime(case["a"], case["b"], case["G"], case["H"], case["Q"], p)
            assert got == case["expected"]
        elif op == "ipa_prove":
            label = case.get("transcript_label", "ipa-v1").encode("utf-8")
            P_prime, proof = ipa.ipa_prove(case["a"], case["b"], case["G"], case["H"], case["Q"], p, transcript_label=label)
            expected = case["expected"]
            assert P_prime == expected["P_prime"]
            assert proof == _proof_from_dict(expected["proof"])
        elif op == "ipa_verify":
            label = case.get("transcript_label", "ipa-v1").encode("utf-8")
            proof = _proof_from_dict(case["proof"])
            got = ipa.ipa_verify(case["P_prime"], case["G"], case["H"], case["Q"], proof, p, transcript_label=label)
            assert got == case["expected"]
        else:
            raise AssertionError(f"unknown op: {op}")


def test_properties_and_edge_cases():
    rng = random.Random(0)
    p = ipa.P

    for _ in range(256):
        x = rng.randrange(1, p)
        inv = ipa.modinv(x, p)
        assert (x * inv) % p == 1

    a, b, G, H, Q = ipa.demo_instance(p)
    P_prime, proof = ipa.ipa_prove(a, b, G, H, Q, p)
    assert ipa.ipa_verify(P_prime, G, H, Q, proof, p)

    tampered = ipa.InnerProductProof(Ls=[(proof.Ls[0] + 1) % p] + proof.Ls[1:], Rs=proof.Rs, a=proof.a, b=proof.b)
    assert not ipa.ipa_verify(P_prime, G, H, Q, tampered, p)

    try:
        ipa.inner_product([1, 2], [3], p)
        raise AssertionError("expected inner_product length mismatch")
    except ValueError:
        pass

    try:
        ipa.ipa_prove([1, 2, 3], [4, 5, 6], [7, 8, 9], [1, 2, 3], Q, p)
        raise AssertionError("expected non-power-of-two error")
    except ValueError:
        pass


if __name__ == "__main__":
    test_vectors()
    test_properties_and_edge_cases()
    print("all tests pass")

