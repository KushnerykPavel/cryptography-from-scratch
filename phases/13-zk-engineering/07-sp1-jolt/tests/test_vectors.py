import json
import os
import random
import sys


HERE = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(HERE, "..", "code"))
sys.path.append(CODE_DIR)

import main as sp1_jolt  # noqa: E402


def _load_vectors():
    path = os.path.join(HERE, "vectors.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def test_vectors():
    data = _load_vectors()
    assert "vectors" in data and isinstance(data["vectors"], list)

    for v in data["vectors"]:
        op = v["op"]
        inputs = v.get("inputs", {})
        expected = v["expected"]

        if op == "next_power_of_two":
            got = sp1_jolt.next_power_of_two(inputs["n"])
            assert got == expected
        elif op == "pad_to_pow2":
            got = sp1_jolt.pad_to_pow2(inputs["values"], inputs.get("pad_value", 0))
            assert got == expected
        elif op == "fib_trace_last":
            trace = sp1_jolt.fib_trace(inputs["a0"], inputs["a1"], inputs["steps"], sp1_jolt.FIELD_PRIME)
            got = list(trace[-1])
            assert got == expected
        elif op == "fib_transition_violations":
            got = [list(x) for x in sp1_jolt.fib_transition_violations(inputs["trace"], sp1_jolt.FIELD_PRIME)]
            assert got == expected
        elif op == "combine_violations":
            got = sp1_jolt.combine_violations(inputs["violations"], inputs["alpha"], sp1_jolt.FIELD_PRIME)
            assert got == expected
        elif op == "geometric_weights":
            got = sp1_jolt.geometric_weights(inputs["values"], inputs["gamma"], sp1_jolt.FIELD_PRIME)
            assert got == expected
        elif op == "mle_eval":
            got = sp1_jolt.mle_eval(inputs["evals"], inputs["r"], sp1_jolt.FIELD_PRIME)
            assert got == expected
        elif op == "sumcheck_proof":
            tr = sp1_jolt.Transcript(inputs["transcript_label"])
            for lab, s in inputs.get("transcript_preamble", []):
                tr.append(lab, s.encode("utf-8"))

            proof, r = sp1_jolt.sumcheck_prove_multilinear(
                inputs["evals"], inputs["claimed_sum"], tr, sp1_jolt.FIELD_PRIME
            )
            assert proof.round_evals == [tuple(x) for x in expected["round_evals"]]
            assert r == expected["r"]
            assert sp1_jolt.mle_eval(inputs["evals"], r, sp1_jolt.FIELD_PRIME) == expected["final_eval"]

            vr = sp1_jolt.Transcript(inputs["transcript_label"])
            for lab, s in inputs.get("transcript_preamble", []):
                vr.append(lab, s.encode("utf-8"))

            assert sp1_jolt.sumcheck_verify_multilinear(
                inputs["evals"], inputs["claimed_sum"], proof, vr, sp1_jolt.FIELD_PRIME
            )
        else:
            raise AssertionError(f"unknown op: {op}")


def test_mle_eval_recovers_vertices():
    p = sp1_jolt.FIELD_PRIME
    rng = random.Random(2026)
    n = 5
    evals = [rng.randrange(0, p) for _ in range(2**n)]
    for idx in range(2**n):
        r = [(idx >> i) & 1 for i in range(n)]
        assert sp1_jolt.mle_eval(evals, r, p) == evals[idx] % p


def test_sumcheck_accepts_and_rejects():
    p = sp1_jolt.FIELD_PRIME
    rng = random.Random(1337)
    evals = [rng.randrange(0, p) for _ in range(32)]
    claimed_sum = sum(evals) % p

    tr = sp1_jolt.Transcript("prop_sumcheck")
    tr.append("bind", b"demo")
    proof, _r = sp1_jolt.sumcheck_prove_multilinear(evals, claimed_sum, tr, p)

    vr_ok = sp1_jolt.Transcript("prop_sumcheck")
    vr_ok.append("bind", b"demo")
    assert sp1_jolt.sumcheck_verify_multilinear(evals, claimed_sum, proof, vr_ok, p)

    vr_bad_claim = sp1_jolt.Transcript("prop_sumcheck")
    vr_bad_claim.append("bind", b"demo")
    assert not sp1_jolt.sumcheck_verify_multilinear(evals, (claimed_sum + 1) % p, proof, vr_bad_claim, p)

    proof_bad = sp1_jolt.SumcheckProof(round_evals=proof.round_evals[:])
    s0, s1 = proof_bad.round_evals[0]
    proof_bad.round_evals[0] = ((s0 + 1) % p, s1)
    vr_bad_proof = sp1_jolt.Transcript("prop_sumcheck")
    vr_bad_proof.append("bind", b"demo")
    assert not sp1_jolt.sumcheck_verify_multilinear(evals, claimed_sum, proof_bad, vr_bad_proof, p)


if __name__ == "__main__":
    test_vectors()
    test_mle_eval_recovers_vertices()
    test_sumcheck_accepts_and_rejects()
    print("all tests pass")

