import json
import os
import random
import sys


HERE = os.path.dirname(__file__)
CODE_DIR = os.path.normpath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

from main import (  # noqa: E402
    OrCommitment,
    OrProver,
    OrResponse,
    SchnorrTranscript,
    inv_mod,
    or_extract_witness_from_two_transcripts,
    or_verify,
    schnorr_extract_witness,
    schnorr_simulate_commitment,
    schnorr_verify,
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
        elif op == "schnorr_verify":
            tr = SchnorrTranscript(**inputs["transcript"])
            out = schnorr_verify(p=inputs["p"], q=inputs["q"], g=inputs["g"], y=inputs["y"], transcript=tr)
        elif op == "schnorr_simulate_commitment":
            out = schnorr_simulate_commitment(
                p=inputs["p"], g=inputs["g"], y=inputs["y"], c=inputs["c"], s=inputs["s"]
            )
        elif op == "schnorr_extract_witness":
            tr1 = SchnorrTranscript(**inputs["transcript1"])
            tr2 = SchnorrTranscript(**inputs["transcript2"])
            out = schnorr_extract_witness(q=inputs["q"], transcript1=tr1, transcript2=tr2)
        elif op == "or_verify":
            com = OrCommitment(**inputs["commitment"])
            resp = OrResponse(**inputs["response"])
            out = or_verify(
                p=inputs["p"],
                q=inputs["q"],
                g=inputs["g"],
                y1=inputs["y1"],
                y2=inputs["y2"],
                commitment=com,
                challenge=inputs["challenge"],
                response=resp,
            )
        elif op == "or_extract_witness_from_two_transcripts":
            com = OrCommitment(**inputs["commitment"])
            resp1 = OrResponse(**inputs["response1"])
            resp2 = OrResponse(**inputs["response2"])
            out = list(
                or_extract_witness_from_two_transcripts(
                    p=inputs["p"],
                    q=inputs["q"],
                    g=inputs["g"],
                    y1=inputs["y1"],
                    y2=inputs["y2"],
                    commitment=com,
                    challenge1=inputs["challenge1"],
                    response1=resp1,
                    challenge2=inputs["challenge2"],
                    response2=resp2,
                )
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


def test_schnorr_extract_roundtrip():
    p, q, g = toy_group()
    rng = random.Random(0)
    for _ in range(200):
        x = rng.randrange(0, q)
        y = pow(g, x, p)
        r = rng.randrange(0, q)
        t = pow(g, r, p)

        c1 = rng.randrange(0, q)
        c2 = (c1 + 1 + rng.randrange(0, q - 1)) % q
        s1 = (r + c1 * x) % q
        s2 = (r + c2 * x) % q

        tr1 = SchnorrTranscript(t=t, c=c1, s=s1)
        tr2 = SchnorrTranscript(t=t, c=c2, s=s2)
        assert schnorr_verify(p=p, q=q, g=g, y=y, transcript=tr1)
        assert schnorr_verify(p=p, q=q, g=g, y=y, transcript=tr2)

        x_hat = schnorr_extract_witness(q=q, transcript1=tr1, transcript2=tr2)
        assert x_hat == x


def test_schnorr_extract_rejects_bad_inputs():
    _, q, _ = toy_group()
    tr1 = SchnorrTranscript(t=1, c=1, s=1)
    tr2 = SchnorrTranscript(t=2, c=2, s=2)
    try:
        schnorr_extract_witness(q=q, transcript1=tr1, transcript2=tr2)
    except ValueError as e:
        assert "same commitment" in str(e)
    else:
        raise AssertionError("expected ValueError")

    tr3 = SchnorrTranscript(t=1, c=1, s=1)
    tr4 = SchnorrTranscript(t=1, c=1, s=2)
    try:
        schnorr_extract_witness(q=q, transcript1=tr3, transcript2=tr4)
    except ValueError as e:
        assert "different challenges" in str(e)
    else:
        raise AssertionError("expected ValueError")


def test_or_extraction_extracts_real_branch():
    p, q, g = toy_group()
    x1 = 42
    x2 = 99
    y1 = pow(g, x1, p)
    y2 = pow(g, x2, p)

    prover = OrProver(p=p, q=q, g=g, y1=y1, y2=y2, x1=x1, x2=None, rng=random.Random(0))
    com = prover.commit()
    e1 = 7
    e2 = 8
    resp1 = prover.respond(e1)
    resp2 = prover.respond(e2)

    branch, witness = or_extract_witness_from_two_transcripts(
        p=p, q=q, g=g, y1=y1, y2=y2, commitment=com, challenge1=e1, response1=resp1, challenge2=e2, response2=resp2
    )
    assert branch == 1
    assert witness == x1


if __name__ == "__main__":
    test_vectors()
    test_inv_mod_properties()
    test_schnorr_extract_roundtrip()
    test_schnorr_extract_rejects_bad_inputs()
    test_or_extraction_extracts_real_branch()
    print("all tests pass")

