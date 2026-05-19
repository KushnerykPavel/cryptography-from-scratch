import json
import random
import sys
from pathlib import Path


LESSON = Path(__file__).resolve().parents[1]
VECTORS_PATH = LESSON / "tests" / "vectors.json"

sys.path.insert(0, str(LESSON / "code"))
import main as sigma  # noqa: E402


def _params(vector) -> sigma.SchnorrParams:
    return sigma.SchnorrParams(p=vector["p"], q=vector["q"], g=vector["g"])


def call(vector):
    op = vector["op"]

    if op == "mod_inv":
        return sigma.mod_inv(vector["a"], vector["mod"])

    if op == "schnorr_public_key":
        return sigma.schnorr_public_key(_params(vector), vector["x"])
    if op == "schnorr_commit":
        return sigma.schnorr_commit(_params(vector), vector["r"])
    if op == "schnorr_response":
        return sigma.schnorr_response(vector["q"], vector["r"], vector["c"], vector["x"])
    if op == "schnorr_verify":
        params = _params(vector)
        return sigma.schnorr_verify(params, vector["y"], vector["a"], vector["c"], vector["s"])
    if op == "schnorr_simulate_hvz":
        params = _params(vector)
        t = sigma.schnorr_simulate_hvz(params, vector["y"], vector["c"], vector["s"])
        return {"commitment": t.commitment, "challenge": t.challenge, "response": t.response}
    if op == "schnorr_extract_witness":
        return sigma.schnorr_extract_witness(
            vector["q"], vector["c1"], vector["s1"], vector["c2"], vector["s2"]
        )

    raise AssertionError(f"unknown op: {op}")


def test_vectors():
    vectors = json.loads(VECTORS_PATH.read_text())["vectors"]
    for vector in vectors:
        if "expected_error" in vector:
            try:
                call(vector)
            except ValueError as error:
                assert str(error) == vector["expected_error"]
            else:
                raise AssertionError(f"{vector['op']} did not raise")
            continue

        assert call(vector) == vector["expected"]


def test_honest_proofs_verify():
    params = sigma.SchnorrParams(p=23, q=11, g=2)
    rng = random.Random(0)

    for _ in range(200):
        x = rng.randrange(0, params.q)
        r = rng.randrange(0, params.q)
        c = rng.randrange(0, params.q)
        y = sigma.schnorr_public_key(params, x)
        sigma.assert_schnorr_params(params, y)
        t = sigma.schnorr_prove(params, x, r, c)
        assert sigma.schnorr_verify(params, y, t.commitment, t.challenge, t.response)


def test_simulated_transcripts_verify():
    params = sigma.SchnorrParams(p=23, q=11, g=2)
    rng = random.Random(1)
    x = 7
    y = sigma.schnorr_public_key(params, x)
    sigma.assert_schnorr_params(params, y)

    for _ in range(200):
        c = rng.randrange(0, params.q)
        s = rng.randrange(0, params.q)
        t = sigma.schnorr_simulate_hvz(params, y, c, s)
        assert sigma.schnorr_verify(params, y, t.commitment, t.challenge, t.response)


def test_extractor_recovers_witness_from_two_transcripts():
    params = sigma.SchnorrParams(p=23, q=11, g=2)
    x = 3
    y = sigma.schnorr_public_key(params, x)
    sigma.assert_schnorr_params(params, y)

    r = 4
    a = sigma.schnorr_commit(params, r)
    c1, c2 = 1, 9
    s1 = sigma.schnorr_response(params.q, r, c1, x)
    s2 = sigma.schnorr_response(params.q, r, c2, x)

    assert sigma.schnorr_verify(params, y, a, c1, s1)
    assert sigma.schnorr_verify(params, y, a, c2, s2)
    extracted = sigma.schnorr_extract_witness(params.q, c1, s1, c2, s2)
    assert extracted == x


def test_param_validation_rejects_non_subgroup_elements():
    params = sigma.SchnorrParams(p=23, q=11, g=2)
    y_not_in_subgroup = 5
    try:
        sigma.assert_schnorr_params(params, y_not_in_subgroup)
    except ValueError as error:
        assert str(error) == "y is not in the subgroup of order q"
    else:
        raise AssertionError("expected subgroup-membership check to fail")


if __name__ == "__main__":
    test_vectors()
    test_honest_proofs_verify()
    test_simulated_transcripts_verify()
    test_extractor_recovers_witness_from_two_transcripts()
    test_param_validation_rejects_non_subgroup_elements()
    print("all tests pass")

