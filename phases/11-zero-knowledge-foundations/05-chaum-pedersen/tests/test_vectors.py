import json
import random
import sys
from pathlib import Path


LESSON = Path(__file__).resolve().parents[1]
VECTORS_PATH = LESSON / "tests" / "vectors.json"

sys.path.insert(0, str(LESSON / "code"))
import main as cp  # noqa: E402


def _params(vector) -> cp.ChaumPedersenParams:
    return cp.ChaumPedersenParams(
        p=vector["p"],
        q=vector["q"],
        g=vector["g"],
        h=vector["h"],
    )


def call(vector):
    op = vector["op"]

    if op == "mod_inv":
        return cp.mod_inv(vector["a"], vector["mod"])

    if op == "cp_publics":
        y1, y2 = cp.chaum_pedersen_publics(_params(vector), vector["x"])
        return {"y1": y1, "y2": y2}
    if op == "cp_commit":
        a1, a2 = cp.chaum_pedersen_commit(_params(vector), vector["r"])
        return {"a1": a1, "a2": a2}
    if op == "cp_response":
        return cp.chaum_pedersen_response(vector["q"], vector["r"], vector["c"], vector["x"])
    if op == "cp_verify":
        params = _params(vector)
        return cp.chaum_pedersen_verify(
            params,
            vector["y1"],
            vector["y2"],
            vector["a1"],
            vector["a2"],
            vector["c"],
            vector["s"],
        )
    if op == "cp_simulate_hvz":
        params = _params(vector)
        t = cp.chaum_pedersen_simulate_hvz(
            params, vector["y1"], vector["y2"], vector["c"], vector["s"]
        )
        return {
            "commitment_g": t.commitment_g,
            "commitment_h": t.commitment_h,
            "challenge": t.challenge,
            "response": t.response,
        }
    if op == "cp_extract_witness":
        return cp.chaum_pedersen_extract_witness(
            vector["q"], vector["c1"], vector["s1"], vector["c2"], vector["s2"]
        )
    if op == "cp_fiat_shamir_challenge":
        params = cp.ChaumPedersenParams(p=vector["ints"][0], q=vector["ints"][1], g=vector["ints"][2], h=vector["ints"][3])
        y1, y2, a1, a2 = vector["ints"][4], vector["ints"][5], vector["ints"][6], vector["ints"][7]
        return cp.chaum_pedersen_fiat_shamir_challenge(params, y1, y2, a1, a2, vector["domain"])

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
    params = cp.ChaumPedersenParams(p=23, q=11, g=2, h=6)
    rng = random.Random(0)

    for _ in range(200):
        x = rng.randrange(0, params.q)
        y1, y2 = cp.chaum_pedersen_publics(params, x)
        cp.assert_chaum_pedersen_params(params, y1, y2)

        r = rng.randrange(0, params.q)
        c = rng.randrange(0, params.q)
        a1, a2 = cp.chaum_pedersen_commit(params, r)
        s = cp.chaum_pedersen_response(params.q, r, c, x)
        assert cp.chaum_pedersen_verify(params, y1, y2, a1, a2, c, s)


def test_simulated_transcripts_verify():
    params = cp.ChaumPedersenParams(p=23, q=11, g=2, h=6)
    rng = random.Random(1)
    x = 7
    y1, y2 = cp.chaum_pedersen_publics(params, x)
    cp.assert_chaum_pedersen_params(params, y1, y2)

    for _ in range(200):
        c = rng.randrange(0, params.q)
        s = rng.randrange(0, params.q)
        t = cp.chaum_pedersen_simulate_hvz(params, y1, y2, c, s)
        assert cp.chaum_pedersen_verify(
            params, y1, y2, t.commitment_g, t.commitment_h, t.challenge, t.response
        )


def test_extractor_recovers_witness_from_two_transcripts():
    params = cp.ChaumPedersenParams(p=23, q=11, g=2, h=6)
    x = 3
    y1, y2 = cp.chaum_pedersen_publics(params, x)
    cp.assert_chaum_pedersen_params(params, y1, y2)

    r = 4
    a1, a2 = cp.chaum_pedersen_commit(params, r)
    c1, c2 = 1, 9
    s1 = cp.chaum_pedersen_response(params.q, r, c1, x)
    s2 = cp.chaum_pedersen_response(params.q, r, c2, x)

    assert cp.chaum_pedersen_verify(params, y1, y2, a1, a2, c1, s1)
    assert cp.chaum_pedersen_verify(params, y1, y2, a1, a2, c2, s2)
    extracted = cp.chaum_pedersen_extract_witness(params.q, c1, s1, c2, s2)
    assert extracted == x


def test_fiat_shamir_proofs_verify_and_bind_statement():
    params = cp.ChaumPedersenParams(p=23, q=11, g=2, h=6)
    domain = "CPv1"
    rng = random.Random(2)

    for _ in range(200):
        x = rng.randrange(0, params.q)
        y1, y2 = cp.chaum_pedersen_publics(params, x)
        cp.assert_chaum_pedersen_params(params, y1, y2)

        r = rng.randrange(0, params.q)
        a1, a2 = cp.chaum_pedersen_commit(params, r)
        c = cp.chaum_pedersen_fiat_shamir_challenge(params, y1, y2, a1, a2, domain)
        s = cp.chaum_pedersen_response(params.q, r, c, x)

        assert cp.chaum_pedersen_verify_fiat_shamir(params, y1, y2, a1, a2, s, domain)


def test_fiat_shamir_tampering_breaks_for_fixed_example():
    params = cp.ChaumPedersenParams(p=23, q=11, g=2, h=6)
    domain = "CPv1"
    x = 7
    r = 4

    y1, y2 = cp.chaum_pedersen_publics(params, x)
    a1, a2 = cp.chaum_pedersen_commit(params, r)
    c = cp.chaum_pedersen_fiat_shamir_challenge(params, y1, y2, a1, a2, domain)
    s = cp.chaum_pedersen_response(params.q, r, c, x)
    assert cp.chaum_pedersen_verify_fiat_shamir(params, y1, y2, a1, a2, s, domain)

    y1_tampered = (y1 * 2) % params.p
    assert not cp.chaum_pedersen_verify_fiat_shamir(params, y1_tampered, y2, a1, a2, s, domain)


def test_param_validation_rejects_non_subgroup_elements():
    params = cp.ChaumPedersenParams(p=23, q=11, g=2, h=6)
    y1, y2 = cp.chaum_pedersen_publics(params, 3)
    cp.assert_chaum_pedersen_params(params, y1, y2)

    y1_not_in_subgroup = 5
    try:
        cp.assert_chaum_pedersen_params(params, y1_not_in_subgroup, y2)
    except ValueError as error:
        assert str(error) == "y1 is not in the subgroup of order q"
    else:
        raise AssertionError("expected subgroup-membership check to fail")


if __name__ == "__main__":
    test_vectors()
    test_honest_proofs_verify()
    test_simulated_transcripts_verify()
    test_extractor_recovers_witness_from_two_transcripts()
    test_fiat_shamir_proofs_verify_and_bind_statement()
    test_fiat_shamir_tampering_breaks_for_fixed_example()
    test_param_validation_rejects_non_subgroup_elements()
    print("all tests pass")
