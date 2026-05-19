import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (  # noqa: E402
    PedersenParams,
    check_pedersen_params,
    extract_log_g_h_from_double_opening,
    forge_opening_if_trapdoor_known,
    mod_inverse,
    pedersen_add_openings,
    pedersen_commit,
    pedersen_combine,
    pedersen_rerandomize,
    pedersen_verify,
    toy_params,
)


def params_from_vector(v):
    return PedersenParams(p=v["p"], q=v["q"], g=v["g"], h=v["h"])


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        if op == "mod_inverse":
            try:
                got = mod_inverse(v["a"], v["n"])
            except ValueError as exc:
                assert v.get("expected_error") == str(exc), (
                    f"mod_inverse wrong error: got {exc!s}, expected {v.get('expected_error')}"
                )
                continue
        elif op == "pedersen_commit":
            got = pedersen_commit(params_from_vector(v), v["m"], v["r"])
        elif op == "pedersen_verify":
            got = pedersen_verify(params_from_vector(v), v["c"], v["m"], v["r"])
        elif op == "pedersen_combine":
            got = pedersen_combine(params_from_vector(v), v["c1"], v["c2"])
        elif op == "pedersen_add_openings":
            got = pedersen_add_openings(
                params_from_vector(v), (v["m1"], v["r1"]), (v["m2"], v["r2"])
            )
            got = [got[0], got[1]]
        elif op == "pedersen_rerandomize":
            got = pedersen_rerandomize(params_from_vector(v), v["c"], v["delta_r"])
        elif op == "forge_opening_if_trapdoor_known":
            got = forge_opening_if_trapdoor_known(
                params_from_vector(v),
                v["m_from"],
                v["r_from"],
                v["m_target"],
                v["alpha"],
            )
        elif op == "extract_log_g_h_from_double_opening":
            got = extract_log_g_h_from_double_opening(
                v["q"], v["m1"], v["r1"], v["m2"], v["r2"]
            )
        else:
            raise AssertionError(f"unknown op {op}")

        assert "expected" in v, f"{op} missing expected result"
        assert got == v["expected"], f"{op} failed: got {got}, expected {v['expected']}"


def test_roundtrip_and_rejection():
    params, _ = toy_params()
    check_pedersen_params(params)

    for m in range(params.q):
        for r in range(params.q):
            c = pedersen_commit(params, m, r)
            assert pedersen_verify(params, c, m, r)

    try:
        pedersen_commit(params, params.q, 0)
        raise AssertionError("expected ValueError for m out of range")
    except ValueError as exc:
        assert str(exc) == "message m must be in Z_q"

    try:
        pedersen_commit(params, 0, params.q)
        raise AssertionError("expected ValueError for r out of range")
    except ValueError as exc:
        assert str(exc) == "blinding r must be in Z_q"


def test_hiding_distribution_for_toy_params():
    params, _ = toy_params()
    q = params.q

    sets = []
    for m in [0, 3, 7]:
        images = {pedersen_commit(params, m, r) for r in range(q)}
        assert len(images) == q
        sets.append(images)

    assert sets[0] == sets[1] == sets[2]


def test_homomorphism_and_rerandomization():
    params, alpha = toy_params()

    m1, r1 = 2, 7
    m2, r2 = 6, 4
    c1 = pedersen_commit(params, m1, r1)
    c2 = pedersen_commit(params, m2, r2)

    combined = pedersen_combine(params, c1, c2)
    m_sum, r_sum = pedersen_add_openings(params, (m1, r1), (m2, r2))
    direct = pedersen_commit(params, m_sum, r_sum)
    assert combined == direct

    c = pedersen_commit(params, 3, 5)
    c_rr = pedersen_rerandomize(params, c, 8)
    assert pedersen_verify(params, c_rr, 3, (5 + 8) % params.q)

    m_target = 9
    r_target = forge_opening_if_trapdoor_known(params, 3, 5, m_target, alpha)
    assert pedersen_verify(params, c, m_target, r_target)

    alpha_extracted = extract_log_g_h_from_double_opening(params.q, 3, 5, m_target, r_target)
    assert alpha_extracted == alpha


if __name__ == "__main__":
    test_vectors()
    test_roundtrip_and_rejection()
    test_hiding_distribution_for_toy_params()
    test_homomorphism_and_rerandomization()
    print("all tests pass")

