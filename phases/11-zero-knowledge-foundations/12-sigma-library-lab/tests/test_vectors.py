import json
import sys
from pathlib import Path

try:
    import pytest  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    pytest = None


THIS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(THIS_DIR.parent / "code"))

import main as lab  # noqa: E402


def _load_vectors() -> dict:
    path = THIS_DIR / "vectors.json"
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _params_from_inputs(inputs: dict) -> lab.SchnorrParams:
    return lab.SchnorrParams(p=inputs["p"], q=inputs["q"], g=inputs["g"])


def _assert_raises(exc_type, fn, /, *args, **kwargs):
    if pytest is not None:
        with pytest.raises(exc_type):
            fn(*args, **kwargs)
        return
    try:
        fn(*args, **kwargs)
    except exc_type:
        return
    except Exception as e:  # noqa: BLE001
        raise AssertionError(f"expected {exc_type.__name__}, got {type(e).__name__}") from e
    raise AssertionError(f"expected {exc_type.__name__} to be raised")


def test_vectors() -> None:
    data = _load_vectors()
    assert isinstance(data["source"], str)
    assert isinstance(data["vectors"], list)

    for v in data["vectors"]:
        op = v["op"]
        inputs = v["inputs"]

        if op == "mod_inv":
            got = lab.mod_inv(inputs["a"], inputs["mod"])
            assert got == v["expected"]
            continue

        if op == "schnorr_public_key":
            params = _params_from_inputs(inputs)
            got = lab.schnorr_public_key(params, inputs["x"])
            assert got == v["expected"]
            continue

        if op == "schnorr_prove":
            params = _params_from_inputs(inputs)
            rng = lab.DeterministicRNG(bytes.fromhex(inputs["rng_seed_hex"]))
            got = lab.schnorr_prove(params, inputs["x"], c=inputs["c"], rng=rng)
            assert {
                "commitment": got.commitment,
                "challenge": got.challenge,
                "response": got.response,
            } == v["expected"]
            continue

        if op == "schnorr_verify":
            params = _params_from_inputs(inputs)
            got = lab.schnorr_verify(params, inputs["y"], inputs["a"], inputs["c"], inputs["s"])
            assert got == v["expected"]
            continue

        if op == "schnorr_simulate_hvz":
            params = _params_from_inputs(inputs)
            got = lab.schnorr_simulate_hvz(params, inputs["y"], inputs["c"], inputs["s"])
            assert {
                "commitment": got.commitment,
                "challenge": got.challenge,
                "response": got.response,
            } == v["expected"]
            assert lab.schnorr_verify(params, inputs["y"], got.commitment, got.challenge, got.response) is True
            continue

        if op == "schnorr_extract_witness":
            got = lab.schnorr_extract_witness(
                inputs["q"], inputs["c1"], inputs["s1"], inputs["c2"], inputs["s2"]
            )
            assert got == v["expected"]
            continue

        if op == "fiat_shamir_challenge":
            items = [(k, int(vv)) for k, vv in inputs["items"]]
            got = lab.fiat_shamir_challenge(inputs["q"], domain_sep=inputs["domain_sep"], items=items)
            assert got == v["expected"]
            continue

        if op == "schnorr_prove_fs":
            params = _params_from_inputs(inputs)
            rng = lab.DeterministicRNG(bytes.fromhex(inputs["rng_seed_hex"]))
            got = lab.schnorr_prove_fs(
                params,
                inputs["x"],
                statement_y=inputs["y"],
                domain_sep=inputs["domain_sep"],
                rng=rng,
            )
            assert {
                "commitment": got.commitment,
                "challenge": got.challenge,
                "response": got.response,
            } == v["expected"]
            assert lab.schnorr_verify_fs(params, inputs["y"], got, domain_sep=inputs["domain_sep"]) is True
            continue

        if op == "dleq_prove":
            params = _params_from_inputs(inputs)
            rng = lab.DeterministicRNG(bytes.fromhex(inputs["rng_seed_hex"]))
            y1 = lab.mod_pow(inputs["g1"], inputs["x"], params.p)
            y2 = lab.mod_pow(inputs["g2"], inputs["x"], params.p)
            stmt = lab.DLEQStatement(params=params, g1=inputs["g1"], g2=inputs["g2"], y1=y1, y2=y2)
            got = lab.dleq_prove(stmt, inputs["x"], c=inputs["c"], rng=rng)
            a1, a2 = got.commitment
            assert {
                "commitment": [a1, a2],
                "challenge": got.challenge,
                "response": got.response,
            } == v["expected"]
            continue

        if op == "dleq_verify":
            params = _params_from_inputs(inputs)
            stmt = lab.DLEQStatement(
                params=params, g1=inputs["g1"], g2=inputs["g2"], y1=inputs["y1"], y2=inputs["y2"]
            )
            a = (inputs["a"][0], inputs["a"][1])
            got = lab.dleq_verify(stmt, a, inputs["c"], inputs["s"])
            assert got == v["expected"]
            continue

        if op == "dleq_simulate_hvz":
            params = _params_from_inputs(inputs)
            stmt = lab.DLEQStatement(
                params=params, g1=inputs["g1"], g2=inputs["g2"], y1=inputs["y1"], y2=inputs["y2"]
            )
            got = lab.dleq_simulate_hvz(stmt, inputs["c"], inputs["s"])
            a1, a2 = got.commitment
            assert {
                "commitment": [a1, a2],
                "challenge": got.challenge,
                "response": got.response,
            } == v["expected"]
            assert lab.dleq_verify(stmt, (a1, a2), got.challenge, got.response) is True
            continue

        if op == "dleq_prove_fs":
            params = _params_from_inputs(inputs)
            rng = lab.DeterministicRNG(bytes.fromhex(inputs["rng_seed_hex"]))
            stmt = lab.DLEQStatement(
                params=params, g1=inputs["g1"], g2=inputs["g2"], y1=inputs["y1"], y2=inputs["y2"]
            )
            got = lab.dleq_prove_fs(stmt, inputs["x"], domain_sep=inputs["domain_sep"], rng=rng)
            a1, a2 = got.commitment
            assert {
                "commitment": [a1, a2],
                "challenge": got.challenge,
                "response": got.response,
            } == v["expected"]
            assert lab.dleq_verify_fs(stmt, got, domain_sep=inputs["domain_sep"]) is True
            continue

        raise AssertionError(f"unknown op: {op}")


def test_subgroup_validation_rejects_non_member() -> None:
    params = lab.schnorr_params_toy()
    y_bad = 5
    _assert_raises(ValueError, lab.assert_prime_order_subgroup, params, elements=[y_bad])


def test_schnorr_verify_rejects_out_of_range_values() -> None:
    params = lab.schnorr_params_toy()
    x = 7
    y = lab.schnorr_public_key(params, x)
    lab.assert_prime_order_subgroup(params, elements=[y])

    tr = lab.schnorr_prove(params, x, c=5, rng=lab.DeterministicRNG(b"lesson-seed"))

    assert lab.schnorr_verify(params, y, tr.commitment, -1, tr.response) is False
    assert lab.schnorr_verify(params, y, tr.commitment, params.q, tr.response) is False
    assert lab.schnorr_verify(params, y, tr.commitment, tr.challenge, -1) is False
    assert lab.schnorr_verify(params, y, tr.commitment, tr.challenge, params.q) is False
    assert lab.schnorr_verify(params, y, -1, tr.challenge, tr.response) is False
    assert lab.schnorr_verify(params, y, params.p, tr.challenge, tr.response) is False


def test_hvz_simulation_accepts_for_many_choices() -> None:
    params = lab.schnorr_params_toy()
    x = 7
    y = lab.schnorr_public_key(params, x)
    lab.assert_prime_order_subgroup(params, elements=[y])

    for c in range(params.q):
        for s in range(params.q):
            tr = lab.schnorr_simulate_hvz(params, y, c, s)
            assert lab.schnorr_verify(params, y, tr.commitment, tr.challenge, tr.response) is True

    stmt = lab.DLEQStatement(
        params=params, g1=params.g, g2=6, y1=y, y2=lab.mod_pow(6, x, params.p)
    )
    lab.assert_prime_order_subgroup(params, elements=[stmt.g2, stmt.y1, stmt.y2])
    for c in range(params.q):
        for s in range(params.q):
            tr = lab.dleq_simulate_hvz(stmt, c, s)
            a1, a2 = tr.commitment
            assert lab.dleq_verify(stmt, (a1, a2), tr.challenge, tr.response) is True


def test_extractor_requires_distinct_challenges() -> None:
    _assert_raises(ValueError, lab.schnorr_extract_witness, 11, 3, 1, 3, 2)


def test_fiat_shamir_is_deterministic_and_domain_sep_required() -> None:
    q = 11
    items = [("y", 13), ("a", 8)]
    c1 = lab.fiat_shamir_challenge(q, domain_sep="sigma-library-lab-v1", items=items)
    c2 = lab.fiat_shamir_challenge(q, domain_sep="sigma-library-lab-v1", items=items)
    assert c1 == c2
    _assert_raises(ValueError, lab.fiat_shamir_challenge, q, domain_sep="", items=items)


def test_fs_verify_rejects_modified_challenge() -> None:
    params = lab.schnorr_params_toy()
    x = 7
    y = lab.schnorr_public_key(params, x)
    proof = lab.schnorr_prove_fs(
        params,
        x,
        statement_y=y,
        domain_sep="sigma-library-lab-v1",
        rng=lab.DeterministicRNG(b"lesson-seed"),
    )
    bad = lab.SigmaTranscript(commitment=proof.commitment, challenge=(proof.challenge + 1) % params.q, response=proof.response)
    assert lab.schnorr_verify_fs(params, y, bad, domain_sep="sigma-library-lab-v1") is False


if __name__ == "__main__":
    if pytest is not None:
        raise SystemExit(pytest.main([__file__]))

    tests = [v for k, v in globals().items() if k.startswith("test_") and callable(v)]
    for t in sorted(tests, key=lambda f: f.__name__):
        t()
    print("all tests pass")

