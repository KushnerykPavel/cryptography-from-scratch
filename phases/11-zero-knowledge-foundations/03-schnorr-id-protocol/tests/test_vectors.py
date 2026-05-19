import json
import sys
from pathlib import Path

try:
    import pytest  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    pytest = None


THIS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(THIS_DIR.parent / "code"))

import main as schnorr  # noqa: E402


def _load_vectors() -> dict:
    path = THIS_DIR / "vectors.json"
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _params_from_inputs(inputs: dict) -> schnorr.SchnorrParams:
    return schnorr.SchnorrParams(p=inputs["p"], q=inputs["q"], g=inputs["g"])


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
            got = schnorr.mod_inv(inputs["a"], inputs["mod"])
            assert got == v["expected"]
            continue

        if op == "schnorr_public_key":
            params = _params_from_inputs(inputs)
            got = schnorr.schnorr_public_key(params, inputs["x"])
            assert got == v["expected"]
            continue

        if op == "schnorr_id_commit":
            params = _params_from_inputs(inputs)
            got = schnorr.schnorr_id_commit(params, inputs["r"])
            assert got == v["expected"]
            continue

        if op == "schnorr_id_respond":
            got = schnorr.schnorr_id_respond(inputs["q"], inputs["r"], inputs["c"], inputs["x"])
            assert got == v["expected"]
            continue

        if op == "schnorr_id_verify":
            params = _params_from_inputs(inputs)
            got = schnorr.schnorr_id_verify(
                params,
                inputs["y"],
                inputs["t"],
                inputs["c"],
                inputs["s"],
            )
            assert got == v["expected"]
            continue

        if op == "schnorr_id_simulate_hvz":
            params = _params_from_inputs(inputs)
            got = schnorr.schnorr_id_simulate_hvz(params, inputs["y"], inputs["c"], inputs["s"])
            assert {"t": got.t, "c": got.c, "s": got.s} == v["expected"]
            assert schnorr.schnorr_id_verify(params, inputs["y"], got.t, got.c, got.s) is True
            continue

        if op == "schnorr_extract_secret_from_nonce_reuse":
            got = schnorr.schnorr_extract_secret_from_nonce_reuse(
                inputs["q"], inputs["c1"], inputs["s1"], inputs["c2"], inputs["s2"]
            )
            assert got == v["expected"]
            continue

        if op == "schnorr_fiat_shamir_challenge":
            got = schnorr.schnorr_fiat_shamir_challenge(
                inputs["q"],
                domain_sep=inputs["domain_sep"],
                statement_y=inputs["statement_y"],
                commitment_t=inputs["commitment_t"],
            )
            assert got == v["expected"]
            continue

        raise AssertionError(f"unknown op: {op}")


def test_verify_rejects_out_of_range_values() -> None:
    params = schnorr.schnorr_params_toy()
    y = schnorr.schnorr_public_key(params, 3)

    t = schnorr.schnorr_id_commit(params, 4)
    s = schnorr.schnorr_id_respond(params.q, 4, 5, 3)

    assert schnorr.schnorr_id_verify(params, y, t, -1, s) is False
    assert schnorr.schnorr_id_verify(params, y, t, params.q, s) is False
    assert schnorr.schnorr_id_verify(params, y, t, 5, -1) is False
    assert schnorr.schnorr_id_verify(params, y, t, 5, params.q) is False
    assert schnorr.schnorr_id_verify(params, y, -1, 5, s) is False
    assert schnorr.schnorr_id_verify(params, y, params.p, 5, s) is False


def test_params_validation_rejects_non_subgroup_statement() -> None:
    params = schnorr.schnorr_params_toy()
    y_bad = 5  # not in subgroup of order q=11 (since 5^11 mod 23 != 1)
    _assert_raises(ValueError, schnorr.assert_schnorr_params, params=params, y=y_bad)


def test_hvz_simulation_accepts_for_many_choices() -> None:
    params = schnorr.schnorr_params_toy()
    y = schnorr.schnorr_public_key(params, 7)
    schnorr.assert_schnorr_params(params, y)

    for c in range(params.q):
        for s in range(params.q):
            tr = schnorr.schnorr_id_simulate_hvz(params, y, c, s)
            assert schnorr.schnorr_id_verify(params, y, tr.t, tr.c, tr.s) is True


def test_nonce_reuse_extracts_secret() -> None:
    params = schnorr.schnorr_params_toy()
    x = 9
    y = schnorr.schnorr_public_key(params, x)
    schnorr.assert_schnorr_params(params, y)

    r = 3
    t = schnorr.schnorr_id_commit(params, r)
    c1, c2 = 1, 7
    s1 = schnorr.schnorr_id_respond(params.q, r, c1, x)
    s2 = schnorr.schnorr_id_respond(params.q, r, c2, x)
    assert schnorr.schnorr_id_verify(params, y, t, c1, s1) is True
    assert schnorr.schnorr_id_verify(params, y, t, c2, s2) is True

    extracted = schnorr.schnorr_extract_secret_from_nonce_reuse(params.q, c1, s1, c2, s2)
    assert extracted == (x % params.q)


def test_fiat_shamir_is_deterministic() -> None:
    q = 11
    c1 = schnorr.schnorr_fiat_shamir_challenge(
        q, domain_sep="schnorr-id-demo-v1", statement_y=8, commitment_t=18
    )
    c2 = schnorr.schnorr_fiat_shamir_challenge(
        q, domain_sep="schnorr-id-demo-v1", statement_y=8, commitment_t=18
    )
    assert c1 == c2


def test_fiat_shamir_rejects_empty_domain_sep() -> None:
    _assert_raises(
        ValueError,
        schnorr.schnorr_fiat_shamir_challenge,
        11,
        domain_sep="",
        statement_y=1,
        commitment_t=2,
    )


if __name__ == "__main__":
    if pytest is not None:
        raise SystemExit(pytest.main([__file__]))

    tests = [v for k, v in globals().items() if k.startswith("test_") and callable(v)]
    for t in sorted(tests, key=lambda f: f.__name__):
        t()
    print("all tests pass")
