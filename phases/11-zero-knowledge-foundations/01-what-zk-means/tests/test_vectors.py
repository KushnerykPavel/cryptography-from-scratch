from __future__ import annotations

import json
import pathlib
import random
import sys


HERE = pathlib.Path(__file__).resolve().parent
CODE_DIR = HERE.parent / "code"
sys.path.insert(0, str(CODE_DIR))

import main as lesson


def load_vectors() -> list[dict]:
    path = HERE / "vectors.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    vectors = data.get("vectors", [])
    if not isinstance(vectors, list):
        raise TypeError("vectors.json: 'vectors' must be a list")
    return vectors


def params_from_vec(v: dict) -> lesson.SchnorrParams:
    return lesson.SchnorrParams(p=v["p"], q=v["q"], g=v["g"])


def run_vector(vec: dict) -> None:
    op = vec["op"]

    if op == "mod_inv":
        if "expect_error" in vec:
            try:
                lesson.mod_inv(vec["a"], vec["mod"])
            except Exception as exc:
                assert exc.__class__.__name__ == vec["expect_error"]
                return
            raise AssertionError("expected an exception but got none")
        assert lesson.mod_inv(vec["a"], vec["mod"]) == vec["expected"]
        return

    if op == "schnorr_public_key":
        params = params_from_vec(vec)
        assert lesson.schnorr_public_key(params, vec["x"]) == vec["expected"]
        return

    if op == "schnorr_commit":
        params = params_from_vec(vec)
        assert lesson.schnorr_commit(params, vec["r"]) == vec["expected"]
        return

    if op == "schnorr_response":
        assert (
            lesson.schnorr_response(vec["q"], vec["r"], vec["e"], vec["x"])
            == vec["expected"]
        )
        return

    if op == "schnorr_verify":
        params = params_from_vec(vec)
        assert (
            lesson.schnorr_verify(
                params,
                vec["y"],
                vec["a"],
                vec["e"],
                vec["z"],
            )
            == vec["expected"]
        )
        return

    if op == "schnorr_simulate_hvz":
        params = params_from_vec(vec)
        a, e, z = lesson.schnorr_simulate_hvz(
            params,
            vec["y"],
            vec["e"],
            vec["z"],
        )
        expected = vec["expected"]
        assert {"a": a, "e": e, "z": z} == expected
        assert lesson.schnorr_verify(params, vec["y"], a, e, z) is True
        return

    if op == "schnorr_extract_witness":
        assert (
            lesson.schnorr_extract_witness(
                vec["q"],
                vec["e1"],
                vec["z1"],
                vec["e2"],
                vec["z2"],
            )
            == vec["expected"]
        )
        return

    raise ValueError(f"unknown vector op: {op}")


def test_vectors() -> None:
    vectors = load_vectors()
    for i, vec in enumerate(vectors):
        try:
            run_vector(vec)
        except Exception as exc:
            raise AssertionError(f"vector #{i} failed: {vec}") from exc


def test_completeness_accepts_honest_prover() -> None:
    rng = random.Random(0)
    params = lesson.SchnorrParams(p=23, q=11, g=2)

    for _ in range(50):
        x = rng.randrange(0, params.q)
        y = lesson.schnorr_public_key(params, x)
        lesson.assert_schnorr_params(params, y)

        r = rng.randrange(0, params.q)
        e = rng.randrange(0, params.q)
        a = lesson.schnorr_commit(params, r)
        z = lesson.schnorr_response(params.q, r, e, x)
        assert lesson.schnorr_verify(params, y, a, e, z) is True


def test_hvz_simulator_produces_accepting_transcripts() -> None:
    rng = random.Random(1)
    params = lesson.SchnorrParams(p=23, q=11, g=2)
    x = 7
    y = lesson.schnorr_public_key(params, x)
    lesson.assert_schnorr_params(params, y)

    for _ in range(50):
        e = rng.randrange(0, params.q)
        z = rng.randrange(0, params.q)
        a, e, z = lesson.schnorr_simulate_hvz(params, y, e, z)
        assert lesson.schnorr_verify(params, y, a, e, z) is True


def test_extractor_recovers_witness_from_two_transcripts() -> None:
    rng = random.Random(2)
    params = lesson.SchnorrParams(p=23, q=11, g=2)

    for _ in range(50):
        x = rng.randrange(0, params.q)
        y = lesson.schnorr_public_key(params, x)
        lesson.assert_schnorr_params(params, y)

        r = rng.randrange(0, params.q)
        a = lesson.schnorr_commit(params, r)

        e1 = rng.randrange(0, params.q)
        e2 = (e1 + 1) % params.q
        z1 = lesson.schnorr_response(params.q, r, e1, x)
        z2 = lesson.schnorr_response(params.q, r, e2, x)
        assert lesson.schnorr_verify(params, y, a, e1, z1) is True
        assert lesson.schnorr_verify(params, y, a, e2, z2) is True

        extracted = lesson.schnorr_extract_witness(params.q, e1, z1, e2, z2)
        assert extracted == x


def test_extractor_rejects_same_challenge() -> None:
    try:
        lesson.schnorr_extract_witness(11, 3, 4, 3, 5)
    except ValueError:
        return
    raise AssertionError("expected ValueError for equal challenges")


def test_verify_rejects_out_of_range() -> None:
    params = lesson.SchnorrParams(p=23, q=11, g=2)
    y = lesson.schnorr_public_key(params, 7)
    a = lesson.schnorr_commit(params, 3)
    assert lesson.schnorr_verify(params, y, a, 11, 0) is False
    assert lesson.schnorr_verify(params, y, a, 0, 11) is False


def main() -> None:
    test_vectors()
    test_completeness_accepts_honest_prover()
    test_hvz_simulator_produces_accepting_transcripts()
    test_extractor_recovers_witness_from_two_transcripts()
    test_extractor_rejects_same_challenge()
    test_verify_rejects_out_of_range()
    print("all tests pass")


if __name__ == "__main__":
    main()
