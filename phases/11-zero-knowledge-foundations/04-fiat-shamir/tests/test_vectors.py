import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (  # noqa: E402
    SchnorrParams,
    check_schnorr_params,
    fiat_shamir_challenge,
    forge_fs_proof_by_grinding,
    fs_prove,
    fs_verify,
    mod_inverse,
    schnorr_commit,
    schnorr_response,
    schnorr_verify,
    toy_keypair,
    toy_params,
    weak_fiat_shamir_challenge_without_message,
    weak_fs_prove_without_message,
    weak_fs_verify_without_message,
)


def params_from_vector(v):
    return SchnorrParams(p=v["p"], q=v["q"], g=v["g"])


def _msg(v):
    return v["message"].encode("utf-8")


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
        elif op == "schnorr_commit":
            got = schnorr_commit(params_from_vector(v), v["r"])
        elif op == "schnorr_response":
            got = schnorr_response(params_from_vector(v), v["r"], v["c"], v["x"])
        elif op == "schnorr_verify":
            got = schnorr_verify(params_from_vector(v), v["y"], v["t"], v["c"], v["s"])
        elif op == "fiat_shamir_challenge":
            got = fiat_shamir_challenge(params_from_vector(v), v["y"], v["t"], _msg(v))
        elif op == "fs_verify":
            got = fs_verify(params_from_vector(v), v["y"], _msg(v), v["proof"])
        elif op == "weak_fiat_shamir_challenge_without_message":
            got = weak_fiat_shamir_challenge_without_message(
                params_from_vector(v), v["y"], v["t"]
            )
        elif op == "weak_fs_verify_without_message":
            got = weak_fs_verify_without_message(params_from_vector(v), v["y"], v["proof"])
        elif op == "forge_fs_proof_by_grinding":
            got = forge_fs_proof_by_grinding(params_from_vector(v), v["y"], _msg(v))
        else:
            raise AssertionError(f"unknown op {op}")

        assert "expected" in v, f"{op} missing expected result"
        assert got == v["expected"], f"{op} failed: got {got}, expected {v['expected']}"


def test_interactive_roundtrip():
    params = toy_params()
    check_schnorr_params(params)
    x, y = toy_keypair(params, x=7)
    q = params.q

    for r in range(q):
        t = schnorr_commit(params, r)
        for c in range(q):
            s = schnorr_response(params, r, c, x)
            assert schnorr_verify(params, y, t, c, s)


def test_fiat_shamir_roundtrip_and_binding():
    params = toy_params()
    x, y = toy_keypair(params, x=7)

    msg = b"hello"
    proof = fs_prove(params, x, msg, nonce=4)
    assert fs_verify(params, y, msg, proof)
    assert not fs_verify(params, y, b"bye", proof)

    try:
        fiat_shamir_challenge(params, y, proof["t"], "not-bytes")  # type: ignore[arg-type]
        raise AssertionError("expected TypeError for non-bytes message")
    except TypeError as exc:
        assert str(exc) == "message must be bytes"


def test_weak_fiat_shamir_is_transferable():
    params = toy_params()
    x, y = toy_keypair(params, x=7)

    proof = weak_fs_prove_without_message(params, x, nonce=4)
    assert weak_fs_verify_without_message(params, y, proof)
    assert weak_fs_verify_without_message(params, y, proof)


def test_grinding_forges_a_proof_for_toy_params():
    params = toy_params()
    _, y = toy_keypair(params, x=7)

    msg = b"hello"
    forged = forge_fs_proof_by_grinding(params, y, msg)
    assert fs_verify(params, y, msg, forged)


if __name__ == "__main__":
    test_vectors()
    test_interactive_roundtrip()
    test_fiat_shamir_roundtrip_and_binding()
    test_weak_fiat_shamir_is_transferable()
    test_grinding_forges_a_proof_for_toy_params()
    print("all tests pass")

