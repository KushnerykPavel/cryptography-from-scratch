import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (
    TOY_GROUP,
    derive_key_pair,
    dleq_prove,
    dleq_verify,
    hash_to_group,
    hash_to_scalar,
    inv_element,
    is_valid_element,
    mod_inverse,
    oprf_blind,
    oprf_evaluate,
    oprf_finalize,
    oprf_unblind,
)


def _b(s: str) -> bytes:
    return s.encode("utf-8")


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        try:
            if op == "mod_inverse":
                got = mod_inverse(v["a"], v["n"])
            elif op == "hash_to_scalar":
                got = hash_to_scalar(_b(v["dst"]), _b(v["msg"]), TOY_GROUP)
            elif op == "hash_to_group":
                got = hash_to_group(_b(v["dst"]), _b(v["msg"]), TOY_GROUP)
            elif op == "derive_key_pair":
                got = list(derive_key_pair(_b(v["seed"]), TOY_GROUP))
            elif op == "oprf_blind":
                _, alpha = oprf_blind(_b(v["msg"]), v["blind"], TOY_GROUP)
                got = alpha
            elif op == "oprf_evaluate":
                got = oprf_evaluate(v["blinded_element"], v["sk"], TOY_GROUP)
            elif op == "oprf_unblind":
                got = oprf_unblind(v["evaluated_element"], v["blind"], TOY_GROUP)
            elif op == "oprf_finalize":
                out = oprf_finalize(_b(v["msg"]), v["unblinded_element"], TOY_GROUP)
                got = out.hex()
            elif op == "dleq_prove":
                got = list(
                    dleq_prove(v["sk"], v["alpha"], v["beta"], nonce=v["nonce"], group=TOY_GROUP)
                )
            elif op == "dleq_verify":
                got = dleq_verify(v["pk"], v["alpha"], v["beta"], (v["c"], v["s"]), TOY_GROUP)
            else:
                raise AssertionError(f"unknown op {op}")
        except ValueError as exc:
            assert v.get("expected_error") == str(exc), (
                f"{op} wrong error: got {exc!s}, expected {v.get('expected_error')}"
            )
            continue

        assert "expected" in v, f"{op} missing expected result"
        assert got == v["expected"], f"{op} failed: got {got}, expected {v['expected']}"


def test_oprf_roundtrip_matches_direct_evaluation():
    sk, pk = derive_key_pair(b"server key seed (property test)", TOY_GROUP)
    msg = b"property-test-input"

    p = hash_to_group(b"OPRF-H1", msg, TOY_GROUP)
    direct = pow(p, sk, TOY_GROUP.p)
    assert is_valid_element(direct, TOY_GROUP)

    for blind in [1, 2, 3, 4, 5, 42, 1337, TOY_GROUP.q - 1]:
        _, alpha = oprf_blind(msg, blind, TOY_GROUP)
        beta = oprf_evaluate(alpha, sk, TOY_GROUP)
        unblinded = oprf_unblind(beta, blind, TOY_GROUP)
        assert unblinded == direct

        out = oprf_finalize(msg, unblinded, TOY_GROUP)
        assert len(out) == 32

    # Different input => different output (extremely likely; for a test, pick deterministic inputs).
    _, alpha2 = oprf_blind(b"property-test-input-2", 42, TOY_GROUP)
    beta2 = oprf_evaluate(alpha2, sk, TOY_GROUP)
    unblinded2 = oprf_unblind(beta2, 42, TOY_GROUP)
    out1 = oprf_finalize(msg, direct, TOY_GROUP)
    out2 = oprf_finalize(b"property-test-input-2", unblinded2, TOY_GROUP)
    assert out1 != out2


def test_dleq_proof_rejects_tampering():
    sk, pk = derive_key_pair(b"server key seed (dleq property test)", TOY_GROUP)
    msg = b"dleq-message"
    blind = 17
    _, alpha = oprf_blind(msg, blind, TOY_GROUP)
    beta = oprf_evaluate(alpha, sk, TOY_GROUP)

    proof = dleq_prove(sk, alpha, beta, nonce=1234, group=TOY_GROUP)
    assert dleq_verify(pk, alpha, beta, proof, TOY_GROUP)

    # Tamper beta.
    bad_beta = (beta * TOY_GROUP.g) % TOY_GROUP.p
    assert not dleq_verify(pk, alpha, bad_beta, proof, TOY_GROUP)

    # Tamper proof.
    c, s = proof
    assert not dleq_verify(pk, alpha, beta, ((c + 1) % TOY_GROUP.q, s), TOY_GROUP)
    assert not dleq_verify(pk, alpha, beta, (c, (s + 1) % TOY_GROUP.q), TOY_GROUP)

    # Wrong public key.
    _, pk2 = derive_key_pair(b"some other server", TOY_GROUP)
    assert not dleq_verify(pk2, alpha, beta, proof, TOY_GROUP)


def test_invalid_group_elements_are_rejected():
    sk, _ = derive_key_pair(b"server key seed (invalid elements)", TOY_GROUP)

    # Not in subgroup: for safe prime p=2q+1, -1 has order 2, so (-1)^q = -1 != 1.
    not_in_subgroup = TOY_GROUP.p - 1
    assert not is_valid_element(not_in_subgroup, TOY_GROUP)

    try:
        oprf_evaluate(not_in_subgroup, sk, TOY_GROUP)
        raise AssertionError("expected ValueError for invalid blinded element")
    except ValueError as exc:
        assert str(exc) == "invalid blinded element"

    try:
        inv_element(not_in_subgroup, TOY_GROUP)
        raise AssertionError("expected ValueError for invalid group element")
    except ValueError as exc:
        assert str(exc) == "invalid group element"


if __name__ == "__main__":
    test_vectors()
    test_oprf_roundtrip_matches_direct_evaluation()
    test_dleq_proof_rejects_tampering()
    test_invalid_group_elements_are_rejected()
    print("all tests pass")
