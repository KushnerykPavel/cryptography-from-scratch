import json
import os
import sys
from typing import Dict


HERE = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as frost  # noqa: E402


VECTORS_PATH = os.path.join(HERE, "vectors.json")


def _decode_hex_field(inputs: dict, key: str) -> bytes:
    if key not in inputs:
        raise KeyError(key)
    return bytes.fromhex(inputs[key])


def _int_keyed_dict(d: dict) -> dict:
    return {int(k): v for (k, v) in d.items()}


def _run_vector_case(case: dict) -> None:
    op = case["op"]
    inputs = case.get("inputs", {})
    expected = case["expected"]

    if op == "find_generator_of_order_q":
        got = frost.find_generator_of_order_q(inputs["p"], inputs["q"])
        assert got == expected
        return

    if op == "modinv":
        got = frost.modinv(inputs["a"], inputs["m"])
        assert got == expected
        return

    if op == "eval_polynomial":
        got = frost.eval_polynomial(inputs["coefficients"], inputs["x"], q=inputs.get("q", frost.Q))
        assert got == expected
        return

    if op == "lagrange_coefficient_at_zero":
        got = frost.lagrange_coefficient_at_zero(
            inputs["identifier"],
            inputs["participant_ids"],
            q=inputs.get("q", frost.Q),
        )
        assert got == expected
        return

    if op == "shamir_combine_at_zero":
        shares = [(i, y) for (i, y) in inputs["shares"]]
        got = frost.shamir_combine_at_zero(shares, q=inputs.get("q", frost.Q))
        assert got == expected
        return

    if op == "trusted_dealer_keygen":
        g = frost.find_generator_of_order_q(frost.P, frost.Q)
        secret, group_pk, key_shares = frost.trusted_dealer_keygen(
            secret=inputs["secret"],
            threshold=inputs["threshold"],
            participant_ids=inputs["participant_ids"],
            g=g,
            seed=inputs["seed"].encode("utf-8"),
        )
        assert secret == expected["group_sk"]
        assert group_pk == expected["group_pk"]
        expected_shares = {int(k): int(v) for (k, v) in expected["sk_shares"].items()}
        got_shares = {i: ks.sk_share for (i, ks) in key_shares.items()}
        assert got_shares == expected_shares
        return

    if op == "nonce_generate_sequence":
        g = frost.find_generator_of_order_q(frost.P, frost.Q)
        rng = frost.DeterministicRng(inputs["seed"].encode("utf-8"))
        got = {}
        for identifier in inputs["participant_ids"]:
            np = frost.nonce_generate(identifier, rng, g, p=frost.P, q=frost.Q)
            got[identifier] = {"d": np.hiding_nonce, "e": np.binding_nonce, "D": np.hiding_commitment, "E": np.binding_commitment}
        assert got == {int(k): v for (k, v) in expected["nonces"].items()}
        return

    if op == "compute_binding_factors":
        msg = _decode_hex_field(inputs, "msg_hex")
        commitment_list = [tuple(item) for item in inputs["commitment_list"]]
        got = frost.compute_binding_factors(inputs["group_pk"], commitment_list, msg, q=frost.Q, p=frost.P)
        assert got == _int_keyed_dict(expected)
        return

    if op == "commitment_share":
        commitment_list = [tuple(item) for item in inputs["commitment_list"]]
        binding_factors = _int_keyed_dict(inputs["binding_factors"])
        got = frost.commitment_share(inputs["identifier"], commitment_list, binding_factors, p=inputs.get("p", frost.P))
        assert got == expected
        return

    if op == "compute_group_commitment":
        commitment_list = [tuple(item) for item in inputs["commitment_list"]]
        binding_factors = _int_keyed_dict(inputs["binding_factors"])
        got = frost.compute_group_commitment(commitment_list, binding_factors, p=inputs.get("p", frost.P))
        assert got == expected
        return

    if op == "compute_challenge":
        msg = _decode_hex_field(inputs, "msg_hex")
        got = frost.compute_challenge(inputs["group_commitment"], inputs["group_pk"], msg, q=frost.Q, p=frost.P)
        assert got == expected
        return

    if op == "sign_signature_share":
        g = frost.find_generator_of_order_q(frost.P, frost.Q)
        identifier = inputs["identifier"]
        key_share = frost.ParticipantKeyShare(identifier=identifier, sk_share=inputs["sk_share"], pk_share=frost.group_pow(g, inputs["sk_share"], frost.P))
        nonce = inputs["nonce"]
        nonce_pair = frost.NoncePair(
            hiding_nonce=nonce["d"],
            binding_nonce=nonce["e"],
            hiding_commitment=frost.group_pow(g, nonce["d"], frost.P),
            binding_commitment=frost.group_pow(g, nonce["e"], frost.P),
        )
        got = frost.sign_signature_share(
            identifier,
            key_share,
            nonce_pair,
            inputs["binding_factor"],
            inputs["challenge"],
            inputs["participant_ids"],
            q=inputs.get("q", frost.Q),
        )
        assert got == expected
        return

    if op == "verify_signature_share":
        g = frost.find_generator_of_order_q(frost.P, frost.Q)
        identifier = inputs["identifier"]
        key_share = frost.ParticipantKeyShare(identifier=identifier, sk_share=0, pk_share=inputs["pk_share"])
        commitment_list = [tuple(item) for item in inputs["commitment_list"]]
        binding_factors = _int_keyed_dict(inputs["binding_factors"])
        got = frost.verify_signature_share(
            identifier,
            inputs["sig_share"],
            key_share,
            commitment_list,
            binding_factors,
            inputs["challenge"],
            inputs["participant_ids"],
            g,
            p=frost.P,
            q=frost.Q,
        )
        assert got == expected
        return

    if op == "aggregate_signature":
        sig_shares = _int_keyed_dict(inputs["sig_shares"])
        R, z = frost.aggregate_signature(sig_shares, inputs["group_commitment"], q=inputs.get("q", frost.Q))
        assert {"R": R, "z": z} == expected
        return

    if op == "prime_order_verify":
        g = frost.find_generator_of_order_q(frost.P, frost.Q)
        msg = _decode_hex_field(inputs, "msg_hex")
        sig = inputs["sig"]
        got = frost.prime_order_verify(msg, (sig["R"], sig["z"]), inputs["pk"], g, p=frost.P, q=frost.Q)
        assert got == expected
        return

    if op == "recover_secret_from_reused_nonce":
        msg1 = _decode_hex_field(inputs, "msg1_hex")
        msg2 = _decode_hex_field(inputs, "msg2_hex")
        sig1 = (inputs["sig1"]["R"], inputs["sig1"]["z"])
        sig2 = (inputs["sig2"]["R"], inputs["sig2"]["z"])
        got = frost.recover_secret_from_reused_nonce(msg1, msg2, sig1, sig2, inputs["pk"], q=frost.Q, p=frost.P)
        assert got == expected
        return

    raise ValueError(f"unknown op: {op}")


def test_vectors() -> None:
    with open(VECTORS_PATH, "r", encoding="utf-8") as f:
        vectors = json.load(f)["vectors"]

    for case in vectors:
        _run_vector_case(case)


def test_properties_and_edge_cases() -> None:
    g = frost.find_generator_of_order_q(frost.P, frost.Q)

    msg = b"hello frost"
    bad_msg = b"hello frosu"
    sk = 123
    pk = frost.group_pow(g, sk, frost.P)
    R, z, _ = frost.prime_order_sign(msg, sk, g, seed=b"schnorr-demo")
    assert frost.prime_order_verify(msg, (R, z), pk, g, p=frost.P, q=frost.Q)
    assert not frost.prime_order_verify(bad_msg, (R, z), pk, g, p=frost.P, q=frost.Q)

    try:
        frost.modinv(0, frost.Q)
        assert False, "expected failure"
    except ValueError:
        pass

    threshold = 3
    ids = [1, 2, 3, 4, 5]
    group_sk, _, shares = frost.trusted_dealer_keygen(
        secret=777,
        threshold=threshold,
        participant_ids=ids,
        g=g,
        seed=b"dealer-demo",
    )
    subset = [2, 4, 5]
    reconstructed = frost.shamir_combine_at_zero([(i, shares[i].sk_share) for i in subset], q=frost.Q)
    assert reconstructed == group_sk

    signers = [1, 2, 4]
    round1_rng = frost.DeterministicRng(b"round1-demo")
    msg = b"hello frost"
    nonce_pairs: Dict[int, frost.NoncePair] = {}
    commitment_list: frost.CommitmentList = []
    for i in signers:
        nonce_pairs[i] = frost.nonce_generate(i, round1_rng, g, p=frost.P, q=frost.Q)
        np = nonce_pairs[i]
        commitment_list.append((i, np.hiding_commitment, np.binding_commitment))
    commitment_list.sort(key=lambda t: t[0])
    rhos = frost.compute_binding_factors(frost.group_pow(g, group_sk, frost.P), commitment_list, msg, q=frost.Q, p=frost.P)
    R_group = frost.compute_group_commitment(commitment_list, rhos, p=frost.P)
    c = frost.compute_challenge(R_group, frost.group_pow(g, group_sk, frost.P), msg, q=frost.Q, p=frost.P)
    sig_shares = {}
    for i in signers:
        sig_shares[i] = frost.sign_signature_share(i, shares[i], nonce_pairs[i], rhos[i], c, signers, q=frost.Q)

    sig = frost.aggregate_signature(sig_shares, R_group, q=frost.Q)
    assert frost.prime_order_verify(msg, sig, frost.group_pow(g, group_sk, frost.P), g, p=frost.P, q=frost.Q)

    bad_shares = dict(sig_shares)
    bad_shares[1] = (bad_shares[1] + 1) % frost.Q
    bad_sig = frost.aggregate_signature(bad_shares, R_group, q=frost.Q)
    assert not frost.prime_order_verify(msg, bad_sig, frost.group_pow(g, group_sk, frost.P), g, p=frost.P, q=frost.Q)


if __name__ == "__main__":
    test_vectors()
    test_properties_and_edge_cases()
    print("all tests pass")
