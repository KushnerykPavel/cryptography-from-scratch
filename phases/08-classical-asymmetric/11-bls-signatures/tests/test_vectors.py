import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (  # noqa: E402
    G1,
    G2,
    aggregate_signatures,
    aggregate_verify,
    bls_sign,
    bls_verify,
    fast_aggregate_verify_same_message,
    fast_aggregate_verify_same_message_with_pops,
    hash_to_g1,
    keygen,
    pop_prove,
    pop_verify,
    sk_to_pk,
)


def _int_from_hex(h: str) -> int:
    if h.startswith("0x"):
        h = h[2:]
    if not h:
        return 0
    return int(h, 16)


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        if op == "keygen":
            got = keygen(bytes.fromhex(v["seed_hex"]))
            assert got == _int_from_hex(v["expected_sk_hex"])
            continue

        if op == "hash_to_g1":
            got = hash_to_g1(bytes.fromhex(v["msg_hex"])).exp
            assert got == _int_from_hex(v["expected_exp_hex"])
            continue

        if op == "sk_to_pk":
            got = sk_to_pk(_int_from_hex(v["sk_hex"])).exp
            assert got == _int_from_hex(v["expected_pk_exp_hex"])
            continue

        if op == "sign":
            got = bls_sign(_int_from_hex(v["sk_hex"]), bytes.fromhex(v["msg_hex"])).exp
            assert got == _int_from_hex(v["expected_sig_exp_hex"])
            continue

        if op == "verify":
            pk = G2(_int_from_hex(v["pk_exp_hex"]))
            sig = G1(_int_from_hex(v["sig_exp_hex"]))
            got = bls_verify(pk, bytes.fromhex(v["msg_hex"]), sig)
            assert got == v["expected"]
            continue

        if op == "aggregate_signatures":
            sigs = [G1(_int_from_hex(x)) for x in v["sig_exp_hex_list"]]
            got = aggregate_signatures(sigs).exp
            assert got == _int_from_hex(v["expected_agg_sig_exp_hex"])
            continue

        if op == "aggregate_verify":
            pks = [G2(_int_from_hex(x)) for x in v["pk_exp_hex_list"]]
            msgs = [bytes.fromhex(x) for x in v["msg_hex_list"]]
            sig = G1(_int_from_hex(v["agg_sig_exp_hex"]))
            got = aggregate_verify(pks, msgs, sig)
            assert got == v["expected"]
            continue

        if op == "pop_prove":
            got = pop_prove(_int_from_hex(v["sk_hex"])).exp
            assert got == _int_from_hex(v["expected_pop_exp_hex"])
            continue

        if op == "pop_verify":
            pk = G2(_int_from_hex(v["pk_exp_hex"]))
            proof = G1(_int_from_hex(v["pop_exp_hex"]))
            got = pop_verify(pk, proof)
            assert got == v["expected"]
            continue

        if op == "fast_aggregate_verify_same_message":
            pks = [G2(_int_from_hex(x)) for x in v["pk_exp_hex_list"]]
            sig = G1(_int_from_hex(v["agg_sig_exp_hex"]))
            got = fast_aggregate_verify_same_message(pks, bytes.fromhex(v["msg_hex"]), sig)
            assert got == v["expected"]
            continue

        raise AssertionError(f"unknown op {op}")


def test_properties_and_rejection():
    seed_a = bytes.fromhex("00010203")
    seed_b = bytes.fromhex("04050607")
    sk_a = keygen(seed_a)
    sk_b = keygen(seed_b)
    pk_a = sk_to_pk(sk_a)
    pk_b = sk_to_pk(sk_b)

    msg_a = b"hello"
    msg_b = b"world"

    sig_a = bls_sign(sk_a, msg_a)
    sig_b = bls_sign(sk_b, msg_b)

    assert bls_verify(pk_a, msg_a, sig_a)
    assert not bls_verify(pk_a, msg_b, sig_a)
    assert not bls_verify(pk_b, msg_a, sig_a)

    agg1 = aggregate_signatures([sig_a, sig_b])
    agg2 = aggregate_signatures([sig_b, sig_a])
    assert agg1 == agg2
    assert aggregate_verify([pk_a, pk_b], [msg_a, msg_b], agg1)
    assert not aggregate_verify([pk_a, pk_b], [msg_a, msg_a], agg1)

    common = b"same"
    sigs_common = [bls_sign(sk_a, common), bls_sign(sk_b, common)]
    agg_common = aggregate_signatures(sigs_common)
    assert fast_aggregate_verify_same_message([pk_a, pk_b], common, agg_common)
    assert not fast_aggregate_verify_same_message([pk_a, pk_b], common + b"\x00", agg_common)

    pops = [pop_prove(sk_a), pop_prove(sk_b)]
    assert fast_aggregate_verify_same_message_with_pops([pk_a, pk_b], pops, common, agg_common)
    assert not fast_aggregate_verify_same_message_with_pops([pk_a, pk_b], [pops[1], pops[0]], common, agg_common)

    try:
        aggregate_signatures([])
        raise AssertionError("expected ValueError for empty signatures")
    except ValueError:
        pass

    try:
        aggregate_verify([pk_a], [msg_a, msg_b], agg1)
        raise AssertionError("expected ValueError for mismatched lengths")
    except ValueError:
        pass


if __name__ == "__main__":
    test_vectors()
    test_properties_and_rejection()
    print("all tests pass")

