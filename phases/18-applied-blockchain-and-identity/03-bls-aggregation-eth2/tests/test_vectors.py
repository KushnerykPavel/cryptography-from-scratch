import json
import sys
from pathlib import Path

LESSON = Path(__file__).resolve().parents[1]
VECTORS_PATH = LESSON / "tests" / "vectors.json"

sys.path.insert(0, str(LESSON / "code"))
import main as bls  # noqa: E402


def _b(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


def call(vector):
    op = vector["op"]

    if op == "hash_to_g1":
        return bls.bls_hash_to_g1(_b(vector["message_hex"]))

    if op == "keygen":
        return bls.bls_keygen(vector["sk"])

    if op == "sign":
        return bls.bls_sign(vector["sk"], _b(vector["message_hex"]))

    if op == "verify":
        return bls.bls_verify(vector["pk"], _b(vector["message_hex"]), vector["sig"])

    if op == "aggregate_sigs":
        return bls.bls_aggregate_sigs(vector["sigs"])

    if op == "aggregate_pks":
        return bls.bls_aggregate_pks(vector["pks"])

    if op == "verify_aggregate":
        return bls.bls_verify_aggregate(
            vector["agg_pk"], _b(vector["message_hex"]), vector["agg_sig"]
        )

    if op == "rogue_key_attack":
        return bls.bls_rogue_key_attack(vector["target_pk"], vector["attacker_sk"])

    if op == "verify_pop":
        return bls.bls_verify_pop(vector["pk"], vector["pop"])

    raise AssertionError(f"unknown op: {op}")


def _expected(vector):
    for key in ("expected_pk", "expected_sig", "expected_agg_sig", "expected_agg_pk",
                "expected_rogue_pk", "expected_h", "expected"):
        if key in vector:
            return vector[key]
    raise AssertionError(f"no expected key in vector: {vector}")


def test_vectors():
    vectors = json.loads(VECTORS_PATH.read_text())["vectors"]
    for i, vector in enumerate(vectors):
        result = call(vector)
        expected = _expected(vector)
        assert result == expected, (
            f"vector[{i}] op={vector['op']!r}: got {result!r}, expected {expected!r}"
        )


def test_sign_verify_roundtrip():
    for sk in [1, 7, 42, 123, 999, 10000, 500001]:
        pk = bls.bls_keygen(sk)
        for msg in [b"hello", b"ethereum", b"\x00\x01\x02"]:
            sig = bls.bls_sign(sk, msg)
            assert bls.bls_verify(pk, msg, sig), f"roundtrip failed sk={sk}"
            wrong_msg = b"wrong"
            if msg != wrong_msg:
                assert not bls.bls_verify(pk, wrong_msg, sig), "wrong msg accepted"


def test_aggregate_same_message():
    sks = [42, 100, 200, 300]
    msg = b"beacon chain"
    pks = [bls.bls_keygen(sk) for sk in sks]
    sigs = [bls.bls_sign(sk, msg) for sk in sks]
    agg_sig = bls.bls_aggregate_sigs(sigs)
    agg_pk = bls.bls_aggregate_pks(pks)
    assert bls.bls_verify_aggregate(agg_pk, msg, agg_sig)
    assert not bls.bls_verify_aggregate(agg_pk, b"other", agg_sig)


def test_aggregate_multi_message():
    sks = [42, 100, 200]
    messages = [b"msg_alice", b"msg_bob", b"msg_carol"]
    pks = [bls.bls_keygen(sk) for sk in sks]
    sigs = [bls.bls_sign(sk, m) for sk, m in zip(sks, messages)]
    agg_sig = bls.bls_aggregate_sigs(sigs)
    assert bls.bls_verify_aggregate_multi(pks, messages, agg_sig)
    swapped = [messages[1], messages[0], messages[2]]
    assert not bls.bls_verify_aggregate_multi(pks, swapped, agg_sig)


def test_rogue_key_attack():
    victim_sk, victim_pk = 42, bls.bls_keygen(42)
    attacker_sk = 999
    rogue_pk = bls.bls_rogue_key_attack(victim_pk, attacker_sk)
    naive_agg = (victim_pk + rogue_pk) % bls.Q
    assert naive_agg == attacker_sk % bls.Q
    msg = b"forged"
    forged_sig = bls.bls_sign(attacker_sk, msg)
    assert bls.bls_verify_aggregate(naive_agg, msg, forged_sig), "attack should succeed"


def test_proof_of_possession():
    for sk in [42, 100, 200, 999]:
        pk, pop = bls.bls_sign_with_pop(sk)
        assert bls.bls_verify_pop(pk, pop), f"valid PoP failed for sk={sk}"
    # Wrong pop for a different pk
    _, pop42 = bls.bls_sign_with_pop(42)
    pk100 = bls.bls_keygen(100)
    assert not bls.bls_verify_pop(pk100, pop42), "PoP cross-check should fail"


if __name__ == "__main__":
    test_vectors()
    test_sign_verify_roundtrip()
    test_aggregate_same_message()
    test_aggregate_multi_message()
    test_rogue_key_attack()
    test_proof_of_possession()
    print("all tests pass")
