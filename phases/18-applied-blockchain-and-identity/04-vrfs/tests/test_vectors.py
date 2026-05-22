import json
import sys
from pathlib import Path

LESSON = Path(__file__).resolve().parents[1]
VECTORS_PATH = LESSON / "tests" / "vectors.json"

sys.path.insert(0, str(LESSON / "code"))
import main as vrf  # noqa: E402


def call(vector):
    op = vector["op"]

    if op == "keygen":
        return vrf.vrf_keygen(vector["sk"])

    if op == "hash_to_group":
        return vrf.vrf_hash_to_group(vector["m"].encode())

    if op == "evaluate":
        gamma, c, s = vrf.vrf_evaluate(
            vector["sk"], vector["m"].encode(), vector["k"]
        )
        return {"gamma": gamma, "c": c, "s": s}

    if op == "verify":
        return vrf.vrf_verify(
            vector["pk"],
            vector["m"].encode(),
            vector["gamma"],
            vector["c"],
            vector["s"],
        )

    if op == "proof_to_hash":
        return vrf.vrf_proof_to_hash(vector["gamma"]).hex()

    raise AssertionError(f"unknown op: {op}")


def test_vectors():
    vectors = json.loads(VECTORS_PATH.read_text())["vectors"]
    for i, v in enumerate(vectors):
        op = v["op"]
        result = call(v)

        if op == "keygen":
            assert result == v["expected_pk"], (
                f"vector[{i}] keygen: got {result}, expected {v['expected_pk']}"
            )
        elif op == "hash_to_group":
            assert result == v["expected_h"], (
                f"vector[{i}] hash_to_group: got {result}, expected {v['expected_h']}"
            )
        elif op == "evaluate":
            assert result["gamma"] == v["expected_gamma"], f"vector[{i}] gamma mismatch"
            assert result["c"] == v["expected_c"], f"vector[{i}] c mismatch"
            assert result["s"] == v["expected_s"], f"vector[{i}] s mismatch"
        elif op == "verify":
            assert result == v["expected"], (
                f"vector[{i}] verify: got {result}, expected {v['expected']}"
            )
        elif op == "proof_to_hash":
            assert result.lower() == v["expected_hex"].lower(), (
                f"vector[{i}] proof_to_hash: got {result}, expected {v['expected_hex']}"
            )


def test_roundtrip():
    for sk in [1, 42, 12345, 99999, 2**31 - 1]:
        pk = vrf.vrf_keygen(sk)
        for msg in [b"hello", b"world", b"block-42", b"\x00\x01\x02"]:
            k = (sk * 7 + hash(msg)) % vrf.SUBGROUP_ORDER
            if k == 0:
                k = 1
            gamma, c, s = vrf.vrf_evaluate(sk, msg, k)
            assert vrf.vrf_verify(pk, msg, gamma, c, s), (
                f"roundtrip failed sk={sk} msg={msg!r}"
            )


def test_different_messages_give_different_beta():
    sk = 42
    k = 123456
    msgs = [b"a", b"b", b"c", b"aa", b"ab"]
    betas = set()
    for msg in msgs:
        gamma, c, s = vrf.vrf_evaluate(sk, msg, k + hash(msg) % 1000)
        betas.add(vrf.vrf_proof_to_hash(gamma).hex())
    assert len(betas) == len(msgs), "colliding beta outputs"


def test_tampered_proof_rejected():
    sk = 12345
    k = 67890
    pk = vrf.vrf_keygen(sk)
    msg = b"hello vrf"
    gamma, c, s = vrf.vrf_evaluate(sk, msg, k)
    assert not vrf.vrf_verify(pk, msg, (gamma + 1) % vrf.P, c, s)
    assert not vrf.vrf_verify(pk, msg, gamma, (c + 1) % vrf.SUBGROUP_ORDER, s)
    assert not vrf.vrf_verify(pk, msg, gamma, c, (s + 1) % vrf.SUBGROUP_ORDER)
    assert not vrf.vrf_verify(pk, b"other message", gamma, c, s)


def test_wrong_pk_rejected():
    sk1, sk2 = 111, 222
    pk1 = vrf.vrf_keygen(sk1)
    pk2 = vrf.vrf_keygen(sk2)
    msg = b"test"
    k = 9999
    gamma, c, s = vrf.vrf_evaluate(sk1, msg, k)
    assert vrf.vrf_verify(pk1, msg, gamma, c, s)
    assert not vrf.vrf_verify(pk2, msg, gamma, c, s)


if __name__ == "__main__":
    test_vectors()
    test_roundtrip()
    test_different_messages_give_different_beta()
    test_tampered_proof_rejected()
    test_wrong_pk_rejected()
    print("all tests pass")
