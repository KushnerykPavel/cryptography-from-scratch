import json
import sys
from pathlib import Path

LESSON = Path(__file__).resolve().parents[1]
VECTORS_PATH = LESSON / "tests" / "vectors.json"

sys.path.insert(0, str(LESSON / "code"))
import main as bbs  # noqa: E402


def call(vector: dict, sk: int):
    op = vector["op"]

    if op == "bbs_keygen":
        got_sk, got_pk = bbs.bbs_keygen()
        assert got_sk == vector["expected_sk"], f"sk mismatch: {got_sk}"
        assert got_pk == vector["expected_pk"], f"pk mismatch: {got_pk}"
        return True

    if op == "bbs_sign_verify":
        msgs = vector["messages"]
        A, e, s = bbs.bbs_sign(sk, msgs)
        assert A == vector["expected_A"], (
            f"A mismatch for {msgs}: got {A}, want {vector['expected_A']}"
        )
        ok = bbs.bbs_verify(sk, msgs, (A, e, s))
        assert ok == vector["expected_verify"]
        return ok

    if op == "bbs_verify":
        msgs = vector["messages"]
        sig = (vector["A"], vector["e"], vector["s"])
        return bbs.bbs_verify(sk, msgs, sig)

    if op == "bbs_proof":
        msgs = vector["messages"]
        revealed = vector["revealed"]
        A, e, s = bbs.bbs_sign(sk, msgs)
        proof = bbs.bbs_create_proof(msgs, (A, e, s), revealed)
        return bbs.bbs_verify_proof(sk, proof)

    if op == "bbs_proof_tamper":
        msgs = vector["messages"]
        revealed = vector["revealed"]
        A, e, s = bbs.bbs_sign(sk, msgs)
        proof = bbs.bbs_create_proof(msgs, (A, e, s), revealed)
        # Tamper with a revealed message
        bad_proof = dict(proof)
        bad_proof["revealed_messages"] = dict(proof["revealed_messages"])
        bad_proof["revealed_messages"][vector["tamper_index"]] = vector["tamper_value"]
        return bbs.bbs_verify_proof(sk, bad_proof)

    raise AssertionError(f"unknown op: {op}")


def test_vectors() -> None:
    data = json.loads(VECTORS_PATH.read_text())
    sk = data["sk"]
    for vec in data["vectors"]:
        op = vec["op"]
        result = call(vec, sk)

        if op == "bbs_verify":
            assert result == vec["expected"], (
                f"bbs_verify mismatch for {vec['messages']}: got {result}"
            )
        elif op == "bbs_proof":
            assert result == vec["expected_proof_verify"], (
                f"bbs_proof mismatch for {vec['messages']}: got {result}"
            )
        elif op == "bbs_proof_tamper":
            assert result == vec["expected_proof_verify"], (
                f"bbs_proof_tamper: expected {vec['expected_proof_verify']}, got {result}"
            )


def test_sign_verify_roundtrip() -> None:
    sk, pk = bbs.bbs_keygen()
    for msgs in [[1], [1, 2], [0, 0, 0], [100, 200, 300, 400, 500]]:
        A, e, s = bbs.bbs_sign(sk, msgs)
        assert bbs.bbs_verify(sk, msgs, (A, e, s)), f"verify failed for {msgs}"


def test_verify_rejects_wrong_message() -> None:
    sk, _ = bbs.bbs_keygen()
    msgs = [10, 20, 30]
    A, e, s = bbs.bbs_sign(sk, msgs)
    sig = (A, e, s)
    assert not bbs.bbs_verify(sk, [10, 20, 31], sig), "should reject msg change"
    assert not bbs.bbs_verify(sk, [11, 20, 30], sig), "should reject msg change"


def test_selective_disclosure_all_revealed() -> None:
    """Proof with all attributes revealed should still verify."""
    sk, _ = bbs.bbs_keygen()
    msgs = [1, 2, 3, 4]
    A, e, s = bbs.bbs_sign(sk, msgs)
    proof = bbs.bbs_create_proof(msgs, (A, e, s), list(range(len(msgs))))
    assert bbs.bbs_verify_proof(sk, proof)


def test_selective_disclosure_none_revealed() -> None:
    """Proof with no attributes revealed should still verify (zero-knowledge base case)."""
    sk, _ = bbs.bbs_keygen()
    msgs = [7, 8, 9]
    A, e, s = bbs.bbs_sign(sk, msgs)
    proof = bbs.bbs_create_proof(msgs, (A, e, s), [])
    assert bbs.bbs_verify_proof(sk, proof)


def test_selective_disclosure_tamper_hidden_commitment() -> None:
    """Altering a hidden commitment should cause proof verification to fail."""
    sk, _ = bbs.bbs_keygen()
    msgs = [42, 1337, 2024, 99]
    A, e, s = bbs.bbs_sign(sk, msgs)
    proof = bbs.bbs_create_proof(msgs, (A, e, s), [0, 2])
    bad_proof = dict(proof)
    bad_proof["hidden_commitments"] = dict(proof["hidden_commitments"])
    # Corrupt hidden commitment for index 1
    bad_proof["hidden_commitments"][1] = (proof["hidden_commitments"][1] + 1) % bbs.P
    assert not bbs.bbs_verify_proof(sk, bad_proof), "tampered commitment should fail"


def test_different_messages_different_signatures() -> None:
    """Two distinct message vectors must produce different A values."""
    sk, _ = bbs.bbs_keygen()
    A1, _, _ = bbs.bbs_sign(sk, [1, 2, 3])
    A2, _, _ = bbs.bbs_sign(sk, [1, 2, 4])
    assert A1 != A2, "A values must differ for different messages"


if __name__ == "__main__":
    test_vectors()
    test_sign_verify_roundtrip()
    test_verify_rejects_wrong_message()
    test_selective_disclosure_all_revealed()
    test_selective_disclosure_none_revealed()
    test_selective_disclosure_tamper_hidden_commitment()
    test_different_messages_different_signatures()
    print("all tests pass")
