import json
import sys
from pathlib import Path

LESSON = Path(__file__).resolve().parents[1]
VECTORS_PATH = LESSON / "tests" / "vectors.json"

sys.path.insert(0, str(LESSON / "code"))
import main as aa  # noqa: E402


def call(vector):
    op = vector["op"]

    if op == "aa_compute_address":
        return aa.aa_compute_address(vector["owner_sk"])

    if op == "aa_create_account":
        acc = aa.aa_create_account(vector["owner_sk"])
        return {
            "commitment": acc["commitment"],
            "address": acc["address"],
            "nonce": acc["nonce"],
        }

    if op == "aa_create_user_op":
        acc = aa.aa_create_account(vector["owner_sk"])
        calldata = bytes.fromhex(vector["calldata_hex"])
        user_op = aa.aa_create_user_op(acc, calldata, vector["max_fee"])
        return {
            "sender": user_op["sender"],
            "nonce": user_op["nonce"],
            "calldata": user_op["calldata"],
            "max_fee": user_op["max_fee"],
        }

    if op == "aa_zk_proof_verify":
        acc = aa.aa_create_account(vector["owner_sk"])
        calldata = bytes.fromhex(vector["calldata_hex"])
        user_op = aa.aa_create_user_op(acc, calldata, vector["max_fee"])
        proof = aa.aa_create_zk_proof(vector["owner_sk"], user_op)
        R, s = proof
        valid = aa.aa_validate_user_op(acc, user_op, proof)
        return {"R": R, "s": s, "valid": valid}

    if op == "aa_paymaster_check":
        user_op = {"sender": vector["sender"], "max_fee": vector["max_fee"]}
        return aa.aa_paymaster_check(user_op, vector["policy"])

    raise AssertionError(f"unknown op: {op}")


def test_vectors():
    vectors = json.loads(VECTORS_PATH.read_text())["vectors"]
    for vector in vectors:
        op = vector["op"]
        result = call(vector)

        if op == "aa_compute_address":
            assert result == vector["expected"], (
                f"aa_compute_address({vector['owner_sk']}): got {result}, "
                f"expected {vector['expected']}"
            )

        elif op == "aa_create_account":
            assert result["commitment"] == vector["expected_commitment"]
            assert result["address"] == vector["expected_address"]
            assert result["nonce"] == vector["expected_nonce"]

        elif op == "aa_create_user_op":
            assert result["sender"] == vector["expected_sender"]
            assert result["nonce"] == vector["expected_nonce"]
            assert result["calldata"] == vector["expected_calldata"]
            assert result["max_fee"] == vector["expected_max_fee"]

        elif op == "aa_zk_proof_verify":
            assert result["R"] == vector["expected_R"], (
                f"[{vector['label']}] R mismatch: got {result['R']}"
            )
            assert result["s"] == vector["expected_s"], (
                f"[{vector['label']}] s mismatch: got {result['s']}"
            )
            assert result["valid"] == vector["expected_valid"], (
                f"[{vector['label']}] valid mismatch"
            )

        elif op == "aa_paymaster_check":
            assert result == vector["expected"], (
                f"paymaster_check [{vector['label']}]: got {result}"
            )


def test_bad_proof_rejected():
    """A proof from a different key must not verify."""
    acc = aa.aa_create_account(424242)
    user_op = aa.aa_create_user_op(acc, b"test", 1000)
    bad_proof = aa.aa_create_zk_proof(424243, user_op)
    assert not aa.aa_validate_user_op(acc, user_op, bad_proof)


def test_proof_binds_to_op():
    """A proof generated for one UserOp must not verify a different op."""
    sk = 424242
    acc = aa.aa_create_account(sk)
    op1 = aa.aa_create_user_op(acc, b"calldata1", 1000)
    op2 = aa.aa_create_user_op(acc, b"calldata2", 2000)
    proof1 = aa.aa_create_zk_proof(sk, op1)
    assert aa.aa_validate_user_op(acc, op1, proof1)
    assert not aa.aa_validate_user_op(acc, op2, proof1)


def test_bundle_verify_rejects_missing_proof():
    """aa_verify_bundle must return False when proof is None."""
    sk = 424242
    acc = aa.aa_create_account(sk)
    op = aa.aa_create_user_op(acc, b"data", 1000)
    # proof stays None
    bundle = aa.aa_bundle_ops([op])
    assert not aa.aa_verify_bundle(bundle, [acc])


def test_bundle_verify_roundtrip():
    """Full create → proof → bundle → verify roundtrip."""
    sk = 12345
    acc = aa.aa_create_account(sk)
    op = aa.aa_create_user_op(acc, b"roundtrip", 500)
    proof = aa.aa_create_zk_proof(sk, op)
    op_with_proof = dict(op, proof=proof)
    bundle = aa.aa_bundle_ops([op_with_proof])
    assert aa.aa_verify_bundle(bundle, [acc])


def test_paymaster_open_policy():
    """Empty whitelist means all senders are allowed."""
    acc = aa.aa_create_account(1)
    op = aa.aa_create_user_op(acc, b"x", 100)
    policy = {"max_fee": 200, "whitelist": []}
    assert aa.aa_paymaster_check(op, policy)


if __name__ == "__main__":
    test_vectors()
    test_bad_proof_rejected()
    test_proof_binds_to_op()
    test_bundle_verify_rejects_missing_proof()
    test_bundle_verify_roundtrip()
    test_paymaster_open_policy()
    print("all tests pass")
