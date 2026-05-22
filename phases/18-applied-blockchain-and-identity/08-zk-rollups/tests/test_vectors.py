import json
import sys
from pathlib import Path

LESSON = Path(__file__).resolve().parents[1]
VECTORS_PATH = LESSON / "tests" / "vectors.json"

sys.path.insert(0, str(LESSON / "code"))
import main as zk  # noqa: E402


def _b(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


def call(vector):
    op = vector["op"]

    if op == "state_root":
        return zk.state_root(vector["balances"]).hex()

    if op == "genesis_root":
        gs = zk.rollup_genesis_state(vector["balances"])
        return gs["root"]

    if op == "apply_transfer_balances":
        gs = zk.rollup_genesis_state(vector["genesis"])
        new_state = zk.rollup_apply_transfer(gs, vector["tx"])
        return {
            "alice": new_state["alice"],
            "bob": new_state["bob"],
            "root": new_state["root"],
        }

    if op == "apply_batch_balances":
        gs = zk.rollup_genesis_state(vector["genesis"])
        new_state = zk.rollup_apply_batch(gs, vector["txs"])
        balances = {k: v for k, v in new_state.items() if k != "root"}
        return {"balances": balances, "root": new_state["root"]}

    if op == "prove_batch_tx_hash":
        gs = zk.rollup_genesis_state(vector["genesis"])
        new_state = zk.rollup_apply_batch(gs, vector["txs"])
        proof = zk.rollup_prove_batch(gs, vector["txs"], new_state)
        return proof["tx_hash"]

    if op == "verify_proof":
        old_root = _b(vector["old_root_hex"])
        new_root = _b(vector["new_root_hex"])
        return zk.rollup_verify_proof(old_root, new_root, vector["proof"])

    if op == "r1cs_check":
        constraints = zk.r1cs_encode_transfer(
            vector["from_bal"], vector["to_bal"], vector["amount"]
        )
        return zk.r1cs_check_satisfied(constraints, vector["witness"])

    raise AssertionError(f"unknown op: {op}")


def test_vectors():
    vectors = json.loads(VECTORS_PATH.read_text())["vectors"]
    for vector in vectors:
        op = vector["op"]

        if op == "state_root":
            result = call(vector)
            assert result == vector["expected_hex"], (
                f"FAIL [{vector['description']}]: got {result!r}, "
                f"expected {vector['expected_hex']!r}"
            )

        elif op == "genesis_root":
            result = call(vector)
            assert result == vector["expected_hex"], (
                f"FAIL [{vector['description']}]: got {result!r}"
            )

        elif op == "apply_transfer_balances":
            result = call(vector)
            assert result["alice"] == vector["expected_alice"], (
                f"FAIL [{vector['description']}] alice balance"
            )
            assert result["bob"] == vector["expected_bob"], (
                f"FAIL [{vector['description']}] bob balance"
            )
            assert result["root"] == vector["expected_root_hex"], (
                f"FAIL [{vector['description']}] root"
            )

        elif op == "apply_batch_balances":
            result = call(vector)
            assert result["balances"] == vector["expected"], (
                f"FAIL [{vector['description']}] balances: {result['balances']}"
            )
            assert result["root"] == vector["expected_root_hex"], (
                f"FAIL [{vector['description']}] root"
            )

        elif op == "prove_batch_tx_hash":
            result = call(vector)
            assert result == vector["expected_tx_hash"], (
                f"FAIL [{vector['description']}]: got {result!r}"
            )

        elif op in ("verify_proof", "r1cs_check"):
            result = call(vector)
            assert result == vector["expected"], (
                f"FAIL [{vector['description']}]: got {result!r}, "
                f"expected {vector['expected']!r}"
            )


def test_apply_transfer_insufficient_balance():
    gs = zk.rollup_genesis_state({"alice": 10, "bob": 50})
    try:
        zk.rollup_apply_transfer(gs, {"from": "alice", "to": "bob", "amount": 20})
    except ValueError as e:
        assert "insufficient" in str(e).lower()
    else:
        raise AssertionError("expected ValueError for overdraft")


def test_apply_transfer_unknown_sender():
    gs = zk.rollup_genesis_state({"alice": 100, "bob": 50})
    try:
        zk.rollup_apply_transfer(gs, {"from": "nobody", "to": "bob", "amount": 10})
    except ValueError as e:
        assert "nobody" in str(e)
    else:
        raise AssertionError("expected ValueError for unknown sender")


def test_apply_transfer_zero_amount():
    gs = zk.rollup_genesis_state({"alice": 100, "bob": 50})
    try:
        zk.rollup_apply_transfer(gs, {"from": "alice", "to": "bob", "amount": 0})
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for zero amount")


def test_state_root_deterministic():
    balances = {"z": 1, "a": 2, "m": 3}
    r1 = zk.state_root(balances)
    r2 = zk.state_root({"m": 3, "z": 1, "a": 2})
    assert r1 == r2, "state_root must be order-independent"


def test_batch_conservation():
    genesis = {"alice": 100, "bob": 50, "carol": 75, "dave": 25}
    gs = zk.rollup_genesis_state(genesis)
    batch = [
        {"from": "alice", "to": "bob",   "amount": 10},
        {"from": "carol", "to": "dave",  "amount": 5},
    ]
    new_state = zk.rollup_apply_batch(gs, batch)
    total_before = sum(genesis.values())
    total_after  = sum(v for k, v in new_state.items() if k != "root")
    assert total_before == total_after, "batch must conserve total supply"


def test_r1cs_num_constraints():
    constraints = zk.r1cs_encode_transfer(100, 50, 20)
    assert len(constraints) == 3, f"expected 3 constraints, got {len(constraints)}"


def test_prove_verify_roundtrip():
    genesis = {"alice": 200, "bob": 100}
    gs = zk.rollup_genesis_state(genesis)
    txs = [{"from": "alice", "to": "bob", "amount": 50}]
    new_state = zk.rollup_apply_batch(gs, txs)

    old_bals = {k: v for k, v in gs.items() if k != "root"}
    new_bals = {k: v for k, v in new_state.items() if k != "root"}
    old_root = zk.state_root(old_bals)
    new_root = zk.state_root(new_bals)

    proof = zk.rollup_prove_batch(gs, txs, new_state)
    assert zk.rollup_verify_proof(old_root, new_root, proof)
    assert not zk.rollup_verify_proof(bytes(32), new_root, proof)
    assert not zk.rollup_verify_proof(old_root, bytes(32), proof)


if __name__ == "__main__":
    test_vectors()
    test_apply_transfer_insufficient_balance()
    test_apply_transfer_unknown_sender()
    test_apply_transfer_zero_amount()
    test_state_root_deterministic()
    test_batch_conservation()
    test_r1cs_num_constraints()
    test_prove_verify_roundtrip()
    print("all tests pass")
