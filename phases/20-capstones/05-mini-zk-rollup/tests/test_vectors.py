import hashlib
import json
import os
import sys
from contextlib import contextmanager

HERE = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as zk  # noqa: E402


@contextmanager
def _raises(exc_type):
    try:
        yield
    except exc_type:
        return
    raise AssertionError(f"expected {exc_type.__name__} to be raised")


def _b(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


# ---------------------------------------------------------------------------
# Helpers to reconstruct demo state (mirrors main.py constants)
# ---------------------------------------------------------------------------

ADDR_ALICE = 0x00000001
ADDR_BOB   = 0x00000002
ADDR_CAROL = 0x00000003
ADDR_DAVE  = 0x00000004

SK_ALICE = hashlib.sha256(b"sk:alice").digest()
SK_BOB   = hashlib.sha256(b"sk:bob").digest()
SK_CAROL = hashlib.sha256(b"sk:carol").digest()
SK_DAVE  = hashlib.sha256(b"sk:dave").digest()

SK_MAP = {
    ADDR_ALICE: SK_ALICE,
    ADDR_BOB:   SK_BOB,
    ADDR_CAROL: SK_CAROL,
    ADDR_DAVE:  SK_DAVE,
}

INITIAL_STATE = [
    zk.Account(ADDR_ALICE, 1000),
    zk.Account(ADDR_BOB,    500),
    zk.Account(ADDR_CAROL,  750),
    zk.Account(ADDR_DAVE,   250),
]

PROOF_SEED = b"rollup-demo-seed-v1"


def _make_initial_leaves():
    return [a.leaf_hash() for a in INITIAL_STATE]


def _make_batch_txs():
    tx1 = zk.Transaction(ADDR_ALICE, ADDR_BOB,   100, 1)
    tx2 = zk.Transaction(ADDR_BOB,   ADDR_CAROL,  50, 1)
    tx3 = zk.Transaction(ADDR_CAROL, ADDR_DAVE,  200, 1)
    tx1.sig = zk.sign_tx(SK_ALICE, tx1)
    tx2.sig = zk.sign_tx(SK_BOB,   tx2)
    tx3.sig = zk.sign_tx(SK_CAROL, tx3)
    return [tx1, tx2, tx3]


# ---------------------------------------------------------------------------
# Vector tests
# ---------------------------------------------------------------------------

def test_vectors():
    with open(os.path.join(HERE, "vectors.json"), "r", encoding="utf-8") as f:
        data = json.load(f)

    for vec in data["vectors"]:
        op = vec["op"]

        if op == "merkle_hash":
            got = zk.merkle_hash(_b(vec["left_hex"]), _b(vec["right_hex"]))
            assert got == _b(vec["expected_hex"]), f"vector failed: op={op}"

        elif op == "merkle_root":
            leaves = [_b(h) for h in vec["leaves_hex"]]
            got = zk.merkle_root(leaves)
            assert got == _b(vec["expected_hex"]), f"vector failed: op={op}"

        elif op == "merkle_verify":
            root  = _b(vec["root_hex"])
            leaf  = _b(vec["leaf_hex"])
            proof = [_b(h) for h in vec["proof_hex"]]
            got = zk.merkle_verify(root, leaf, proof, vec["index"])
            assert got == vec["expected_valid"], f"vector failed: op={op}"

        elif op == "sign_tx":
            sk = _b(vec["sk_hex"])
            tx = zk.Transaction(vec["sender"], vec["receiver"], vec["amount"], vec["nonce"])
            got = zk.sign_tx(sk, tx)
            assert got == _b(vec["expected_sig_hex"]), f"vector failed: op={op}"

        elif op == "state_root_after_single_tx":
            state = [zk.Account(e["address"], e["balance"]) for e in vec["initial_balances"]]
            tx = zk.Transaction(ADDR_ALICE, ADDR_BOB, 100, 1)
            tx.sig = zk.sign_tx(SK_ALICE, tx)
            new_state = zk.apply_tx(state, tx, SK_MAP)
            got_root = zk.state_root(new_state)
            assert got_root == _b(vec["expected_new_root_hex"]), f"vector failed: op={op}"
            got_bals = [(a.address, a.balance) for a in new_state]
            exp_bals = [(e["address"], e["balance"]) for e in vec["expected_new_balances"]]
            assert got_bals == exp_bals, f"vector failed: op={op} (balances)"

        elif op == "state_root_after_batch":
            state = [zk.Account(e["address"], e["balance"]) for e in vec["initial_balances"]]
            txs = _make_batch_txs()
            new_state = zk.apply_batch(state, txs, SK_MAP)
            got_root = zk.state_root(new_state)
            assert got_root == _b(vec["expected_new_root_hex"]), f"vector failed: op={op}"

        elif op == "validity_proof":
            txs = _make_batch_txs()
            new_state = zk.apply_batch(INITIAL_STATE, txs, SK_MAP)
            seed = vec["seed_ascii"].encode()
            vp, disclosures = zk.generate_validity_proof(INITIAL_STATE, new_state, txs, seed)
            assert vp == _b(vec["expected_proof_hex"]), f"vector failed: op={op} (proof hex)"
            assert disclosures[0].commitment_old == _b(vec["disc0_commitment_old_hex"]), \
                f"vector failed: op={op} (disc0 c_old)"
            assert disclosures[0].commitment_new == _b(vec["disc0_commitment_new_hex"]), \
                f"vector failed: op={op} (disc0 c_new)"

        else:
            raise ValueError(f"unknown op in vectors.json: {op}")


# ---------------------------------------------------------------------------
# Property tests
# ---------------------------------------------------------------------------

def test_merkle_root_single_leaf():
    leaf = b"\xab" * 32
    assert zk.merkle_root([leaf]) == leaf


def test_merkle_verify_correct_and_incorrect():
    leaves = _make_initial_leaves()
    root = zk.merkle_root(leaves)
    for idx in range(len(leaves)):
        proof = zk.merkle_proof(leaves, idx)
        assert zk.merkle_verify(root, leaves[idx], proof, idx), \
            f"valid proof for index {idx} should verify"
    # Wrong leaf at index 0 should fail
    wrong_leaf = b"\x00" * 32
    proof0 = zk.merkle_proof(leaves, 0)
    assert not zk.merkle_verify(root, wrong_leaf, proof0, 0), \
        "wrong leaf should not verify"


def test_sign_and_verify_roundtrip():
    tx = zk.Transaction(ADDR_ALICE, ADDR_BOB, 50, 42)
    sig = zk.sign_tx(SK_ALICE, tx)
    assert zk.verify_tx(SK_ALICE, tx, sig)
    # Wrong key must fail
    assert not zk.verify_tx(SK_BOB, tx, sig)
    # Tampered amount must fail
    tx_bad = zk.Transaction(ADDR_ALICE, ADDR_BOB, 51, 42)
    assert not zk.verify_tx(SK_ALICE, tx_bad, sig)


def test_invalid_tx_rejected_bad_signature():
    state = [zk.Account(a.address, a.balance) for a in INITIAL_STATE]
    tx = zk.Transaction(ADDR_ALICE, ADDR_BOB, 100, 1)
    tx.sig = b"\x00" * 32   # garbage sig
    with _raises(ValueError):
        zk.apply_tx(state, tx, SK_MAP)


def test_invalid_tx_rejected_insufficient_balance():
    state = [zk.Account(a.address, a.balance) for a in INITIAL_STATE]
    tx = zk.Transaction(ADDR_ALICE, ADDR_BOB, 9999, 1)
    tx.sig = zk.sign_tx(SK_ALICE, tx)
    with _raises(ValueError):
        zk.apply_tx(state, tx, SK_MAP)


def test_apply_batch_state_correctness():
    txs = _make_batch_txs()
    new_state = zk.apply_batch(INITIAL_STATE, txs, SK_MAP)
    bals = {a.address: a.balance for a in new_state}
    assert bals[ADDR_ALICE] == 900
    assert bals[ADDR_BOB]   == 550
    assert bals[ADDR_CAROL] == 600
    assert bals[ADDR_DAVE]  == 450


def test_validity_proof_verifies():
    txs = _make_batch_txs()
    new_state = zk.apply_batch(INITIAL_STATE, txs, SK_MAP)
    old_root = zk.state_root(INITIAL_STATE)
    new_root = zk.state_root(new_state)
    vp, disclosures = zk.generate_validity_proof(INITIAL_STATE, new_state, txs, PROOF_SEED)
    assert zk.verify_validity_proof(old_root, new_root, vp, disclosures)


def test_validity_proof_rejects_tampered_commitment():
    txs = _make_batch_txs()
    new_state = zk.apply_batch(INITIAL_STATE, txs, SK_MAP)
    old_root = zk.state_root(INITIAL_STATE)
    new_root = zk.state_root(new_state)
    vp, disclosures = zk.generate_validity_proof(INITIAL_STATE, new_state, txs, PROOF_SEED)

    d0 = disclosures[0]
    bad_d0 = zk.TxProofData(
        tx_index=d0.tx_index,
        old_balance=d0.old_balance,
        amount=d0.amount,
        balance_minus_amount=d0.balance_minus_amount,
        commitment_old=bytes([d0.commitment_old[0] ^ 0xFF]) + d0.commitment_old[1:],
        commitment_new=d0.commitment_new,
        randomness_old=d0.randomness_old,
        randomness_new=d0.randomness_new,
    )
    bad_disclosures = [bad_d0] + disclosures[1:]
    assert not zk.verify_validity_proof(old_root, new_root, vp, bad_disclosures)


def test_validity_proof_rejects_negative_remainder():
    txs = _make_batch_txs()
    new_state = zk.apply_batch(INITIAL_STATE, txs, SK_MAP)
    old_root = zk.state_root(INITIAL_STATE)
    new_root = zk.state_root(new_state)
    vp, disclosures = zk.generate_validity_proof(INITIAL_STATE, new_state, txs, PROOF_SEED)

    d0 = disclosures[0]
    bad_d0 = zk.TxProofData(
        tx_index=d0.tx_index,
        old_balance=d0.old_balance,
        amount=d0.amount,
        balance_minus_amount=-1,   # forged negative remainder
        commitment_old=d0.commitment_old,
        commitment_new=d0.commitment_new,
        randomness_old=d0.randomness_old,
        randomness_new=d0.randomness_new,
    )
    bad_disclosures = [bad_d0] + disclosures[1:]
    assert not zk.verify_validity_proof(old_root, new_root, vp, bad_disclosures)


def test_l1_submission_roundtrip():
    txs = _make_batch_txs()
    new_state = zk.apply_batch(INITIAL_STATE, txs, SK_MAP)
    vp, _ = zk.generate_validity_proof(INITIAL_STATE, new_state, txs, PROOF_SEED)
    sub = zk.build_l1_submission(INITIAL_STATE, new_state, txs, vp)
    assert sub.old_root == zk.state_root(INITIAL_STATE)
    assert sub.new_root == zk.state_root(new_state)
    assert sub.validity_proof == vp
    assert len(sub.compressed_txs) > 0
    # compressed_txs must be valid JSON
    parsed = json.loads(sub.compressed_txs)
    assert len(parsed) == 3


if __name__ == "__main__":
    tests = [
        test_vectors,
        test_merkle_root_single_leaf,
        test_merkle_verify_correct_and_incorrect,
        test_sign_and_verify_roundtrip,
        test_invalid_tx_rejected_bad_signature,
        test_invalid_tx_rejected_insufficient_balance,
        test_apply_batch_state_correctness,
        test_validity_proof_verifies,
        test_validity_proof_rejects_tampered_commitment,
        test_validity_proof_rejects_negative_remainder,
        test_l1_submission_roundtrip,
    ]
    for t in tests:
        t()
    print("all tests pass")
