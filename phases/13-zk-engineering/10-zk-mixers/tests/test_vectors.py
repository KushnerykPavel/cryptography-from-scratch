import json
import os
import sys


HERE = os.path.dirname(__file__)
CODE_DIR = os.path.normpath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as m  # noqa: E402


def load_vectors():
    with open(os.path.join(HERE, "vectors.json"), "r", encoding="utf-8") as f:
        return json.load(f)


def _hex32(x):
    b = bytes.fromhex(x)
    assert len(b) == 32
    return b


def run_vector(vec):
    op = vec["op"]
    inputs = vec["inputs"]
    expected = vec["expected"]

    if op == "note_roundtrip":
        secret = _hex32(inputs["secret_hex"])
        nullifier = _hex32(inputs["nullifier_hex"])
        note = m.format_note(secret, nullifier)
        assert note == expected["note"]
        s2, n2 = m.parse_note(note)
        assert s2 == secret
        assert n2 == nullifier
        return

    if op == "commitment":
        secret = _hex32(inputs["secret_hex"])
        nullifier = _hex32(inputs["nullifier_hex"])
        got = m.commitment(secret, nullifier).hex()
        assert got == expected["commitment_hex"]
        return

    if op == "nullifier_hash":
        nullifier = _hex32(inputs["nullifier_hex"])
        got = m.nullifier_hash(nullifier).hex()
        assert got == expected["nullifier_hash_hex"]
        return

    if op == "merkle_root":
        leaves = [bytes.fromhex(x) for x in inputs["commitment_hexes"]]
        root = m.merkle_root(leaves).hex()
        assert root == expected["root_hex"]
        return

    if op == "merkle_inclusion_proof":
        leaves = [bytes.fromhex(x) for x in inputs["commitment_hexes"]]
        idx = inputs["index"]
        proof = m.merkle_inclusion_proof(leaves, idx)
        got_path = [{"side": side, "hash_hex": h.hex()} for side, h in proof]
        assert got_path == expected["path"]
        root = bytes.fromhex(expected["root_hex"])
        assert m.verify_merkle_inclusion(leaves[idx], idx, proof, root)
        return

    if op == "prove_withdrawal":
        leaves = [bytes.fromhex(x) for x in inputs["commitment_hexes"]]
        proof = m.prove_withdrawal(
            leaves=leaves,
            secret=_hex32(inputs["secret_hex"]),
            nullifier=_hex32(inputs["nullifier_hex"]),
            leaf_index=int(inputs["leaf_index"]),
            recipient=inputs["recipient"],
            relayer=inputs["relayer"],
            fee_wei=int(inputs["fee_wei"]),
        )
        exp = expected
        assert proof.statement.root_hex == exp["statement"]["root_hex"]
        assert proof.statement.nullifier_hash_hex == exp["statement"]["nullifier_hash_hex"]
        assert proof.statement.recipient == exp["statement"]["recipient"]
        assert proof.statement.relayer == exp["statement"]["relayer"]
        assert proof.statement.fee_wei == exp["statement"]["fee_wei"]
        assert proof.leaf_index == exp["leaf_index"]
        assert proof.merkle_path == exp["merkle_path"]
        assert proof.proof_digest_hex == exp["proof_digest_hex"]
        assert m.verify_withdrawal(leaves, proof)
        return

    raise ValueError(f"unknown op: {op}")


def test_vectors():
    payload = load_vectors()
    assert "vectors" in payload
    for vec in payload["vectors"]:
        run_vector(vec)


def test_note_rejects_bad_prefix():
    secret = b"\x11" * 32
    nullifier = b"\x22" * 32
    note = m.format_note(secret, nullifier)
    bad = note.replace("mixer-v1", "mixer-v0", 1)
    try:
        m.parse_note(bad)
    except ValueError:
        return
    raise AssertionError("expected ValueError for bad prefix")


def test_merkle_inclusion_roundtrip_small_random():
    for n in range(1, 15):
        leaves = [m.sha256(f"leaf-{n}-{i}".encode("utf-8")) for i in range(n)]
        root = m.merkle_root(leaves)
        for idx in range(n):
            proof = m.merkle_inclusion_proof(leaves, idx)
            assert m.verify_merkle_inclusion(leaves[idx], idx, proof, root)


def test_withdrawal_binds_recipient():
    leaves = []
    for seed in [1, 2, 3, 4]:
        s = m.pseudo_random_bytes(1000 + seed, m.NOTE_PART_LEN)
        n = m.pseudo_random_bytes(2000 + seed, m.NOTE_PART_LEN)
        leaves.append(m.commitment(s, n))

    s2 = m.pseudo_random_bytes(1003, m.NOTE_PART_LEN)
    n2 = m.pseudo_random_bytes(2003, m.NOTE_PART_LEN)
    p = m.prove_withdrawal(
        leaves=leaves,
        secret=s2,
        nullifier=n2,
        leaf_index=2,
        recipient="0x1111111111111111111111111111111111111111",
        relayer="0x2222222222222222222222222222222222222222",
        fee_wei=1,
    )
    assert m.verify_withdrawal(leaves, p)

    stolen = m.WithdrawalProof(
        statement=m.WithdrawalStatement(
            root_hex=p.statement.root_hex,
            nullifier_hash_hex=p.statement.nullifier_hash_hex,
            recipient="0x9999999999999999999999999999999999999999",
            relayer=p.statement.relayer,
            fee_wei=p.statement.fee_wei,
        ),
        leaf_index=p.leaf_index,
        merkle_path=p.merkle_path,
        proof_digest_hex=p.proof_digest_hex,
    )
    assert not m.verify_withdrawal(leaves, stolen)


def test_mixer_double_spend_rejected():
    mixer = m.Mixer()
    notes = []
    for seed in [1, 2, 3]:
        s = m.pseudo_random_bytes(1000 + seed, m.NOTE_PART_LEN)
        n = m.pseudo_random_bytes(2000 + seed, m.NOTE_PART_LEN)
        mixer.deposit(m.commitment(s, n))
        notes.append((s, n))

    s2, n2 = notes[1]
    proof = m.prove_withdrawal(
        leaves=mixer.leaves,
        secret=s2,
        nullifier=n2,
        leaf_index=1,
        recipient="0x1111111111111111111111111111111111111111",
        relayer="0x2222222222222222222222222222222222222222",
        fee_wei=0,
    )
    mixer.withdraw(proof)
    try:
        mixer.withdraw(proof)
    except ValueError:
        return
    raise AssertionError("expected ValueError for double spend")


def _run_all_tests():
    test_vectors()
    test_note_rejects_bad_prefix()
    test_merkle_inclusion_roundtrip_small_random()
    test_withdrawal_binds_recipient()
    test_mixer_double_spend_rejected()


if __name__ == "__main__":
    _run_all_tests()
    print("all tests pass")

