import json
import os
import random
import sys


HERE = os.path.dirname(__file__)
CODE_DIR = os.path.normpath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as m  # noqa: E402


def load_vectors():
    with open(os.path.join(HERE, "vectors.json"), "r", encoding="utf-8") as f:
        return json.load(f)


def run_vector(vec):
    op = vec["op"]
    inputs = vec["inputs"]
    expected = vec["expected"]

    if op == "state_step":
        got = m.state_step(inputs["start_state_hex"], inputs["message"])
        assert got == expected["end_state_hex"]
        return

    if op == "prove_step":
        proof = m.prove_step(inputs["start_state_hex"], inputs["message"])
        assert proof.end_state_hex == expected["end_state_hex"]
        assert proof.digest_hex == expected["digest_hex"]
        assert m.verify_step(proof)
        return

    if op == "merkle_root":
        leaves = [bytes.fromhex(x) for x in inputs["leaf_digest_hexes"]]
        root = m.merkle_root(leaves).hex()
        assert root == expected["root_hex"]
        return

    if op == "merkle_inclusion_proof":
        leaves = [bytes.fromhex(x) for x in inputs["leaf_digest_hexes"]]
        idx = inputs["index"]
        proof = m.merkle_inclusion_proof(leaves, idx)
        got_path = [{"side": side, "hash_hex": h.hex()} for side, h in proof]
        assert got_path == expected["path"]
        root = bytes.fromhex(expected["root_hex"])
        assert m.verify_merkle_inclusion(leaves[idx], idx, proof, root)
        return

    if op == "prove_segment":
        state = inputs["start_state_hex"]
        step_proofs = []
        for msg in inputs["messages"]:
            p = m.prove_step(state, msg)
            step_proofs.append(p)
            state = p.end_state_hex
        seg = m.prove_segment(step_proofs)
        exp = expected["segment"]
        assert seg.start_state_hex == exp["start_state_hex"]
        assert seg.end_state_hex == exp["end_state_hex"]
        assert seg.step_count == exp["step_count"]
        assert seg.commitment_root_hex == exp["commitment_root_hex"]
        assert seg.digest_hex == exp["digest_hex"]
        assert m.verify_segment(seg, step_proofs)
        return

    if op == "fold_segments_binary":
        state = inputs["start_state_hex"]
        step_proofs = []
        for msg in inputs["messages"]:
            p = m.prove_step(state, msg)
            step_proofs.append(p)
            state = p.end_state_hex

        chunk = inputs["chunk"]
        segments = [m.prove_segment(step_proofs[i : i + chunk]) for i in range(0, len(step_proofs), chunk)]
        folded = m.fold_segments_binary(segments)
        exp = expected["final"]
        assert folded.start_state_hex == exp["start_state_hex"]
        assert folded.end_state_hex == exp["end_state_hex"]
        assert folded.step_count == exp["step_count"]
        assert folded.commitment_root_hex == exp["commitment_root_hex"]
        assert folded.digest_hex == exp["digest_hex"]
        return

    raise ValueError(f"unknown op: {op}")


def test_vectors():
    payload = load_vectors()
    assert "vectors" in payload
    for vec in payload["vectors"]:
        run_vector(vec)


def test_step_tamper_rejected():
    genesis = m.sha256_hex(b"genesis")
    p = m.prove_step(genesis, "tx: alice->bob 3")
    assert m.verify_step(p)

    tampered = m.StepProof(
        start_state_hex=p.start_state_hex,
        message="tx: alice->bob 4",
        end_state_hex=p.end_state_hex,
        digest_hex=p.digest_hex,
    )
    assert not m.verify_step(tampered)


def test_merkle_inclusion_roundtrip_small_random():
    random.seed(123)
    for n in range(1, 10):
        leaves = [m.sha256(f"leaf-{n}-{i}".encode("utf-8")) for i in range(n)]
        root = m.merkle_root(leaves)
        for idx in range(n):
            proof = m.merkle_inclusion_proof(leaves, idx)
            assert m.verify_merkle_inclusion(leaves[idx], idx, proof, root)


def test_segment_requires_sequential_linking():
    genesis = m.sha256_hex(b"genesis")
    p0 = m.prove_step(genesis, "m0")
    p1 = m.prove_step(genesis, "m1")
    try:
        m.prove_segment([p0, p1])
    except ValueError:
        return
    raise AssertionError("expected ValueError for non-sequential segment")


def test_fold_requires_linking():
    genesis = m.sha256_hex(b"genesis")
    p0 = m.prove_step(genesis, "m0")
    p1 = m.prove_step(p0.end_state_hex, "m1")
    p2 = m.prove_step(genesis, "bad")

    seg_ok = m.prove_segment([p0, p1])
    seg_bad = m.prove_segment([p2])
    try:
        m.fold_two_segments(seg_ok, seg_bad)
    except ValueError:
        return
    raise AssertionError("expected ValueError for non-linkable fold")


def _run_all_tests():
    test_vectors()
    test_step_tamper_rejected()
    test_merkle_inclusion_roundtrip_small_random()
    test_segment_requires_sequential_linking()
    test_fold_requires_linking()


if __name__ == "__main__":
    _run_all_tests()
    print("all tests pass")

