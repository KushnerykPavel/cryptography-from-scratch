import json
import os
import sys


THIS_DIR = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(THIS_DIR, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as starks  # noqa: E402


def _load_vectors():
    path = os.path.join(THIS_DIR, "vectors.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def test_vectors():
    data = _load_vectors()
    vectors = data["vectors"]

    for v in vectors:
        op = v["op"]
        inputs = v["inputs"]
        expected = v["expected"]

        if op == "modinv":
            got = starks.modinv(inputs["a"], inputs["p"])
            assert got == expected
        elif op == "fib_trace":
            got = starks.fib_trace(inputs["a0"], inputs["a1"], inputs["steps"], inputs["p"])
            assert [list(x) for x in got] == expected
        elif op == "fib_air_transition_ok":
            curr = (inputs["curr"][0], inputs["curr"][1])
            nxt = (inputs["nxt"][0], inputs["nxt"][1])
            got = starks.fib_air_transition_ok(curr, nxt, inputs["p"])
            assert got == expected
        elif op == "trace_row_payload":
            row = (inputs["row"][0], inputs["row"][1])
            got = starks.trace_row_payload(row).hex()
            assert got == expected
        elif op == "merkle_root":
            leaf_payloads = [bytes.fromhex(h) for h in inputs["leaf_payloads_hex"]]
            levels = starks.merkle_build(leaf_payloads)
            got = starks.merkle_root(levels).hex()
            assert got == expected
        elif op == "merkle_open_verify":
            root = bytes.fromhex(inputs["root_hex"])
            leaf_payload = bytes.fromhex(inputs["leaf_payload_hex"])
            path = [(bytes.fromhex(h), int(side)) for h, side in inputs["path"]]
            got = starks.merkle_verify(root, leaf_payload, inputs["index"], path)
            assert got == expected
        elif op == "fs_challenges":
            root = bytes.fromhex(inputs["root_hex"])
            got = starks.fs_challenges(root, inputs["n"], inputs["count"])
            assert got == expected
        else:
            raise AssertionError(f"unknown op: {op}")


def test_modinv_roundtrip():
    p = starks.P
    for a in (1, 2, 3, 5, 7, 1234567, p - 2):
        inv = starks.modinv(a, p)
        assert (a * inv) % p == 1


def test_modinv_rejects_zero():
    try:
        starks.modinv(0, starks.P)
        assert False, "expected ZeroDivisionError"
    except ZeroDivisionError:
        pass


def test_fib_air_rejects_corrupted_trace():
    p = starks.P
    trace = starks.fib_trace(1, 1, 16, p)
    assert starks.fib_air_all_transitions(trace, p) is True
    bad = list(trace)
    bad[7] = (bad[7][0], (bad[7][1] + 1) % p)
    assert starks.fib_air_all_transitions(bad, p) is False


def test_merkle_rejects_tampering():
    p = starks.P
    trace = starks.fib_trace(1, 1, 8, p)
    leaves = [starks.trace_row_payload(r) for r in trace]
    levels = starks.merkle_build(leaves)
    root = starks.merkle_root(levels)
    idx = 3
    path = starks.merkle_open(levels, idx)
    assert starks.merkle_verify(root, leaves[idx], idx, path) is True

    tampered_leaf = leaves[idx][:-1] + bytes([leaves[idx][-1] ^ 0x01])
    assert starks.merkle_verify(root, tampered_leaf, idx, path) is False

    tampered_path = list(path)
    tampered_path[0] = (tampered_path[0][0][:-1] + bytes([tampered_path[0][0][-1] ^ 0x01]), tampered_path[0][1])
    assert starks.merkle_verify(root, leaves[idx], idx, tampered_path) is False


def test_stark_proof_accepts_honest_and_rejects_modified_row():
    proof = starks.prove_fib(1, 1, steps=32, p=starks.P, query_count=6)
    assert starks.verify_fib(proof, query_count=6) is True

    mutated = json.loads(json.dumps(proof.__dict__))
    mutated["queries"][0]["row_i"][1] = (mutated["queries"][0]["row_i"][1] + 1) % starks.P
    bad = starks.StarkProof(**mutated)
    assert starks.verify_fib(bad, query_count=6) is False


def test_fs_challenges_unique():
    root = bytes.fromhex("00" * 32)
    xs = starks.fs_challenges(root, n=128, count=64)
    assert len(xs) == 64
    assert len(set(xs)) == 64


if __name__ == "__main__":
    try:
        import pytest  # type: ignore

        rc = pytest.main([__file__])
        if rc != 0:
            raise SystemExit(rc)
    except ImportError:
        test_vectors()
        test_modinv_roundtrip()
        test_modinv_rejects_zero()
        test_fib_air_rejects_corrupted_trace()
        test_merkle_rejects_tampering()
        test_stark_proof_accepts_honest_and_rejects_modified_row()
        test_fs_challenges_unique()

    print("all tests pass")

