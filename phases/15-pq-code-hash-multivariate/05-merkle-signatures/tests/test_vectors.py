import json
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
CODE_DIR = (HERE.parent / "code").resolve()
sys.path.insert(0, str(CODE_DIR))

import main as m  # noqa: E402


def _b(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


def _load_vectors() -> dict:
    path = HERE / "vectors.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _run_vector(v: dict) -> None:
    op = v["op"]
    inputs = v["inputs"]
    expected = v["expected"]

    if op == "lamport_pk_hash":
        seed = _b(inputs["seed_hex"])
        _, pk = m.lamport_keygen(seed)
        got = m.lamport_pk_hash(pk).hex()
        assert got == expected["pk_hash_hex"]
        return

    if op == "lamport_sign_fingerprint":
        seed = _b(inputs["seed_hex"])
        msg = _b(inputs["message_hex"])
        sk, pk = m.lamport_keygen(seed)
        sig = m.lamport_sign(sk, msg)
        got_fp = m.lamport_signature_fingerprint(sig).hex()
        assert got_fp == expected["sig_fp_hex"]
        assert m.lamport_verify(pk, msg, sig) is expected["verify"]
        return

    if op == "mss_keygen_root":
        master_seed = _b(inputs["master_seed_hex"])
        height = int(inputs["height"])
        _, pk, _levels = m.mss_keygen(master_seed, height)
        assert pk.root.hex() == expected["root_hex"]
        return

    if op == "mss_auth_path":
        master_seed = _b(inputs["master_seed_hex"])
        height = int(inputs["height"])
        leaf_index = int(inputs["leaf_index"])
        _sk, pk, levels = m.mss_keygen(master_seed, height)
        path = m.merkle_auth_path(levels, leaf_index)
        got = [x.hex() for x in path]
        assert got == expected["auth_path_hex"]
        assert m.merkle_verify_path(levels[0][leaf_index], leaf_index, path, pk.root) is True
        return

    if op == "mss_sign_verify_fingerprint":
        master_seed = _b(inputs["master_seed_hex"])
        height = int(inputs["height"])
        leaf_index = int(inputs["leaf_index"])
        msg = _b(inputs["message_hex"])
        sk, pk, levels = m.mss_keygen(master_seed, height)
        assert pk.root.hex() == expected["root_hex"]
        sig = m.mss_sign(sk, levels, leaf_index, msg)
        got_fp = m.mss_signature_fingerprint(sig).hex()
        assert got_fp == expected["sig_fp_hex"]
        assert m.mss_verify(pk, msg, sig) is expected["verify"]
        return

    if op == "mss_verify_tampered_message":
        master_seed = _b(inputs["master_seed_hex"])
        height = int(inputs["height"])
        leaf_index = int(inputs["leaf_index"])
        msg = _b(inputs["message_hex"])
        tampered = _b(inputs["tampered_message_hex"])
        sk, pk, levels = m.mss_keygen(master_seed, height)
        sig = m.mss_sign(sk, levels, leaf_index, msg)
        assert m.mss_verify(pk, tampered, sig) is expected["verify"]
        return

    raise ValueError(f"unknown op: {op}")


def test_vectors() -> None:
    vectors = _load_vectors()["vectors"]
    for v in vectors:
        _run_vector(v)


def test_merkle_requires_power_of_two_leaves() -> None:
    leaves = [b"\x00" * 32] * 3
    try:
        m.merkle_build(leaves)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_merkle_verify_path_rejects_wrong_sibling_order() -> None:
    master_seed = b"\x55" * 32
    _sk, pk, levels = m.mss_keygen(master_seed, 3)
    idx = 6
    path = m.merkle_auth_path(levels, idx)
    assert m.merkle_verify_path(levels[0][idx], idx, path, pk.root) is True
    bad_path = list(path)
    bad_path[0], bad_path[1] = bad_path[1], bad_path[0]
    assert m.merkle_verify_path(levels[0][idx], idx, bad_path, pk.root) is False


def test_mss_rejects_wrong_index() -> None:
    master_seed = b"\x66" * 32
    sk, pk, levels = m.mss_keygen(master_seed, 3)
    msg = b"index test"
    sig = m.mss_sign(sk, levels, 1, msg)
    assert m.mss_verify(pk, msg, sig) is True
    sig2 = m.MerkleSignature(
        leaf_index=2,
        lamport_pk_hash=sig.lamport_pk_hash,
        lamport_pk=sig.lamport_pk,
        lamport_sig=sig.lamport_sig,
        auth_path=sig.auth_path,
    )
    assert m.mss_verify(pk, msg, sig2) is False


def test_lamport_signature_tamper_fails() -> None:
    seed = b"\x77" * 32
    sk, pk = m.lamport_keygen(seed)
    msg = b"tamper me"
    sig = m.lamport_sign(sk, msg)
    assert m.lamport_verify(pk, msg, sig) is True
    bad = list(sig)
    bad[0] = b"\x00" * 32
    assert m.lamport_verify(pk, msg, bad) is False


if __name__ == "__main__":
    test_vectors()
    test_merkle_requires_power_of_two_leaves()
    test_merkle_verify_path_rejects_wrong_sibling_order()
    test_mss_rejects_wrong_index()
    test_lamport_signature_tamper_fails()
    print("all tests pass")

