import json
import os
import sys


HERE = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main


def _load_vectors():
    path = os.path.join(HERE, "vectors.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _bytes_from_inputs(inputs: dict) -> bytes:
    if "data_hex" in inputs:
        return bytes.fromhex(inputs["data_hex"])
    if "data_utf8" in inputs:
        return inputs["data_utf8"].encode("utf-8")
    raise KeyError("expected one of: data_hex, data_utf8")


def _run_vector(vec: dict):
    op = vec["op"]
    inputs = vec["inputs"]
    expected = vec["expected"]

    if op == "keccak_256_hex":
        got = main.keccak_256_hex(_bytes_from_inputs(inputs))
        assert got == expected.lower()
        return

    if op == "eip55_checksum_address":
        got = main.eip55_checksum_address(inputs["address"])
        assert got == expected
        return

    if op == "pubkey_keccak256_from_privkey":
        priv = int(inputs["privkey_hex"], 16)
        pub = main.secp256k1_public_key_uncompressed(priv)
        got = main.keccak_256_hex(pub[1:])
        assert got == expected.lower()
        return

    if op == "eth_address_from_privkey":
        priv = int(inputs["privkey_hex"], 16)
        pub = main.secp256k1_public_key_uncompressed(priv)
        got = main.ethereum_address_from_pubkey_uncompressed(pub)
        assert got == expected.lower()
        return

    if op == "ecdsa_sign_sha256_der":
        priv = int(inputs["privkey_int"])
        msg = inputs["message_utf8"].encode("utf-8")
        got = main.ecdsa_sign_sha256_der(priv, msg)
        assert got.upper() == expected.upper()
        return

    raise ValueError(f"unknown op: {op}")


def test_vectors():
    data = _load_vectors()
    assert isinstance(data.get("source"), str) and data["source"]
    vectors = data.get("vectors")
    assert isinstance(vectors, list) and vectors
    for vec in vectors:
        _run_vector(vec)


def test_keccak_is_not_sha3_256():
    assert main.keccak_256_hex(b"") != main.hashlib.sha3_256(b"").hexdigest()


def test_pubkey_and_address_roundtrip_example():
    priv = int("f8f8a2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f315", 16)
    pub = main.secp256k1_public_key_uncompressed(priv)
    assert pub[0] == 0x04 and len(pub) == 65
    assert main.is_on_secp256k1((int.from_bytes(pub[1:33], "big"), int.from_bytes(pub[33:], "big")))

    addr = main.ethereum_address_from_pubkey_uncompressed(pub)
    assert addr == "0x001d3f1ef827552ae1114027bd3ecf1f086ba0f9"
    assert main.eip55_checksum_address(addr) == "0x001d3F1ef827552Ae1114027BD3ECF1f086bA0F9"


def test_ecdsa_verify_accepts_our_own_signatures():
    priv = 1
    pub = main.secp256k1_public_key_uncompressed(priv)
    msg_hash = main.keccak_256(b"hello")
    sig = main.ecdsa_sign_rfc6979(priv, msg_hash)
    assert main.ecdsa_verify(pub, msg_hash, sig)


def test_ecdsa_verify_rejects_tampering():
    priv = 1
    pub = main.secp256k1_public_key_uncompressed(priv)
    msg_hash = main.keccak_256(b"hello")
    sig = main.ecdsa_sign_rfc6979(priv, msg_hash)

    assert not main.ecdsa_verify(pub, main.keccak_256(b"hello!"), sig)
    assert not main.ecdsa_verify(pub, msg_hash, (sig[0] + 1, sig[1]))
    assert not main.ecdsa_verify(pub, msg_hash, (sig[0], sig[1] + 1))


def test_eip55_rejects_bad_input():
    try:
        main.eip55_checksum_address("0x1234")
        raise AssertionError("expected ValueError for short address")
    except ValueError:
        pass

    try:
        main.eip55_checksum_address("0x" + "g" * 40)
        raise AssertionError("expected ValueError for non-hex address")
    except ValueError:
        pass


def test_eip191_hash_matches_manual_prefixing():
    msg = b"hello"
    manual = main.keccak_256(b"\x19Ethereum Signed Message:\n5hello")
    assert main.eip191_personal_message_hash(msg) == manual


if __name__ == "__main__":
    tests = [
        test_vectors,
        test_keccak_is_not_sha3_256,
        test_pubkey_and_address_roundtrip_example,
        test_ecdsa_verify_accepts_our_own_signatures,
        test_ecdsa_verify_rejects_tampering,
        test_eip55_rejects_bad_input,
        test_eip191_hash_matches_manual_prefixing,
    ]
    for t in tests:
        t()
    print("all tests pass")
