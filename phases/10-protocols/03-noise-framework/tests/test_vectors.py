import json
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (  # noqa: E402
    aead_decrypt,
    aead_encrypt,
    decrypt_and_hash,
    dh_keypair,
    dh_public_key,
    dh_shared_secret,
    encrypt_and_hash,
    hkdf_sha256,
    initialize_symmetric,
    mix_hash,
    mix_key,
    noise_nn_handshake,
)


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        if op == "hkdf_sha256":
            ck = bytes.fromhex(v["chaining_key_hex"])
            ikm = bytes.fromhex(v["ikm_hex"])
            got = [x.hex() for x in hkdf_sha256(ck, ikm, num_outputs=v["num_outputs"])]
            assert got == v["expected_hex"], f"hkdf_sha256 failed: got {got}, expected {v['expected_hex']}"
            continue

        if op == "mix_hash":
            h = bytes.fromhex(v["h_hex"])
            data_bytes = bytes.fromhex(v["data_hex"])
            got = mix_hash(h, data_bytes).hex()
            assert got == v["expected_hex"], f"mix_hash failed: got {got}, expected {v['expected_hex']}"
            continue

        if op == "dh_shared_secret":
            pub = int(v["public"])
            got = dh_shared_secret(v["private"], pub).hex()
            assert got == v["expected_hex"], f"dh_shared_secret failed: got {got}, expected {v['expected_hex']}"
            continue

        if op == "aead_encrypt":
            key = bytes.fromhex(v["key_hex"])
            nonce = v["nonce"]
            aad = bytes.fromhex(v["aad_hex"])
            pt = bytes.fromhex(v["plaintext_hex"])
            got = aead_encrypt(key, nonce, aad, pt).hex()
            assert got == v["expected_hex"], f"aead_encrypt failed: got {got}, expected {v['expected_hex']}"
            continue

        if op == "noise_nn_handshake":
            prologue = bytes.fromhex(v["prologue_hex"])
            res = noise_nn_handshake(
                initiator_e_priv=v["initiator_e_priv"], responder_e_priv=v["responder_e_priv"], prologue=prologue
            )
            exp = v["expected"]
            assert res.handshake_hash.hex() == exp["handshake_hash_hex"]
            assert res.initiator_tx.hex() == exp["initiator_tx_hex"]
            assert res.initiator_rx.hex() == exp["initiator_rx_hex"]
            assert res.responder_tx.hex() == exp["responder_tx_hex"]
            assert res.responder_rx.hex() == exp["responder_rx_hex"]
            continue

        raise AssertionError(f"unknown op {op}")


def test_dh_commutativity():
    rng = random.Random(0)
    for _ in range(50):
        a_priv, a_pub = dh_keypair(rng)
        b_priv, b_pub = dh_keypair(rng)
        assert dh_shared_secret(a_priv, b_pub) == dh_shared_secret(b_priv, a_pub)


def test_aead_roundtrip_and_rejection():
    rng = random.Random(0)
    for n in range(0, 65):
        key = rng.randbytes(32)
        nonce = rng.randrange(0, 2**32)
        aad = rng.randbytes(rng.randrange(0, 16))
        pt = rng.randbytes(n)
        ct = aead_encrypt(key, nonce, aad, pt)
        got = aead_decrypt(key, nonce, aad, ct)
        assert got == pt

    key = b"\x00" * 32
    nonce = 0
    aad = b""
    pt = b"hello"
    ct = bytearray(aead_encrypt(key, nonce, aad, pt))
    ct[-1] ^= 1
    try:
        aead_decrypt(key, nonce, aad, bytes(ct))
        raise AssertionError("expected tag mismatch")
    except ValueError:
        pass


def test_encrypt_and_hash_transcript_consistency():
    ck, h0 = initialize_symmetric("Noise_NN_25519_SHA256_ToyAEAD")
    h0 = mix_hash(h0, b"prologue")
    ck, k = mix_key(ck, b"shared")
    h1, c = encrypt_and_hash(k, h0, nonce=0, plaintext=b"hello")
    h2, p = decrypt_and_hash(k, h0, nonce=0, ciphertext=c)
    assert p == b"hello"
    assert h1 == h2


def test_hkdf_rejects_bad_count():
    ck, _ = initialize_symmetric("Noise_NN_25519_SHA256_ToyAEAD")
    for n in [-1, 0, 4]:
        try:
            hkdf_sha256(ck, b"x", num_outputs=n)
            raise AssertionError("expected ValueError")
        except ValueError:
            pass


if __name__ == "__main__":
    test_vectors()
    test_dh_commutativity()
    test_aead_roundtrip_and_rejection()
    test_encrypt_and_hash_transcript_consistency()
    test_hkdf_rejects_bad_count()
    print("all tests pass")

