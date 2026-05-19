import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))

from main import (  # noqa: E402
    SecretstreamState,
    _secretbox_with_nonce,
    auth,
    auth_verify,
    kdf_derive_from_key,
    pwhash,
    pwhash_str,
    pwhash_str_verify,
    secretbox,
    secretbox_keygen,
    secretbox_open,
    secretstream_init_pull,
    secretstream_init_push,
    secretstream_keygen,
    secretstream_pull,
    secretstream_push,
    SECRETBOX_KEYBYTES,
    SECRETBOX_NONCEBYTES,
    AUTH_KEYBYTES,
    KDF_BYTES_MIN,
    KDF_BYTES_MAX,
    PWHASH_SALTBYTES,
)


def _h(s: str) -> bytes:
    return bytes.fromhex(s)


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json"), encoding="utf-8") as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]
        inp = v["inputs"]

        if op == "auth":
            key = _h(inp["key_hex"])
            msg = _h(inp["message_hex"])
            got = auth(key, msg)
            assert got == _h(v["expected_hex"]), f"auth mismatch for {v.get('note')}"

        elif op == "pwhash":
            passwd = _h(inp["passwd_hex"])
            salt = _h(inp["salt_hex"])
            got = pwhash(inp["outlen"], passwd, salt, opslimit=inp["opslimit"])
            assert got == _h(v["expected_hex"]), f"pwhash mismatch for {v.get('note')}"

        elif op == "secretbox":
            key = _h(inp["key_hex"])
            nonce = _h(inp["nonce_hex"])
            message = _h(inp["message_hex"])
            aad = _h(inp["aad_hex"])
            got = _secretbox_with_nonce(key, nonce, message, aad)
            assert got == _h(v["expected_box_hex"]), f"secretbox mismatch for {v.get('note')}"
            # roundtrip
            recovered = secretbox_open(key, got, aad)
            assert recovered == message

        elif op == "kdf_derive_from_key":
            key = _h(inp["key_hex"])
            ctx = _h(inp["ctx_hex"])
            got = kdf_derive_from_key(inp["subkey_len"], inp["subkey_id"], ctx, key)
            assert got == _h(v["expected_hex"]), f"kdf mismatch for {v.get('note')}"

        elif op == "secretstream":
            key = _h(inp["key_hex"])
            header = _h(inp["header_hex"])
            msgs = inp["messages"]
            expected_chunks = v["expected_chunks_hex"]

            push_state = SecretstreamState(key=key, nonce_base=header, counter=0)
            pull_state = SecretstreamState(key=key, nonce_base=header, counter=0)

            for i, (m, exp) in enumerate(zip(msgs, expected_chunks)):
                msg = _h(m["message_hex"])
                ad = _h(m["ad_hex"])
                chunk = secretstream_push(push_state, msg, ad=ad)
                assert chunk == _h(exp), f"secretstream push mismatch chunk {i}"
                recovered = secretstream_pull(pull_state, chunk, ad=ad)
                assert recovered == msg, f"secretstream pull mismatch chunk {i}"

        else:
            raise AssertionError(f"unknown op: {op}")


def test_auth_verify_rejects_tampered():
    key = b"\x01" * AUTH_KEYBYTES
    msg = b"legitimate message"
    tag = auth(key, msg)
    assert auth_verify(key, msg, tag)
    assert not auth_verify(key, msg + b"\x00", tag)
    assert not auth_verify(key, msg, tag[:15] + bytes([(tag[15] ^ 1)]))


def test_auth_different_keys_produce_different_tags():
    key1 = b"\x01" * AUTH_KEYBYTES
    key2 = b"\x02" * AUTH_KEYBYTES
    msg = b"same message"
    assert auth(key1, msg) != auth(key2, msg)


def test_secretbox_roundtrip_random_key():
    key = secretbox_keygen()
    message = b"test payload 12345"
    aad = b"context-v1"
    box = secretbox(key, message, aad=aad)
    assert len(box) == SECRETBOX_NONCEBYTES + 16 + len(message)
    recovered = secretbox_open(key, box, aad=aad)
    assert recovered == message


def test_secretbox_rejects_wrong_aad():
    key = secretbox_keygen()
    box = secretbox(key, b"hello", aad=b"real-aad")
    try:
        secretbox_open(key, box, aad=b"wrong-aad")
        raise AssertionError("should have raised ValueError")
    except ValueError:
        pass


def test_secretbox_rejects_bit_flip_in_ciphertext():
    key = secretbox_keygen()
    box = secretbox(key, b"payload")
    flipped = bytearray(box)
    flipped[-1] ^= 0xFF
    try:
        secretbox_open(key, bytes(flipped))
        raise AssertionError("should have raised ValueError")
    except ValueError:
        pass


def test_secretbox_nonce_uniqueness():
    key = secretbox_keygen()
    msg = b"same message"
    box1 = secretbox(key, msg)
    box2 = secretbox(key, msg)
    nonce1 = box1[:SECRETBOX_NONCEBYTES]
    nonce2 = box2[:SECRETBOX_NONCEBYTES]
    assert nonce1 != nonce2, "Two secretbox calls must produce different nonces"


def test_secretbox_empty_message():
    key = secretbox_keygen()
    box = secretbox(key, b"")
    recovered = secretbox_open(key, box)
    assert recovered == b""


def test_kdf_subkeys_are_independent():
    key = b"\xAB" * 32
    ctx = b"testctx1"
    k0 = kdf_derive_from_key(32, 0, ctx, key)
    k1 = kdf_derive_from_key(32, 1, ctx, key)
    k2 = kdf_derive_from_key(32, 2, ctx, key)
    assert k0 != k1 and k1 != k2 and k0 != k2


def test_kdf_different_ctx_produces_different_keys():
    key = b"\xAB" * 32
    k_pay = kdf_derive_from_key(32, 0, b"payments", key)
    k_enc = kdf_derive_from_key(32, 0, b"enckeys0", key)  # different ctx, exactly 8 bytes
    assert k_pay != k_enc


def test_kdf_rejects_invalid_ctx():
    key = b"\x00" * 32
    try:
        kdf_derive_from_key(32, 0, b"tooshort", key)  # exactly 8 bytes - fine
        kdf_derive_from_key(32, 0, b"short", key)  # 5 bytes - should fail
        raise AssertionError("should have raised ValueError")
    except ValueError:
        pass


def test_kdf_rejects_invalid_subkey_len():
    key = b"\x00" * 32
    ctx = b"testctx1"
    try:
        kdf_derive_from_key(KDF_BYTES_MIN - 1, 0, ctx, key)
        raise AssertionError("should have raised ValueError for undersize")
    except ValueError:
        pass
    try:
        kdf_derive_from_key(KDF_BYTES_MAX + 1, 0, ctx, key)
        raise AssertionError("should have raised ValueError for oversize")
    except ValueError:
        pass


def test_pwhash_different_salts_produce_different_keys():
    passwd = b"password"
    salt1 = b"\x01" * PWHASH_SALTBYTES
    salt2 = b"\x02" * PWHASH_SALTBYTES
    k1 = pwhash(32, passwd, salt1, opslimit=1024)
    k2 = pwhash(32, passwd, salt2, opslimit=1024)
    assert k1 != k2


def test_pwhash_str_roundtrip():
    passwd = b"correct horse battery staple"
    stored = pwhash_str(passwd, opslimit=1024)
    assert pwhash_str_verify(stored, passwd)
    assert not pwhash_str_verify(stored, b"wrong password")


def test_secretstream_multi_message_roundtrip():
    key = secretstream_keygen()
    push_state, header = secretstream_init_push(key)
    pull_state = secretstream_init_pull(key, header)

    messages = [b"first", b"second", b"third chunk with more data"]
    chunks = [secretstream_push(push_state, m, ad=b"v1") for m in messages]
    recovered = [secretstream_pull(pull_state, c, ad=b"v1") for c in chunks]
    assert recovered == messages


def test_secretstream_rejects_replay_or_reorder():
    key = secretstream_keygen()
    push_state, header = secretstream_init_push(key)
    chunk0 = secretstream_push(push_state, b"msg0")
    chunk1 = secretstream_push(push_state, b"msg1")

    # Pull in wrong order: counter will be off
    pull_state = secretstream_init_pull(key, header)
    secretstream_pull(pull_state, chunk0)
    try:
        # chunk0 again (replay): counter now 1, but chunk0 was encrypted at counter 0
        secretstream_pull(pull_state, chunk0)
        raise AssertionError("should have rejected replayed chunk")
    except ValueError:
        pass


def test_secretstream_rejects_bit_flip():
    key = secretstream_keygen()
    push_state, header = secretstream_init_push(key)
    chunk = secretstream_push(push_state, b"secret data")
    flipped = bytearray(chunk)
    flipped[0] ^= 0x01
    pull_state = secretstream_init_pull(key, header)
    try:
        secretstream_pull(pull_state, bytes(flipped))
        raise AssertionError("should have raised ValueError")
    except ValueError:
        pass


if __name__ == "__main__":
    test_vectors()
    test_auth_verify_rejects_tampered()
    test_auth_different_keys_produce_different_tags()
    test_secretbox_roundtrip_random_key()
    test_secretbox_rejects_wrong_aad()
    test_secretbox_rejects_bit_flip_in_ciphertext()
    test_secretbox_nonce_uniqueness()
    test_secretbox_empty_message()
    test_kdf_subkeys_are_independent()
    test_kdf_different_ctx_produces_different_keys()
    test_kdf_rejects_invalid_ctx()
    test_kdf_rejects_invalid_subkey_len()
    test_pwhash_different_salts_produce_different_keys()
    test_pwhash_str_roundtrip()
    test_secretstream_multi_message_roundtrip()
    test_secretstream_rejects_replay_or_reorder()
    test_secretstream_rejects_bit_flip()
    print("all tests pass")
