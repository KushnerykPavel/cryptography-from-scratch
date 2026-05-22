import json
import random
import sys
from pathlib import Path


LESSON = Path(__file__).resolve().parents[1]
VECTORS_PATH = LESSON / "tests" / "vectors.json"

sys.path.insert(0, str(LESSON / "code"))
import main as btc  # noqa: E402


def _b(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


def call(vector):
    op = vector["op"]

    if op == "sha256":
        return btc.sha256(_b(vector["data_hex"])).hex()

    if op == "hash256":
        return btc.hash256(_b(vector["data_hex"])).hex()

    if op == "tagged_hash":
        return btc.tagged_hash(vector["tag"], _b(vector["msg_hex"])).hex()

    if op == "pubkey_gen_xonly":
        return btc.pubkey_gen_xonly(_b(vector["seckey_hex"])).hex()

    if op == "schnorr_sign":
        msg = _b(vector["msg_hex"])
        seckey = _b(vector["seckey_hex"])
        aux = _b(vector["aux_hex"])
        return btc.schnorr_sign(msg, seckey, aux).hex()

    if op == "schnorr_verify":
        msg = _b(vector["msg_hex"])
        pubkey = _b(vector["pubkey_hex"])
        sig = _b(vector["sig_hex"])
        return btc.schnorr_verify(msg, pubkey, sig)

    raise AssertionError(f"unknown op: {op}")


def test_vectors():
    vectors = json.loads(VECTORS_PATH.read_text())["vectors"]
    for vector in vectors:
        if "expected_error" in vector:
            try:
                call(vector)
            except ValueError as error:
                assert str(error) == vector["expected_error"]
            else:
                raise AssertionError(f"{vector['op']} did not raise")
            continue

        if "expected_hex" in vector:
            assert call(vector).lower() == vector["expected_hex"].lower()
        else:
            assert call(vector) == vector["expected"]


def test_sign_verify_roundtrip():
    rng = random.Random(0)
    for i in range(25):
        d = rng.randrange(1, btc.SECP256K1_N)
        seckey = btc.int_to_bytes(d, 32)
        pubkey = btc.pubkey_gen_xonly(seckey)
        msg = btc.sha256(b"msg:" + btc.int_to_bytes(i, 4))
        aux = btc.sha256(b"aux:" + btc.int_to_bytes(i, 4))
        sig = btc.schnorr_sign(msg, seckey, aux)
        assert btc.schnorr_verify(msg, pubkey, sig)


def test_message_binding():
    d = 3
    seckey = btc.int_to_bytes(d, 32)
    pubkey = btc.pubkey_gen_xonly(seckey)
    msg1 = b"\x00" * 32
    msg2 = b"\x01" * 32
    aux = b"\x00" * 32
    sig = btc.schnorr_sign(msg1, seckey, aux)
    assert btc.schnorr_verify(msg1, pubkey, sig)
    assert not btc.schnorr_verify(msg2, pubkey, sig)


def test_rejects_bad_lengths():
    try:
        btc.schnorr_sign(b"", b"\x01" * 31, b"\x00" * 32)
    except ValueError as error:
        assert str(error) == "seckey must be 32 bytes"
    else:
        raise AssertionError("expected seckey length error")

    try:
        btc.schnorr_sign(b"", b"\x01" * 32, b"\x00" * 31)
    except ValueError as error:
        assert str(error) == "aux_rand must be 32 bytes instead of 31"
    else:
        raise AssertionError("expected aux length error")

    try:
        btc.schnorr_verify(b"", b"\x00" * 31, b"\x00" * 64)
    except ValueError as error:
        assert str(error) == "pubkey must be 32 bytes"
    else:
        raise AssertionError("expected pubkey length error")

    try:
        btc.schnorr_verify(b"", b"\x00" * 32, b"\x00" * 63)
    except ValueError as error:
        assert str(error) == "sig must be 64 bytes"
    else:
        raise AssertionError("expected sig length error")


def test_lift_x_returns_even_y():
    pubkey = bytes.fromhex("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9")
    P = btc.lift_x(btc.bytes_to_int(pubkey))
    assert P is not None
    assert btc.has_even_y(P)


if __name__ == "__main__":
    test_vectors()
    test_sign_verify_roundtrip()
    test_message_binding()
    test_rejects_bad_lengths()
    test_lift_x_returns_even_y()
    print("all tests pass")
