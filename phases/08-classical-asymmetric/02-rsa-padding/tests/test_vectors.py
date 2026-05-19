import json
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
CODE_DIR = (HERE / "../code").resolve()
sys.path.insert(0, str(CODE_DIR))

import main as rsa  # noqa: E402


def _b(hex_str: str) -> bytes:
    if hex_str == "":
        return b""
    return bytes.fromhex(hex_str)


def _load_vectors():
    with open(HERE / "vectors.json", "r", encoding="utf-8") as f:
        data = json.load(f)
    return data["vectors"]


def test_vectors():
    key = rsa.DEMO_KEY
    vectors = _load_vectors()
    for v in vectors:
        op = v["op"]
        inputs = v["inputs"]
        expected = v["expected"]

        if op == "mgf1":
            out = rsa.mgf1(_b(inputs["seed_hex"]), inputs["mask_len"], inputs["hash_name"])
            assert out.hex() == expected["mask_hex"]
        elif op == "eme_pkcs1_v1_5_encode":
            out = rsa.eme_pkcs1_v1_5_encode(
                _b(inputs["message_hex"]), inputs["k"], ps=_b(inputs["ps_hex"])
            )
            assert out.hex() == expected["em_hex"]
        elif op == "rsaes_pkcs1_v1_5_encrypt":
            out = rsa.rsaes_pkcs1_v1_5_encrypt(
                _b(inputs["message_hex"]), key.n, key.e, ps=_b(inputs["ps_hex"])
            )
            assert out.hex() == expected["ciphertext_hex"]
            assert rsa.rsaes_pkcs1_v1_5_decrypt(out, key.n, key.d) == _b(inputs["message_hex"])
        elif op == "oaep_encode":
            out = rsa.oaep_encode(
                _b(inputs["message_hex"]),
                inputs["k"],
                label=_b(inputs["label_hex"]),
                hash_name=inputs["hash_name"],
                seed=_b(inputs["seed_hex"]),
            )
            assert out.hex() == expected["em_hex"]
            assert (
                rsa.oaep_decode(
                    out, inputs["k"], label=_b(inputs["label_hex"]), hash_name=inputs["hash_name"]
                )
                == _b(inputs["message_hex"])
            )
        elif op == "rsaes_oaep_encrypt":
            out = rsa.rsaes_oaep_encrypt(
                _b(inputs["message_hex"]),
                key.n,
                key.e,
                hash_name=inputs["hash_name"],
                seed=_b(inputs["seed_hex"]),
            )
            assert out.hex() == expected["ciphertext_hex"]
            assert (
                rsa.rsaes_oaep_decrypt(out, key.n, key.d, hash_name=inputs["hash_name"])
                == _b(inputs["message_hex"])
            )
        elif op == "pss_encode":
            out = rsa.pss_encode(
                _b(inputs["message_hash_hex"]),
                inputs["em_bits"],
                hash_name=inputs["hash_name"],
                salt=_b(inputs["salt_hex"]),
            )
            assert out.hex() == expected["em_hex"]
            assert rsa.pss_verify(
                _b(inputs["message_hash_hex"]),
                out,
                inputs["em_bits"],
                hash_name=inputs["hash_name"],
                salt_len=len(_b(inputs["salt_hex"])),
            )
        elif op == "rsassa_pss_sign":
            out = rsa.rsassa_pss_sign(
                _b(inputs["message_hex"]),
                key.n,
                key.d,
                hash_name=inputs["hash_name"],
                salt=_b(inputs["salt_hex"]),
            )
            assert out.hex() == expected["signature_hex"]
            assert rsa.rsassa_pss_verify(
                _b(inputs["message_hex"]),
                out,
                key.n,
                key.e,
                hash_name=inputs["hash_name"],
                salt_len=len(_b(inputs["salt_hex"])),
            )
        elif op == "rsassa_pkcs1_v1_5_sign":
            out = rsa.rsassa_pkcs1_v1_5_sign(
                _b(inputs["message_hex"]), key.n, key.d, hash_name=inputs["hash_name"]
            )
            assert out.hex() == expected["signature_hex"]
            assert rsa.rsassa_pkcs1_v1_5_verify(
                _b(inputs["message_hex"]), out, key.n, key.e, hash_name=inputs["hash_name"]
            )
        else:
            raise AssertionError(f"unknown op: {op}")


def test_properties():
    key = rsa.DEMO_KEY

    # OAEP: label must match.
    msg = b"label mismatch"
    seed = bytes.fromhex("11" * hashlib_len("sha256"))
    ct = rsa.rsaes_oaep_encrypt(msg, key.n, key.e, hash_name="sha256", seed=seed, label=b"a")
    assert rsa.rsaes_oaep_decrypt(ct, key.n, key.d, hash_name="sha256", label=b"a") == msg
    try:
        rsa.rsaes_oaep_decrypt(ct, key.n, key.d, hash_name="sha256", label=b"b")
        assert False, "expected label mismatch to fail"
    except ValueError:
        pass

    # PSS: signature must bind to message.
    salt = bytes.fromhex("22" * 32)
    sig = rsa.rsassa_pss_sign(b"m1", key.n, key.d, hash_name="sha256", salt=salt)
    assert rsa.rsassa_pss_verify(b"m1", sig, key.n, key.e, hash_name="sha256", salt_len=32)
    assert not rsa.rsassa_pss_verify(b"m2", sig, key.n, key.e, hash_name="sha256", salt_len=32)

    # PKCS#1 v1.5 encryption padding: header byte must be 0x02.
    msg2 = b"hi"
    em = rsa.eme_pkcs1_v1_5_encode(msg2, key.k, ps=b"\x01" * (key.k - len(msg2) - 3))
    bad = b"\x00\x01" + em[2:]
    try:
        rsa.eme_pkcs1_v1_5_decode(bad)
        assert False, "expected decode failure"
    except ValueError:
        pass


def hashlib_len(hash_name: str) -> int:
    import hashlib

    return hashlib.new(hash_name).digest_size


if __name__ == "__main__":
    test_vectors()
    test_properties()
    print("all tests pass")

