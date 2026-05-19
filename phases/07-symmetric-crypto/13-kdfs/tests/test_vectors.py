import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))

from main import (  # noqa: E402
    derive_subkeys_hkdf,
    hkdf_expand_sha256,
    hkdf_extract_sha256,
    hkdf_sha256,
    pbkdf2_hmac_sha256,
    scrypt_kdf,
)


def _from_hex(s: str) -> bytes:
    return bytes.fromhex(s)


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json"), "r", encoding="utf-8") as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]
        inputs = v["inputs"]
        expected = _from_hex(v["expected_hex"])

        if op == "hkdf_extract_sha256":
            salt = _from_hex(inputs["salt_hex"])
            ikm = _from_hex(inputs["ikm_hex"])
            got = hkdf_extract_sha256(salt=salt, ikm=ikm)
            assert got == expected
        elif op == "hkdf_expand_sha256":
            prk = _from_hex(inputs["prk_hex"])
            info = _from_hex(inputs["info_hex"])
            got = hkdf_expand_sha256(prk=prk, info=info, length=inputs["length"])
            assert got == expected
        elif op == "hkdf_sha256":
            salt = _from_hex(inputs["salt_hex"])
            ikm = _from_hex(inputs["ikm_hex"])
            info = _from_hex(inputs["info_hex"])
            got = hkdf_sha256(ikm=ikm, length=inputs["length"], salt=salt, info=info)
            assert got == expected
        elif op == "pbkdf2_hmac_sha256":
            password = _from_hex(inputs["password_hex"])
            salt = _from_hex(inputs["salt_hex"])
            got = pbkdf2_hmac_sha256(
                password=password,
                salt=salt,
                iterations=inputs["iterations"],
                dklen=inputs["dklen"],
            )
            assert got == expected
        elif op == "scrypt":
            password = _from_hex(inputs["password_hex"])
            salt = _from_hex(inputs["salt_hex"])
            got = scrypt_kdf(
                password=password,
                salt=salt,
                n=inputs["n"],
                r=inputs["r"],
                p=inputs["p"],
                dklen=inputs["dklen"],
            )
            assert got == expected
        else:
            raise AssertionError(f"unknown op {op}")


def test_hkdf_expand_edge_cases_and_rejection():
    prk = b"\x00" * hashlib.sha256().digest_size
    assert hkdf_expand_sha256(prk=prk, info=b"", length=0) == b""

    try:
        hkdf_expand_sha256(prk=prk, info=b"", length=255 * 32 + 1)
        raise AssertionError("expected ValueError for oversize HKDF output")
    except ValueError:
        pass


def test_pbkdf2_matches_hashlib():
    cases = [
        (b"password", b"salt", 1, 32),
        (b"password", b"salt", 2, 32),
        (b"password", b"salt", 4096, 32),
        (b"passwordPASSWORDpassword", b"saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 40),
    ]
    for password, salt, iters, dklen in cases:
        got = pbkdf2_hmac_sha256(password=password, salt=salt, iterations=iters, dklen=dklen)
        expected = hashlib.pbkdf2_hmac("sha256", password, salt, iters, dklen)
        assert got == expected


def test_pbkdf2_rejects_invalid_params():
    try:
        pbkdf2_hmac_sha256(password=b"pw", salt=b"s", iterations=0, dklen=32)
        raise AssertionError("expected ValueError for iterations=0")
    except ValueError:
        pass

    try:
        pbkdf2_hmac_sha256(password=b"pw", salt=b"s", iterations=1, dklen=0)
        raise AssertionError("expected ValueError for dklen=0")
    except ValueError:
        pass


def test_scrypt_rejects_invalid_n():
    try:
        scrypt_kdf(password=b"pw", salt=b"salt", n=15, r=1, p=1, dklen=32)
        raise AssertionError("expected ValueError for non-power-of-two n")
    except ValueError:
        pass


def test_key_separation_distinctness():
    k1 = derive_subkeys_hkdf(master_secret=b"ms", salt=b"salt", context=b"context-1")
    k2 = derive_subkeys_hkdf(master_secret=b"ms", salt=b"salt", context=b"context-2")
    assert len(k1.enc_key) == 32 and len(k1.mac_key) == 32 and len(k1.nonce_key) == 12
    assert k1.enc_key != k1.mac_key
    assert k1.enc_key != k1.nonce_key
    assert k1.mac_key != k1.nonce_key
    assert k1 != k2


if __name__ == "__main__":
    test_vectors()
    test_hkdf_expand_edge_cases_and_rejection()
    test_pbkdf2_matches_hashlib()
    test_pbkdf2_rejects_invalid_params()
    test_scrypt_rejects_invalid_n()
    test_key_separation_distinctness()
    print("all tests pass")

