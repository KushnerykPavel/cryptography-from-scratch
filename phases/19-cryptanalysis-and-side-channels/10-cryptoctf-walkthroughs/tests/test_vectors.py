import json
import os
import sys

HERE = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as ctf  # noqa: E402


def _b(hex_str: str) -> bytes:
    if hex_str == "":
        return b""
    return bytes.fromhex(hex_str)


def test_vectors():
    with open(os.path.join(HERE, "vectors.json"), "r", encoding="utf-8") as f:
        data = json.load(f)

    for vec in data["vectors"]:
        op = vec["op"]
        if op == "decode_hex_or_base64":
            got = ctf.decode_hex_or_base64(vec["s"]).hex()
            assert got == vec["expected_hex"]
        elif op == "break_single_byte_xor":
            k, pt = ctf.break_single_byte_xor(_b(vec["ciphertext_hex"]))
            assert k == vec["expected_key"]
            assert pt.hex() == vec["expected_plaintext_hex"]
        elif op == "find_shared_prime":
            got = ctf.find_shared_prime(int(vec["n1"]), int(vec["n2"]))
            assert got == vec["expected"]
        else:
            raise ValueError(f"unknown op in vectors.json: {op}")


def test_shared_prime_rsa_decrypts():
    p = 1_000_003
    q1 = 1_000_033
    q2 = 1_000_037
    e = 65537
    n1 = p * q1
    n2 = p * q2
    g = ctf.find_shared_prime(n1, n2)
    assert g == p

    pub = ctf.RSAPublic(n=n1, e=e)
    msg = b"hi"
    c1 = ctf.rsa_encrypt_bytes(msg, pub)
    recovered = ctf.rsa_decrypt_int(c1, p=g, q=n1 // g, e=e)
    assert recovered == msg


if __name__ == "__main__":
    tests = [
        test_vectors,
        test_shared_prime_rsa_decrypts,
    ]
    for t in tests:
        t()
    print("all tests pass")
