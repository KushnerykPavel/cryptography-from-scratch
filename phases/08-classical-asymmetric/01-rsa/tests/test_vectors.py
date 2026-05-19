import json
import os
import math
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (
    RSAKeypair,
    bytes_to_int,
    factor_semiprime_trial,
    int_to_bytes,
    is_probable_prime,
    mod_inverse,
    mod_pow,
    recover_private_exponent_from_factoring,
    rsa_decrypt_int,
    rsa_encrypt_int,
    rsa_generate_keypair,
    rsa_keypair_from_primes,
)


def _from_hex(s: str) -> bytes:
    return bytes.fromhex(s)


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]
        if op == "mod_inverse":
            got = mod_inverse(v["a"], v["modulus"])
            assert got == v["expected"], f"mod_inverse failed: got {got}, expected {v['expected']}"
        elif op == "mod_pow":
            got = mod_pow(v["base"], v["exponent"], v["modulus"])
            assert got == v["expected"], f"mod_pow failed: got {got}, expected {v['expected']}"
        elif op == "is_probable_prime":
            got = is_probable_prime(v["n"])
            assert got == v["expected"], f"is_probable_prime failed: got {got}, expected {v['expected']}"
        elif op == "rsa_keypair_from_primes":
            key = rsa_keypair_from_primes(p=v["p"], q=v["q"], e=v["e"])
            assert key.n == v["expected_n"], f"keygen n failed: got {key.n}, expected {v['expected_n']}"
            assert key.d == v["expected_d"], f"keygen d failed: got {key.d}, expected {v['expected_d']}"
        elif op == "rsa_encrypt_int":
            got = rsa_encrypt_int(v["m"], v["n"], v["e"])
            assert got == v["expected"], f"rsa_encrypt_int failed: got {got}, expected {v['expected']}"
        elif op == "rsa_decrypt_int":
            got = rsa_decrypt_int(v["c"], v["n"], v["d"])
            assert got == v["expected"], f"rsa_decrypt_int failed: got {got}, expected {v['expected']}"
        elif op == "bytes_to_int":
            got = bytes_to_int(_from_hex(v["bytes_hex"]))
            assert got == v["expected"], f"bytes_to_int failed: got {got}, expected {v['expected']}"
        elif op == "int_to_bytes":
            got = int_to_bytes(v["x"], v["length"]).hex()
            assert got == v["expected_hex"], f"int_to_bytes failed: got {got}, expected {v['expected_hex']}"
        elif op == "factor_semiprime_trial":
            p, q = factor_semiprime_trial(v["n"])
            got = sorted([p, q])
            assert got == sorted(v["expected_factors"]), f"factoring failed: got {got}, expected {v['expected_factors']}"
        elif op == "recover_private_exponent_from_factoring":
            p, q, d = recover_private_exponent_from_factoring(v["n"], v["e"])
            got = sorted([p, q])
            assert got == sorted(v["expected_factors"]), f"recover factors failed: got {got}, expected {v['expected_factors']}"
            assert d == v["expected_d"], f"recover d failed: got {d}, expected {v['expected_d']}"
        else:
            raise AssertionError(f"unknown op {op}")


def test_mod_inverse_property():
    rng = random.Random(0)
    for _ in range(200):
        modulus = rng.randrange(3, 5000)
        a = rng.randrange(1, modulus)
        if math.gcd(a, modulus) != 1:
            continue
        inv = mod_inverse(a, modulus)
        assert (a * inv) % modulus == 1


def test_rsa_roundtrip_ints_small_key():
    rng = random.Random(123)
    key = rsa_generate_keypair(bits=32, e=65537, rng=rng)
    assert isinstance(key, RSAKeypair)

    rng = random.Random(999)
    for _ in range(50):
        m = rng.randrange(0, key.n)
        c = rsa_encrypt_int(m, key.n, key.e)
        back = rsa_decrypt_int(c, key.n, key.d)
        assert back == m


def test_error_rejection():
    key = rsa_keypair_from_primes(61, 53, 17)
    try:
        rsa_encrypt_int(-1, key.n, key.e)
        raise AssertionError("expected ValueError for negative message")
    except ValueError:
        pass
    try:
        rsa_encrypt_int(key.n, key.n, key.e)
        raise AssertionError("expected ValueError for m >= n")
    except ValueError:
        pass
    try:
        rsa_decrypt_int(key.n, key.n, key.d)
        raise AssertionError("expected ValueError for c >= n")
    except ValueError:
        pass


if __name__ == "__main__":
    test_vectors()
    test_mod_inverse_property()
    test_rsa_roundtrip_ints_small_key()
    test_error_rejection()
    print("all tests pass")
