import json
import os
import random
import sys


THIS_DIR = os.path.dirname(__file__)
CODE_DIR = os.path.join(THIS_DIR, "..", "code")
sys.path.append(os.path.abspath(CODE_DIR))

import main as lesson  # noqa: E402


VECTORS_PATH = os.path.join(THIS_DIR, "vectors.json")


def _load_vectors():
    with open(VECTORS_PATH, "r", encoding="utf-8") as f:
        doc = json.load(f)
    return doc["vectors"]


def _run_vector(vec):
    op = vec["op"]

    if op == "centered_mod":
        got = lesson.centered_mod(vec["x"], vec["modulus"])
        assert got == vec["expected"]
        return

    if op == "encrypt_bit_with_qr":
        got = lesson.encrypt_bit_with_qr(
            vec["p"], vec["m"], q=vec["q"], r=vec["r"]
        )
        assert got == vec["expected"]
        return

    if op == "decrypt_bit":
        got = lesson.decrypt_bit(vec["p"], vec["c"])
        assert got == vec["expected"]
        return

    if op == "ciphertext_noise":
        got = lesson.ciphertext_noise(vec["p"], vec["c"])
        assert got == vec["expected"]
        return

    if op == "homomorphic_xor":
        got = lesson.homomorphic_xor(vec["c1"], vec["c2"])
        assert got == vec["expected"]
        return

    if op == "homomorphic_and":
        got = lesson.homomorphic_and(vec["c1"], vec["c2"])
        assert got == vec["expected"]
        return

    if op == "eval_circuit_xor_and":
        rng = random.Random(vec["rng_seed"])
        got = lesson.eval_circuit_xor_and(
            vec["p"],
            vec["c_bits"],
            q_bits=vec["q_bits"],
            r_bound=vec["r_bound"],
            rng=rng,
        )
        assert got == vec["expected"]
        return

    raise ValueError(f"unknown op: {op}")


def test_vectors():
    for vec in _load_vectors():
        _run_vector(vec)


def test_roundtrip_randomized():
    rng = random.Random(1337)
    p = lesson.keygen_dghv(p_bits=31, rng=rng)

    for _ in range(200):
        m = rng.randrange(2)
        c = lesson.encrypt_bit(p, m, q_bits=64, r_bound=16, rng=rng)
        assert lesson.decrypt_bit(p, c) == m
        assert lesson.ciphertext_noise(p, c) <= 2 * 16 + 1


def test_homomorphic_xor_and_small_noise():
    rng = random.Random(2026)
    p = lesson.keygen_dghv(p_bits=33, rng=rng)

    for _ in range(100):
        m1 = rng.randrange(2)
        m2 = rng.randrange(2)
        c1 = lesson.encrypt_bit(p, m1, q_bits=64, r_bound=8, rng=rng)
        c2 = lesson.encrypt_bit(p, m2, q_bits=64, r_bound=8, rng=rng)

        c_xor = lesson.homomorphic_xor(c1, c2)
        assert lesson.decrypt_bit(p, c_xor) == (m1 ^ m2)

        c_and = lesson.homomorphic_and(c1, c2)
        assert lesson.decrypt_bit(p, c_and) == (m1 & m2)


def test_reject_invalid_inputs():
    rng = random.Random(0)
    p = lesson.keygen_dghv(p_bits=17, rng=rng)

    for bad_m in (-1, 2, 3, 10):
        try:
            lesson.encrypt_bit(p, bad_m, q_bits=16, r_bound=3, rng=rng)
        except ValueError:
            pass
        else:
            raise AssertionError("encrypt_bit should reject m not in {0,1}")

    try:
        lesson.centered_mod(1, 10)
    except ValueError:
        pass
    else:
        raise AssertionError("centered_mod should reject even modulus")


def test_noise_non_decreasing_under_and_chain():
    rng = random.Random(99)
    p = lesson.keygen_dghv(p_bits=31, rng=rng)

    c = lesson.encrypt_bit(p, 1, q_bits=64, r_bound=8, rng=rng)
    prev_noise = lesson.ciphertext_noise(p, c)

    for _ in range(6):
        c = lesson.homomorphic_and(c, lesson.encrypt_bit(p, 1, q_bits=64, r_bound=8, rng=rng))
        n = lesson.ciphertext_noise(p, c)
        assert n >= prev_noise
        prev_noise = n


if __name__ == "__main__":
    test_vectors()
    test_roundtrip_randomized()
    test_homomorphic_xor_and_small_noise()
    test_reject_invalid_inputs()
    test_noise_non_decreasing_under_and_chain()
    print("all tests pass")

