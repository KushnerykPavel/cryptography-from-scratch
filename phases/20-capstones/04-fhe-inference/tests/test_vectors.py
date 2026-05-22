import json
import os
import random
import sys

HERE = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as fhe  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _keygen(seed: int):
    rng = random.Random(seed)
    return fhe.keygen(rng)


def _encrypt(pk, m: int, seed: int):
    rng = random.Random(seed)
    return fhe.encrypt(pk, m, rng)


# ---------------------------------------------------------------------------
# Vector-based tests
# ---------------------------------------------------------------------------

def test_vectors():
    with open(os.path.join(HERE, "vectors.json"), "r", encoding="utf-8") as f:
        data = json.load(f)

    keygen_seed = data["keygen_seed"]
    sk, pk = _keygen(keygen_seed)

    for vec in data["vectors"]:
        op = vec["op"]

        if op == "encrypt_decrypt_roundtrip":
            ct = _encrypt(pk, vec["m"], vec["seed"])
            got = fhe.decrypt(sk, ct)
            assert got == vec["expected_decrypted"], (
                f"roundtrip failed: m={vec['m']} got={got} expected={vec['expected_decrypted']}"
            )

        elif op == "homo_add":
            ct_a = _encrypt(pk, vec["m_a"], vec["seed_a"])
            ct_b = _encrypt(pk, vec["m_b"], vec["seed_b"])
            ct_sum = fhe.homo_add(ct_a, ct_b)
            got = fhe.decrypt(sk, ct_sum)
            assert got == vec["expected_decrypted"], (
                f"homo_add failed: {vec['m_a']}+{vec['m_b']} got={got} expected={vec['expected_decrypted']}"
            )

        elif op == "homo_scalar_mul":
            ct = _encrypt(pk, vec["m"], vec["seed"])
            ct_mul = fhe.homo_scalar_mul(ct, vec["scalar"])
            got = fhe.decrypt(sk, ct_mul)
            assert got == vec["expected_decrypted"], (
                f"homo_scalar_mul failed: {vec['m']}*{vec['scalar']} got={got} expected={vec['expected_decrypted']}"
            )

        elif op == "linear_inference":
            # Uses its own keygen seed
            sk2, pk2 = _keygen(vec["keygen_seed"])
            rng = random.Random(vec["keygen_seed"])
            fhe.keygen(rng)  # advance rng to match state used in vector generation
            rng2 = random.Random(vec["keygen_seed"])
            sk2, pk2 = fhe.keygen(rng2)
            features = tuple(vec["features"])
            enc_inputs = tuple(_encrypt(pk2, f, vec["keygen_seed"] + 1000 + i) for i, f in enumerate(features))
            # Use the same seeded rng for bias as was used in vector generation
            enc_bias = _encrypt(pk2, fhe.MODEL_BIAS % fhe.T, vec["keygen_seed"] + 2000)
            enc_score = fhe.homo_linear(enc_inputs, fhe.MODEL_WEIGHTS, enc_bias)
            score = fhe.decrypt(sk2, enc_score)
            pred = 1 if score > fhe.THRESHOLD else 0
            assert pred == vec["expected_class"], (
                f"linear_inference class mismatch: got={pred} expected={vec['expected_class']} score={score}"
            )

        else:
            raise ValueError(f"unknown op in vectors.json: {op}")


# ---------------------------------------------------------------------------
# Property tests
# ---------------------------------------------------------------------------

def test_encrypt_decrypt_roundtrip():
    """Encrypt then decrypt should recover the original message."""
    sk, pk = _keygen(999)
    for seed, m in enumerate([0, 1, 42, 255, 1000, 5000, 10000]):
        ct = _encrypt(pk, m, seed + 500)
        got = fhe.decrypt(sk, ct)
        assert got == m, f"roundtrip failed for m={m}: got={got}"


def test_homo_add_correct():
    """homo_add should produce enc(a + b)."""
    sk, pk = _keygen(1001)
    pairs = [(10, 20), (0, 0), (100, 200), (300, 150), (1000, 2000)]
    for i, (a, b) in enumerate(pairs):
        ct_a = _encrypt(pk, a, 600 + i)
        ct_b = _encrypt(pk, b, 700 + i)
        ct_sum = fhe.homo_add(ct_a, ct_b)
        got = fhe.decrypt(sk, ct_sum)
        assert got == a + b, f"homo_add({a},{b}) got={got} expected={a+b}"


def test_homo_scalar_mul_correct():
    """homo_scalar_mul should produce enc(m * w)."""
    sk, pk = _keygen(1002)
    cases = [(25, 3), (10, 5), (0, 100), (50, 8), (100, 1)]
    for i, (m, w) in enumerate(cases):
        ct = _encrypt(pk, m, 800 + i)
        ct_mul = fhe.homo_scalar_mul(ct, w)
        got = fhe.decrypt(sk, ct_mul)
        assert got == m * w, f"homo_scalar_mul({m},{w}) got={got} expected={m*w}"


def test_homo_add_commutativity():
    """homo_add(a, b) and homo_add(b, a) should decrypt to the same value."""
    sk, pk = _keygen(1003)
    ct_a = _encrypt(pk, 123, 900)
    ct_b = _encrypt(pk, 456, 901)
    dec_ab = fhe.decrypt(sk, fhe.homo_add(ct_a, ct_b))
    dec_ba = fhe.decrypt(sk, fhe.homo_add(ct_b, ct_a))
    assert dec_ab == dec_ba, f"commutativity failed: {dec_ab} != {dec_ba}"


def test_plaintext_predict_class_split():
    """plaintext_predict returns class 0 for low-score and class 1 for high-score persons."""
    low  = (25, 20, 9, 0)   # expected class 0
    high = (45, 50, 14, 1)  # expected class 1
    _, pred_low  = fhe.plaintext_predict(low)
    _, pred_high = fhe.plaintext_predict(high)
    assert pred_low  == 0, f"expected class 0 for {low}, got {pred_low}"
    assert pred_high == 1, f"expected class 1 for {high}, got {pred_high}"


def test_fhe_matches_plaintext():
    """FHE inference must match plaintext inference on both example persons."""
    sk, pk = _keygen(42)
    rng = random.Random(42)
    # re-generate to match seeded rng state
    sk, pk = fhe.keygen(rng)

    for person in [(25, 20, 9, 0), (45, 50, 14, 1)]:
        enc_inputs = tuple(fhe.encrypt(pk, f, rng) for f in person)
        enc_bias = fhe.encrypt(pk, fhe.MODEL_BIAS % fhe.T, rng)
        enc_score = fhe.homo_linear(enc_inputs, fhe.MODEL_WEIGHTS, enc_bias)
        fhe_pred = 1 if fhe.decrypt(sk, enc_score) > fhe.THRESHOLD else 0
        _, plain_pred = fhe.plaintext_predict(person)
        assert fhe_pred == plain_pred, (
            f"FHE/plaintext mismatch for {person}: fhe={fhe_pred} plain={plain_pred}"
        )


if __name__ == "__main__":
    tests = [
        test_vectors,
        test_encrypt_decrypt_roundtrip,
        test_homo_add_correct,
        test_homo_scalar_mul_correct,
        test_homo_add_commutativity,
        test_plaintext_predict_class_split,
        test_fhe_matches_plaintext,
    ]
    for t in tests:
        t()
    print("all tests pass")
