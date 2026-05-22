"""
FHE Inference Service (educational).

Run:
  python3 code/main.py

This lesson builds a toy BFV-like scheme over Z_q and uses it to run a
simple linear classifier entirely on encrypted data — the server never sees
plaintext inputs.
"""

from __future__ import annotations

import random
from typing import Tuple

# ---------------------------------------------------------------------------
# Scheme parameters
#   t  – plaintext modulus  (messages live in Z_t, i.e., {0..t-1})
#   q  – ciphertext modulus (q >> t; ciphertexts live in Z_q)
#   n  – secret-key dimension
#   B  – noise bound for fresh samples
#
# Noise budget rough bound:
#   After one scalar-ciphertext multiplication by weight w:
#     noise grows by |w|.
#   After 4 such multiplications and one add:
#     total noise <= 4 * |w_max| * (B + 1) + B  (rough)
#   Decryption succeeds iff total_noise < q / (2*t).
#
#   With q=2^48, t=2^16, q/(2t) ~= 2^31:
#   Max weight = 150, B = 8, 4 terms -> 4 * 150 * 9 + 8 = 5408 << 2^31.  OK.
# ---------------------------------------------------------------------------
T = 1 << 16          # plaintext modulus
Q = 1 << 48          # ciphertext modulus
N = 8                # key dimension
B = 8                # noise bound (samples from [-B, B])

# Half of T, used to centre-decode signed plaintext values
T_HALF = T >> 1

# ---------------------------------------------------------------------------
# Arithmetic helpers
# ---------------------------------------------------------------------------

def _mod_centered(x: int, m: int) -> int:
    """Symmetric-range modular reduction: result in (-m/2, m/2]."""
    r = x % m
    if r > m // 2:
        r -= m
    return r


def _sample_noise(rng: random.Random, bound: int) -> int:
    """Uniform integer in [-bound, bound]."""
    return rng.randint(-bound, bound)


def _sample_ternary(rng: random.Random) -> int:
    """Small ternary value in {-1, 0, 1}."""
    return rng.randint(-1, 1)


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

class SecretKey:
    """Secret key: a length-n vector with entries in {-1, 0, 1}."""

    def __init__(self, s: Tuple[int, ...]) -> None:
        if len(s) != N:
            raise ValueError(f"SecretKey requires length-{N} vector")
        self.s = s


class PublicKey:
    """
    Public key: (a, b) where
      a is a random vector in Z_q^n
      b = -<a, s> + e  mod q   (e is small noise)
    """

    def __init__(self, a: Tuple[int, ...], b: int) -> None:
        if len(a) != N:
            raise ValueError(f"PublicKey requires length-{N} a-vector")
        self.a = a
        self.b = b


def keygen(rng: random.Random) -> Tuple[SecretKey, PublicKey]:
    """Generate a fresh (SecretKey, PublicKey) pair."""
    s = tuple(_sample_ternary(rng) for _ in range(N))
    a = tuple(rng.randint(0, Q - 1) for _ in range(N))
    e = _sample_noise(rng, B)
    dot_as = sum(ai * si for ai, si in zip(a, s)) % Q
    b = (-dot_as + e) % Q
    sk = SecretKey(s)
    pk = PublicKey(a, b)
    return sk, pk


# ---------------------------------------------------------------------------
# Ciphertext: a pair (c0: int, c1: Tuple[int, ...])
#
# c0 lives in Z_q, c1 is a length-n vector in Z_q^n.
# ---------------------------------------------------------------------------

Ciphertext = Tuple[int, Tuple[int, ...]]


# ---------------------------------------------------------------------------
# Encode / Decode (message lifting)
# ---------------------------------------------------------------------------

def _delta() -> int:
    """Return Delta = round(Q / T)."""
    return (Q + T // 2) // T


def _encode(m: int) -> int:
    """Map a plaintext integer m to the ciphertext-space representative."""
    delta = _delta()
    return (m % T) * delta % Q


def _decode(v: int) -> int:
    """
    Invert _encode: given ciphertext-space value v, recover plaintext.
    Returns a *signed* value in (-T/2, T/2].
    """
    delta = _delta()
    # First, work in symmetric range mod Q
    v_sym = _mod_centered(v, Q)
    # Round to nearest multiple of delta
    m_raw = (v_sym + delta // 2) // delta if v_sym >= 0 else -((-v_sym + delta // 2) // delta)
    return _mod_centered(m_raw, T)


# ---------------------------------------------------------------------------
# Encrypt / Decrypt
# ---------------------------------------------------------------------------

def encrypt(pk: PublicKey, m: int, rng: random.Random) -> Ciphertext:
    """
    Encrypt plaintext m in Z_t under pk.

    r  – ternary scalar
    e0 – small noise for c0
    e1 – small noise vector for c1

    c0 = b*r + e0 + encode(m)  mod q
    c1[i] = a[i]*r + e1[i]     mod q
    """
    r = _sample_ternary(rng)
    e0 = _sample_noise(rng, B)
    e1 = tuple(_sample_noise(rng, B) for _ in range(N))

    m_enc = _encode(m % T)
    c0 = (pk.b * r + e0 + m_enc) % Q
    c1 = tuple((pk.a[i] * r + e1[i]) % Q for i in range(N))
    return c0, c1


def decrypt(sk: SecretKey, ct: Ciphertext) -> int:
    """
    Decrypt ciphertext ct = (c0, c1) using secret key sk.

    v = c0 + <c1, s>  mod q
    m = decode(v)

    Returns signed integer in (-T/2, T/2].
    """
    c0, c1 = ct
    dot = sum(c1[i] * sk.s[i] for i in range(N)) % Q
    v = (c0 + dot) % Q
    return _decode(v)


# ---------------------------------------------------------------------------
# Homomorphic operations
# ---------------------------------------------------------------------------

def homo_add(ct_a: Ciphertext, ct_b: Ciphertext) -> Ciphertext:
    """Homomorphic addition: enc(a) + enc(b) -> enc(a + b)."""
    c0_a, c1_a = ct_a
    c0_b, c1_b = ct_b
    c0 = (c0_a + c0_b) % Q
    c1 = tuple((c1_a[i] + c1_b[i]) % Q for i in range(N))
    return c0, c1


def homo_scalar_mul(ct: Ciphertext, scalar: int) -> Ciphertext:
    """
    Multiply an encrypted value by a public plaintext scalar w.

    enc(m) * w -> enc(m * w)  (noise grows by |w| * original_noise).
    """
    c0, c1 = ct
    c0_new = (c0 * scalar) % Q
    c1_new = tuple((c1[i] * scalar) % Q for i in range(N))
    return c0_new, c1_new


# ---------------------------------------------------------------------------
# Linear inference
# ---------------------------------------------------------------------------

def homo_linear(
    encrypted_inputs: Tuple[Ciphertext, ...],
    weights: Tuple[int, ...],
    encrypted_bias: Ciphertext,
) -> Ciphertext:
    """
    Compute sum_i(w_i * enc(x_i)) + enc(bias) homomorphically.

    weights and bias are public model parameters.
    """
    if len(encrypted_inputs) != len(weights):
        raise ValueError("inputs and weights must have the same length")

    result = encrypted_bias
    for enc_x, w in zip(encrypted_inputs, weights):
        term = homo_scalar_mul(enc_x, w)
        result = homo_add(result, term)
    return result


# ---------------------------------------------------------------------------
# Toy linear model
#
# Task: classify "income > 50k" from 4 features.
# Features (integer-valued, kept small to fit noise budget):
#   f0 = age              (range 17-90)
#   f1 = hours_per_week   (range 1-99)
#   f2 = education_years  (range 1-16)
#   f3 = capital_gain     (0 = none, 1 = small, 2 = large)
#
# Pre-trained weights (heuristic, NOT from real data):
#   score = 3*age + 5*hours + 8*education + 150*capital_gain + bias
#   Threshold: score > 0 -> class 1 (income > 50k)
#
# With T=65536 the full score range fits comfortably in (-T/2, T/2].
# ---------------------------------------------------------------------------

MODEL_WEIGHTS: Tuple[int, ...] = (3, 5, 8, 150)
MODEL_BIAS: int = -400     # negative constant shift; acts as intercept
THRESHOLD: int = 0         # class-1 iff decrypted score > 0


def plaintext_predict(features: Tuple[int, ...]) -> Tuple[int, int]:
    """Reference unencrypted score and prediction."""
    score = MODEL_BIAS
    for f, w in zip(features, MODEL_WEIGHTS):
        score += w * f
    return score, (1 if score > THRESHOLD else 0)


# ---------------------------------------------------------------------------
# Main demonstration
# ---------------------------------------------------------------------------

def main() -> None:
    # Deterministic run for reproducibility
    rng = random.Random(42)

    # Example individuals:
    #   Person A: young, part-time, low education, no capital gain -> class 0
    #   Person B: older, full-time, high education, capital gain   -> class 1
    person_a: Tuple[int, ...] = (25, 20, 9, 0)   # (age, hrs/wk, edu-years, cap-gain)
    person_b: Tuple[int, ...] = (45, 50, 14, 1)

    # ------------------------------------------------------------------
    print("=== Step 1: Setup — generate keys ===")
    sk, pk = keygen(rng)
    print(f"  Secret key s (first 4 entries): {sk.s[:4]}")
    print(f"  Public key b (high word):        {pk.b >> 16 & 0xFFFFFFFF}")
    print(f"  Plaintext modulus  t = {T}")
    print(f"  Ciphertext modulus q = 2^{(Q - 1).bit_length()}")
    print(f"  Delta (Q/T)          = {_delta()}")

    # ------------------------------------------------------------------
    print("\n=== Step 2: Encrypt input features ===")
    enc_a = tuple(encrypt(pk, f, rng) for f in person_a)
    enc_b = tuple(encrypt(pk, f, rng) for f in person_b)

    print("  Person A features (plaintext):", person_a)
    for i, ct in enumerate(enc_a):
        print(f"    enc_a[{i}]  c0={ct[0]:012x}  c1[0]={ct[1][0]:012x}")

    print("  Person B features (plaintext):", person_b)
    for i, ct in enumerate(enc_b):
        print(f"    enc_b[{i}]  c0={ct[0]:012x}  c1[0]={ct[1][0]:012x}")

    # ------------------------------------------------------------------
    print("\n=== Step 3: Run encrypted inference — server side ===")
    # Server knows weights + bias but NOT the secret key.
    # It encrypts the bias under the public key, then evaluates
    # the linear score homomorphically.
    enc_bias_a = encrypt(pk, MODEL_BIAS % T, rng)
    enc_bias_b = encrypt(pk, MODEL_BIAS % T, rng)

    enc_score_a = homo_linear(enc_a, MODEL_WEIGHTS, enc_bias_a)
    enc_score_b = homo_linear(enc_b, MODEL_WEIGHTS, enc_bias_b)

    print("  Server evaluated enc_score_a (no plaintext ever visible to server)")
    print("  Server evaluated enc_score_b (no plaintext ever visible to server)")

    # ------------------------------------------------------------------
    print("\n=== Step 4: Decrypt scores — client side ===")
    score_a = decrypt(sk, enc_score_a)
    score_b = decrypt(sk, enc_score_b)

    pred_a_fhe = 1 if score_a > THRESHOLD else 0
    pred_b_fhe = 1 if score_b > THRESHOLD else 0

    print(f"  Person A FHE score: {score_a:6d}  ->  class {pred_a_fhe}")
    print(f"  Person B FHE score: {score_b:6d}  ->  class {pred_b_fhe}")

    # ------------------------------------------------------------------
    print("\n=== Step 5: Compare with plaintext inference ===")
    plain_score_a, pred_a_plain = plaintext_predict(person_a)
    plain_score_b, pred_b_plain = plaintext_predict(person_b)

    match_a_score = (plain_score_a == score_a)
    match_b_score = (plain_score_b == score_b)
    match_a_pred  = (pred_a_plain  == pred_a_fhe)
    match_b_pred  = (pred_b_plain  == pred_b_fhe)

    print(f"  Person A — plain score: {plain_score_a:6d}  FHE score: {score_a:6d}  scores match: {match_a_score}")
    print(f"  Person B — plain score: {plain_score_b:6d}  FHE score: {score_b:6d}  scores match: {match_b_score}")
    print(f"  Person A — plain pred: {pred_a_plain}  FHE pred: {pred_a_fhe}  match: {match_a_pred}")
    print(f"  Person B — plain pred: {pred_b_plain}  FHE pred: {pred_b_fhe}  match: {match_b_pred}")

    assert match_a_pred and match_b_pred, "FHE predictions must match plaintext predictions"
    print("\n  All FHE predictions match plaintext predictions.")


if __name__ == "__main__":
    main()
