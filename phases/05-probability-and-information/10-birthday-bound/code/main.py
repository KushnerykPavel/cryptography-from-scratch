from __future__ import annotations

import math
import random
from collections.abc import Callable


# ---------------------------------------------------------------------------
# Exact and approximate birthday probability
# ---------------------------------------------------------------------------

def birthday_collision_prob_exact(q: int, space_size: int) -> float:
    """Exact probability of at least one collision among q draws from N items.

    P(collision) = 1 - N*(N-1)*...*(N-q+1) / N^q
    Only tractable for small N.  For large N use the approximation.
    """
    if q < 0 or space_size <= 0:
        raise ValueError("q must be >= 0 and space_size must be > 0")
    if q == 0 or q == 1:
        return 0.0
    if q > space_size:
        return 1.0
    log_prob_no_collision = sum(math.log1p(-k / space_size) for k in range(1, q))
    return 1.0 - math.exp(log_prob_no_collision)


def birthday_collision_prob_approx(q: int, n_bits: int) -> float:
    """Upper bound approximation: P(collision) ≤ q*(q-1) / (2 * 2^n).

    Same as the PRP-PRF switching lemma.  Tight for q << 2^n.
    """
    if q < 0:
        raise ValueError("q must be non-negative")
    if n_bits <= 0:
        raise ValueError("n_bits must be positive")
    if q <= 1:
        return 0.0
    return (q * (q - 1)) / (2.0 * (2.0 ** n_bits))


def birthday_collision_prob_exp(q: int, n_bits: int) -> float:
    """Exponential approximation: P ≈ 1 - exp(-q*(q-1)/(2*2^n)).

    Tighter than the linear upper bound; exact for the Poisson model.
    """
    if q < 0:
        raise ValueError("q must be non-negative")
    if n_bits <= 0:
        raise ValueError("n_bits must be positive")
    if q <= 1:
        return 0.0
    exponent = -(q * (q - 1)) / (2.0 * (2.0 ** n_bits))
    return 1.0 - math.exp(exponent)


# ---------------------------------------------------------------------------
# Query thresholds
# ---------------------------------------------------------------------------

def collision_threshold(n_bits: int, *, target_prob: float = 0.5) -> float:
    """Queries needed for collision probability >= target_prob.

    From Poisson model: q ≈ sqrt(-2 * 2^n * ln(1 - p)).
    At p=0.5: q ≈ 1.177 * 2^(n/2).
    """
    if not (0 < target_prob < 1):
        raise ValueError("target_prob must be in (0, 1)")
    if n_bits <= 0:
        raise ValueError("n_bits must be positive")
    return math.sqrt(-2.0 * (2.0 ** n_bits) * math.log1p(-target_prob))


def preimage_expected_queries(n_bits: int) -> float:
    """Expected queries to find x such that H(x) = y: 2^n.

    Each query hits the target with probability 2^{-n}; geometric mean = 2^n.
    """
    if n_bits <= 0:
        raise ValueError("n_bits must be positive")
    return 2.0 ** n_bits


def collision_expected_queries(n_bits: int) -> float:
    """Expected queries to find any collision: ≈ sqrt(π/2 * 2^n) ≈ 1.253 * 2^(n/2)."""
    if n_bits <= 0:
        raise ValueError("n_bits must be positive")
    return math.sqrt(math.pi / 2.0 * (2.0 ** n_bits))


def security_bits_after_birthday(n_bits: int) -> float:
    """Effective security bits for collision resistance: n/2.

    Birthday attack halves the exponent: 2^n space → 2^(n/2) collision cost.
    """
    return n_bits / 2.0


# ---------------------------------------------------------------------------
# Multi-target and meet-in-the-middle
# ---------------------------------------------------------------------------

def multi_target_advantage(q: int, k_targets: int, n_bits: int) -> float:
    """Advantage of finding a preimage for any of k targets within q queries.

    Each query hits any of k targets with probability k/2^n.
    Union bound: Adv ≤ q * k / 2^n.
    """
    if q < 0 or k_targets < 0:
        raise ValueError("q and k_targets must be non-negative")
    if n_bits <= 0:
        raise ValueError("n_bits must be positive")
    return (q * k_targets) / (2.0 ** n_bits)


def meet_in_the_middle_cost(key_bits_per_half: int) -> dict:
    """Time and space cost of meet-in-the-middle on a 2k-bit composed key.

    Double encryption E_k2(E_k1(m)): k1, k2 each key_bits_per_half bits.
    MITM: build table of E_k1(m) for all k1 (2^k entries), then
          search for match among D_k2(c) for all k2.
    Time: 2 * 2^k (k = key_bits_per_half).  Space: 2^k.
    Security: k bits, not 2k bits.
    """
    if key_bits_per_half <= 0:
        raise ValueError("key_bits_per_half must be positive")
    return {
        "nominal_key_bits": 2 * key_bits_per_half,
        "effective_security_bits": key_bits_per_half,
        "time_complexity": 2.0 ** key_bits_per_half,
        "space_complexity": 2.0 ** key_bits_per_half,
    }


def double_enc_security(key_bits: int) -> int:
    """Effective security of double encryption (per key): key_bits, not 2*key_bits.

    Meet-in-the-middle reduces 2k-bit double encryption to k-bit security.
    """
    return key_bits


# ---------------------------------------------------------------------------
# Simulated birthday attack
# ---------------------------------------------------------------------------

def simulate_birthday_attack(
    hash_fn: Callable[[int], int],
    n_bits: int,
    max_queries: int,
    *,
    rng: random.Random | None = None,
) -> tuple[int, int] | None:
    """Find a collision H(x) = H(y) for x ≠ y within max_queries queries.

    hash_fn: maps an integer input to an n_bits-bit integer output.
    Returns (x, y) on success, None if no collision found.
    """
    if rng is None:
        rng = random.Random()
    seen: dict[int, int] = {}
    for _ in range(max_queries):
        x = rng.getrandbits(64)
        h = hash_fn(x) & ((1 << n_bits) - 1)
        if h in seen and seen[h] != x:
            return (seen[h], x)
        seen[h] = x
    return None


def simulate_preimage_attack(
    hash_fn: Callable[[int], int],
    target: int,
    n_bits: int,
    max_queries: int,
    *,
    rng: random.Random | None = None,
) -> int | None:
    """Find x with H(x) = target within max_queries queries.

    Returns x on success, None otherwise.
    """
    if rng is None:
        rng = random.Random()
    mask = (1 << n_bits) - 1
    target_masked = target & mask
    for _ in range(max_queries):
        x = rng.getrandbits(64)
        if hash_fn(x) & mask == target_masked:
            return x
    return None


def main():
    print("=" * 60)
    print("BIRTHDAY BOUND & GENERIC ATTACKS")
    print("=" * 60)

    print("\n--- Exact vs approximation for small spaces ---")
    print(f"  {'q':>6}  {'exact(N=365)':>14}  {'approx(N=365)':>14}  {'exp(N=365)':>12}")
    N = 365
    n_bits_approx = math.log2(N)
    for q in (10, 23, 30, 50, 100):
        exact = birthday_collision_prob_exact(q, N)
        approx = birthday_collision_prob_approx(q, n_bits_approx)
        exp_approx = birthday_collision_prob_exp(q, n_bits_approx)
        print(f"  {q:>6}  {exact:>14.4f}  {approx:>14.4f}  {exp_approx:>12.4f}")

    print("\n--- Collision threshold: queries for 50% probability ---")
    print(f"  {'n_bits':>8}  {'q_50%':>18}  {'≈ 2^':>8}  {'security_bits':>14}")
    for n in (16, 32, 64, 128, 256):
        q = collision_threshold(n, target_prob=0.5)
        sec = security_bits_after_birthday(n)
        print(f"  {n:>8}  {q:>18.1f}  {math.log2(q):>8.1f}  {sec:>14.0f}")

    print("\n--- Preimage vs collision expected cost ---")
    print(f"  {'n_bits':>8}  {'preimage (queries)':>22}  {'collision (queries)':>22}  {'ratio':>8}")
    for n in (16, 32, 64, 128):
        pre = preimage_expected_queries(n)
        col = collision_expected_queries(n)
        print(f"  {n:>8}  {pre:>22.0f}  {col:>22.1f}  {pre/col:>8.1f}")

    print("\n--- Multi-target advantage ---")
    print(f"  SHA-256 (n=256) with q=2^{{60}} queries and k=2^{{20}} targets:")
    adv = multi_target_advantage(2**60, 2**20, 256)
    print(f"  Adv = {adv:.3e}  (still negligible — 2^60 * 2^20 / 2^256 = 2^-176)")

    print("\n--- Meet-in-the-middle: double encryption ---")
    for k in (56, 64, 128):
        result = meet_in_the_middle_cost(k)
        print(f"  Double-DES/AES (k={k}): "
              f"nominal={result['nominal_key_bits']} bits, "
              f"effective={result['effective_security_bits']} bits, "
              f"time=2^{k}")

    print("\n--- Simulated birthday attack (16-bit hash space) ---")
    n_bits = 16
    import hashlib

    def tiny_hash(x: int) -> int:
        return int.from_bytes(hashlib.sha256(x.to_bytes(8, "big")).digest()[:2], "big")

    q_threshold = int(collision_threshold(n_bits, target_prob=0.5))
    result = simulate_birthday_attack(tiny_hash, n_bits, q_threshold, rng=random.Random(42))
    prob_theory = birthday_collision_prob_exp(q_threshold, n_bits)
    print(f"  n={n_bits} bits, q={q_threshold} (50% threshold)")
    print(f"  Theory collision prob: {prob_theory:.3f}")
    if result:
        x, y = result
        print(f"  Found: H({x}) = H({y}) = {tiny_hash(x) & 0xFFFF:#06x}")
    else:
        print("  No collision this run")

    print("\n--- Simulated preimage attack (16-bit hash space) ---")
    target_val = tiny_hash(0xDEADBEEF)
    found = simulate_preimage_attack(tiny_hash, target_val, n_bits, max_queries=5000, rng=random.Random(7))
    theory_adv = 5000 / (2 ** n_bits)
    print(f"  Target={target_val:#06x}, queries=5000, theory_adv={theory_adv:.3f}")
    if found:
        print(f"  Found preimage: x={found}, H(x)={tiny_hash(found) & 0xFFFF:#06x}")
    else:
        print("  Not found this run (expected with prob ≈ {:.3f})".format(1 - theory_adv))

    print("\n--- Real-world consequences ---")
    table = [
        ("MD5",      128, "Collision in 2^17 (broken 2004)"),
        ("SHA-1",    160, "Collision in 2^61 (SHAttered 2017)"),
        ("SHA-256",  256, "Collision in 2^128 (secure)"),
        ("3DES",      64, "Sweet32: collision after 2^32 blocks"),
        ("AES-128",  128, "PRP collision after 2^64 blocks"),
        ("AES-256",  128, "PRP collision after 2^64 blocks (same block size!)"),
    ]
    print(f"  {'Primitive':<12}  {'n_bits':>7}  {'birthday_sec':>14}  {'note'}")
    for name, n, note in table:
        sec = security_bits_after_birthday(n)
        print(f"  {name:<12}  {n:>7}  {sec:>14.0f}  {note}")


if __name__ == "__main__":
    main()
