from __future__ import annotations

import math
import os
import random


class RandomOracle:
    """Simulated random oracle: a consistent lazy random table with programmability.

    Models H: {0,1}* -> {0,1}^output_bits as a truly random function.
    The same input always returns the same output (consistency).
    The simulator can pre-program outputs for chosen inputs (programmability).
    """

    def __init__(self, output_bits: int = 256, *, rng: random.Random | None = None):
        if output_bits <= 0:
            raise ValueError("output_bits must be positive")
        self._output_bits = output_bits
        self._table: dict[bytes, int] = {}
        self._rng = rng if rng is not None else random.Random(os.urandom(32))
        self._query_log: list[bytes] = []

    @property
    def output_bits(self) -> int:
        return self._output_bits

    @property
    def query_count(self) -> int:
        return len(self._query_log)

    @property
    def distinct_queries(self) -> int:
        return len(self._table)

    def query(self, x: bytes) -> int:
        """Return H(x). Consistent: repeated queries return the same value."""
        if not isinstance(x, bytes):
            raise TypeError("query input must be bytes")
        if x not in self._table:
            self._table[x] = self._rng.getrandbits(self._output_bits)
        self._query_log.append(x)
        return self._table[x]

    def program(self, x: bytes, y: int) -> None:
        """Program H(x) = y before any query on x (simulator use only).

        Raises ValueError if x was already queried — programming after the fact
        would be detectable by a consistent adversary.
        """
        if not isinstance(x, bytes):
            raise TypeError("program input must be bytes")
        if x in self._table:
            raise ValueError(f"Cannot program already-queried input")
        if not (0 <= y < 2 ** self._output_bits):
            raise ValueError("y out of range for output_bits")
        self._table[x] = y

    def reset_log(self) -> None:
        """Clear the query log (not the programmed table)."""
        self._query_log.clear()


def preimage_advantage_bound(q: int, output_bits: int) -> float:
    """Upper bound on preimage-finding advantage with q queries.

    Pr[find x s.t. H(x) = y within q queries] <= q / 2^output_bits.
    Union bound: each of q queries independently hits target with prob 1/2^n.
    """
    if q < 0:
        raise ValueError("q must be non-negative")
    if output_bits <= 0:
        raise ValueError("output_bits must be positive")
    return q / (2.0 ** output_bits)


def collision_advantage_bound(q: int, output_bits: int) -> float:
    """Upper bound on collision-finding advantage with q queries (birthday bound).

    Pr[∃ i≠j: H(x_i) = H(x_j) after q queries] <= q*(q-1) / (2 * 2^output_bits).
    """
    if q < 0:
        raise ValueError("q must be non-negative")
    if output_bits <= 0:
        raise ValueError("output_bits must be positive")
    return (q * (q - 1)) / (2.0 * (2.0 ** output_bits))


def birthday_queries(output_bits: int, *, target_prob: float = 0.5) -> float:
    """Queries needed for collision probability >= target_prob (birthday bound).

    q ≈ sqrt(2 * ln(1 / (1 - target_prob)) * 2^output_bits).
    At target_prob=0.5: q ≈ 1.177 * 2^(output_bits/2).
    """
    if not (0 < target_prob < 1):
        raise ValueError("target_prob must be in (0, 1)")
    if output_bits <= 0:
        raise ValueError("output_bits must be positive")
    return math.sqrt(2.0 * math.log(1.0 / (1.0 - target_prob)) * (2.0 ** output_bits))


def rom_security_bits(q: int, output_bits: int) -> float:
    """Security bits against preimage with q RO queries: n - log2(q).

    The preimage bound q/2^n gives -log2(q/2^n) = n - log2(q) security bits.
    """
    if q <= 0:
        raise ValueError("q must be positive")
    if output_bits <= 0:
        raise ValueError("output_bits must be positive")
    return output_bits - math.log2(q)


def simulate_preimage_attack(
    oracle: RandomOracle,
    target: int,
    n_queries: int,
    *,
    rng: random.Random | None = None,
) -> int | None:
    """Try to find x s.t. H(x) = target within n_queries random queries.

    Returns the winning x as bytes if found, else None.
    """
    if rng is None:
        rng = random.Random()
    for _ in range(n_queries):
        x = rng.getrandbits(64).to_bytes(8, "big")
        if oracle.query(x) == target:
            return x
    return None


def simulate_birthday_attack(
    oracle: RandomOracle,
    n_queries: int,
    *,
    rng: random.Random | None = None,
) -> tuple[bytes, bytes] | None:
    """Try to find a collision H(x) = H(y) within n_queries.

    Returns (x, y) pair on success, else None.
    """
    if rng is None:
        rng = random.Random()
    seen: dict[int, bytes] = {}
    for _ in range(n_queries):
        x = rng.getrandbits(64).to_bytes(8, "big")
        h = oracle.query(x)
        if h in seen and seen[h] != x:
            return (seen[h], x)
        seen[h] = x
    return None


def main():
    print("=" * 60)
    print("RANDOM ORACLE MODEL")
    print("=" * 60)

    print("\n--- RandomOracle: consistency and programmability ---")
    ro = RandomOracle(output_bits=32, rng=random.Random(42))
    x1 = b"hello"
    h1 = ro.query(x1)
    h1_again = ro.query(x1)
    print(f"H({x1!r}) = {h1:#010x}")
    print(f"H({x1!r}) again = {h1_again:#010x}  (consistent: {h1 == h1_again})")
    y_programmed = 0xDEADBEEF
    ro.program(b"challenge", y_programmed)
    h_prog = ro.query(b"challenge")
    print(f"Programmed H(b'challenge') = {y_programmed:#010x}, got {h_prog:#010x}  (match: {h_prog == y_programmed})")
    print(f"Total queries: {ro.query_count}, distinct inputs: {ro.distinct_queries}")

    print("\n--- Preimage advantage bound: q / 2^n ---")
    n = 32
    print(f"Output bits n={n}")
    for q in (1, 100, 1_000, 2**16):
        adv = preimage_advantage_bound(q, n)
        bits = rom_security_bits(q, n)
        print(f"  q={q:>8}  Adv <= {adv:.4e}  security = {bits:.1f} bits")

    print("\n--- Collision advantage bound: q(q-1)/(2·2^n) ---")
    print(f"Output bits n={n}")
    for q in (1, 100, 1_000, 2**16):
        adv = collision_advantage_bound(q, n)
        print(f"  q={q:>8}  Adv <= {adv:.4e}")

    print("\n--- Birthday threshold: queries for 50% collision probability ---")
    for bits in (16, 32, 64, 128, 256):
        q = birthday_queries(bits, target_prob=0.5)
        print(f"  n={bits:>3} bits  q_50% ≈ {q:.3e}  ≈ 2^{math.log2(q):.1f}")

    print("\n--- Simulated preimage attack (toy 20-bit oracle) ---")
    n_bits = 20
    ro_attack = RandomOracle(output_bits=n_bits, rng=random.Random(7))
    target = ro_attack.query(b"secret")
    ro_attack.reset_log()
    result = simulate_preimage_attack(ro_attack, target, n_queries=500, rng=random.Random(99))
    theory_adv = preimage_advantage_bound(500, n_bits)
    print(f"Target: {target:#07x}, queries: 500, theory Adv={theory_adv:.4f}")
    print(f"Found preimage: {result is not None} (expected with prob ~{theory_adv:.3f})")

    print("\n--- Simulated birthday attack (toy 16-bit oracle) ---")
    n_bits_b = 16
    q_birthday = int(birthday_queries(n_bits_b, target_prob=0.5))
    ro_bday = RandomOracle(output_bits=n_bits_b, rng=random.Random(13))
    collision = simulate_birthday_attack(ro_bday, q_birthday, rng=random.Random(17))
    theory_b = collision_advantage_bound(q_birthday, n_bits_b)
    print(f"n={n_bits_b} bits, q={q_birthday} (birthday threshold)")
    print(f"Theory collision Adv ≈ {theory_b:.3f}")
    if collision:
        x, y = collision
        print(f"Found collision: H({x.hex()}) = H({y.hex()}) = {ro_bday.query(x):#06x}")
    else:
        print("No collision found this run")

    print("\n--- ROM query bound in proofs ---")
    print("In a ROM proof, if adversary makes q queries:")
    print(f"  q=2^30, n=256: preimage Adv <= {preimage_advantage_bound(2**30, 256):.2e}")
    print(f"  security bits: {rom_security_bits(2**30, 256):.0f}")
    print("The q/2^n bound is the universal ROM tightness result.")


if __name__ == "__main__":
    main()
