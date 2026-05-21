"""
Grover's algorithm impact on symmetric crypto (educational).

Run:
  python3 code/main.py

This script:
- Models brute-force work factors in log2 units ("security bits").
- Shows how Grover changes key search and hash preimage/collision costs.
- Produces practical sizing guidance for AES keys and hash output sizes.
"""

from __future__ import annotations

from fractions import Fraction


def _require_int(name: str, x: int, *, min_value: int | None = None) -> int:
    if not isinstance(x, int):
        raise TypeError(f"{name} must be an int")
    if min_value is not None and x < min_value:
        raise ValueError(f"{name} must be >= {min_value}")
    return x


def is_power_of_two(n: int) -> bool:
    if not isinstance(n, int):
        raise TypeError("n must be an int")
    return n > 0 and (n & (n - 1)) == 0


def log2_pow2(n: int) -> int:
    n = _require_int("n", n, min_value=1)
    if not is_power_of_two(n):
        raise ValueError("n must be a power of two")
    return n.bit_length() - 1


def _format_bits(x: int | Fraction) -> str:
    if isinstance(x, int):
        return str(x)
    if not isinstance(x, Fraction):
        raise TypeError("x must be int or Fraction")
    if x.denominator == 1:
        return str(x.numerator)
    if x.denominator == 2:
        return f"{x.numerator / 2:.1f}"
    return f"{float(x):.6g}"


def classical_key_search_log2_work(*, key_bits: int, parallelism: int = 1) -> int:
    """
    Classical brute-force key search work factor, expressed as log2(trials).

    Model: ~2^key_bits total trials; parallelism reduces work linearly.
    """

    key_bits = _require_int("key_bits", key_bits, min_value=1)
    parallelism = _require_int("parallelism", parallelism, min_value=1)
    return key_bits - log2_pow2(parallelism)


def grover_key_search_log2_work(*, key_bits: int, parallelism: int = 1) -> Fraction:
    """
    Grover key search work factor, expressed as log2(oracle queries).

    Model: ~2^(key_bits/2) queries; parallelism reduces work linearly.
    """

    key_bits = _require_int("key_bits", key_bits, min_value=1)
    parallelism = _require_int("parallelism", parallelism, min_value=1)
    return Fraction(key_bits, 2) - log2_pow2(parallelism)


def min_key_bits_for_target_under_grover(*, target_security_bits: int, safety_margin_bits: int = 0) -> int:
    """
    Minimum key size (in bits) so that Grover cost is at least target bits.

    With the simple model: grover_security ~= key_bits/2 - margin.
    """

    target_security_bits = _require_int("target_security_bits", target_security_bits, min_value=1)
    safety_margin_bits = _require_int("safety_margin_bits", safety_margin_bits, min_value=0)
    return 2 * (target_security_bits + safety_margin_bits)


def recommend_aes_key_bits(*, target_security_bits: int, safety_margin_bits: int = 0) -> int:
    """
    Recommend AES key size from {128, 192, 256} for a post-quantum target.

    Returns the smallest standard AES key size meeting the target under Grover.
    """

    need = min_key_bits_for_target_under_grover(
        target_security_bits=target_security_bits,
        safety_margin_bits=safety_margin_bits,
    )
    for candidate in (128, 192, 256):
        if candidate >= need:
            return candidate
    raise ValueError("target_security_bits too high for standard AES key sizes")


def hash_preimage_log2_work_classical(*, output_bits: int, parallelism: int = 1) -> int:
    output_bits = _require_int("output_bits", output_bits, min_value=1)
    parallelism = _require_int("parallelism", parallelism, min_value=1)
    return output_bits - log2_pow2(parallelism)


def hash_preimage_log2_work_grover(*, output_bits: int, parallelism: int = 1) -> Fraction:
    output_bits = _require_int("output_bits", output_bits, min_value=1)
    parallelism = _require_int("parallelism", parallelism, min_value=1)
    return Fraction(output_bits, 2) - log2_pow2(parallelism)


def hash_collision_log2_work_classical(*, output_bits: int) -> Fraction:
    """
    Collision search cost for an ideal n-bit hash: ~2^(n/2) (birthday bound).
    """

    output_bits = _require_int("output_bits", output_bits, min_value=2)
    return Fraction(output_bits, 2)


def hash_collision_log2_work_quantum_bht(*, output_bits: int) -> Fraction:
    """
    Quantum collision search cost (BHT): ~2^(n/3) for an ideal n-bit hash.
    """

    output_bits = _require_int("output_bits", output_bits, min_value=3)
    return Fraction(output_bits, 3)


def _print_step(n: int, name: str) -> None:
    print(f"=== Step {n}: {name} ===")


def step1_classical_key_search() -> None:
    _print_step(1, "Classical brute-force work (in log2 bits)")
    for k in (64, 80, 128):
        work = classical_key_search_log2_work(key_bits=k, parallelism=1)
        print(f"classical key search for k={k}: log2(work) = {work}")

    p = 2**10
    k = 80
    work_p = classical_key_search_log2_work(key_bits=k, parallelism=p)
    print(f"with parallelism={p} (2^10 workers), k=80 -> log2(work) = {work_p}")


def step2_grover_key_search() -> None:
    _print_step(2, "Grover key search halves the exponent (in log2 bits)")
    for k in (128, 192, 256):
        work = grover_key_search_log2_work(key_bits=k, parallelism=1)
        print(f"grover key search for k={k}: log2(work) = {_format_bits(work)}")

    p = 2**20
    k = 256
    work_p = grover_key_search_log2_work(key_bits=k, parallelism=p)
    print(f"with parallelism={p} (2^20 quantum workers), k=256 -> log2(work) = {_format_bits(work_p)}")


def step3_aes_key_sizing() -> None:
    _print_step(3, "Sizing AES keys for a post-quantum target (rule of thumb)")
    for target in (64, 96, 128):
        rec = recommend_aes_key_bits(target_security_bits=target, safety_margin_bits=0)
        grover_bits = grover_key_search_log2_work(key_bits=rec)
        print(f"target={target} bits PQ -> recommend AES-{rec} (Grover: {_format_bits(grover_bits)} bits)")

    try:
        rec2 = recommend_aes_key_bits(target_security_bits=128, safety_margin_bits=16)
    except ValueError as e:
        print(f"target=128 bits PQ + 16-bit margin -> no standard AES key fits ({e})")
    else:
        grover_bits2 = grover_key_search_log2_work(key_bits=rec2)
        print(
            f"target=128 bits PQ + 16-bit margin -> recommend AES-{rec2} (Grover: {_format_bits(grover_bits2)} bits)"
        )


def step4_hash_sizing() -> None:
    _print_step(4, "Hash preimage vs collision costs under quantum")
    algs = [("SHA-256", 256), ("SHA-384", 384), ("SHA-512", 512)]
    for name, n in algs:
        pre_c = hash_preimage_log2_work_classical(output_bits=n)
        pre_q = hash_preimage_log2_work_grover(output_bits=n)
        col_c = hash_collision_log2_work_classical(output_bits=n)
        col_q = hash_collision_log2_work_quantum_bht(output_bits=n)
        print(
            f"{name}: preimage classical={pre_c}, grover={_format_bits(pre_q)}; "
            f"collision classical={_format_bits(col_c)}, quantum(BHT)={_format_bits(col_q)}"
        )


def main() -> None:
    step1_classical_key_search()
    print()
    step2_grover_key_search()
    print()
    step3_aes_key_sizing()
    print()
    step4_hash_sizing()


if __name__ == "__main__":
    main()
