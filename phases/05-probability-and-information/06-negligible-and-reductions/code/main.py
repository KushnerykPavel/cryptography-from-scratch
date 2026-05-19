from __future__ import annotations

import math
from collections.abc import Callable, Sequence

NeglFn = Callable[[int], float]


def is_negligible_function(
    fn: NeglFn,
    *,
    test_start: int = 10,
    test_end: int = 200,
    poly_degrees: Sequence[int] = (1, 2, 3),
) -> bool:
    """Finite approximation of asymptotic negligibility.

    Returns True if fn(n) < 1/n^d for every d in poly_degrees and every n in
    [test_start, test_end].  A truly negligible function must eventually go
    below 1/p(n) for every polynomial p — this checks the three lowest-degree
    witnesses over a finite range.
    """
    for d in poly_degrees:
        for n in range(test_start, test_end + 1):
            try:
                v = fn(n)
            except (OverflowError, ZeroDivisionError):
                v = 0.0
            if v >= 1.0 / (n ** d):
                return False
    return True


def is_non_negligible_function(
    fn: NeglFn,
    *,
    test_range: Sequence[int],
    poly_degree: int = 1,
) -> bool:
    """True if fn(n) >= 1/n^poly_degree for at least one n in test_range.

    A function is non-negligible if there exists a polynomial p such that
    fn(n) >= 1/p(n) for infinitely many n.  This checks the polynomial 1/n^d
    as a witness over the supplied range.
    """
    return any(fn(n) >= 1.0 / (n ** poly_degree) for n in test_range)


def reduction_advantage(adv_adversary: float, poly_loss: float) -> float:
    """Compute primitive advantage from a reduction with polynomial loss.

    Adv_B(primitive) >= Adv_A(scheme) / poly_loss.
    If Adv_A is non-negligible and poly_loss is polynomial, Adv_B is still
    non-negligible — contradiction with the assumed hardness of the primitive.
    """
    if adv_adversary < 0:
        raise ValueError("advantage must be non-negative")
    if poly_loss <= 0:
        raise ValueError("poly_loss must be positive")
    return adv_adversary / poly_loss


def compose_reductions(losses: Sequence[float]) -> float:
    """Total loss of a chain of reductions: product of all per-hop losses.

    If reduction R1 loses factor q1 and R2 loses q2, the composed reduction
    loses q1 * q2.  Adv_final >= Adv_start / (q1 * q2 * ...).
    """
    if not losses:
        return 1.0
    result = 1.0
    for loss in losses:
        if loss <= 0:
            raise ValueError("each loss must be positive")
        result *= loss
    return result


def security_bits(adv: float) -> float:
    """-log2(advantage). Adv = 2^{-k} means k security bits."""
    if adv <= 0:
        raise ValueError("advantage must be positive")
    if adv > 1:
        raise ValueError("advantage must be <= 1")
    return -math.log2(adv)


def advantage_from_security_bits(bits: float) -> float:
    """2^{-bits}.  Inverse of security_bits."""
    if bits < 0:
        raise ValueError("bits must be non-negative")
    return 2.0 ** (-bits)


def required_primitive_security(
    target_scheme_bits: float,
    total_loss: float,
) -> float:
    """Security bits the primitive needs so the scheme achieves target_scheme_bits.

    Adv_scheme <= Adv_primitive * total_loss.
    For Adv_scheme <= 2^{-target}: Adv_primitive <= 2^{-target} / total_loss
    => primitive bits needed = target + log2(total_loss).
    """
    if total_loss <= 0:
        raise ValueError("total_loss must be positive")
    return target_scheme_bits + math.log2(total_loss)


def concrete_security(
    primitive_security_bits: float,
    total_loss: float,
) -> float:
    """Scheme security bits given primitive security and total reduction loss.

    Adv_scheme <= Adv_primitive * total_loss
    => scheme_bits = primitive_bits - log2(total_loss).
    """
    if total_loss <= 0:
        raise ValueError("total_loss must be positive")
    return primitive_security_bits - math.log2(total_loss)


def is_secure(adv: float, *, min_security_bits: float = 128.0) -> bool:
    """True if adv < 2^{-min_security_bits}."""
    return adv < advantage_from_security_bits(min_security_bits)


def main():
    print("=" * 60)
    print("NEGLIGIBLE FUNCTIONS & REDUCTIONS")
    print("=" * 60)

    print("\n--- Non-negligible: exhibit a polynomial witness ---")
    non_negl_cases = [
        ("1/n",     lambda n: 1.0 / n,        1,   "p(n)=n"),
        ("1/n^2",   lambda n: 1.0 / n ** 2,   2,   "p(n)=n^2"),
        ("1/n^100", lambda n: 1.0 / n ** 100, 100, "p(n)=n^100"),
        ("0.001",   lambda n: 0.001,           1,   "0.001 >= 1/n at n=1000"),
    ]
    ranges = {
        "1/n":     range(10, 201),
        "1/n^2":   range(10, 201),
        "1/n^100": range(10, 201),
        "0.001":   range(500, 2001),   # need n >= 1001 for 0.001 >= 1/n
    }
    print(f"  {'function':<12}  {'witness':>22}  {'detected?':>10}")
    for name, fn, d, reason in non_negl_cases:
        detected = is_non_negligible_function(fn, test_range=ranges[name], poly_degree=d)
        print(f"  {name:<12}  {reason:>15}  {str(detected):>10}")
    print()
    print("Key: 1/n^100 is NOT negligible — p(n)=n^100 is a valid witness.")
    print("     Negligible = below EVERY inverse polynomial, even high-degree ones.")

    print("\n--- Negligible: passes all low-degree polynomial witnesses ---")
    negl_cases = [
        ("2^{-n}", lambda n: 2.0 ** (-n)),
        ("e^{-n}", lambda n: math.exp(-n)),
        ("1/n!",   lambda n: 1.0 / math.factorial(n)),
    ]
    for name, fn in negl_cases:
        negl = is_negligible_function(fn, test_start=10, test_end=200, poly_degrees=(1, 2, 3))
        print(f"  {name:<10}  below 1/n, 1/n^2, 1/n^3 for n=10..200? {negl}")

    print("\n--- Security bits conversion ---")
    for bits in (80, 112, 128, 192, 256):
        adv = advantage_from_security_bits(bits)
        back = security_bits(adv)
        print(f"  {bits:>3} bits  Adv = 2^{{-{bits}}} = {adv:.2e}  round-trip: {back:.1f} bits")

    print("\n--- Reduction tightness ---")
    adv_A = 2.0 ** -64
    print(f"Adversary breaks scheme with Adv_A = 2^{{-64}} = {adv_A:.2e}")
    for loss in (1, 2, 8, 64, 1024):
        adv_B = reduction_advantage(adv_A, loss)
        print(f"  loss={loss:>5}  Adv_B >= {adv_B:.2e}  ({security_bits(adv_B):.1f} bits)")

    print("\n--- Composed reductions ---")
    losses = [2.0, 4.0, 8.0]
    total = compose_reductions(losses)
    print(f"  Losses {losses} -> total loss = {total}")
    print(f"  log2(total) = {math.log2(total):.1f} bits eaten by the chain")

    print("\n--- Concrete security budget ---")
    print(f"{'prim bits':>10}  {'loss':>8}  {'scheme bits':>12}")
    for prim_bits, loss in [(128, 1), (128, 8), (128, 64), (256, 64), (256, 1024)]:
        scheme = concrete_security(prim_bits, loss)
        print(f"  {prim_bits:>8}  {loss:>8}  {scheme:>12.1f}")

    print("\n--- Required primitive for 128-bit scheme security ---")
    for loss in (1, 4, 64, 256, 1024):
        needed = required_primitive_security(128.0, loss)
        print(f"  loss={loss:>5}  need primitive at {needed:.1f} bits")

    print("\n--- is_secure ---")
    for adv, label in [
        (2.0 ** -128, "2^{-128}"),
        (2.0 ** -64,  "2^{-64}"),
        (0.001,       "0.001"),
    ]:
        print(f"  Adv={label:>10}  secure(128)? {is_secure(adv, min_security_bits=128)}")


if __name__ == "__main__":
    main()
