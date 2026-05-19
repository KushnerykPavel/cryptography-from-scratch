from __future__ import annotations

import math
from collections.abc import Mapping
from typing import TypeVar

T = TypeVar("T")


def _check_pmf(pmf: Mapping[T, float], *, name: str, tol: float = 1e-9) -> None:
    if not pmf:
        raise ValueError(f"{name} must be non-empty")
    total = 0.0
    for k, p in pmf.items():
        if p < -tol:
            raise ValueError(f"{name}[{k!r}] must be non-negative, got {p!r}")
        total += p
    if abs(total - 1.0) > tol:
        raise ValueError(f"{name} must sum to 1, got {total!r}")


def shannon_entropy(pmf: Mapping[T, float]) -> float:
    """H(X) = -Σ p(x) log2 p(x). Units: bits."""
    _check_pmf(pmf, name="pmf")
    total = 0.0
    for p in pmf.values():
        if p > 0:
            total -= p * math.log2(p)
    return total


def min_entropy(pmf: Mapping[T, float]) -> float:
    """H_inf(X) = -log2 max_x p(x). The security-relevant entropy."""
    _check_pmf(pmf, name="pmf")
    p_max = max(pmf.values())
    if p_max <= 0:
        raise ValueError("pmf must have positive max probability")
    return -math.log2(p_max)


def collision_entropy(pmf: Mapping[T, float]) -> float:
    """H_2(X) = -log2 Σ p(x)^2. Renyi entropy of order 2."""
    _check_pmf(pmf, name="pmf")
    s = sum(p * p for p in pmf.values())
    if s <= 0:
        raise ValueError("pmf collision probability must be positive")
    return -math.log2(s)


def max_entropy(pmf: Mapping[T, float]) -> float:
    """H_0(X) = log2 |support(X)|. Hartley entropy."""
    _check_pmf(pmf, name="pmf")
    support = sum(1 for p in pmf.values() if p > 0)
    if support == 0:
        raise ValueError("pmf must have non-empty support")
    return math.log2(support)


def renyi_entropy(pmf: Mapping[T, float], alpha: float) -> float:
    """H_α(X) = (1/(1-α)) log2 Σ p(x)^α for α >= 0, α != 1.

    Special cases dispatched: α=0 (max-entropy), α=1 (Shannon),
    α=2 (collision), α=∞ (min-entropy).
    """
    _check_pmf(pmf, name="pmf")
    if alpha < 0:
        raise ValueError("alpha must be >= 0")
    if math.isinf(alpha):
        return min_entropy(pmf)
    if alpha == 0:
        return max_entropy(pmf)
    if alpha == 1:
        return shannon_entropy(pmf)
    s = sum((p ** alpha) for p in pmf.values() if p > 0)
    if s <= 0:
        raise ValueError("Renyi sum must be positive")
    return (1.0 / (1.0 - alpha)) * math.log2(s)


def kl_divergence(p: Mapping[T, float], q: Mapping[T, float]) -> float:
    """D(P || Q) = Σ p(x) log2 (p(x) / q(x)). Bits. Infinite if q(x)=0<p(x)."""
    _check_pmf(p, name="p")
    _check_pmf(q, name="q")
    total = 0.0
    for x, px in p.items():
        if px <= 0:
            continue
        qx = q.get(x, 0.0)
        if qx <= 0:
            return math.inf
        total += px * math.log2(px / qx)
    return total


def joint_pmf(pxy: Mapping[tuple[T, T], float]) -> dict[tuple[T, T], float]:
    _check_pmf(pxy, name="pxy")
    return dict(pxy)


def marginal(pxy: Mapping[tuple[T, T], float], *, axis: int) -> dict[T, float]:
    if axis not in (0, 1):
        raise ValueError("axis must be 0 (X) or 1 (Y)")
    out: dict[T, float] = {}
    for (x, y), p in pxy.items():
        key = x if axis == 0 else y
        out[key] = out.get(key, 0.0) + p
    return out


def conditional_entropy(pxy: Mapping[tuple[T, T], float]) -> float:
    """H(X | Y) = H(X, Y) - H(Y). Bits."""
    _check_pmf(pxy, name="pxy")
    h_xy = shannon_entropy(pxy)
    py = marginal(pxy, axis=1)
    return h_xy - shannon_entropy(py)


def mutual_information(pxy: Mapping[tuple[T, T], float]) -> float:
    """I(X; Y) = H(X) + H(Y) - H(X, Y). Bits."""
    _check_pmf(pxy, name="pxy")
    px = marginal(pxy, axis=0)
    py = marginal(pxy, axis=1)
    return shannon_entropy(px) + shannon_entropy(py) - shannon_entropy(pxy)


def guessing_probability(pmf: Mapping[T, float]) -> float:
    """Optimal one-shot guess probability = max_x p(x) = 2^{-H_inf(X)}."""
    _check_pmf(pmf, name="pmf")
    return max(pmf.values())


def extractable_bits(min_ent: float, *, security: float = 80.0) -> float:
    """Leftover hash lemma: bits extractable from H_inf(X) with stat-sec 2^-security.

    L <= H_inf(X) - 2 * security. Returns max(0, ...).
    """
    if security < 0:
        raise ValueError("security must be >= 0")
    return max(0.0, min_ent - 2.0 * security)


def main():
    print("=" * 60)
    print("ENTROPIES FOR CRYPTOGRAPHERS")
    print("=" * 60)

    print("\n--- Fair coin vs biased coin ---")
    fair = {0: 0.5, 1: 0.5}
    biased = {0: 0.1, 1: 0.9}
    print(f"H(fair)   = {shannon_entropy(fair):.6f}  H_inf = {min_entropy(fair):.6f}")
    print(f"H(biased) = {shannon_entropy(biased):.6f}  H_inf = {min_entropy(biased):.6f}")
    print("(Shannon overestimates security; min-entropy is what attackers care about)")

    print("\n--- Renyi family on a skewed distribution ---")
    skew = {"a": 0.5, "b": 0.25, "c": 0.125, "d": 0.125}
    print(f"H_0   (max)       = {renyi_entropy(skew, 0):.6f}")
    print(f"H_1   (Shannon)   = {renyi_entropy(skew, 1):.6f}")
    print(f"H_2   (collision) = {renyi_entropy(skew, 2):.6f}")
    print(f"H_inf (min)       = {renyi_entropy(skew, math.inf):.6f}")
    print("(monotone decreasing in alpha)")

    print("\n--- KL divergence: biased coin vs fair coin ---")
    print(f"D(biased || fair) = {kl_divergence(biased, fair):.6f} bits")
    print(f"D(fair || biased) = {kl_divergence(fair, biased):.6f} bits  (asymmetric!)")

    print("\n--- Mutual information (correlated bits) ---")
    pxy = {(0, 0): 0.4, (0, 1): 0.1, (1, 0): 0.1, (1, 1): 0.4}
    print(f"I(X; Y) = {mutual_information(pxy):.6f}")
    print(f"H(X|Y)  = {conditional_entropy(pxy):.6f}")

    print("\n--- 32-bit password from a 'looks random' but biased generator ---")
    h_inf_per_bit = -math.log2(0.55)
    h_inf_total = 32 * h_inf_per_bit
    print(f"per-bit p_max=0.55 -> H_inf/bit ≈ {h_inf_per_bit:.4f}")
    print(f"H_inf(32 bits)              ≈ {h_inf_total:.2f}")
    print(f"Extractable @ 80-bit sec    ≈ {extractable_bits(h_inf_total, security=80):.2f} bits")
    print("(Need more raw bits to extract a usable 128-bit key)")

    print("\n--- Guessing probability ---")
    print(f"Pr[guess biased on first try] = {guessing_probability(biased)} = 2^-H_inf")


if __name__ == "__main__":
    main()
