from __future__ import annotations

from collections.abc import Mapping
from itertools import combinations
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


def statistical_distance(p: Mapping[T, float], q: Mapping[T, float]) -> float:
    _check_pmf(p, name="p")
    _check_pmf(q, name="q")
    support = set(p) | set(q)
    return 0.5 * sum(abs(p.get(x, 0.0) - q.get(x, 0.0)) for x in support)


def total_variation_distance(p: Mapping[T, float], q: Mapping[T, float]) -> float:
    return statistical_distance(p, q)


def sd_from_event_max(p: Mapping[T, float], q: Mapping[T, float]) -> float:
    """Compute max_E |P(E) - Q(E)| by enumerating all subsets of the support.

    Equals statistical_distance(p, q). Exponential in support size — use only
    for small examples to verify the identity SD = max_E |P(E) - Q(E)|.
    """
    _check_pmf(p, name="p")
    _check_pmf(q, name="q")
    support = list(set(p) | set(q))
    best = 0.0
    for size in range(len(support) + 1):
        for subset in combinations(support, size):
            p_e = sum(p.get(x, 0.0) for x in subset)
            q_e = sum(q.get(x, 0.0) for x in subset)
            diff = abs(p_e - q_e)
            if diff > best:
                best = diff
    return best


def best_distinguisher_advantage(p: Mapping[T, float], q: Mapping[T, float]) -> float:
    """Optimal computationally-unbounded distinguishing advantage = SD(P, Q)."""
    return statistical_distance(p, q)


def uniform_pmf(support: list[T]) -> dict[T, float]:
    if not support:
        raise ValueError("support must be non-empty")
    n = len(support)
    return {x: 1.0 / n for x in support}


def sd_to_uniform(p: Mapping[T, float], support: list[T]) -> float:
    return statistical_distance(p, uniform_pmf(support))


def biased_bit_sd(epsilon: float) -> float:
    """SD between Bernoulli(1/2 + epsilon) and Bernoulli(1/2). Equals |epsilon|."""
    if not (-0.5 <= epsilon <= 0.5):
        raise ValueError("epsilon must be in [-1/2, 1/2]")
    biased = {0: 0.5 - epsilon, 1: 0.5 + epsilon}
    fair = {0: 0.5, 1: 0.5}
    return statistical_distance(biased, fair)


def triangle_inequality_gap(
    p: Mapping[T, float], q: Mapping[T, float], r: Mapping[T, float]
) -> float:
    """Returns SD(P,R) + SD(R,Q) - SD(P,Q). Must be >= 0 (triangle inequality)."""
    return statistical_distance(p, r) + statistical_distance(r, q) - statistical_distance(p, q)


def is_statistically_close(
    p: Mapping[T, float], q: Mapping[T, float], *, epsilon: float
) -> bool:
    if epsilon < 0:
        raise ValueError("epsilon must be non-negative")
    return statistical_distance(p, q) <= epsilon


def main():
    print("=" * 60)
    print("STATISTICAL DISTANCE & TOTAL VARIATION")
    print("=" * 60)

    print("\n--- Fair vs slightly biased coin ---")
    fair = {0: 0.5, 1: 0.5}
    biased = {0: 0.4, 1: 0.6}
    sd = statistical_distance(fair, biased)
    print(f"SD(fair, biased(0.6)) = {sd:.6f}  (expected 0.1)")
    print(f"biased_bit_sd(0.1)    = {biased_bit_sd(0.1):.6f}")

    print("\n--- SD == max-event identity (small support) ---")
    p = {"a": 0.5, "b": 0.3, "c": 0.2}
    q = {"a": 0.2, "b": 0.5, "c": 0.3}
    print(f"SD          = {statistical_distance(p, q):.6f}")
    print(f"max_E |P-Q| = {sd_from_event_max(p, q):.6f}")

    print("\n--- Distance from uniform (loaded die) ---")
    loaded = {1: 0.1, 2: 0.1, 3: 0.1, 4: 0.1, 5: 0.1, 6: 0.5}
    sd_u = sd_to_uniform(loaded, [1, 2, 3, 4, 5, 6])
    print(f"SD(loaded die, U_6) = {sd_u:.6f}")

    print("\n--- Best distinguisher advantage = SD ---")
    print(f"Adv* = SD(fair, biased) = {best_distinguisher_advantage(fair, biased):.6f}")

    print("\n--- Triangle inequality (non-negative gap) ---")
    r = {0: 0.45, 1: 0.55}
    gap = triangle_inequality_gap(fair, biased, r)
    print(f"SD(F,R) + SD(R,B) - SD(F,B) = {gap:.6f}  (must be >= 0)")

    print("\n--- Statistical closeness check ---")
    print(f"close at eps=0.05? {is_statistically_close(fair, biased, epsilon=0.05)}")
    print(f"close at eps=0.20? {is_statistically_close(fair, biased, epsilon=0.20)}")


if __name__ == "__main__":
    main()
