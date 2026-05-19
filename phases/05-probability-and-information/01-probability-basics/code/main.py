from __future__ import annotations

import random
from collections.abc import Callable, Mapping, Sequence
from typing import TypeVar

T = TypeVar("T")


def _check_prob(p: float, *, name: str) -> None:
    if not (0.0 <= p <= 1.0):
        raise ValueError(f"{name} must be in [0, 1], got {p!r}")


def normalize_pmf(weights: Mapping[T, float]) -> dict[T, float]:
    if not weights:
        raise ValueError("pmf weights must be non-empty")
    total = 0.0
    for p in weights.values():
        if p < 0:
            raise ValueError("pmf weights must be non-negative")
        total += p
    if total <= 0:
        raise ValueError("pmf weights must sum to a positive value")
    return {k: v / total for k, v in weights.items()}


def pmf_from_counts(counts: Mapping[T, int]) -> dict[T, float]:
    if not counts:
        raise ValueError("counts must be non-empty")
    total = 0
    for c in counts.values():
        if c < 0:
            raise ValueError("counts must be non-negative")
        total += c
    if total == 0:
        raise ValueError("counts must sum to a positive value")
    return {k: c / total for k, c in counts.items()}


def prob_event(pmf: Mapping[T, float], predicate: Callable[[T], bool]) -> float:
    return sum(p for outcome, p in pmf.items() if predicate(outcome))


def conditional_probability(p_a_and_b: float, p_b: float) -> float:
    if p_b <= 0:
        raise ValueError("P(B) must be > 0 for conditional probability")
    return p_a_and_b / p_b


def condition_pmf(pmf: Mapping[T, float], predicate: Callable[[T], bool]) -> dict[T, float]:
    p_b = prob_event(pmf, predicate)
    if p_b <= 0:
        raise ValueError("cannot condition on an event with probability 0")
    return {outcome: p / p_b for outcome, p in pmf.items() if predicate(outcome)}


def is_independent(p_a_and_b: float, p_a: float, p_b: float, *, tol: float = 1e-12) -> bool:
    _check_prob(p_a_and_b, name="P(A∩B)")
    _check_prob(p_a, name="P(A)")
    _check_prob(p_b, name="P(B)")
    return abs(p_a_and_b - (p_a * p_b)) <= tol


def union_bound(probs: Sequence[float]) -> float:
    total = 0.0
    for i, p in enumerate(probs):
        _check_prob(p, name=f"probs[{i}]")
        total += p
    return min(1.0, total)


def distinguishing_advantage(p_real: float, p_ideal: float) -> float:
    _check_prob(p_real, name="p_real")
    _check_prob(p_ideal, name="p_ideal")
    return abs(p_real - p_ideal)


def bayes_posterior(*, prior: float, likelihood: float, false_positive_rate: float) -> float:
    _check_prob(prior, name="prior")
    _check_prob(likelihood, name="likelihood")
    _check_prob(false_positive_rate, name="false_positive_rate")
    evidence = likelihood * prior + false_positive_rate * (1.0 - prior)
    if evidence <= 0:
        raise ValueError("evidence must be > 0")
    return (likelihood * prior) / evidence


def monte_carlo_estimate(trials: int, experiment: Callable[[random.Random], bool], *, seed: int = 0) -> float:
    if trials <= 0:
        raise ValueError("trials must be > 0")
    rng = random.Random(seed)
    wins = 0
    for _ in range(trials):
        if experiment(rng):
            wins += 1
    return wins / trials


def main():
    print("=" * 60)
    print("PROBABILITY BASICS FOR CRYPTOGRAPHERS")
    print("=" * 60)

    print("\n--- Conditional probability (cards) ---")
    p_king_given_face = conditional_probability(4 / 52, 12 / 52)
    print(f"P(King | Face card) = {p_king_given_face:.6f} (expected 1/3)")

    print("\n--- Conditioning a PMF ---")
    die = pmf_from_counts({1: 1, 2: 1, 3: 1, 4: 1, 5: 1, 6: 1})
    p_even = prob_event(die, lambda x: x % 2 == 0)
    die_given_even = condition_pmf(die, lambda x: x % 2 == 0)
    print(f"P(even) = {p_even:.6f}")
    print(f"P(die=6 | even) = {die_given_even[6]:.6f} (expected 1/3)")

    print("\n--- Union bound (many bad events) ---")
    k = 1000
    per_trial = 2 ** -40
    print(f"k={k}, per-trial failure <= 2^-40 ≈ {per_trial:.3e}")
    print(f"Union bound: Pr[any failure] <= k·p ≈ {k * per_trial:.3e}")

    print("\n--- Advantage (distinguishing) ---")
    p_real = 0.6
    p_ideal = 0.5
    adv = distinguishing_advantage(p_real, p_ideal)
    print(f"|{p_real} - {p_ideal}| = {adv:.6f}")

    print("\n--- Bayes posterior (base rates matter) ---")
    posterior = bayes_posterior(prior=0.0001, likelihood=0.99, false_positive_rate=0.01)
    print(f"P(sick | positive) ≈ {posterior:.6f} (about {posterior*100:.2f}%)")

    print("\n--- Monte Carlo sanity check (two dice sum=7) ---")
    exact = 6 / 36

    def exp_sum7(rng: random.Random) -> bool:
        a = rng.randrange(1, 7)
        b = rng.randrange(1, 7)
        return (a + b) == 7

    est = monte_carlo_estimate(50_000, exp_sum7, seed=42)
    print(f"Exact: {exact:.6f}, estimate (50k trials): {est:.6f}")


if __name__ == "__main__":
    main()
