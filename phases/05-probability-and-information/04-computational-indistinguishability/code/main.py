from __future__ import annotations

import math
import random
from collections.abc import Callable, Sequence
from typing import TypeVar

T = TypeVar("T")

Distinguisher = Callable[[T], int]


def estimate_advantage(
    distinguisher: Distinguisher,
    samples_0: Sequence,
    samples_1: Sequence,
) -> float:
    """Estimate distinguishing advantage from pre-drawn sample lists.

    Adv = |Pr[D(x)=1 | x←D0] - Pr[D(x)=1 | x←D1]|
    """
    if not samples_0 or not samples_1:
        raise ValueError("sample lists must be non-empty")
    pr1_d0 = sum(1 for x in samples_0 if distinguisher(x) == 1) / len(samples_0)
    pr1_d1 = sum(1 for x in samples_1 if distinguisher(x) == 1) / len(samples_1)
    return abs(pr1_d0 - pr1_d1)


def run_ind_game(
    sampler_0: Callable[[], T],
    sampler_1: Callable[[], T],
    distinguisher: Distinguisher,
    n_rounds: int,
    *,
    rng: random.Random | None = None,
) -> float:
    """Run the IND-distinguishing experiment for n_rounds, return empirical advantage.

    Each round:
      challenger samples b ← {0,1}
      sends x ← D_b to distinguisher
      advantage = |Pr[b'=b] - 1/2| * 2
    """
    if n_rounds <= 0:
        raise ValueError("n_rounds must be positive")
    if rng is None:
        rng = random.Random()
    correct = 0
    for _ in range(n_rounds):
        b = rng.randint(0, 1)
        x = sampler_0() if b == 0 else sampler_1()
        b_prime = distinguisher(x)
        if b_prime == b:
            correct += 1
    success_rate = correct / n_rounds
    return abs(success_rate - 0.5) * 2


def advantage_bernoulli(p0: float, p1: float) -> float:
    """Closed-form optimal advantage against two Bernoulli distributions.

    For D0 = Bernoulli(p0), D1 = Bernoulli(p1):
      Adv_optimal = |p0 - p1|   (equals their statistical distance)
    """
    if not (0.0 <= p0 <= 1.0 and 0.0 <= p1 <= 1.0):
        raise ValueError("probabilities must be in [0, 1]")
    return abs(p0 - p1)


def negligible_bound(security_param: int, *, poly_degree: int = 1) -> float:
    """Return 1 / n^poly_degree — the negligibility threshold at security parameter n."""
    if security_param <= 0:
        raise ValueError("security_param must be positive")
    if poly_degree <= 0:
        raise ValueError("poly_degree must be positive")
    return 1.0 / (security_param ** poly_degree)


def is_negligible(
    epsilon: float,
    security_param: int,
    *,
    poly_degree: int = 1,
) -> bool:
    """True if epsilon < 1/n^poly_degree (negligible with respect to n^d)."""
    return epsilon < negligible_bound(security_param, poly_degree=poly_degree)


def advantage_uniform_vs_biased(support_size: int, delta: float) -> float:
    """Optimal advantage when D0 = Uniform({0..n-1}) and D1 shifts one element by delta.

    D1: one element gets probability 1/n + delta*(n-1)/n,
        all others get probability 1/n * (1-delta).
    Optimal distinguisher: output 1 iff x == 0.
    Adv = |(1/n + delta*(n-1)/n) - 1/n| = delta*(n-1)/n
    """
    if support_size <= 0:
        raise ValueError("support_size must be positive")
    if not (0.0 <= delta <= 1.0):
        raise ValueError("delta must be in [0, 1]")
    return delta * (support_size - 1) / support_size


def statistical_distance_upper_bound(sd: float) -> float:
    """Advantage of the unbounded optimal distinguisher equals SD(D0, D1).

    Any computationally-bounded distinguisher has advantage <= SD.
    Returns sd (the bound).
    """
    if sd < 0:
        raise ValueError("sd must be non-negative")
    return sd


def main():
    print("=" * 60)
    print("COMPUTATIONAL INDISTINGUISHABILITY")
    print("=" * 60)

    rng = random.Random(42)

    print("\n--- Advantage: fair vs biased coin ---")
    adv_theory = advantage_bernoulli(0.5, 0.9)
    samples_fair = [rng.randint(0, 1) for _ in range(20_000)]
    samples_biased = [0 if rng.random() < 0.9 else 1 for _ in range(20_000)]
    adv_empirical = estimate_advantage(lambda x: 1 if x == 0 else 0, samples_fair, samples_biased)
    print(f"Closed-form Adv(fair vs biased p=0.9): {adv_theory:.4f}")
    print(f"Empirical  Adv (20k samples each):     {adv_empirical:.4f}")
    print("(Optimal distinguisher: output 1 iff x == 0)")

    print("\n--- IND game experiment ---")
    rng_game = random.Random(7)
    game_adv = run_ind_game(
        lambda: rng_game.randint(0, 1),
        lambda: 0 if rng_game.random() < 0.9 else 1,
        lambda x: 1 if x == 0 else 0,
        20_000,
        rng=rng_game,
    )
    print(f"IND game advantage (20k rounds): {game_adv:.4f}")
    print("Challenger picks b, sends x←D_b; distinguisher guesses b")

    print("\n--- Negligibility at various security parameters ---")
    print(f"{'n':>6}  {'1/n':>10}  {'1/n^2':>10}  {'1/n^3':>10}")
    for n in (10, 50, 100, 200, 1000):
        print(f"{n:>6}  {1/n:>10.2e}  {1/n**2:>10.2e}  {1/n**3:>10.2e}")
    print()
    print("epsilon=0.001, n=100:")
    print(f"  negligible vs 1/n   ? {is_negligible(0.001, 100, poly_degree=1)}")
    print(f"  negligible vs 1/n^2 ? {is_negligible(0.001, 100, poly_degree=2)}")

    print("\n--- Nearly uniform: computational vs statistical security ---")
    n = 256
    delta = 1e-5
    adv_close = advantage_uniform_vs_biased(n, delta)
    adv_far = advantage_uniform_vs_biased(n, 0.4)
    print(f"N={n}, delta={delta:.0e}: optimal Adv = {adv_close:.2e}")
    print(f"N={n}, delta=0.4:       optimal Adv = {adv_far:.4f}")
    print(f"delta={delta:.0e} is negligible at n=256, d=1? {is_negligible(adv_close, n, poly_degree=1)}")
    print(
        "\nKey insight: even if Adv is tiny (stat. dist small), a PPT adversary"
        "\nmight exploit structure (e.g. in a PRG). Computational security"
        "\nrequires no PPT adversary has non-negligible advantage."
    )

    print("\n--- SD upper-bounds all distinguishers ---")
    sd = 0.001
    print(f"SD(D0, D1) = {sd}")
    print(f"No distinguisher, PPT or unbounded, can exceed Adv = {statistical_distance_upper_bound(sd)}")
    print("Computational ⊆ statistical: if SD is negligible, so is every PPT advantage.")


if __name__ == "__main__":
    main()
