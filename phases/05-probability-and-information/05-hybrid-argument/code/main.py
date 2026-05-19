from __future__ import annotations

import random
from collections.abc import Callable, Sequence

Sampler = Callable[[], object]
Distinguisher = Callable[[object], int]


def hybrid_advantage_bound(per_hop_advantages: Sequence[float]) -> float:
    """Triangle inequality: Adv(H_0, H_k) <= Σ_i Adv(H_i, H_{i+1}).

    Returns the upper bound on total endpoint advantage from per-hop advantages.
    """
    if any(a < 0 for a in per_hop_advantages):
        raise ValueError("advantages must be non-negative")
    return sum(per_hop_advantages)


def run_hybrid_chain(
    samplers: Sequence[Sampler],
    distinguisher: Distinguisher,
    n_rounds: int,
    *,
    rng: random.Random | None = None,
) -> dict:
    """Run the IND game on each adjacent pair in a hybrid chain.

    Returns per_hop empirical advantages, triangle bound, and direct
    endpoint advantage (H_0 vs H_k).
    """
    if len(samplers) < 2:
        raise ValueError("need at least 2 distributions in the chain")
    if n_rounds <= 0:
        raise ValueError("n_rounds must be positive")
    if rng is None:
        rng = random.Random()

    per_hop: list[float] = []
    for s0, s1 in zip(samplers, samplers[1:]):
        correct = 0
        for _ in range(n_rounds):
            b = rng.randint(0, 1)
            x = s0() if b == 0 else s1()
            if distinguisher(x) == b:
                correct += 1
        per_hop.append(abs(correct / n_rounds - 0.5) * 2)

    correct_ep = 0
    for _ in range(n_rounds):
        b = rng.randint(0, 1)
        x = samplers[0]() if b == 0 else samplers[-1]()
        if distinguisher(x) == b:
            correct_ep += 1
    endpoint_adv = abs(correct_ep / n_rounds - 0.5) * 2

    return {
        "per_hop": per_hop,
        "triangle_bound": hybrid_advantage_bound(per_hop),
        "endpoint_advantage": endpoint_adv,
    }


def negligible_sum(epsilon_per_hop: float, n_hops: int) -> float:
    """Total advantage: n_hops * epsilon_per_hop.

    A polynomial number of negligible per-hop advantages sums to a negligible
    total. This function computes the sum; use is_poly_sum_negligible to check.
    """
    if epsilon_per_hop < 0:
        raise ValueError("epsilon_per_hop must be non-negative")
    if n_hops < 0:
        raise ValueError("n_hops must be non-negative")
    return n_hops * epsilon_per_hop


def is_poly_sum_negligible(
    epsilon_per_hop: float,
    n_hops: int,
    security_param: int,
    *,
    poly_degree: int = 1,
) -> bool:
    """True if n_hops * epsilon_per_hop < 1 / security_param^poly_degree.

    The hybrid argument is valid when this sum is negligible in the security
    parameter even after multiplying by a polynomial number of hops.
    """
    if security_param <= 0:
        raise ValueError("security_param must be positive")
    total = negligible_sum(epsilon_per_hop, n_hops)
    return total < 1.0 / (security_param ** poly_degree)


def reduction_advantage(
    distinguisher_advantage: float,
    n_hops: int,
) -> float:
    """Lower bound on the per-hop primitive advantage via reduction.

    If a distinguisher breaks the full chain with advantage A over k hops,
    then by averaging, at least one hop has advantage >= A/k.
    The reduction against that hop achieves A/k.
    """
    if n_hops <= 0:
        raise ValueError("n_hops must be positive")
    if distinguisher_advantage < 0:
        raise ValueError("advantage must be non-negative")
    return distinguisher_advantage / n_hops


def make_hybrid_otp_samplers(
    messages: Sequence[int],
    n_real: int,
    *,
    rng: random.Random | None = None,
) -> Callable[[], tuple[int, ...]]:
    """Return a sampler for hybrid H_{n_real}.

    H_i encrypts the first i messages with truly uniform pads (ideal OTP),
    and the remaining messages with G(k) = k & 1 (toy PRG, same seed k).

    messages: list of plaintext bits
    n_real:   how many messages use the toy PRG (0 = fully ideal, len = fully real)
    """
    if rng is None:
        rng = random.Random()
    n = len(messages)

    def sampler() -> tuple[int, ...]:
        ciphertexts = []
        seed = rng.getrandbits(16)
        for i, m in enumerate(messages):
            if i < (n - n_real):
                pad = rng.randint(0, 1)
            else:
                pad = (seed >> i) & 1
            ciphertexts.append(m ^ pad)
        return tuple(ciphertexts)

    return sampler


def main():
    print("=" * 60)
    print("THE HYBRID ARGUMENT")
    print("=" * 60)

    print("\n--- Triangle inequality on paper ---")
    hops = [0.05, 0.03, 0.04, 0.02]
    bound = hybrid_advantage_bound(hops)
    print(f"Per-hop advantages: {hops}")
    print(f"Triangle bound:     {bound:.4f}")
    print(f"Endpoint Adv <= {bound:.4f}  (sum of {len(hops)} hops)")

    print("\n--- Polynomial sum of negligibles is negligible ---")
    n = 128
    eps = 2 ** -n
    for k in (1, n, n * n):
        total = negligible_sum(eps, k)
        still_ok = is_poly_sum_negligible(eps, k, n, poly_degree=1)
        print(f"  k={k:7d}  k*ε = {total:.2e}  still negligible (d=1)? {still_ok}")
    print("(k*ε stays negligible when k is polynomial in n)")

    print("\n--- Reduction: averaging argument ---")
    full_adv = 0.09
    for k in (3, 9, 100):
        per_hop = reduction_advantage(full_adv, k)
        print(f"  full_adv={full_adv}  k={k:3d}  worst-hop >= {per_hop:.4f}")
    print("If full_adv is non-negligible, at least one hop is non-negligible.")

    print("\n--- Concrete hybrid: 4-message OTP encryption chain ---")
    messages = [1, 0, 1, 1]
    n = len(messages)
    rng_chain = random.Random(42)

    samplers = [
        make_hybrid_otp_samplers(messages, n_real, rng=random.Random(i * 100))
        for i, n_real in enumerate(range(n + 1))
    ]

    def distinguisher_all_zero(ct):
        return 1 if all(b == 0 for b in ct) else 0

    result = run_hybrid_chain(
        samplers,
        distinguisher_all_zero,
        n_rounds=5_000,
        rng=random.Random(99),
    )
    print(f"Per-hop advantages:   {[f'{a:.4f}' for a in result['per_hop']]}")
    print(f"Triangle bound:       {result['triangle_bound']:.4f}")
    print(f"Endpoint advantage:   {result['endpoint_advantage']:.4f}")
    print(f"Bound holds?          {result['endpoint_advantage'] <= result['triangle_bound'] + 0.02}")
    print()
    print("H_0 = all PRG-encrypted  →  H_4 = all truly random pads")
    print("Each hop replaces one PRG call with uniform randomness.")
    print("If PRG is secure, each hop has negligible advantage.")
    print("By the triangle inequality, the endpoints are indistinguishable.")


if __name__ == "__main__":
    main()
