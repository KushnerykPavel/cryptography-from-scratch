from __future__ import annotations

import random
from collections.abc import Callable
from dataclasses import dataclass, field


@dataclass
class GroupParams:
    """Toy discrete-log group: Z_p* with prime p and generator g.

    Order of the group is p-1.  Keep p small (< 10^6) for educational demos.
    """

    p: int
    g: int

    def __post_init__(self) -> None:
        if self.p < 5:
            raise ValueError("p must be at least 5")
        if not (1 < self.g < self.p):
            raise ValueError("g must satisfy 1 < g < p")

    @property
    def order(self) -> int:
        return self.p - 1

    def exp(self, base: int, exp: int) -> int:
        return pow(base, exp % self.order, self.p)

    def inv(self, a: int) -> int:
        return pow(a, self.p - 2, self.p)

    def mul(self, a: int, b: int) -> int:
        return (a * b) % self.p

    def keygen(self, secret: int) -> int:
        """Public key: pk = g^secret mod p."""
        return self.exp(self.g, secret)


@dataclass
class Transcript:
    """A Schnorr-style sigma-protocol transcript: (commitment, challenge, response).

    Both real and simulated transcripts satisfy the same verification equation.
    """

    commitment: int
    challenge: int
    response: int
    simulated: bool = False

    def verify(self, pk: int, group: GroupParams) -> bool:
        """g^response == commitment * pk^challenge (mod p)."""
        lhs = group.exp(group.g, self.response)
        rhs = group.mul(self.commitment, group.exp(pk, self.challenge))
        return lhs == rhs


@dataclass
class SimulationResult:
    """Summary of a simulation experiment."""

    n_real: int
    n_simulated: int
    real_verify_rate: float
    sim_verify_rate: float
    distinguisher_advantage: float
    simulation_succeeds: bool = field(init=False)

    def __post_init__(self) -> None:
        self.simulation_succeeds = (
            abs(self.real_verify_rate - 1.0) < 0.01
            and abs(self.sim_verify_rate - 1.0) < 0.01
            and self.distinguisher_advantage < 0.1
        )


def real_transcript(
    secret: int,
    pk: int,
    group: GroupParams,
    *,
    rng: random.Random | None = None,
) -> Transcript:
    """Generate a real Schnorr ZK transcript using the secret witness.

    Protocol:
      1. Prover picks random r ← Z_{p-1}
      2. Sends commitment R = g^r
      3. Receives challenge c (random)
      4. Sends response s = (r + c * secret) mod (p-1)
    """
    if rng is None:
        rng = random.Random()
    r = rng.randrange(1, group.order)
    R = group.exp(group.g, r)
    c = rng.randrange(1, group.order)
    s = (r + c * secret) % group.order
    return Transcript(commitment=R, challenge=c, response=s, simulated=False)


def simulated_transcript(
    pk: int,
    group: GroupParams,
    *,
    rng: random.Random | None = None,
) -> Transcript:
    """Generate a simulated Schnorr transcript WITHOUT the secret witness.

    Simulator picks c and s freely, then computes R = g^s * pk^{-c}.
    The transcript satisfies the verification equation by construction,
    but the order of operations is reversed (s chosen before R is fixed).
    """
    if rng is None:
        rng = random.Random()
    c = rng.randrange(1, group.order)
    s = rng.randrange(1, group.order)
    pk_neg_c = group.inv(group.exp(pk, c))
    R = group.mul(group.exp(group.g, s), pk_neg_c)
    return Transcript(commitment=R, challenge=c, response=s, simulated=True)


def transcript_advantage(
    distinguisher: Callable[[Transcript], int],
    real_transcripts: list[Transcript],
    sim_transcripts: list[Transcript],
) -> float:
    """Estimate distinguishing advantage of D between real and simulated transcripts.

    Adv = |Pr[D(t)=1 | t real] - Pr[D(t)=1 | t simulated]|
    """
    if not real_transcripts or not sim_transcripts:
        raise ValueError("transcript lists must be non-empty")
    pr_real = sum(1 for t in real_transcripts if distinguisher(t) == 1) / len(real_transcripts)
    pr_sim = sum(1 for t in sim_transcripts if distinguisher(t) == 1) / len(sim_transcripts)
    return abs(pr_real - pr_sim)


def run_simulation_experiment(
    group: GroupParams,
    secret: int,
    n_samples: int,
    distinguisher: Callable[[Transcript], int],
    *,
    rng: random.Random | None = None,
) -> SimulationResult:
    """Run full simulation experiment: generate real + simulated transcripts,
    verify both, measure distinguishing advantage.
    """
    if rng is None:
        rng = random.Random()
    pk = group.keygen(secret)
    reals = [real_transcript(secret, pk, group, rng=rng) for _ in range(n_samples)]
    sims = [simulated_transcript(pk, group, rng=rng) for _ in range(n_samples)]
    real_ok = sum(t.verify(pk, group) for t in reals) / n_samples
    sim_ok = sum(t.verify(pk, group) for t in sims) / n_samples
    adv = transcript_advantage(distinguisher, reals, sims)
    return SimulationResult(
        n_real=n_samples,
        n_simulated=n_samples,
        real_verify_rate=real_ok,
        sim_verify_rate=sim_ok,
        distinguisher_advantage=adv,
    )


def verify_transcript_exact(t: Transcript, pk: int, group: GroupParams) -> bool:
    """Thin wrapper — same as Transcript.verify, for test-vector use."""
    return t.verify(pk, group)


def main():
    print("=" * 60)
    print("THE SIMULATOR — HOW SECURITY PROOFS WORK")
    print("=" * 60)

    # p=23 is prime, g=5 is a generator of Z_23*.
    group = GroupParams(p=23, g=5)
    secret = 3
    pk = group.keygen(secret)  # 5^3 mod 23 = 10
    rng = random.Random(42)

    print(f"\nGroup: p={group.p}, g={group.g}, order={group.order}")
    print(f"Secret x={secret}, public key pk=g^x={pk}")

    print("\n--- Real transcript (prover knows secret) ---")
    rt = real_transcript(secret, pk, group, rng=random.Random(7))
    print(f"  R={rt.commitment}, c={rt.challenge}, s={rt.response}")
    print(f"  Verifies: {rt.verify(pk, group)}")
    print(f"  Check: g^s={group.exp(group.g, rt.response)} == R*pk^c={group.mul(rt.commitment, group.exp(pk, rt.challenge))}")

    print("\n--- Simulated transcript (no secret needed) ---")
    st = simulated_transcript(pk, group, rng=random.Random(99))
    print(f"  R={st.commitment}, c={st.challenge}, s={st.response}")
    print(f"  Verifies: {st.verify(pk, group)}")
    print(f"  Check: g^s={group.exp(group.g, st.response)} == R*pk^c={group.mul(st.commitment, group.exp(pk, st.challenge))}")

    print("\n--- Can a distinguisher tell real from simulated? ---")
    n = 5_000

    def naive_dist(t: Transcript) -> int:
        return 1 if t.simulated else 0

    def commitment_parity_dist(t: Transcript) -> int:
        return 1 if t.commitment % 2 == 0 else 0

    def response_threshold_dist(t: Transcript) -> int:
        return 1 if t.response > group.order // 2 else 0

    for name, dist in [
        ("mark-simulated field", naive_dist),
        ("commitment parity", commitment_parity_dist),
        ("response > order/2", response_threshold_dist),
    ]:
        result = run_simulation_experiment(group, secret, n, dist, rng=random.Random(42))
        print(f"  [{name}]  Adv={result.distinguisher_advantage:.4f}  "
              f"real_verify={result.real_verify_rate:.3f}  "
              f"sim_verify={result.sim_verify_rate:.3f}")

    print()
    print("  'mark-simulated field' has perfect advantage — but it cheats by reading")
    print("  the simulated flag. Any distinguisher that only sees (R, c, s) cannot")
    print("  detect the difference (uniform c, s in both cases over a small group).")

    print("\n--- Why simulation proves zero-knowledge ---")
    print("  Real ZK proof:    prover knows x, produces (R=g^r, c, s=r+cx)")
    print("  Simulated proof:  no x needed, produces (R=g^s·pk^{-c}, c, s)")
    print("  Both verify:      g^s == R·pk^c (by construction)")
    print("  No verifier can:  tell which it got — so the proof leaks zero knowledge")
    print("  Simulator exists: therefore the verifier learns nothing beyond 'pk is valid'")

    print("\n--- Simulation experiment summary (5000 transcripts each) ---")
    result = run_simulation_experiment(
        group, secret, 5_000, commitment_parity_dist, rng=random.Random(0)
    )
    print(f"  Real verify rate:  {result.real_verify_rate:.4f}")
    print(f"  Sim verify rate:   {result.sim_verify_rate:.4f}")
    print(f"  Adv(parity dist):  {result.distinguisher_advantage:.4f}")
    print(f"  Simulation valid:  {result.simulation_succeeds}")


if __name__ == "__main__":
    main()
