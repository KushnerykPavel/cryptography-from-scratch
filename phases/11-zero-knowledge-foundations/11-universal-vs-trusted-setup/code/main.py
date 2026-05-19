"""
Universal vs Trusted Setup (toy model)

This script demonstrates, with a small *toy* KZG-style polynomial commitment,
why "trusted setup" creates "toxic waste", what "updatable ceremonies" buy you,
and how a *universal* setup differs from a per-circuit setup.

Run:
  python3 code/main.py
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Tuple


def mod_inv(a: int, m: int) -> int:
    a %= m
    if a == 0:
        raise ValueError("inverse does not exist for 0")
    t0, t1 = 0, 1
    r0, r1 = m, a
    while r1 != 0:
        q = r0 // r1
        t0, t1 = t1, t0 - q * t1
        r0, r1 = r1, r0 - q * r1
    if r0 != 1:
        raise ValueError("inverse does not exist")
    return t0 % m


def poly_eval(coeffs_asc: List[int], x: int, mod: int) -> int:
    x %= mod
    acc = 0
    power = 1
    for c in coeffs_asc:
        acc = (acc + (c % mod) * power) % mod
        power = (power * x) % mod
    return acc


def poly_div_by_linear(coeffs_asc: List[int], x0: int, mod: int) -> Tuple[List[int], int]:
    if len(coeffs_asc) == 0:
        raise ValueError("empty polynomial")
    if len(coeffs_asc) == 1:
        return [], coeffs_asc[0] % mod
    x0 %= mod
    a_desc = list(reversed([c % mod for c in coeffs_asc]))
    b_desc: List[int] = []
    for i, a in enumerate(a_desc):
        if i == 0:
            b_desc.append(a)
            continue
        b_desc.append((a + b_desc[i - 1] * x0) % mod)
    remainder = b_desc[-1]
    q_desc = b_desc[:-1]
    q_asc = list(reversed(q_desc))
    return q_asc, remainder


def _dlog_table(base: int, p: int, q: int) -> Dict[int, int]:
    table: Dict[int, int] = {}
    acc = 1
    for e in range(q):
        if acc in table:
            raise ValueError("base does not have order q")
        table[acc] = e
        acc = (acc * base) % p
    return table


@dataclass(frozen=True)
class ToyPairingGroup:
    p: int
    q: int
    g1: int
    g2: int
    gt: int
    dlog_g1: Dict[int, int]
    dlog_g2: Dict[int, int]

    def mul(self, a: int, b: int) -> int:
        return (a * b) % self.p

    def inv(self, a: int) -> int:
        a %= self.p
        if a == 0:
            raise ValueError("no inverse for 0 in multiplicative group")
        return pow(a, self.p - 2, self.p)

    def div(self, a: int, b: int) -> int:
        return self.mul(a, self.inv(b))

    def exp(self, a: int, e: int) -> int:
        return pow(a, e % self.q, self.p)

    def g1_exp(self, e: int) -> int:
        return self.exp(self.g1, e)

    def g2_exp(self, e: int) -> int:
        return self.exp(self.g2, e)

    def pairing(self, a_g1: int, b_g2: int) -> int:
        try:
            a = self.dlog_g1[a_g1]
            b = self.dlog_g2[b_g2]
        except KeyError as e:
            raise ValueError("element not in expected subgroup") from e
        return self.exp(self.gt, (a * b) % self.q)


@dataclass(frozen=True)
class KZGParams:
    group: ToyPairingGroup
    max_degree: int
    g1_powers_of_tau: List[int]
    g2_tau: int


def kzg_setup(max_degree: int, tau: int, group: ToyPairingGroup) -> KZGParams:
    if max_degree < 0:
        raise ValueError("max_degree must be >= 0")
    tau %= group.q
    powers: List[int] = []
    tau_power = 1
    for _ in range(max_degree + 1):
        powers.append(group.g1_exp(tau_power))
        tau_power = (tau_power * tau) % group.q
    g2_tau = group.g2_exp(tau)
    return KZGParams(group=group, max_degree=max_degree, g1_powers_of_tau=powers, g2_tau=g2_tau)


def kzg_trim(params: KZGParams, max_degree: int) -> KZGParams:
    if max_degree < 0:
        raise ValueError("max_degree must be >= 0")
    if max_degree > params.max_degree:
        raise ValueError("cannot trim to larger degree")
    return KZGParams(
        group=params.group,
        max_degree=max_degree,
        g1_powers_of_tau=params.g1_powers_of_tau[: max_degree + 1],
        g2_tau=params.g2_tau,
    )


def kzg_commit(coeffs_asc: List[int], params: KZGParams) -> int:
    if len(coeffs_asc) == 0:
        raise ValueError("empty polynomial")
    if len(coeffs_asc) - 1 > params.max_degree:
        raise ValueError("polynomial degree exceeds SRS bound")
    g = params.group
    acc = 1
    for i, c in enumerate(coeffs_asc):
        acc = g.mul(acc, g.exp(params.g1_powers_of_tau[i], c))
    return acc


def kzg_open(coeffs_asc: List[int], x: int, params: KZGParams) -> Tuple[int, int]:
    g = params.group
    x %= g.q
    y = poly_eval(coeffs_asc, x, g.q)
    quot, rem = poly_div_by_linear(coeffs_asc, x, g.q)
    if rem != y:
        raise ValueError("internal error: remainder mismatch")
    proof = kzg_commit(quot if len(quot) > 0 else [0], kzg_trim(params, max(params.max_degree - 1, 0)))
    return y, proof


def kzg_verify(commitment: int, x: int, y: int, proof: int, params: KZGParams) -> bool:
    g = params.group
    x %= g.q
    y %= g.q
    left = g.pairing(g.div(commitment, g.g1_exp(y)), g.g2)
    denom = g.div(params.g2_tau, g.g2_exp(x))
    right = g.pairing(proof, denom)
    return left == right


def pot_update(params: KZGParams, delta: int) -> KZGParams:
    g = params.group
    delta %= g.q
    if delta == 0:
        raise ValueError("delta must be non-zero")
    new_powers: List[int] = []
    delta_power = 1
    for elem in params.g1_powers_of_tau:
        new_powers.append(g.exp(elem, delta_power))
        delta_power = (delta_power * delta) % g.q
    new_g2_tau = g.exp(params.g2_tau, delta)
    return KZGParams(group=g, max_degree=params.max_degree, g1_powers_of_tau=new_powers, g2_tau=new_g2_tau)


def pot_apply_updates(params: KZGParams, deltas: Iterable[int]) -> KZGParams:
    out = params
    for d in deltas:
        out = pot_update(out, d)
    return out


def forge_opening_with_toxic_waste(
    commitment: int, x: int, y_fake: int, tau: int, params: KZGParams
) -> int:
    g = params.group
    x %= g.q
    y_fake %= g.q
    tau %= g.q
    denom = (tau - x) % g.q
    denom_inv = mod_inv(denom, g.q)
    numerator = g.div(commitment, g.g1_exp(y_fake))
    return g.exp(numerator, denom_inv)


def default_toy_group() -> ToyPairingGroup:
    p = 2027
    q = 1013
    g1 = 3
    g2 = 9
    gt = 3
    dlog_g1 = _dlog_table(g1, p, q)
    dlog_g2 = _dlog_table(g2, p, q)
    return ToyPairingGroup(p=p, q=q, g1=g1, g2=g2, gt=gt, dlog_g1=dlog_g1, dlog_g2=dlog_g2)


def _fmt_poly(coeffs: List[int]) -> str:
    terms: List[str] = []
    for i, c in enumerate(coeffs):
        c = int(c)
        if c == 0:
            continue
        if i == 0:
            terms.append(str(c))
        elif i == 1:
            terms.append(f"{c}*x")
        else:
            terms.append(f"{c}*x^{i}")
    return " + ".join(terms) if terms else "0"


def main() -> None:
    group = default_toy_group()

    print("=== Step 1: A Trusted Setup Creates Toxic Waste ===")
    tau = 123
    params = kzg_setup(max_degree=4, tau=tau, group=group)
    poly = [7, 3, 5]  # 7 + 3x + 5x^2
    x = 11
    commitment = kzg_commit(poly, params)
    y, proof = kzg_open(poly, x, params)
    ok = kzg_verify(commitment, x, y, proof, params)
    print(f"Polynomial: p(x) = {_fmt_poly(poly)}  (mod q={group.q})")
    print(f"Commitment C: {commitment}")
    print(f"Open at x={x}: y={y}, proof={proof}, verify={ok}")

    print("\n=== Step 2: If τ Leaks, You Can Forge Openings ===")
    y_fake = (y + 1) % group.q
    proof_forged = forge_opening_with_toxic_waste(commitment, x, y_fake, tau=tau, params=params)
    ok_forged = kzg_verify(commitment, x, y_fake, proof_forged, params)
    print(f"Forged opening at x={x} to y_fake={y_fake}: proof={proof_forged}, verify={ok_forged}")

    print("\n=== Step 3: Updatable (Multi-Party) Setup ===")
    deltas = [17, 222, 501]
    params_updated = pot_apply_updates(params, deltas)
    commitment_u = kzg_commit(poly, params_updated)
    y_u, proof_u = kzg_open(poly, x, params_updated)
    ok_u = kzg_verify(commitment_u, x, y_u, proof_u, params_updated)
    print(f"Contributions (deltas): {deltas}")
    print(f"Verify after updates (same polynomial): {ok_u}")

    print("\n=== Step 4: Universal Setup vs Per-Circuit Setup ===")
    universal = kzg_setup(max_degree=8, tau=777, group=group)
    circuit_a = kzg_trim(universal, max_degree=2)
    circuit_b = kzg_trim(universal, max_degree=5)
    poly_a = [1, 0, 1]  # 1 + x^2
    poly_b = [2, 1, 0, 0, 3, 4]  # 2 + x + 3x^4 + 4x^5
    ca = kzg_commit(poly_a, circuit_a)
    cb = kzg_commit(poly_b, circuit_b)
    ya, pa = kzg_open(poly_a, x=3, params=circuit_a)
    yb, pb = kzg_open(poly_b, x=3, params=circuit_b)
    print(f"Universal SRS degree bound: {universal.max_degree}")
    print(f"Circuit A bound: {circuit_a.max_degree}, commit={ca}, verify={kzg_verify(ca, 3, ya, pa, circuit_a)}")
    print(f"Circuit B bound: {circuit_b.max_degree}, commit={cb}, verify={kzg_verify(cb, 3, yb, pb, circuit_b)}")


if __name__ == "__main__":
    main()
