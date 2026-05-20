"""
Toy Groth16 (educational) implemented with stdlib-only finite fields and a toy pairing.

What this file does:
- Builds a tiny R1CS for the relation "I know x such that y = x^2" (y public, x private).
- Converts the R1CS to a QAP and checks the divisibility condition.
- Runs a toy Groth16 Setup/Prove/Verify flow using a fake bilinear pairing:
    e(g^a, g^b) = g^(a*b)

How to run:
  python3 code/main.py

Important:
- This is an educational implementation. Not constant-time. Not production-safe.
- The "pairing" here is not an elliptic-curve pairing; it's a toy map over a small group.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from typing import Iterable, List, Sequence, Tuple


# We work in:
# - A scalar field F_r of order r (prime)
# - A multiplicative group mod P that has a subgroup of order r
SCALAR_FIELD_MODULUS = 509  # prime
GROUP_MODULUS = 1019  # prime, and (1019 - 1) = 2 * 509 so there is a subgroup of order 509


def mod_norm(x: int, mod: int) -> int:
    return x % mod


def mod_inv(x: int, mod: int) -> int:
    x = x % mod
    if x == 0:
        raise ZeroDivisionError("no inverse for 0")
    return pow(x, -1, mod)


def mod_div(a: int, b: int, mod: int) -> int:
    return (a % mod) * mod_inv(b, mod) % mod


def poly_trim(poly: List[int]) -> List[int]:
    while len(poly) > 1 and poly[-1] == 0:
        poly.pop()
    return poly


def poly_add(a: Sequence[int], b: Sequence[int], mod: int) -> List[int]:
    out = []
    n = max(len(a), len(b))
    for i in range(n):
        av = a[i] if i < len(a) else 0
        bv = b[i] if i < len(b) else 0
        out.append((av + bv) % mod)
    return poly_trim(out)


def poly_sub(a: Sequence[int], b: Sequence[int], mod: int) -> List[int]:
    out = []
    n = max(len(a), len(b))
    for i in range(n):
        av = a[i] if i < len(a) else 0
        bv = b[i] if i < len(b) else 0
        out.append((av - bv) % mod)
    return poly_trim(out)


def poly_scale(a: Sequence[int], k: int, mod: int) -> List[int]:
    k %= mod
    return poly_trim([(k * c) % mod for c in a] if a else [0])


def poly_mul(a: Sequence[int], b: Sequence[int], mod: int) -> List[int]:
    if not a or not b:
        return [0]
    out = [0] * (len(a) + len(b) - 1)
    for i, av in enumerate(a):
        if av == 0:
            continue
        for j, bv in enumerate(b):
            out[i + j] = (out[i + j] + av * bv) % mod
    return poly_trim(out)


def poly_eval(poly: Sequence[int], x: int, mod: int) -> int:
    x %= mod
    acc = 0
    power = 1
    for c in poly:
        acc = (acc + c * power) % mod
        power = (power * x) % mod
    return acc


def poly_divmod(numer: Sequence[int], denom: Sequence[int], mod: int) -> Tuple[List[int], List[int]]:
    denom = poly_trim(list(denom))
    numer = poly_trim(list(numer))

    if denom == [0]:
        raise ZeroDivisionError("polynomial division by zero")
    if len(numer) < len(denom):
        return [0], list(numer)

    numer = list(numer)
    denom_deg = len(denom) - 1
    denom_lc = denom[-1] % mod
    denom_lc_inv = mod_inv(denom_lc, mod)

    q = [0] * (len(numer) - len(denom) + 1)
    while len(numer) >= len(denom) and numer != [0]:
        shift = (len(numer) - 1) - denom_deg
        coeff = numer[-1] * denom_lc_inv % mod
        q[shift] = coeff
        for i in range(len(denom)):
            numer[shift + i] = (numer[shift + i] - coeff * denom[i]) % mod
        poly_trim(numer)
    return poly_trim(q), poly_trim(numer)


def lagrange_interpolate(xs: Sequence[int], ys: Sequence[int], mod: int) -> List[int]:
    if len(xs) != len(ys):
        raise ValueError("xs and ys must have the same length")
    if len(xs) == 0:
        raise ValueError("need at least one point")

    xs = [x % mod for x in xs]
    ys = [y % mod for y in ys]

    out = [0]
    for j in range(len(xs)):
        numer = [1]
        denom = 1
        xj = xs[j]
        for m in range(len(xs)):
            if m == j:
                continue
            xm = xs[m]
            numer = poly_mul(numer, [(-xm) % mod, 1], mod)  # (x - xm)
            denom = (denom * ((xj - xm) % mod)) % mod
        scale = mod_div(ys[j], denom, mod)
        out = poly_add(out, poly_scale(numer, scale, mod), mod)
    return poly_trim(out)


def vanishing_poly(domain_xs: Sequence[int], mod: int) -> List[int]:
    out = [1]
    for x in domain_xs:
        out = poly_mul(out, [(-x) % mod, 1], mod)
    return poly_trim(out)


def dot(a: Sequence[int], b: Sequence[int], mod: int) -> int:
    if len(a) != len(b):
        raise ValueError("dot: length mismatch")
    return sum((ai * bi) % mod for ai, bi in zip(a, b)) % mod


@dataclass(frozen=True)
class R1CS:
    a: List[List[int]]
    b: List[List[int]]
    c: List[List[int]]
    num_public: int  # number of public variables excluding the constant 1
    var_names: List[str]

    @property
    def num_constraints(self) -> int:
        return len(self.a)

    @property
    def num_vars(self) -> int:
        return len(self.var_names)


def r1cs_is_satisfied(r1cs: R1CS, witness: Sequence[int], mod: int) -> bool:
    if len(witness) != r1cs.num_vars:
        raise ValueError("witness length mismatch")
    for row_a, row_b, row_c in zip(r1cs.a, r1cs.b, r1cs.c):
        left = dot(row_a, witness, mod)
        right = dot(row_b, witness, mod)
        out = dot(row_c, witness, mod)
        if (left * right - out) % mod != 0:
            return False
    return True


@dataclass(frozen=True)
class QAP:
    u_polys: List[List[int]]
    v_polys: List[List[int]]
    w_polys: List[List[int]]
    t_poly: List[int]
    domain: List[int]
    num_public: int
    var_names: List[str]

    @property
    def num_vars(self) -> int:
        return len(self.var_names)


def r1cs_to_qap(r1cs: R1CS, mod: int) -> QAP:
    n = r1cs.num_constraints
    domain = list(range(1, n + 1))  # [1,2,...,n]

    u_polys: List[List[int]] = []
    v_polys: List[List[int]] = []
    w_polys: List[List[int]] = []

    for var_i in range(r1cs.num_vars):
        u_values = [r1cs.a[j][var_i] % mod for j in range(n)]
        v_values = [r1cs.b[j][var_i] % mod for j in range(n)]
        w_values = [r1cs.c[j][var_i] % mod for j in range(n)]
        u_polys.append(lagrange_interpolate(domain, u_values, mod))
        v_polys.append(lagrange_interpolate(domain, v_values, mod))
        w_polys.append(lagrange_interpolate(domain, w_values, mod))

    t_poly = vanishing_poly(domain, mod)
    return QAP(
        u_polys=u_polys,
        v_polys=v_polys,
        w_polys=w_polys,
        t_poly=t_poly,
        domain=domain,
        num_public=r1cs.num_public,
        var_names=r1cs.var_names,
    )


def qap_instance_polynomials(qap: QAP, witness: Sequence[int], mod: int) -> dict:
    if len(witness) != qap.num_vars:
        raise ValueError("witness length mismatch")

    a_poly = [0]
    b_poly = [0]
    c_poly = [0]
    for wi, u_i, v_i, w_i in zip(witness, qap.u_polys, qap.v_polys, qap.w_polys):
        a_poly = poly_add(a_poly, poly_scale(u_i, wi, mod), mod)
        b_poly = poly_add(b_poly, poly_scale(v_i, wi, mod), mod)
        c_poly = poly_add(c_poly, poly_scale(w_i, wi, mod), mod)

    p_poly = poly_sub(poly_mul(a_poly, b_poly, mod), c_poly, mod)
    h_poly, rem = poly_divmod(p_poly, qap.t_poly, mod)
    return {
        "a_poly": a_poly,
        "b_poly": b_poly,
        "c_poly": c_poly,
        "p_poly": p_poly,
        "h_poly": h_poly,
        "remainder": rem,
    }


def derive_scalars(seed: bytes, mod: int, count: int) -> List[int]:
    out: List[int] = []
    for i in range(count):
        h = hashlib.sha256(seed + b":" + str(i).encode("ascii")).digest()
        v = int.from_bytes(h, "big") % mod
        if v == 0:
            v = 1
        out.append(v)
    return out


def find_subgroup_generator(p: int, q: int) -> int:
    for g in range(2, p - 1):
        if pow(g, q, p) == 1 and g % p != 1:
            return g
    raise ValueError("no subgroup generator found")


@dataclass(frozen=True)
class GroupParams:
    p: int
    q: int
    g: int

    def elt(self, exp: int) -> int:
        return pow(self.g, exp % self.q, self.p)


@dataclass(frozen=True)
class G1:
    params: GroupParams
    exp: int

    def __mul__(self, other: "G1") -> "G1":
        if self.params != other.params:
            raise ValueError("G1 params mismatch")
        return G1(self.params, (self.exp + other.exp) % self.params.q)

    def __pow__(self, scalar: int) -> "G1":
        return G1(self.params, (self.exp * (scalar % self.params.q)) % self.params.q)

    def value(self) -> int:
        return self.params.elt(self.exp)


@dataclass(frozen=True)
class G2:
    params: GroupParams
    exp: int

    def __mul__(self, other: "G2") -> "G2":
        if self.params != other.params:
            raise ValueError("G2 params mismatch")
        return G2(self.params, (self.exp + other.exp) % self.params.q)

    def __pow__(self, scalar: int) -> "G2":
        return G2(self.params, (self.exp * (scalar % self.params.q)) % self.params.q)

    def value(self) -> int:
        return self.params.elt(self.exp)


@dataclass(frozen=True)
class GT:
    params: GroupParams
    exp: int

    def __mul__(self, other: "GT") -> "GT":
        if self.params != other.params:
            raise ValueError("GT params mismatch")
        return GT(self.params, (self.exp + other.exp) % self.params.q)

    def value(self) -> int:
        return self.params.elt(self.exp)


def pairing(a: G1, b: G2) -> GT:
    if a.params != b.params:
        raise ValueError("pairing params mismatch")
    q = a.params.q
    return GT(a.params, (a.exp * b.exp) % q)


@dataclass(frozen=True)
class ProvingKey:
    params: GroupParams
    num_public: int
    alpha_g1: G1
    beta_g1: G1
    beta_g2: G2
    gamma_g2: G2
    delta_g1: G1
    delta_g2: G2
    u_tau_g1: List[G1]
    v_tau_g1: List[G1]
    v_tau_g2: List[G2]
    k_delta_g1: List[G1]  # for private vars only (i > num_public)
    t_tau_powers_over_delta_g1: List[G1]  # i=0..deg(t)-2: (tau^i * t(tau) / delta) in G1


@dataclass(frozen=True)
class VerifyingKey:
    params: GroupParams
    num_public: int
    alpha_g1: G1
    beta_g2: G2
    gamma_g2: G2
    delta_g2: G2
    ic_g1: List[G1]  # length = num_public + 1 (includes the constant "1" slot)


@dataclass(frozen=True)
class Proof:
    a_g1: G1
    b_g2: G2
    c_g1: G1


def groth16_setup_toy(qap: QAP, alpha: int, beta: int, gamma: int, delta: int, tau: int, mod: int) -> Tuple[ProvingKey, VerifyingKey]:
    if gamma % mod == 0:
        raise ValueError("gamma must be non-zero")
    if delta % mod == 0:
        raise ValueError("delta must be non-zero")

    g = find_subgroup_generator(GROUP_MODULUS, SCALAR_FIELD_MODULUS)
    params = GroupParams(p=GROUP_MODULUS, q=SCALAR_FIELD_MODULUS, g=g)

    def g1(exp: int) -> G1:
        return G1(params, exp % params.q)

    def g2(exp: int) -> G2:
        return G2(params, exp % params.q)

    alpha %= mod
    beta %= mod
    gamma %= mod
    delta %= mod
    tau %= mod

    u_tau = [poly_eval(u, tau, mod) for u in qap.u_polys]
    v_tau = [poly_eval(v, tau, mod) for v in qap.v_polys]
    w_tau = [poly_eval(w, tau, mod) for w in qap.w_polys]
    t_tau = poly_eval(qap.t_poly, tau, mod)

    alpha_g1 = g1(alpha)
    beta_g1 = g1(beta)
    beta_g2 = g2(beta)
    gamma_g2 = g2(gamma)
    delta_g1 = g1(delta)
    delta_g2 = g2(delta)

    u_tau_g1 = [g1(v) for v in u_tau]
    v_tau_g1 = [g1(v) for v in v_tau]
    v_tau_g2 = [g2(v) for v in v_tau]

    ic_g1: List[G1] = []
    for i in range(qap.num_public + 1):  # includes i=0 (constant 1)
        term = (beta * u_tau[i] + alpha * v_tau[i] + w_tau[i]) % mod
        ic_g1.append(g1(mod_div(term, gamma, mod)))

    k_delta_g1: List[G1] = []
    for i in range(qap.num_public + 1, qap.num_vars):
        term = (beta * u_tau[i] + alpha * v_tau[i] + w_tau[i]) % mod
        k_delta_g1.append(g1(mod_div(term, delta, mod)))

    deg_t = len(qap.t_poly) - 1
    t_tau_powers_over_delta_g1: List[G1] = []
    for i in range(max(0, deg_t - 1)):  # 0..deg(t)-2
        tau_i = pow(tau, i, mod)
        t_tau_powers_over_delta_g1.append(g1(mod_div(t_tau * tau_i, delta, mod)))

    pk = ProvingKey(
        params=params,
        num_public=qap.num_public,
        alpha_g1=alpha_g1,
        beta_g1=beta_g1,
        beta_g2=beta_g2,
        gamma_g2=gamma_g2,
        delta_g1=delta_g1,
        delta_g2=delta_g2,
        u_tau_g1=u_tau_g1,
        v_tau_g1=v_tau_g1,
        v_tau_g2=v_tau_g2,
        k_delta_g1=k_delta_g1,
        t_tau_powers_over_delta_g1=t_tau_powers_over_delta_g1,
    )
    vk = VerifyingKey(
        params=params,
        num_public=qap.num_public,
        alpha_g1=alpha_g1,
        beta_g2=beta_g2,
        gamma_g2=gamma_g2,
        delta_g2=delta_g2,
        ic_g1=ic_g1,
    )
    return pk, vk


def groth16_prove_toy(qap: QAP, pk: ProvingKey, witness: Sequence[int], r: int, s: int, alpha: int, beta: int, delta: int, tau: int, mod: int) -> Proof:
    if len(witness) != qap.num_vars:
        raise ValueError("witness length mismatch")
    if witness[0] % mod != 1:
        raise ValueError("witness[0] must be 1 (the constant slot)")

    u_tau = [poly_eval(u, tau, mod) for u in qap.u_polys]
    v_tau = [poly_eval(v, tau, mod) for v in qap.v_polys]
    w_tau = [poly_eval(w, tau, mod) for w in qap.w_polys]
    t_tau = poly_eval(qap.t_poly, tau, mod)

    a_scalar = (alpha + sum((wi * ui) % mod for wi, ui in zip(witness, u_tau)) + (r % mod) * delta) % mod
    b_scalar = (beta + sum((wi * vi) % mod for wi, vi in zip(witness, v_tau)) + (s % mod) * delta) % mod

    inst = qap_instance_polynomials(qap, witness, mod)
    if inst["remainder"] != [0]:
        raise ValueError("witness does not satisfy QAP divisibility")
    h_tau = poly_eval(inst["h_poly"], tau, mod)

    private_sum = 0
    for i in range(qap.num_public + 1, qap.num_vars):
        private_sum = (private_sum + witness[i] * ((beta * u_tau[i] + alpha * v_tau[i] + w_tau[i]) % mod)) % mod

    c_scalar = (
        mod_div(private_sum + (h_tau * t_tau) % mod, delta, mod)
        + (a_scalar * (s % mod)) % mod
        + (b_scalar * (r % mod)) % mod
        - ((r % mod) * (s % mod) % mod) * delta
    ) % mod

    return Proof(
        a_g1=G1(pk.params, a_scalar),
        b_g2=G2(pk.params, b_scalar),
        c_g1=G1(pk.params, c_scalar),
    )


def groth16_verify_toy(vk: VerifyingKey, public_inputs: Sequence[int], proof: Proof, mod: int) -> bool:
    if len(public_inputs) != vk.num_public:
        raise ValueError("public input length mismatch")

    # vk_x = IC[0] + sum_i input[i-1] * IC[i]
    vk_x = vk.ic_g1[0]
    for i, inp in enumerate(public_inputs, start=1):
        vk_x = vk_x * (vk.ic_g1[i] ** (inp % mod))

    left = pairing(proof.a_g1, proof.b_g2)
    right = pairing(vk.alpha_g1, vk.beta_g2) * pairing(vk_x, vk.gamma_g2) * pairing(proof.c_g1, vk.delta_g2)
    return left.exp % vk.params.q == right.exp % vk.params.q


def build_square_r1cs(mod: int) -> R1CS:
    # witness = [1, y, x, v] where v = x*x and y = v
    var_names = ["one", "y", "x", "v"]

    a = [
        [0, 0, 1, 0],  # x
        [0, 0, 0, 1],  # v
    ]
    b = [
        [0, 0, 1, 0],  # x
        [1, 0, 0, 0],  # 1
    ]
    c = [
        [0, 0, 0, 1],  # v
        [0, 1, 0, 0],  # y
    ]

    def norm_mat(m: List[List[int]]) -> List[List[int]]:
        return [[v % mod for v in row] for row in m]

    return R1CS(a=norm_mat(a), b=norm_mat(b), c=norm_mat(c), num_public=1, var_names=var_names)


def witness_for_square(x: int, mod: int) -> List[int]:
    x %= mod
    v = (x * x) % mod
    y = v
    return [1, y, x, v]


def as_jsonable_proof(proof: Proof) -> dict:
    return {"A_exp": proof.a_g1.exp, "B_exp": proof.b_g2.exp, "C_exp": proof.c_g1.exp}


def main() -> None:
    mod = SCALAR_FIELD_MODULUS

    print("=== Step 1: Toy field + polynomials ===")
    poly = [1, 2, 3]
    x = 5
    print(f"poly_eval({poly}, x={x}) mod {mod} -> {poly_eval(poly, x, mod)}")
    xs = [1, 2]
    ys = [3, 5]
    interp = lagrange_interpolate(xs, ys, mod)
    print(f"lagrange_interpolate(xs={xs}, ys={ys}) -> {interp}")

    print("\n=== Step 2: R1CS for y = x^2 ===")
    r1cs = build_square_r1cs(mod)
    witness = witness_for_square(x=11, mod=mod)
    print("witness:", dict(zip(r1cs.var_names, witness)))
    print("r1cs_is_satisfied:", r1cs_is_satisfied(r1cs, witness, mod))

    print("\n=== Step 3: QAP and divisibility check ===")
    qap = r1cs_to_qap(r1cs, mod)
    inst = qap_instance_polynomials(qap, witness, mod)
    print("t(x):", qap.t_poly)
    print("remainder of (A*B - C) / t:", inst["remainder"])
    print("h(x):", inst["h_poly"])

    print("\n=== Step 4: Toy Groth16 (setup / prove / verify) ===")
    seed = b"toy-groth16-demo"
    alpha, beta, gamma, delta, tau, r, s = derive_scalars(seed, mod, 7)
    pk, vk = groth16_setup_toy(qap, alpha=alpha, beta=beta, gamma=gamma, delta=delta, tau=tau, mod=mod)

    proof = groth16_prove_toy(
        qap=qap,
        pk=pk,
        witness=witness,
        r=r,
        s=s,
        alpha=alpha,
        beta=beta,
        delta=delta,
        tau=tau,
        mod=mod,
    )
    public_inputs = [witness[1]]  # y
    ok = groth16_verify_toy(vk, public_inputs, proof, mod)
    print("proof:", as_jsonable_proof(proof))
    print("verify(public y):", ok)

    bad_witness = witness_for_square(x=12, mod=mod)
    bad_public_inputs = [public_inputs[0]]
    bad_proof = groth16_prove_toy(
        qap=qap,
        pk=pk,
        witness=bad_witness,
        r=r,
        s=s,
        alpha=alpha,
        beta=beta,
        delta=delta,
        tau=tau,
        mod=mod,
    )
    ok_bad = groth16_verify_toy(vk, bad_public_inputs, bad_proof, mod)
    print("verify(wrong witness x but same public y):", ok_bad)

    # Write deterministic vectors if run from the lesson directory (optional convenience).
    if os.environ.get("WRITE_VECTORS") == "1":
        vectors_path = os.path.join(os.path.dirname(__file__), "..", "tests", "vectors.json")
        vectors = {
            "source": "Generated deterministically by phases/12-zk-proof-systems/05-groth16/code/main.py with seed='toy-groth16-demo', mod=509.",
            "vectors": [
                {"op": "poly_eval", "inputs": {"poly": [1, 2, 3], "x": 5, "mod": 509}, "expected": 86},
                {"op": "lagrange_interpolate", "inputs": {"xs": [1, 2], "ys": [3, 5], "mod": 509}, "expected": [1, 2]},
                {"op": "r1cs_is_satisfied", "inputs": {"x": 11}, "expected": True},
                {"op": "qap_remainder_is_zero", "inputs": {"x": 11}, "expected": True},
                {
                    "op": "groth16_verify",
                    "inputs": {"x": 11, "seed": "toy-groth16-demo"},
                    "expected": {"ok": True, "proof": as_jsonable_proof(proof), "public": public_inputs},
                },
            ],
        }
        with open(vectors_path, "w", encoding="utf-8") as f:
            json.dump(vectors, f, indent=2, sort_keys=True)
            f.write("\n")
        print(f"\nWrote vectors to {vectors_path}")


if __name__ == "__main__":
    main()
