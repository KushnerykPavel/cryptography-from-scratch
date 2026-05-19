"""
Toy KZG (Kate) polynomial commitments, end-to-end:

- Commit to a polynomial f(x) with a constant-size commitment C
- Open at a point z with a constant-size proof pi
- Verify the opening with a toy bilinear pairing

This is an educational implementation using a tiny prime field and a "pairing"
that works by tracking exponents. It is not constant-time and not production-safe.

Run:
  python3 code/main.py
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Sequence, Tuple


def mod_norm(x: int, mod: int) -> int:
    if mod <= 1:
        raise ValueError("mod must be > 1")
    return x % mod


def mod_inv(x: int, mod: int) -> int:
    x = mod_norm(x, mod)
    if x == 0:
        raise ZeroDivisionError("division by zero in field")
    return pow(x, -1, mod)


def poly_trim(coeffs: Sequence[int]) -> List[int]:
    out = list(coeffs)
    while len(out) > 0 and out[-1] == 0:
        out.pop()
    return out


def poly_eval(coeffs: Sequence[int], x: int, mod: int) -> int:
    x = mod_norm(x, mod)
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + (c % mod)) % mod
    return acc


def poly_divmod_x_minus_z(coeffs: Sequence[int], z: int, mod: int) -> Tuple[List[int], int]:
    z = mod_norm(z, mod)
    if len(coeffs) == 0:
        raise ValueError("polynomial must be non-empty")

    desc = [c % mod for c in reversed(coeffs)]  # a_n .. a_0
    b: List[int] = [desc[0]]
    for i in range(1, len(desc)):
        b.append((desc[i] + z * b[i - 1]) % mod)

    remainder = b[-1]
    quotient = list(reversed(b[:-1]))
    return poly_trim(quotient), remainder


@dataclass(frozen=True)
class ToyBilinearGroup:
    q: int
    p: int
    g: int

    def __post_init__(self) -> None:
        if self.q <= 2:
            raise ValueError("q must be > 2")
        if self.p <= 2:
            raise ValueError("p must be > 2")
        if not (2 <= self.g < self.p):
            raise ValueError("g must be in [2, p-1]")

        if pow(self.g, self.q, self.p) != 1:
            raise ValueError("g must have order q in Z_p*")

    def elem(self, scalar: int) -> ToyElement:
        return ToyElement(self, scalar)

    def zero(self) -> ToyElement:
        return ToyElement(self, 0)

    def gen(self) -> ToyElement:
        return ToyElement(self, 1)

    def pair(self, a: ToyElement, b: ToyElement) -> ToyElement:
        if a.group is not self or b.group is not self:
            raise TypeError("pairing requires elements from this group")
        return ToyElement(self, (a.scalar * b.scalar) % self.q)


@dataclass(frozen=True)
class ToyElement:
    group: ToyBilinearGroup
    scalar: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "scalar", self.scalar % self.group.q)

    def __add__(self, other: ToyElement) -> ToyElement:
        if other.group is not self.group:
            raise TypeError("cannot add elements from different groups")
        return ToyElement(self.group, self.scalar + other.scalar)

    def __sub__(self, other: ToyElement) -> ToyElement:
        if other.group is not self.group:
            raise TypeError("cannot subtract elements from different groups")
        return ToyElement(self.group, self.scalar - other.scalar)

    def __neg__(self) -> ToyElement:
        return ToyElement(self.group, -self.scalar)

    def __mul__(self, k: int) -> ToyElement:
        if not isinstance(k, int):
            raise TypeError("can only scalar-multiply by int")
        return ToyElement(self.group, self.scalar * k)

    def __rmul__(self, k: int) -> ToyElement:
        return self.__mul__(k)

    def int_value(self) -> int:
        return pow(self.group.g, self.scalar, self.group.p)


@dataclass(frozen=True)
class KZGParams:
    group: ToyBilinearGroup
    max_degree: int
    g1_powers: Tuple[ToyElement, ...]  # [s^i] in G1 for i=0..max_degree
    g2: ToyElement  # [1] in G2
    g2_s: ToyElement  # [s] in G2


def toy_group_for_demo() -> ToyBilinearGroup:
    q = 1019
    p = 2039
    g = 4
    return ToyBilinearGroup(q=q, p=p, g=g)


def kzg_setup(max_degree: int, *, group: ToyBilinearGroup | None = None, s: int) -> KZGParams:
    if max_degree < 0:
        raise ValueError("max_degree must be >= 0")
    if group is None:
        group = toy_group_for_demo()

    s = mod_norm(s, group.q)
    if s == 0:
        raise ValueError("s must be non-zero in the field")

    powers: List[ToyElement] = []
    cur = 1
    for _ in range(max_degree + 1):
        powers.append(group.elem(cur))
        cur = (cur * s) % group.q

    g2 = group.gen()
    g2_s = s * g2
    return KZGParams(
        group=group,
        max_degree=max_degree,
        g1_powers=tuple(powers),
        g2=g2,
        g2_s=g2_s,
    )


def kzg_commit(params: KZGParams, coeffs: Sequence[int]) -> ToyElement:
    poly = [c % params.group.q for c in coeffs]
    if len(poly) == 0:
        raise ValueError("polynomial must be non-empty")
    if len(poly) - 1 > params.max_degree:
        raise ValueError("polynomial degree exceeds SRS max_degree")

    acc = params.group.zero()
    for i, c in enumerate(poly):
        acc = acc + (c * params.g1_powers[i])
    return acc


def kzg_open(params: KZGParams, coeffs: Sequence[int], z: int) -> Tuple[int, ToyElement]:
    poly = [c % params.group.q for c in coeffs]
    if len(poly) == 0:
        raise ValueError("polynomial must be non-empty")
    if len(poly) - 1 > params.max_degree:
        raise ValueError("polynomial degree exceeds SRS max_degree")

    z = mod_norm(z, params.group.q)
    y = poly_eval(poly, z, params.group.q)
    quotient, remainder = poly_divmod_x_minus_z(poly, z, params.group.q)
    if remainder != y:
        raise AssertionError("internal error: remainder theorem mismatch")
    pi = kzg_commit(params, quotient if len(quotient) > 0 else [0])
    return y, pi


def kzg_verify(params: KZGParams, commitment: ToyElement, z: int, y: int, proof: ToyElement) -> bool:
    if commitment.group is not params.group or proof.group is not params.group:
        raise TypeError("commitment/proof must be in params.group")

    z = mod_norm(z, params.group.q)
    y = mod_norm(y, params.group.q)

    left = params.group.pair(commitment - (y * params.group.gen()), params.g2)
    right = params.group.pair(proof, params.g2_s - (z * params.g2))
    return left == right


def _step(title: str) -> None:
    print(f"=== {title} ===")


def _poly_str(coeffs: Sequence[int]) -> str:
    terms: List[str] = []
    for i, c in enumerate(coeffs):
        c = int(c)
        if c == 0:
            continue
        if i == 0:
            terms.append(str(c))
        elif i == 1:
            terms.append(f"{c}·x")
        else:
            terms.append(f"{c}·x^{i}")
    return " + ".join(terms) if terms else "0"


def main() -> None:
    group = toy_group_for_demo()
    q = group.q

    _step("Step 1: Finite-field polynomials (eval in F_q)")
    f = [3, 5, 7, 11]  # f(x) = 3 + 5x + 7x^2 + 11x^3  in F_q
    x = 9
    y = poly_eval(f, x, q)
    print(f"q={q}")
    print(f"f(x) = {_poly_str(f)}")
    print(f"f({x}) = {y}")
    print()

    _step("Step 2: Divide by (x - z) via synthetic division")
    z = 9
    quotient, remainder = poly_divmod_x_minus_z(f, z, q)
    print(f"divide f(x) by (x - {z}) over F_q")
    print(f"quotient(x) = {_poly_str(quotient)}")
    print(f"remainder = {remainder} (should equal f({z}))")
    print()

    _step("Step 3: Toy bilinear group elements (track scalars, show g^scalar mod p)")
    print(f"p={group.p} (safe prime), subgroup order q={group.q}, generator g={group.g}")
    a = group.elem(123)
    b = group.elem(77)
    e_ab = group.pair(a, b)
    print(f"[a] scalar=123 value={a.int_value()}")
    print(f"[b] scalar=77  value={b.int_value()}")
    print(f"pair([a],[b]) has scalar=123*77 mod q = {e_ab.scalar}, value={e_ab.int_value()}")
    print()

    _step("Step 4: KZG commit/open/verify at one point")
    params = kzg_setup(max_degree=8, group=group, s=17)
    C = kzg_commit(params, f)
    y_open, pi = kzg_open(params, f, z=9)
    ok = kzg_verify(params, C, z=9, y=y_open, proof=pi)
    print(f"srs.max_degree={params.max_degree}, s (toxic waste) destroyed after setup")
    print(f"commitment C: scalar={C.scalar} value={C.int_value()}")
    print(f"open at z=9 gives y={y_open} and proof pi: scalar={pi.scalar} value={pi.int_value()}")
    print(f"verify(C, z=9, y, pi) = {ok}")
    print()

    print("-- tampering --")
    ok_wrong_y = kzg_verify(params, C, z=9, y=(y_open + 1) % q, proof=pi)
    ok_wrong_pi = kzg_verify(params, C, z=9, y=y_open, proof=(pi + params.group.gen()))
    ok_wrong_z = kzg_verify(params, C, z=10, y=y_open, proof=pi)
    print(f"verify(wrong y)  = {ok_wrong_y}")
    print(f"verify(wrong pi) = {ok_wrong_pi}")
    print(f"verify(wrong z)  = {ok_wrong_z}")


if __name__ == "__main__":
    main()
