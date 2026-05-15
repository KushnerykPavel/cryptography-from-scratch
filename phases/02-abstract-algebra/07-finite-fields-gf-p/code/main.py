from __future__ import annotations

from dataclasses import dataclass
from math import isqrt
from typing import Iterable


def is_prime(n: int) -> bool:
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    for d in range(3, isqrt(n) + 1, 2):
        if n % d == 0:
            return False
    return True


def require_prime(p: int) -> None:
    if not is_prime(p):
        raise ValueError("p must be prime")


def egcd(a: int, b: int) -> tuple[int, int, int]:
    old_r, r = abs(a), abs(b)
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t

    if a < 0:
        old_s = -old_s
    if b < 0:
        old_t = -old_t

    return old_r, old_s, old_t


def mod_inverse(a: int, p: int) -> int:
    require_prime(p)
    a %= p
    if a == 0:
        raise ValueError("zero has no multiplicative inverse")

    g, x, _ = egcd(a, p)
    if g != 1:
        raise ValueError("element is not invertible")
    return x % p


def fp_add(a: int, b: int, p: int) -> int:
    require_prime(p)
    return (a + b) % p


def fp_sub(a: int, b: int, p: int) -> int:
    require_prime(p)
    return (a - b) % p


def fp_neg(a: int, p: int) -> int:
    require_prime(p)
    return (-a) % p


def fp_mul(a: int, b: int, p: int) -> int:
    require_prime(p)
    return (a * b) % p


def fp_div(a: int, b: int, p: int) -> int:
    require_prime(p)
    return (a * mod_inverse(b, p)) % p


def fp_pow(a: int, exponent: int, p: int) -> int:
    require_prime(p)
    if exponent < 0:
        return pow(mod_inverse(a, p), -exponent, p)
    return pow(a % p, exponent, p)


@dataclass(frozen=True)
class Fp:
    value: int
    p: int

    def __post_init__(self) -> None:
        require_prime(self.p)
        object.__setattr__(self, "value", self.value % self.p)

    def _coerce(self, other: int | Fp) -> Fp:
        if isinstance(other, Fp):
            if other.p != self.p:
                raise ValueError("cannot mix different prime fields")
            return other
        return Fp(other, self.p)

    def __add__(self, other: int | Fp) -> Fp:
        other = self._coerce(other)
        return Fp(self.value + other.value, self.p)

    def __radd__(self, other: int | Fp) -> Fp:
        return self + other

    def __sub__(self, other: int | Fp) -> Fp:
        other = self._coerce(other)
        return Fp(self.value - other.value, self.p)

    def __rsub__(self, other: int | Fp) -> Fp:
        return self._coerce(other) - self

    def __neg__(self) -> Fp:
        return Fp(-self.value, self.p)

    def __mul__(self, other: int | Fp) -> Fp:
        other = self._coerce(other)
        return Fp(self.value * other.value, self.p)

    def __rmul__(self, other: int | Fp) -> Fp:
        return self * other

    def inverse(self) -> Fp:
        return Fp(mod_inverse(self.value, self.p), self.p)

    def __truediv__(self, other: int | Fp) -> Fp:
        other = self._coerce(other)
        return self * other.inverse()

    def __rtruediv__(self, other: int | Fp) -> Fp:
        return self._coerce(other) / self

    def __pow__(self, exponent: int) -> Fp:
        return Fp(fp_pow(self.value, exponent, self.p), self.p)

    def __int__(self) -> int:
        return self.value

    def __repr__(self) -> str:
        return f"Fp({self.value}, p={self.p})"


def field(p: int) -> list[Fp]:
    require_prime(p)
    return [Fp(x, p) for x in range(p)]


def addition_table(p: int) -> list[list[int]]:
    require_prime(p)
    return [[fp_add(a, b, p) for b in range(p)] for a in range(p)]


def multiplication_table(p: int) -> list[list[int]]:
    require_prime(p)
    return [[fp_mul(a, b, p) for b in range(p)] for a in range(p)]


def inverses(p: int) -> dict[int, int]:
    require_prime(p)
    return {a: mod_inverse(a, p) for a in range(1, p)}


def multiplicative_order(a: int, p: int) -> int:
    require_prime(p)
    a %= p
    if a == 0:
        raise ValueError("zero has no multiplicative order")

    x = 1
    for k in range(1, p):
        x = (x * a) % p
        if x == 1:
            return k

    raise ValueError("order search failed")


def is_generator(a: int, p: int) -> bool:
    require_prime(p)
    return a % p != 0 and multiplicative_order(a, p) == p - 1


def generators(p: int) -> list[int]:
    require_prime(p)
    return [a for a in range(1, p) if is_generator(a, p)]


def poly_eval(coefficients: Iterable[int], x: int, p: int) -> int:
    require_prime(p)
    result = 0
    for coefficient in reversed(list(coefficients)):
        result = (result * x + coefficient) % p
    return result


def lagrange_interpolate_at(
    points: Iterable[tuple[int, int]],
    x: int,
    p: int,
) -> int:
    require_prime(p)
    pts = [(px % p, py % p) for px, py in points]
    xs = [px for px, _ in pts]
    if len(set(xs)) != len(xs):
        raise ValueError("x coordinates must be distinct")

    total = 0
    for i, (xi, yi) in enumerate(pts):
        numerator = 1
        denominator = 1
        for j, (xj, _) in enumerate(pts):
            if i == j:
                continue
            numerator = (numerator * (x - xj)) % p
            denominator = (denominator * (xi - xj)) % p
        total = (total + yi * numerator * mod_inverse(denominator, p)) % p

    return total


def field_report(p: int) -> dict[str, object]:
    require_prime(p)
    return {
        "p": p,
        "order": p,
        "characteristic": p,
        "zero": 0,
        "one": 1,
        "nonzero_elements": list(range(1, p)),
        "inverses": inverses(p),
        "generators": generators(p),
    }


def main() -> None:
    p = 17
    a = Fp(29, p)
    b = Fp(5, p)
    points = [(1, 9), (2, 15), (3, 8)]

    print("field:", f"GF({p})")
    print("a:", a)
    print("b:", b)
    print("a + b:", a + b)
    print("a * b:", a * b)
    print("a / b:", a / b)
    print("b^-1:", b.inverse())
    print("3^k order:", multiplicative_order(3, p))
    print("generators:", generators(p))
    print("interpolate at x=0:", lagrange_interpolate_at(points, 0, p))


if __name__ == "__main__":
    main()
