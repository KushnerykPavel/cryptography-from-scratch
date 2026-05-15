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


def mod_inverse(a: int, p: int) -> int:
    require_prime(p)
    a %= p
    if a == 0:
        raise ValueError("zero has no multiplicative inverse")
    return pow(a, p - 2, p)


def normalize(coefficients: Iterable[int], p: int) -> list[int]:
    require_prime(p)
    result = [c % p for c in coefficients]
    while len(result) > 1 and result[-1] == 0:
        result.pop()
    return result or [0]


def require_nonzero_poly(coefficients: Iterable[int], p: int) -> list[int]:
    poly = normalize(coefficients, p)
    if poly == [0]:
        raise ValueError("zero polynomial is not allowed")
    return poly


def poly_degree(coefficients: Iterable[int], p: int) -> int:
    poly = normalize(coefficients, p)
    if poly == [0]:
        return -1
    return len(poly) - 1


def poly_to_string(coefficients: Iterable[int], p: int, variable: str = "x") -> str:
    poly = normalize(coefficients, p)
    if poly == [0]:
        return "0"

    terms: list[str] = []
    for power in range(len(poly) - 1, -1, -1):
        coefficient = poly[power]
        if coefficient == 0:
            continue
        if power == 0:
            terms.append(str(coefficient))
        elif power == 1:
            term = variable if coefficient == 1 else f"{coefficient}{variable}"
            terms.append(term)
        else:
            if coefficient == 1:
                term = f"{variable}^{power}"
            else:
                term = f"{coefficient}{variable}^{power}"
            terms.append(term)
    return " + ".join(terms)


def poly_add(a: Iterable[int], b: Iterable[int], p: int) -> list[int]:
    left = normalize(a, p)
    right = normalize(b, p)
    length = max(len(left), len(right))
    result = (
        (left[i] if i < len(left) else 0)
        + (right[i] if i < len(right) else 0)
        for i in range(length)
    )
    return normalize(result, p)


def poly_neg(a: Iterable[int], p: int) -> list[int]:
    return normalize((-c for c in normalize(a, p)), p)


def poly_sub(a: Iterable[int], b: Iterable[int], p: int) -> list[int]:
    return poly_add(a, poly_neg(b, p), p)


def poly_scale(a: Iterable[int], scalar: int, p: int) -> list[int]:
    return normalize((scalar * c for c in normalize(a, p)), p)


def poly_mul(a: Iterable[int], b: Iterable[int], p: int) -> list[int]:
    left = normalize(a, p)
    right = normalize(b, p)
    if left == [0] or right == [0]:
        return [0]

    result = [0] * (len(left) + len(right) - 1)
    for i, ac in enumerate(left):
        for j, bc in enumerate(right):
            result[i + j] = (result[i + j] + ac * bc) % p
    return normalize(result, p)


def poly_divmod(
    dividend: Iterable[int],
    divisor: Iterable[int],
    p: int,
) -> tuple[list[int], list[int]]:
    remainder = normalize(dividend, p)
    divisor_poly = require_nonzero_poly(divisor, p)
    if poly_degree(remainder, p) < poly_degree(divisor_poly, p):
        return [0], remainder

    quotient = [0] * (len(remainder) - len(divisor_poly) + 1)
    divisor_degree = len(divisor_poly) - 1
    divisor_lead_inv = mod_inverse(divisor_poly[-1], p)

    while remainder != [0] and len(remainder) - 1 >= divisor_degree:
        shift = len(remainder) - len(divisor_poly)
        factor = (remainder[-1] * divisor_lead_inv) % p
        quotient[shift] = factor
        subtractor = [0] * shift + [(factor * c) % p for c in divisor_poly]
        remainder = poly_sub(remainder, subtractor, p)

    return normalize(quotient, p), remainder


def poly_mod(poly: Iterable[int], modulus: Iterable[int], p: int) -> list[int]:
    return poly_divmod(poly, modulus, p)[1]


def poly_monic(poly: Iterable[int], p: int) -> list[int]:
    normalized = require_nonzero_poly(poly, p)
    return poly_scale(normalized, mod_inverse(normalized[-1], p), p)


def poly_gcd(a: Iterable[int], b: Iterable[int], p: int) -> list[int]:
    left = normalize(a, p)
    right = normalize(b, p)
    while right != [0]:
        left, right = right, poly_mod(left, right, p)
    if left == [0]:
        return [0]
    return poly_monic(left, p)


def poly_extended_gcd(
    a: Iterable[int],
    b: Iterable[int],
    p: int,
) -> tuple[list[int], list[int], list[int]]:
    old_r, r = normalize(a, p), normalize(b, p)
    old_s, s = [1], [0]
    old_t, t = [0], [1]

    while r != [0]:
        q, new_r = poly_divmod(old_r, r, p)
        old_r, r = r, new_r
        old_s, s = s, poly_sub(old_s, poly_mul(q, s, p), p)
        old_t, t = t, poly_sub(old_t, poly_mul(q, t, p), p)

    if old_r == [0]:
        return [0], [0], [0]

    lead_inv = mod_inverse(old_r[-1], p)
    return (
        poly_scale(old_r, lead_inv, p),
        poly_scale(old_s, lead_inv, p),
        poly_scale(old_t, lead_inv, p),
    )


def poly_eval(coefficients: Iterable[int], x: int, p: int) -> int:
    result = 0
    for coefficient in reversed(normalize(coefficients, p)):
        result = (result * x + coefficient) % p
    return result


def quotient_add(
    a: Iterable[int],
    b: Iterable[int],
    modulus: Iterable[int],
    p: int,
) -> list[int]:
    return poly_mod(poly_add(a, b, p), modulus, p)


def quotient_sub(
    a: Iterable[int],
    b: Iterable[int],
    modulus: Iterable[int],
    p: int,
) -> list[int]:
    return poly_mod(poly_sub(a, b, p), modulus, p)


def quotient_mul(
    a: Iterable[int],
    b: Iterable[int],
    modulus: Iterable[int],
    p: int,
) -> list[int]:
    return poly_mod(poly_mul(a, b, p), modulus, p)


def quotient_pow(
    a: Iterable[int],
    exponent: int,
    modulus: Iterable[int],
    p: int,
) -> list[int]:
    if exponent < 0:
        return quotient_pow(quotient_inverse(a, modulus, p), -exponent, modulus, p)

    base = poly_mod(a, modulus, p)
    result = [1]
    while exponent:
        if exponent & 1:
            result = quotient_mul(result, base, modulus, p)
        base = quotient_mul(base, base, modulus, p)
        exponent >>= 1
    return result


def quotient_inverse(
    a: Iterable[int],
    modulus: Iterable[int],
    p: int,
) -> list[int]:
    value = poly_mod(a, modulus, p)
    if value == [0]:
        raise ValueError("zero has no multiplicative inverse")

    gcd, x, _ = poly_extended_gcd(value, modulus, p)
    if gcd != [1]:
        raise ValueError("element is not invertible with this modulus")
    return poly_mod(x, modulus, p)


def quotient_div(
    a: Iterable[int],
    b: Iterable[int],
    modulus: Iterable[int],
    p: int,
) -> list[int]:
    return quotient_mul(a, quotient_inverse(b, modulus, p), modulus, p)


def polynomials_below_degree(degree: int, p: int) -> list[list[int]]:
    require_prime(p)
    if degree < 0:
        raise ValueError("degree must be nonnegative")

    values: list[list[int]] = []
    for n in range(p**degree):
        coefficients: list[int] = []
        current = n
        for _ in range(degree):
            coefficients.append(current % p)
            current //= p
        values.append(normalize(coefficients, p))
    return values


def zero_divisor_pair(
    modulus: Iterable[int],
    p: int,
) -> tuple[list[int], list[int]] | None:
    modulus_poly = require_nonzero_poly(modulus, p)
    degree = len(modulus_poly) - 1
    elements = [poly for poly in polynomials_below_degree(degree, p) if poly != [0]]

    for a in elements:
        for b in elements:
            if quotient_mul(a, b, modulus_poly, p) == [0]:
                return a, b
    return None


@dataclass(frozen=True)
class Poly:
    coefficients: tuple[int, ...]
    p: int

    def __init__(self, coefficients: Iterable[int], p: int) -> None:
        object.__setattr__(self, "p", p)
        object.__setattr__(self, "coefficients", tuple(normalize(coefficients, p)))

    @property
    def degree(self) -> int:
        return poly_degree(self.coefficients, self.p)

    def _coerce(self, other: Iterable[int] | Poly) -> Poly:
        if isinstance(other, Poly):
            if other.p != self.p:
                raise ValueError("cannot mix polynomials over different fields")
            return other
        return Poly(other, self.p)

    def __add__(self, other: Iterable[int] | Poly) -> Poly:
        other = self._coerce(other)
        return Poly(poly_add(self.coefficients, other.coefficients, self.p), self.p)

    def __radd__(self, other: Iterable[int] | Poly) -> Poly:
        return self + other

    def __neg__(self) -> Poly:
        return Poly(poly_neg(self.coefficients, self.p), self.p)

    def __sub__(self, other: Iterable[int] | Poly) -> Poly:
        other = self._coerce(other)
        return Poly(poly_sub(self.coefficients, other.coefficients, self.p), self.p)

    def __rsub__(self, other: Iterable[int] | Poly) -> Poly:
        return self._coerce(other) - self

    def __mul__(self, other: Iterable[int] | Poly) -> Poly:
        other = self._coerce(other)
        return Poly(poly_mul(self.coefficients, other.coefficients, self.p), self.p)

    def __rmul__(self, other: Iterable[int] | Poly) -> Poly:
        return self * other

    def divmod(self, other: Iterable[int] | Poly) -> tuple[Poly, Poly]:
        other = self._coerce(other)
        q, r = poly_divmod(self.coefficients, other.coefficients, self.p)
        return Poly(q, self.p), Poly(r, self.p)

    def __mod__(self, other: Iterable[int] | Poly) -> Poly:
        return self.divmod(other)[1]

    def __call__(self, x: int) -> int:
        return poly_eval(self.coefficients, x, self.p)

    def __repr__(self) -> str:
        return f"Poly({list(self.coefficients)}, p={self.p})"

    def __str__(self) -> str:
        return poly_to_string(self.coefficients, self.p)


@dataclass(frozen=True)
class PolyMod:
    value: tuple[int, ...]
    modulus: tuple[int, ...]
    p: int

    def __init__(
        self,
        value: Iterable[int],
        modulus: Iterable[int],
        p: int,
    ) -> None:
        modulus_poly = require_nonzero_poly(modulus, p)
        if len(modulus_poly) < 2:
            raise ValueError("modulus polynomial must have positive degree")
        object.__setattr__(self, "p", p)
        object.__setattr__(self, "modulus", tuple(poly_monic(modulus_poly, p)))
        object.__setattr__(self, "value", tuple(poly_mod(value, self.modulus, p)))

    def _coerce(self, other: Iterable[int] | PolyMod) -> PolyMod:
        if isinstance(other, PolyMod):
            if other.p != self.p or other.modulus != self.modulus:
                raise ValueError("cannot mix different quotient rings")
            return other
        return PolyMod(other, self.modulus, self.p)

    def __add__(self, other: Iterable[int] | PolyMod) -> PolyMod:
        other = self._coerce(other)
        return PolyMod(
            quotient_add(self.value, other.value, self.modulus, self.p),
            self.modulus,
            self.p,
        )

    def __radd__(self, other: Iterable[int] | PolyMod) -> PolyMod:
        return self + other

    def __neg__(self) -> PolyMod:
        return PolyMod(poly_neg(self.value, self.p), self.modulus, self.p)

    def __sub__(self, other: Iterable[int] | PolyMod) -> PolyMod:
        other = self._coerce(other)
        return PolyMod(
            quotient_sub(self.value, other.value, self.modulus, self.p),
            self.modulus,
            self.p,
        )

    def __rsub__(self, other: Iterable[int] | PolyMod) -> PolyMod:
        return self._coerce(other) - self

    def __mul__(self, other: Iterable[int] | PolyMod) -> PolyMod:
        other = self._coerce(other)
        return PolyMod(
            quotient_mul(self.value, other.value, self.modulus, self.p),
            self.modulus,
            self.p,
        )

    def __rmul__(self, other: Iterable[int] | PolyMod) -> PolyMod:
        return self * other

    def inverse(self) -> PolyMod:
        return PolyMod(
            quotient_inverse(self.value, self.modulus, self.p),
            self.modulus,
            self.p,
        )

    def __truediv__(self, other: Iterable[int] | PolyMod) -> PolyMod:
        other = self._coerce(other)
        return self * other.inverse()

    def __rtruediv__(self, other: Iterable[int] | PolyMod) -> PolyMod:
        return self._coerce(other) / self

    def __pow__(self, exponent: int) -> PolyMod:
        return PolyMod(
            quotient_pow(self.value, exponent, self.modulus, self.p),
            self.modulus,
            self.p,
        )

    def __repr__(self) -> str:
        return f"PolyMod({list(self.value)}, modulus={list(self.modulus)}, p={self.p})"

    def __str__(self) -> str:
        return poly_to_string(self.value, self.p)


def polynomial_ring_report(modulus: Iterable[int], p: int) -> dict[str, object]:
    modulus_poly = poly_monic(modulus, p)
    degree = len(modulus_poly) - 1
    return {
        "p": p,
        "modulus": modulus_poly,
        "modulus_terms": poly_to_string(modulus_poly, p),
        "quotient_order": p**degree,
        "representatives": polynomials_below_degree(degree, p),
        "zero_divisor_pair": zero_divisor_pair(modulus_poly, p),
    }


def main() -> None:
    p = 5
    f = Poly([1, 2, 0, 1], p)
    g = Poly([4, 1, 1], p)
    modulus = [2, 0, 1]
    a = PolyMod([3, 4], modulus, p)
    b = PolyMod([2, 1], modulus, p)

    print("f:", f)
    print("g:", g)
    print("f + g:", f + g)
    print("f * g:", f * g)
    print("f div g:", f.divmod(g))
    print("a in F_5[x]/(x^2+2):", a)
    print("b in F_5[x]/(x^2+2):", b)
    print("a * b:", a * b)
    print("b^-1:", b.inverse())


if __name__ == "__main__":
    main()
