from __future__ import annotations

from dataclasses import dataclass
from itertools import product
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
            terms.append(variable if coefficient == 1 else f"{coefficient}{variable}")
        elif coefficient == 1:
            terms.append(f"{variable}^{power}")
        else:
            terms.append(f"{coefficient}{variable}^{power}")
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


def poly_eval(coefficients: Iterable[int], x: int, p: int) -> int:
    result = 0
    for coefficient in reversed(normalize(coefficients, p)):
        result = (result * x + coefficient) % p
    return result


def poly_pow_mod(
    base: Iterable[int],
    exponent: int,
    modulus: Iterable[int],
    p: int,
) -> list[int]:
    if exponent < 0:
        raise ValueError("exponent must be nonnegative")

    modulus_poly = require_nonzero_poly(modulus, p)
    result = [1]
    power = poly_mod(base, modulus_poly, p)
    while exponent:
        if exponent & 1:
            result = poly_mod(poly_mul(result, power, p), modulus_poly, p)
        power = poly_mod(poly_mul(power, power, p), modulus_poly, p)
        exponent >>= 1
    return result


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


def quotient_add(
    a: Iterable[int],
    b: Iterable[int],
    modulus: Iterable[int],
    p: int,
) -> list[int]:
    return poly_mod(poly_add(a, b, p), modulus, p)


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
    return poly_pow_mod(a, exponent, modulus, p)


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


def prime_factors(n: int) -> list[int]:
    if n < 1:
        raise ValueError("n must be positive")

    factors: list[int] = []
    candidate = 2
    while candidate * candidate <= n:
        if n % candidate == 0:
            factors.append(candidate)
            while n % candidate == 0:
                n //= candidate
        candidate += 1 if candidate == 2 else 2
    if n > 1:
        factors.append(n)
    return factors


def monic_polynomials(degree: int, p: int) -> list[list[int]]:
    require_prime(p)
    if degree < 0:
        raise ValueError("degree must be nonnegative")
    if degree == 0:
        return [[1]]

    return [normalize((*coefficients, 1), p) for coefficients in product(range(p), repeat=degree)]


def roots(poly: Iterable[int], p: int) -> list[int]:
    value = require_nonzero_poly(poly, p)
    return [x for x in range(p) if poly_eval(value, x, p) == 0]


def has_root(poly: Iterable[int], p: int) -> bool:
    return bool(roots(poly, p))


def is_irreducible(poly: Iterable[int], p: int) -> bool:
    f = poly_monic(poly, p)
    degree = len(f) - 1
    if degree <= 0:
        return False
    if degree == 1:
        return True

    x_poly = [0, 1]
    for q in prime_factors(degree):
        frobenius = poly_pow_mod(x_poly, p ** (degree // q), f, p)
        if poly_gcd(poly_sub(frobenius, x_poly, p), f, p) != [1]:
            return False

    final = poly_pow_mod(x_poly, p**degree, f, p)
    return poly_sub(final, x_poly, p) == [0]


def find_nontrivial_factor(poly: Iterable[int], p: int) -> list[int] | None:
    f = poly_monic(poly, p)
    degree = len(f) - 1
    if degree <= 1:
        return None

    for factor_degree in range(1, degree // 2 + 1):
        for candidate in monic_polynomials(factor_degree, p):
            if factor_degree > 1 and candidate[0] == 0:
                continue
            _, remainder = poly_divmod(f, candidate, p)
            if remainder == [0]:
                return candidate
    return None


def factor_by_trial(poly: Iterable[int], p: int) -> list[list[int]]:
    remaining = poly_monic(poly, p)
    if len(remaining) <= 1:
        return [remaining]

    factors: list[list[int]] = []
    while len(remaining) > 2:
        factor = find_nontrivial_factor(remaining, p)
        if factor is None:
            break
        quotient, _ = poly_divmod(remaining, factor, p)
        factors.append(factor)
        remaining = poly_monic(quotient, p)

    if remaining != [1]:
        factors.append(remaining)
    return factors


def reducible_witness(poly: Iterable[int], p: int) -> tuple[list[int], list[int]] | None:
    f = poly_monic(poly, p)
    factor = find_nontrivial_factor(f, p)
    if factor is None:
        return None
    cofactor, _ = poly_divmod(f, factor, p)
    return factor, poly_monic(cofactor, p)


def find_irreducible(degree: int, p: int) -> list[int]:
    require_prime(p)
    if degree < 1:
        raise ValueError("degree must be positive")

    for candidate in monic_polynomials(degree, p):
        if degree > 1 and candidate[0] == 0:
            continue
        if is_irreducible(candidate, p):
            return candidate
    raise ValueError("no irreducible polynomial found")


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


def field_report(modulus: Iterable[int], p: int) -> dict[str, object]:
    modulus_poly = poly_monic(modulus, p)
    degree = len(modulus_poly) - 1
    irreducible = is_irreducible(modulus_poly, p)
    witness = None if irreducible else reducible_witness(modulus_poly, p)
    return {
        "p": p,
        "modulus": modulus_poly,
        "modulus_terms": poly_to_string(modulus_poly, p),
        "degree": degree,
        "order": p**degree,
        "irreducible": irreducible,
        "roots": roots(modulus_poly, p),
        "reducible_witness": witness,
    }


@dataclass(frozen=True)
class ExtensionField:
    value: tuple[int, ...]
    modulus: tuple[int, ...]
    p: int

    def __init__(self, value: Iterable[int], modulus: Iterable[int], p: int) -> None:
        modulus_poly = poly_monic(modulus, p)
        if not is_irreducible(modulus_poly, p):
            raise ValueError("modulus polynomial must be irreducible")
        object.__setattr__(self, "p", p)
        object.__setattr__(self, "modulus", tuple(modulus_poly))
        object.__setattr__(self, "value", tuple(poly_mod(value, modulus_poly, p)))

    @property
    def degree(self) -> int:
        return len(self.modulus) - 1

    def _coerce(self, other: Iterable[int] | ExtensionField) -> ExtensionField:
        if isinstance(other, ExtensionField):
            if other.p != self.p or other.modulus != self.modulus:
                raise ValueError("cannot mix different extension fields")
            return other
        return ExtensionField(other, self.modulus, self.p)

    def __add__(self, other: Iterable[int] | ExtensionField) -> ExtensionField:
        other = self._coerce(other)
        return ExtensionField(
            quotient_add(self.value, other.value, self.modulus, self.p),
            self.modulus,
            self.p,
        )

    def __radd__(self, other: Iterable[int] | ExtensionField) -> ExtensionField:
        return self + other

    def __neg__(self) -> ExtensionField:
        return ExtensionField(poly_neg(self.value, self.p), self.modulus, self.p)

    def __sub__(self, other: Iterable[int] | ExtensionField) -> ExtensionField:
        return self + (-self._coerce(other))

    def __rsub__(self, other: Iterable[int] | ExtensionField) -> ExtensionField:
        return self._coerce(other) - self

    def __mul__(self, other: Iterable[int] | ExtensionField) -> ExtensionField:
        other = self._coerce(other)
        return ExtensionField(
            quotient_mul(self.value, other.value, self.modulus, self.p),
            self.modulus,
            self.p,
        )

    def __rmul__(self, other: Iterable[int] | ExtensionField) -> ExtensionField:
        return self * other

    def inverse(self) -> ExtensionField:
        return ExtensionField(
            quotient_inverse(self.value, self.modulus, self.p),
            self.modulus,
            self.p,
        )

    def __truediv__(self, other: Iterable[int] | ExtensionField) -> ExtensionField:
        other = self._coerce(other)
        return self * other.inverse()

    def __pow__(self, exponent: int) -> ExtensionField:
        return ExtensionField(
            quotient_pow(self.value, exponent, self.modulus, self.p),
            self.modulus,
            self.p,
        )

    def __repr__(self) -> str:
        return f"ExtensionField({list(self.value)}, modulus={list(self.modulus)}, p={self.p})"

    def __str__(self) -> str:
        return poly_to_string(self.value, self.p)


def main() -> None:
    p = 5
    modulus = [2, 0, 1]
    a = ExtensionField([3, 4], modulus, p)
    b = ExtensionField([2, 1], modulus, p)

    print("modulus:", poly_to_string(modulus, p))
    print("report:", field_report(modulus, p))
    print("a:", a)
    print("b:", b)
    print("a * b:", a * b)
    print("b^-1:", b.inverse())


if __name__ == "__main__":
    main()
