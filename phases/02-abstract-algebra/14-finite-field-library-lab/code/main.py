from __future__ import annotations

from dataclasses import dataclass
from math import isqrt
from typing import Iterable, Sequence


class FiniteFieldError(ValueError):
    pass


class InvalidFieldError(FiniteFieldError):
    pass


class NotIrreducibleError(InvalidFieldError):
    pass


class NoInverseError(FiniteFieldError):
    pass


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
        raise InvalidFieldError("p must be prime")


def egcd(a: int, b: int) -> tuple[int, int, int]:
    if a == 0 and b == 0:
        return 0, 0, 0

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
        raise NoInverseError("zero has no multiplicative inverse")

    g, x, _ = egcd(a, p)
    if g != 1:
        raise NoInverseError("element is not invertible")
    return x % p


def normalize_poly(coefficients: Iterable[int], p: int) -> list[int]:
    require_prime(p)
    result = [c % p for c in coefficients]
    while len(result) > 1 and result[-1] == 0:
        result.pop()
    return result or [0]


def require_nonzero_poly(coefficients: Iterable[int], p: int) -> list[int]:
    poly = normalize_poly(coefficients, p)
    if poly == [0]:
        raise InvalidFieldError("zero polynomial is not allowed")
    return poly


def poly_degree(coefficients: Iterable[int], p: int) -> int:
    poly = normalize_poly(coefficients, p)
    if poly == [0]:
        return -1
    return len(poly) - 1


def poly_to_string(coefficients: Iterable[int], p: int, variable: str = "x") -> str:
    poly = normalize_poly(coefficients, p)
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
    left = normalize_poly(a, p)
    right = normalize_poly(b, p)
    length = max(len(left), len(right))
    out = []
    for i in range(length):
        out.append(((left[i] if i < len(left) else 0) + (right[i] if i < len(right) else 0)) % p)
    return normalize_poly(out, p)


def poly_neg(a: Iterable[int], p: int) -> list[int]:
    return normalize_poly(((-c) % p for c in normalize_poly(a, p)), p)


def poly_sub(a: Iterable[int], b: Iterable[int], p: int) -> list[int]:
    return poly_add(a, poly_neg(b, p), p)


def poly_scale(a: Iterable[int], scalar: int, p: int) -> list[int]:
    return normalize_poly((scalar * c for c in normalize_poly(a, p)), p)


def poly_mul(a: Iterable[int], b: Iterable[int], p: int) -> list[int]:
    left = normalize_poly(a, p)
    right = normalize_poly(b, p)
    if left == [0] or right == [0]:
        return [0]

    result = [0] * (len(left) + len(right) - 1)
    for i, ac in enumerate(left):
        for j, bc in enumerate(right):
            result[i + j] = (result[i + j] + ac * bc) % p
    return normalize_poly(result, p)


def poly_divmod(dividend: Iterable[int], divisor: Iterable[int], p: int) -> tuple[list[int], list[int]]:
    remainder = normalize_poly(dividend, p)
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

    return normalize_poly(quotient, p), remainder


def poly_mod(poly: Iterable[int], modulus: Iterable[int], p: int) -> list[int]:
    return poly_divmod(poly, modulus, p)[1]


def poly_monic(poly: Iterable[int], p: int) -> list[int]:
    normalized = require_nonzero_poly(poly, p)
    return poly_scale(normalized, mod_inverse(normalized[-1], p), p)


def poly_gcd(a: Iterable[int], b: Iterable[int], p: int) -> list[int]:
    left = normalize_poly(a, p)
    right = normalize_poly(b, p)
    while right != [0]:
        left, right = right, poly_mod(left, right, p)
    if left == [0]:
        return [0]
    return poly_monic(left, p)


def poly_pow_mod(base: Iterable[int], exponent: int, modulus: Iterable[int], p: int) -> list[int]:
    if exponent < 0:
        raise InvalidFieldError("exponent must be nonnegative")

    modulus_poly = require_nonzero_poly(modulus, p)
    result = [1]
    power = poly_mod(base, modulus_poly, p)
    while exponent:
        if exponent & 1:
            result = poly_mod(poly_mul(result, power, p), modulus_poly, p)
        power = poly_mod(poly_mul(power, power, p), modulus_poly, p)
        exponent >>= 1
    return result


def poly_extended_gcd(a: Iterable[int], b: Iterable[int], p: int) -> tuple[list[int], list[int], list[int]]:
    old_r, r = normalize_poly(a, p), normalize_poly(b, p)
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


def prime_factors(n: int) -> list[int]:
    if n < 1:
        raise InvalidFieldError("n must be positive")

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


def is_irreducible(modulus: Iterable[int], p: int) -> bool:
    f = poly_monic(modulus, p)
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


@dataclass(frozen=True)
class PrimeField:
    p: int

    def __post_init__(self) -> None:
        require_prime(self.p)

    def __call__(self, value: int) -> Fp:
        return Fp(value, self)

    @property
    def zero(self) -> Fp:
        return self(0)

    @property
    def one(self) -> Fp:
        return self(1)


@dataclass(frozen=True)
class Fp:
    value: int
    field: PrimeField

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", self.value % self.field.p)

    def _coerce(self, other: int | Fp) -> Fp:
        if isinstance(other, Fp):
            if other.field.p != self.field.p:
                raise InvalidFieldError("cannot mix different prime fields")
            return other
        return self.field(other)

    def __add__(self, other: int | Fp) -> Fp:
        other = self._coerce(other)
        return self.field(self.value + other.value)

    def __radd__(self, other: int | Fp) -> Fp:
        return self + other

    def __sub__(self, other: int | Fp) -> Fp:
        other = self._coerce(other)
        return self.field(self.value - other.value)

    def __rsub__(self, other: int | Fp) -> Fp:
        return self._coerce(other) - self

    def __neg__(self) -> Fp:
        return self.field(-self.value)

    def __mul__(self, other: int | Fp) -> Fp:
        other = self._coerce(other)
        return self.field(self.value * other.value)

    def __rmul__(self, other: int | Fp) -> Fp:
        return self * other

    def inverse(self) -> Fp:
        return self.field(mod_inverse(self.value, self.field.p))

    def __truediv__(self, other: int | Fp) -> Fp:
        other = self._coerce(other)
        return self * other.inverse()

    def __rtruediv__(self, other: int | Fp) -> Fp:
        return self._coerce(other) / self

    def __pow__(self, exponent: int) -> Fp:
        if exponent < 0:
            return self.inverse() ** (-exponent)
        return self.field(pow(self.value, exponent, self.field.p))

    def __int__(self) -> int:
        return self.value

    def __repr__(self) -> str:
        return f"Fp({self.value}, p={self.field.p})"


@dataclass(frozen=True)
class PolyField:
    p: int
    modulus: tuple[int, ...]

    def __init__(self, p: int, modulus: Sequence[int]) -> None:
        require_prime(p)
        modulus_poly = poly_monic(modulus, p)
        if not is_irreducible(modulus_poly, p):
            raise NotIrreducibleError("modulus polynomial must be irreducible")
        object.__setattr__(self, "p", p)
        object.__setattr__(self, "modulus", tuple(modulus_poly))

    @property
    def degree(self) -> int:
        return len(self.modulus) - 1

    def __call__(self, value: int | Sequence[int]) -> Fq:
        if isinstance(value, int):
            coefficients = [value]
        else:
            coefficients = list(value)
        return Fq(coefficients, self)

    @property
    def zero(self) -> Fq:
        return self([0])

    @property
    def one(self) -> Fq:
        return self([1])


@dataclass(frozen=True)
class Fq:
    coefficients: tuple[int, ...]
    field: PolyField

    def __init__(self, coefficients: Iterable[int], field: PolyField) -> None:
        value = poly_mod(coefficients, field.modulus, field.p)
        object.__setattr__(self, "coefficients", tuple(value))
        object.__setattr__(self, "field", field)

    def _coerce(self, other: int | Sequence[int] | Fq) -> Fq:
        if isinstance(other, Fq):
            if other.field.p != self.field.p or other.field.modulus != self.field.modulus:
                raise InvalidFieldError("cannot mix different extension fields")
            return other
        if isinstance(other, int):
            return self.field([other])
        return self.field(other)

    def __add__(self, other: int | Sequence[int] | Fq) -> Fq:
        other = self._coerce(other)
        return self.field(poly_add(self.coefficients, other.coefficients, self.field.p))

    def __radd__(self, other: int | Sequence[int] | Fq) -> Fq:
        return self + other

    def __neg__(self) -> Fq:
        return self.field(poly_neg(self.coefficients, self.field.p))

    def __sub__(self, other: int | Sequence[int] | Fq) -> Fq:
        return self + (-self._coerce(other))

    def __rsub__(self, other: int | Sequence[int] | Fq) -> Fq:
        return self._coerce(other) - self

    def __mul__(self, other: int | Sequence[int] | Fq) -> Fq:
        other = self._coerce(other)
        return self.field(poly_mul(self.coefficients, other.coefficients, self.field.p))

    def __rmul__(self, other: int | Sequence[int] | Fq) -> Fq:
        return self * other

    def inverse(self) -> Fq:
        if list(self.coefficients) == [0]:
            raise NoInverseError("zero has no multiplicative inverse")
        gcd, x, _ = poly_extended_gcd(self.coefficients, self.field.modulus, self.field.p)
        if gcd != [1]:
            raise NoInverseError("element is not invertible with this modulus")
        return self.field(poly_mod(x, self.field.modulus, self.field.p))

    def __truediv__(self, other: int | Sequence[int] | Fq) -> Fq:
        other = self._coerce(other)
        return self * other.inverse()

    def __pow__(self, exponent: int) -> Fq:
        if exponent < 0:
            return self.inverse() ** (-exponent)

        result = self.field.one
        power = self
        e = exponent
        while e:
            if e & 1:
                result = result * power
            power = power * power
            e >>= 1
        return result

    def __int__(self) -> int:
        if self.field.p != 2:
            raise InvalidFieldError("int() is only supported for p=2 extension fields")
        value = 0
        for i, coefficient in enumerate(self.coefficients):
            value |= (coefficient & 1) << i
        return value

    def __repr__(self) -> str:
        return f"Fq({list(self.coefficients)}, p={self.field.p}, modulus={list(self.field.modulus)})"

    def __str__(self) -> str:
        return poly_to_string(self.coefficients, self.field.p)


AES_MODULUS_POLY = (1, 1, 0, 1, 1, 0, 0, 0, 1)
_AES_FIELD = PolyField(2, AES_MODULUS_POLY)


def aes_field() -> PolyField:
    return _AES_FIELD


def aes_mul(a: int, b: int) -> int:
    if not (0 <= a < 256 and 0 <= b < 256):
        raise InvalidFieldError("AES bytes must be in 0..255")
    field = aes_field()
    left = field([(a >> i) & 1 for i in range(field.degree)])
    right = field([(b >> i) & 1 for i in range(field.degree)])
    return int(left * right)


def aes_inverse(byte: int) -> int:
    if not (0 <= byte < 256):
        raise InvalidFieldError("AES byte must be in 0..255")
    if byte == 0:
        raise NoInverseError("zero has no multiplicative inverse")
    field = aes_field()
    value = field([(byte >> i) & 1 for i in range(field.degree)])
    return int(value.inverse())


def main() -> None:
    f17 = PrimeField(17)
    a = f17(29)
    b = f17(5)
    print("F_17: (29 + 5) * 4 =", (a + b) * 4)

    f25 = PolyField(5, [2, 0, 1])
    x = f25([0, 1])
    print("F_25: x^2 =", x**2)

    print("AES: 0x57 * 0x83 =", hex(aes_mul(0x57, 0x83)))


if __name__ == "__main__":
    main()
