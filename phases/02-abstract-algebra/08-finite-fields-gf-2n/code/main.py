from __future__ import annotations

from dataclasses import dataclass

AES_MODULUS = 0x11B


def require_nonnegative(poly: int) -> None:
    if poly < 0:
        raise ValueError("polynomial must be nonnegative")


def poly_degree(poly: int) -> int:
    require_nonnegative(poly)
    return poly.bit_length() - 1


def poly_to_terms(poly: int) -> str:
    require_nonnegative(poly)
    if poly == 0:
        return "0"

    terms: list[str] = []
    for power in range(poly_degree(poly), -1, -1):
        if not (poly >> power) & 1:
            continue
        if power == 0:
            terms.append("1")
        elif power == 1:
            terms.append("x")
        else:
            terms.append(f"x^{power}")
    return " + ".join(terms)


def poly_add(a: int, b: int) -> int:
    require_nonnegative(a)
    require_nonnegative(b)
    return a ^ b


def poly_mul(a: int, b: int) -> int:
    require_nonnegative(a)
    require_nonnegative(b)
    result = 0
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        b >>= 1
    return result


def poly_divmod(dividend: int, divisor: int) -> tuple[int, int]:
    require_nonnegative(dividend)
    require_nonnegative(divisor)
    if divisor == 0:
        raise ValueError("division by zero polynomial")

    quotient = 0
    remainder = dividend
    divisor_degree = poly_degree(divisor)

    while remainder and poly_degree(remainder) >= divisor_degree:
        shift = poly_degree(remainder) - divisor_degree
        quotient ^= 1 << shift
        remainder ^= divisor << shift

    return quotient, remainder


def poly_mod(poly: int, modulus: int) -> int:
    return poly_divmod(poly, modulus)[1]


def poly_gcd(a: int, b: int) -> int:
    require_nonnegative(a)
    require_nonnegative(b)
    while b:
        a, b = b, poly_mod(a, b)
    return a


def poly_extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    require_nonnegative(a)
    require_nonnegative(b)
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r:
        q, new_r = poly_divmod(old_r, r)
        old_r, r = r, new_r
        old_s, s = s, old_s ^ poly_mul(q, s)
        old_t, t = t, old_t ^ poly_mul(q, t)

    return old_r, old_s, old_t


def require_modulus(modulus: int) -> None:
    require_nonnegative(modulus)
    if poly_degree(modulus) < 1:
        raise ValueError("modulus polynomial must have degree at least one")
    if modulus & 1 == 0:
        raise ValueError("modulus polynomial must have constant term one")


def is_irreducible(modulus: int) -> bool:
    require_modulus(modulus)
    degree = poly_degree(modulus)
    if degree == 1:
        return True

    for d in range(1, degree // 2 + 1):
        for candidate in range(1 << d, 1 << (d + 1)):
            if candidate & 1 == 0:
                continue
            if poly_mod(modulus, candidate) == 0:
                return False
    return True


def gf2n_add(a: int, b: int, modulus: int) -> int:
    require_modulus(modulus)
    return poly_mod(a, modulus) ^ poly_mod(b, modulus)


def gf2n_mul(a: int, b: int, modulus: int) -> int:
    require_modulus(modulus)
    return poly_mod(poly_mul(a, b), modulus)


def gf2n_pow(a: int, exponent: int, modulus: int) -> int:
    require_modulus(modulus)
    a = poly_mod(a, modulus)
    if exponent < 0:
        return gf2n_pow(gf2n_inverse(a, modulus), -exponent, modulus)

    result = 1
    while exponent:
        if exponent & 1:
            result = gf2n_mul(result, a, modulus)
        a = gf2n_mul(a, a, modulus)
        exponent >>= 1
    return result


def gf2n_inverse(a: int, modulus: int) -> int:
    require_modulus(modulus)
    a = poly_mod(a, modulus)
    if a == 0:
        raise ValueError("zero has no multiplicative inverse")

    gcd, x, _ = poly_extended_gcd(a, modulus)
    if gcd != 1:
        raise ValueError("element is not invertible with this modulus")
    return poly_mod(x, modulus)


def gf2n_div(a: int, b: int, modulus: int) -> int:
    return gf2n_mul(a, gf2n_inverse(b, modulus), modulus)


def gf2n_multiplicative_order(a: int, modulus: int) -> int:
    require_modulus(modulus)
    a = poly_mod(a, modulus)
    if a == 0:
        raise ValueError("zero has no multiplicative order")

    x = 1
    order = (1 << poly_degree(modulus)) - 1
    for k in range(1, order + 1):
        x = gf2n_mul(x, a, modulus)
        if x == 1:
            return k

    raise ValueError("order search failed")


def gf2n_is_generator(a: int, modulus: int) -> bool:
    require_modulus(modulus)
    return poly_mod(a, modulus) != 0 and gf2n_multiplicative_order(a, modulus) == (
        (1 << poly_degree(modulus)) - 1
    )


@dataclass(frozen=True)
class GF2N:
    value: int
    modulus: int

    def __post_init__(self) -> None:
        require_modulus(self.modulus)
        object.__setattr__(self, "value", poly_mod(self.value, self.modulus))

    @property
    def degree(self) -> int:
        return poly_degree(self.modulus)

    def _coerce(self, other: int | GF2N) -> GF2N:
        if isinstance(other, GF2N):
            if other.modulus != self.modulus:
                raise ValueError("cannot mix different binary fields")
            return other
        return GF2N(other, self.modulus)

    def __add__(self, other: int | GF2N) -> GF2N:
        other = self._coerce(other)
        return GF2N(gf2n_add(self.value, other.value, self.modulus), self.modulus)

    def __radd__(self, other: int | GF2N) -> GF2N:
        return self + other

    def __sub__(self, other: int | GF2N) -> GF2N:
        return self + other

    def __rsub__(self, other: int | GF2N) -> GF2N:
        return self._coerce(other) + self

    def __neg__(self) -> GF2N:
        return self

    def __mul__(self, other: int | GF2N) -> GF2N:
        other = self._coerce(other)
        return GF2N(gf2n_mul(self.value, other.value, self.modulus), self.modulus)

    def __rmul__(self, other: int | GF2N) -> GF2N:
        return self * other

    def inverse(self) -> GF2N:
        return GF2N(gf2n_inverse(self.value, self.modulus), self.modulus)

    def __truediv__(self, other: int | GF2N) -> GF2N:
        other = self._coerce(other)
        return self * other.inverse()

    def __rtruediv__(self, other: int | GF2N) -> GF2N:
        return self._coerce(other) / self

    def __pow__(self, exponent: int) -> GF2N:
        return GF2N(gf2n_pow(self.value, exponent, self.modulus), self.modulus)

    def __int__(self) -> int:
        return self.value

    def __repr__(self) -> str:
        width = max(1, (self.degree + 3) // 4)
        return f"GF2N(0x{self.value:0{width}x}, modulus=0x{self.modulus:x})"


def gf2n_elements(modulus: int) -> list[int]:
    require_modulus(modulus)
    return list(range(1 << poly_degree(modulus)))


def gf2n_inverses(modulus: int) -> dict[int, int]:
    require_modulus(modulus)
    return {a: gf2n_inverse(a, modulus) for a in range(1, 1 << poly_degree(modulus))}


def gf2n_field_report(modulus: int) -> dict[str, object]:
    require_modulus(modulus)
    degree = poly_degree(modulus)
    return {
        "modulus": modulus,
        "modulus_terms": poly_to_terms(modulus),
        "degree": degree,
        "order": 1 << degree,
        "characteristic": 2,
        "irreducible": is_irreducible(modulus),
        "elements": gf2n_elements(modulus),
    }


def aes_xtime(byte: int) -> int:
    if not 0 <= byte <= 0xFF:
        raise ValueError("byte must be in 0..255")
    return gf2n_mul(byte, 0x02, AES_MODULUS)


def aes_mul(a: int, b: int) -> int:
    if not 0 <= a <= 0xFF or not 0 <= b <= 0xFF:
        raise ValueError("bytes must be in 0..255")
    return gf2n_mul(a, b, AES_MODULUS)


def aes_mix_single_column(column: list[int]) -> list[int]:
    if len(column) != 4:
        raise ValueError("column must contain four bytes")
    if any(not 0 <= byte <= 0xFF for byte in column):
        raise ValueError("column bytes must be in 0..255")

    a0, a1, a2, a3 = column
    return [
        aes_mul(0x02, a0) ^ aes_mul(0x03, a1) ^ a2 ^ a3,
        a0 ^ aes_mul(0x02, a1) ^ aes_mul(0x03, a2) ^ a3,
        a0 ^ a1 ^ aes_mul(0x02, a2) ^ aes_mul(0x03, a3),
        aes_mul(0x03, a0) ^ a1 ^ a2 ^ aes_mul(0x02, a3),
    ]


def main() -> None:
    modulus = AES_MODULUS
    a = GF2N(0x57, modulus)
    b = GF2N(0x83, modulus)

    print("field:", "GF(2^8)")
    print("modulus:", poly_to_terms(modulus))
    print("irreducible:", is_irreducible(modulus))
    print("a + b:", hex(int(a + b)))
    print("a * b:", hex(int(a * b)))
    print("a^-1:", hex(int(a.inverse())))
    print("xtime(0x57):", hex(aes_xtime(0x57)))
    print("mix column:", [hex(x) for x in aes_mix_single_column([0xDB, 0x13, 0x53, 0x45])])


if __name__ == "__main__":
    main()
