from math import isqrt
from typing import Callable, Hashable, TypeVar

T = TypeVar("T", bound=Hashable)
Operation = Callable[[T, T], T]
Fp2 = tuple[int, int]


def add_mod(a: int, b: int, n: int) -> int:
    if n <= 0:
        raise ValueError("modulus must be positive")
    return (a + b) % n


def sub_mod(a: int, b: int, n: int) -> int:
    if n <= 0:
        raise ValueError("modulus must be positive")
    return (a - b) % n


def neg_mod(a: int, n: int) -> int:
    if n <= 0:
        raise ValueError("modulus must be positive")
    return (-a) % n


def mul_mod(a: int, b: int, n: int) -> int:
    if n <= 0:
        raise ValueError("modulus must be positive")
    return (a * b) % n


def residues_mod(n: int) -> list[int]:
    if n <= 0:
        raise ValueError("modulus must be positive")
    return list(range(n))


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


def egcd(a: int, b: int) -> tuple[int, int, int]:
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t

    return old_r, old_s, old_t


def inv_mod(a: int, n: int) -> int:
    if n <= 0:
        raise ValueError("modulus must be positive")
    g, x, _ = egcd(a % n, n)
    if g != 1:
        raise ValueError("element is not invertible modulo n")
    return x % n


def find_identity(elements: list[T], operation: Operation[T]) -> T | None:
    for candidate in elements:
        if all(
            operation(candidate, element) == element
            and operation(element, candidate) == element
            for element in elements
        ):
            return candidate
    return None


def is_closed(elements: list[T], operation: Operation[T]) -> bool:
    element_set = set(elements)
    return all(operation(a, b) in element_set for a in elements for b in elements)


def is_associative(elements: list[T], operation: Operation[T]) -> bool:
    return all(
        operation(operation(a, b), c) == operation(a, operation(b, c))
        for a in elements
        for b in elements
        for c in elements
    )


def is_commutative(elements: list[T], operation: Operation[T]) -> bool:
    return all(operation(a, b) == operation(b, a) for a in elements for b in elements)


def inverse_of(element: T, elements: list[T], operation: Operation[T]) -> T | None:
    identity = find_identity(elements, operation)
    if identity is None:
        return None

    for candidate in elements:
        if (
            operation(element, candidate) == identity
            and operation(candidate, element) == identity
        ):
            return candidate
    return None


def is_abelian_group(elements: list[T], operation: Operation[T]) -> bool:
    if not elements:
        return False
    if len(set(elements)) != len(elements):
        return False
    if not is_closed(elements, operation):
        return False
    if not is_associative(elements, operation):
        return False
    if not is_commutative(elements, operation):
        return False
    return all(
        inverse_of(element, elements, operation) is not None
        for element in elements
    )


def is_distributive(elements: list[T], add: Operation[T], mul: Operation[T]) -> bool:
    return all(
        mul(a, add(b, c)) == add(mul(a, b), mul(a, c))
        and mul(add(b, c), a) == add(mul(b, a), mul(c, a))
        for a in elements
        for b in elements
        for c in elements
    )


def additive_identity(elements: list[T], add: Operation[T]) -> T:
    identity = find_identity(elements, add)
    if identity is None:
        raise ValueError("additive identity does not exist")
    return identity


def multiplicative_identity(elements: list[T], mul: Operation[T]) -> T | None:
    return find_identity(elements, mul)


def is_commutative_ring(
    elements: list[T],
    add: Operation[T],
    mul: Operation[T],
) -> bool:
    if not is_abelian_group(elements, add):
        return False
    if not is_closed(elements, mul):
        return False
    if not is_associative(elements, mul):
        return False
    if not is_commutative(elements, mul):
        return False
    return is_distributive(elements, add, mul)


def units(elements: list[T], add: Operation[T], mul: Operation[T]) -> list[T]:
    one = multiplicative_identity(elements, mul)
    if one is None:
        return []
    return sorted(
        element for element in elements if inverse_of(element, elements, mul) is not None
    )


def zero_divisors(elements: list[T], add: Operation[T], mul: Operation[T]) -> list[T]:
    zero = additive_identity(elements, add)
    nonzero = [element for element in elements if element != zero]
    result: list[T] = []

    for a in nonzero:
        for b in nonzero:
            if mul(a, b) == zero:
                result.append(a)
                break

    return sorted(result)


def is_field(elements: list[T], add: Operation[T], mul: Operation[T]) -> bool:
    if not is_commutative_ring(elements, add, mul):
        return False

    zero = additive_identity(elements, add)
    one = multiplicative_identity(elements, mul)
    if one is None or one == zero:
        return False

    return all(
        inverse_of(element, elements, mul) is not None
        for element in elements
        if element != zero
    )


def field_report(
    elements: list[T],
    add: Operation[T],
    mul: Operation[T],
) -> dict[str, object]:
    return {
        "order": len(elements),
        "is_commutative_ring": is_commutative_ring(elements, add, mul),
        "is_field": is_field(elements, add, mul),
        "additive_identity": additive_identity(elements, add),
        "multiplicative_identity": multiplicative_identity(elements, mul),
        "zero_divisors": zero_divisors(elements, add, mul),
        "units": units(elements, add, mul),
    }


def prime_field_elements(p: int) -> list[int]:
    if not is_prime(p):
        raise ValueError("p must be prime")
    return residues_mod(p)


def legendre_symbol(a: int, p: int) -> int:
    if not is_prime(p) or p == 2:
        raise ValueError("p must be an odd prime")
    value = pow(a % p, (p - 1) // 2, p)
    if value == p - 1:
        return -1
    return value


def is_quadratic_non_residue(beta: int, p: int) -> bool:
    return legendre_symbol(beta, p) == -1


def fp2_elements(p: int) -> list[Fp2]:
    if not is_prime(p):
        raise ValueError("p must be prime")
    return [(a, b) for a in range(p) for b in range(p)]


def fp2_add(x: Fp2, y: Fp2, p: int) -> Fp2:
    return ((x[0] + y[0]) % p, (x[1] + y[1]) % p)


def fp2_neg(x: Fp2, p: int) -> Fp2:
    return ((-x[0]) % p, (-x[1]) % p)


def fp2_sub(x: Fp2, y: Fp2, p: int) -> Fp2:
    return fp2_add(x, fp2_neg(y, p), p)


def fp2_mul(x: Fp2, y: Fp2, p: int, beta: int) -> Fp2:
    a, b = x
    c, d = y
    return ((a * c + beta * b * d) % p, (a * d + b * c) % p)


def fp2_conjugate(x: Fp2, p: int) -> Fp2:
    return (x[0] % p, (-x[1]) % p)


def fp2_trace(x: Fp2, p: int) -> int:
    return (2 * x[0]) % p


def fp2_norm(x: Fp2, p: int, beta: int) -> int:
    a, b = x
    return (a * a - beta * b * b) % p


def fp2_inv(x: Fp2, p: int, beta: int) -> Fp2:
    if x == (0, 0):
        raise ValueError("zero has no multiplicative inverse")
    denom = fp2_norm(x, p, beta)
    if denom == 0:
        raise ValueError("element is a zero divisor, not a unit")
    scale = inv_mod(denom, p)
    conj = fp2_conjugate(x, p)
    return ((conj[0] * scale) % p, (conj[1] * scale) % p)


def fp2_pow(x: Fp2, exponent: int, p: int, beta: int) -> Fp2:
    if exponent < 0:
        return fp2_pow(fp2_inv(x, p, beta), -exponent, p, beta)

    result = (1, 0)
    base = x
    power = exponent

    while power:
        if power % 2 == 1:
            result = fp2_mul(result, base, p, beta)
        base = fp2_mul(base, base, p, beta)
        power //= 2

    return result


def fp2_is_field(p: int, beta: int) -> bool:
    if not is_prime(p) or p == 2:
        return False
    return is_quadratic_non_residue(beta, p)


def fp2_zero_divisor_pair(p: int, beta: int) -> tuple[Fp2, Fp2] | None:
    elements = fp2_elements(p)
    zero = (0, 0)
    nonzero = [element for element in elements if element != zero]

    for a in nonzero:
        for b in nonzero:
            if fp2_mul(a, b, p, beta) == zero:
                return a, b

    return None


def fp2_report(p: int, beta: int) -> dict[str, object]:
    elements = fp2_elements(p)
    add = lambda x, y: fp2_add(x, y, p)
    mul = lambda x, y: fp2_mul(x, y, p, beta)
    report = field_report(elements, add, mul)
    report["base_prime"] = p
    report["beta"] = beta % p
    report["degree"] = 2
    report["irreducible_x2_minus_beta"] = fp2_is_field(p, beta)
    return report


def main() -> None:
    p = 5
    beta = 2
    x = (3, 4)
    y = (1, 2)

    print("F_5[u] / (u^2 - 2)")
    print("x + y =", fp2_add(x, y, p))
    print("x * y =", fp2_mul(x, y, p, beta))
    print("x^-1 =", fp2_inv(x, p, beta))
    print("x * x^-1 =", fp2_mul(x, fp2_inv(x, p, beta), p, beta))
    print("field:", fp2_is_field(p, beta))
    print("reducible beta=4 zero divisors:", fp2_zero_divisor_pair(p, 4))


if __name__ == "__main__":
    main()
