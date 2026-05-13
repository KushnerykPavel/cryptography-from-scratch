from math import gcd
from typing import Callable, Hashable, TypeVar

T = TypeVar("T", bound=Hashable)
Operation = Callable[[T, T], T]


def add_mod(a: int, b: int, n: int) -> int:
    if n <= 0:
        raise ValueError("modulus must be positive")
    return (a + b) % n


def mul_mod(a: int, b: int, n: int) -> int:
    if n <= 0:
        raise ValueError("modulus must be positive")
    return (a * b) % n


def residues_mod(n: int) -> list[int]:
    if n <= 0:
        raise ValueError("modulus must be positive")
    return list(range(n))


def unique_sorted(values: list[T]) -> list[T]:
    seen: set[T] = set()
    result: list[T] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return sorted(result)


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
    return all(
        operation(a, b) == operation(b, a)
        for a in elements
        for b in elements
    )


def inverse_of(
    element: T, elements: list[T], operation: Operation[T]
) -> T | None:
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
    if len(elements) == 0:
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


def is_distributive(
    elements: list[T],
    add: Operation[T],
    mul: Operation[T],
) -> bool:
    return all(
        mul(a, add(b, c)) == add(mul(a, b), mul(a, c))
        and mul(add(b, c), a) == add(mul(b, a), mul(c, a))
        for a in elements
        for b in elements
        for c in elements
    )


def is_ring(
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
    return is_distributive(elements, add, mul)


def is_commutative_ring(
    elements: list[T],
    add: Operation[T],
    mul: Operation[T],
) -> bool:
    return is_ring(elements, add, mul) and is_commutative(elements, mul)


def additive_identity(
    elements: list[T],
    add: Operation[T],
) -> T:
    identity = find_identity(elements, add)
    if identity is None:
        raise ValueError("additive identity does not exist")
    return identity


def multiplicative_identity(
    elements: list[T],
    mul: Operation[T],
) -> T | None:
    return find_identity(elements, mul)


def principal_ideal(
    generator: T,
    elements: list[T],
    mul: Operation[T],
) -> list[T]:
    if generator not in set(elements):
        raise ValueError("generator must be in the ring")
    return unique_sorted([mul(generator, r) for r in elements])


def is_ideal(
    subset: list[T],
    elements: list[T],
    add: Operation[T],
    mul: Operation[T],
) -> bool:
    if not is_ring(elements, add, mul):
        return False

    element_set = set(elements)
    subset_set = set(subset)
    if not subset_set.issubset(element_set):
        return False
    if len(subset_set) != len(subset):
        return False
    if len(subset) == 0:
        return False

    zero = additive_identity(elements, add)
    if zero not in subset_set:
        return False

    for a in subset:
        for b in subset:
            if add(a, b) not in subset_set:
                return False

    for a in subset:
        if inverse_of(a, elements, add) not in subset_set:
            return False

    for r in elements:
        for s in subset:
            if mul(r, s) not in subset_set:
                return False
            if mul(s, r) not in subset_set:
                return False

    return True


def canonical_coset_rep(
    element: T,
    ideal: list[T],
    add: Operation[T],
) -> T:
    return min(add(element, i) for i in ideal)


def quotient_coset_reps(
    elements: list[T],
    ideal: list[T],
    add: Operation[T],
    mul: Operation[T],
) -> list[T]:
    if not is_ideal(ideal, elements, add, mul):
        raise ValueError("subset must be an ideal of the ring")

    reps: list[T] = []
    seen: set[T] = set()
    for element in elements:
        rep = canonical_coset_rep(element, ideal, add)
        if rep not in seen:
            seen.add(rep)
            reps.append(rep)
    return sorted(reps)


def quotient_add(
    a: T,
    b: T,
    elements: list[T],
    ideal: list[T],
    add: Operation[T],
    mul: Operation[T],
) -> T:
    if not is_ideal(ideal, elements, add, mul):
        raise ValueError("subset must be an ideal of the ring")
    return canonical_coset_rep(add(a, b), ideal, add)


def quotient_mul(
    a: T,
    b: T,
    elements: list[T],
    ideal: list[T],
    add: Operation[T],
    mul: Operation[T],
) -> T:
    if not is_ideal(ideal, elements, add, mul):
        raise ValueError("subset must be an ideal of the ring")
    return canonical_coset_rep(mul(a, b), ideal, add)


def quotient_is_ring(
    elements: list[T],
    ideal: list[T],
    add: Operation[T],
    mul: Operation[T],
) -> bool:
    reps = quotient_coset_reps(elements, ideal, add, mul)
    quot_add: Operation[T] = lambda a, b: quotient_add(
        a, b, elements, ideal, add, mul
    )
    quot_mul: Operation[T] = lambda a, b: quotient_mul(
        a, b, elements, ideal, add, mul
    )
    return is_ring(reps, quot_add, quot_mul)


def zero_divisors(
    elements: list[T],
    add: Operation[T],
    mul: Operation[T],
) -> list[T]:
    if not is_ring(elements, add, mul):
        raise ValueError("elements and operations must form a ring")

    zero = additive_identity(elements, add)
    nonzero = [x for x in elements if x != zero]
    divisors: list[T] = []
    for a in nonzero:
        for b in nonzero:
            if mul(a, b) == zero:
                divisors.append(a)
                break
    return sorted(divisors)


def units(
    elements: list[T],
    add: Operation[T],
    mul: Operation[T],
) -> list[T]:
    if not is_ring(elements, add, mul):
        raise ValueError("elements and operations must form a ring")

    one = multiplicative_identity(elements, mul)
    if one is None:
        return []
    return sorted(
        x for x in elements if inverse_of(x, elements, mul) is not None
    )


def ring_report(
    elements: list[T],
    add: Operation[T],
    mul: Operation[T],
) -> dict[str, object]:
    if not is_ring(elements, add, mul):
        return {
            "order": len(elements),
            "is_ring": False,
            "is_commutative_ring": False,
            "additive_identity": None,
            "multiplicative_identity": None,
            "zero_divisors": [],
            "units": [],
        }

    return {
        "order": len(elements),
        "is_ring": True,
        "is_commutative_ring": is_commutative(elements, mul),
        "additive_identity": additive_identity(elements, add),
        "multiplicative_identity": multiplicative_identity(elements, mul),
        "zero_divisors": zero_divisors(elements, add, mul),
        "units": units(elements, add, mul),
    }


def ideal_report(
    subset: list[T],
    elements: list[T],
    add: Operation[T],
    mul: Operation[T],
) -> dict[str, object]:
    ideal_valid = is_ideal(subset, elements, add, mul)
    if not ideal_valid:
        return {
            "size": len(set(subset)),
            "is_ideal": False,
            "coset_reps": [],
            "quotient_order": 0,
            "quotient_is_ring": False,
        }

    reps = quotient_coset_reps(elements, subset, add, mul)
    return {
        "size": len(subset),
        "is_ideal": True,
        "coset_reps": reps,
        "quotient_order": len(reps),
        "quotient_is_ring": quotient_is_ring(elements, subset, add, mul),
    }


def main():
    z12 = residues_mod(12)
    z12_add = lambda a, b: add_mod(a, b, 12)
    z12_mul = lambda a, b: mul_mod(a, b, 12)

    print("Ring Z/12Z")
    print(ring_report(z12, z12_add, z12_mul))
    print()

    ideal_3 = principal_ideal(3, z12, z12_mul)
    print("Ideal (3) in Z/12Z =", ideal_3)
    print(ideal_report(ideal_3, z12, z12_add, z12_mul))
    print()

    z6 = residues_mod(6)
    z6_add = lambda a, b: add_mod(a, b, 6)
    z6_mul = lambda a, b: mul_mod(a, b, 6)

    print("Ring Z/6Z")
    print(ring_report(z6, z6_add, z6_mul))
    print()

    ideal_2 = principal_ideal(2, z6, z6_mul)
    print("Ideal (2) in Z/6Z =", ideal_2)
    print(ideal_report(ideal_2, z6, z6_add, z6_mul))


if __name__ == "__main__":
    main()
