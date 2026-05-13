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


def units_mod(n: int) -> list[int]:
    if n <= 0:
        raise ValueError("modulus must be positive")
    return [a for a in range(n) if gcd(a, n) == 1]


def cayley_table(elements: list[T], operation: Operation[T]) -> list[list[T]]:
    return [[operation(a, b) for b in elements] for a in elements]


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


def find_identity(elements: list[T], operation: Operation[T]) -> T | None:
    for candidate in elements:
        if all(
            operation(candidate, x) == x and operation(x, candidate) == x
            for x in elements
        ):
            return candidate
    return None


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


def inverse_map(elements: list[T], operation: Operation[T]) -> dict[T, T] | None:
    inverses: dict[T, T] = {}
    for element in elements:
        inverse = inverse_of(element, elements, operation)
        if inverse is None:
            return None
        inverses[element] = inverse
    return inverses


def is_group(elements: list[T], operation: Operation[T]) -> bool:
    if len(elements) == 0:
        return False
    if len(set(elements)) != len(elements):
        return False
    if not is_closed(elements, operation):
        return False
    if not is_associative(elements, operation):
        return False
    if find_identity(elements, operation) is None:
        return False
    return inverse_map(elements, operation) is not None


def element_order(element: T, elements: list[T], operation: Operation[T]) -> int:
    if not is_group(elements, operation):
        raise ValueError("elements and operation must form a group")

    identity = find_identity(elements, operation)
    current = element

    for order in range(1, len(elements) + 1):
        if current == identity:
            return order
        current = operation(current, element)

    raise ValueError("element order not found")


def group_report(elements: list[T], operation: Operation[T]) -> dict[str, object]:
    identity = find_identity(elements, operation)
    inverses = inverse_map(elements, operation)
    orders: dict[T, int] = {}

    if is_group(elements, operation):
        orders = {
            element: element_order(element, elements, operation) for element in elements
        }

    return {
        "order": len(elements),
        "closed": is_closed(elements, operation),
        "associative": is_associative(elements, operation),
        "identity": identity,
        "inverses": inverses,
        "element_orders": orders,
        "is_group": is_group(elements, operation),
    }


def main():
    z5 = residues_mod(5)
    z5_add = lambda a, b: add_mod(a, b, 5)
    print("Z/5Z under addition")
    print(group_report(z5, z5_add))
    print(cayley_table(z5, z5_add))
    print()

    u8 = units_mod(8)
    u8_mul = lambda a, b: mul_mod(a, b, 8)
    print("(Z/8Z)^* under multiplication")
    print(group_report(u8, u8_mul))
    print(cayley_table(u8, u8_mul))


if __name__ == "__main__":
    main()
