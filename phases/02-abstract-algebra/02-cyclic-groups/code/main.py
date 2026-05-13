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


def is_prime(n: int) -> bool:
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False

    divisor = 3
    while divisor * divisor <= n:
        if n % divisor == 0:
            return False
        divisor += 2
    return True


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


def is_group(elements: list[T], operation: Operation[T]) -> bool:
    if len(elements) == 0:
        return False
    if len(set(elements)) != len(elements):
        return False
    if not is_closed(elements, operation):
        return False
    if not is_associative(elements, operation):
        return False
    return all(
        inverse_of(element, elements, operation) is not None for element in elements
    )


def repeat_operation(
    element: T, exponent: int, identity: T, operation: Operation[T]
) -> T:
    if exponent < 0:
        raise ValueError("exponent must be non-negative")

    result = identity
    base = element
    power = exponent

    while power > 0:
        if power % 2 == 1:
            result = operation(result, base)
        base = operation(base, base)
        power //= 2

    return result


def element_order(element: T, elements: list[T], operation: Operation[T]) -> int:
    if element not in set(elements):
        raise ValueError("element must be in the group")
    if not is_group(elements, operation):
        raise ValueError("elements and operation must form a group")

    identity = find_identity(elements, operation)
    current = identity

    for order in range(1, len(elements) + 1):
        current = operation(current, element)
        if current == identity:
            return order

    raise ValueError("element order not found")


def generated_subgroup(
    element: T, elements: list[T], operation: Operation[T]
) -> list[T]:
    if not is_group(elements, operation):
        raise ValueError("elements and operation must form a group")

    identity = find_identity(elements, operation)
    subgroup = [identity]
    current = identity

    for _ in range(element_order(element, elements, operation)):
        current = operation(current, element)
        if current != identity:
            subgroup.append(current)

    return subgroup


def is_generator(element: T, elements: list[T], operation: Operation[T]) -> bool:
    return len(generated_subgroup(element, elements, operation)) == len(elements)


def generators(elements: list[T], operation: Operation[T]) -> list[T]:
    if not is_group(elements, operation):
        raise ValueError("elements and operation must form a group")
    return [
        element for element in elements if is_generator(element, elements, operation)
    ]


def is_cyclic(elements: list[T], operation: Operation[T]) -> bool:
    return len(generators(elements, operation)) > 0


def primitive_roots_mod_prime(p: int) -> list[int]:
    if not is_prime(p):
        raise ValueError("modulus must be prime")

    elements = units_mod(p)
    operation = lambda a, b: mul_mod(a, b, p)
    return generators(elements, operation)


def discrete_log_bruteforce(
    base: T, target: T, elements: list[T], operation: Operation[T]
) -> int | None:
    if not is_group(elements, operation):
        raise ValueError("elements and operation must form a group")

    identity = find_identity(elements, operation)
    current = identity

    for exponent in range(len(elements)):
        if current == target:
            return exponent
        current = operation(current, base)

    return None


def cyclic_group_report(
    elements: list[T], operation: Operation[T]
) -> dict[str, object]:
    if not is_group(elements, operation):
        return {
            "order": len(elements),
            "identity": find_identity(elements, operation),
            "is_group": False,
            "is_cyclic": False,
            "generators": [],
            "element_orders": {},
        }

    return {
        "order": len(elements),
        "identity": find_identity(elements, operation),
        "is_group": True,
        "is_cyclic": is_cyclic(elements, operation),
        "generators": generators(elements, operation),
        "element_orders": {
            element: element_order(element, elements, operation) for element in elements
        },
    }


def main():
    z6 = residues_mod(6)
    z6_add = lambda a, b: add_mod(a, b, 6)
    print("Z/6Z under addition")
    print(cyclic_group_report(z6, z6_add))
    print("<2> =", generated_subgroup(2, z6, z6_add))
    print()

    u7 = units_mod(7)
    u7_mul = lambda a, b: mul_mod(a, b, 7)
    print("(Z/7Z)^* under multiplication")
    print(cyclic_group_report(u7, u7_mul))
    print("<3> =", generated_subgroup(3, u7, u7_mul))
    print("log_3(6) =", discrete_log_bruteforce(3, 6, u7, u7_mul))


if __name__ == "__main__":
    main()
