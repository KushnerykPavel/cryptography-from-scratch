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
    if element not in set(elements):
        raise ValueError("element must be in the group")
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


def is_subgroup(
    subset: list[T], elements: list[T], operation: Operation[T]
) -> bool:
    if len(subset) == 0:
        return False
    if len(set(subset)) != len(subset):
        return False
    if not set(subset).issubset(set(elements)):
        return False
    if not is_group(elements, operation):
        return False

    identity = find_identity(elements, operation)
    if identity not in set(subset):
        return False
    if not is_closed(subset, operation):
        return False
    return all(inverse_of(element, subset, operation) is not None for element in subset)


def left_coset(
    representative: T, subgroup: list[T], elements: list[T], operation: Operation[T]
) -> list[T]:
    if representative not in set(elements):
        raise ValueError("representative must be in the group")
    if not is_subgroup(subgroup, elements, operation):
        raise ValueError("subset must be a subgroup")

    return unique_in_order([operation(representative, h) for h in subgroup])


def right_coset(
    representative: T, subgroup: list[T], elements: list[T], operation: Operation[T]
) -> list[T]:
    if representative not in set(elements):
        raise ValueError("representative must be in the group")
    if not is_subgroup(subgroup, elements, operation):
        raise ValueError("subset must be a subgroup")

    return unique_in_order([operation(h, representative) for h in subgroup])


def unique_in_order(values: list[T]) -> list[T]:
    seen: set[T] = set()
    unique = []
    for value in values:
        if value not in seen:
            unique.append(value)
            seen.add(value)
    return unique


def canonical_set(values: list[T]) -> frozenset[T]:
    return frozenset(values)


def left_cosets(
    subgroup: list[T], elements: list[T], operation: Operation[T]
) -> list[list[T]]:
    if not is_subgroup(subgroup, elements, operation):
        raise ValueError("subset must be a subgroup")

    cosets: list[list[T]] = []
    seen: set[frozenset[T]] = set()
    for representative in elements:
        coset = left_coset(representative, subgroup, elements, operation)
        key = canonical_set(coset)
        if key not in seen:
            cosets.append(coset)
            seen.add(key)
    return cosets


def right_cosets(
    subgroup: list[T], elements: list[T], operation: Operation[T]
) -> list[list[T]]:
    if not is_subgroup(subgroup, elements, operation):
        raise ValueError("subset must be a subgroup")

    cosets: list[list[T]] = []
    seen: set[frozenset[T]] = set()
    for representative in elements:
        coset = right_coset(representative, subgroup, elements, operation)
        key = canonical_set(coset)
        if key not in seen:
            cosets.append(coset)
            seen.add(key)
    return cosets


def cosets_partition_group(
    cosets: list[list[T]], elements: list[T]
) -> bool:
    if not cosets:
        return False

    element_set = set(elements)
    covered: set[T] = set()
    for coset in cosets:
        coset_set = set(coset)
        if len(coset_set) != len(coset):
            return False
        if not coset_set.issubset(element_set):
            return False
        if covered.intersection(coset_set):
            return False
        covered.update(coset_set)
    return covered == element_set


def subgroup_index(
    subgroup: list[T], elements: list[T], operation: Operation[T]
) -> int:
    return len(left_cosets(subgroup, elements, operation))


def lagrange_holds(
    subgroup: list[T], elements: list[T], operation: Operation[T]
) -> bool:
    if not is_subgroup(subgroup, elements, operation):
        raise ValueError("subset must be a subgroup")
    return len(elements) % len(subgroup) == 0


def lagrange_report(
    subgroup: list[T], elements: list[T], operation: Operation[T]
) -> dict[str, object]:
    if not is_group(elements, operation):
        return {
            "group_order": len(elements),
            "subgroup_order": len(subgroup),
            "is_group": False,
            "is_subgroup": False,
            "index": None,
            "left_cosets": [],
            "partitions_group": False,
            "lagrange_holds": False,
        }

    subgroup_ok = is_subgroup(subgroup, elements, operation)
    if not subgroup_ok:
        return {
            "group_order": len(elements),
            "subgroup_order": len(subgroup),
            "is_group": True,
            "is_subgroup": False,
            "index": None,
            "left_cosets": [],
            "partitions_group": False,
            "lagrange_holds": False,
        }

    cosets = left_cosets(subgroup, elements, operation)
    return {
        "group_order": len(elements),
        "subgroup_order": len(subgroup),
        "is_group": True,
        "is_subgroup": True,
        "index": len(cosets),
        "left_cosets": cosets,
        "partitions_group": cosets_partition_group(cosets, elements),
        "lagrange_holds": lagrange_holds(subgroup, elements, operation),
    }


def possible_subgroup_orders(elements: list[T], operation: Operation[T]) -> list[int]:
    if not is_group(elements, operation):
        raise ValueError("elements and operation must form a group")
    return [d for d in range(1, len(elements) + 1) if len(elements) % d == 0]


def main():
    z12 = residues_mod(12)
    z12_add = lambda a, b: add_mod(a, b, 12)
    h = generated_subgroup(3, z12, z12_add)

    print("Z/12Z under addition")
    print("H = <3> =", h)
    print("left cosets =", left_cosets(h, z12, z12_add))
    print(lagrange_report(h, z12, z12_add))
    print()

    u8 = units_mod(8)
    u8_mul = lambda a, b: mul_mod(a, b, 8)
    k = generated_subgroup(3, u8, u8_mul)

    print("(Z/8Z)^* under multiplication")
    print("K = <3> =", k)
    print("left cosets =", left_cosets(k, u8, u8_mul))
    print(lagrange_report(k, u8, u8_mul))


if __name__ == "__main__":
    main()
