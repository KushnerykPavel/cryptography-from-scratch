from math import gcd
from typing import Callable, Hashable, TypeVar

T = TypeVar("T", bound=Hashable)
U = TypeVar("U", bound=Hashable)
Operation = Callable[[T, T], T]
Map = Callable[[T], U]


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


def unique_in_order(values: list[T]) -> list[T]:
    seen: set[T] = set()
    unique = []
    for value in values:
        if value not in seen:
            unique.append(value)
            seen.add(value)
    return unique


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

    while True:
        current = operation(current, element)
        if current == identity:
            return subgroup
        subgroup.append(current)


def is_homomorphism(
    domain_elements: list[T],
    codomain_elements: list[U],
    domain_operation: Operation[T],
    codomain_operation: Operation[U],
    mapping: Map[T, U],
) -> bool:
    if not is_group(domain_elements, domain_operation):
        return False
    if not is_group(codomain_elements, codomain_operation):
        return False

    codomain_set = set(codomain_elements)
    for element in domain_elements:
        if mapping(element) not in codomain_set:
            return False

    return all(
        mapping(domain_operation(a, b)) == codomain_operation(mapping(a), mapping(b))
        for a in domain_elements
        for b in domain_elements
    )


def mapping_table(domain_elements: list[T], mapping: Map[T, U]) -> dict[T, U]:
    return {element: mapping(element) for element in domain_elements}


def image(
    domain_elements: list[T],
    codomain_elements: list[U],
    domain_operation: Operation[T],
    codomain_operation: Operation[U],
    mapping: Map[T, U],
) -> list[U]:
    if not is_homomorphism(
        domain_elements,
        codomain_elements,
        domain_operation,
        codomain_operation,
        mapping,
    ):
        raise ValueError("mapping must be a homomorphism")
    return unique_in_order([mapping(element) for element in domain_elements])


def kernel(
    domain_elements: list[T],
    codomain_elements: list[U],
    domain_operation: Operation[T],
    codomain_operation: Operation[U],
    mapping: Map[T, U],
) -> list[T]:
    if not is_homomorphism(
        domain_elements,
        codomain_elements,
        domain_operation,
        codomain_operation,
        mapping,
    ):
        raise ValueError("mapping must be a homomorphism")

    codomain_identity = find_identity(codomain_elements, codomain_operation)
    return [
        element
        for element in domain_elements
        if mapping(element) == codomain_identity
    ]


def is_injective_homomorphism(
    domain_elements: list[T],
    codomain_elements: list[U],
    domain_operation: Operation[T],
    codomain_operation: Operation[U],
    mapping: Map[T, U],
) -> bool:
    if not is_homomorphism(
        domain_elements,
        codomain_elements,
        domain_operation,
        codomain_operation,
        mapping,
    ):
        return False

    values = [mapping(element) for element in domain_elements]
    return len(values) == len(set(values))


def is_surjective_homomorphism(
    domain_elements: list[T],
    codomain_elements: list[U],
    domain_operation: Operation[T],
    codomain_operation: Operation[U],
    mapping: Map[T, U],
) -> bool:
    if not is_homomorphism(
        domain_elements,
        codomain_elements,
        domain_operation,
        codomain_operation,
        mapping,
    ):
        return False
    return set(
        image(
            domain_elements,
            codomain_elements,
            domain_operation,
            codomain_operation,
            mapping,
        )
    ) == set(codomain_elements)


def is_isomorphism(
    domain_elements: list[T],
    codomain_elements: list[U],
    domain_operation: Operation[T],
    codomain_operation: Operation[U],
    mapping: Map[T, U],
) -> bool:
    return is_injective_homomorphism(
        domain_elements,
        codomain_elements,
        domain_operation,
        codomain_operation,
        mapping,
    ) and is_surjective_homomorphism(
        domain_elements,
        codomain_elements,
        domain_operation,
        codomain_operation,
        mapping,
    )


def inverse_isomorphism_table(
    domain_elements: list[T],
    codomain_elements: list[U],
    domain_operation: Operation[T],
    codomain_operation: Operation[U],
    mapping: Map[T, U],
) -> dict[U, T]:
    if not is_isomorphism(
        domain_elements,
        codomain_elements,
        domain_operation,
        codomain_operation,
        mapping,
    ):
        raise ValueError("mapping must be an isomorphism")
    return {mapping(element): element for element in domain_elements}


def first_isomorphism_size_check(
    domain_elements: list[T],
    codomain_elements: list[U],
    domain_operation: Operation[T],
    codomain_operation: Operation[U],
    mapping: Map[T, U],
) -> bool:
    return len(domain_elements) == len(
        kernel(
            domain_elements,
            codomain_elements,
            domain_operation,
            codomain_operation,
            mapping,
        )
    ) * len(
        image(
            domain_elements,
            codomain_elements,
            domain_operation,
            codomain_operation,
            mapping,
        )
    )


def preserves_repetition(
    element: T,
    exponent: int,
    domain_elements: list[T],
    codomain_elements: list[U],
    domain_operation: Operation[T],
    codomain_operation: Operation[U],
    mapping: Map[T, U],
) -> bool:
    if not is_homomorphism(
        domain_elements,
        codomain_elements,
        domain_operation,
        codomain_operation,
        mapping,
    ):
        raise ValueError("mapping must be a homomorphism")
    if element not in set(domain_elements):
        raise ValueError("element must be in the domain")

    domain_identity = find_identity(domain_elements, domain_operation)
    codomain_identity = find_identity(codomain_elements, codomain_operation)
    domain_power = repeat_operation(element, exponent, domain_identity, domain_operation)
    codomain_power = repeat_operation(
        mapping(element),
        exponent,
        codomain_identity,
        codomain_operation,
    )
    return mapping(domain_power) == codomain_power


def homomorphism_report(
    domain_elements: list[T],
    codomain_elements: list[U],
    domain_operation: Operation[T],
    codomain_operation: Operation[U],
    mapping: Map[T, U],
) -> dict[str, object]:
    domain_is_group = is_group(domain_elements, domain_operation)
    codomain_is_group = is_group(codomain_elements, codomain_operation)
    hom = is_homomorphism(
        domain_elements,
        codomain_elements,
        domain_operation,
        codomain_operation,
        mapping,
    )

    if not hom:
        return {
            "domain_order": len(domain_elements),
            "codomain_order": len(codomain_elements),
            "domain_is_group": domain_is_group,
            "codomain_is_group": codomain_is_group,
            "is_homomorphism": False,
            "table": mapping_table(domain_elements, mapping),
            "kernel": [],
            "image": [],
            "injective": False,
            "surjective": False,
            "isomorphism": False,
            "first_isomorphism_size_check": False,
        }

    return {
        "domain_order": len(domain_elements),
        "codomain_order": len(codomain_elements),
        "domain_is_group": True,
        "codomain_is_group": True,
        "is_homomorphism": True,
        "table": mapping_table(domain_elements, mapping),
        "kernel": kernel(
            domain_elements,
            codomain_elements,
            domain_operation,
            codomain_operation,
            mapping,
        ),
        "image": image(
            domain_elements,
            codomain_elements,
            domain_operation,
            codomain_operation,
            mapping,
        ),
        "injective": is_injective_homomorphism(
            domain_elements,
            codomain_elements,
            domain_operation,
            codomain_operation,
            mapping,
        ),
        "surjective": is_surjective_homomorphism(
            domain_elements,
            codomain_elements,
            domain_operation,
            codomain_operation,
            mapping,
        ),
        "isomorphism": is_isomorphism(
            domain_elements,
            codomain_elements,
            domain_operation,
            codomain_operation,
            mapping,
        ),
        "first_isomorphism_size_check": first_isomorphism_size_check(
            domain_elements,
            codomain_elements,
            domain_operation,
            codomain_operation,
            mapping,
        ),
    }


def main():
    z12 = residues_mod(12)
    z4 = residues_mod(4)
    z12_add = lambda a, b: add_mod(a, b, 12)
    z4_add = lambda a, b: add_mod(a, b, 4)
    reduce_to_z4 = lambda x: x % 4

    print("Z/12Z -> Z/4Z by x mod 4")
    print(homomorphism_report(z12, z4, z12_add, z4_add, reduce_to_z4))
    print()

    z5 = residues_mod(5)
    h = generated_subgroup(3, units_mod(11), lambda a, b: mul_mod(a, b, 11))
    z5_add = lambda a, b: add_mod(a, b, 5)
    h_mul = lambda a, b: mul_mod(a, b, 11)
    exponent_map = lambda k: pow(3, k, 11)

    print("Z/5Z -> <3> in (Z/11Z)^* by k -> 3^k")
    print(homomorphism_report(z5, h, z5_add, h_mul, exponent_map))


if __name__ == "__main__":
    main()
