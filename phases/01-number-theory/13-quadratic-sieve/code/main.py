from math import gcd, isqrt


def ceil_sqrt(n: int) -> int:
    if n < 0:
        raise ValueError("n must be non-negative")
    root = isqrt(n)
    return root if root * root == n else root + 1


def is_square(n: int) -> bool:
    if n < 0:
        return False
    root = isqrt(n)
    return root * root == n


def primes_up_to(limit: int) -> list[int]:
    if limit < 2:
        return []

    sieve = [True] * (limit + 1)
    sieve[0] = False
    sieve[1] = False
    for p in range(2, isqrt(limit) + 1):
        if sieve[p]:
            for multiple in range(p * p, limit + 1, p):
                sieve[multiple] = False
    return [p for p, prime in enumerate(sieve) if prime]


def legendre_symbol(a: int, p: int) -> int:
    if p < 2:
        raise ValueError("p must be prime")
    if p == 2:
        return a % 2

    value = pow(a % p, (p - 1) // 2, p)
    if value == p - 1:
        return -1
    return value


def tonelli_shanks(n: int, p: int) -> int | None:
    if p == 2:
        return n % 2
    if p < 2 or p % 2 == 0:
        raise ValueError("p must be an odd prime")
    if legendre_symbol(n, p) != 1:
        return None
    if p % 4 == 3:
        return pow(n, (p + 1) // 4, p)

    q = p - 1
    s = 0
    while q % 2 == 0:
        s += 1
        q //= 2

    z = 2
    while legendre_symbol(z, p) != -1:
        z += 1

    m = s
    c = pow(z, q, p)
    t = pow(n, q, p)
    r = pow(n, (q + 1) // 2, p)

    while t != 1:
        i = 1
        probe = pow(t, 2, p)
        while probe != 1:
            probe = pow(probe, 2, p)
            i += 1
            if i == m:
                return None

        b = pow(c, 1 << (m - i - 1), p)
        m = i
        c = (b * b) % p
        t = (t * c) % p
        r = (r * b) % p

    return r


def factor_base(n: int, bound: int) -> list[int]:
    if n <= 1:
        raise ValueError("n must be greater than 1")
    if bound < 2:
        raise ValueError("bound must be at least 2")

    base = []
    for p in primes_up_to(bound):
        if p == 2:
            base.append(p)
        elif n % p != 0 and legendre_symbol(n, p) == 1:
            base.append(p)
    return base


def roots_for_factor_base(n: int, base: list[int]) -> dict[int, tuple[int, ...]]:
    roots = {}
    for p in base:
        root = tonelli_shanks(n, p)
        if root is None:
            continue
        roots[p] = tuple(sorted({root % p, (-root) % p}))
    return roots


def factor_over_base(value: int, base: list[int]) -> list[int] | None:
    if value == 0:
        return None

    remaining = abs(value)
    exponents = []
    for p in base:
        exponent = 0
        while remaining % p == 0:
            remaining //= p
            exponent += 1
        exponents.append(exponent)

    if remaining != 1:
        return None
    return exponents


def parity_vector(exponents: list[int]) -> int:
    vector = 0
    for i, exponent in enumerate(exponents):
        if exponent % 2 == 1:
            vector |= 1 << i
    return vector


def collect_relations(n: int, bound: int, interval: int) -> list[dict[str, object]]:
    if interval <= 0:
        raise ValueError("interval must be positive")

    base = factor_base(n, bound)
    start = ceil_sqrt(n)
    relations = []

    for x in range(start, start + interval):
        qx = x * x - n
        exponents = factor_over_base(qx, base)
        if exponents is None:
            continue
        relations.append(
            {
                "x": x,
                "qx": qx,
                "exponents": exponents,
                "parity": parity_vector(exponents),
            }
        )
    return relations


def dependency_masks(vectors: list[int]) -> list[int]:
    basis: dict[int, tuple[int, int]] = {}
    masks = []

    for row, vector in enumerate(vectors):
        reduced = vector
        mask = 1 << row

        while reduced:
            pivot = reduced.bit_length() - 1
            if pivot not in basis:
                basis[pivot] = (reduced, mask)
                break
            basis_vector, basis_mask = basis[pivot]
            reduced ^= basis_vector
            mask ^= basis_mask

        if reduced == 0 and mask != 0:
            masks.append(mask)

    return masks


def mask_indices(mask: int) -> list[int]:
    return [i for i in range(mask.bit_length()) if (mask >> i) & 1]


def build_congruence(
    n: int, base: list[int], relations: list[dict[str, object]], indices: list[int]
) -> tuple[int, int]:
    x_value = 1
    exponent_sums = [0] * len(base)

    for index in indices:
        relation = relations[index]
        x_value = (x_value * int(relation["x"])) % n
        for i, exponent in enumerate(relation["exponents"]):
            exponent_sums[i] += int(exponent)

    y_value = 1
    for p, exponent in zip(base, exponent_sums):
        y_value = (y_value * pow(p, exponent // 2, n)) % n

    return x_value, y_value


def extract_factor(n: int, x_value: int, y_value: int) -> int | None:
    for candidate in (gcd(abs(x_value - y_value), n), gcd((x_value + y_value) % n, n)):
        if 1 < candidate < n:
            return candidate
    return None


def factor_pair(n: int, factor: int | None) -> tuple[int, int] | None:
    if factor is None or factor <= 1 or factor >= n or n % factor != 0:
        return None
    other = n // factor
    return (factor, other) if factor <= other else (other, factor)


def quadratic_sieve(
    n: int, bound: int = 50, interval: int = 1_000
) -> tuple[int, int] | None:
    if n <= 1:
        raise ValueError("n must be greater than 1")
    if bound < 2:
        raise ValueError("bound must be at least 2")
    if interval <= 0:
        raise ValueError("interval must be positive")
    if n % 2 == 0:
        return (2, n // 2)
    if is_square(n):
        root = isqrt(n)
        return factor_pair(n, root)

    for p in primes_up_to(bound):
        shared = gcd(n, p)
        if 1 < shared < n:
            return factor_pair(n, shared)

    base = factor_base(n, bound)
    relations = collect_relations(n, bound, interval)
    vectors = [int(relation["parity"]) for relation in relations]

    for mask in dependency_masks(vectors):
        indices = mask_indices(mask)
        if not indices:
            continue
        x_value, y_value = build_congruence(n, base, relations, indices)
        factor = extract_factor(n, x_value, y_value)
        pair = factor_pair(n, factor)
        if pair is not None:
            return pair

    return None


def main() -> None:
    examples = [91, 1649, 2491, 10_403]
    for n in examples:
        print(f"{n}: {quadratic_sieve(n, bound=50, interval=500)}")

    n = 1649
    base = factor_base(n, 30)
    relations = collect_relations(n, 30, 100)
    print(f"factor base for {n}: {base}")
    print(f"first relations: {relations[:4]}")


if __name__ == "__main__":
    main()
