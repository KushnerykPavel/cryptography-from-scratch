from math import ceil, gcd, isqrt, log2


def is_prime_trial(n: int) -> bool:
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    d = 3
    while d * d <= n:
        if n % d == 0:
            return False
        d += 2
    return True


def integer_nth_root(value: int, degree: int) -> int:
    if value < 0:
        raise ValueError("value must be non-negative")
    if degree <= 0:
        raise ValueError("degree must be positive")
    if value in (0, 1):
        return value

    low = 1
    high = value
    answer = 1
    while low <= high:
        mid = (low + high) // 2
        power = mid**degree
        if power == value:
            return mid
        if power < value:
            answer = mid
            low = mid + 1
        else:
            high = mid - 1
    return answer


def is_perfect_power(n: int) -> bool:
    if n < 2:
        return False

    max_degree = n.bit_length()
    for degree in range(2, max_degree + 1):
        root = integer_nth_root(n, degree)
        if root**degree == n:
            return True
    return False


def euler_totient(n: int) -> int:
    if n <= 0:
        raise ValueError("n must be positive")

    result = n
    factor = 2
    remaining = n
    while factor * factor <= remaining:
        if remaining % factor == 0:
            while remaining % factor == 0:
                remaining //= factor
            result -= result // factor
        factor = 3 if factor == 2 else factor + 2
    if remaining > 1:
        result -= result // remaining
    return result


def multiplicative_order_mod(n: int, r: int) -> int:
    if r <= 1:
        raise ValueError("r must be greater than 1")
    if gcd(n, r) != 1:
        raise ValueError("n and r must be coprime")

    value = n % r
    order = 1
    while value != 1:
        value = (value * n) % r
        order += 1
    return order


def aks_order_threshold(n: int) -> int:
    if n < 2:
        raise ValueError("n must be at least 2")
    return ceil(log2(n) ** 2)


def find_smallest_r(n: int) -> int:
    if n < 2:
        raise ValueError("n must be at least 2")

    threshold = aks_order_threshold(n)
    r = 2
    while True:
        if gcd(n, r) == 1 and multiplicative_order_mod(n, r) > threshold:
            return r
        r += 1


def smallest_factor_up_to(n: int, limit: int) -> int | None:
    if n % 2 == 0:
        return 2 if limit >= 2 and n != 2 else None

    d = 3
    bound = min(limit, isqrt(n))
    while d <= bound:
        if n % d == 0:
            return d
        d += 2
    return None


def poly_mul_mod(left: list[int], right: list[int], modulus: int, r: int) -> list[int]:
    if modulus <= 0:
        raise ValueError("modulus must be positive")
    if r <= 0:
        raise ValueError("r must be positive")

    result = [0] * r
    for i, left_coeff in enumerate(left[:r]):
        if left_coeff == 0:
            continue
        for j, right_coeff in enumerate(right[:r]):
            if right_coeff == 0:
                continue
            index = (i + j) % r
            result[index] = (result[index] + left_coeff * right_coeff) % modulus
    return result


def poly_pow_mod(base: list[int], exponent: int, modulus: int, r: int) -> list[int]:
    if exponent < 0:
        raise ValueError("exponent must be non-negative")

    result = [0] * r
    result[0] = 1 % modulus
    power = [coefficient % modulus for coefficient in base[:r]]
    if len(power) < r:
        power.extend([0] * (r - len(power)))

    while exponent > 0:
        if exponent & 1:
            result = poly_mul_mod(result, power, modulus, r)
        exponent >>= 1
        if exponent:
            power = poly_mul_mod(power, power, modulus, r)
    return result


def aks_target_polynomial(n: int, r: int, a: int) -> list[int]:
    target = [0] * r
    target[0] = a % n
    target[n % r] = (target[n % r] + 1) % n
    return target


def aks_congruence_holds(n: int, r: int, a: int) -> bool:
    base = [0] * r
    base[0] = a % n
    base[1 % r] = (base[1 % r] + 1) % n
    return poly_pow_mod(base, n, n, r) == aks_target_polynomial(n, r, a)


def aks_witness_limit(n: int, r: int) -> int:
    return max(1, isqrt(euler_totient(r)) * ceil(log2(n)))


def aks_primality_test(n: int) -> bool:
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if is_perfect_power(n):
        return False

    r = find_smallest_r(n)
    factor = smallest_factor_up_to(n, r)
    if factor is not None and factor < n:
        return False
    if n <= r:
        return True

    limit = aks_witness_limit(n, r)
    for a in range(1, limit + 1):
        if not aks_congruence_holds(n, r, a):
            return False
    return True


def certificate_route(n: int) -> str:
    if n < 2:
        return "neither-prime-nor-composite"
    if not aks_primality_test(n):
        return "composite"
    if n < 10_000:
        return "prime-by-aks-toy-check"
    return "prime-use-ecpp-or-library-certification"


def main() -> None:
    for candidate in [31, 64, 91, 97]:
        print(
            f"{candidate}: perfect_power={is_perfect_power(candidate)} "
            f"r={find_smallest_r(candidate)} aks={aks_primality_test(candidate)}"
        )
    print()

    for candidate in [31, 91, 97, 127]:
        print(f"{candidate}: {certificate_route(candidate)}")


if __name__ == "__main__":
    main()
