import secrets


def mod_add(a: int, b: int, n: int) -> int:
    return (a + b) % n


def mod_sub(a: int, b: int, n: int) -> int:
    return (a - b) % n


def mod_mul(a: int, b: int, n: int) -> int:
    return (a * b) % n


def mod_pow(base: int, exp: int, n: int) -> int:
    if n == 1:
        return 0
    if exp < 0:
        raise ValueError("negative exponent requires modular inverse (lesson 03)")
    result = 1
    base = base % n
    while exp > 0:
        if exp & 1:
            result = (result * base) % n
        exp >>= 1
        base = (base * base) % n
    return result


def clock(n: int, marks):
    hits = {m % n for m in marks}
    for i in range(n):
        print(f"  {i:2d}: {'●' if i in hits else '·'}")


def main():
    n = 2**256 - 189
    for _ in range(1000):
        a = secrets.randbelow(n)
        k = secrets.randbelow(n)
        assert mod_pow(a, k, n) == pow(a, k, n)
    print("mod_pow agrees with pow() over 1000 random 256-bit inputs")
    print()
    print("clock(12, [7, 12, 17, 0]):")
    clock(12, [7, 12, 17, 0])


if __name__ == "__main__":
    main()
