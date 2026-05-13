def gcd(a: int, b: int) -> int:
    a = abs(a)
    b = abs(b)
    while b != 0:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    if a == 0 and b == 0:
        return 0, 0, 0

    old_r, r = abs(a), abs(b)
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t

    if a < 0:
        old_s = -old_s
    if b < 0:
        old_t = -old_t

    return old_r, old_s, old_t


def main():
    samples = [(240, 46), (35, 15), (-99, 78), (0, 13), (0, 0)]
    for a, b in samples:
        g, s, t = extended_gcd(a, b)
        print(f"a={a}, b={b}")
        print(f"  gcd(a, b) = {gcd(a, b)}")
        print(f"  extended_gcd(a, b) = (g={g}, s={s}, t={t})")
        print(f"  check: {s}*{a} + {t}*{b} = {s * a + t * b}")
        print()


if __name__ == "__main__":
    main()
