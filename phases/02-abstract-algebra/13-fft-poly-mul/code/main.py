from __future__ import annotations

import math


def next_power_of_two(n: int) -> int:
    if n < 1:
        raise ValueError("n must be positive")
    p = 1
    while p < n:
        p <<= 1
    return p


def require_power_of_two(n: int) -> None:
    if n < 1 or (n & (n - 1)) != 0:
        raise ValueError("n must be a power of two")


def bit_reverse_permute(a: list[complex]) -> None:
    n = len(a)
    j = 0
    for i in range(1, n):
        bit = n >> 1
        while j & bit:
            j ^= bit
            bit >>= 1
        j ^= bit
        if i < j:
            a[i], a[j] = a[j], a[i]


def fft_inplace(a: list[complex], invert: bool) -> None:
    n = len(a)
    require_power_of_two(n)

    bit_reverse_permute(a)

    length = 2
    while length <= n:
        angle = 2.0 * math.pi / length
        if not invert:
            angle = -angle
        wlen = complex(math.cos(angle), math.sin(angle))
        half = length // 2
        for i in range(0, n, length):
            w = 1.0 + 0.0j
            for j in range(half):
                u = a[i + j]
                v = a[i + j + half] * w
                a[i + j] = u + v
                a[i + j + half] = u - v
                w *= wlen
        length *= 2


def ifft_inplace(a: list[complex]) -> None:
    n = len(a)
    fft_inplace(a, invert=True)
    inv_n = 1.0 / n
    for i in range(n):
        a[i] *= inv_n


def fft(a: list[complex]) -> list[complex]:
    out = list(a)
    fft_inplace(out, invert=False)
    return out


def ifft(a: list[complex]) -> list[complex]:
    out = list(a)
    ifft_inplace(out)
    return out


def poly_mul_naive(a: list[int], b: list[int]) -> list[int]:
    if not a or not b:
        raise ValueError("inputs must be non-empty")
    out = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            out[i + j] += x * y
    return out


def poly_mul_fft(a: list[int], b: list[int]) -> list[int]:
    if not a or not b:
        raise ValueError("inputs must be non-empty")

    out_len = len(a) + len(b) - 1
    n = next_power_of_two(out_len)

    fa = [complex(x, 0.0) for x in a] + [0.0j] * (n - len(a))
    fb = [complex(x, 0.0) for x in b] + [0.0j] * (n - len(b))

    fft_inplace(fa, invert=False)
    fft_inplace(fb, invert=False)
    for i in range(n):
        fa[i] *= fb[i]
    ifft_inplace(fa)

    return [int(round(fa[i].real)) for i in range(out_len)]


def circular_convolution_fft(a: list[int], b: list[int], n: int) -> list[int]:
    require_power_of_two(n)
    if not a or not b:
        raise ValueError("inputs must be non-empty")
    if len(a) > n or len(b) > n:
        raise ValueError("inputs longer than n")

    fa = [complex(x, 0.0) for x in a] + [0.0j] * (n - len(a))
    fb = [complex(x, 0.0) for x in b] + [0.0j] * (n - len(b))

    fft_inplace(fa, invert=False)
    fft_inplace(fb, invert=False)
    for i in range(n):
        fa[i] *= fb[i]
    ifft_inplace(fa)

    return [int(round(fa[i].real)) for i in range(n)]


def main() -> None:
    a = [1, 2, 3]
    b = [4, 5]
    print("=== FFT polynomial multiplication demo ===")
    print(f"a: {a}")
    print(f"b: {b}")
    print(f"a*b (fft):   {poly_mul_fft(a, b)}")
    print(f"a*b (naive): {poly_mul_naive(a, b)}")

    print()
    print("=== Padding pitfall demo (circular vs linear) ===")
    a2 = [1, 1, 1]
    b2 = [1, 1, 1]
    print(f"a: {a2}")
    print(f"b: {b2}")
    print(f"linear product:   {poly_mul_naive(a2, b2)}")
    print(f"circular (n=4):   {circular_convolution_fft(a2, b2, n=4)}")


if __name__ == "__main__":
    main()
