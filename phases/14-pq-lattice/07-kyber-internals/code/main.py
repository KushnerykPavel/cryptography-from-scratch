"""
Kyber internals (toy, educational): polynomial multiplication via a twisted NTT
and Kyber-style coefficient compression.

Run:
  python3 code/main.py

This is an educational implementation to make the mechanics concrete.
It is not constant-time and not production-safe.
"""

from __future__ import annotations


Q = 3329
N = 256
N_HALF = 128

PSI_256 = 17
OMEGA_128 = pow(PSI_256, 2, Q)
INV_PSI_256 = pow(PSI_256, -1, Q)
INV_OMEGA_128 = pow(OMEGA_128, -1, Q)


def mod_q(x: int, q: int = Q) -> int:
    return x % q


def check_poly(poly: list[int], n: int, q: int = Q) -> None:
    if len(poly) != n:
        raise ValueError(f"expected polynomial of length {n}, got {len(poly)}")
    for c in poly:
        if not (0 <= c < q):
            raise ValueError("all coefficients must be reduced into [0, q)")


def poly_add(a: list[int], b: list[int], q: int = Q) -> list[int]:
    if len(a) != len(b):
        raise ValueError("polynomials must have the same length")
    return [(a[i] + b[i]) % q for i in range(len(a))]


def poly_sub(a: list[int], b: list[int], q: int = Q) -> list[int]:
    if len(a) != len(b):
        raise ValueError("polynomials must have the same length")
    return [(a[i] - b[i]) % q for i in range(len(a))]


def poly_mul_schoolbook_negacyclic(a: list[int], b: list[int], q: int = Q) -> list[int]:
    """
    Negacyclic convolution in Z_q[x] / (x^n + 1) for n = len(a) = len(b).

    Wrap rule: x^n = -1, so terms that wrap around pick up a sign flip.
    """

    if len(a) != len(b):
        raise ValueError("polynomials must have the same length")
    n = len(a)
    check_poly(a, n, q=q)
    check_poly(b, n, q=q)

    c = [0] * n
    for i in range(n):
        ai = a[i]
        if ai == 0:
            continue
        for j in range(n):
            bj = b[j]
            if bj == 0:
                continue
            k = i + j
            prod = (ai * bj) % q
            if k >= n:
                k -= n
                prod = (-prod) % q
            c[k] = (c[k] + prod) % q
    return c


def ntt_cyclic(a: list[int], q: int, root: int) -> list[int]:
    """
    Naive O(n^2) NTT over Z_q with a primitive n-th root `root`.

    This is not Kyber's fast in-place butterfly schedule; it's the math definition,
    kept small and explicit for learning.
    """

    n = len(a)
    check_poly(a, n, q=q)
    out = [0] * n
    for k in range(n):
        s = 0
        for j in range(n):
            s = (s + a[j] * pow(root, (j * k) % n, q)) % q
        out[k] = s
    return out


def intt_cyclic(a_ntt: list[int], q: int, root_inv: int) -> list[int]:
    n = len(a_ntt)
    check_poly(a_ntt, n, q=q)
    inv_n = pow(n, -1, q)

    out = [0] * n
    for j in range(n):
        s = 0
        for k in range(n):
            s = (s + a_ntt[k] * pow(root_inv, (j * k) % n, q)) % q
        out[j] = (s * inv_n) % q
    return out


def negacyclic_mul_128_via_twist(a: list[int], b: list[int], q: int = Q) -> list[int]:
    """
    Negacyclic multiplication in Z_q[y] / (y^128 + 1) using a "twisted" NTT:

      - pick psi of order 256 (so psi^128 = -1)
      - omega = psi^2 has order 128
      - twist:  a'_j = a_j * psi^j
      - cyclic NTT with omega:  A = NTT_omega(a')
      - pointwise multiply: C_k = A_k * B_k
      - untwist: c_j = INTT_omega(C)_j * psi^{-j}
    """

    check_poly(a, N_HALF, q=q)
    check_poly(b, N_HALF, q=q)

    a_tw = [(a[j] * pow(PSI_256, j, q)) % q for j in range(N_HALF)]
    b_tw = [(b[j] * pow(PSI_256, j, q)) % q for j in range(N_HALF)]

    a_ntt = ntt_cyclic(a_tw, q=q, root=OMEGA_128)
    b_ntt = ntt_cyclic(b_tw, q=q, root=OMEGA_128)
    c_ntt = [(a_ntt[i] * b_ntt[i]) % q for i in range(N_HALF)]
    c_tw = intt_cyclic(c_ntt, q=q, root_inv=INV_OMEGA_128)
    return [(c_tw[j] * pow(INV_PSI_256, j, q)) % q for j in range(N_HALF)]


def split_even_odd_256(poly: list[int], q: int = Q) -> tuple[list[int], list[int]]:
    check_poly(poly, N, q=q)
    even = [poly[2 * i] for i in range(N_HALF)]
    odd = [poly[2 * i + 1] for i in range(N_HALF)]
    return even, odd


def combine_even_odd_256(even: list[int], odd: list[int], q: int = Q) -> list[int]:
    check_poly(even, N_HALF, q=q)
    check_poly(odd, N_HALF, q=q)
    poly = [0] * N
    for i in range(N_HALF):
        poly[2 * i] = even[i]
        poly[2 * i + 1] = odd[i]
    return poly


def mul_by_y_in_mod_y128_plus_1(poly: list[int], q: int = Q) -> list[int]:
    """
    Multiply by y in Z_q[y] / (y^128 + 1):
      y * (a0 + a1 y + ... + a127 y^127)
        = (-a127) + a0 y + a1 y^2 + ... + a126 y^127
    """

    check_poly(poly, N_HALF, q=q)
    out = [0] * N_HALF
    out[0] = (-poly[-1]) % q
    for i in range(1, N_HALF):
        out[i] = poly[i - 1]
    return out


def poly_mul_kyber_style_ntt_256(a: list[int], b: list[int], q: int = Q) -> list[int]:
    """
    Multiply in R_q = Z_q[x] / (x^256 + 1) by splitting into even/odd parts:
      a(x) = a_e(y) + x * a_o(y),  y = x^2,  with y^128 = -1.

    Then multiplication reduces to negacyclic degree-128 multiplies in Z_q[y]/(y^128+1).
    """

    a_even, a_odd = split_even_odd_256(a, q=q)
    b_even, b_odd = split_even_odd_256(b, q=q)

    ee = negacyclic_mul_128_via_twist(a_even, b_even, q=q)
    oo = negacyclic_mul_128_via_twist(a_odd, b_odd, q=q)
    eo = negacyclic_mul_128_via_twist(a_even, b_odd, q=q)
    oe = negacyclic_mul_128_via_twist(a_odd, b_even, q=q)

    c_even = poly_add(ee, mul_by_y_in_mod_y128_plus_1(oo, q=q), q=q)
    c_odd = poly_add(eo, oe, q=q)
    return combine_even_odd_256(c_even, c_odd, q=q)


def compress_coeff(c: int, d: int, q: int = Q) -> int:
    if not (0 <= c < q):
        raise ValueError("coefficient must be reduced into [0, q)")
    if not (1 <= d <= 16):
        raise ValueError("d must be in [1, 16]")
    scale = 1 << d
    return ((c * scale + q // 2) // q) & (scale - 1)


def decompress_coeff(t: int, d: int, q: int = Q) -> int:
    if not (1 <= d <= 16):
        raise ValueError("d must be in [1, 16]")
    scale = 1 << d
    if not (0 <= t < scale):
        raise ValueError("compressed value out of range for d bits")
    return (t * q + scale // 2) // scale % q


def pack_bits(values: list[int], bits: int) -> bytes:
    if bits <= 0:
        raise ValueError("bits must be positive")
    mask = (1 << bits) - 1
    out = bytearray()
    acc = 0
    acc_bits = 0
    for v in values:
        if not (0 <= v <= mask):
            raise ValueError("value does not fit in requested bit width")
        acc |= (v & mask) << acc_bits
        acc_bits += bits
        while acc_bits >= 8:
            out.append(acc & 0xFF)
            acc >>= 8
            acc_bits -= 8
    if acc_bits:
        out.append(acc & 0xFF)
    return bytes(out)


def unpack_bits(data: bytes, bits: int, count: int) -> list[int]:
    if bits <= 0:
        raise ValueError("bits must be positive")
    if count < 0:
        raise ValueError("count must be non-negative")
    mask = (1 << bits) - 1

    values: list[int] = []
    acc = 0
    acc_bits = 0
    idx = 0
    while len(values) < count:
        while acc_bits < bits:
            if idx >= len(data):
                raise ValueError("not enough data to unpack requested count")
            acc |= data[idx] << acc_bits
            acc_bits += 8
            idx += 1
        values.append(acc & mask)
        acc >>= bits
        acc_bits -= bits
    return values


def compress_poly(coeffs: list[int], d: int, q: int = Q) -> bytes:
    for c in coeffs:
        if not (0 <= c < q):
            raise ValueError("all coefficients must be reduced into [0, q)")
    t = [compress_coeff(c, d=d, q=q) for c in coeffs]
    return pack_bits(t, bits=d)


def decompress_poly(data: bytes, d: int, count: int, q: int = Q) -> list[int]:
    t = unpack_bits(data, bits=d, count=count)
    return [decompress_coeff(x, d=d, q=q) for x in t]


def poly_max_abs_error(a: list[int], b: list[int], q: int = Q) -> int:
    if len(a) != len(b):
        raise ValueError("polynomials must have the same length")
    max_err = 0
    for i in range(len(a)):
        diff = (a[i] - b[i]) % q
        diff = min(diff, q - diff)
        if diff > max_err:
            max_err = diff
    return max_err


def sparse_poly_256(terms: list[tuple[int, int]], q: int = Q) -> list[int]:
    poly = [0] * N
    for idx, val in terms:
        if not (0 <= idx < N):
            raise ValueError("index out of range for degree-256 polynomial")
        poly[idx] = val % q
    return poly


def pretty_terms(poly: list[int], limit: int = 8) -> str:
    terms = []
    for i, c in enumerate(poly):
        if c % Q != 0:
            terms.append((i, c))
            if len(terms) >= limit:
                break
    if not terms:
        return "0"
    parts = []
    for i, c in terms:
        if i == 0:
            parts.append(str(c))
        elif i == 1:
            parts.append(f"{c}*x")
        else:
            parts.append(f"{c}*x^{i}")
    if sum(1 for c in poly if c != 0) > limit:
        parts.append("...")
    return " + ".join(parts)


def main() -> None:
    a = sparse_poly_256([(0, 1), (1, 2), (2, 3), (10, 1234), (255, Q - 1)])
    b = sparse_poly_256([(0, 5), (2, 7), (3, 11), (128, 42), (200, 1000)])

    print("=== Step 1: Ring arithmetic and schoolbook negacyclic multiplication ===")
    print("q =", Q, "n =", N, "modulus = x^256 + 1")
    print("a(x) =", pretty_terms(a))
    print("b(x) =", pretty_terms(b))
    c_school = poly_mul_schoolbook_negacyclic(a, b, q=Q)
    print("a*b (schoolbook) =", pretty_terms(c_school))

    print("\n=== Step 2: Twisted NTT for degree-128 negacyclic multiplication ===")
    print("Working in Z_q[y]/(y^128 + 1) with psi=17 (order 256) and omega=psi^2 (order 128).")
    a_even, _ = split_even_odd_256(a)
    b_even, _ = split_even_odd_256(b)
    c_even_ntt = negacyclic_mul_128_via_twist(a_even, b_even)
    c_even_school = poly_mul_schoolbook_negacyclic(a_even, b_even)
    print("even*even matches schoolbook =", c_even_ntt == c_even_school)

    print("\n=== Step 3: Kyber-style degree-256 multiplication via even/odd split ===")
    c_ntt = poly_mul_kyber_style_ntt_256(a, b, q=Q)
    print("a*b (NTT-based) =", pretty_terms(c_ntt))
    print("NTT-based matches schoolbook =", c_ntt == c_school)

    print("\n=== Step 4: Coefficient compression and bit packing ===")
    d = 4
    blob = compress_poly(c_ntt, d=d)
    c_decomp = decompress_poly(blob, d=d, count=len(c_ntt))
    print(f"compress d={d} bits: {len(c_ntt)} coeffs -> {len(blob)} bytes")
    print("max |error| after decompress =", poly_max_abs_error(c_ntt, c_decomp))
    print("first 8 coeffs original     =", c_ntt[:8])
    print("first 8 coeffs decompressed =", c_decomp[:8])


if __name__ == "__main__":
    main()

