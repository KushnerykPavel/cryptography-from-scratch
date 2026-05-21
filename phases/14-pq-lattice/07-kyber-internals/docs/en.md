# Kyber Internals — NTT & Compression
> Split, twist, transform: multiplication and compression are Kyber’s hidden engines.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** `phases/14-pq-lattice/06-kyber-ml-kem/`, `phases/02-abstract-algebra/09-polynomial-rings/`, `phases/02-abstract-algebra/13-fft-poly-mul/`  
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain why Kyber uses polynomial arithmetic modulo `x^256 + 1` (negacyclic) and what “wrap with a sign flip” means
- Compute a negacyclic schoolbook product in `R_q = Z_q[x]/(x^256 + 1)` with `q=3329`
- Implement a twisted NTT to multiply in `Z_q[y]/(y^128 + 1)` and use it as a building block
- Distinguish cyclic convolution (`x^n - 1`) from negacyclic convolution (`x^n + 1`) and how a “twist” bridges them
- Apply Kyber-style coefficient compression + bit packing and quantify the rounding error it introduces

## The Problem

Kyber / ML-KEM looks clean on paper: “just” multiply polynomials in a ring, add noise, and pack bits. But the actual engineering pain is in the *internals*: how do you multiply polynomials fast enough, and how do you shrink ciphertexts without breaking decryption?

If you implement ring multiplication naively, it works (and it’s great for learning), but it’s too slow for production and it obscures what real implementations do. If you implement compression/packing incorrectly (bit order, rounding, coefficient ranges), you can get ciphertexts that “almost” work — until decapsulation starts failing, or worse, starts leaking information through error behavior or timing.

This lesson isolates the two “quiet heroes” inside Kyber:
1) **NTT-based multiplication** (how `O(n^2)` becomes closer to `O(n log n)`), and  
2) **Lossy compression** (how 12-bit coefficients become 4–11 bits while staying decryptable).

## The Concept

### The ring you’re in
Kyber works in:

`R_q = Z_q[x] / (x^256 + 1)` with `q = 3329`.

That modulus (`x^256 + 1`) means:

`x^256 = -1`.

So when you multiply two polynomials and a term “wraps” past degree 255, it comes back around with a **sign flip**.

### Cyclic vs negacyclic convolution (the common gotcha)

| Modulus | Convolution type | Wrap rule |
|---|---|---|
| `x^n - 1` | cyclic | `x^n = 1` (wrap with **no** sign flip) |
| `x^n + 1` | negacyclic | `x^n = -1` (wrap with a **sign flip**) |

Kyber is **negacyclic**.

### The “twisted NTT” trick in one sentence
To multiply modulo `(y^128 + 1)`, we:

1) multiply coefficients by powers of a special element `psi` (the **twist**),  
2) run an NTT that is only for cyclic convolution,  
3) undo the twist.

Concretely, for Kyber parameters we can choose:
- `psi = 17` which has order `256` modulo `q=3329` (so `psi^128 = -1`)
- `omega = psi^2` which has order `128`

That’s exactly what we need for a degree-128 negacyclic multiply in `Z_q[y]/(y^128 + 1)`.

### Why we can use degree 128 at all (the even/odd split)
We still want to multiply degree-256 polynomials in `x`. The cute algebraic move is:

Let `y = x^2`. Write any `a(x)` as:

`a(x) = a_e(y) + x·a_o(y)`

where `a_e` holds the even coefficients and `a_o` holds the odd coefficients.

Then the product becomes:

`a(x)·b(x) = (a_e b_e + y·a_o b_o) + x·(a_e b_o + a_o b_e)`  in `Z_q[y]/(y^128 + 1)`

So a degree-256 multiply reduces to a handful of degree-128 negacyclic multiplies plus adds/shifts.

### Compression is deliberate information loss
Kyber coefficients live in `[0, q)` (about 12 bits). To save bytes, we compress each coefficient to `d` bits:

`t = round(2^d · c / q)`  (so `t` fits in `[0, 2^d)`).

Decompression maps back approximately:

`c' = round(q · t / 2^d)`

The difference `|c' - c|` is the “quantization error”; smaller `d` means bigger error.

## Build It

### Step 1: Ring arithmetic + schoolbook negacyclic multiplication
```python
Q = 3329
N = 256
N_HALF = 128


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
```

This is the “truth” implementation: it directly encodes `x^n = -1`. It’s slow for big `n`, but it’s the best place to debug your understanding of the ring.

### Step 2: A twisted NTT for degree-128 negacyclic multiplication
```python
PSI_256 = 17
OMEGA_128 = pow(PSI_256, 2, Q)
INV_PSI_256 = pow(PSI_256, -1, Q)
INV_OMEGA_128 = pow(OMEGA_128, -1, Q)


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
```

This step is the conceptual heart of Kyber’s NTT story: a negacyclic multiply becomes “twist → cyclic NTT → pointwise multiply → inverse NTT → untwist”.

### Step 3: Degree-256 multiplication via even/odd split
```python
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
```

This is the “structural” trick: you reuse the 128-degree negacyclic multiply as a subroutine to get the full 256-degree multiply in Kyber’s ring.

### Step 4: Coefficient compression + bit packing
```python
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
```

Compression is a controlled rounding step. Packing is pure bit plumbing — but it’s also where many “it works on my machine” bugs are born (endianness, off-by-one counts, mismatched `d`).

Run it:
`python3 code/main.py`

## Use It

Real implementations do the same logical steps, but optimized and constant-time:

- **CRYSTALS-Kyber / ML-KEM reference (C):** fixed-size, constant-time-ish modular arithmetic, precomputed twiddle factors, and carefully tuned compression/packing.
- **PQClean:** “clean C” implementations that aim to be readable and portable (often used as a reference baseline).
- **liboqs:** a production-oriented library exposing standardized KEMs with constant-time primitives and platform optimizations.

If you read production code, map the names:
- “NTT” is the same transform, just implemented as an in-place butterfly schedule with precomputed constants.
- “basemul” is the “pointwise multiply in the transform domain” step.
- “compress/polycompress” is our `compress_poly` + `pack_bits` logic specialized to Kyber’s exact `d` values and byte layout.

## Pitfalls

1. **Mixing cyclic and negacyclic multiplication**  
   Using an NTT that computes modulo `x^n - 1` when you need `x^n + 1` silently produces the wrong ring product.

2. **Forgetting the twist (or using the wrong root)**  
   The twist depends on `psi^128 = -1`. If `psi` isn’t the right order, your transform becomes “some transform” that doesn’t match negacyclic multiplication.

3. **Not reducing coefficients after intermediate operations**  
   In Python you won’t overflow, but in C a missed reduction can overflow a 16/32-bit path, corrupting results and potentially leaking via timing.

4. **Bit packing mismatch (endianness + ordering)**  
   If encoder/decoder disagree about whether the first coefficient goes into the low bits or high bits of the first byte, you get decryption failures that look like “random noise”.

5. **Treating lossy decompression as if it were exact**  
   Compression introduces error. The scheme design budgets for it. If you change `d` or rounding rules, you can move from “rare failures” to “breaks reliably”.

## Ship It

This lesson ships a reusable audit checklist:

- `outputs/kyber-internals-review-checklist.md`

Use it when:
- reviewing a Kyber/ML-KEM implementation PR (NTT, packing, compression),
- translating code between languages (C ↔ Rust ↔ Python),
- debugging “decapsulation failures” bugs that are actually bit layout or rounding mismatches.

## Exercises

1. **Easy:** Run `python3 code/main.py`. Observe that the NTT-based multiply matches the schoolbook multiply exactly.
2. **Medium:** Change `d` in Step 4 (try `d=4`, `d=10`, `d=11`). Measure `poly_max_abs_error()` and the compressed byte length.
3. **Hard:** Take your `phases/14-pq-lattice/06-kyber-ml-kem/` implementation and swap its polynomial multiplication to use `poly_mul_kyber_style_ntt_256()`. Confirm your encryption/decryption still works, then time the difference.

## Key Terms

| Term | What people say | What it actually means |
|---|---|---|
| NTT | “FFT but modular” | A discrete Fourier transform in `Z_q` using roots of unity |
| Negacyclic convolution | “Multiply mod `x^n + 1`” | Wrap-around terms flip sign because `x^n = -1` |
| Twist | “Multiply by powers of psi” | A pre/post scaling that turns negacyclic into cyclic in the transform domain |
| `psi`, `omega` | “roots of unity constants” | `psi` has order `2n`, `omega = psi^2` has order `n` for the NTT |
| Coefficient compression | “round to d bits” | Map `c ∈ [0,q)` to `t ∈ [0,2^d)` and accept quantization error |

## Further Reading

- Bos, Ducas, Kiltz, Lepoint, Lyubashevsky, Schanck, Schwabe, Seiler, Stehlé, *CRYSTALS-Kyber* (2018) — design rationale + parameters behind Kyber/ML-KEM.
- NIST, *FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)* (2024) — standardization of Kyber and its exact packing/compression rules.
- Bernstein, *Multidigit multiplication for mathematicians* (2001) — intuition for why transforms accelerate convolution (bridges to NTT thinking).

