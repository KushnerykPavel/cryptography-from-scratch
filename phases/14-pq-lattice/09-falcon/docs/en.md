# Falcon (Toy) — NTRU Trapdoor + Short Signatures

> A Falcon signature is a *short* solution to `s1 + s2*h = c (mod q)`.

**Type:** Build
**Languages:** Python
**Prerequisites:** `14-pq-lattice/04-regev-encryption`, `14-pq-lattice/05-dual-regev-trapdoors` (or equivalent lattice intuition)
**Time:** ~90 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain how Falcon verification reduces to one ring equation plus a norm bound.
- Compute negacyclic products in `Z_q[x]/(x^n+1)`.
- Implement polynomial inversion modulo `(x^n+1, q)` for tiny `n`.
- Distinguish “any solution” from a *short* solution (why the norm bound matters).
- Apply Babai-style rounding to get a “close” lattice vector in a toy setting.

## The Problem

Classical signatures (ECDSA, Ed25519, RSA-PSS) are threatened by sufficiently large quantum computers: once Shor’s algorithm is practical, discrete logs and factoring stop being hard. That means the signatures that authenticate software updates, supply-chain artifacts, and on-chain transactions become forgeable.

Post-quantum signatures exist today, but they come with engineering trade-offs: public keys and signatures are bigger, verification rules differ, and implementations can be tricky. Falcon (FN-DSA) is interesting because it targets **small signatures** and **fast verification**, but its signing algorithm is significantly more complex than “multiply and hash”.

This lesson makes the verification equation concrete, and shows (on toy parameters) the “shape” of Falcon: hash-to-point → find a short lattice vector → verifier recomputes `s1` and checks a norm bound.

## The Concept

Falcon works in the ring:

- `R_q = Z_q[x] / (x^n + 1)`
- where `n` is a power of two (real Falcon uses `n = 512` or `1024`) and `q = 12289`.

Key relations (high level):

- Public key is one polynomial: `h = g / f (mod x^n+1, q)`.
- Secret key polynomials satisfy an **NTRU equation**: `fG - gF = q (mod x^n+1)`.

Sign/verify relation (the part you *must* internalize):

1) Hash message + salt to a ring element `c`.
2) Signature contains `s2` (a polynomial with small-ish integer coefficients).
3) Verifier recomputes:

`s1 = c - s2*h (mod x^n+1, q)`

4) Verifier accepts iff the vector `(s1, s2)` is “short enough”:

`||(s1, s2)||^2 <= beta^2`.

Why is this meaningful? Because `s1 = c - s2*h` is *always* true by definition — the security is entirely in the fact that a forger should not be able to make `(s1, s2)` short without knowing the trapdoor basis.

In this lesson we use **tiny toy parameters** (`n = 4`) and a toy “closest vector” routine (Babai nearest-plane). This is not Falcon. It’s a scaffold that makes the equations executable.

## Build It

### Step 1: Negacyclic polynomial arithmetic
```python
def _center_lift_coeff(x: int, q: int) -> int:
    y = x % q
    if y > q // 2:
        y -= q
    return y


def poly_center_lift(a: Sequence[int], q: int, n: int) -> List[int]:
    _require(len(a) == n, "wrong polynomial length")
    return [_center_lift_coeff(x, q) for x in a]


def poly_mod_q(a: Sequence[int], q: int, n: int) -> List[int]:
    if len(a) != n:
        raise ValueError("wrong polynomial length")
    return [int(x) % q for x in a]


def poly_add_mod_q(a: Sequence[int], b: Sequence[int], q: int, n: int) -> List[int]:
    _require(len(a) == n and len(b) == n, "wrong polynomial length")
    return [(int(x) + int(y)) % q for x, y in zip(a, b)]


def poly_sub_mod_q(a: Sequence[int], b: Sequence[int], q: int, n: int) -> List[int]:
    _require(len(a) == n and len(b) == n, "wrong polynomial length")
    return [(int(x) - int(y)) % q for x, y in zip(a, b)]


def poly_mul_mod_phi_int(a: Sequence[int], b: Sequence[int], n: int) -> List[int]:
    _require(len(a) == n and len(b) == n, "wrong polynomial length")
    out = [0] * n
    for i, ai in enumerate(a):
        ai = int(ai)
        if ai == 0:
            continue
        for j, bj in enumerate(b):
            bj = int(bj)
            if bj == 0:
                continue
            k = i + j
            if k < n:
                out[k] += ai * bj
            else:
                out[k - n] -= ai * bj
    return out


def poly_mul_mod_phi_q(a: Sequence[int], b: Sequence[int], q: int, n: int) -> List[int]:
    out = poly_mul_mod_phi_int(a, b, n)
    return [x % q for x in out]
```

This is the “workhorse” arithmetic: multiplication is **negacyclic convolution**, because `x^n = -1` in the quotient ring `Z_q[x]/(x^n+1)`. Everything else (keygen, signing, verifying) is built on this.

### Step 2: Invert `f` modulo `(x^n+1, q)` and compute `h`
```python
def _poly_strip_mod_q(p: List[int], q: int) -> List[int]:
    while len(p) > 0 and (p[-1] % q) == 0:
        p.pop()
    if not p:
        return [0]
    return [x % q for x in p]


def _poly_add_poly_mod_q(a: List[int], b: List[int], q: int) -> List[int]:
    out = [0] * max(len(a), len(b))
    for i in range(len(out)):
        out[i] = ((a[i] if i < len(a) else 0) + (b[i] if i < len(b) else 0)) % q
    return _poly_strip_mod_q(out, q)


def _poly_sub_poly_mod_q(a: List[int], b: List[int], q: int) -> List[int]:
    out = [0] * max(len(a), len(b))
    for i in range(len(out)):
        out[i] = ((a[i] if i < len(a) else 0) - (b[i] if i < len(b) else 0)) % q
    return _poly_strip_mod_q(out, q)


def _poly_mul_poly_mod_q(a: List[int], b: List[int], q: int) -> List[int]:
    out = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        ai %= q
        if ai == 0:
            continue
        for j, bj in enumerate(b):
            bj %= q
            if bj == 0:
                continue
            out[i + j] = (out[i + j] + ai * bj) % q
    return _poly_strip_mod_q(out, q)


def _poly_divmod_mod_q(a: List[int], b: List[int], q: int) -> Tuple[List[int], List[int]]:
    a = _poly_strip_mod_q(a[:], q)
    b = _poly_strip_mod_q(b[:], q)
    if b == [0]:
        raise ZeroDivisionError("polynomial division by zero")
    da = len(a) - 1
    db = len(b) - 1
    if da < db:
        return [0], a
    inv_lead = pow(b[-1] % q, -1, q)
    quotient = [0] * (da - db + 1)
    rem = a[:]
    while len(rem) - 1 >= db and rem != [0]:
        dr = len(rem) - 1
        coeff = (rem[-1] * inv_lead) % q
        shift = dr - db
        quotient[shift] = coeff
        sub = [0] * shift + [(coeff * x) % q for x in b]
        rem = _poly_sub_poly_mod_q(rem, sub, q)
    return _poly_strip_mod_q(quotient, q), _poly_strip_mod_q(rem, q)


def _poly_mod_mod_q(a: List[int], modulus: List[int], q: int) -> List[int]:
    _, r = _poly_divmod_mod_q(a, modulus, q)
    return r


def poly_inv_mod_phi_q(f: Sequence[int], q: int, n: int) -> List[int]:
    _require(len(f) == n, "wrong polynomial length")
    phi = [1] + [0] * (n - 1) + [1]

    r0 = _poly_strip_mod_q([int(x) % q for x in f], q)
    r1 = _poly_strip_mod_q(phi[:], q)
    s0, s1 = [1], [0]
    t0, t1 = [0], [1]

    while r1 != [0]:
        quotient, r2 = _poly_divmod_mod_q(r0, r1, q)
        r0, r1 = r1, r2
        s0, s1 = s1, _poly_sub_poly_mod_q(s0, _poly_mul_poly_mod_q(quotient, s1, q), q)
        t0, t1 = t1, _poly_sub_poly_mod_q(t0, _poly_mul_poly_mod_q(quotient, t1, q), q)

    if len(r0) != 1 or r0[0] % q == 0:
        raise ValueError("not invertible modulo (x^n+1, q)")
    inv_g = pow(r0[0], -1, q)
    inv = [(inv_g * x) % q for x in s0]
    inv = _poly_mod_mod_q(inv, phi, q)
    inv = inv + [0] * (n - len(inv))
    return inv[:n]


def ntru_public_key_h(f: Sequence[int], g: Sequence[int], q: int, n: int) -> List[int]:
    inv_f = poly_inv_mod_phi_q(f, q, n)
    return poly_mul_mod_phi_q(g, inv_f, q, n)
```

This is where the *public key as a single polynomial* comes from: compute `f^{-1}` modulo `q` (and `x^n+1`), then multiply by `g` to get `h = g/f (mod q)`.

### Step 3: Solve the NTRU equation `fG - gF = q`
```python
def _mul_matrix_negacyclic(poly: Sequence[int], n: int) -> List[List[int]]:
    poly = [int(x) for x in poly]
    _require(len(poly) == n, "wrong polynomial length")
    mat = [[0 for _ in range(n)] for _ in range(n)]
    for j in range(n):
        e = [0] * n
        e[j] = 1
        col = poly_mul_mod_phi_int(poly, e, n)
        for i in range(n):
            mat[i][j] = int(col[i])
    return mat


def _rref_augmented(a: Sequence[Sequence[int]], b: Sequence[int]) -> Tuple[List[List[Fraction]], List[Fraction], List[int]]:
    m = len(a)
    n = len(a[0]) if m > 0 else 0
    mat = [[Fraction(int(x)) for x in row] for row in a]
    rhs = [Fraction(int(x)) for x in b]

    pivots: List[int] = []
    row = 0
    for col in range(n):
        if row >= m:
            break
        pivot_row = None
        for r in range(row, m):
            if mat[r][col] != 0:
                pivot_row = r
                break
        if pivot_row is None:
            continue
        if pivot_row != row:
            mat[row], mat[pivot_row] = mat[pivot_row], mat[row]
            rhs[row], rhs[pivot_row] = rhs[pivot_row], rhs[row]

        pivot_val = mat[row][col]
        inv = Fraction(1, 1) / pivot_val
        mat[row] = [x * inv for x in mat[row]]
        rhs[row] *= inv

        for r in range(m):
            if r == row:
                continue
            factor = mat[r][col]
            if factor == 0:
                continue
            mat[r] = [x - factor * y for x, y in zip(mat[r], mat[row])]
            rhs[r] = rhs[r] - factor * rhs[row]

        pivots.append(col)
        row += 1

    return mat, rhs, pivots


def solve_ntru_equation_small(
    f: Sequence[int], g: Sequence[int], q: int, n: int, *, max_abs: int = 2
) -> Tuple[List[int], List[int]]:
    _require(len(f) == n and len(g) == n, "wrong polynomial length")
    mf = _mul_matrix_negacyclic(f, n)
    mg = _mul_matrix_negacyclic(g, n)
    a = [row_f + [-x for x in row_g] for row_f, row_g in zip(mf, mg)]
    rhs = [0] * n
    rhs[0] = q

    rref, rref_rhs, pivots = _rref_augmented(a, rhs)
    nvars = 2 * n

    for i in range(n):
        if all(rref[i][j] == 0 for j in range(nvars)) and rref_rhs[i] != 0:
            raise ValueError("no solution to NTRU equation")

    free_cols = [j for j in range(nvars) if j not in pivots]
    _require(len(free_cols) > 0, "unexpected full-rank system")

    best: Tuple[int, List[int]] | None = None
    values_range = range(-max_abs, max_abs + 1)
    for values in itertools.product(values_range, repeat=len(free_cols)):
        x: List[Fraction] = [Fraction(0) for _ in range(nvars)]
        for col, val in zip(free_cols, values):
            x[col] = Fraction(val)
        for i, pcol in enumerate(pivots):
            acc = rref_rhs[i]
            for j in free_cols:
                acc -= rref[i][j] * x[j]
            x[pcol] = acc

        if any(xx.denominator != 1 for xx in x):
            continue
        x_int = [int(xx) for xx in x]

        g_coeffs = x_int[:n]
        f_coeffs = x_int[n:]

        lhs = poly_mul_mod_phi_int(f, g_coeffs, n)
        rhs_part = poly_mul_mod_phi_int(g, f_coeffs, n)
        check = [lhs[i] - rhs_part[i] for i in range(n)]
        if check[0] != q or any(check[i] != 0 for i in range(1, n)):
            continue

        score = _l2_norm2(g_coeffs) + _l2_norm2(f_coeffs)
        if best is None or score < best[0]:
            best = (score, x_int)

    if best is None:
        raise ValueError("failed to find (F, G) for NTRU equation")

    x_int = best[1]
    g_poly = x_int[:n]
    f_poly = x_int[n:]
    F = f_poly
    G = g_poly
    return F, G
```

In real Falcon, solving the NTRU equation and getting “small enough” `F,G` is nontrivial and uses specialized algorithms (including Babai-style reductions and FFT-domain tricks). Here we do a toy exact solve for tiny `n` using row-reduction over rationals, then a small integer search.

### Step 4: Hash-to-point + toy sign/verify
```python
def hash_to_point(msg: bytes, salt: bytes, n: int, q: int) -> List[int]:
    out: List[int] = []
    counter = 0
    while len(out) < n:
        h = hashlib.sha256(salt + msg + counter.to_bytes(4, "big")).digest()
        for i in range(0, len(h), 2):
            if len(out) >= n:
                break
            val = int.from_bytes(h[i : i + 2], "big") % q
            out.append(val)
        counter += 1
    return out


def gram_schmidt(basis: Sequence[Sequence[int]]) -> Tuple[List[List[float]], List[List[float]], List[float]]:
    n = len(basis)
    dim = len(basis[0]) if n > 0 else 0
    b = [[float(x) for x in row] for row in basis]
    mu = [[0.0 for _ in range(n)] for _ in range(n)]
    b_star = [[0.0 for _ in range(dim)] for _ in range(n)]
    norm2 = [0.0 for _ in range(n)]

    for i in range(n):
        v = b[i][:]
        for j in range(i):
            if norm2[j] == 0.0:
                raise ValueError("dependent basis")
            mu[i][j] = _dot(b[i], b_star[j]) / norm2[j]
            for k in range(dim):
                v[k] -= mu[i][j] * b_star[j][k]
        b_star[i] = v
        norm2[i] = _dot(v, v)

    return b, b_star, norm2


def babai_nearest_plane(basis: Sequence[Sequence[int]], target: Sequence[int]) -> List[int]:
    b, b_star, norm2 = gram_schmidt(basis)
    y = [float(x) for x in target]
    coeffs = [0] * len(basis)

    for i in reversed(range(len(basis))):
        if norm2[i] == 0.0:
            raise ValueError("dependent basis")
        t = _dot(y, b_star[i]) / norm2[i]
        c = int(round(t))
        coeffs[i] = c
        for k in range(len(y)):
            y[k] -= c * b[i][k]

    out = [0] * len(target)
    for c, vec in zip(coeffs, basis):
        if c == 0:
            continue
        for i, x in enumerate(vec):
            out[i] += c * int(x)
    return out


def toy_sign(msg: bytes, sk: ToyFalconSecretKey, salt: bytes) -> Tuple[bytes, List[int]]:
    _require(len(salt) == 16, "toy signer expects 16-byte salt")
    c = hash_to_point(msg, salt, sk.n, sk.q)
    c_center = poly_center_lift(c, sk.q, sk.n)

    basis = _basis_from_fgFG(sk.f, sk.g, sk.F, sk.G, sk.n)
    target = [0] * sk.n + c_center
    closest = babai_nearest_plane(basis, target)
    s2 = closest[: sk.n]
    return salt, s2


def toy_verify(msg: bytes, sig: Tuple[bytes, Sequence[int]], pk: ToyFalconPublicKey, beta2: int = TOY_BETA2) -> bool:
    salt, s2 = sig
    if len(salt) != 16:
        return False
    if len(s2) != pk.n:
        return False
    c = hash_to_point(msg, salt, pk.n, pk.q)
    s2_modq = [int(x) % pk.q for x in s2]
    s2h = poly_mul_mod_phi_q(s2_modq, pk.h, pk.q, pk.n)
    s1_modq = poly_sub_mod_q(c, s2h, pk.q, pk.n)
    s1 = poly_center_lift(s1_modq, pk.q, pk.n)
    norm2 = _l2_norm2(s1) + _l2_norm2([int(x) for x in s2])
    return norm2 <= beta2
```

This is the essence of Falcon verification: recompute `c`, recompute `s1 = c - s2*h`, and check a squared-norm bound. The real scheme’s job is to make “short” signatures feasible for the signer (with the trapdoor), and infeasible for everyone else.

Run it:

`python3 code/main.py`

## Use It

When you need real Falcon/FN-DSA, use an audited implementation. Typical choices:

- C reference implementation from the Falcon authors (basis for many ports).
- `liboqs` / Open Quantum Safe integrations (C).
- `PQClean`-style clean-room C ports used by many ecosystems.
- Rust crates implementing FN-DSA (Falcon) for server-side applications.

## Pitfalls

- Treating the verification equation as the “security check” (it always holds; only the **norm bound** matters).
- Mixing coefficient domains (integers vs mod `q` vs centered lift) and accidentally computing the norm in the wrong range.
- Wrong ring multiplication (cyclic vs **negacyclic**): `x^n = -1` changes the sign on wraparound terms.
- Nonce/salt misuse: signing with one salt and verifying with another silently changes `c`.
- Side-channels: real Falcon signing uses floating-point FFT sampling and requires constant-time care.

## Ship It

Save this lesson’s reusable artifact from `outputs/` and use it as a PR-review checklist when adding Falcon/FN-DSA to a system:

- confirm you’re using the right parameter set,
- confirm encoding/decoding rules and salt handling,
- confirm you enforce norm checks and input validation.

## Exercises

1. Easy: Run `python3 code/main.py`. Observe that verification recomputes `s1` from `c`, `s2`, and `h`, then checks only a norm bound.
2. Medium: Change `TOY_N` from `4` to `8` (and update `toy_keypair()` accordingly). Measure how much slower `solve_ntru_equation_small()` gets.
3. Hard: Replace the toy signer with a real FN-DSA implementation (via an audited library) and write a small adapter that verifies signatures against test vectors from that library.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| `R_q = Z_q[x]/(x^n+1)` | “a polynomial field” | A ring of polynomials reduced modulo `x^n+1`, with coefficients reduced modulo `q`. |
| Negacyclic convolution | “polynomial multiply” | Multiply then reduce with the rule `x^n = -1` (wraparound terms flip sign). |
| NTRU equation | “keygen constraint” | A relation `fG - gF = q` that yields a trapdoor basis for an NTRU lattice/module. |
| Trapdoor basis | “private key” | A lattice basis that makes finding *short* vectors near a target feasible. |
| Babai rounding | “approximate CVP” | A nearest-plane heuristic using Gram–Schmidt projections. |

## Further Reading

- Thomas Prest et al., *Falcon: Fast-Fourier Lattice-based Compact Signatures over NTRU* (spec) — the core reference for the real scheme.
- NIST PQC project materials on Falcon/FN-DSA — standardization context and recommended parameter sets.
- “NTRU lattices” primers — for intuition on why `(f, g, F, G)` define a short basis.
