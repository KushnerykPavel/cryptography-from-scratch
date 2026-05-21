# Multivariate Cryptography — Rainbow's Death

> A trapdoor MQ system looks random… until you know which variables to “fix” so the rest becomes linear.

**Type:** Build
**Languages:** Python
**Prerequisites:** Finite fields GF(p), solving linear systems, hash functions (see Phase 2: Abstract Algebra — “Finite Fields GF(p)”)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** why “fix vinegar → solve oils” turns MQ into linear algebra
- **Compute** message digests as field elements in GF(p)
- **Implement** a tiny layered Oil-and-Vinegar (Rainbow-style) central map and invert it
- **Distinguish** secret trapdoor maps (S, F, T) from the public map (dense quadratic polynomials)
- **Apply** a verification check `P(signature) == H(message)` and show tampering fails

## The Problem

You ship a system that depends on signatures that must remain unforgeable even if large quantum computers exist. Classical signatures like RSA and ECDSA are not expected to survive Shor’s algorithm. So you look at “post-quantum” families: lattices, hashes, codes… and multivariate quadratic (MQ) signatures.

MQ signatures are appealing on paper: verification is “just evaluate quadratic polynomials over a small finite field,” which is fast. But the history is brutal: many MQ constructions were broken, and Rainbow — the most famous layered Oil-and-Vinegar (OV) signature — collapsed under practical key-recovery attacks. You still need to understand Rainbow, because its *trapdoor shape* (layered OV + affine hiding) is the blueprint for modern descendants and for how MQ cryptanalysis thinks.

This lesson builds a tiny Rainbow-like scheme that you can run end-to-end: generate keys, sign, verify, and see how “hard MQ” becomes “easy linear algebra” once you know the hidden variable partition.

## The Concept

### MQ signatures in one line

The public key is a polynomial map:

```
P : GF(p)^n -> GF(p)^m
```

Each output coordinate is a quadratic polynomial in `n` variables:

```
y_k = sum_{i<=j} q[k,i,j] * x_i * x_j + sum_i l[k,i] * x_i + c[k]   (mod p)
```

To verify a signature `s` on message `m`:

```
H(m) == P(s)
```

The security hope: given `P` and `H(m)`, finding an `s` such that `P(s)=H(m)` is an instance of solving a system of multivariate quadratic equations, believed hard in general.

### The trapdoor: “Oil and Vinegar”

Rainbow’s core trick is not “solve MQ” — it’s “*construct* an MQ system that becomes linear if you fix the right variables.”

Split variables into:
- **Vinegar** variables: you are allowed to choose them (or they’re already known)
- **Oil** variables: you solve for them

An OV polynomial is built so that it has **no oil×oil quadratic terms**. Then once vinegars are fixed, every remaining term is linear in the oils, and you can solve by Gaussian elimination.

### Layers: why Rainbow is “layered OV”

Rainbow repeats that idea in stages:

Layer 1:
- pick `v1` vinegar values
- solve for `o1` oil values

Layer 2:
- treat all Layer-1 variables (`v1 + o1`) as “vinegars” for Layer 2
- solve for `o2` new oil values

The central map `F` is easy to invert if you know this structure.

### Hiding the structure (and why the public key is huge)

If we published `F` directly, its OV structure would be obvious and attacks would target it. So MQ signatures hide `F` behind two secret affine maps:

```
P = S ∘ F ∘ T
```

- `T : GF(p)^n -> GF(p)^n` mixes inputs
- `S : GF(p)^m -> GF(p)^m` mixes outputs

After composition, the public polynomials become dense: oil/oil terms appear, and the system “looks random” — at least that was the intention.

Rainbow is historically important because it shows how far you can push this “trapdoor by structure, hide by affine mixing” pattern — and also because it shows how such structure can still be recovered by cryptanalysis.

## Build It

### Step 1: Finite-field plumbing (GF(p))
This is the minimal math toolkit: modular inversion and solving square linear systems over a prime field.

```python
import hashlib
import json
import random
from dataclasses import dataclass


def modp(x, p):
    return x % p


def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def mod_inv(a, p):
    a = a % p
    if a == 0:
        raise ZeroDivisionError("no inverse for 0")
    g, x, _ = egcd(a, p)
    if g != 1:
        raise ZeroDivisionError("not invertible")
    return x % p


def mat_identity(n):
    return [[1 if i == j else 0 for j in range(n)] for i in range(n)]


def mat_vec_mul(A, x, p):
    out = []
    for row in A:
        acc = 0
        for a, xi in zip(row, x):
            acc = (acc + a * xi) % p
        out.append(acc)
    return out


def mat_inv(A, p):
    n = len(A)
    M = [row[:] + eye_row[:] for row, eye_row in zip(A, mat_identity(n))]

    for col in range(n):
        pivot = None
        for r in range(col, n):
            if M[r][col] % p != 0:
                pivot = r
                break
        if pivot is None:
            raise ValueError("matrix not invertible")
        if pivot != col:
            M[col], M[pivot] = M[pivot], M[col]

        inv_piv = mod_inv(M[col][col], p)
        for c in range(2 * n):
            M[col][c] = (M[col][c] * inv_piv) % p

        for r in range(n):
            if r == col:
                continue
            factor = M[r][col] % p
            if factor == 0:
                continue
            for c in range(2 * n):
                M[r][c] = (M[r][c] - factor * M[col][c]) % p

    return [row[n:] for row in M]


def solve_linear_system(A, b, p):
    n = len(A)
    M = [A[i][:] + [b[i] % p] for i in range(n)]

    for col in range(n):
        pivot = None
        for r in range(col, n):
            if M[r][col] % p != 0:
                pivot = r
                break
        if pivot is None:
            return None
        if pivot != col:
            M[col], M[pivot] = M[pivot], M[col]

        inv_piv = mod_inv(M[col][col], p)
        for c in range(col, n + 1):
            M[col][c] = (M[col][c] * inv_piv) % p

        for r in range(n):
            if r == col:
                continue
            factor = M[r][col] % p
            if factor == 0:
                continue
            for c in range(col, n + 1):
                M[r][c] = (M[r][c] - factor * M[col][c]) % p

    return [M[i][n] % p for i in range(n)]


def hash_to_field_elems(message, p, m, domain=b"rainbow-toy-v1"):
    out = []
    counter = 0
    while len(out) < m:
        h = hashlib.sha256()
        h.update(domain)
        h.update(b"|")
        h.update(message)
        h.update(b"|")
        h.update(counter.to_bytes(4, "big"))
        digest = h.digest()
        for i in range(0, len(digest), 4):
            if len(out) >= m:
                break
            out.append(int.from_bytes(digest[i : i + 4], "big") % p)
        counter += 1
    return out
```

This works because we chose a prime field GF(p). Modular inversion exists for every nonzero element, and Gaussian elimination works exactly like over the reals — just with all operations taken modulo `p`.

### Step 2: Quadratic maps (public keys are polynomials)
We represent quadratic maps (a list of quadratic polynomials), and we implement the two compositions that create a Rainbow-style public key: `P = S ∘ F ∘ T`.

```python
def _linear_polynomial(constant, coeffs):
    return {"c": constant, "a": coeffs}


def _mul_linear_polys(u, v, p):
    c1, a1 = u["c"] % p, u["a"]
    c2, a2 = v["c"] % p, v["a"]
    n = len(a1)
    q = [[0 for _ in range(n)] for _ in range(n)]
    l = [0 for _ in range(n)]
    c = (c1 * c2) % p

    for i in range(n):
        l[i] = (c1 * a2[i] + c2 * a1[i]) % p

    for i in range(n):
        for j in range(i, n):
            if i == j:
                q[i][j] = (q[i][j] + a1[i] * a2[j]) % p
            else:
                q[i][j] = (q[i][j] + a1[i] * a2[j] + a1[j] * a2[i]) % p
    return q, l, c


def _add_scaled_quadratic(acc_q, acc_l, acc_c, q, l, c, scale, p):
    n = len(acc_l)
    scale %= p
    if scale == 0:
        return
    for i in range(n):
        acc_l[i] = (acc_l[i] + scale * l[i]) % p
    for i in range(n):
        for j in range(i, n):
            acc_q[i][j] = (acc_q[i][j] + scale * q[i][j]) % p
    acc_c[0] = (acc_c[0] + scale * c) % p


@dataclass(frozen=True)
class AffineMap:
    A: list[list[int]]
    b: list[int]
    p: int

    def apply(self, x):
        y = mat_vec_mul(self.A, x, self.p)
        return [(yi + bi) % self.p for yi, bi in zip(y, self.b)]

    def inverse(self):
        Ainv = mat_inv(self.A, self.p)
        binv = mat_vec_mul(Ainv, [(-bi) % self.p for bi in self.b], self.p)
        return AffineMap(Ainv, binv, self.p)


@dataclass(frozen=True)
class QuadraticMap:
    q: list[list[list[int]]]
    l: list[list[int]]
    c: list[int]
    p: int

    def m(self):
        return len(self.q)

    def n(self):
        return len(self.l[0]) if self.l else 0

    def evaluate(self, x):
        p = self.p
        n = self.n()
        out = []
        for k in range(self.m()):
            acc = self.c[k] % p
            lk = self.l[k]
            qk = self.q[k]
            for i in range(n):
                acc = (acc + lk[i] * x[i]) % p
            for i in range(n):
                xi = x[i]
                for j in range(i, n):
                    acc = (acc + qk[i][j] * xi * x[j]) % p
            out.append(acc)
        return out

    def nonzero_quadratic_terms(self):
        n = self.n()
        total = 0
        for k in range(self.m()):
            for i in range(n):
                for j in range(i, n):
                    if self.q[k][i][j] % self.p != 0:
                        total += 1
        return total


def compose_quadratic_with_affine_input(F, T):
    p = F.p
    m = F.m()
    n = T.inverse().A and len(T.A[0])  # input dim

    t_polys = []
    for a in range(len(T.b)):
        coeffs = [T.A[a][i] % p for i in range(n)]
        t_polys.append(_linear_polynomial(T.b[a] % p, coeffs))

    new_q = [[[0 for _ in range(n)] for _ in range(n)] for _ in range(m)]
    new_l = [[0 for _ in range(n)] for _ in range(m)]
    new_c = [0 for _ in range(m)]

    for k in range(m):
        acc_q = [[0 for _ in range(n)] for _ in range(n)]
        acc_l = [0 for _ in range(n)]
        acc_c = [0]

        for a in range(F.n()):
            scale = F.l[k][a]
            if scale % p != 0:
                poly = t_polys[a]
                _add_scaled_quadratic(
                    acc_q,
                    acc_l,
                    acc_c,
                    [[0 for _ in range(n)] for _ in range(n)],
                    poly["a"],
                    poly["c"],
                    scale,
                    p,
                )

        for a in range(F.n()):
            for b in range(a, F.n()):
                scale = F.q[k][a][b]
                if scale % p == 0:
                    continue
                qtmp, ltmp, ctmp = _mul_linear_polys(t_polys[a], t_polys[b], p)
                _add_scaled_quadratic(acc_q, acc_l, acc_c, qtmp, ltmp, ctmp, scale, p)

        acc_c[0] = (acc_c[0] + F.c[k]) % p

        new_q[k] = acc_q
        new_l[k] = acc_l
        new_c[k] = acc_c[0]

    for k in range(m):
        for i in range(n):
            for j in range(i):
                new_q[k][i][j] = 0
    return QuadraticMap(new_q, new_l, new_c, p)


def apply_output_affine_to_quadratic(F, S):
    p = F.p
    m = F.m()
    n = F.n()

    new_q = [[[0 for _ in range(n)] for _ in range(n)] for _ in range(m)]
    new_l = [[0 for _ in range(n)] for _ in range(m)]
    new_c = [0 for _ in range(m)]

    for r in range(m):
        for k in range(m):
            a = S.A[r][k] % p
            if a == 0:
                continue
            for i in range(n):
                new_l[r][i] = (new_l[r][i] + a * F.l[k][i]) % p
            for i in range(n):
                for j in range(i, n):
                    new_q[r][i][j] = (new_q[r][i][j] + a * F.q[k][i][j]) % p
            new_c[r] = (new_c[r] + a * F.c[k]) % p
        new_c[r] = (new_c[r] + S.b[r]) % p

    return QuadraticMap(new_q, new_l, new_c, p)
```

The key intuition: `F` is structured (easy to invert), but `P` is what the verifier gets — and `P` is a dense list of quadratic polynomials.

### Step 3: Layered Oil-and-Vinegar (Rainbow-style) inversion
We now construct a **two-layer** OV central map `F` and implement inversion by turning each layer into a linear system.

```python
def random_invertible_matrix(rng, size, p):
    while True:
        A = [[rng.randrange(p) for _ in range(size)] for _ in range(size)]
        try:
            _ = mat_inv(A, p)
            return A
        except ValueError:
            continue


def random_affine_map(rng, dim, p):
    A = random_invertible_matrix(rng, dim, p)
    b = [rng.randrange(p) for _ in range(dim)]
    return AffineMap(A, b, p)


def _random_invertible_linear_block(rng, size, p):
    return random_invertible_matrix(rng, size, p)


@dataclass(frozen=True)
class RainbowToyParams:
    p: int = 31
    v1: int = 2
    o1: int = 2
    o2: int = 2

    def n(self):
        return self.v1 + self.o1 + self.o2

    def m(self):
        return self.o1 + self.o2


@dataclass(frozen=True)
class LayeredOVCentralMap:
    params: RainbowToyParams
    F: QuadraticMap

    def invert(self, y, vinegar_seed, max_tries=64):
        p = self.params.p
        v1, o1, o2 = self.params.v1, self.params.o1, self.params.o2
        n = self.params.n()

        layer1_out = list(range(0, o1))
        layer2_out = list(range(o1, o1 + o2))

        layer1_oils = list(range(v1, v1 + o1))
        layer2_oils = list(range(v1 + o1, v1 + o1 + o2))

        for attempt in range(max_tries):
            x = [0 for _ in range(n)]
            vvals = vinegar_values(vinegar_seed, attempt, p, v1)
            for i in range(v1):
                x[i] = vvals[i]

            o1_vals = self._solve_layer(layer1_out, layer1_oils, x, y[:o1])
            if o1_vals is None:
                continue
            for idx, val in zip(layer1_oils, o1_vals):
                x[idx] = val

            o2_vals = self._solve_layer(layer2_out, layer2_oils, x, y[o1:])
            if o2_vals is None:
                continue
            for idx, val in zip(layer2_oils, o2_vals):
                x[idx] = val

            if self.F.evaluate(x) == [yi % p for yi in y]:
                return x

        raise ValueError("could not invert central map (increase max_tries)")

    def _solve_layer(self, poly_indices, oil_indices, x_partial, y_target):
        p = self.params.p
        n = self.params.n()
        k = len(oil_indices)
        if k == 0:
            return []

        A = [[0 for _ in range(k)] for _ in range(k)]
        b = [0 for _ in range(k)]

        for row, poly_idx in enumerate(poly_indices):
            base = x_partial[:]
            for oi in oil_indices:
                base[oi] = 0
            base_val = self.F.evaluate(base)[poly_idx]
            rhs = (y_target[row] - base_val) % p
            b[row] = rhs

            for col, oi in enumerate(oil_indices):
                test = base[:]
                test[oi] = 1
                coeff = (self.F.evaluate(test)[poly_idx] - base_val) % p
                A[row][col] = coeff

        return solve_linear_system(A, b, p)


def vinegar_values(seed, attempt, p, count):
    out = []
    for i in range(count):
        h = hashlib.sha256()
        h.update(seed)
        h.update(b"|")
        h.update(attempt.to_bytes(4, "big"))
        h.update(b"|")
        h.update(i.to_bytes(4, "big"))
        out.append(int.from_bytes(h.digest()[:4], "big") % p)
    return out
```

Notice how `LayeredOVCentralMap._solve_layer(...)` extracts a linear system by probing each oil variable one-at-a-time while keeping all other oils at zero. This works only because the OV structure forbids oil×oil terms.

### Step 4: Toy signature (keygen / sign / verify)
Finally, we put it together into a toy signature scheme where the public key is just a `QuadraticMap` and verification is a single equality check.

```python
def rainbow_toy_keygen(seed, params=RainbowToyParams()):
    rng = random.Random(int.from_bytes(hashlib.sha256(seed).digest()[:8], "big"))
    p = params.p
    n = params.n()
    m = params.m()

    q = [[[0 for _ in range(n)] for _ in range(n)] for _ in range(m)]
    l = [[0 for _ in range(n)] for _ in range(m)]
    c = [0 for _ in range(m)]

    v1, o1, o2 = params.v1, params.o1, params.o2
    oils1 = list(range(v1, v1 + o1))
    oils2 = list(range(v1 + o1, v1 + o1 + o2))

    M1 = _random_invertible_linear_block(rng, o1, p)
    M2 = _random_invertible_linear_block(rng, o2, p)

    for k in range(o1):
        for i in range(v1):
            for j in range(i, v1):
                q[k][i][j] = rng.randrange(p)
        for j, oi in enumerate(oils1):
            l[k][oi] = M1[k][j] % p
        for i in range(v1):
            l[k][i] = rng.randrange(p)
        c[k] = rng.randrange(p)

    v2 = v1 + o1
    for k2 in range(o2):
        k = o1 + k2
        for i in range(v2):
            for j in range(i, v2):
                q[k][i][j] = rng.randrange(p)
        for j, oi in enumerate(oils2):
            l[k][oi] = M2[k2][j] % p
        for i in range(v2):
            l[k][i] = rng.randrange(p)
        c[k] = rng.randrange(p)

    F = QuadraticMap(q, l, c, p)
    central = LayeredOVCentralMap(params=params, F=F)
    S = random_affine_map(rng, m, p)
    T = random_affine_map(rng, n, p)

    G = compose_quadratic_with_affine_input(F, T)
    P = apply_output_affine_to_quadratic(G, S)

    pk = RainbowToyPublicKey(params=params, P=P)
    sk = RainbowToySecretKey(params=params, S=S, T=T, central=central, seed=seed)
    return pk, sk


def rainbow_toy_sign(sk, message):
    p = sk.params.p
    y = hash_to_field_elems(message, p, sk.params.m())

    y0 = sk.S.inverse().apply(y)
    vinegar_seed = hashlib.sha256(sk.seed + b"|" + message).digest()
    x = sk.central.invert(y0, vinegar_seed=vinegar_seed)
    sig = sk.T.inverse().apply(x)
    return sig


def rainbow_toy_verify(pk, message, signature):
    p = pk.params.p
    y = hash_to_field_elems(message, p, pk.params.m())
    y2 = pk.P.evaluate(signature)
    return [yi % p for yi in y2] == [yi % p for yi in y]
```

Run it:

`python3 code/main.py`

## Use It

This lesson’s code is deliberately tiny so you can see the trapdoor. In real life:

- **Do not use Rainbow.** It was broken by key-recovery attacks; it’s taught today as a case study.
- Prefer standardized PQ signatures (lattice/hash-based) for production use (you already built several in this course).
- If you need MQ signatures specifically, look at modern UOV-family research schemes (next lesson: **UOV & MAYO**).

Practical equivalents / references:

| Need | Use in practice | Why |
|---|---|---|
| Production PQ signatures | ML-DSA (Dilithium), Falcon, SPHINCS+ | Standardized / widely implemented |
| MQ signatures research | UOV, MAYO and variants | Active research; different tradeoffs |
| Historical Rainbow code | Archived implementations (research only) | For studying attacks and structure |

## Pitfalls

1. **Forgetting “mod p everywhere.”** One missing `% p` in Gaussian elimination silently breaks signing.
2. **Using a non-prime modulus with this code.** The inversion code assumes every nonzero element is invertible.
3. **Singular linear systems during signing.** Real Rainbow implementations may need to retry with new vinegar values; your code must handle “no solution.”
4. **Side-channel leakage in the signer.** Even “correct math” can leak the oil/vinegar structure or affine maps through timing/power/faults.
5. **Deploying broken primitives.** “Fast verify” is irrelevant if cryptanalysis recovers the key in practice.

## Ship It

This lesson ships a reusable MQ signature review checklist:

- Open `outputs/mq-signature-review-checklist.md`.
- Use it as a PR-review prompt when you see an MQ-based scheme or an implementation claiming “Rainbow-like performance.”
- It’s written to be pasteable into an issue/PR comment and to force concrete questions: field choice, retry logic, constant-time constraints, and “is this scheme already broken?”

## Exercises

1. **Easy.** Run `python3 code/main.py`. Observe that `verify(tampered)` becomes `False`.
2. **Medium.** Change `RainbowToyParams(p=31, v1=2, o1=2, o2=2)` to a larger/smaller toy size and compare `central F quadratic terms` vs `public P quadratic terms`.
3. **Hard.** Add an option to `LayeredOVCentralMap.invert(...)` to simulate “retry needed” by intentionally making one layer’s oil coefficient matrix sometimes singular, and measure how many retries signing needs on average.

## Key Terms

| Term | What people say | What it actually means |
|---|---|---|
| MQ problem | “Solving quadratic equations” | Finding `x` such that `P(x)=y` over a finite field |
| Central map `F` | “Trapdoor” | Structured MQ system that’s easy to invert *if you know the structure* |
| Vinegar variables | “Random variables” | Variables you choose/fix so the remaining system becomes linear |
| Oil variables | “Solved variables” | Unknowns that appear only linearly after vinegar fixing |
| Affine hiding `S, T` | “Mixing” | Secret invertible affine maps so public polynomials look dense/random |

## Further Reading

- Ding & Schmidt, *Rainbow, a New Multivariable Polynomial Signature Scheme* (2005) — original Rainbow construction (layered OV).
- Beullens, *Breaking Rainbow Takes a Weekend on a Laptop* (2022) — practical key-recovery attacks that broke Rainbow.
- Cartor et al., *IPRainbow* (2022) — explores whether Rainbow-like performance can be “repaired” and compares to UOV.
