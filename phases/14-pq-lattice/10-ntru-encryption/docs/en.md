# NTRU Encryption & NTRU Prime

> Encrypt with polynomials; decrypt by rounding back to “small”.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 14 · 06 (Kyber ML-KEM), Phase 14 · 07 (Kyber Internals), Phase 14 · 09 (Falcon)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain the NTRUEncrypt “small × big mod q” design and why decryption is a rounding problem.
- Compute cyclic polynomial products in `Z_q[x]/(x^N - 1)` and interpret center-lifted coefficients.
- Implement polynomial inversion modulo a prime in the quotient ring `(Z/pZ)[x]/(x^N - 1)`.
- Distinguish classic NTRUEncrypt from NTRU Prime at the “ring + sampling + security notes” level.
- Apply a practical review checklist to spot decryption-failure, CCA, and parameter pitfalls in NTRU-like code.

## The Problem

You’re migrating a product to post-quantum crypto and you run into an “NTRU-family” option in a standards document or a library. It looks deceptively simple: “just multiply polynomials.” Without a clear mental model, it’s easy to ship something that *sometimes decrypts wrong* (decryption failures), or leaks information through how it handles failures.

Also: once you’ve seen Kyber, you might incorrectly assume every lattice scheme is “LWE + NTT + gadgets.” NTRU takes a different path: the public key is a polynomial inverse in a quotient ring, and correctness is about keeping coefficients “small enough” so that a center-lift recovers the intended integers.

This lesson gives you a runnable toy NTRUEncrypt implementation you can step through, plus the review instincts you need to evaluate real implementations (where the hard part isn’t “multiply polynomials,” it’s *parameter discipline + failure behavior + CCA transforms*).

## The Concept

**The ring.** We work in a cyclic polynomial ring:

- `R = Z[x]/(x^N - 1)`
- `R_q = (Z/qZ)[x]/(x^N - 1)` and `R_p = (Z/pZ)[x]/(x^N - 1)`

Represent polynomials as length-`N` lists of coefficients. Multiplication is **cyclic convolution**: `x^N ≡ 1`, so indices wrap modulo `N`.

**“Big mod q” + “small polynomials.”** NTRUEncrypt uses:

- a large modulus `q` (e.g. `q=2048` or larger in real parameter sets; we use a tiny prime in this toy),
- a small modulus `p` (often `p=3`),
- “small” polynomials `f, g, r, m` with tiny coefficients (often ternary `{-1,0,1}`).

**Key idea:** choose a small secret `f` that is invertible in both `R_p` and `R_q`. Build a public key `h` that “contains” `f^{-1}` modulo `q`. Then:

- Encrypt: `e = r*h + m (mod q)`
- Decrypt: multiply by `f`, then **center-lift** back to small integers so that reducing mod `p` recovers `m`.

If the coefficients get too large (wrap modulo `q`), decryption can fail. Real schemes pick parameters so that failures are negligible *and* treat any failure as a security-sensitive event.

## Build It

### Step 1: Ring arithmetic

Implement cyclic polynomial arithmetic for `Z_q[x]/(x^N - 1)`, plus **center-lift** (mapping residues mod `q` back to small integers in `[-⌊q/2⌋, ⌊q/2⌋]`). This is the “engine” for everything in NTRU.

```python
def poly_add(a: List[int], b: List[int], mod: int | None = None) -> List[int]:
    if len(a) != len(b):
        raise ValueError("poly_add: mismatched lengths")
    out = [a[i] + b[i] for i in range(len(a))]
    if mod is not None:
        out = [x % mod for x in out]
    return out


def poly_sub(a: List[int], b: List[int], mod: int | None = None) -> List[int]:
    if len(a) != len(b):
        raise ValueError("poly_sub: mismatched lengths")
    out = [a[i] - b[i] for i in range(len(a))]
    if mod is not None:
        out = [x % mod for x in out]
    return out


def poly_scalar_mul(a: List[int], k: int, mod: int | None = None) -> List[int]:
    out = [k * x for x in a]
    if mod is not None:
        out = [x % mod for x in out]
    return out


def poly_mod(a: List[int], mod: int) -> List[int]:
    return [x % mod for x in a]


def poly_center_lift(a: List[int], mod: int) -> List[int]:
    if mod <= 1:
        raise ValueError("poly_center_lift: mod must be > 1")
    half = mod // 2
    out = []
    for x in a:
        r = x % mod
        if r > half:
            r -= mod
        out.append(r)
    return out


def poly_mul_cyclic(a: List[int], b: List[int], N: int, mod: int | None = None) -> List[int]:
    if len(a) != N or len(b) != N:
        raise ValueError("poly_mul_cyclic: inputs must have length N")
    acc = [0] * N
    for i in range(N):
        ai = a[i]
        if ai == 0:
            continue
        for j in range(N):
            acc[(i + j) % N] += ai * b[j]
    if mod is not None:
        acc = [x % mod for x in acc]
    return acc


def poly_to_str(a: List[int]) -> str:
    terms = []
    for i, c in enumerate(a):
        if c == 0:
            continue
        if i == 0:
            terms.append(str(c))
        elif i == 1:
            terms.append(f"{c}·x")
        else:
            terms.append(f"{c}·x^{i}")
    if not terms:
        return "0"
    return " + ".join(terms)
```

This step answers: “When I multiply two polynomials modulo `x^N - 1` and reduce coefficients mod `q`, how do I get back to the *intended* small integers?” In NTRU, **center-lift** is the glue between `mod q` arithmetic and “small-no-wrap” correctness.

### Step 2: Inverting a polynomial mod a prime

Key generation needs a secret `f` that is invertible in both `R_p` and `R_q`. For this toy lesson, we pick `p` and `q` to be primes so we can compute inverses using the extended Euclidean algorithm over the field `Z/pZ`.

```python
def _poly_strip(a: List[int]) -> List[int]:
    a = a[:]
    while len(a) > 1 and a[-1] == 0:
        a.pop()
    return a


def _poly_add_mod(a: List[int], b: List[int], mod: int) -> List[int]:
    n = max(len(a), len(b))
    out = [0] * n
    for i in range(n):
        out[i] = ((a[i] if i < len(a) else 0) + (b[i] if i < len(b) else 0)) % mod
    return _poly_strip(out)


def _poly_sub_mod(a: List[int], b: List[int], mod: int) -> List[int]:
    n = max(len(a), len(b))
    out = [0] * n
    for i in range(n):
        out[i] = ((a[i] if i < len(a) else 0) - (b[i] if i < len(b) else 0)) % mod
    return _poly_strip(out)


def _poly_mul_mod(a: List[int], b: List[int], mod: int) -> List[int]:
    if a == [0] or b == [0]:
        return [0]
    out = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        if ai == 0:
            continue
        for j, bj in enumerate(b):
            out[i + j] = (out[i + j] + ai * bj) % mod
    return _poly_strip(out)


def _poly_scale_mod(a: List[int], k: int, mod: int) -> List[int]:
    return _poly_strip([(k * x) % mod for x in a])


def _poly_divmod_mod(a: List[int], b: List[int], mod: int) -> Tuple[List[int], List[int]]:
    a = _poly_strip([x % mod for x in a])
    b = _poly_strip([x % mod for x in b])
    if b == [0]:
        raise ZeroDivisionError("polynomial division by zero")
    if a == [0] or len(a) < len(b):
        return [0], a

    q = [0] * (len(a) - len(b) + 1)
    r = a[:]
    inv_lc = pow(b[-1], -1, mod)
    while r != [0] and len(r) >= len(b):
        deg = len(r) - len(b)
        coef = (r[-1] * inv_lc) % mod
        q[deg] = coef
        subtract = _poly_scale_mod(([0] * deg) + b, coef, mod)
        r = _poly_sub_mod(r, subtract, mod)
    return _poly_strip(q), _poly_strip(r)


def poly_inverse_mod_prime(f: List[int], N: int, prime: int) -> List[int]:
    """
    Compute f^{-1} in (Z/prime Z)[x] / (x^N - 1), if it exists.

    Returns a length-N polynomial with coefficients in 0..prime-1.
    """
    if prime <= 2:
        raise ValueError("poly_inverse_mod_prime: prime must be an odd prime")
    if len(f) != N:
        raise ValueError("poly_inverse_mod_prime: f must have length N")

    f_mod = [x % prime for x in f]
    phi = [(-1) % prime] + [0] * (N - 1) + [1]

    r0, r1 = _poly_strip(phi), _poly_strip(f_mod)
    s0, s1 = [1], [0]
    t0, t1 = [0], [1]

    while r1 != [0]:
        q, r2 = _poly_divmod_mod(r0, r1, prime)
        r0, r1 = r1, r2
        s0, s1 = s1, _poly_sub_mod(s0, _poly_mul_mod(q, s1, prime), prime)
        t0, t1 = t1, _poly_sub_mod(t0, _poly_mul_mod(q, t1, prime), prime)

    if len(r0) != 1 or r0[0] == 0:
        raise ValueError("polynomial is not invertible modulo (x^N - 1) over this prime")

    scale = pow(r0[0], -1, prime)
    inv = _poly_scale_mod(t0, scale, prime)  # s0*phi + inv*f = 1
    _, inv_red = _poly_divmod_mod(inv, phi, prime)
    inv_red = inv_red[:N] + [0] * (N - len(inv_red))
    return inv_red
```

This step answers: “What does it mean for a polynomial to be invertible in `R_p`?” Practically: it means there exists another polynomial `F_p` such that `f * F_p ≡ 1 (mod p, x^N - 1)`.

### Step 3: Key generation + encryption

Now we can build a toy NTRUEncrypt-style public key. We sample small `f` and `g`, compute `f^{-1} (mod q)`, then set:

- `h = p * f^{-1} * g (mod q)`
- Encrypt: `e = r*h + m (mod q)`

```python
def _rand_from_seed(seed: str) -> random.Random:
    h = hashlib.sha256(seed.encode("utf-8")).digest()
    return random.Random(int.from_bytes(h[:8], "big"))


def sample_ternary(N: int, rand: random.Random, weight: int) -> List[int]:
    """
    Sample a "small" polynomial with exactly `weight` non-zero coefficients,
    each chosen from {-1, +1}.
    """
    if weight < 0 or weight > N:
        raise ValueError("sample_ternary: invalid weight")
    out = [0] * N
    positions = list(range(N))
    rand.shuffle(positions)
    chosen = positions[:weight]
    half = weight // 2
    for i, pos in enumerate(chosen):
        out[pos] = 1 if i < half else -1
    rand.shuffle(out)
    return out


@dataclass(frozen=True)
class NTRUParams:
    N: int
    p: int
    q: int


@dataclass(frozen=True)
class NTRUPublicKey:
    params: NTRUParams
    h: List[int]  # coefficients modulo q


@dataclass(frozen=True)
class NTRUPrivateKey:
    params: NTRUParams
    f: List[int]  # small coefficients (centered integers)
    f_inv_p: List[int]  # coefficients modulo p (0..p-1)


def ntru_keygen_deterministic(params: NTRUParams, seed: str) -> Tuple[NTRUPublicKey, NTRUPrivateKey]:
    """
    Deterministic toy key generation for NTRUEncrypt-style encryption.

    This is a teaching aid: it uses small primes and brute-force sampling
    until an invertible `f` is found.
    """
    if params.p <= 2 or params.q <= 2 or params.p >= params.q:
        raise ValueError("ntru_keygen_deterministic: require 2 < p < q")
    if params.N < 3:
        raise ValueError("ntru_keygen_deterministic: N too small")

    rand = _rand_from_seed(seed)

    for _ in range(10_000):
        f = sample_ternary(params.N, rand, weight=max(3, params.N // 3))
        try:
            f_inv_p = poly_inverse_mod_prime(f, params.N, params.p)
            f_inv_q = poly_inverse_mod_prime(f, params.N, params.q)
        except ValueError:
            continue

        g = sample_ternary(params.N, rand, weight=max(3, params.N // 3))
        h = poly_mul_cyclic(f_inv_q, g, params.N, mod=params.q)
        h = poly_scalar_mul(h, params.p, mod=params.q)

        pub = NTRUPublicKey(params=params, h=h)
        priv = NTRUPrivateKey(params=params, f=f, f_inv_p=f_inv_p)
        return pub, priv

    raise RuntimeError("ntru_keygen_deterministic: failed to find invertible f")


def ntru_encrypt(pub: NTRUPublicKey, m: List[int], r: List[int]) -> List[int]:
    """
    Encrypt a message polynomial m using blinding polynomial r:
      e = r*h + m (mod q)
    """
    N, q = pub.params.N, pub.params.q
    if len(m) != N or len(r) != N:
        raise ValueError("ntru_encrypt: m and r must have length N")
    e = poly_add(poly_mul_cyclic(r, pub.h, N, mod=q), poly_mod(m, q), mod=q)
    return e
```

### Step 4: Decryption + roundtrip

Decryption multiplies the ciphertext by the secret `f`, then uses center-lift to recover the intended small coefficients before reducing modulo `p`.

```python
def ntru_decrypt(priv: NTRUPrivateKey, e: List[int]) -> List[int]:
    """
    Decrypt:
      a = f*e (mod q) then center-lift a to small integers
      m = f^{-1} * a (mod p) then center-lift modulo p
    """
    N, p, q = priv.params.N, priv.params.p, priv.params.q
    if len(e) != N:
        raise ValueError("ntru_decrypt: ciphertext must have length N")
    a = poly_mul_cyclic(priv.f, e, N, mod=q)
    a_center = poly_center_lift(a, q)
    m_mod_p = poly_mul_cyclic(priv.f_inv_p, poly_mod(a_center, p), N, mod=p)
    m_center = poly_center_lift(m_mod_p, p)
    return m_center
```

Run it:
`python3 code/main.py`

## Use It

- **NTRU Prime / sntrup KEM (modern).** In practice you almost never deploy “raw NTRUEncrypt PKE.” You deploy a **KEM** (key encapsulation mechanism) with constant-time implementations, carefully chosen parameters, and a CCA-secure transform.
- **Classic NTRUEncrypt (historical + standardization).** Older NTRUEncrypt variants exist (and have extensive engineering around encoding, failure handling, and side channels).

What changes in “real life” compared to this toy:

| Topic | This lesson | Production reality |
|------|-------------|-------------------|
| Moduli | tiny primes (`p=3`, `q=61`) | specific parameter sets, often `p=3`, large `q`, strict bounds |
| Inversion | extended Euclid over a prime field | specialized inversion and constant-time code paths |
| Payload | polynomial `m` directly | structured encoding, padding, and validity checks |
| Security | CPA-style intuition | CCA security (KEM + transform), failure indistinguishability |
| Side channels | ignored | constant-time + masked/microarchitectural hardening |

## Pitfalls

1. **Treating decryption failure as “just an error.”** If your code takes a different amount of time, logs differently, or retries differently on failure, you can hand attackers an oracle.
2. **Parameter drift.** Small changes in sampling weight, message encoding, or modulus sizes can silently raise decryption-failure rates from “negligible” to “practically exploitable.”
3. **Assuming commutativity fixes bugs.** In cyclic rings multiplication is commutative, but *reductions, encodings, and transforms* can be order-sensitive in real code.
4. **Skipping center-lift / range checks.** The math proof of correctness depends on recovering the *intended* small integers before reducing mod `p`.
5. **Rolling your own CCA transform.** “Hash it and hope” isn’t a security proof. Use established KEM constructions with vetted parameter sets.

## Ship It

Save the reusable review checklist to:

- `outputs/ntru-encryption-review-checklist.md`

Use it to review PRs that implement (or wrap) NTRU-like code:

- check parameters + bounds,
- check failure behavior,
- check constant-time constraints,
- check that a CCA-secure KEM / transform is used instead of raw PKE.

## Exercises

1. Easy: Run `python3 code/main.py`. Observe how center-lift turns `mod q` residues back into small signed integers.
2. Medium: Change `(N, p, q)` in `_demo_params()` to another small prime `q` (e.g. `q=59` or `q=71`) and see how often `ntru_keygen_deterministic` needs to resample `f`. Explain what “invertible in `R_p` and `R_q`” is checking.
3. Hard: Write a short “red team note” explaining how decryption failures can turn into a side-channel/oracle problem in real systems, and map each risk to one item in `outputs/ntru-encryption-review-checklist.md`.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| `Z_q[x]/(x^N - 1)` | “polynomials mod q” | cyclic convolution: indices wrap because `x^N ≡ 1` |
| center-lift | “make it negative/positive” | choose the small signed representative of a residue mod `q` |
| invertible polynomial | “has an inverse” | there exists `F` with `f*F ≡ 1 (mod p, x^N - 1)` |
| decryption failure | “rare bug” | event that must be negligible *and* handled without leaking |
| NTRU Prime | “NTRU but safer” | NTRU-family KEMs with different ring choices and conservative design |

## Further Reading

- Hoffstein, Pipher, Silverman, *NTRU: A Ring-Based Public Key Cryptosystem* (1996/1998) — the original NTRU design and intuition.
- NIST PQC, *NTRU / NTRU Prime submissions* (Round 1–3 era) — engineering notes, parameter choices, and security discussions.
- Bernstein et al., *NTRU Prime: reducing attack surface at low cost* (2016+) — motivation for “Prime” ring choices and conservative design.
