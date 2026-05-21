# NewHope & Saber — Noise vs Rounding in Lattice KEMs

> You don’t “hide” the secret with one trick: you either **add noise** (LWE/RLWE) or you **throw away bits** (LWR/RLWR).

**Type:** Build  
**Languages:** Python  
**Prerequisites:** `phases/14-pq-lattice/04-regev-encryption`, `phases/14-pq-lattice/06-kyber-ml-kem`, `phases/14-pq-lattice/11-frodokem`  
**Time:** ~45 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** why NewHope lives in a polynomial ring `R_q = Z_q[x]/(x^n + 1)` and why `n` is a power of two.
- **Distinguish** RLWE (random error sampling) from RLWR (deterministic rounding noise).
- **Compute** negacyclic polynomial products (the `x^n = -1` rule) and reduce coefficients mod `q`.
- **Implement** a toy RLWE PKE (NewHope-family flavor) with “0 vs q/2” message embedding.
- **Apply** a toy LWR PKE (Saber-family flavor) using `p|q` rounding and bit-decoding.

## The Problem
You want a post-quantum key exchange / KEM, but “just doing Diffie–Hellman with a different group” is not an option: the security assumptions change, and quantum attacks (notably Shor) change what’s feasible.

Lattice KEMs solved the practicality problem by leaning on two ideas that are easy to implement and fast on real machines:
1) work in a structured ring/module so multiplication is fast, and  
2) make decryption “usually correct” via **noise** (LWE/RLWE) or **rounding** (LWR/RLWR).

If you don’t internalize how noise/rounding and decoding interact, you’ll ship a scheme that is either insecure (too little hiding) or unreliable (too many decryption failures), and you won’t be able to review or debug real ML-KEM implementations later.

## The Concept
Both NewHope and Saber are “public-key encryption + KEM transform” designs built on lattice problems.

### The common algebra
We work in the ring:

`R_q = Z_q[x] / (x^n + 1)`

Elements are polynomials of degree `< n` with coefficients mod `q`. The reduction polynomial enforces:

`x^n ≡ -1`

That means multiplication is **negacyclic**:

`(a(x) * b(x)) mod (x^n + 1)` wraps the high-degree terms back into low degrees with a minus sign.

### RLWE (NewHope flavor): hide with sampled error
Toy (ring) LWE-style key equation:

- choose uniform `a ∈ R_q` (public)
- sample small secret `s` and error `e`
- publish `b = a*s + e (mod q)`

To encrypt a bit `m ∈ {0,1}`, embed it as a coefficient near either `0` or `q/2`. After decryption you decode by “which center is closer?”

### RLWR / LWR (Saber flavor): hide by rounding (throwing away bits)
LWR replaces sampled error with deterministic rounding:

`Round_p(a*s) ∈ R_p` where `p | q`

Intuition: if `q` and `p` are powers of two, “rounding to `p`” is “keep the top bits, drop the low bits”. The dropped bits behave like noise.

### NewHope vs Saber (high level)

| Scheme | Core hardness | “Noise” comes from | Typical moduli vibe |
|---|---|---|---|
| NewHope | Ring-LWE | sampled small error (CBD) | prime-ish `q` chosen for NTT-friendly arithmetic |
| Saber | Module-LWR | deterministic rounding + small error in ciphertext | power-of-two `q` and `p` for bit-shifts and compression |

In this lesson we implement toy versions of both patterns with tiny parameters so you can see the shape.

## Build It

### Step 1: Ring arithmetic (negacyclic polynomials)
```python
def mod_q(x: int, q: int) -> int:
    return x % q


def poly_add(a: List[int], b: List[int], q: int) -> List[int]:
    if len(a) != len(b):
        raise ValueError("length mismatch")
    return [(x + y) % q for x, y in zip(a, b)]


def poly_sub(a: List[int], b: List[int], q: int) -> List[int]:
    if len(a) != len(b):
        raise ValueError("length mismatch")
    return [(x - y) % q for x, y in zip(a, b)]


def poly_mul_negacyclic(a: List[int], b: List[int], q: int) -> List[int]:
    if len(a) != len(b):
        raise ValueError("length mismatch")
    n = len(a)
    acc = [0] * n
    for i in range(n):
        ai = a[i]
        for j in range(n):
            prod = ai * b[j]
            k = i + j
            if k < n:
                acc[k] += prod
            else:
                acc[k - n] -= prod
    return [x % q for x in acc]
```
This is the “ring backbone”: addition/subtraction are coefficient-wise mod `q`, and multiplication is naive `O(n^2)` with the key twist `x^n = -1` (so terms that overflow degree `n-1` wrap around with a minus sign).

### Step 2: Deterministic XOF + CBD noise sampling
```python
def xof(seed: bytes, domain: bytes, outlen: int) -> bytes:
    if outlen < 0:
        raise ValueError("outlen must be non-negative")
    return hashlib.shake_256(domain + seed).digest(outlen)


def _bit_at(buf: bytes, bit_index: int) -> int:
    if bit_index < 0:
        raise ValueError("bit_index must be non-negative")
    return (buf[bit_index // 8] >> (bit_index % 8)) & 1


def sample_small_poly_cbd(seed: bytes, n: int, eta: int, domain: bytes = b"cbd") -> List[int]:
    if n <= 0:
        raise ValueError("n must be positive")
    if eta <= 0:
        raise ValueError("eta must be positive")

    bits_needed = n * 2 * eta
    buf = xof(seed, domain, (bits_needed + 7) // 8)
    coeffs: List[int] = []
    bitpos = 0
    for _ in range(n):
        a = 0
        b = 0
        for _ in range(eta):
            a += _bit_at(buf, bitpos)
            bitpos += 1
        for _ in range(eta):
            b += _bit_at(buf, bitpos)
            bitpos += 1
        coeffs.append(a - b)
    return coeffs


def uniform_poly(seed: bytes, n: int, q: int, domain: bytes = b"uniform") -> List[int]:
    if n <= 0:
        raise ValueError("n must be positive")
    if q <= 1:
        raise ValueError("q must be > 1")

    limit = (65536 // q) * q
    out: List[int] = []
    counter = 0
    buf = b""
    pos = 0
    while len(out) < n:
        if pos + 2 > len(buf):
            counter_bytes = counter.to_bytes(4, "little")
            buf = xof(seed, domain + counter_bytes, 256)
            pos = 0
            counter += 1
        val = int.from_bytes(buf[pos : pos + 2], "little")
        pos += 2
        if val < limit:
            out.append(val % q)
    return out
```
Real schemes derive public parameters from an XOF (so nobody can “choose a backdoored `a`”) and sample small secrets/errors from distributions like CBD. Here we use `SHAKE-256` from the stdlib so everything is deterministic and reproducible.

### Step 3: NewHope-style RLWE PKE (toy)
```python
def _dist_mod(a: int, b: int, q: int) -> int:
    d = (a - b) % q
    return min(d, q - d)


def encode_bits_as_poly(bits: Iterable[int], q: int) -> List[int]:
    half = q // 2
    out = []
    for bit in bits:
        if bit not in (0, 1):
            raise ValueError("bits must be 0/1")
        out.append((bit * half) % q)
    return out


def decode_poly_to_bits(poly: List[int], q: int) -> List[int]:
    half = q // 2
    out: List[int] = []
    for x in poly:
        d0 = _dist_mod(x, 0, q)
        d1 = _dist_mod(x, half, q)
        out.append(1 if d1 < d0 else 0)
    return out


@dataclass(frozen=True)
class RLWEPublicKey:
    seed_a: bytes
    b: List[int]


@dataclass(frozen=True)
class RLWESecretKey:
    s: List[int]


def rlwe_keygen(seed_a: bytes, seed_s: bytes, n: int = TOY_N, q: int = NEWHOPE_Q, eta: int = TOY_ETA) -> Tuple[RLWEPublicKey, RLWESecretKey]:
    a = uniform_poly(seed_a, n=n, q=q, domain=b"rlwe-a")
    s = sample_small_poly_cbd(seed_s, n=n, eta=eta, domain=b"rlwe-s")
    e = sample_small_poly_cbd(seed_s, n=n, eta=eta, domain=b"rlwe-e")

    as_ = poly_mul_negacyclic(a, [x % q for x in s], q)
    b = poly_add(as_, [x % q for x in e], q)
    return RLWEPublicKey(seed_a=seed_a, b=b), RLWESecretKey(s=[x % q for x in s])


def rlwe_encrypt(pk: RLWEPublicKey, msg_bits: List[int], seed_r: bytes, n: int = TOY_N, q: int = NEWHOPE_Q, eta: int = TOY_ETA) -> Tuple[List[int], List[int]]:
    if len(msg_bits) != n:
        raise ValueError("msg_bits length must equal n")
    a = uniform_poly(pk.seed_a, n=n, q=q, domain=b"rlwe-a")
    sp = sample_small_poly_cbd(seed_r, n=n, eta=eta, domain=b"rlwe-sp")
    ep = sample_small_poly_cbd(seed_r, n=n, eta=eta, domain=b"rlwe-ep")
    epp = sample_small_poly_cbd(seed_r, n=n, eta=eta, domain=b"rlwe-epp")

    u = poly_add(poly_mul_negacyclic(a, [x % q for x in sp], q), [x % q for x in ep], q)
    v = poly_add(poly_mul_negacyclic(pk.b, [x % q for x in sp], q), [x % q for x in epp], q)
    v = poly_add(v, encode_bits_as_poly(msg_bits, q), q)
    return u, v


def rlwe_decrypt(sk: RLWESecretKey, ct: Tuple[List[int], List[int]], n: int = TOY_N, q: int = NEWHOPE_Q) -> List[int]:
    u, v = ct
    if len(u) != n or len(v) != n:
        raise ValueError("ciphertext polynomials must have length n")
    us = poly_mul_negacyclic(u, [x % q for x in sk.s], q)
    mpoly = poly_sub(v, us, q)
    return decode_poly_to_bits(mpoly, q)
```
This toy RLWE encryption pattern shows the “classic” trick: represent a bit by pushing a coefficient near either `0` or `q/2`, then recover the bit by measuring which center is closer after subtracting `u*s`.

### Step 4: Saber-style LWR PKE (toy)
```python
def poly_round_to_p(poly: List[int], q: int, p: int) -> List[int]:
    if p <= 0 or (q % p) != 0:
        raise ValueError("require p>0 and p|q")
    scale = q // p
    half = scale // 2
    out: List[int] = []
    for x in poly:
        out.append(((x + half) // scale) % p)
    return out


def poly_lift_from_p(poly_p: List[int], q: int, p: int) -> List[int]:
    if p <= 0 or (q % p) != 0:
        raise ValueError("require p>0 and p|q")
    scale = q // p
    return [(x % p) * scale % q for x in poly_p]


@dataclass(frozen=True)
class LWRPublicKey:
    seed_a: bytes
    b_p: List[int]


@dataclass(frozen=True)
class LWRSecretKey:
    s: List[int]


def lwr_keygen(seed_a: bytes, seed_s: bytes, n: int = TOY_N, q: int = SABER_Q, p: int = SABER_P, eta: int = TOY_ETA) -> Tuple[LWRPublicKey, LWRSecretKey]:
    a = uniform_poly(seed_a, n=n, q=q, domain=b"lwr-a")
    s = sample_small_poly_cbd(seed_s, n=n, eta=eta, domain=b"lwr-s")
    as_ = poly_mul_negacyclic(a, [x % q for x in s], q)
    b_p = poly_round_to_p(as_, q=q, p=p)
    return LWRPublicKey(seed_a=seed_a, b_p=b_p), LWRSecretKey(s=[x % q for x in s])


def lwr_encrypt(pk: LWRPublicKey, msg_bits: List[int], seed_r: bytes, n: int = TOY_N, q: int = SABER_Q, p: int = SABER_P, eta: int = TOY_ETA) -> Tuple[List[int], List[int]]:
    if len(msg_bits) != n:
        raise ValueError("msg_bits length must equal n")
    a = uniform_poly(pk.seed_a, n=n, q=q, domain=b"lwr-a")
    sp = sample_small_poly_cbd(seed_r, n=n, eta=eta, domain=b"lwr-sp")
    ep = sample_small_poly_cbd(seed_r, n=n, eta=eta, domain=b"lwr-ep")

    u = poly_add(poly_mul_negacyclic(a, [x % q for x in sp], q), [x % q for x in ep], q)

    b_lift = poly_lift_from_p(pk.b_p, q=q, p=p)
    v = poly_mul_negacyclic(b_lift, [x % q for x in sp], q)
    v_p = poly_round_to_p(v, q=q, p=p)

    half_p = p // 2
    v_p = [(x + (bit * half_p)) % p for x, bit in zip(v_p, msg_bits)]
    return u, v_p


def lwr_decrypt(sk: LWRSecretKey, ct: Tuple[List[int], List[int]], n: int = TOY_N, q: int = SABER_Q, p: int = SABER_P) -> List[int]:
    u, v_p = ct
    if len(u) != n or len(v_p) != n:
        raise ValueError("ciphertext polynomials must have length n")
    us = poly_mul_negacyclic(u, [x % q for x in sk.s], q)
    us_p = poly_round_to_p(us, q=q, p=p)

    half_p = p // 2
    out: List[int] = []
    for x, y in zip(v_p, us_p):
        d0 = _dist_mod((x - y) % p, 0, p)
        d1 = _dist_mod((x - y) % p, half_p, p)
        out.append(1 if d1 < d0 else 0)
    return out
```
This is the “rounding” version: the public key is stored in a smaller modulus `p`, and the scheme’s security relies on information loss when mapping from `q` down to `p` (the dropped bits are the “noise”).

Run it:

`python3 code/main.py`

## Use It
- NewHope: see the NewHope reference implementations/papers; the “real” design uses `n = 1024`, `q = 12289`, and heavy NTT engineering for multiplication.
- Saber: see the official Saber spec and reference code; Saber uses module structure (vectors of polynomials) and power-of-two moduli (commonly described as `q = 2^13`, `p = 2^10`) to make rounding and compression cheap.
- In 2024, NIST standardized Kyber as ML-KEM (FIPS 203). In modern systems you typically integrate ML-KEM rather than NewHope/Saber directly, but NewHope/Saber are still useful for understanding the design space and trade-offs.

## Pitfalls
- Confusing “mod q” with “centered”: decoding depends on how you interpret distances around `0` and `q/2`.
- Using non-domain-separated hashes/XOFs: reusing one seed stream for different roles (`a`, `s`, `e`, `r`) is a footgun.
- Picking parameters by vibes: too much noise yields decryption failures; too little noise/rounding leaks structure.
- Treating toy arithmetic as production-safe: constant-time, side-channel resistance, and CCA transforms (e.g. Fujisaki–Okamoto) are non-optional in real KEMs.
- Forgetting compression bias: “round then lift” must be designed so bias doesn’t accumulate into failures or leakage.

## Ship It
Save and reuse the checklist in `outputs/lattice-kem-review-checklist.md` when:
- reviewing PRs that touch lattice KEM code (sampling, rounding, compression, encoding), or
- integrating a KEM into a hybrid key exchange (where transcript binding and domain separation matter).

## Exercises
1. Easy: run `python3 code/main.py` and observe that both toy schemes decrypt the exact bit-patterns printed in Step 3 and Step 4.
2. Medium: in `code/main.py`, change `TOY_ETA` (e.g. `2`, `4`, `8`) and rerun; explain how it affects the margin between “decode to 0” and “decode to 1”.
3. Hard: extend the toy RLWE PKE into a toy “KEM-style” API: derive a shared key as `SHAKE-256(msg_bits || ct)` and explain why binding the ciphertext into the KDF matters (malleability/CCA intuition).

## Key Terms

| Term | What people say | What it actually means |
|---|---|---|
| LWE / RLWE | “Noise hides the secret” | Public values look random because `b = a*s + e` with a small random error `e`. |
| LWR / RLWR | “Rounding replaces noise” | The “error” comes from throwing away low bits when mapping `Z_q → Z_p`. |
| Negacyclic | “x^n = -1” | Multiply polynomials then fold terms `x^{n+k}` into `-x^k`. |
| CBD (η) | “Sample small integers” | Sum/difference of bits gives small coefficients in `[-η, η]`. |
| Decode | “Closest center” | Decide which of `{0, q/2}` (or `{0, p/2}`) a noisy value is nearer to. |

## Further Reading
- Alkim, Ducas, Pöppelmann, Schwabe, “Post-quantum key exchange — a new hope” (2016) — the original NewHope design and reconciliation discussion.
- D’Anvers et al., “Saber: Module-LWR based key exchange, CPA-secure encryption and CCA-secure KEM” (2018) — motivation for power-of-two moduli and LWR design choices.
- NewHope specification (NewHopeCrypto site) — algorithm-level details, encoding/compression, and NTT domain tricks.
