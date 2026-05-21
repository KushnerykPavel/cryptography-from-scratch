# Dilithium / ML-DSA from Scratch (Toy)

> Hints let you round the same way without seeing the missing bits.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** Phase 14, Lessons 04–07 (module-LWE context, polynomial rings, ML-KEM/Kyber basics)  
**Time:** ~120 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** how ML-DSA (Dilithium) fits the “Fiat–Shamir with aborts” pattern
- **Compute** products in \(R_q = \mathbb{Z}_q[x]/(x^n+1)\) and matrix–vector multiplies over that ring
- **Implement** `Decompose` / `HighBits` / `LowBits` plus `MakeHint` / `UseHint` in a toy setting
- **Distinguish** “public-key compression” (`t = t1·2^d + t0`) from “commitment rounding” (`w -> w1`)
- **Apply** the signing/verification equations and the rejection checks to catch real-world implementation bugs

## The Problem

Digital signatures are the glue of modern software and identity: package managers, secure boot, certificate chains, firmware updates, document signing, transparency logs, and more. If the signature breaks, everything above it becomes forgeable.

In a post-quantum migration plan, key exchange is only half the story. You also need a post-quantum signature scheme that you can ship in production and audit with confidence. That’s what ML-DSA (standardized from CRYSTALS-Dilithium) is for.

But ML-DSA is full of details that look like “just optimization” at first glance: high/low bits, dropped bits in the public key, hint bits in signatures, and a rejection-sampling loop that may retry. Missing any of these details can silently produce signatures that (a) fail to verify, (b) verify but leak key material over many signatures, or (c) mismatch the standard even though the code “looks right”.

This lesson builds a tiny, runnable ML-DSA-shaped signature to make those details feel inevitable.

## The Concept

### What ML-DSA is “shaped like”

ML-DSA is a lattice signature in the Fiat–Shamir style. At a high level, it has the same “commit → hash → respond” skeleton as Schnorr signatures, but the group operations are replaced by polynomial-ring / module-lattice arithmetic.

You can think in terms of:

- A public, structured matrix \(A \in R_q^{k\times \ell}\)
- Two small secret vectors \(s_1 \in R_q^\ell\) and \(s_2 \in R_q^k\)
- A public key vector \(t = A s_1 + s_2 \pmod q\)

To sign a message, we sample a fresh “mask” \(y\), compute \(w = A y\), hash \(w\) (actually: a compressed “high bits” view of \(w\)) into a short challenge polynomial \(c\), then respond with \(z = y + c s_1\).

Verification recomputes a \(w'\) from public data and checks the hash matches the signature’s challenge seed.

### Why “high bits” and “hint bits” show up

Two nuisances appear immediately in real ML-DSA:

1. The verifier does not recompute exactly \(w = Ay\). It recomputes something derived from \(Az - ct\), which expands to \(Ay - cs_2\). Those extra “small noise” terms must not change the *rounded/high-bit* view of the commitment, or the verifier would hash a different value.
2. The public key does not include all of \(t\). It stores a compressed \(t_1\) and drops the low bits \(t_0\). Verification therefore naturally computes an approximation that differs by \(c t_0\). A *hint* tells the verifier how to round the approximation to recover the same “high bits” the signer hashed.

The guiding idea:

- `Decompose` splits a coefficient into **high bits** + **low bits** at a chosen base \(\alpha\).
- `MakeHint` tells you whether a small correction would flip the high bits.
- `UseHint` lets you recover the high bits of \(r + z\) using only \(r\) and the hint bit (when \(z\) is sufficiently small).

## Build It

### Step 1: Ring arithmetic (R_q)

ML-DSA works over polynomials modulo \(x^n+1\), i.e. **negacyclic** multiplication. This is the algebraic “engine” behind the matrix–vector multiplies.

```python
def poly_add(a: Sequence[int], b: Sequence[int], q: int) -> list[int]:
    if len(a) != len(b) or len(a) != TOY_N:
        raise ValueError("wrong polynomial length")
    return [(int(x) + int(y)) % q for x, y in zip(a, b)]


def poly_sub(a: Sequence[int], b: Sequence[int], q: int) -> list[int]:
    if len(a) != len(b) or len(a) != TOY_N:
        raise ValueError("wrong polynomial length")
    return [(int(x) - int(y)) % q for x, y in zip(a, b)]


def poly_mul_negacyclic(a: Sequence[int], b: Sequence[int], q: int) -> list[int]:
    if len(a) != len(b) or len(a) != TOY_N:
        raise ValueError("wrong polynomial length")
    out = [0] * TOY_N
    for i, ai in enumerate(a):
        ai = int(ai) % q
        for j, bj in enumerate(b):
            bj = int(bj) % q
            k = i + j
            prod = (ai * bj) % q
            if k < TOY_N:
                out[k] = (out[k] + prod) % q
            else:
                out[k - TOY_N] = (out[k - TOY_N] - prod) % q
    return out
```

### Step 2: HighBits / LowBits + hints

The “hint” mechanism is the key ML-DSA idea you can’t safely hand-wave. It’s how verification reconstructs the same high bits the signer hashed, even when some low-bit information is missing.

```python
def decompose_coeff(r: int, q: int, alpha: int) -> tuple[int, int]:
    if alpha <= 0 or (q - 1) % alpha != 0:
        raise ValueError("alpha must divide q-1")
    r = int(r) % q
    r1 = (r + alpha // 2) // alpha
    r0 = r - r1 * alpha
    if r0 > alpha // 2:
        r0 -= alpha
        r1 += 1
    if r0 < -alpha // 2:
        r0 += alpha
        r1 -= 1
    r1 %= (q - 1) // alpha
    return int(r1), int(r0)


def high_bits(p: Sequence[int], q: int, alpha: int) -> list[int]:
    if len(p) != TOY_N:
        raise ValueError("wrong polynomial length")
    return [decompose_coeff(c, q, alpha)[0] for c in p]


def low_bits(p: Sequence[int], q: int, alpha: int) -> list[int]:
    if len(p) != TOY_N:
        raise ValueError("wrong polynomial length")
    return [decompose_coeff(c, q, alpha)[1] for c in p]


def make_hint(z: Sequence[int], r: Sequence[int], q: int, alpha: int) -> list[int]:
    if len(z) != len(r) or len(r) != TOY_N:
        raise ValueError("wrong polynomial length")
    out = []
    for zi, ri in zip(z, r):
        r1 = decompose_coeff(ri, q, alpha)[0]
        v1 = decompose_coeff(ri + zi, q, alpha)[0]
        out.append(1 if r1 != v1 else 0)
    return out


def use_hint(h: Sequence[int], r: Sequence[int], q: int, alpha: int) -> list[int]:
    if len(h) != len(r) or len(r) != TOY_N:
        raise ValueError("wrong polynomial length")
    out = []
    m = (q - 1) // alpha
    for hi, ri in zip(h, r):
        r1, r0 = decompose_coeff(ri, q, alpha)
        if int(hi) == 0:
            out.append(r1)
            continue
        if r0 > 0:
            out.append((r1 + 1) % m)
        else:
            out.append((r1 - 1) % m)
    return out
```

### Step 3: Toy ML-DSA key generation

Real ML-DSA key generation compresses \(t\) by dropping \(d\) low bits. We mirror that with `power2round_*` and store only `t1` in the public key (plus the matrix seed `rho`).

```python
def expand_a(rho: bytes, q: int) -> list[list[list[int]]]:
    if len(rho) != 32:
        raise ValueError("rho must be 32 bytes")
    mat: list[list[list[int]]] = []
    for i in range(TOY_K):
        row: list[list[int]] = []
        for j in range(TOY_L):
            stream = shake256(rho + bytes([i, j]), TOY_N * 4)
            poly = []
            for t in range(TOY_N):
                coeff = int.from_bytes(stream[t * 4 : (t + 1) * 4], "little") % q
                poly.append(coeff)
            row.append(poly)
        mat.append(row)
    return mat


def power2round_coeff(r: int, q: int, d: int) -> tuple[int, int]:
    if d <= 0 or d >= 31:
        raise ValueError("bad d")
    r = int(r) % q
    two_d = 1 << d
    r0 = r % two_d
    if r0 > two_d // 2:
        r0 -= two_d
    r1 = (r - r0) // two_d
    return int(r1), int(r0)


def power2round_vec(v: Sequence[Sequence[int]], q: int, d: int) -> tuple[list[list[int]], list[list[int]]]:
    high: list[list[int]] = []
    low: list[list[int]] = []
    for p in v:
        if len(p) != TOY_N:
            raise ValueError("wrong polynomial length")
        p_high = []
        p_low = []
        for c in p:
            r1, r0 = power2round_coeff(c, q, d)
            p_high.append(r1)
            p_low.append(r0)
        high.append(p_high)
        low.append(p_low)
    return high, low


def toy_mldsa_keygen(seed: bytes) -> tuple[PublicKey, SecretKey]:
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    rho = shake256(seed + b"rho", 32)
    key_seed = shake256(seed + b"key", 32)
    mat_a = expand_a(rho, TOY_Q)

    s1 = [_sample_small_poly(seed, b"s1" + bytes([i]), TOY_ETA, TOY_Q) for i in range(TOY_L)]
    s2 = [_sample_small_poly(seed, b"s2" + bytes([i]), TOY_ETA, TOY_Q) for i in range(TOY_K)]

    t = vec_add(mat_vec_mul(mat_a, s1, TOY_Q), s2, TOY_Q)
    t1, t0 = power2round_vec(t, TOY_Q, TOY_D)

    pk = PublicKey(rho=rho, t1=t1)
    sk = SecretKey(rho=rho, key_seed=key_seed, s1=s1, s2=s2, t0=t0, pk=pk)
    return pk, sk
```

### Step 4: Toy ML-DSA sign + verify

This step is the full flow: commit (`w1`), hash-to-challenge (`c_seed` → `c`), respond (`z`), reject on bad norms / rounding mismatch, then verify by recomputing the same `c_seed`.

```python
def toy_mldsa_sign_det(sk: SecretKey, msg: bytes, max_tries: int = 64) -> Signature:
    mat_a = expand_a(sk.rho, TOY_Q)
    mu = shake256(sk.pk.encode() + msg, 64)

    for kappa in range(max_tries):
        y_seed = shake256(sk.key_seed + mu + _i2le(kappa, 2), 32)
        y = [_sample_mask_poly(y_seed, b"y" + bytes([i]), TOY_GAMMA1, TOY_Q) for i in range(TOY_L)]
        w = mat_vec_mul(mat_a, y, TOY_Q)
        w1 = [high_bits(p, TOY_Q, TOY_ALPHA) for p in w]

        c_seed = _challenge_from(mu, w1)
        c = sample_in_ball(c_seed, TOY_Q, TOY_TAU)

        cs2 = vec_mul_poly(sk.s2, c, TOY_Q)
        w_minus_cs2 = vec_sub(w, cs2, TOY_Q)
        if [high_bits(p, TOY_Q, TOY_ALPHA) for p in w_minus_cs2] != w1:
            continue

        cs1 = vec_mul_poly(sk.s1, c, TOY_Q)
        z = vec_add(y, cs1, TOY_Q)
        if vec_norm_inf_centered(z, TOY_Q) >= TOY_GAMMA1 - TOY_BETA:
            continue

        az = mat_vec_mul(mat_a, z, TOY_Q)
        ct1_2d = vec_scale(vec_mul_poly(sk.pk.t1, c, TOY_Q), 1 << TOY_D, TOY_Q)
        r = vec_sub(az, ct1_2d, TOY_Q)

        neg_ct0 = vec_scale(vec_mul_poly(sk.t0, c, TOY_Q), -1, TOY_Q)
        h = [make_hint(zp, rp, TOY_Q, TOY_ALPHA) for zp, rp in zip(neg_ct0, r)]
        if hint_weight(h) > TOY_OMEGA:
            continue

        return Signature(c_seed=c_seed, z=z, h=h)

    raise RuntimeError("signing failed (too many rejections)")


def toy_mldsa_verify(pk: PublicKey, msg: bytes, sig: Signature) -> bool:
    if len(sig.c_seed) != 32:
        return False
    if len(pk.t1) != TOY_K or len(sig.z) != TOY_L or len(sig.h) != TOY_K:
        return False
    for p in pk.t1:
        if len(p) != TOY_N:
            return False
    for p in sig.z:
        if len(p) != TOY_N:
            return False
    for p in sig.h:
        if len(p) != TOY_N or any(int(x) not in (0, 1) for x in p):
            return False
    if vec_norm_inf_centered(sig.z, TOY_Q) >= TOY_GAMMA1 - TOY_BETA:
        return False
    if hint_weight(sig.h) > TOY_OMEGA:
        return False

    mat_a = expand_a(pk.rho, TOY_Q)
    mu = shake256(pk.encode() + msg, 64)
    c = sample_in_ball(sig.c_seed, TOY_Q, TOY_TAU)

    az = mat_vec_mul(mat_a, sig.z, TOY_Q)
    ct1_2d = vec_scale(vec_mul_poly(pk.t1, c, TOY_Q), 1 << TOY_D, TOY_Q)
    r = vec_sub(az, ct1_2d, TOY_Q)

    w1 = [use_hint(hp, rp, TOY_Q, TOY_ALPHA) for hp, rp in zip(sig.h, r)]
    c_seed_check = _challenge_from(mu, w1)
    return c_seed_check == sig.c_seed
```

Run it:

```bash
python3 code/main.py
```

## Use It

This lesson’s code is intentionally tiny and insecure. For real ML-DSA, use a vetted implementation that follows NIST FIPS 204 exactly.

Practical options you’ll see in production:

- **NIST FIPS 204**: the normative spec for ML-DSA (ML-DSA-44/65/87).
- **OpenSSL**: exposes ML-DSA via the EVP signature APIs (look for `EVP_SIGNATURE-ML-DSA` docs).
- **liboqs / Open Quantum Safe**: provides ML-DSA implementations and integration points for experimentation and TLS testbeds.

## Pitfalls

1. **Skipping the “rounding mismatch” rejection.** In signing, you must ensure the verifier will hash the same `w1` (in our toy code: the `w_minus_cs2` check).
2. **Using one parameter for everything.** In the real scheme, `t` compression (`2^d`) and `w` decomposition (`α = 2·γ2`) are distinct; mixing them breaks correctness or leaks information.
3. **Not checking `||z||∞` in verification.** It’s not optional; it’s part of the signature validity condition.
4. **Accepting non-canonical encodings.** If multiple byte encodings decode to the same math object, you can get malleability and cross-implementation bugs.
5. **Forgetting that “from scratch” is not constant-time.** Real implementations must avoid timing / cache leakage in sampling, NTTs, packing, and norm checks.

## Ship It

Save and reuse the review artifact:

- `outputs/ml-dsa-implementation-review-checklist.md`

Use it as a PR checklist when reviewing an ML-DSA implementation or evaluating a library for compliance and interoperability.

## Exercises

1. **Easy:** Run `python3 code/main.py`. Observe that `UseHint(MakeHint(z,r), r)` matches `HighBits(r+z)` and that tampering with the message breaks verification.
2. **Medium:** Change `TOY_TAU` (challenge sparsity) and `TOY_OMEGA` (hint weight limit). Measure how often signing needs to retry (increase `max_tries` and count rejections).
3. **Hard:** Use a real implementation (OpenSSL or liboqs) to sign and verify a file. Then compare: which checks exist in the library API, and which are internal to the implementation?

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Module lattice | “A lattice thing” | Vectors of polynomials over a ring \(R_q\), with structured matrix–vector multiplication |
| Fiat–Shamir | “Hash makes it non-interactive” | Replace a verifier challenge with `H(message || commitment)` |
| Abort / rejection sampling | “Retry sometimes” | Reject signatures that would leak information or fail correctness conditions |
| `t1` / `t0` | “Dropped bits” | Public key keeps high bits `t1`; secret key keeps low bits `t0` so the signer can correct rounding |
| Hint (`h`) | “Some extra bits” | A compact guide telling the verifier how to round an approximation to match the signer’s commitment |

## Further Reading

- NIST, *FIPS 204: Module-Lattice-Based Digital Signature Standard* (2024) — the ML-DSA spec (formerly Dilithium).
- Ducas et al., *CRYSTALS-Dilithium* (specification, latest) — background and design rationale for hints, rounding, and parameter sets.
- Barbosa et al., *Fixing and Mechanizing the Security Proof of Fiat–Shamir with Aborts and Dilithium* (CRYPTO 2023) — deeper view into the security proof details.

