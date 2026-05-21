# BGV / BFV from Scratch
> Exact integer FHE is “plaintext + noise”. Everything you do is about keeping the noise below the rounding threshold.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 4 · 09 (LWE), Phase 4 · 10 (Ring-LWE & Module-LWE)
**Time:** ~120 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain BFV’s `Δ = ⌊q/t⌋` scaling and the decryption rounding rule.
- Compute negacyclic products in `R_q = Z_q[x]/(x^n + 1)`.
- Implement a toy BFV pipeline: keygen → encrypt → decrypt → add → mul → relinearize.
- Distinguish BFV’s “scale-and-round after multiply” from BGV’s “modulus switching across levels”.
- Apply a toy modulus switch and predict when decryption will still succeed.

## The Problem

You want to compute on encrypted integers **exactly**, not approximately. Example: a hospital wants to compute a risk score from a patient’s encrypted lab values; a fintech wants to run fraud rules on encrypted transaction features; a SaaS wants to run a SQL-style filter (`age > 30 AND country == "PL"`) over encrypted rows. You cannot decrypt on the server, and “just use MPC” may not fit latency, networking, or multi-tenant constraints.

Fully Homomorphic Encryption (FHE) gives you the dream API: encrypt once, then do additions and multiplications on ciphertexts, and only the client can decrypt. But there is a catch: every ciphertext carries **noise**, and every homomorphic operation grows it. BFV and BGV are the workhorse “exact arithmetic” schemes: they can evaluate integer circuits, but only up to a depth your parameters can handle.

This lesson builds a tiny, from-scratch BFV-style scheme (toy parameters, stdlib-only) and uses it to make the real engineering questions concrete: what does “noise budget” mean, why does multiplication explode complexity, what is relinearization, and why do BGV/BFV talk about modulus switching and “levels”?

## The Concept

### The ring

We work in the polynomial ring:

`R_q = Z_q[x] / (x^n + 1)` where `n` is a power of two.

Multiplication is **negacyclic**: `x^n == -1`, so high-degree terms fold back with a sign flip. This is the algebraic container that lets Ring-LWE look like “LWE, but packed into polynomials”.

### The BFV invariant (what encryption “means”)

A BFV-style ciphertext `(c0, c1)` is designed so that:

`c0 + c1*s  ≈  Δ*m  (mod q)`

where:
- `s` is a small secret polynomial (the Ring-LWE secret),
- `m` is the plaintext polynomial with coefficients modulo `t`,
- `q` is the ciphertext modulus,
- `Δ = ⌊q/t⌋` is a scaling factor,
- and “≈” hides a small noise term.

Decryption computes `u = (c0 + c1*s) mod q`, lifts coefficients to a centered range (around 0), and then **rounds**:

`m = round(t * u / q) mod t`

That rounding step is why BFV can do *exact* integer arithmetic: as long as noise stays small, rounding recovers the intended integer.

### What changes for multiplication

Addition is easy: add components, noise adds.

Multiplication is the hard part:
- `(c0 + c1*s)` times `(d0 + d1*s)` produces a term in `s^2`,
- so the product ciphertext naturally becomes **3 components** `(e0, e1, e2)` decrypting with `s, s^2`.

To keep ciphertext size fixed (usually back to 2 components), BFV/BGV uses **relinearization** (a special key-switch): you publish a “relinearization key” that lets the evaluator fold the `s^2` term back into the `(1, s)` basis.

### Where BGV differs

BFV typically manages scale by doing a **scale-and-round** after multiplication (the `t/q` factor in this lesson’s `bfv_mul_raw`).

BGV is usually taught as managing depth via **modulus switching** across a chain of ciphertext moduli. After (some) operations, you map ciphertext coefficients from modulus `q` down to a smaller `q'` via scale-and-round. This shrinks values (and the noise) in a controlled way, at the cost of losing “headroom” for further growth.

This lesson implements BFV-style multiplication + relinearization, and then adds a small modulus-switch demo to illustrate the BGV idea.

## Build It

### Step 1: Ring arithmetic (R_q = Z_q[x]/(x^n+1))

```python
def poly_mul_negacyclic_int(a: Sequence[int], b: Sequence[int]) -> Poly:
    if len(a) != len(b):
        raise ValueError("poly_mul_negacyclic_int: length mismatch")
    n = len(a)
    tmp = [0] * (2 * n - 1)
    for i in range(n):
        ai = a[i]
        for j in range(n):
            tmp[i + j] += ai * b[j]
    res = [0] * n
    for k, v in enumerate(tmp):
        if k < n:
            res[k] += v
        else:
            res[k - n] -= v  # x^n == -1
    return res


def poly_mul_negacyclic(a: Sequence[int], b: Sequence[int], q: int) -> Poly:
    return poly_mod(poly_mul_negacyclic_int(a, b), q)
```

Everything that follows is “just” these ring ops plus careful rounding. If you get the negacyclic reduction wrong, encryption/decryption will appear to randomly fail.

### Step 2: BFV-style Encrypt/Decrypt (exact integers mod t)

```python
def bfv_encrypt(params: Params, s: Sequence[int], m: Sequence[int], rng: random.Random) -> Ciphertext:
    _check_params(params)
    if len(s) != params.n or len(m) != params.n:
        raise ValueError("bfv_encrypt: length mismatch")
    a = sample_uniform(params.n, params.q, rng)
    e = sample_small(params.n, rng, bound=1)
    a_s = poly_mul_negacyclic(a, poly_mod(s, params.q), params.q)
    delta_m = poly_scalar_mul(poly_mod(m, params.q), params.delta, params.q)
    c0 = poly_add(poly_add(a_s, poly_mod(e, params.q), params.q), delta_m, params.q)
    c1 = poly_sub([0] * params.n, a, params.q)
    return Ciphertext(c0=c0, c1=c1)


def bfv_decrypt(params: Params, s: Sequence[int], ct: Ciphertext) -> Poly:
    _check_params(params)
    if len(s) != params.n or len(ct.c0) != params.n or len(ct.c1) != params.n:
        raise ValueError("bfv_decrypt: length mismatch")
    c1s = poly_mul_negacyclic(ct.c1, poly_mod(s, params.q), params.q)
    u = poly_add(ct.c0, c1s, params.q)
    u_centered = poly_lift_centered(u, params.q)
    return [round_div(x * params.t, params.q) % params.t for x in u_centered]
```

This is the core “plaintext + noise” invariant in code. Decryption is rounding; correctness is “noise must stay small enough that rounding lands on the right integer”.

### Step 3: Homomorphic addition

```python
def bfv_add(params: Params, a: Ciphertext, b: Ciphertext) -> Ciphertext:
    if len(a.c0) != params.n or len(b.c0) != params.n:
        raise ValueError("bfv_add: length mismatch")
    return Ciphertext(
        c0=poly_add(a.c0, b.c0, params.q),
        c1=poly_add(a.c1, b.c1, params.q),
    )
```

Addition is “free”: component-wise add modulo `q`. The only thing to remember is that noise adds too, so repeated addition can still break correctness if you do enough of it.

### Step 4: Homomorphic multiplication + relinearization

```python
def bfv_mul_raw(params: Params, a: Ciphertext, b: Ciphertext) -> Ciphertext3:
    """
    BFV/FV-style ciphertext multiplication, producing a 3-component ciphertext:
        (d0, d1, d2) where d0 + d1*s + d2*s^2 ~= Δ*(m*m') (mod q)

    Implementation detail: we compute products using the centered lift to
    reduce wrap-around surprises, then scale-and-round by t/q.
    """

    if len(a.c0) != params.n or len(b.c0) != params.n:
        raise ValueError("bfv_mul_raw: length mismatch")

    a0 = poly_lift_centered(a.c0, params.q)
    a1 = poly_lift_centered(a.c1, params.q)
    b0 = poly_lift_centered(b.c0, params.q)
    b1 = poly_lift_centered(b.c1, params.q)

    p00 = poly_mul_negacyclic_int(a0, b0)
    p01 = poly_add_int(poly_mul_negacyclic_int(a0, b1), poly_mul_negacyclic_int(a1, b0))
    p11 = poly_mul_negacyclic_int(a1, b1)

    d0 = poly_scale_round(p00, params.t, params.q, params.q)
    d1 = poly_scale_round(p01, params.t, params.q, params.q)
    d2 = poly_scale_round(p11, params.t, params.q, params.q)
    return Ciphertext3(c0=d0, c1=d1, c2=d2)


def bfv_relinearize(params: Params, ct: Ciphertext3, rlk: RelinKey) -> Ciphertext:
    if rlk.base != params.relin_base:
        raise ValueError("bfv_relinearize: rlk base mismatch")
    digits = len(rlk.pieces)
    dec = poly_decompose_base(ct.c2, rlk.base, digits)

    acc0 = ct.c0[:]
    acc1 = ct.c1[:]
    for di, (k0, k1) in zip(dec, rlk.pieces):
        acc0 = poly_add(acc0, poly_mul_negacyclic(k0, di, params.q), params.q)
        acc1 = poly_add(acc1, poly_mul_negacyclic(k1, di, params.q), params.q)
    return Ciphertext(c0=acc0, c1=acc1)
```

`bfv_mul_raw` is the “math” (multiply, then scale-and-round by `t/q` to keep the plaintext scale stable). `bfv_relinearize` is the “engineering” (key switching to keep ciphertext size at 2 components, so your evaluator doesn’t carry an ever-growing tuple).

### Step 5: Modulus switching (BGV-style idea)

```python
def bfv_modulus_switch(params: Params, ct: Ciphertext, q_new: int) -> Ciphertext:
    """
    Toy BGV-style modulus switching:

    For each coefficient c in Z_q, map it to Z_{q_new} by:
        c' = round((q_new/q) * lift_centered(c)) mod q_new

    This is only a demo. Real BGV/BFV implementations do this across an RNS
    modulus chain (many primes), and correctness constraints are subtle.
    """

    _check_params(params)
    if q_new <= 2 or q_new >= params.q:
        raise ValueError("q_new must be in (2, q)")

    def switch_poly(p: Sequence[int]) -> Poly:
        lifted = poly_lift_centered(p, params.q)
        return [round_div(x * q_new, params.q) % q_new for x in lifted]

    return Ciphertext(c0=switch_poly(ct.c0), c1=switch_poly(ct.c1))
```

This is the core modulus-switching idea in one function: lift to centered integers, scale by `q_new/q`, then round. In real BGV/BFV libraries, modulus switching is done in RNS across a chain of primes, and the details determine performance and correctness.

Run it:
```bash
python3 code/main.py
```

## Use It

Production-grade libraries implement BFV/BGV (and usually CKKS) with RNS, NTTs, SIMD packing, key switching variants, and parameter selection tools.

- **Microsoft SEAL** (C++) — BFV and CKKS, widely used reference implementation (especially for BFV).
- **HElib** (C++) — historically “the BGV library”; strong BGV pedigree and optimizations.
- **OpenFHE** (C++) — modern successor ecosystem (BFV/BGV/CKKS/TFHE-style), designed for research + production use.
- **Lattigo** (Go) — BFV/BGV/CKKS in Go, useful for backend services.

Practical mapping:

| What you want | Typical scheme |
|--------------|----------------|
| Exact integer circuits (counts, comparisons-as-circuits) | BFV or BGV |
| Approximate real/float workloads (ML inference) | CKKS |
| Bit-level gates / bootstrapped boolean circuits | TFHE |

## Pitfalls

1. **Forgetting the centered lift.** Doing rounding on `[0, q)` coefficients instead of centered coefficients breaks correctness near the wrap boundary.
2. **Mixing moduli.** The moment you modulus-switch to `q'`, you must consistently run ring ops modulo `q'`.
3. **Ignoring ciphertext growth.** Without relinearization, ciphertext size increases with each multiplication (and so does evaluator cost).
4. **Picking tiny parameters and extrapolating.** `n=8` is a demo; production uses `n` in the thousands and RNS moduli with dozens of bits each.
5. **Treating noise budget as a vibe.** You need a concrete bound/estimate; otherwise a circuit that “worked in testing” will fail on edge inputs.

## Ship It

Save and reuse the checklist in `outputs/bgv-bfv-eval-checklist.md` whenever you:
- evaluate a BFV/BGV proposal,
- review a PR touching FHE parameters or bootstrapping,
- or need to explain scheme choice to a product/security audience.

Workflow: paste it into an issue/PR template and fill in each checkbox (especially the “ciphertext modulus chain”, “depth”, and “relinearization strategy” sections).

## Exercises

1. Easy. Run `python3 code/main.py`. Observe that add/mul decrypted outputs match the plaintext computations mod `t`.
2. Medium. Make `q` smaller (e.g., try `q=8192` or `q=4096`) and rerun. Find a point where multiplication starts decrypting incorrectly. Explain why in terms of rounding/noise.
3. Hard. In a real library (SEAL, OpenFHE, HElib, or Lattigo), implement the same computation as Step 4 (encrypt two vectors, multiply, decrypt) and compare: what API calls correspond to “relinearization” and “modulus switching”?

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Ring-LWE | “LWE but in polynomials” | A hard problem over `R_q` that enables compact keys and SIMD-style packing. |
| `R_q` | “the ciphertext ring” | `Z_q[x]/(x^n+1)`, where ops are negacyclic and mod `q`. |
| Noise | “randomness for security” | The error term that hides the plaintext but limits depth via rounding failure. |
| `Δ = ⌊q/t⌋` | “scale factor” | How BFV embeds a plaintext mod `t` into a modulus `q` space. |
| Relinearization | “shrink ciphertext after multiply” | Key switching that turns an `(1, s, s^2)` ciphertext back into `(1, s)`. |
| Modulus switching | “drop to a smaller q” | Scale-and-round mapping of coefficients from `q` to `q'` to manage growth across levels. |

## Further Reading

- Zvika Brakerski, Craig Gentry, Vinod Vaikuntanathan, *Fully Homomorphic Encryption without Bootstrapping* (2012) — introduces modulus switching and leveled FHE ideas.
- Junfeng Fan, Frederik Vercauteren, *Somewhat Practical Fully Homomorphic Encryption* (2012) — FV/BFV-style exact arithmetic with scale-and-round.
- HomomorphicEncryption.org, *Homomorphic Encryption Standard* (latest) — practical parameter guidance and scheme definitions.
- Microsoft Research, *SEAL Manual / BFV Tutorial* — engineering-focused BFV guidance and examples.
