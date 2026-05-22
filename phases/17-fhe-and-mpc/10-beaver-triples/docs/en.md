# Beaver Triples & Multiplication Triples
> Multiply secrets with one public reveal.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** `phases/17-fhe-and-mpc/08-bgw` (additive sharing), `phases/17-fhe-and-mpc/09-spdz` (offline/online)  
**Time:** ~50 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** why naive multiplication leaks in additive-sharing MPC
- **Compute** how a Beaver triple `(a, b, c=a·b)` enables secure multiplication
- **Implement** triple generation (dealer model) and the online multiply step
- **Distinguish** the offline phase (triples) from the online phase (inputs)
- **Apply** triples to evaluate small arithmetic circuits (add + multiply)

## The Problem
Additive secret sharing makes addition easy: each party holds a share, and adding shares adds secrets. But multiplication is the core operation you need for *real* programs: dot products, matrix multiplies, linear models, and basically any arithmetic circuit beyond a single sum.

If you try to multiply shared secrets directly, you get stuck: each party only has local shares `(x_i, y_i)`, but the product `x·y` expands into cross-terms `x_i·y_j` that no single party can compute without learning something they shouldn't. Many MPC protocols are essentially “how do we do multiplication without leaking?”

Beaver triples solve this by pushing the hard work into an *offline* preprocessing phase. Once you have triples, the online phase can multiply secrets with only a small amount of public communication (opening two masked values).

## The Concept
We work in a finite field `F_p` (integers mod a prime `p`). With **additive sharing** among `n` parties, a secret `x` is represented as shares `x_0, …, x_{n-1}` such that:

`x ≡ (x_0 + x_1 + … + x_{n-1}) mod p`

Addition/subtraction are local. Multiplication needs help.

A **Beaver triple** is a correlated randomness triple `(a, b, c)` with `c = a·b (mod p)`, where each value is itself secret-shared among the parties.

To multiply shared `x` and `y`, parties do:

1. Compute masked differences in shares: `d = x - a`, `e = y - b`.
2. **Open** `d` and `e` (reconstruct them publicly). They are safe to open because `a` and `b` are random and unknown.
3. Compute shares of the product:

`z = c + d·b + e·a + d·e`

Because `d` and `e` are now public scalars, `d·b` and `e·a` are just “public times shared,” which is easy. The only subtlety is that `d·e` is a public scalar too, so we can add it to the sharing by giving it to a single party’s share (or splitting it arbitrarily).

### Mental model
- Offline phase: manufacture many triples `(a,b,c)` *before* inputs exist.
- Online phase: for each multiplication gate, consume 1 triple and open exactly 2 field elements (`d` and `e`).

## Build It

### Step 1: Field arithmetic + additive secret sharing
```python
def modp(x: int, p: int) -> int:
    return x % p


def field_add(a: int, b: int, p: int) -> int:
    return (a + b) % p


def field_sub(a: int, b: int, p: int) -> int:
    return (a - b) % p


def field_mul(a: int, b: int, p: int) -> int:
    return (a * b) % p


def share_secret(x: int, n: int, p: int, rng) -> list[int]:
    if n < 2:
        raise ValueError("n must be >= 2")
    x = modp(x, p)
    shares = [rng.randrange(p) for _ in range(n - 1)]
    last = x
    for s in shares:
        last = field_sub(last, s, p)
    shares.append(last)
    return shares


def reconstruct(shares: list[int], p: int) -> int:
    total = 0
    for s in shares:
        total = field_add(total, s, p)
    return total
```
We work mod a prime `p`. `share_secret` makes `n` additive shares that sum to `x (mod p)`. `reconstruct` adds shares back together.

### Step 2: Generate a Beaver triple (dealer model)
```python
def generate_beaver_triple_shares(n: int, p: int, rng) -> tuple[list[int], list[int], list[int]]:
    a = rng.randrange(p)
    b = rng.randrange(p)
    c = field_mul(a, b, p)
    a_sh = share_secret(a, n, p, rng)
    b_sh = share_secret(b, n, p, rng)
    c_sh = share_secret(c, n, p, rng)
    return a_sh, b_sh, c_sh
```
In a real MPC, triples come from a preprocessing protocol (or a trusted dealer / hardware / setup). For learning, we simulate the simplest world: a dealer picks random `a, b`, computes `c=a·b`, and secret-shares all three.

### Step 3: Multiply shared secrets using a triple (online phase)
```python
def share_sub(x_sh: list[int], y_sh: list[int], p: int) -> list[int]:
    if len(x_sh) != len(y_sh):
        raise ValueError("share length mismatch")
    return [field_sub(a, b, p) for a, b in zip(x_sh, y_sh)]


def share_add(x_sh: list[int], y_sh: list[int], p: int) -> list[int]:
    if len(x_sh) != len(y_sh):
        raise ValueError("share length mismatch")
    return [field_add(a, b, p) for a, b in zip(x_sh, y_sh)]


def share_scalar_mul(x_sh: list[int], k: int, p: int) -> list[int]:
    k = modp(k, p)
    return [field_mul(s, k, p) for s in x_sh]


def beaver_multiply_shares(
    x_sh: list[int],
    y_sh: list[int],
    a_sh: list[int],
    b_sh: list[int],
    c_sh: list[int],
    p: int,
    dealer_party: int = 0,
) -> tuple[list[int], int, int]:
    n = len(x_sh)
    if not (len(y_sh) == len(a_sh) == len(b_sh) == len(c_sh) == n):
        raise ValueError("share length mismatch")
    if not (0 <= dealer_party < n):
        raise ValueError("dealer_party out of range")

    d_sh = share_sub(x_sh, a_sh, p)
    e_sh = share_sub(y_sh, b_sh, p)
    d = reconstruct(d_sh, p)
    e = reconstruct(e_sh, p)

    z_sh = []
    for i in range(n):
        part = c_sh[i]
        part = field_add(part, field_mul(d, b_sh[i], p), p)
        part = field_add(part, field_mul(e, a_sh[i], p), p)
        if i == dealer_party:
            part = field_add(part, field_mul(d, e, p), p)
        z_sh.append(part)

    return z_sh, d, e
```
`beaver_multiply_shares` consumes one triple and returns shares of `z=x·y`. The only values reconstructed publicly are `d=x-a` and `e=y-b`, which are information-theoretically masked by random `a` and `b`.

### Step 4: Evaluate a tiny arithmetic circuit
```python
def circuit_example(
    x: int, y: int, z: int, n: int, p: int, rng
) -> tuple[int, int]:
    x_sh = share_secret(x, n, p, rng)
    y_sh = share_secret(y, n, p, rng)
    z_sh = share_secret(z, n, p, rng)

    a1, b1, c1 = generate_beaver_triple_shares(n, p, rng)
    xy_sh, _, _ = beaver_multiply_shares(x_sh, y_sh, a1, b1, c1, p)

    sum_sh = share_add(xy_sh, z_sh, p)
    opened = reconstruct(sum_sh, p)
    expected = field_add(field_mul(modp(x, p), modp(y, p), p), modp(z, p), p)
    return opened, expected
```
This shows the “circuit view”: additions are local, and every multiplication gate consumes exactly one Beaver triple.

Run it:

`python3 code/main.py`

## Use It
Production MPC systems typically implement triples as part of a larger protocol:

- **SPDZ / MASCOT family**: triples generated via somewhat homomorphic encryption, OT extension, or other preprocessing; then used for fast online evaluation.
- **ABY / MP-SPDZ**: multiple protocols and triple generation backends; switches representations for performance.
- **SecretFlow / CrypTen**: higher-level ML-oriented MPC frameworks that compile computations down to share operations and multiplication protocols.

Rule of thumb: in real systems, you almost never “hand-roll Beaver triples”; you use a protocol suite that gives you triples, MACs/authentication, and malicious-security checks.

## Pitfalls
- Reusing the same triple for multiple multiplications (breaks privacy).
- Generating triples with a weak RNG or biased distribution (opens subtle leakage).
- Opening `d` and `e` in the wrong ring/field (mod mismatch makes results garbage and can leak).
- Forgetting malicious security: without MACs/consistency checks, a party can send bad shares and silently corrupt outputs.
- Mixing signed integers and mod-`p` arithmetic in engineering code (negative values and overflow bugs).

## Ship It
Save `outputs/beaver-triples-review-checklist.md` and use it as a PR review checklist when you:

- add an MPC multiplication primitive,
- integrate an MPC runtime into an application,
- or evaluate whether a library’s “preprocessing” design matches your threat model.

## Exercises
1. Easy: run `python3 code/main.py` and observe how only `d` and `e` are opened for a multiply gate.
2. Medium: extend `circuit_example` to compute `(x+y)·(y+z)` and verify it matches the cleartext value mod `p`.
3. Hard: sketch how you would add *malicious security* (e.g., SPDZ-style MACs) so a cheating party can’t bias the result unnoticed.

## Key Terms
| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Additive sharing | “Split a secret into random pieces” | Shares sum to the secret mod `p`; each share alone is information-free |
| Beaver triple | “Random (a,b,c) with c=a·b” | Correlated randomness that turns multiplication into opening masked differences |
| Offline/online | “Preprocessing then compute” | Precompute triples before inputs; online uses triples with minimal interaction |
| Open / reconstruct | “Reveal d and e” | Parties publicly learn a value by summing shares; safe only if value is masked |

## Further Reading
- Donald Beaver, *Efficient Multiparty Protocols Using Circuit Randomization* (1991) — introduces multiplication triples for MPC.
- Ivan Damgård et al., *SPDZ* (2012) — practical preprocessing + MAC-based malicious security for arithmetic MPC.
