# DEEP-FRI — Sampling Outside the Box

> If the prover can only answer “on the grid”, make them answer off the grid.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** `12-zk-proof-systems/12-fri` (FRI idea), finite fields & polynomials, Merkle trees / hash commitments  
**Time:** ~90 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** why “out-of-domain sampling” improves soundness in FRI-based commitments.
- **Compute** a DEEP quotient table `q(x) = (f(x)-f(z))/(x-z)` over a subgroup domain.
- **Implement** one FRI folding round from evaluation pairs `(x, -x)`.
- **Distinguish** “commit (Merkle root)” vs “open (value + authentication path)”.
- **Apply** the toy verifier to accept an honest proof and reject a tampered one.

## The Problem

In a STARK, the prover commits to a big table of values (trace columns, constraint/composition polynomials, etc.) and the verifier only reads *a few* entries. The whole trick is to convince the verifier that those committed values behave like evaluations of a **low-degree polynomial** — because low-degree structure is what makes spot-checking meaningful.

Plain FRI already does a lot, but it still starts from a specific evaluation domain (a “grid”). If the verifier only ever checks points *on that grid*, a cheating prover can try to build a table that looks consistent on the grid while being inconsistent with any single low-degree polynomial globally. The DEEP idea (“Domain Extending for Eliminating Pretenders”) is: sample **outside** the original evaluation domain and force the prover to stay consistent there too.

In production STARKs, this shows up as “out-of-domain sampling” and “DEEP composition”: you pick random field points `z` (and sometimes `g·z`, `g^2·z`, …) that are not on the evaluation subgroup, and you quotient by `(X - z)` so the verifier can bind the prover to those out-of-domain values while still running a proximity test on a grid.

## The Concept

We’ll work over a small prime field `F_p` and an FFT-friendly multiplicative subgroup `D = {1, w, w^2, …, w^{n-1}}` where `n` is a power of two. Because `-1 = w^{n/2}` is in the subgroup, every point has a natural partner:

- `x = w^i`
- `-x = w^{i+n/2}`

### DEEP quotienting (the “outside the box” move)

Let `f(X)` be the polynomial you *wish* the committed table corresponds to, and let the verifier pick a random point `z` **not in** `D`. The prover provides (or is bound to) `f(z)`. Define:

`q(X) = (f(X) - f(z)) / (X - z)`

If `f` has degree `< d`, then `q` has degree `< d-1`. More importantly, on any sampled `x ∈ D` the verifier can check:

`f(x) ?= q(x)·(x - z) + f(z)`

So if the prover commits to `q` on `D` and `f` on `D`, the verifier can spot-check the link between them.

### FRI folding (degree halves, domain halves)

Given an evaluation oracle `q : D → F_p`, a folding round defines a new function on the “squared” domain `D' = {x^2 : x ∈ D}`:

`q_next(x^2) = (q(x)+q(-x))/2 + beta · (q(x)-q(-x)) / (2x)`

Where `beta` is a random verifier challenge. Repeating this shrinks the table from `n` to `n/2` to `n/4` … while shrinking the degree bound.

### Merkle commitments

Each layer’s evaluation table is committed with a Merkle root. An opening is:

- the value at an index, plus
- a Merkle authentication path proving that value is in the committed tree.

## Build It

### Step 1: build a power-of-two subgroup domain
```python
def factorize(n):
    out = []
    d = 2
    while d * d <= n:
        if n % d == 0:
            out.append(d)
            while n % d == 0:
                n //= d
        d += 1 if d == 2 else 2
    if n > 1:
        out.append(n)
    return out


def primitive_root(p):
    factors = factorize(p - 1)
    for g in range(2, p - 1):
        ok = True
        for q in factors:
            if pow(g, (p - 1) // q, p) == 1:
                ok = False
                break
        if ok:
            return g
    raise ValueError("no primitive root found")


def root_of_unity(p, n):
    if (p - 1) % n != 0:
        raise ValueError("n must divide p-1")
    g = primitive_root(p)
    w = pow(g, (p - 1) // n, p)
    if pow(w, n, p) != 1:
        raise ValueError("bad root")
    if n > 1 and pow(w, n // 2, p) == 1:
        raise ValueError("root does not have exact order n")
    return w


def subgroup_domain(p, n):
    w = root_of_unity(p, n)
    dom = [1]
    for _ in range(1, n):
        dom.append((dom[-1] * w) % p)
    return dom
```
This finds a generator `w` of a multiplicative subgroup of size `n = 2^k`, then lists the domain points in exponent order. The `x` vs `-x` pairing is just an index shift by `n/2`.

### Step 2: deep-quotient at an out-of-domain point `z`
```python
def f_inv(a, p):
    a %= p
    if a == 0:
        raise ValueError("division by zero")
    return pow(a, p - 2, p)


def poly_eval(coeffs, x, p):
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % p
    return acc


def poly_eval_many(coeffs, xs, p):
    return [poly_eval(coeffs, x, p) for x in xs]


def deep_quotient_values(p, domain, values, z, fz):
    out = []
    for x, fx in zip(domain, values):
        out.append(((fx - fz) % p) * f_inv((x - z) % p, p) % p)
    return out
```
Given `f` evaluated on the domain plus a single “off-grid” value `f(z)`, this computes the evaluation table for the quotient `(f(X)-f(z))/(X-z)` over the original domain.

### Step 3: one FRI folding round from evaluation pairs
```python
def fri_fold_layer(p, domain, values, beta):
    n = len(values)
    if n % 2 != 0:
        raise ValueError("layer size must be even")
    half = n // 2
    inv2 = (p + 1) // 2
    next_domain = [(domain[i] * domain[i]) % p for i in range(half)]
    next_values = []
    for i in range(half):
        x = domain[i]
        a = values[i]
        b = values[i + half]
        g = (a + b) % p * inv2 % p
        h = (a - b) % p * inv2 % p * f_inv(x, p) % p
        next_values.append((g + beta * h) % p)
    return next_domain, next_values
```
This is the FRI “fold”: it turns `n` values into `n/2` values while mixing in a verifier challenge `beta`. The only thing the verifier needs to recompute a folded value is the pair `(q(x), q(-x))` and the point `x`.

### Step 4: Merkle-commit layers and open entries
```python
def _sha256(data):
    return hashlib.sha256(data).digest()


def _field_to_bytes(x):
    return int(x).to_bytes(32, "big")


def merkle_build(leaves):
    if not leaves:
        raise ValueError("empty tree")
    level = [_sha256(b"\x00" + leaf) for leaf in leaves]
    levels = [level]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level = level + [level[-1]]
        nxt = []
        for i in range(0, len(level), 2):
            nxt.append(_sha256(b"\x01" + level[i] + level[i + 1]))
        level = nxt
        levels.append(level)
    return levels


def merkle_root(tree):
    return tree[-1][0]


def merkle_proof(tree, index):
    proof = []
    idx = index
    for level in tree[:-1]:
        if idx % 2 == 0:
            sib = level[idx + 1] if idx + 1 < len(level) else level[idx]
            proof.append((sib, False))
        else:
            sib = level[idx - 1]
            proof.append((sib, True))
        idx //= 2
    return proof


def merkle_verify(leaf, index, proof, root):
    h = _sha256(b"\x00" + leaf)
    idx = index
    for sib, sib_on_left in proof:
        if sib_on_left:
            h = _sha256(b"\x01" + sib + h)
        else:
            h = _sha256(b"\x01" + h + sib)
        idx //= 2
    return h == root


def merkle_commit_field(values):
    tree = merkle_build([_field_to_bytes(v) for v in values])
    return tree, merkle_root(tree)
```
This is a minimal Merkle commitment scheme (with `0x00`/`0x01` domain separation) that lets you commit to a vector and later prove membership of one entry with an authentication path.

### Step 5: wire DEEP quotient + FRI + openings into a tiny verifier
```python
def deep_fri_build(p, domain, f_values, z, fz, betas):
    q0 = deep_quotient_values(p, domain, f_values, z, fz)
    q_domains = [domain]
    q_layers = [q0]
    for beta in betas:
        domain, q0 = fri_fold_layer(p, domain, q0, beta)
        q_domains.append(domain)
        q_layers.append(q0)
    return q_domains, q_layers


def deep_fri_verify(p, f_domain, f_root, q_domains, q_roots, z, fz, betas, queries, openings):
    if len(q_domains) != len(q_roots):
        raise ValueError("domains/roots mismatch")
    if len(q_domains) != len(betas) + 1:
        raise ValueError("betas mismatch")
    if len(openings) != len(queries):
        raise ValueError("openings mismatch")

    for q_idx, opening in zip(queries, openings):
        fx, fx_proof = opening["f0"]
        qx, qx_proof = opening["q0"]
        if not merkle_verify(_field_to_bytes(fx), q_idx, fx_proof, f_root):
            return False
        if not merkle_verify(_field_to_bytes(qx), q_idx, qx_proof, q_roots[0]):
            return False

        x = f_domain[q_idx]
        if (qx * ((x - z) % p) + fz) % p != fx:
            return False

        idx = q_idx
        for r, beta in enumerate(betas):
            layer_n = len(q_domains[r])
            half = layer_n // 2
            base = idx % half
            sib = base + half
            q_i, q_i_proof = opening[f"q{r}a"]
            q_s, q_s_proof = opening[f"q{r}b"]
            q_next, q_next_proof = opening[f"q{r+1}"]

            if not merkle_verify(_field_to_bytes(q_i), base, q_i_proof, q_roots[r]):
                return False
            if not merkle_verify(_field_to_bytes(q_s), sib, q_s_proof, q_roots[r]):
                return False

            next_idx = base
            if not merkle_verify(_field_to_bytes(q_next), next_idx, q_next_proof, q_roots[r + 1]):
                return False

            x = q_domains[r][next_idx]
            inv2 = (p + 1) // 2
            g = (q_i + q_s) % p * inv2 % p
            h = (q_i - q_s) % p * inv2 % p * f_inv(x, p) % p
            expected = (g + beta * h) % p
            if expected != q_next:
                return False

            idx = next_idx

    return True
```
This verifier checks two things at a few random indices: (1) the DEEP linkage between `f` and `q`, and (2) that each folding step is consistent with the committed next layer.

Run it:

`python3 code/main.py`

## Use It

In real systems you rarely implement DEEP-FRI “from scratch” — you use it as part of a STARK prover/verifier stack.

- **STARK proof systems:** use DEEP composition + FRI as the core polynomial commitment for constraint polynomials.
- **Plonky3 (FRI-based PCS):** uses (batched) FRI-style reductions for polynomial commitments (see `p3-uni-stark`, `p3-fri`, recursion support).
- **Winterfell (Rust STARK library):** exposes “DEEP composition coefficients” and out-of-domain sampling in its AIR/prover logic.

## Pitfalls

- **Wrong domain pairing:** folding assumes you can query both `x` and `-x`. If `-1` isn’t in your subgroup (or you reorder indices incorrectly), folding checks silently become nonsense.
- **Forgetting to bind `f(z)`:** DEEP only helps if `f(z)` is cryptographically bound to the transcript (Fiat–Shamir) and linked to the committed table.
- **Merkle ambiguities:** avoid non-domain-separated hashing; otherwise “leaf vs internal node” collisions can invalidate inclusion proofs.
- **Index mapping bugs across rounds:** if you don’t map indices consistently from layer `i` to `i+1`, you can accept invalid proofs.
- **Field edge cases:** quotienting divides by `(x-z)` and folding divides by `x`; if you accidentally allow `x=0` or `x=z` you can get catastrophic “division by zero” behavior.

## Ship It

This lesson ships a reusable review checklist:

- `outputs/deep_fri_review_checklist.md`

Use it when reviewing a STARK/FRI implementation (or when you’re integrating a library) to sanity-check: out-of-domain sampling, quotienting, transcript binding, Merkle openings, and fold correctness.

## Exercises

1. **Easy.** Run `python3 code/main.py`. Observe that the verifier accepts the honest proof and rejects the tampered proof.
2. **Medium.** Change `f_coeffs` to a higher-degree polynomial (e.g. 20 coefficients) and increase `n`. Watch how many fold rounds you need to reduce the table to a tiny layer.
3. **Hard.** Implement batching: commit to two different polynomials `f1, f2`, sample one `z`, build two deep quotients, then combine them into one “batched” table with a random linear combination before running FRI.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| FRI | “A low-degree test” | An IOPP that checks a committed evaluation table is *close* to a Reed–Solomon codeword via folding + random queries. |
| Out-of-domain sampling | “Sample z outside the subgroup” | Querying a point not in the evaluation domain to bind the prover globally, not just on the grid. |
| DEEP quotient | “Divide by (X−z)” | The table for `(f(X)-f(z))/(X-z)`; reduces degree and ties the oracle to an off-grid value. |
| Folding | “Halve the table” | Combining `(q(x), q(-x))` into a new value at `x^2` with a random challenge. |
| Merkle opening | “Decommitment” | Value + authentication path proving membership in the committed layer root. |
| Soundness | “How hard it is to cheat” | The probability a dishonest prover can make the verifier accept a false statement. |

## Further Reading

- Ben-Sasson, Bentov, Horesh, Riabzev, *Fast Reed-Solomon Interactive Oracle Proofs of Proximity* (2018) — the original FRI protocol paper.
- Ben-Sasson, Goldberg, Kopparty, Saraf, *DEEP-FRI: Sampling Outside the Box Improves Soundness* (2019) — the DEEP technique and DEEP-FRI soundness improvement.
- StarkWare, *STARK 101* (2021–) — practical walk-through of a STARK with out-of-domain sampling and FRI.
