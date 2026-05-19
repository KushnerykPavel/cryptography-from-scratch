# Poseidon — ZK-Friendly Hash
> Hash inside the field: cheap constraints, fast proofs.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** Phase 02 · 06 (Fields and Field Extensions), Phase 02 · 07 (Finite Fields GF(p))  
**Time:** ~90 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain why SNARK-friendly hashes live in `F_p` instead of bytes.
- Compute basic field operations mod a large prime (`BN254_PRIME`).
- Implement a Poseidon-style permutation (Hades rounds: full + partial).
- Distinguish safe input handling (length/padding + domain separation) from unsafe “implicit zeros”.
- Apply a review checklist to avoid Poseidon integration footguns in circuits and backends.

## The Problem

You want to hash things *inside* a zero-knowledge circuit: Merkle tree nodes,
commitments, nullifiers, message transcripts, or state updates. SHA-256 works
great on CPUs, but inside an arithmetic circuit it’s expensive: everything is
bits, so you pay a lot of constraints to emulate byte/bit operations.

Poseidon is designed to be *arithmetic-friendly*: it works directly over a
prime field `F_p`, using additions, multiplications, and an exponentiation
S-box like `x ↦ x^5`. In SNARKs, these operations are the native currency, so
the constraint count is dramatically lower than bit-oriented hashes.

But “we used Poseidon” is not a single thing. Real systems have to agree on a
specific field, specific round numbers, specific constants, and—crucially—on
exact input encoding rules. Many real-world failures are *not* cryptanalysis;
they’re parameter mismatches, missing domain separation, or unsafe padding.

## The Concept

Poseidon is built from two layers repeated for many rounds (an SPN / Hades
strategy):

1. **Add round constants:** `S[i] ← S[i] + C[r, i]`
2. **Nonlinearity (S-box):** raise to a power in the field, often `x^5`
   - **Full rounds:** apply the S-box to every state word
   - **Partial rounds:** apply the S-box to only one word (cheaper in circuits)
3. **Linear mixing (MDS):** multiply by a `t×t` MDS matrix to spread changes

To turn the permutation into a hash, you wrap it in a **sponge**:

- Split the state into **capacity** (kept “hidden”) and **rate** (absorbs input).
- Absorb input words into the rate, apply the permutation, then squeeze output
  from the rate.

Two practical rules matter more than the math in many codebases:

- **Fixed instances:** Poseidon is a *family*. Everyone must match the same
  instance (field modulus, `t`, rounds, constants, S-box exponent).
- **Injective input handling:** a variable-length sponge must encode length
  and/or use padding; otherwise `hash([x]) == hash([x, 0])` can happen.

## Build It

### Step 1: Prime field arithmetic (BN254)

We’ll work in the BN254 prime field. The only operations we need are “reduce
mod `p`” and “invert mod `p`” (using Fermat’s little theorem: `a^(p-2) mod p`).

```python
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Sequence


BN254_PRIME = (
    21888242871839275222246405745257275088548364400416034343698204186575808495617
)


@dataclass(frozen=True)
class PoseidonParams:
    p: int
    t: int
    rate: int
    alpha: int
    full_rounds: int
    partial_rounds: int
    mds: tuple[tuple[int, ...], ...]
    round_constants: tuple[int, ...]
    seed: bytes


def fe(x: int, p: int) -> int:
    if not isinstance(x, int):
        raise TypeError("field elements must be integers")
    if not isinstance(p, int) or p <= 2:
        raise ValueError("p must be an integer prime modulus > 2")
    return x % p


def fe_inv(x: int, p: int) -> int:
    a = fe(x, p)
    if a == 0:
        raise ValueError("0 has no inverse modulo p")
    return pow(a, p - 2, p)
```

This is the core mental model: everything is an integer, but equalities are
checked “mod `p`”. The hash will never leave this field.

### Step 2: Deterministic constants (seeded) + Cauchy MDS

Poseidon instances need:

- **Round constants** `C[r, i]` (break symmetry)
- An **MDS mixing matrix** (diffusion)

In real deployments these are generated deterministically from a public seed
to avoid trapdoors. Here we use SHA-256 as a simple deterministic generator,
and construct an MDS matrix as a Cauchy matrix `M[i][j] = 1/(x_i + y_j)`.

```python
class SHA256XOF:
    def __init__(self, seed: bytes):
        if not isinstance(seed, (bytes, bytearray, memoryview)):
            raise TypeError("seed must be bytes-like")
        self._seed = bytes(seed)
        self._ctr = 0

    def next_u256(self) -> int:
        c = self._ctr
        self._ctr += 1
        digest = hashlib.sha256(self._seed + c.to_bytes(4, "big")).digest()
        return int.from_bytes(digest, "big")

    def next_field(self, p: int) -> int:
        while True:
            x = self.next_u256()
            if x < p:
                return x


def _generate_distinct_field_elements(*, p: int, n: int, seed: bytes) -> list[int]:
    xof = SHA256XOF(seed)
    out: list[int] = []
    seen: set[int] = set()
    while len(out) < n:
        v = xof.next_field(p)
        if v == 0 or v in seen:
            continue
        out.append(v)
        seen.add(v)
    return out


def generate_cauchy_mds(*, p: int, t: int, seed: bytes) -> tuple[tuple[int, ...], ...]:
    if t < 2:
        raise ValueError("t must be >= 2")
    xs = _generate_distinct_field_elements(p=p, n=t, seed=seed + b"/x")
    ys = _generate_distinct_field_elements(p=p, n=t, seed=seed + b"/y")

    rows: list[tuple[int, ...]] = []
    for i in range(t):
        row: list[int] = []
        for j in range(t):
            denom = (xs[i] + ys[j]) % p
            if denom == 0:
                raise ValueError("bad Cauchy construction: x_i + y_j == 0")
            row.append(fe_inv(denom, p))
        rows.append(tuple(row))
    return tuple(rows)


def generate_round_constants(*, p: int, n: int, seed: bytes) -> tuple[int, ...]:
    if n <= 0:
        raise ValueError("n must be positive")
    xof = SHA256XOF(seed + b"/rc")
    return tuple(xof.next_field(p) for _ in range(n))


def poseidon_default_params() -> PoseidonParams:
    p = BN254_PRIME
    t = 3
    rate = 2
    alpha = 5
    full_rounds = 8
    partial_rounds = 57
    seed = b"CFSC-POSEIDON-v1"

    mds = generate_cauchy_mds(p=p, t=t, seed=seed)
    round_constants = generate_round_constants(
        p=p, n=(full_rounds + partial_rounds) * t, seed=seed
    )
    return PoseidonParams(
        p=p,
        t=t,
        rate=rate,
        alpha=alpha,
        full_rounds=full_rounds,
        partial_rounds=partial_rounds,
        mds=mds,
        round_constants=round_constants,
        seed=seed,
    )
```

This gives us a concrete Poseidon-like instance `(p, t, rounds, constants)`.
Interoperability requires everyone to share the exact same instance.

### Step 3: Poseidon permutation (Hades rounds)

Now we implement the Hades round structure:

- `R_f/2` full rounds
- `R_p` partial rounds
- `R_f/2` full rounds

Each round does: add constants → S-box (`x^alpha`) → MDS mix.

```python
def _mat_vec_mul(m: Sequence[Sequence[int]], v: Sequence[int], p: int) -> list[int]:
    t = len(v)
    if len(m) != t or any(len(row) != t for row in m):
        raise ValueError("matrix must be t x t")
    out = [0] * t
    for i in range(t):
        acc = 0
        for j in range(t):
            acc = (acc + m[i][j] * v[j]) % p
        out[i] = acc
    return out


def poseidon_permute(state: Sequence[int], *, params: PoseidonParams) -> list[int]:
    if not isinstance(state, (list, tuple)):
        raise TypeError("state must be a sequence of integers")
    if len(state) != params.t:
        raise ValueError(f"state must have length t={params.t}")

    p = params.p
    st = [fe(x, p) for x in state]

    rounds = params.full_rounds + params.partial_rounds
    full_half = params.full_rounds // 2
    rc = params.round_constants
    rc_idx = 0

    for r in range(rounds):
        for i in range(params.t):
            st[i] = (st[i] + rc[rc_idx]) % p
            rc_idx += 1

        if r < full_half or r >= full_half + params.partial_rounds:
            st = [pow(x, params.alpha, p) for x in st]
        else:
            st[0] = pow(st[0], params.alpha, p)

        st = _mat_vec_mul(params.mds, st, p)

    return st
```

This is the “expensive part” you place inside a SNARK. Partial rounds are a
big performance win because only one S-box is used in the middle.

### Step 4: Pitfall: implicit zero padding causes collisions

If you treat missing inputs as zeros (or allow variable-length inputs without
injective padding), you can get trivial collisions: `[x]` and `[x, 0]` can
produce the same absorbed state and therefore the same hash.

This function is intentionally unsafe so you can see the problem.

```python
def poseidon_sponge_hash_unsafe(
    inputs: Sequence[int], *, params: PoseidonParams, domain: int = 0
) -> int:
    if not isinstance(inputs, (list, tuple)):
        raise TypeError("inputs must be a sequence of integers")
    if params.t != 3 or params.rate != 2:
        raise ValueError("this educational sponge expects (t=3, rate=2)")

    p = params.p
    st = [fe(domain, p), 0, 0]

    i = 0
    while i < len(inputs):
        chunk = inputs[i : i + params.rate]
        for j, x in enumerate(chunk):
            st[1 + j] = (st[1 + j] + fe(x, p)) % p
        st = poseidon_permute(st, params=params)
        i += params.rate

    if len(inputs) == 0:
        st = poseidon_permute(st, params=params)

    return st[1]
```

If your circuit expects “exactly `rate` inputs” you can avoid this by
enforcing fixed-length inputs. If you truly need variable length, you must
encode length and/or pad injectively.

### Step 5: Safer sponge: length encoding + padding + domain separation

We fix two issues:

- **Length encoding** in the capacity element: `(len(inputs) << 64) + domain`
- **Padding** when the final chunk is short, and also for exact multiples of
  the rate (to avoid ambiguity)

```python
def poseidon_sponge_hash(
    inputs: Sequence[int], *, params: PoseidonParams, domain: int = 0
) -> int:
    if not isinstance(inputs, (list, tuple)):
        raise TypeError("inputs must be a sequence of integers")
    if params.t != 3 or params.rate != 2:
        raise ValueError("this educational sponge expects (t=3, rate=2)")

    p = params.p
    iv = (fe(domain, p) + (len(inputs) << 64)) % p
    st = [iv, 0, 0]

    i = 0
    while i < len(inputs):
        chunk = inputs[i : i + params.rate]
        for j, x in enumerate(chunk):
            st[1 + j] = (st[1 + j] + fe(x, p)) % p
        if len(chunk) < params.rate:
            st[1 + len(chunk)] = (st[1 + len(chunk)] + 1) % p
        st = poseidon_permute(st, params=params)
        i += params.rate

    if len(inputs) % params.rate == 0:
        st[1] = (st[1] + 1) % p
        st = poseidon_permute(st, params=params)

    return st[1]
```

Domain separation is not optional in real protocols: you don’t want
`hash(leaf)` to ever equal `hash(internal_node)` for some crafted inputs.

Run it:

```bash
python3 code/main.py
```

## Use It

Poseidon is almost always used via a library that ships a well-audited,
well-tested parameter set (and often optimized sparse matrices).

- **Circom / circomlib**: Poseidon circuits + constants for BN254
- **circomlibjs**: JS/TS implementation compatible with circom
- **Rust**: crates like `light-poseidon`, `pso-poseidon`, `dusk-hades` (parameter sets vary)
- **arkworks**: Poseidon implementations and parameter generation utilities

Rule of thumb: treat Poseidon like “a specific algorithm + a specific config”.
If your constants differ, your hashes won’t match across environments.

## Pitfalls

1. **Variable-length collisions via implicit zeros**: `hash([x]) == hash([x, 0])`
   if you don’t use injective padding or length encoding.
2. **Parameter mismatch across systems**: different `(p, t, rounds, constants)`
   means proofs or Merkle roots won’t verify.
3. **Missing domain separation**: using one hash function for multiple object
   types without a domain tag invites cross-type collisions.
4. **Wrong field / reduction rules**: hashing numbers without reducing mod `p`
   (or reducing with the wrong `p`) silently breaks interoperability.
5. **Assuming “Poseidon in circuit” equals “Poseidon off-chain”**: you must
   match the same sponge rules (rate/capacity split, padding, output element).

## Ship It

Save the reusable checklist in `outputs/poseidon-integration-checklist.md` and
use it when:

- Reviewing a PR that introduces Poseidon in circuits/contracts/backends
- Debugging “hash mismatch” bugs between a prover and a verifier
- Choosing safe domain separation and input encoding rules

## Exercises

1. Easy. Run `python3 code/main.py`. Observe the collision in Step 4 and how
   Step 5 avoids it.
2. Medium. Change `domain` in `poseidon_sponge_hash(...)` and confirm you get
   different outputs for the same inputs. Explain why this matters for Merkle
   trees (leaf vs internal node hashing).
3. Hard. Integrate a production Poseidon implementation (e.g., circomlibjs or
   a Rust crate) and compare its outputs to this lesson’s implementation.
   Document the exact parameter set and sponge rules you used, and explain
   why “Poseidon” alone was not enough to make them match.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| `F_p` | “the field” | Integers modulo a prime `p`; all operations reduce mod `p`. |
| S-box | “nonlinear layer” | A map like `x ↦ x^5` that provides nonlinearity in the permutation. |
| Full/partial rounds | “cheap vs expensive rounds” | Full: S-box on all state words. Partial: S-box on one word. |
| MDS matrix | “mixing matrix” | A linear transform with strong diffusion: every output depends on every input. |
| Domain separation | “different prefixes” | Make hashes for different object types live in disjoint domains. |

## Further Reading

- Grassi et al., *Poseidon: A New Hash Function for Zero-Knowledge Proof Systems* (2019) — the original design and parameter guidance.
- “Hades design” papers and writeups — why partial rounds work and how to choose round numbers safely.
- Poseidon2 (2023) — a newer design with different padding/IV ideas for sponge hashing.
