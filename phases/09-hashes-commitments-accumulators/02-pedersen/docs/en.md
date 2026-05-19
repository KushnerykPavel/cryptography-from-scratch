# Pedersen Commitments

> A commitment is a sealed envelope; Pedersen is the algebraic one.

**Type:** Build
**Languages:** Python
**Prerequisites:** `phases/09-hashes-commitments-accumulators/01-hash-commitments`, `phases/01-number-theory/03-modular-inverse-and-fast-exp`, `phases/02-abstract-algebra/02-cyclic-groups-and-generators`, `phases/01-number-theory/14-index-calculus-discrete-log`
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain hiding vs binding in commitment schemes
- Compute Pedersen commitments in a prime-order subgroup
- Implement commit/open/verify, combine, and rerandomize
- Distinguish safe setup from “trapdoor” setup
- Apply homomorphism to add committed values

## The Problem

Lots of protocols need you to *choose a value now* but *reveal it later* without letting anyone change it in between. Think: sealed-bid auctions, coin-toss over chat, committing to an exam solution before grading, or committing to balances in a privacy system.

A hash commitment (previous lesson) works great when your message is a byte string and you’re happy with “computational hiding + computational binding” under a hash assumption. But in zero-knowledge protocols you often want a commitment that is *algebra-friendly*: you want to add commitments, rerandomize them, and prove relations about committed values without revealing them.

Pedersen commitments are the workhorse for that world: simple, fast, and with clean algebraic properties that show up everywhere (range proofs, confidential transactions, Sigma protocols, vector commitments).

## The Concept

A commitment scheme is a two-phase protocol:

- **Commit:** choose a message `m`, choose randomness `r`, publish `C`.
- **Open:** later reveal `(m, r)`, and anyone can verify that it matches `C`.

Pedersen’s commitment lives in a *prime-order* cyclic group `G` of order `q` with two public generators `g, h ∈ G`:

```
C = g^m · h^r
```

You can read that as:

- `g^m` is the “message part”
- `h^r` is the “blinding part”
- multiplying them mixes the two

### Why it hides

If `r` is uniform in `Z_q` and `h` is a generator, then `h^r` ranges uniformly over `G`, so `C` is uniformly random in `G` too — independent of `m`. That’s **perfect hiding**.

### Why it binds

If someone can find two different openings for the same commitment:

```
g^m · h^r = g^m' · h^r'   with m ≠ m'
```

then rearranging gives a discrete-log relation between `g` and `h`. In other words: cheating would let you solve a discrete log instance. That’s **computational binding**.

### The homomorphic “superpower”

Multiplying two commitments adds the messages and randomness (mod `q`):

```
C(m1, r1) · C(m2, r2) = C(m1 + m2, r1 + r2)
```

This is why Pedersen commitments show up in ZK proofs: you can combine commitments without opening them.

## Build It

We’ll implement Pedersen commitments in a toy subgroup of `Z_p*` (multiplicative integers mod `p`). Real systems use large primes or elliptic curves; this toy keeps the math visible.

### Step 1: Parameters and modular inverse
```python
from dataclasses import dataclass
from secrets import randbelow


@dataclass(frozen=True)
class PedersenParams:
    p: int
    q: int
    g: int
    h: int


def egcd(a, b):
    x0, y0, x1, y1 = 1, 0, 0, 1
    while b != 0:
        q = a // b
        a, b = b, a - q * b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def mod_inverse(a, n):
    if n <= 0:
        raise ValueError("modulus must be positive")
    a = a % n
    g, x, _ = egcd(a, n)
    if g != 1:
        raise ValueError("not invertible modulo n")
    return x % n


def check_pedersen_params(params):
    p, q, g, h = params.p, params.q, params.g, params.h
    if p <= 2 or q <= 1:
        raise ValueError("p and q must be > 2")
    if (p - 1) % q != 0:
        raise ValueError("q must divide p-1")
    if not (1 < g < p) or not (1 < h < p):
        raise ValueError("g and h must be in [2, p-2]")
    if pow(g, q, p) != 1 or pow(h, q, p) != 1:
        raise ValueError("g and h must have order dividing q")
    if g == 1 or h == 1:
        raise ValueError("g and h must not be 1")
    if g == h:
        raise ValueError("g and h must be distinct")
```

This step defines the public parameters `(p, q, g, h)` and a minimal `mod_inverse()` for arithmetic mod `q`. The `check_pedersen_params()` function enforces basic group-shape sanity checks so later steps can assume the algebra works.

### Step 2: Commit and verify
```python
def pedersen_commit(params, m, r):
    check_pedersen_params(params)
    q = params.q
    if not (0 <= m < q):
        raise ValueError("message m must be in Z_q")
    if not (0 <= r < q):
        raise ValueError("blinding r must be in Z_q")
    return (pow(params.g, m, params.p) * pow(params.h, r, params.p)) % params.p


def pedersen_verify(params, c, m, r):
    return pedersen_commit(params, m, r) == c
```

`pedersen_commit()` is the whole scheme: compute `g^m · h^r (mod p)` with `m, r ∈ Z_q`. `pedersen_verify()` simply recomputes and checks equality, which is what “opening” means for Pedersen commitments.

### Step 3: Combine and add openings
```python
def pedersen_combine(params, c1, c2):
    check_pedersen_params(params)
    return (c1 * c2) % params.p


def pedersen_add_openings(params, opening1, opening2):
    check_pedersen_params(params)
    m1, r1 = opening1
    m2, r2 = opening2
    q = params.q
    if not (0 <= m1 < q and 0 <= r1 < q and 0 <= m2 < q and 0 <= r2 < q):
        raise ValueError("openings must be pairs in Z_q × Z_q")
    return ((m1 + m2) % q, (r1 + r2) % q)
```

This step exposes the homomorphism directly: multiplying commitments corresponds to adding their openings modulo `q`. That single property powers “prove statements about sums” patterns in ZK systems.

### Step 4: Rerandomize and trapdoors
```python
def pedersen_rerandomize(params, c, delta_r):
    check_pedersen_params(params)
    q = params.q
    if not (0 <= delta_r < q):
        raise ValueError("delta_r must be in Z_q")
    return (c * pow(params.h, delta_r, params.p)) % params.p


def extract_log_g_h_from_double_opening(q, m1, r1, m2, r2):
    if m1 == m2:
        raise ValueError("need two different messages to extract log_g(h)")
    den = (r2 - r1) % q
    if den == 0:
        raise ValueError("need r2 != r1 to extract log_g(h)")
    return ((m1 - m2) % q) * mod_inverse(den, q) % q


def forge_opening_if_trapdoor_known(params, m_from, r_from, m_target, alpha):
    q = params.q
    if not (0 <= m_from < q and 0 <= r_from < q and 0 <= m_target < q):
        raise ValueError("messages and randomness must be in Z_q")
    if not (1 <= alpha < q):
        raise ValueError("alpha must be in [1, q-1]")
    return (r_from + ((m_from - m_target) % q) * mod_inverse(alpha, q)) % q
```

Rerandomization (`C' = C · h^{Δr}`) keeps the same message but refreshes the blinding. The other two functions explain the security story:

- If someone can open the same commitment in two different ways, you can extract `alpha = log_g(h)`.
- If someone *already knows* `alpha`, they can forge openings to any message (binding is gone).

Run it:

`python3 code/main.py`

## Use It

Real systems usually implement Pedersen commitments in an elliptic curve group (additive notation `C = m·G + r·H`), not in `Z_p*`.

| Context | Typical library | Notes |
|---|---|---|
| Rust ZK / signatures | `curve25519-dalek` (Ristretto), `arkworks` (`ark-ec`) | Prime-order groups; avoids small-subgroup pitfalls |
| Bitcoin confidential transactions | `secp256k1-zkp` | Uses Pedersen commitments plus range proofs |
| Proof systems | `bulletproofs`, `halo2`, `plonky2` ecosystems | Commitments are glued to proofs of relations |

The core API shape is the same: `commit(params, m, r) -> C`, `verify(C, m, r) -> bool`, plus helpers for combining and rerandomizing.

## Pitfalls

1. **Using the wrong group (not prime order).** If the group has small subgroups, attackers can confine elements and leak info. Prime-order subgroups avoid this.
2. **Not checking group membership.** If you accept a “commitment” not in the intended subgroup, downstream proofs can break in surprising ways.
3. **Weak or reused blinding `r`.** If `r` repeats, commitments to different messages become linkable; if `r` comes from a tiny set, hiding is gone.
4. **Toxic setup (known `log_g(h)`).** If the party choosing `h` knows `h = g^alpha`, they can open commitments to any message.
5. **Forgetting the mod `q` message space.** The committed value is an exponent modulo `q`; committing to large integers requires a consistent encoding and usually a range proof.

## Ship It

This lesson ships a reusable Pedersen commitment review checklist.

1. Open `outputs/pedersen_commitment_review_checklist.md`.
2. Paste it into a PR review (or a design doc) any time you see “Pedersen commitment”, “blinding factor”, “generators G/H”, or “range proof”.
3. Use it to spot the real bugs: bad setup, bad randomness, missing membership checks, and missing range constraints.

## Exercises

1. Easy: Run `python3 code/main.py`. Observe that the same `m` with different `r` yields different commitments, and that combining commitments matches committing to the sum.
2. Medium: Extend `code/main.py` to also show “subtraction”: compute `c1 * inv(c2)` and show it commits to `(m1 - m2, r1 - r2) mod q`.
3. Hard: Sketch how you’d integrate Pedersen commitments into a protocol: commit to an amount, then prove in zero-knowledge that it’s in `[0, 2^64)` (range proof) without revealing it.

## Key Terms

| Term | What people say | What it actually means |
|---|---|---|
| Commitment | “Like a hash” | Two-phase protocol: commit now, open later |
| Opening | “The secret” | The pair `(m, r)` that verifies `C = g^m h^r` |
| Perfect hiding | “Nobody can learn m” | Distribution of `C` is independent of `m` (even for unbounded adversaries) |
| Computational binding | “You can’t change your mind” | Two different openings imply solving a hard discrete log relation |
| Rerandomization | “Freshen the commit” | Multiply by `h^{Δr}` to refresh blinding without changing `m` |

## Further Reading

- Torben Pryds Pedersen, *Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing* (1991/1992) — original construction and properties.
- Stanford CS355 notes on commitments (various years) — concise proofs of hiding/binding.
- Bulletproofs paper (Bünz et al., 2018) — shows Pedersen commitments as the backbone of practical range proofs.
