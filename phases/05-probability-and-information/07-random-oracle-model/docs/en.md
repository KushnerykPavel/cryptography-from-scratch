# Random Oracle Model — Heuristic vs Reality

> The random oracle is a hash function that answers honestly, forgets nothing, and can be programmed by the simulator — but does not exist in the real world.

**Type:** Learn
**Languages:** Python
**Prerequisites:** Phase 05 · 04 (Computational Indistinguishability) · 05 (Hybrid Argument) · 06 (Negligible Functions & Reductions)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Describe the four properties of a random oracle: truly random, consistent, public, lazy-sampled.
- Explain programmability and show how a reduction uses it to embed a challenge into the oracle.
- Compute the preimage advantage bound q/2^n and the collision birthday bound q²/2^(n+1).
- Determine the minimum hash output length for k-bit preimage and k-bit collision security.
- State the CGH limitation: ROM-secure schemes can be insecure with any concrete hash.

## The Problem

Real hash functions (SHA-256, SHA-3) are deterministic and public — anyone
can compute them without asking an oracle. Yet nearly every practical security
proof — for digital signatures (RSA-PSS, EdDSA), key exchange (ECDH-based
KEM), password hashing, and AEAD construction — uses a model where the hash
function is a **random oracle**: a black box that returns a uniformly random
output for each new input, consistent across calls.

Without the Random Oracle Model (ROM):
- You cannot follow the security proofs for RSA-PSS, ECDSA, Schnorr, OAEP, or HKDF.
- You cannot compute the tight query bounds that govern how many hash queries an adversary is allowed.
- You cannot understand why hash output length matters for security — or how birthday attacks set the floor.

The ROM is a heuristic: replacing the random oracle with a concrete hash
function may introduce attacks. But it is the dominant proof technique for
efficient practical schemes, and every working cryptographer must be fluent in it.

## The Concept

### The random oracle definition

A **random oracle** `H : {0,1}* → {0,1}^n` is modelled as:

1. **Truly random**: for each new input `x`, `H(x)` is drawn uniformly from `{0,1}^n`.
2. **Consistent**: querying `x` twice always returns the same `H(x)`.
3. **Public**: adversary and honest parties share the same oracle.
4. **Lazy sampled**: `H(x)` is not fixed until `x` is first queried.

No real hash function has all four properties simultaneously (real hash
functions are deterministic and efficient to compute without querying an oracle).

### The ROM methodology

A ROM security proof proceeds as follows:

```
1. Replace the concrete hash H with a random oracle RO.
2. Prove the scheme is secure assuming RO is truly random.
3. Argue (heuristically) that replacing RO with SHA-256 does not break security.
```

The proof lives entirely in step 2. Step 3 is a heuristic, not a theorem.

### Programmability — the key to reductions

In ROM proofs, the **simulator** controls the random oracle. When the
adversary queries `H(x)`, the simulator can:

- **Lazy-sample**: return a fresh random value and record it.
- **Program**: pre-set `H(x*) = v` for a chosen input `x*` before the adversary queries it.

Programmability is what makes reductions work. Example (RSA-FDH signature):

```
Reduction embeds RSA challenge y* into the oracle:
  program H(m*) = y*   (before adversary queries m*)
  adversary forges signature on m* -> produces x with x^e = H(m*) = y*
  reduction reads out x -> breaks RSA
```

The adversary cannot detect the programming because, from its view, `H(m*)`
looks exactly like a fresh random value.

### Query bounds — concrete security from the ROM

Since the adversary can only find a preimage or collision by querying the
oracle, the advantage is bounded by the number of queries:

**Preimage bound (union bound):**
```
Pr[find x: H(x) = y within q queries] ≤ q / 2^n
```
Each query independently hits the target with probability `1/2^n`. Union bound
over `q` queries gives `q/2^n`.

**Collision bound (birthday):**
```
Pr[∃ i≠j: H(x_i) = H(x_j) within q queries] ≤ q(q-1) / (2 · 2^n) ≈ q² / 2^(n+1)
```
The birthday bound: after `q` queries, there are `q(q-1)/2` pairs, each
colliding with probability `2^{-n}`.

**Birthday threshold:** collision probability reaches `≈ 1/2` when:
```
q ≈ sqrt(2 · ln(2) · 2^n) ≈ 1.177 · 2^(n/2)
```

So `n = 256`-bit output: need `q ≈ 2^{128}` queries to collide with
probability `1/2`. This is why SHA-256 provides **128-bit collision resistance**.

### Preimage vs collision resistance: n matters differently

| Attack | Queries | Hash length needed for k-bit security |
|--------|---------|--------------------------------------|
| Preimage | `q = 2^k` | `n ≥ k` bits |
| Collision (birthday) | `q = 2^(k/2)` | `n ≥ 2k` bits |

A 128-bit-secure hash for preimage: `n ≥ 128`. For collision: `n ≥ 256`.
SHA-256 gives 128-bit collision security; SHA-512 gives 256-bit collision security.

### Limitations of the ROM

The CGH theorem (Canetti, Goldreich, Halevi 1998): there exist signature and
encryption schemes that are secure in the ROM but **insecure with any concrete
hash function**. So ROM proofs are heuristic — they do not transfer automatically
to the standard model. In practice, this rarely matters for well-designed schemes
(RSA-PSS, OAEP, ECDSA) but is a theoretical gap to be aware of.

## Build It

### Step 1: lazy random oracle with programmability

```python
class RandomOracle:
    def query(self, x: bytes) -> int:
        if x not in self._table:
            self._table[x] = self._rng.getrandbits(self._output_bits)
        self._query_log.append(x)
        return self._table[x]

    def program(self, x: bytes, y: int) -> None:
        if x in self._table:
            raise ValueError("cannot program already-queried input")
        self._table[x] = y              # simulator sets output before adversary queries
```

`query` is lazy-sampled. `program` lets the simulator pre-set `H(x) = y` — from the adversary's view this is indistinguishable from a fresh random value.

### Step 2: query bounds

```python
def preimage_advantage_bound(q, output_bits):
    return q / (2.0 ** output_bits)           # union bound over q queries

def collision_advantage_bound(q, output_bits):
    return q * (q - 1) / (2.0 * 2.0 ** output_bits)   # birthday

def birthday_queries(output_bits, *, target_prob=0.5):
    return math.sqrt(-2.0 * (2.0 ** output_bits) * math.log1p(-target_prob))
```

### Step 3: simulated attacks

```python
def simulate_preimage_attack(oracle, target, n_queries, *, rng=None):
    for _ in range(n_queries):
        x = rng.getrandbits(64).to_bytes(8, "big")
        if oracle.query(x) == target:
            return x
    return None

def simulate_birthday_attack(oracle, n_queries, *, rng=None):
    seen = {}
    for _ in range(n_queries):
        x = rng.getrandbits(64).to_bytes(8, "big")
        h = oracle.query(x)
        if h in seen and seen[h] != x:
            return (seen[h], x)
        seen[h] = x
    return None
```

Run it:

```
python3 code/main.py
```

## Use It

In real protocols and libraries:

- **HKDF** (RFC 5869): the `Extract` step is ROM-based — modelled as
  `H(salt || IKM)` where H is a random oracle. The security proof bounds the
  advantage of distinguishing the output from uniform by `q/2^n`.
- **RSA-PSS / OAEP** (PKCS#1 v2): the hash in the padding is modelled as a
  random oracle; the security reduction embeds the RSA challenge via programming.
- **Schnorr / EdDSA**: the challenge hash `H(R || PK || m)` is the random oracle;
  the forking lemma (a ROM technique) extracts the discrete log.
- **SHA-256 as a ROM substitute**: Python `hashlib.sha256(x).digest()` is used
  in practice where the ROM says `H(x)`. The proof guarantee holds heuristically.

## Attack It

**Birthday attack on a 32-bit hash:**

With `output_bits = 32` and `q = 2^{16} = 65536` queries, the expected
collision probability is:

```
Adv ≈ q² / 2^(n+1) = 2^32 / 2^33 = 0.5
```

Run `simulate_birthday_attack` with a 32-bit oracle and 65536 queries —
you will find a collision with probability ≈ 50%. This is exactly why
MD5 (128-bit, 64-bit collision security) and SHA-1 (160-bit, 80-bit
collision security) are deprecated for collision-sensitive uses.

The lesson: **hash output length must be at least 2k bits for k-bit collision
security**. Using a 128-bit hash for digital signatures gives only 64-bit
collision security — breakable with 2^64 work.

## Ship It

This lesson ships a reusable review prompt:

- `outputs/prompt-rom-audit.md`

Use it when reviewing protocol specs, signature schemes, or KDF constructions
that cite "ROM security" or "modelled as a random oracle".

## Exercises

1. Easy: for a 256-bit hash, compute the number of queries needed to achieve
   collision advantage 0.01, 0.5, and 0.99. Use `birthday_queries` with
   appropriate `target_prob` values.

2. Medium: implement a simulated reduction for a toy "hash-then-sign" scheme:
   the signing oracle programs `H(m*) = challenge` before the forger runs.
   Show that if the forger outputs a valid signature on `m*`, the reduction
   recovers the preimage of `challenge`.

3. Hard: the CGH limitation — sketch why a ROM proof does not guarantee
   security with a concrete hash. Construct a toy "pathological" scheme that
   is secure with any random oracle but where substituting `H(x) = SHA256(x || SHA256(x))`
   breaks it. (Hint: make the scheme use the circuit of the hash function itself.)

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| random oracle (RO) | "ideal hash" | lazy random function H: {0,1}* → {0,1}^n, consistent, programmable |
| ROM proof | "proven secure" | secure when H is a random oracle; heuristic with concrete hash |
| programmability | "simulator trick" | setting H(x) = v before the adversary queries x |
| preimage bound | "one-way in ROM" | Pr[find preimage in q queries] ≤ q/2^n |
| birthday bound | "collision in ROM" | Pr[collision in q queries] ≤ q²/2^(n+1) |
| birthday threshold | "collision crossover" | q ≈ 2^(n/2) queries for 50% collision probability |
| CGH limitation | "ROM is heuristic" | ROM-secure schemes can be insecure with any concrete hash |

## Test Vectors

Source: derived from closed-form definitions: preimage bound = q/2^n,
collision bound = q(q-1)/(2·2^n), birthday threshold = sqrt(2·ln(2)·2^n).

Code must pass all vectors in `tests/vectors.json`.

## Further Reading

- [Bellare & Rogaway, "Random Oracles are Practical" (1993)](https://cseweb.ucsd.edu/~mihir/papers/ro.pdf) — original ROM methodology paper
- [Canetti, Goldreich & Halevi, "The Random Oracle Methodology, Revisited" (1998)](https://eprint.iacr.org/1998/011.pdf) — CGH impossibility
- [Boneh & Shoup, *A Graduate Course in Applied Cryptography*, Ch. 8](https://toc.cryptobook.us/) — ROM proofs for signatures and encryption
- [Katz & Lindell, *Introduction to Modern Cryptography*, §8.4](https://www.cs.umd.edu/~jkatz/imc.html) — Schnorr and the forking lemma
