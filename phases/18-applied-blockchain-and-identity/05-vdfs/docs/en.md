# VDFs — Verifiable Delay Functions

> Prove you waited — without anyone having to wait again.

**Type:** Build
**Languages:** Python
**Prerequisites:** 01-bitcoin-stack (RSA modular arithmetic), 04-vrfs (hash-based randomness)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## The Problem

Imagine a lottery where the winning number must depend on future events that no one can
predict or manipulate.  A trusted random beacon sounds good in theory, but every
centralised source can be bribed or coerced.  Blockchain randomness ("use the next block
hash") is gameable by miners who can withhold unfavourable blocks.

What you really need is a function that:

1. Takes a fixed amount of sequential computation to evaluate — no matter how many
   parallel processors an attacker throws at it.
2. Produces a result that anyone can verify cheaply — in a fraction of the time it took
   to compute.
3. Is unpredictable before evaluation starts — so no one can pre-compute the output.

That is exactly what a **Verifiable Delay Function (VDF)** provides.  Ethereum's
RANDAO randomness layer, Chia's proof-of-space consensus, and several DeFi protocols
use VDFs to create delay-based commitments that are both sequential and publicly
verifiable.

## The Concept

### Repeated squaring in an RSA group

The core operation is repeated modular squaring:

```
y = x^(2^T) mod N
```

- `N = p * q` is an RSA modulus (product of two large primes).
- `T` is the delay parameter — the number of sequential squarings.
- `x` is the input (often derived from a block hash or other public value).

Each squaring depends on the result of the previous one, so you cannot parallelise the
T steps.  An attacker with a million cores still needs T multiplications in the critical
path.

### Why RSA groups?

In a group of unknown order (the attacker does not know `φ(N) = (p-1)(q-1)`), there is
no known shortcut for computing `x^(2^T)` other than performing all T squarings.
Knowing the factorisation of N breaks this, so in production the modulus is generated
with a *trapdoor-free* ceremony (nobody knows p and q).

### Wesolowski proof

Evaluating the VDF takes T steps, but asking the verifier to redo all T squarings
defeats the point.  The **Wesolowski proof** (2018) lets a prover convince the verifier
in roughly `O(T/log T)` squarings:

1. **Challenge**: derive `l = H(x, y, T)` — a hash-derived integer.
2. **Proof**: compute `π = x^(⌊2^T / l⌋) mod N`.
3. **Verify**: check `(π^l · x^(2^T mod l)) mod N == y`.

The verifier only needs `pow(π, l)` and `pow(x, r)` where `r = 2^T mod l` — far
cheaper than T full squarings.

```
Prover                          Verifier
------                          --------
y = x^(2^T) mod N               knows x, T, N
l = H(x, y, T)                  l = H(x, y, T)  [same hash]
q = floor(2^T / l)
π = x^q mod N
                -- y, π -->
                                r = 2^T mod l
                                check π^l · x^r == y  (mod N)
```

### Time-lock encryption

A VDF naturally enables **time-lock encryption**: encrypt a secret now, and it can only
be decrypted after someone evaluates the VDF.

1. Pick a random `x`.
2. Compute `y = VDF(x, T, N)` — this takes time proportional to T.
3. Encrypt: `ciphertext = message XOR KDF(y)`.
4. Publish `(x, T, ciphertext)` — anyone can decrypt once they solve the VDF.

## Build It

### Step 1: RSA Modulus

```python
_P = (1 << 31) - 1   # Mersenne prime 2^31-1
_Q = (1 << 61) - 1   # Mersenne prime 2^61-1
_N = _P * _Q         # 92-bit demo modulus

def vdf_setup() -> int:
    return _N
```

In production the modulus would be 2048+ bits and generated without anyone knowing
the factorisation.

### Step 2: Evaluate the VDF

```python
def vdf_eval(x: int, T: int, N: int) -> int:
    y = x % N
    for _ in range(T):
        y = (y * y) % N
    return y
```

T sequential squarings — this is the sequential bottleneck by design.

### Step 3: Wesolowski Proof

Compute `q = floor(2^T / l)` incrementally without ever materialising `2^T`:

```python
def vdf_eval_with_proof(x: int, T: int, N: int) -> tuple[int, int]:
    y = vdf_eval(x, T, N)
    l = vdf_challenge(x, y, T)
    q, r = 0, 1          # invariant: r == 2^i mod l
    for _ in range(T):
        two_r = 2 * r
        q = 2 * q + two_r // l
        r = two_r % l
    pi = pow(x, q, N)
    return y, pi
```

### Step 4: Verify

```python
def vdf_verify(x: int, T: int, y: int, pi: int, N: int) -> bool:
    l = vdf_challenge(x, y, T)
    r = pow(2, T, l)
    return (pow(pi, l, N) * pow(x, r, N)) % N == y
```

### Step 5: Time-Lock Encryption

```python
def vdf_time_lock_encrypt(message, T, N):
    x = random_in_range(1, N-1)
    y = vdf_eval(x, T, N)
    ciphertext = message XOR KDF(y)
    return x, T, ciphertext

def vdf_time_lock_decrypt(y, ciphertext):
    return ciphertext XOR KDF(y)
```

## Use It

Production VDF implementations:

| Project | Library | Modulus |
|---------|---------|---------|
| Chia | [chiavdf](https://github.com/Chia-Network/chiavdf) | 1024-bit RSA (trapdoor-free) |
| Ethereum RANDAO | Pietrzak VDF | 2048-bit RSA |
| Filecoin | [bellman](https://github.com/zkcrypto/bellman) | Wesolowski over class groups |

The key difference from this toy: production moduli are generated so that nobody
knows the factorisation (`N = p*q` but both p and q are discarded after N is created).

## Attack It

### Factor the modulus

If an attacker learns `p` and `q` they can compute `φ(N)` and evaluate
`y = x^(2^T mod φ(N)) mod N` in `O(T_bits)` multiplications rather than T.
**Mitigation**: trapdoor-free RSA modulus generation ceremonies.

### ASIC speedup

A custom squaring ASIC can perform each squaring much faster than commodity hardware.
This does not break soundness but reduces effective delay.
**Mitigation**: choose T based on the fastest known hardware; use a class group
whose squaring speed is harder to accelerate.

### Weak challenge l

If the challenge `l` is too small, the Wesolowski proof's soundness degrades.  In
this toy we truncate to T-2 bits; in production l should be a uniformly random
`λ`-bit prime (`λ ≥ 128`).

## Ship It

The reusable artifact for this lesson is a time-lock encryption template.
See `outputs/vdf-timelock-template.md`.

## Exercises

1. **Easy**: Change T from 20 to 100 and measure wall-clock time.  Estimate how
   large T must be for a 10-second delay on your hardware.
2. **Medium**: Extend `vdf_time_lock_encrypt` to support arbitrary-length messages
   by using a proper stream cipher seeded with `SHA-256(y)`.
3. **Hard**: Implement the Pietrzak recursive halving proof and compare proof
   generation time and proof size with the Wesolowski scheme implemented here.

## Key Terms

| Term | What people say | What it actually means |
|------|-----------------|------------------------|
| VDF | "delay function" | A function that takes exactly T sequential steps and whose output is publicly verifiable |
| Wesolowski proof | "efficient VDF proof" | A one-round interactive proof that verifies in O(1) exponentiations instead of T |
| RSA group of unknown order | "trapdoor RSA" | Z_N* where φ(N) is unknown, making repeated squaring hard to shortcut |
| Time-lock puzzle | "delay encryption" | A ciphertext that can only be decrypted after solving a sequential computation |
| Trapdoor-free setup | "trusted setup" | Generating N = p*q and then discarding p and q so no one can compute φ(N) |

## Test Vectors

Derived from `code/main.py` using `N = (2^31-1) * (2^61-1)`.

| x | T | y = x^(2^T) mod N |
|---|---|-------------------|
| 2 | 10 | 604453686716752709025796 |
| 2 | 20 | 302222231672357927124996 |
| 3 | 5  | 1853020188851841 |
| 3 | 10 | 4085088768715370141837429273 |

See `tests/vectors.json` for full proof verification vectors.

## Further Reading

- [Wesolowski 2018](https://eprint.iacr.org/2018/623.pdf) — Efficient Verifiable Delay Functions
- [Pietrzak 2018](https://eprint.iacr.org/2018/627.pdf) — Simple Verifiable Delay Functions
- [Boneh et al. 2018](https://eprint.iacr.org/2018/601.pdf) — A Survey of Two Verifiable Delay Functions
- [VDF Research](https://vdfresearch.org) — Community hub for VDF progress and implementations
