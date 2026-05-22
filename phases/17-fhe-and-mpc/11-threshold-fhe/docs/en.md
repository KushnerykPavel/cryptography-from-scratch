# Threshold FHE & Distributed Decryption
> You can compute on encrypted data all day — the hard part is letting *a quorum* decrypt.

**Type:** Build
**Languages:** Python
**Prerequisites:** `phases/17-fhe-and-mpc/01-fhe-overview`, `phases/17-fhe-and-mpc/08-bgw` (Shamir sharing + interpolation), comfort with modular arithmetic
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain why “distributed decryption” is the bottleneck in many FHE deployments
- Compute Paillier encrypt/decrypt and additive homomorphism on toy parameters
- Implement Shamir `t-of-n` secret sharing and reconstruction at `x=0`
- Distinguish “threshold decryption” from “just splitting a key file”
- Apply threshold decryption to decrypt an encrypted aggregate (a vote tally)

## The Problem

Homomorphic encryption lets an untrusted compute provider evaluate a function on encrypted inputs. In many real deployments, that compute provider is *not* allowed to decrypt the result — the decrypted output has to be released only when a quorum of key-holders agrees (or when some external condition holds).

If decryption is a single private key sitting on one server, then your whole “privacy” story collapses into “please don’t hack that server” or “please don’t bribe that operator”. Threshold decryption replaces a single point of failure with a quorum: **any `t` out of `n` parties can decrypt, but fewer than `t` can’t**.

This shows up everywhere: encrypted on-chain state with key committees, federated analytics where no single company should see the aggregate alone, and FHE-as-a-service where decryption is mediated by a governance set instead of the compute node.

## The Concept

### The mental model

Think of an HE system as two separable pieces:

1) **Evaluate:** anyone can take ciphertexts and compute new ciphertexts (requires public/evaluation keys).
2) **Decrypt:** someone turns ciphertexts back into plaintexts (requires secret key material).

Threshold HE (or “threshold decryption” in an HE system) modifies (2) so the secret key is never held by one party.

### A toy-but-useful stand-in: Paillier + threshold decryption

Full FHE schemes (BFV/BGV/CKKS/TFHE) are complex and depend on lattice math, noise budgets, key switching, and bootstrapping. This lesson focuses on the *threshold* part using a simpler homomorphic scheme:

- **Paillier** is *additively* homomorphic: multiplying ciphertexts adds plaintexts.
- It’s not FHE, but it’s enough to demonstrate the “encrypted aggregate + quorum decryption” workflow.

### What “threshold” really means (and what this lesson does)

In production threshold cryptography:
- each party holds a **secret key share**
- parties produce **partial decryptions**
- a combiner merges partial decryptions into the plaintext
- the combiner should learn **no secret key**
- there are usually proofs / checks so malicious parties can’t sabotage decryption

In this educational build, we take a simpler path:
- we use **Shamir secret sharing** to split the Paillier secret key pieces
- to decrypt, a combiner uses `t` shares to **reconstruct** the key (then decrypts)

This is *not* a secure threshold decryption protocol, but it’s a clear stepping stone: you’ll see exactly where the “real” protocols add verifiable partial decryptions and avoid key reconstruction.

## Build It

### Step 1: Toy Paillier (additive HE)
```python
from dataclasses import dataclass
import math
import secrets


@dataclass(frozen=True)
class PaillierPublicKey:
    n: int
    g: int
    n_sq: int


@dataclass(frozen=True)
class PaillierPrivateKey:
    lam: int
    mu: int


def egcd(a: int, b: int) -> tuple[int, int, int]:
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def modinv(a: int, m: int) -> int:
    a %= m
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("no modular inverse")
    return x % m


def lcm(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return abs(a // math.gcd(a, b) * b)


def L(u: int, n: int) -> int:
    if (u - 1) % n != 0:
        raise ValueError("L(u) undefined: u != 1 (mod n)")
    return (u - 1) // n


def paillier_keygen_from_primes(p: int, q: int) -> tuple[PaillierPublicKey, PaillierPrivateKey]:
    if p <= 2 or q <= 2 or p == q:
        raise ValueError("p and q must be distinct primes > 2")
    n = p * q
    n_sq = n * n
    g = n + 1
    lam = lcm(p - 1, q - 1)
    u = pow(g, lam, n_sq)
    lu = L(u, n)
    mu = modinv(lu, n)
    return PaillierPublicKey(n=n, g=g, n_sq=n_sq), PaillierPrivateKey(lam=lam, mu=mu)


def paillier_sample_r(n: int) -> int:
    while True:
        r = secrets.randbelow(n - 1) + 1
        if math.gcd(r, n) == 1:
            return r


def paillier_encrypt(m: int, pub: PaillierPublicKey, r: int | None = None) -> int:
    if not (0 <= m < pub.n):
        raise ValueError("message out of range")
    if r is None:
        r = paillier_sample_r(pub.n)
    if math.gcd(r, pub.n) != 1:
        raise ValueError("r must be in Z*_n")
    return (pow(pub.g, m, pub.n_sq) * pow(r, pub.n, pub.n_sq)) % pub.n_sq


def paillier_decrypt(c: int, pub: PaillierPublicKey, priv: PaillierPrivateKey) -> int:
    if not (0 <= c < pub.n_sq):
        raise ValueError("ciphertext out of range")
    u = pow(c, priv.lam, pub.n_sq)
    return (L(u, pub.n) * priv.mu) % pub.n
```
Paillier is additively homomorphic: decrypting the product of two ciphertexts yields the sum of the plaintexts (mod `n`). We use toy primes so you can see concrete integers go in and out.

### Step 2: Homomorphic evaluation (add, scalar mul)
```python
def paillier_hom_add(c1: int, c2: int, pub: PaillierPublicKey) -> int:
    return (c1 * c2) % pub.n_sq


def paillier_hom_scalar_mul(c: int, k: int, pub: PaillierPublicKey) -> int:
    if k < 0:
        raise ValueError("k must be non-negative in this toy demo")
    return pow(c, k, pub.n_sq)
```
With these two operations you can compute many “encrypted aggregates”: sums, weighted sums, vote tallies, histograms, and anything expressible as additions and multiplies-by-known-scalars.

### Step 3: Shamir secret sharing (t-of-n)
```python
from dataclasses import dataclass
from typing import Sequence


SHAMIR_PRIME_127 = (1 << 127) - 1


@dataclass(frozen=True)
class Share:
    x: int
    y: int


def poly_eval(coeffs: Sequence[int], x: int, prime: int) -> int:
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % prime
    return acc


def shamir_split(
    secret: int,
    n_shares: int,
    threshold: int,
    prime: int,
    *,
    coefficients: Sequence[int] | None = None,
) -> list[Share]:
    if not (1 <= threshold <= n_shares):
        raise ValueError("invalid threshold")
    if not (0 <= secret < prime):
        raise ValueError("secret out of field range")
    if coefficients is None:
        coeffs = [secret] + [secrets.randbelow(prime) for _ in range(threshold - 1)]
    else:
        if len(coefficients) != threshold - 1:
            raise ValueError("wrong number of coefficients")
        if any((c < 0 or c >= prime) for c in coefficients):
            raise ValueError("coefficients out of field range")
        coeffs = [secret, *coefficients]
    return [Share(x=i, y=poly_eval(coeffs, i, prime)) for i in range(1, n_shares + 1)]


def shamir_reconstruct_at_zero(shares: Sequence[Share], prime: int) -> int:
    if len(shares) == 0:
        raise ValueError("need at least one share")
    xs = [s.x % prime for s in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate x coordinates")

    secret = 0
    for j, share_j in enumerate(shares):
        xj = xs[j]
        num = 1
        den = 1
        for m, xm in enumerate(xs):
            if m == j:
                continue
            num = (num * xm) % prime
            den = (den * (xm - xj)) % prime
        lj = num * modinv(den, prime) % prime
        secret = (secret + share_j.y * lj) % prime
    return secret
```
Shamir sharing is “a random polynomial with `f(0)=secret`”. Any `threshold` points reconstruct `f(0)`. Fewer points can produce *some* value — but not reliably the right one.

### Step 4: Threshold decryption (reconstruct-and-decrypt)
```python
from dataclasses import dataclass
from typing import Sequence


@dataclass(frozen=True)
class ThresholdPaillierShare:
    x: int
    lam_y: int
    mu_y: int


def threshold_split_paillier_private_key(
    priv: PaillierPrivateKey,
    *,
    n_shares: int,
    threshold: int,
    prime: int,
    lam_coefficients: Sequence[int] | None = None,
    mu_coefficients: Sequence[int] | None = None,
) -> list[ThresholdPaillierShare]:
    lam_shares = shamir_split(priv.lam, n_shares, threshold, prime, coefficients=lam_coefficients)
    mu_shares = shamir_split(priv.mu, n_shares, threshold, prime, coefficients=mu_coefficients)
    combined: list[ThresholdPaillierShare] = []
    for ls, ms in zip(lam_shares, mu_shares, strict=True):
        combined.append(ThresholdPaillierShare(x=ls.x, lam_y=ls.y, mu_y=ms.y))
    return combined


def threshold_decrypt_paillier(
    c: int,
    pub: PaillierPublicKey,
    shares: Sequence[ThresholdPaillierShare],
    *,
    threshold: int,
    prime: int,
) -> int:
    if len(shares) < threshold:
        raise ValueError("not enough shares to decrypt")
    used = shares[:threshold]
    lam = shamir_reconstruct_at_zero([Share(s.x, s.lam_y) for s in used], prime)
    mu = shamir_reconstruct_at_zero([Share(s.x, s.mu_y) for s in used], prime)
    return paillier_decrypt(c, pub, PaillierPrivateKey(lam=lam, mu=mu))
```
This is the “threshold” wrapper: split secret key material with Shamir, then require `threshold` shares to decrypt. Again: production designs avoid reconstructing `lam`/`mu` in one place, but the control flow is the same.

Run it:
python3 code/main.py

## Use It

Real FHE systems implement thresholding differently depending on the scheme and library, but the integration points are consistent:

- **OpenFHE** — threshold variants for BFV/BGV/CKKS (DKG + distributed decryption; check the library’s “threshold” and “multiparty” examples)
- **Microsoft SEAL** — core BFV/CKKS building blocks; threshold requires an external protocol layer (no built-in threshold decryption in the same “one call” sense)
- **Lattigo (Go)** — includes multi-party / threshold HE examples for lattice HE settings
- **TFHE / Concrete / TFHE-rs** — more natural for boolean/lookup workloads; threshold typically wraps key generation + decryption with MPC/proofs
- **Homomorphic Encryption Standard** — describes recommended parameters and APIs, and discusses threshold HE at a high level

Rule of thumb: in production you want (a) distributed key generation (DKG), (b) partial decryption proofs or robust checks, and (c) tight governance/identity around who can trigger decryptions.

## Pitfalls

1) **“Threshold” that reconstructs the key in one place.** It defeats the point if any combiner can end up holding the full secret key (this lesson does it on purpose for clarity).
2) **No verifiability for partial decryptions.** A malicious party can send garbage shares and stall the system unless you add proofs/checks and a retry policy.
3) **Nonce / randomness reuse (Paillier).** Reusing `r` across encryptions can leak relationships between plaintexts; real schemes treat randomness as critical secret material.
4) **Wrong threshold / liveness tradeoff.** Too-low `t` enables collusion; too-high `t` makes decryption brittle during outages or key-holder churn.
5) **Unauthenticated shares and IDs.** If you don’t bind shares to party identities (and authenticated channels), an attacker can mix-and-match shares or replay old ones.

## Ship It

Save and reuse the checklist at:
`outputs/threshold-fhe-deployment-checklist.md`

Use it when you:
- review a design doc for threshold decryption / threshold HE
- review a PR that adds “distributed decryption” to an HE/MPC system
- write runbooks for key ceremonies, decryption ceremonies, and key rotation

## Exercises

1. Easy. Run `python3 code/main.py`. Observe that multiplying ciphertexts adds plaintexts, and that fewer than `threshold` shares can’t decrypt.
2. Medium. Extend the demo to compute an encrypted **weighted sum** (e.g., votes with weights) using `paillier_hom_scalar_mul`, then threshold decrypt the result.
3. Hard. Replace the “reconstruct-and-decrypt” step with a **partial decryption API** (each party returns a partial value) and add a sanity check that detects a malicious party returning inconsistent output.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Threshold decryption | “You need `t-of-n` to decrypt.” | Decryption requires contributions from multiple key-holders, ideally without reconstructing the secret key. |
| Secret sharing | “Split the key into pieces.” | Encode a secret as a polynomial so any `t` shares reconstruct and fewer reveal nothing (information-theoretic). |
| Partial decryption | “Each party decrypts their part.” | Each party computes a share-dependent transform of the ciphertext; a combiner merges them into the plaintext. |
| DKG | “No trusted dealer.” | Parties jointly generate a public key and secret shares without a single party ever learning the full secret. |
| Evaluation key | “Extra public key.” | Public auxiliary material that enables homomorphic operations (e.g., key switching/relinearization), often large. |

## Further Reading

- Pascal Paillier, *Public-Key Cryptosystems Based on Composite Degree Residuosity Classes* (1999) — the original Paillier cryptosystem.
- Ronald Cramer, Ivan Damgård, Jesper Buus Nielsen, *Secure Multiparty Computation and Secret Sharing* (2015) — Shamir sharing, interpolation, and MPC foundations.
- Homomorphic Encryption Standard (v1.1) — practical guidance for HE APIs, parameters, and interoperability (including threshold HE concepts).
