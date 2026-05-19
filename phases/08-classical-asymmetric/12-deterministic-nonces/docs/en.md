# Deterministic Nonces — RFC 6979
> If your nonce generation is “almost random”, your private key is “almost public”.

**Type:** Build
**Languages:** Python
**Prerequisites:** `phases/08-classical-asymmetric/06-dsa-ecdsa`, `phases/08-classical-asymmetric/07-ecdsa-attacks`
**Time:** ~45 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** why DSA/ECDSA nonces (`k`) are a single point of failure
- **Compute** how RFC 6979 turns `(x, H(m))` into a per-message `k`
- **Implement** RFC 6979 nonce generation (HMAC-DRBG) from scratch (stdlib only)
- **Distinguish** “deterministic nonce” (RFC 6979) from “random nonce” (CSPRNG) and “fixed nonce” (catastrophic)
- **Apply** a nonce-reuse key-recovery attack to validate why the rules exist

## The Problem
You’re reviewing or building a signing system (API request signing, firmware updates, package signing, blockchain transactions). The signature algorithm might be “standard” (DSA/ECDSA), but the implementation still has one fragile dependency: generating the per-signature nonce `k`.

If `k` is ever reused, leaked, biased, or drawn from too small a range, attackers can often recover the long-term private key from a handful of signatures. This has happened in real deployments: VM snapshot restores, low-entropy embedded devices, RNG bugs, “debug logs” that accidentally leak a scalar, and concurrency/caching mistakes can all turn into key compromise.

RFC 6979 eliminates the dependency on “high-quality randomness at signing time” by deriving `k` deterministically from the private key and the message hash. That makes implementations easier to test and dramatically reduces the most common operational failure modes.

## The Concept
DSA and ECDSA both have a hidden secret per signature: the nonce `k`. The signing equation (over a group of order `q`) can be remembered as:

`s ≡ k^{-1}(h + x·r) (mod q)`

where:
- `x` is the long-term private key
- `h` is the message hash interpreted as an integer mod `q`
- `r` is the first signature component (derived from `k` and the group generator)

Rearrange it and you get the “danger equation”:

`s·k ≡ h + x·r (mod q)`

From that:
- If `k` is known once, `x` is solvable from one signature.
- If the same `k` is reused for two messages, `k` is solvable from the pair — and then `x` follows.

So `k` must be:
- **unique** per signature (for a given key),
- **secret** (never logged / never leaked),
- **unpredictable** to attackers (either truly random, or RFC 6979-deterministic in a way that looks random to anyone without `x`).

RFC 6979’s core idea: build a deterministic PRNG (HMAC-DRBG) seeded with `(x, H(m))`, then draw `k` from it until `1 <= k < q`. For the same key and message, you get the same `k` — which makes testing easy — but to an attacker who doesn’t know `x`, it is computationally indistinguishable from random.

## Build It

### Step 1: Hashes, integers, and octets
RFC 6979 is defined in terms of bit strings and octet strings. The conversions are easy to get subtly wrong (bit order, truncation length, reduction mod `q`). We implement the exact transforms needed for deterministic nonce generation.

```python
def int_to_bytes(x: int, length: int) -> bytes:
    if x < 0:
        raise ValueError("x must be >= 0")
    return x.to_bytes(length, "big")


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def bits2int(b: bytes, qlen: int) -> int:
    x = bytes_to_int(b)
    blen = 8 * len(b)
    if blen > qlen:
        x >>= blen - qlen
    return x


def int2octets(x: int, rolen: int) -> bytes:
    if x < 0:
        raise ValueError("x must be >= 0")
    return int_to_bytes(x, rolen)


def bits2octets(h1: bytes, q: int) -> bytes:
    qlen = q.bit_length()
    rolen = (qlen + 7) // 8
    z1 = bits2int(h1, qlen)
    z2 = z1 % q
    return int2octets(z2, rolen)
```

`bits2int()` takes the leftmost `qlen` bits of the hash (this matches how DSA/ECDSA turn a hash into an integer). `bits2octets()` then reduces that integer mod `q` and re-encodes it as exactly `rolen` bytes.

### Step 2: RFC 6979 deterministic nonce generation
Now we implement the RFC 6979 HMAC-DRBG loop: it maintains two internal byte strings (`K` and `V`) and produces candidate nonces until the candidate lands in the valid range `1..q-1`.

```python
import hashlib
import hmac
from dataclasses import dataclass
from typing import Callable, Iterator


@dataclass
class Rfc6979NonceGenerator:
    q: int
    qlen: int
    rolen: int
    hashfunc: Callable[[], "hashlib._Hash"]
    v: bytes
    k: bytes

    @classmethod
    def from_key_and_hash(
        cls,
        *,
        x: int,
        q: int,
        h1: bytes,
        hashfunc: Callable[[], "hashlib._Hash"] = hashlib.sha256,
    ) -> "Rfc6979NonceGenerator":
        qlen = q.bit_length()
        holen = hashfunc().digest_size
        rolen = (qlen + 7) // 8

        bx = int2octets(x % q, rolen) + bits2octets(h1, q)
        v = b"\x01" * holen
        k = b"\x00" * holen

        k = hmac.new(k, v + b"\x00" + bx, hashfunc).digest()
        v = hmac.new(k, v, hashfunc).digest()
        k = hmac.new(k, v + b"\x01" + bx, hashfunc).digest()
        v = hmac.new(k, v, hashfunc).digest()

        return cls(q=q, qlen=qlen, rolen=rolen, hashfunc=hashfunc, v=v, k=k)

    def next_k(self) -> int:
        while True:
            t = b""
            while len(t) < self.rolen:
                self.v = hmac.new(self.k, self.v, self.hashfunc).digest()
                t += self.v

            candidate = bits2int(t[: self.rolen], self.qlen)
            if 1 <= candidate < self.q:
                return candidate

            self.k = hmac.new(self.k, self.v + b"\x00", self.hashfunc).digest()
            self.v = hmac.new(self.k, self.v, self.hashfunc).digest()


def rfc6979_k_stream(
    *,
    x: int,
    q: int,
    message: bytes,
    hashfunc: Callable[[], "hashlib._Hash"] = hashlib.sha256,
) -> Iterator[int]:
    h1 = hashfunc(message).digest()
    gen = Rfc6979NonceGenerator.from_key_and_hash(x=x, q=q, h1=h1, hashfunc=hashfunc)
    while True:
        yield gen.next_k()


def rfc6979_generate_k(
    *,
    x: int,
    q: int,
    message: bytes,
    hashfunc: Callable[[], "hashlib._Hash"] = hashlib.sha256,
) -> int:
    return next(rfc6979_k_stream(x=x, q=q, message=message, hashfunc=hashfunc))
```

This is “deterministic randomness”: given the same `(x, message)`, it always returns the same `k`. But without knowing `x`, the output is pseudorandom.

### Step 3: Deterministic DSA sign/verify (RFC 6979)
To make RFC 6979 concrete, we implement DSA signing and verification using the deterministic `k` generator from Step 2. This is the same math as earlier DSA/ECDSA lessons — but now `k` is produced in a way that is testable and avoids RNG foot-guns at signing time.

```python
def mod_inv(a: int, modulus: int) -> int:
    a %= modulus
    if a == 0:
        raise ValueError("inverse does not exist")

    t, new_t = 0, 1
    r, new_r = modulus, a
    while new_r != 0:
        q = r // new_r
        t, new_t = new_t, t - q * new_t
        r, new_r = new_r, r - q * new_r

    if r != 1:
        raise ValueError("inverse does not exist")
    return t % modulus


def hash_to_int(message: bytes, q: int, hashfunc: Callable[[], "hashlib._Hash"] = hashlib.sha256) -> int:
    qlen = q.bit_length()
    h1 = hashfunc(message).digest()
    return bits2int(h1, qlen) % q


def dsa_sign(
    *,
    p: int,
    q: int,
    g: int,
    x: int,
    message: bytes,
    hashfunc: Callable[[], "hashlib._Hash"] = hashlib.sha256,
    k: int | None = None,
) -> tuple[int, int, int]:
    if not (1 <= x < q):
        raise ValueError("private key x must be in 1..q-1")

    h = hash_to_int(message, q, hashfunc)

    if k is not None:
        k_candidates = iter([k])
    else:
        k_candidates = rfc6979_k_stream(x=x, q=q, message=message, hashfunc=hashfunc)

    for k_try in k_candidates:
        if not (1 <= k_try < q):
            raise ValueError("nonce k must be in 1..q-1")

        r = pow(g, k_try, p) % q
        if r == 0:
            continue

        s = (mod_inv(k_try, q) * (h + x * r)) % q
        if s == 0:
            continue

        return r, s, k_try

    raise ValueError("failed to produce non-zero (r,s)")


def dsa_verify(
    *,
    p: int,
    q: int,
    g: int,
    y: int,
    message: bytes,
    r: int,
    s: int,
    hashfunc: Callable[[], "hashlib._Hash"] = hashlib.sha256,
) -> bool:
    if not (1 <= r < q and 1 <= s < q):
        return False

    h = hash_to_int(message, q, hashfunc)
    w = mod_inv(s, q)
    u1 = (h * w) % q
    u2 = (r * w) % q
    v = (pow(g, u1, p) * pow(y, u2, p)) % p
    v %= q
    return v == r
```

The only difference between “randomized DSA” and “deterministic DSA” is how `k` is chosen. Everything else (verification, signature format, compatibility) stays the same.

### Step 4: Nonce reuse breaks DSA (key recovery)
To lock in *why* this matters, we implement the algebra that recovers the private key if the same nonce signs two different messages.

```python
def recover_k_from_reused_dsa_nonce(*, q: int, h1: int, h2: int, s1: int, s2: int) -> int:
    if s1 == s2:
        raise ValueError("s1 must not equal s2 for reused-nonce recovery")
    return ((h1 - h2) * mod_inv((s1 - s2) % q, q)) % q


def recover_x_from_dsa_known_k(*, q: int, r: int, s: int, h: int, k: int) -> int:
    if r == 0:
        raise ValueError("r must be non-zero")
    return ((s * k - h) * mod_inv(r % q, q)) % q
```

If your system ever emits two signatures with the same nonce (same `r`), the private key is no longer “long-term secret” — it’s a solvable equation.

Run it:

python3 code/main.py

## Use It
In production, you should not implement RFC 6979 yourself unless you’re building a crypto library. Use audited libraries that already expose deterministic signing modes.

Examples:
- **PyCryptodome**: `Crypto.Signature.DSS.new(key, "deterministic-rfc6979")` for DSA/ECDSA.
- **OpenSSL**: many ECDSA implementations support deterministic `k` internally (depending on version/build/config); prefer high-level, audited APIs.
- **Ed25519 / EdDSA**: nonce is deterministic by design (derived from a secret prefix + message), so it avoids the “random k” foot-gun entirely.

## Pitfalls
- Using `random` / `Math.random()` / weak PRNGs for `k` (catastrophic).
- “Deterministic nonce” implemented as `k = H(x || m)` without RFC 6979’s HMAC-DRBG structure (easy to get wrong, easy to bias, and hard to audit).
- Hash-to-int conversion bugs: using the full hash without truncation, wrong bit order, or forgetting the reduction mod `q`.
- Accidentally reusing `k` due to caching, retries, concurrency bugs, or VM snapshot restores (the `r` values will repeat).
- Assuming RFC 6979 eliminates all side channels: deterministic `k` does not make scalar multiplication constant-time, and it doesn’t protect you if `k` (or intermediate values) leak through logs, timing, or power analysis.

## Ship It
This lesson ships a reusable review artifact:

- `outputs/skill-rfc6979-nonce-audit.md` — copy/paste checklist for reviewing deterministic nonces in DSA/ECDSA codebases (what to verify, what to ban in app code, what incidents look like).

Use it in PR reviews: when you see ECDSA/DSA signing code, paste the checklist into your review notes and work through it systematically.

## Exercises
1. Easy. Run `python3 code/main.py`. Observe that RFC 6979 produces the exact same `k, r, s` for the RFC test vectors.
2. Medium. Extend the script to print and compare RFC 6979 vectors for a second hash (e.g., SHA-1 or SHA-512) for the same DSA parameters.
3. Hard. Find a real signing callsite (a library wrapper or service) and use `outputs/skill-rfc6979-nonce-audit.md` to write a short audit note: what’s safe, what’s risky, and what evidence would prove nonce reuse in logs.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Nonce (`k`) | “Random per-signature number” | A per-signature secret scalar; if reused/leaked/biased, the long-term key can be recovered. |
| Deterministic nonce | “No RNG needed” | A nonce derived from `(x, H(m))` so it’s unique per message and pseudorandom to outsiders. |
| RFC 6979 | “Deterministic ECDSA” | A specific HMAC-DRBG construction + integer conversion rules that produce compatible DSA/ECDSA signatures. |
| HMAC-DRBG | “PRNG” | A deterministic generator built from HMAC with internal state `(K,V)` and a reseed/update rule. |
| Nonce reuse | “Accidental repeat” | Two signatures share the same `k` (often seen as repeated `r`); typically implies full private-key compromise. |

## Further Reading
- T. Pornin, *RFC 6979: Deterministic Usage of DSA and ECDSA* (2013) — the deterministic nonce standard and test vectors.
- NIST, *Digital Signature Standard (FIPS 186-4 / 186-5)* (2013/2023) — the underlying DSA/ECDSA signing equations and validity checks.
- Fail0verflow / PS3 ECDSA incident writeups (2010) — a real-world example of “fixed nonce == leaked private key”.
