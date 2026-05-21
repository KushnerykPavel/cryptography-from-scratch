# Regev Encryption from Scratch

> A bit is “0 or q/2”, plus noise you can’t quite undo.

**Type:** Build
**Languages:** Python
**Prerequisites:** 04-lattices/09-lwe (LWE samples + toy bit encryption), basic modular arithmetic + vectors/matrices
**Time:** ~90 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain how Regev PKE hides a bit as a phase shift of `q/2` inside a noisy dot product
- Compute the decryption “phase” `x = v - <u, s> (mod q)` and decide 0 vs 1 by circular distance
- Implement keygen, bit encryption, bit decryption, and a tiny hybrid (KEM-DEM) wrapper using stdlib-only code
- Distinguish “toy Regev PKE” from real-world MLWE/RLWE KEMs (Kyber/ML-KEM) and why production needs constant-time sampling/encoding
- Apply a brute-force recovery attack on toy parameters and observe decryption failures when noise wraps modulo `q`

## The Problem

You’ll see lattice-based cryptography described as “just linear algebra modulo `q`”. Without a concrete encryption scheme in your hands, that can feel hand-wavy: where does *semantic security* come from, and why does a single “tiny noise term” matter so much?

Regev encryption is the canonical “minimal” public-key encryption built from LWE. It’s simple enough to fit in a lesson, but it contains the core pattern you’ll see again in modern PQC: publish noisy linear equations, then use a random subset + a `q/2` “phase shift” to carry message bits.

This lesson takes you from LWE samples to a working toy PKE and then to a toy hybrid encryption wrapper (the idea behind KEM-DEM), so later schemes (Kyber/ML-KEM) look like engineering improvements to the same shape rather than magic.

## The Concept

Start with LWE samples:

```text
A ← Z_q^{m×n}  uniform
s ← small in Z^n
e ← small in Z^m
b = A·s + e   (mod q)
```

Public key: `(A, b)`. Secret key: `s`.

To encrypt a bit `μ ∈ {0,1}`, choose a random binary selector `r ∈ {0,1}^m` (think: “pick a random subset of rows”), and small fresh noise:

```text
u = A^T·r + e1            (mod q)
v = b^T·r + e2 + μ·(q/2)  (mod q)
```

Decrypt by removing the `A·s` contribution:

```text
x = v - <u, s> (mod q) ≈ μ·(q/2) + (small noise)
```

If the total noise is small enough that `x` lands closer to `0` than to `q/2` (or vice versa) on the circle modulo `q`, you recover `μ`.

The entire scheme is “two facts”:

1. LWE makes `(A, b=A·s+e)` look pseudorandom without `s`.
2. With `s`, you can remove the structured part and only leave small noise — unless you choose parameters so badly that noise wraps around modulo `q`.

## Build It

### Step 1: Modular linear algebra + center lift

You need vector/matrix operations modulo `q`, plus a “center lift” that maps a residue back into a small signed representative in `[-q/2, q/2]`. Decryption is a *closeness* test, so you need a consistent way to talk about “small”.

```python
Vec = tuple[int, ...]
Matrix = list[list[int]]


def _require_positive_int(name: str, x: int) -> None:
    if not isinstance(x, int):
        raise TypeError(f"{name} must be int")
    if x <= 0:
        raise ValueError(f"{name} must be positive")


def _require_vec_dim(v: Vec, n: int, *, name: str) -> None:
    if len(v) != n:
        raise ValueError(f"{name} dimension mismatch")


def _require_matrix_dim(A: Matrix, m: int, n: int, *, name: str) -> None:
    if len(A) != m:
        raise ValueError(f"{name} row dimension mismatch")
    for row in A:
        if len(row) != n:
            raise ValueError(f"{name} column dimension mismatch")


def mod_q(x: int, q: int) -> int:
    _require_positive_int("q", q)
    return x % q


def center_lift(x: int, q: int) -> int:
    _require_positive_int("q", q)
    y = x % q
    half = q // 2
    if y > half:
        y -= q
    return y


def vec_add_mod(a: Vec, b: Vec, q: int) -> Vec:
    _require_vec_dim(a, len(b), name="a")
    return tuple((x + y) % q for x, y in zip(a, b))


def vec_sub_mod(a: Vec, b: Vec, q: int) -> Vec:
    _require_vec_dim(a, len(b), name="a")
    return tuple((x - y) % q for x, y in zip(a, b))


def dot_mod(a: Vec, b: Vec, q: int) -> int:
    _require_vec_dim(a, len(b), name="a")
    acc = 0
    for x, y in zip(a, b):
        acc += x * y
    return acc % q


def mat_vec_mul_mod(A: Matrix, x: Vec, q: int) -> Vec:
    _require_positive_int("q", q)
    m = len(A)
    if m == 0:
        raise ValueError("A must be non-empty")
    n = len(A[0])
    _require_matrix_dim(A, m, n, name="A")
    _require_vec_dim(x, n, name="x")
    out = []
    for i in range(m):
        out.append(dot_mod(tuple(A[i]), x, q))
    return tuple(out)


def mat_t_vec_mul_mod(A: Matrix, r: Vec, q: int) -> Vec:
    _require_positive_int("q", q)
    m = len(A)
    if m == 0:
        raise ValueError("A must be non-empty")
    n = len(A[0])
    _require_matrix_dim(A, m, n, name="A")
    _require_vec_dim(r, m, name="r")
    out = []
    for j in range(n):
        acc = 0
        for i in range(m):
            acc += A[i][j] * r[i]
        out.append(acc % q)
    return tuple(out)
```

This is the “algebraic surface area” you need for Regev: dot products, `A·s`, and `A^T·r`.

### Step 2: Deterministic RNG + sampling helpers

For learning (and for test vectors), it’s useful to have a deterministic RNG. We’ll use SHA-256 in counter mode to generate pseudorandom bytes and then sample integers.

```python
import hashlib


class Sha256CtrRng:
    def __init__(self, seed: bytes):
        if not isinstance(seed, (bytes, bytearray)):
            raise TypeError("seed must be bytes")
        if len(seed) == 0:
            raise ValueError("seed must be non-empty")
        self._seed = bytes(seed)
        self._ctr = 0
        self._buf = b""
        self._pos = 0

    def _refill(self) -> None:
        h = hashlib.sha256()
        h.update(self._seed)
        h.update(self._ctr.to_bytes(8, "big"))
        self._ctr += 1
        self._buf = h.digest()
        self._pos = 0

    def random_bytes(self, n: int) -> bytes:
        if n < 0:
            raise ValueError("n must be non-negative")
        out = bytearray()
        while len(out) < n:
            if self._pos >= len(self._buf):
                self._refill()
            take = min(n - len(out), len(self._buf) - self._pos)
            out += self._buf[self._pos : self._pos + take]
            self._pos += take
        return bytes(out)

    def _randbits(self, k: int) -> int:
        if k < 0:
            raise ValueError("k must be non-negative")
        nbytes = (k + 7) // 8
        x = int.from_bytes(self.random_bytes(nbytes), "big")
        if k % 8:
            x &= (1 << k) - 1
        return x

    def randbelow(self, n: int) -> int:
        if n <= 0:
            raise ValueError("n must be positive")
        k = n.bit_length()
        while True:
            x = self._randbits(k)
            if x < n:
                return x


def sample_uniform_matrix(rng: Sha256CtrRng, m: int, n: int, q: int) -> Matrix:
    _require_positive_int("m", m)
    _require_positive_int("n", n)
    _require_positive_int("q", q)
    return [[rng.randbelow(q) for _ in range(n)] for __ in range(m)]


def sample_ternary_vector(rng: Sha256CtrRng, n: int) -> Vec:
    _require_positive_int("n", n)
    return tuple(rng.randbelow(3) - 1 for _ in range(n))


def sample_binary_vector(rng: Sha256CtrRng, n: int) -> Vec:
    _require_positive_int("n", n)
    return tuple(rng.randbelow(2) for _ in range(n))
```

This RNG is **not** cryptographic as an implementation detail (it’s fine as a PRNG), but the entire code here is still not production-safe due to side channels and missing constant-time precautions.

### Step 3: Key generation (public key = noisy linear equations)

Key generation is exactly “publish LWE samples”:

- choose `A` uniform,
- choose small secret `s` and small error `e`,
- publish `b = A·s + e (mod q)`.

```python
from dataclasses import dataclass


@dataclass(frozen=True)
class RegevParams:
    n: int
    m: int
    q: int
    error_bound: int = 1

    def validate(self) -> None:
        _require_positive_int("n", self.n)
        _require_positive_int("m", self.m)
        _require_positive_int("q", self.q)
        if self.q <= 2:
            raise ValueError("q must be >= 3")
        if self.error_bound < 0:
            raise ValueError("error_bound must be non-negative")


@dataclass(frozen=True)
class RegevPublicKey:
    A: Matrix
    b: Vec


@dataclass(frozen=True)
class RegevSecretKey:
    s: Vec


def regev_keygen(rng: Sha256CtrRng, params: RegevParams) -> tuple[RegevPublicKey, RegevSecretKey]:
    params.validate()
    A = sample_uniform_matrix(rng, params.m, params.n, params.q)
    s = sample_ternary_vector(rng, params.n)
    e = sample_ternary_vector(rng, params.m)
    As = mat_vec_mul_mod(A, s, params.q)
    b = vec_add_mod(As, e, params.q)
    return RegevPublicKey(A=A, b=b), RegevSecretKey(s=s)
```

The public key is `m` equations, each “almost consistent” with the same hidden secret `s`.

### Step 4: Encrypt/decrypt one bit (Regev)

Encryption hides `μ` as a shift by `q/2`, then decryption checks which target (`0` or `q/2`) is closer on the modular circle.

```python
CiphertextBit = tuple[Vec, int]


def _circular_distance(a: int, b: int, q: int) -> int:
    d = (a - b) % q
    return min(d, (-d) % q)


def regev_encrypt_bit(
    rng: Sha256CtrRng,
    params: RegevParams,
    pk: RegevPublicKey,
    mu: int,
) -> CiphertextBit:
    params.validate()
    if mu not in (0, 1):
        raise ValueError("mu must be 0 or 1")
    _require_matrix_dim(pk.A, params.m, params.n, name="pk.A")
    _require_vec_dim(pk.b, params.m, name="pk.b")

    r = sample_binary_vector(rng, params.m)
    e1 = sample_ternary_vector(rng, params.n)
    e2 = rng.randbelow(3) - 1

    u0 = mat_t_vec_mul_mod(pk.A, r, params.q)
    u = vec_add_mod(u0, e1, params.q)
    v0 = dot_mod(r, pk.b, params.q)
    v = (v0 + e2 + mu * (params.q // 2)) % params.q
    return u, v


def regev_decrypt_bit(params: RegevParams, sk: RegevSecretKey, ct: CiphertextBit) -> int:
    params.validate()
    u, v = ct
    _require_vec_dim(u, params.n, name="u")
    _require_vec_dim(sk.s, params.n, name="sk.s")
    x = (v - dot_mod(u, sk.s, params.q)) % params.q
    d0 = _circular_distance(x, 0, params.q)
    d1 = _circular_distance(x, params.q // 2, params.q)
    return 0 if d0 < d1 else 1
```

This is the “signature shape” you’ll keep seeing: random subset `r`, transpose multiply `A^T·r`, plus a `q/2` encoding of the bit.

### Step 5: Hybrid encryption (KEM-DEM toy)

Real deployments don’t encrypt long messages directly with public-key math. They encrypt a *small key* (KEM), then use that key with symmetric crypto (DEM).

Here we do a toy version: pick a few random key bytes, encrypt all its bits with Regev, then XOR-encrypt a message with a SHA-256-derived keystream.

```python
from typing import Sequence


def bits_from_bytes(data: bytes) -> list[int]:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes-like")
    out = []
    for b in data:
        for i in range(7, -1, -1):
            out.append((b >> i) & 1)
    return out


def bytes_from_bits(bits: Sequence[int]) -> bytes:
    if len(bits) % 8 != 0:
        raise ValueError("bit length must be a multiple of 8")
    out = bytearray()
    for i in range(0, len(bits), 8):
        acc = 0
        for j in range(8):
            bit = bits[i + j]
            if bit not in (0, 1):
                raise ValueError("bits must be 0/1")
            acc = (acc << 1) | bit
        out.append(acc)
    return bytes(out)


class Sha256XorStream:
    def __init__(self, key: bytes, *, domain: bytes = b"regev-demo-stream-v1"):
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("key must be bytes-like")
        if len(key) == 0:
            raise ValueError("key must be non-empty")
        self._key = bytes(key)
        self._domain = bytes(domain)

    def keystream(self, n: int) -> bytes:
        if n < 0:
            raise ValueError("n must be non-negative")
        out = bytearray()
        ctr = 0
        while len(out) < n:
            h = hashlib.sha256()
            h.update(self._domain)
            h.update(self._key)
            h.update(ctr.to_bytes(8, "big"))
            out += h.digest()
            ctr += 1
        return bytes(out[:n])


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor requires equal-length inputs")
    return bytes(x ^ y for x, y in zip(a, b))


def regev_encrypt_bits(
    rng: Sha256CtrRng,
    params: RegevParams,
    pk: RegevPublicKey,
    bits: Sequence[int],
) -> list[CiphertextBit]:
    out = []
    for bit in bits:
        if bit not in (0, 1):
            raise ValueError("bits must be 0/1")
        out.append(regev_encrypt_bit(rng, params, pk, bit))
    return out


def regev_decrypt_bits(params: RegevParams, sk: RegevSecretKey, cts: Sequence[CiphertextBit]) -> list[int]:
    return [regev_decrypt_bit(params, sk, ct) for ct in cts]


def hybrid_encrypt(
    rng: Sha256CtrRng,
    params: RegevParams,
    pk: RegevPublicKey,
    plaintext: bytes,
    *,
    key_len: int = 4,
) -> dict:
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes-like")
    _require_positive_int("key_len", key_len)
    kem_key = rng.random_bytes(key_len)
    kem_bits = bits_from_bytes(kem_key)
    kem_ct = regev_encrypt_bits(rng, params, pk, kem_bits)

    stream = Sha256XorStream(kem_key)
    mask = stream.keystream(len(plaintext))
    ciphertext = xor_bytes(bytes(plaintext), mask)

    return {
        "kem_ct": kem_ct,
        "ciphertext": ciphertext,
        "key_len": key_len,
    }


def hybrid_decrypt(params: RegevParams, sk: RegevSecretKey, payload: dict) -> bytes:
    kem_ct = payload["kem_ct"]
    ciphertext = payload["ciphertext"]
    key_len = payload["key_len"]

    kem_bits = regev_decrypt_bits(params, sk, kem_ct)
    kem_key = bytes_from_bits(kem_bits[: key_len * 8])

    stream = Sha256XorStream(kem_key)
    mask = stream.keystream(len(ciphertext))
    return xor_bytes(ciphertext, mask)
```

This is intentionally inefficient (encrypting many bits) — modern schemes improve this with structured lattices and compression/encoding.

Run it:

```
python3 code/main.py
```

## Use It

Regev PKE is primarily a teaching construction. Real-world PQC uses related LWE variants plus a lot of engineering.

- **NIST-standard KEM:** ML-KEM (Kyber) — high-performance *module-LWE* KEM with tight encoding, compression, and constant-time implementations.
- **“Plain LWE” KEM (no rings):** FrodoKEM — larger keys/ciphertexts, but simpler structure assumptions.
- **Production guidance:** use vetted implementations (liboqs, PQClean, BoringSSL/OpenSSL when available), and follow NIST parameter sets — do not roll your own.

## Pitfalls

- Picking `q` too small or noise too large: decryption flips bits when the “phase” wraps around modulo `q`.
- Treating “deterministic RNG for demos” as acceptable in real crypto: you need high-quality entropy and side-channel-safe sampling.
- Forgetting domain separation: reuse of the same seed/key across roles (RNG vs keystream vs hashing) can create cross-protocol attacks.
- Thinking “bit encryption” scales: encrypting each bit independently is huge; real schemes use packing/compression and structured lattices.
- Ignoring attack surface: toy parameters are breakable by brute force and lattice reduction; real parameters are chosen against best-known attacks.

## Ship It

Save the review checklist in `outputs/regev-pke-review-checklist.md` and use it when you:

- review a PR touching “lattice/PQ encryption” code paths,
- sanity check parameter choices and message encoding,
- or migrate a protocol from “PKE mental model” to KEM-DEM design.

## Exercises

1. Easy: run `python3 code/main.py` and observe the `bit errors` count when we intentionally choose a smaller `q` (more wrap-around risk).
2. Medium: change `key_len` in `hybrid_encrypt()` to `8`, measure how much larger the KEM ciphertext gets, and print the total ciphertext “size” in bytes.
3. Hard: implement a slightly smarter toy attack (beyond brute force) by collecting multiple ciphertexts and looking for correlations when you force `r` to be sparse — then explain why real schemes avoid such bad randomness patterns.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Regev encryption | “PKE from LWE” | a bit encryption scheme using `u=A^T r + e1` and `v=b^T r + e2 + μ·q/2` |
| Phase | “value near 0 or q/2” | `x = v - <u,s> (mod q)`; decryption picks the nearer target |
| Center lift | “undo mod q” | map a residue into a small signed representative to talk about “small noise” |
| KEM-DEM | “hybrid encryption” | encapsulate a key with public-key math, then encrypt data symmetrically |
| Toy parameters | “small numbers for demos” | settings where brute force / simple attacks work and decryption can fail |

## Further Reading

- Oded Regev, *On lattices, learning with errors, random linear codes, and cryptography* (2005) — introduces LWE and the foundational encryption idea.
- Chris Peikert, *A Decade of Lattice Cryptography* (2016) — practical perspective on parameters, errors, and modern constructions.
- NIST, *FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)* (2024) — how the modern standardized descendant looks in production.
