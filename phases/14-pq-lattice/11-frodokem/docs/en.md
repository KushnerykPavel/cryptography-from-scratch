# FrodoKEM — LWE Without Rings
> Conservative lattice crypto: keep the math generic, and pay the matrix bill.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 14 · 04 (Regev Encryption), Phase 14 · 06 (Kyber ML-KEM)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain why FrodoKEM avoids rings and what you pay for it.
- Compute the Frodo `Encode/Decode` mapping between bits and `Z_q` matrices.
- Implement a toy FrodoPKE (`KeyGen/Enc/Dec`) over LWE matrices.
- Distinguish CPA (PKE) security from CCA (KEM) security via a re-encryption check.
- Apply a review checklist to spot common LWE/KEM implementation bugs.

## The Problem

You need a post-quantum key exchange. In 2026, that usually means ML-KEM (Kyber) — fast, small keys, and standardized. But some deployments want a **more conservative assumption surface**: no ring/module structure, no NTT, no “maybe this extra algebra is exploitable” anxiety.

FrodoKEM is the canonical example: it sticks close to plain **Learning With Errors (LWE)** and avoids rings entirely. The tradeoff is brutal but honest: **big matrices**, big bandwidth, and expensive multiplications. If you don’t understand how this style of scheme works, you can’t evaluate conservative PQ alternatives, audit their implementations, or reason about FO-transform pitfalls (re-encryption checks, malleability, and side-channels).

This lesson builds a small FrodoKEM-like KEM (with tiny parameters so you can read it), and makes you implement the exact pieces that tend to break in real code: matrix dimensions, noise sampling, `Encode/Decode`, and “decapsulate = decrypt + re-encrypt check”.

## The Concept

At the core is LWE in matrix form:

```
B = A*S + E   (mod q)
```

- `A` is uniform in `Z_q^{n×n}` (public, derived from a seed).
- `S` is a small secret in `Z^{n×n̄}`.
- `E` is a small error in `Z^{n×n̄}`.
- `q = 2^D` is a power-of-two modulus (Frodo uses `D ≤ 16`).

Encryption uses an *ephemeral* secret `S'` and errors `E', E''`:

```
B' = S' * A + E'           (mod q)    where B' ∈ Z_q^{n̄×n}
V  = S' * B + E''          (mod q)    where V  ∈ Z_q^{n̄×n̄}
C  = V + Encode(μ)         (mod q)    ciphertext carries (B', C)
```

Decryption cancels the large term:

```
W = C - B' * S   (mod q) ≈ Encode(μ) + (small noise)
μ = Decode(W)
```

`Encode/Decode` is the key “reconciliation” trick. For `B` bits per entry, Frodo encodes an integer `0 ≤ k < 2^B` as:

```
ec(k) = k * q / 2^B
```

and decodes by rounding:

```
dc(c) = round(c * 2^B / q) mod 2^B
```

Finally, FrodoKEM turns the CPA-secure PKE into a CCA-secure KEM using a Fujisaki–Okamoto style re-encryption check: decapsulation decrypts `μ`, re-derives the encryption “coins” from `μ`, re-encrypts, and only accepts `μ` if the ciphertext matches.

In this lesson we shrink parameters to a **toy** `n = 8`, `n̄ = 8`, `q = 2^15`, `B = 2`. The structure is real; the security is not.

## Build It

### Step 1: Deterministic matrix A (uniform mod q)
```python
from dataclasses import dataclass
import hashlib
import hmac
from typing import Iterable, List, Sequence, Tuple


Matrix = List[List[int]]


@dataclass(frozen=True)
class FrodoParams:
    n: int
    nbar: int
    q: int
    B: int
    eta: int

    def mu_bytes(self) -> int:
        bits = self.B * self.nbar * self.nbar
        if bits % 8 != 0:
            raise ValueError("B * nbar^2 must be a multiple of 8")
        return bits // 8

    def validate(self) -> None:
        if self.q <= 2**self.B:
            raise ValueError("need 2^B <= q")
        if self.q & (self.q - 1) != 0:
            raise ValueError("this toy expects q as a power of two")
        if self.n % 8 != 0 or self.nbar % 8 != 0:
            raise ValueError("this toy expects n, nbar ≡ 0 (mod 8)")
        if self.eta <= 0:
            raise ValueError("eta must be positive")
        _ = self.mu_bytes()


DEFAULT_PARAMS = FrodoParams(n=8, nbar=8, q=1 << 15, B=2, eta=2)


@dataclass(frozen=True)
class FrodoPublicKey:
    seed_a: bytes
    b: Matrix  # n x nbar


@dataclass(frozen=True)
class FrodoSecretKey:
    pk: FrodoPublicKey
    s: Matrix  # n x nbar
    fail_seed: bytes


@dataclass(frozen=True)
class FrodoCiphertext:
    bprime: Matrix  # nbar x n
    c: Matrix  # nbar x nbar


def shake256(data: bytes, outlen: int) -> bytes:
    return hashlib.shake_256(data).digest(outlen)


def expand_seed(seed: bytes, label: bytes, outlen: int) -> bytes:
    return shake256(b"FRODO-TOY|" + label + b"|" + seed, outlen)


def zeros(rows: int, cols: int) -> Matrix:
    return [[0 for _ in range(cols)] for _ in range(rows)]


def mat_add_mod_q(a: Matrix, b: Matrix, q: int) -> Matrix:
    rows = len(a)
    cols = len(a[0])
    out = zeros(rows, cols)
    for i in range(rows):
        for j in range(cols):
            out[i][j] = (a[i][j] + b[i][j]) % q
    return out


def mat_sub_mod_q(a: Matrix, b: Matrix, q: int) -> Matrix:
    rows = len(a)
    cols = len(a[0])
    out = zeros(rows, cols)
    for i in range(rows):
        for j in range(cols):
            out[i][j] = (a[i][j] - b[i][j]) % q
    return out


def mat_mul_mod_q(a: Matrix, b: Matrix, q: int) -> Matrix:
    rows = len(a)
    mid = len(a[0])
    cols = len(b[0])
    out = zeros(rows, cols)
    for i in range(rows):
        for k in range(mid):
            aik = a[i][k]
            for j in range(cols):
                out[i][j] = (out[i][j] + aik * b[k][j]) % q
    return out


def gen_matrix_a(seed_a: bytes, n: int, q: int) -> Matrix:
    """
    Deterministically expand seed_a into an n×n uniform matrix mod q.

    Real FrodoKEM uses careful generation; for this toy we exploit q=2^D and
    take 16-bit words mod q.
    """

    out = zeros(n, n)
    buf = expand_seed(seed_a, b"A", 2 * n * n)
    idx = 0
    for i in range(n):
        for j in range(n):
            word = buf[idx] | (buf[idx + 1] << 8)
            idx += 2
            out[i][j] = word % q
    return out
```

This step defines the parameter object, basic matrix arithmetic in `Z_q`, and a deterministic `A ← Gen(seedA)` function using SHAKE256 as a PRG. In the real scheme, this determinism is what makes public keys compact: you send `seedA`, not the whole `A`.

### Step 2: Noise sampling and KeyGen (B = A*S + E mod q)
```python
def _chunk_bits_le(buf: bytes) -> Iterable[int]:
    for byte in buf:
        for i in range(8):
            yield (byte >> i) & 1


def sample_cbd(seed: bytes, count: int, eta: int) -> List[int]:
    """
    Sample 'count' integers from a centered binomial distribution CBD_eta:
      e = sum_{i=1..eta}(a_i - b_i), with a_i,b_i ∈ {0,1} uniform.
    """

    needed_bits = count * 2 * eta
    needed_bytes = (needed_bits + 7) // 8
    stream = expand_seed(seed, b"CBD", needed_bytes)
    bits = _chunk_bits_le(stream)

    out: List[int] = []
    for _ in range(count):
        a = 0
        b = 0
        for _ in range(eta):
            a += next(bits)
        for _ in range(eta):
            b += next(bits)
        out.append(a - b)
    return out


def sample_error_matrix(seed: bytes, rows: int, cols: int, eta: int) -> Matrix:
    samples = sample_cbd(seed, rows * cols, eta)
    out = zeros(rows, cols)
    idx = 0
    for i in range(rows):
        for j in range(cols):
            out[i][j] = samples[idx]
            idx += 1
    return out


def frodo_pke_keygen(seed: bytes, params: FrodoParams = DEFAULT_PARAMS) -> Tuple[FrodoPublicKey, FrodoSecretKey]:
    params.validate()

    seed_a = expand_seed(seed, b"seedA", 16)
    seed_se = expand_seed(seed, b"seedSE", 16)
    fail_seed = expand_seed(seed, b"fail", 16)

    a = gen_matrix_a(seed_a, params.n, params.q)
    s = sample_error_matrix(seed_se + b"|S", params.n, params.nbar, params.eta)
    e = sample_error_matrix(seed_se + b"|E", params.n, params.nbar, params.eta)

    b = mat_add_mod_q(mat_mul_mod_q(a, s, params.q), e, params.q)
    pk = FrodoPublicKey(seed_a=seed_a, b=b)
    sk = FrodoSecretKey(pk=pk, s=s, fail_seed=fail_seed)
    return pk, sk
```

Here you build the LWE public key. The *only* thing making `B` look random is the small secret `S` and error `E`. If you recover `S` from `B = A*S + E`, you’ve broken the scheme — that’s the LWE problem.

### Step 3: Encode/Decode and CPA encryption
```python
def encode(mu: bytes, params: FrodoParams) -> Matrix:
    """
    Encode mu (B*nbar^2 bits) into an nbar×nbar matrix over Z_q.

    FrodoKEM's ec(k) is: ec(k) = k * q / 2^B.
    """

    params.validate()
    if len(mu) != params.mu_bytes():
        raise ValueError(f"mu must be exactly {params.mu_bytes()} bytes")

    step = params.q // (1 << params.B)
    out = zeros(params.nbar, params.nbar)

    bits = []
    for byte in mu:
        for i in range(8):
            bits.append((byte >> i) & 1)

    symbols: List[int] = []
    for i in range(0, len(bits), params.B):
        sym = 0
        for j in range(params.B):
            sym |= bits[i + j] << j
        symbols.append(sym)

    idx = 0
    for i in range(params.nbar):
        for j in range(params.nbar):
            out[i][j] = symbols[idx] * step
            idx += 1
    return out


def decode(m: Matrix, params: FrodoParams) -> bytes:
    """
    Decode an nbar×nbar matrix over Z_q back into mu.

    FrodoKEM's dc(c) is: dc(c) = round(c * 2^B / q) mod 2^B.
    """

    params.validate()
    if len(m) != params.nbar or len(m[0]) != params.nbar:
        raise ValueError("matrix must be nbar×nbar")

    mask = (1 << params.B) - 1
    bits: List[int] = []
    for i in range(params.nbar):
        for j in range(params.nbar):
            c = m[i][j] % params.q
            k = ((c * (1 << params.B) + (params.q // 2)) // params.q) & mask
            for t in range(params.B):
                bits.append((k >> t) & 1)

    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte |= bits[i + j] << j
        out.append(byte)
    return bytes(out)


def frodo_pke_encrypt(
    pk: FrodoPublicKey, mu: bytes, seed: bytes, params: FrodoParams = DEFAULT_PARAMS
) -> FrodoCiphertext:
    params.validate()

    a = gen_matrix_a(pk.seed_a, params.n, params.q)

    sprime = sample_error_matrix(seed + b"|S'", params.nbar, params.n, params.eta)
    eprime = sample_error_matrix(seed + b"|E'", params.nbar, params.n, params.eta)
    edprime = sample_error_matrix(seed + b"|E''", params.nbar, params.nbar, params.eta)

    bprime = mat_add_mod_q(mat_mul_mod_q(sprime, a, params.q), eprime, params.q)
    v = mat_add_mod_q(mat_mul_mod_q(sprime, pk.b, params.q), edprime, params.q)
    c = mat_add_mod_q(v, encode(mu, params), params.q)
    return FrodoCiphertext(bprime=bprime, c=c)


def frodo_pke_decrypt(ct: FrodoCiphertext, sk: FrodoSecretKey, params: FrodoParams = DEFAULT_PARAMS) -> bytes:
    params.validate()

    w = mat_sub_mod_q(ct.c, mat_mul_mod_q(ct.bprime, sk.s, params.q), params.q)
    return decode(w, params)
```

This is the heart of “how a noisy lattice scheme carries bits”: `Encode` pushes small symbols into the top bits of `Z_q`, the scheme adds noise, and `Decode` rounds back to the nearest symbol.

### Step 4: KEM wrapper (decapsulate = decrypt + re-encrypt check)
```python
def kem_kdf(mu: bytes, ct: FrodoCiphertext) -> bytes:
    packed = serialize_ciphertext(ct)
    return shake256(b"KDF|" + mu + b"|" + packed, 32)


def serialize_matrix(m: Matrix) -> bytes:
    out = bytearray()
    for row in m:
        for x in row:
            out += int(x).to_bytes(2, "little", signed=False)
    return bytes(out)


def serialize_ciphertext(ct: FrodoCiphertext) -> bytes:
    return serialize_matrix(ct.bprime) + serialize_matrix(ct.c)


def frodo_encaps(pk: FrodoPublicKey, seed: bytes, params: FrodoParams = DEFAULT_PARAMS) -> Tuple[FrodoCiphertext, bytes]:
    params.validate()

    mu = expand_seed(seed, b"mu", params.mu_bytes())
    coins = expand_seed(mu + pk.seed_a, b"coins", 16)

    ct = frodo_pke_encrypt(pk, mu, coins, params)
    ss = kem_kdf(mu, ct)
    return ct, ss


def frodo_decaps(ct: FrodoCiphertext, sk: FrodoSecretKey, params: FrodoParams = DEFAULT_PARAMS) -> bytes:
    params.validate()

    mu_hat = frodo_pke_decrypt(ct, sk, params)
    coins_hat = expand_seed(mu_hat + sk.pk.seed_a, b"coins", 16)
    ct_hat = frodo_pke_encrypt(sk.pk, mu_hat, coins_hat, params)

    ok = hmac.compare_digest(serialize_ciphertext(ct_hat), serialize_ciphertext(ct))
    if ok:
        mu_final = mu_hat
    else:
        mu_final = expand_seed(sk.fail_seed + serialize_ciphertext(ct), b"failmu", params.mu_bytes())
    return kem_kdf(mu_final, ct)
```

This FO-style check is what upgrades the encryption scheme into something KEM-like under chosen-ciphertext attacks: decapsulation refuses to “leak information by outputting a key” on malformed ciphertexts.

Run it:
python3 code/main.py

## Use It

If you need *real* FrodoKEM (not a toy), use a vetted implementation and an integration layer:

- **liboqs** — a C library implementing many PQ algorithms (including FrodoKEM) behind a common `OQS_KEM_*` API. The OQS docs include FrodoKEM parameter sets and characteristics.  
- **PQClean / pqm4** — portable “clean C” implementations and embedded benchmarking harnesses used widely in academic and engineering evaluations.

In production, you typically never call “FrodoKEM math” directly. You call a KEM API that returns `(ct, ss)` and you feed `ss` into a symmetric AEAD + key schedule.

## Pitfalls

- Mixing up dimensions (`n×n`, `n×n̄`, `n̄×n`, `n̄×n̄`) silently produces garbage ciphertexts that still “look random”.
- Getting `Encode/Decode` bit order wrong (endianness, symbol packing) breaks interoperability and can raise the decryption failure rate.
- Skipping domain separation in SHAKE expansions (reusing the same stream for `A`, `S`, `E`, `coins`, etc.) couples secrets in ways specs explicitly avoid.
- Implementing the re-encryption check or ciphertext compare in variable time (or with early-exit) creates side-channel oracles; FO checks are a known hot spot.
- Using “`x % q`” with non-power-of-two `q` without a uniform sampler introduces bias in `A` (and can be exploitable in some settings).

## Ship It

Save and reuse the artifact in `outputs/frodokem-audit-checklist.md`. Use it as:

- a PR review checklist when you see “LWE-based KEM” code,
- a design review template when choosing between conservative LWE and structured MLWE schemes,
- a personal “don’t forget” list before you wire a KEM into a protocol.

## Exercises

1. Easy: Run `python3 code/main.py`. Observe that `(encaps, decaps)` agree, but a 1-unit ciphertext tamper changes the shared secret.
2. Medium: In `DEFAULT_PARAMS`, vary `eta` (e.g., 1, 2, 3). Write a loop in `main()` that runs 1,000 encaps/decaps trials and report how often decryption fails.
3. Hard: Replace the toy KEM with a real liboqs call (outside this repo) and build a tiny hybrid KEX transcript: `X25519` + `FrodoKEM` → HKDF → AEAD.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| LWE | “Hard lattice problem” | Recover `S` from `A*S + E (mod q)` where `E` is small. |
| Modulus `q` | “Integer mod q” | Wrap-around arithmetic; often `q=2^D` for fast packing/rounding. |
| Error distribution | “Small noise” | The only thing preventing linear algebra from solving the secret. |
| `Encode/Decode` | “Reconciliation” | Map bits ↔ `Z_q` entries by scaling + rounding. |
| FO transform | “CCA upgrade” | Decrypt then re-encrypt to check validity before outputting a key. |
| Re-encryption check | “Ciphertext verification” | A correctness/CCA step that is also a common side-channel hazard. |

## Further Reading

- Alkim et al., *FrodoKEM: A conservative quantum-safe cryptographic algorithm* — the FrodoKEM specification and design rationale.
- Open Quantum Safe, *liboqs documentation* — practical KEM APIs and available FrodoKEM parameter sets.
- Hövelmanns et al., *(Un)breakable Curses: Re-encryption in the Fujisaki–Okamoto Transform* — why FO checks are subtle and can leak side channels.
