# Lattice PQC Lab — Build a Mini Kyber

> Module-LWE becomes real once you can run keygen → encrypt → decrypt on polynomials.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 14 Lesson 04 (Regev), Lesson 06 (Kyber / ML-KEM), Lesson 07 (Kyber Internals — NTT & Compression)
**Time:** ~120 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain Module-LWE encryption at a high level
- Compute negacyclic polynomial multiplication in `R_q`
- Implement a toy Kyber-style PKE (keygen/encrypt/decrypt)
- Distinguish uniform sampling from centered noise sampling
- Apply coefficient compression + bit-packing and understand the error it introduces

## The Problem

You will see ML-KEM (Kyber) show up as “just a KEM,” but integrating it safely is not “just call the API.” Teams ship broken PQ integrations by misunderstanding what the randomness is for, what gets compressed, and where decryption failures come from.

This lesson is a lab to turn the black box into shapes you can reason about: vectors of polynomials, small noise, a public matrix `A`, and two ciphertext parts `(u, v)` that are basically “masked linear algebra + rounding.” Once you can run a *mini* version end-to-end, you can review real-world code more confidently.

## The Concept

Kyber/ML-KEM is built on Module-LWE over a polynomial ring:

- Ring: `R_q = Z_q[x] / (x^N + 1)` (negacyclic: `x^N = -1`)
- Matrix: `A ∈ R_q^{k×k}` sampled “uniformly”
- Secrets/noise: `s, e, r, e1, e2` are *small* (e.g. centered binomial)

Toy PKE structure (IND-CPA):

```
Keygen:
  t = A·s + e
  pk = (seed_A, t)
  sk = s

Encrypt m:
  u = A^T·r + e1
  v = t^T·r + e2 + Encode(m)
  ct = (u, v)

Decrypt:
  m' = Decode(v - s^T·u)
```

Compression/packing in real schemes is a *lossy* rounding step:

- compress: map a coefficient in `[0, q)` to `d` bits
- decompress: map back to an approximate representative in `[0, q)`

That rounding is safe only because the noise is small enough that “0 vs `q/2`” remains distinguishable after compression.

## Build It

### Step 1: Negacyclic ring arithmetic (R_q = Z_q[x]/(x^N+1))

We implement polynomial addition/subtraction mod `q`, plus **negacyclic** multiplication (wrap-around terms flip sign because `x^N = -1`).

```python
def mod_q(x: int, q: int = Q) -> int:
    return x % q


def poly_reduce(a: Sequence[int], q: int = Q) -> Poly:
    if len(a) != N:
        raise ValueError(f"poly must have length {N}")
    return [x % q for x in a]


def poly_add(a: Sequence[int], b: Sequence[int], q: int = Q) -> Poly:
    if len(a) != N or len(b) != N:
        raise ValueError(f"polys must have length {N}")
    return [(x + y) % q for x, y in zip(a, b)]


def poly_sub(a: Sequence[int], b: Sequence[int], q: int = Q) -> Poly:
    if len(a) != N or len(b) != N:
        raise ValueError(f"polys must have length {N}")
    return [(x - y) % q for x, y in zip(a, b)]


def poly_mul_negacyclic(a: Sequence[int], b: Sequence[int], q: int = Q) -> Poly:
    if len(a) != N or len(b) != N:
        raise ValueError(f"polys must have length {N}")

    tmp = [0] * (2 * N - 1)
    for i, ai in enumerate(a):
        for j, bj in enumerate(b):
            tmp[i + j] += ai * bj

    out = [0] * N
    for k, val in enumerate(tmp):
        if k < N:
            out[k] += val
        else:
            out[k - N] -= val
    return [x % q for x in out]
```

### Step 2: Deterministic sampling: uniform A and small noise

Real Kyber specifies exact sampling procedures. For this lab we keep the *shape* the same and use SHAKE256 as a deterministic PRG, plus a simple centered-binomial sampler for noise.

```python
def _shake256(data: bytes, outlen: int) -> bytes:
    if outlen < 0:
        raise ValueError("outlen must be >= 0")
    return hashlib.shake_256(data).digest(outlen)


def prg(seed: bytes, domain: bytes, nonce: int, outlen: int) -> bytes:
    if not (0 <= nonce < 2**16):
        raise ValueError("nonce must fit in 16 bits")
    return _shake256(seed + domain + nonce.to_bytes(2, "little"), outlen)


def _bytes_to_bits_le(data: bytes) -> List[int]:
    return [(b >> i) & 1 for b in data for i in range(8)]


def sample_cbd_poly(seed: bytes, nonce: int, eta: int = ETA, n: int = N) -> Poly:
    if eta <= 0:
        raise ValueError("eta must be >= 1")
    if n <= 0:
        raise ValueError("n must be >= 1")
    nbits = 2 * eta * n
    nbytes = (nbits + 7) // 8
    raw = prg(seed, b"|N|", nonce, nbytes)
    bits = _bytes_to_bits_le(raw)[:nbits]

    out: Poly = []
    idx = 0
    for _ in range(n):
        a = sum(bits[idx : idx + eta])
        idx += eta
        b = sum(bits[idx : idx + eta])
        idx += eta
        out.append((a - b) % Q)
    if len(out) != N:
        raise ValueError("internal error: unexpected cbd length")
    return out


def sample_uniform_poly(seed: bytes, nonce: int, n: int = N, q: int = Q) -> Poly:
    raw = prg(seed, b"|A|", nonce, 2 * n)
    out = [int.from_bytes(raw[2 * i : 2 * i + 2], "little") % q for i in range(n)]
    if len(out) != N:
        raise ValueError("internal error: unexpected uniform length")
    return out


def vec_add(v: Sequence[Sequence[int]], w: Sequence[Sequence[int]], q: int = Q) -> PolyVec:
    if len(v) != K or len(w) != K:
        raise ValueError(f"vectors must have length {K}")
    return [poly_add(v[i], w[i], q=q) for i in range(K)]


def mat_vec_mul(a: PolyMat, s: Sequence[Sequence[int]], q: int = Q) -> PolyVec:
    if len(a) != K or any(len(row) != K for row in a):
        raise ValueError(f"matrix must be {K}x{K}")
    if len(s) != K:
        raise ValueError(f"vector must have length {K}")

    out: PolyVec = []
    for i in range(K):
        acc = [0] * N
        for j in range(K):
            acc = poly_add(acc, poly_mul_negacyclic(a[i][j], s[j], q=q), q=q)
        out.append(acc)
    return out


def mat_t_vec_mul(a: PolyMat, r: Sequence[Sequence[int]], q: int = Q) -> PolyVec:
    if len(a) != K or any(len(row) != K for row in a):
        raise ValueError(f"matrix must be {K}x{K}")
    if len(r) != K:
        raise ValueError(f"vector must have length {K}")

    out: PolyVec = []
    for i in range(K):
        acc = [0] * N
        for j in range(K):
            acc = poly_add(acc, poly_mul_negacyclic(a[j][i], r[j], q=q), q=q)
        out.append(acc)
    return out


def vec_dot(v: Sequence[Sequence[int]], w: Sequence[Sequence[int]], q: int = Q) -> Poly:
    if len(v) != K or len(w) != K:
        raise ValueError(f"vectors must have length {K}")
    acc = [0] * N
    for i in range(K):
        acc = poly_add(acc, poly_mul_negacyclic(v[i], w[i], q=q), q=q)
    return acc


def gen_matrix(seed_a: bytes) -> PolyMat:
    a: PolyMat = []
    nonce = 0
    for _ in range(K):
        row: List[Poly] = []
        for _ in range(K):
            row.append(sample_uniform_poly(seed_a, nonce))
            nonce += 1
        a.append(row)
    return a


def gen_noise_vec(seed: bytes, start_nonce: int) -> PolyVec:
    return [sample_cbd_poly(seed, start_nonce + i) for i in range(K)]


def gen_noise_poly(seed: bytes, nonce: int) -> Poly:
    return sample_cbd_poly(seed, nonce)
```

### Step 3: Mini Kyber-style PKE: keygen, encrypt, decrypt

Now we build the end-to-end flow. Message encoding is “bit → coefficient is either `0` or `~q/2`,” and decoding is a threshold test.

```python
def msg_to_poly(m: int) -> Poly:
    if not (0 <= m < 2**N):
        raise ValueError(f"message must fit in {N} bits")
    half = (Q + 1) // 2
    return [half if ((m >> i) & 1) else 0 for i in range(N)]


def poly_to_msg(p: Sequence[int]) -> int:
    if len(p) != N:
        raise ValueError(f"poly must have length {N}")
    lo = Q // 4
    hi = (3 * Q) // 4
    out = 0
    for i, c in enumerate(p):
        c = c % Q
        bit = 1 if (lo <= c < hi) else 0
        out |= bit << i
    return out


@dataclass(frozen=True)
class PublicKey:
    seed_a: bytes
    t: PolyVec


@dataclass(frozen=True)
class SecretKey:
    s: PolyVec


@dataclass(frozen=True)
class Ciphertext:
    u: PolyVec
    v: Poly


def keygen(master_seed: bytes) -> Tuple[PublicKey, SecretKey]:
    if len(master_seed) < 16:
        raise ValueError("master_seed must be at least 16 bytes")

    seed_a = _shake256(b"A" + master_seed, 32)
    seed_n = _shake256(b"N" + master_seed, 32)

    a = gen_matrix(seed_a)
    s = gen_noise_vec(seed_n, 0)
    e = gen_noise_vec(seed_n, K)
    t = vec_add(mat_vec_mul(a, s), e)
    return PublicKey(seed_a=seed_a, t=t), SecretKey(s=s)


def encrypt(pk: PublicKey, m: int, coins: bytes) -> Ciphertext:
    if len(coins) < 16:
        raise ValueError("coins must be at least 16 bytes")
    a = gen_matrix(pk.seed_a)

    seed_r = _shake256(b"R" + coins, 32)
    r = gen_noise_vec(seed_r, 0)
    e1 = gen_noise_vec(seed_r, K)
    e2 = gen_noise_poly(seed_r, 2 * K)

    u = vec_add(mat_t_vec_mul(a, r), e1)
    v = poly_add(vec_dot(pk.t, r), poly_add(e2, msg_to_poly(m)))
    return Ciphertext(u=u, v=v)


def decrypt(sk: SecretKey, ct: Ciphertext) -> int:
    m_poly = poly_sub(ct.v, vec_dot(sk.s, ct.u))
    return poly_to_msg(m_poly)
```

### Step 4: Compression + bit-packing (toy serialization)

Real ML-KEM uses compression and packing to keep ciphertexts small. We implement coefficient rounding and a tiny “pack `d`-bit integers into bytes” helper.

```python
def compress_coeff(x: int, d: int, q: int = Q) -> int:
    if d <= 0 or d > 12:
        raise ValueError("d must be in 1..12 for this demo")
    x = x % q
    t = ((x << d) + (q // 2)) // q
    return t & ((1 << d) - 1)


def decompress_coeff(t: int, d: int, q: int = Q) -> int:
    if d <= 0 or d > 12:
        raise ValueError("d must be in 1..12 for this demo")
    t &= (1 << d) - 1
    return ((t * q) + (1 << (d - 1))) >> d


def compress_poly(p: Sequence[int], d: int, q: int = Q) -> List[int]:
    if len(p) != N:
        raise ValueError(f"poly must have length {N}")
    return [compress_coeff(c, d=d, q=q) for c in p]


def decompress_poly(p: Sequence[int], d: int, q: int = Q) -> Poly:
    if len(p) != N:
        raise ValueError(f"poly must have length {N}")
    return [decompress_coeff(int(t), d=d, q=q) for t in p]


def pack_bits_le(values: Sequence[int], bits: int) -> bytes:
    if bits <= 0 or bits > 16:
        raise ValueError("bits must be in 1..16")
    mask = (1 << bits) - 1
    acc = 0
    acc_bits = 0
    out = bytearray()
    for v in values:
        v &= mask
        acc |= v << acc_bits
        acc_bits += bits
        while acc_bits >= 8:
            out.append(acc & 0xFF)
            acc >>= 8
            acc_bits -= 8
    if acc_bits:
        out.append(acc & 0xFF)
    return bytes(out)


def unpack_bits_le(data: bytes, count: int, bits: int) -> List[int]:
    if count < 0:
        raise ValueError("count must be >= 0")
    if bits <= 0 or bits > 16:
        raise ValueError("bits must be in 1..16")
    mask = (1 << bits) - 1
    acc = 0
    acc_bits = 0
    out: List[int] = []
    it = iter(data)
    while len(out) < count:
        while acc_bits < bits:
            try:
                b = next(it)
            except StopIteration as e:
                raise ValueError("not enough bytes to unpack") from e
            acc |= b << acc_bits
            acc_bits += 8
        out.append(acc & mask)
        acc >>= bits
        acc_bits -= bits
    return out
```

Run it:
`python3 code/main.py`

## Use It

Production ML-KEM implementations handle exact sampling, compression, serialization formats, and constant-time behavior.

- **NIST ML-KEM (Kyber)**: follow FIPS 203 for algorithms, parameter sets, and encoding details.
- **liboqs**: a C library that exposes a stable KEM API (ML-KEM among other PQC).
- **Rust / Go / Java bindings**: use well-audited, maintained libraries for your stack; treat serialization formats as part of the spec, not “implementation detail.”

## Pitfalls

- **IND-CPA vs IND-CCA**: the “raw PKE” structure here is *not* a full KEM; real ML-KEM applies a transform to get chosen-ciphertext security.
- **Missing domain separation**: if you reuse seeds across “A sampling” and “noise sampling” without strict domains/nonces, you can create correlations that break proofs.
- **Bad randomness plumbing**: deterministic demos are for tests; real code must use OS randomness and handle failure states.
- **Compression mismatch**: one off-by-one in rounding or bit order can make decryption fail (or worse: fail open).
- **Side channels**: constant-time isn’t optional in production PQC; “works on my machine” is not a security argument.

## Ship It

Save and reuse the review checklist in `outputs/prompt-mini-kyber-review.md` when you:

- review a PQ KEM integration PR
- sanity-check ciphertext/PK serialization code paths
- audit randomness usage and domain separation

It’s meant to be pasted into an LLM, a PR description, or a security review doc.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe how `(u, v)` changes while `decrypt(encrypt(m)) == m`.
2. Medium. Change `ETA` (noise size) and rerun. Find the smallest `ETA` where decryption starts failing for some messages.
3. Hard. Replace this toy PKE with a real ML-KEM library in a separate script and write a “wire format” test that roundtrips `pk`/`ct` bytes exactly.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| `R_q` | “polynomials mod q” | The quotient ring `Z_q[x]/(x^N+1)` with negacyclic wrap-around |
| Module-LWE | “LWE but faster” | LWE where secrets/noise are vectors of ring elements (structure enables speed) |
| CBD noise | “small random errors” | Coefficients sampled from a small symmetric distribution (here: centered binomial) |
| Compression | “just packing” | Lossy rounding that *must* preserve decoding margins |
| IND-CCA KEM | “Kyber is secure” | Security goal requiring protection against chosen-ciphertext attacks (not provided by raw PKE) |

## Further Reading

- NIST, *FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard* (2024) — the ML-KEM standard (Kyber).
- Bos et al., *CRYSTALS-Kyber* (spec / round submissions) — design notes and parameter tradeoffs.
- Regev, *On Lattices, Learning with Errors, Random Linear Codes, and Cryptography* (2005) — where LWE enters crypto.
