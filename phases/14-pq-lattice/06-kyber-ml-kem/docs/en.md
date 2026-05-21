# Kyber / ML-KEM from Scratch
> Noisy linear algebra + hashing → a shared key (and no decryption oracle).

**Type:** Build  
**Languages:** Python  
**Prerequisites:** `phases/14-pq-lattice/04-regev-encryption/`, `phases/14-pq-lattice/05-dual-regev-trapdoors/`  
**Time:** ~120 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain why ML-KEM is a *KEM* (not a general PKE)  
- Distinguish IND-CPA PKE from IND-CCA KEM (and why FO matters)  
- Implement Kyber-style bit packing and coefficient compression  
- Compute module-LWE encryption/decryption in the ring `R_q = Z_q[X]/(X^N + 1)`  
- Apply the FO-style re-encryption check (implicit rejection) in decapsulation

## The Problem
You want two parties to agree on a fresh 32-byte session key over an untrusted network (like a TLS handshake), but you can’t rely on RSA or elliptic-curve Diffie–Hellman staying safe in a world with large quantum computers.

Lattice KEMs like Kyber / ML-KEM solve this, but they come with new engineering constraints: big keys/ciphertexts, error/noise that must stay within bounds, lossy compression that must still decrypt correctly, and strict “don’t leak validity” rules during decapsulation.

If you treat the underlying public-key encryption (PKE) as a drop-in “encrypt any message” primitive, or if you skip the CCA transform details, you can ship something that *works in tests* but is insecure under chosen-ciphertext attacks or side-channel observation.

## The Concept
ML-KEM (standardized as NIST FIPS 203) is built from:

1. **A ring of polynomials**  
   Work in `R_q = Z_q[X]/(X^N + 1)` with fixed `N=256` and `q=3329`. Each polynomial is a vector of 256 coefficients modulo `q`.

2. **Module-LWE “noisy linear equations”**  
   Generate a public matrix `A` and small secret/noise polynomials `s,e`. Publish `t = A·s + e`. The hardness assumption: recovering `s` from `(A,t)` is hard.

3. **IND-CPA PKE (K-PKE)**  
   Encrypt a 32-byte message `m` by embedding its bits into a polynomial (coefficients `0` or about `q/2`) and masking it with noisy products like `A^T·r + e1` and `t^T·r + e2`.

4. **IND-CCA KEM (ML-KEM) via an FO-style transform**  
   Encapsulation picks an internal `m`, hashes it with the public key to derive coins, encrypts `m` deterministically, and derives the shared secret by hashing.  
   Decapsulation decrypts to `m'`, re-encrypts to check the ciphertext, and if the check fails returns a pseudorandom-looking key derived from a secret `z` (**implicit rejection**). This avoids giving attackers a decryption-validity oracle.

The key engineering trick: **compression + bit packing**. Coefficients live modulo `q` (12 bits), but ciphertext components are compressed to `d_u` and `d_v` bits per coefficient to keep ciphertexts small.

## Build It

### Step 1: Pack bits + Compress coefficients
This is the “plumbing” that makes Kyber sizes work: pack `d`-bit integers into bytes and compress coefficients modulo `q` down to `d` bits (and back).

```python
def pack_bits(values: list[int], bits: int) -> bytes:
    if bits <= 0:
        raise ValueError("bits must be positive")
    mask = (1 << bits) - 1
    acc = 0
    acc_bits = 0
    out = bytearray()
    for v in values:
        if v < 0 or v > mask:
            raise ValueError("value out of range for packing")
        acc |= (v & mask) << acc_bits
        acc_bits += bits
        while acc_bits >= 8:
            out.append(acc & 0xFF)
            acc >>= 8
            acc_bits -= 8
    if acc_bits:
        out.append(acc & 0xFF)
    return bytes(out)


def unpack_bits(data: bytes, bits: int, count: int) -> list[int]:
    if bits <= 0:
        raise ValueError("bits must be positive")
    if count < 0:
        raise ValueError("count must be non-negative")
    mask = (1 << bits) - 1
    acc = 0
    acc_bits = 0
    pos = 0
    out: list[int] = []
    for _ in range(count):
        while acc_bits < bits:
            if pos >= len(data):
                raise ValueError("not enough bytes to unpack requested count")
            acc |= data[pos] << acc_bits
            acc_bits += 8
            pos += 1
        out.append(acc & mask)
        acc >>= bits
        acc_bits -= bits
    return out


def compress_coeff(x: int, d: int) -> int:
    if not (1 <= d <= 12):
        raise ValueError("d must be in [1, 12]")
    x = x % Q
    return (((x << d) + Q // 2) // Q) & ((1 << d) - 1)


def decompress_coeff(y: int, d: int) -> int:
    if not (1 <= d <= 12):
        raise ValueError("d must be in [1, 12]")
    if y < 0 or y >= (1 << d):
        raise ValueError("compressed coefficient out of range")
    return ((y * Q) + (1 << (d - 1))) >> d
```

### Step 2: Sample A uniformly + Sample CBD noise
Kyber expands a 32-byte seed into a public matrix `A` using SHAKE (rejection sampling), and samples “small” secrets/noise from a centered binomial distribution (CBD).

```python
def _prf(seed: bytes, nonce: int, outlen: int) -> bytes:
    if len(seed) != SEED_BYTES:
        raise ValueError("seed must be 32 bytes")
    if not (0 <= nonce <= 255):
        raise ValueError("nonce must be a byte")
    return _shake256(seed + bytes([nonce]), outlen)


def sample_uniform_poly(rho: bytes, i: int, j: int) -> list[int]:
    if len(rho) != SEED_BYTES:
        raise ValueError("rho must be 32 bytes")
    if not (0 <= i <= 255 and 0 <= j <= 255):
        raise ValueError("indices must fit in a byte")
    buf = _shake128(rho + bytes([j, i]), 4096)
    coeffs: list[int] = []
    pos = 0
    while len(coeffs) < N:
        if pos + 3 > len(buf):
            raise RuntimeError("unexpected rejection-sampling shortfall")
        b0 = buf[pos]
        b1 = buf[pos + 1]
        b2 = buf[pos + 2]
        pos += 3
        d1 = b0 | ((b1 & 0x0F) << 8)
        d2 = (b1 >> 4) | (b2 << 4)
        if d1 < Q:
            coeffs.append(d1)
            if len(coeffs) == N:
                break
        if d2 < Q:
            coeffs.append(d2)
    return coeffs


def gen_matrix(rho: bytes, params: MlKemParams, transpose: bool) -> list[list[list[int]]]:
    A: list[list[list[int]]] = []
    for i in range(params.k):
        row: list[list[int]] = []
        for j in range(params.k):
            if transpose:
                row.append(sample_uniform_poly(rho, j, i))
            else:
                row.append(sample_uniform_poly(rho, i, j))
        A.append(row)
    return A


def sample_cbd_poly(seed: bytes, nonce: int, eta: int) -> list[int]:
    if eta <= 0:
        raise ValueError("eta must be positive")
    needed_bits = 2 * eta * N
    needed_bytes = (needed_bits + 7) // 8
    buf = _prf(seed, nonce, needed_bytes)
    bit_pos = 0
    out: list[int] = []
    for _ in range(N):
        a = 0
        b = 0
        for _ in range(eta):
            byte = buf[bit_pos >> 3]
            a += (byte >> (bit_pos & 7)) & 1
            bit_pos += 1
        for _ in range(eta):
            byte = buf[bit_pos >> 3]
            b += (byte >> (bit_pos & 7)) & 1
            bit_pos += 1
        out.append((a - b) % Q)
    return out
```

### Step 3: K-PKE (KeyGen / Encrypt / Decrypt)
This is the IND-CPA public-key encryption scheme inside ML-KEM: it encrypts exactly 32 bytes by embedding bits into a polynomial and adding noise.

```python
def kpke_keygen(seed_d: bytes, params: MlKemParams) -> tuple[bytes, bytes]:
    if len(seed_d) != SEED_BYTES:
        raise ValueError("seed_d must be 32 bytes")
    rho_sigma = _sha3_512(seed_d)
    rho = rho_sigma[:SEED_BYTES]
    sigma = rho_sigma[SEED_BYTES:]

    A = gen_matrix(rho, params, transpose=False)
    s = [sample_cbd_poly(sigma, nonce=i, eta=params.eta1) for i in range(params.k)]
    e = [sample_cbd_poly(sigma, nonce=params.k + i, eta=params.eta1) for i in range(params.k)]
    t = polyvec_add(mat_vec_mul(A, s, params), e, params)

    pk = polyvec_to_bytes(t, params) + rho
    sk = polyvec_to_bytes(s, params)
    return pk, sk


def kpke_encrypt(pk: bytes, m: bytes, coins: bytes, params: MlKemParams) -> bytes:
    if len(pk) != (12 * params.k * N) // 8 + SEED_BYTES:
        raise ValueError("bad public key length")
    if len(coins) != SEED_BYTES:
        raise ValueError("coins must be 32 bytes")
    t = polyvec_from_bytes(pk[: (12 * params.k * N) // 8], params)
    rho = pk[(12 * params.k * N) // 8 :]

    A_t = gen_matrix(rho, params, transpose=True)
    r = [sample_cbd_poly(coins, nonce=i, eta=params.eta1) for i in range(params.k)]
    e1 = [sample_cbd_poly(coins, nonce=params.k + i, eta=params.eta2) for i in range(params.k)]
    e2 = sample_cbd_poly(coins, nonce=2 * params.k, eta=params.eta2)

    u = polyvec_add(mat_vec_mul(A_t, r, params), e1, params)
    v = poly_add(vec_dot(t, r, params), poly_add(e2, msg_to_poly(m)))

    c1 = polyvec_compress_to_bytes(u, params.du, params)
    c2 = poly_compress_to_bytes(v, params.dv)
    return c1 + c2


def kpke_decrypt(sk: bytes, ct: bytes, params: MlKemParams) -> bytes:
    sk_len = (12 * params.k * N) // 8
    if len(sk) != sk_len:
        raise ValueError("bad secret key length")
    c1_len = (params.du * params.k * N) // 8
    c2_len = (params.dv * N) // 8
    if len(ct) != c1_len + c2_len:
        raise ValueError("bad ciphertext length")

    s = polyvec_from_bytes(sk, params)
    u = polyvec_decompress_from_bytes(ct[:c1_len], params.du, params)
    v = poly_decompress_from_bytes(ct[c1_len:], params.dv)

    w = poly_sub(v, vec_dot(s, u, params))
    return poly_to_msg(w)
```

### Step 4: ML-KEM (KeyGen / Encaps / Decaps)
ML-KEM wraps K-PKE with an FO-style transform: encryption becomes deterministic from `m` and `H(pk)`, and decapsulation does a re-encryption check (implicit rejection) to avoid returning a “valid/invalid” oracle.

```python
def ml_kem_keygen(seed: bytes | None, params: MlKemParams) -> tuple[bytes, bytes]:
    if seed is None:
        seed = os.urandom(KEM_SEED_BYTES)
    if len(seed) != KEM_SEED_BYTES:
        raise ValueError("seed must be 64 bytes")
    d = seed[:SEED_BYTES]
    z = seed[SEED_BYTES:]
    ek, dk_pke = kpke_keygen(d, params)
    dk = dk_pke + ek + _sha3_256(ek) + z
    return ek, dk


def ml_kem_encaps(ek: bytes, seed: bytes | None, params: MlKemParams) -> tuple[bytes, bytes]:
    if len(ek) != (12 * params.k * N) // 8 + SEED_BYTES:
        raise ValueError("bad encapsulation key length")
    if seed is None:
        seed = os.urandom(SEED_BYTES)
    if len(seed) != SEED_BYTES:
        raise ValueError("encapsulation seed must be 32 bytes")

    m = _sha3_256(seed)
    k_r = _sha3_512(m + _sha3_256(ek))
    k_bar = k_r[:SEED_BYTES]
    coins = k_r[SEED_BYTES:]
    ct = kpke_encrypt(ek, m, coins, params)
    ss = _shake256(k_bar + _sha3_256(ct), SHARED_SECRET_BYTES)
    return ct, ss


def ml_kem_decaps(dk: bytes, ct: bytes, params: MlKemParams) -> bytes:
    dk_pke_len = (12 * params.k * N) // 8
    ek_len = (12 * params.k * N) // 8 + SEED_BYTES
    expected_dk_len = dk_pke_len + ek_len + 32 + 32
    if len(dk) != expected_dk_len:
        raise ValueError("bad decapsulation key length")

    dk_pke = dk[:dk_pke_len]
    ek = dk[dk_pke_len : dk_pke_len + ek_len]
    z = dk[-SEED_BYTES:]

    m = kpke_decrypt(dk_pke, ct, params)
    k_r = _sha3_512(m + _sha3_256(ek))
    k_bar = k_r[:SEED_BYTES]
    coins = k_r[SEED_BYTES:]

    ct_check = kpke_encrypt(ek, m, coins, params)
    if ct_check == ct:
        key = k_bar
    else:
        key = z
    return _shake256(key + _sha3_256(ct), SHARED_SECRET_BYTES)
```

Run it:

```bash
python3 code/main.py
```

## Use It
Real-world ML-KEM is something you *use*, not something you re-implement:

- OpenSSL: ML-KEM key types and KEM APIs (and hybrid TLS stacks via protocol implementations)
- liboqs / PQClean: widely used C reference/portable implementations, used by many projects as a baseline
- Language bindings/wrappers: Rust crates and Python packages that expose an ML-KEM API, often backed by PQClean or formally verified implementations

Rule of thumb: ship ML-KEM only through a well-reviewed implementation, and prefer hybrid key exchange (classical + PQ) where the ecosystem expects it (e.g., TLS deployments).

## Pitfalls
- Treating ML-KEM as “PKE for arbitrary messages”: ML-KEM establishes a shared secret; you then use an AEAD (AES-GCM/ChaCha20-Poly1305) for data.
- Skipping the **re-encryption check** in decapsulation: that turns your system into a chosen-ciphertext oracle.
- Getting bit packing/compression wrong: off-by-one in `ByteEncode/Decode` or `Compress/Decompress` breaks interoperability and can break correctness.
- Leaking secret-dependent timing: naive polynomial arithmetic, comparisons, and early exits can become side-channel signals.
- Forgetting input validation: accept-only correct lengths and reject malformed keys/ciphertexts early and consistently.

## Ship It
Save a reusable ML-KEM integration checklist to:

- `phases/14-pq-lattice/06-kyber-ml-kem/outputs/ml_kem_integration_checklist.md`

Use it when reviewing PRs that add ML-KEM to:
- TLS handshakes / hybrid KEM stacks
- session-key establishment for messaging protocols
- any service that stores or transports ML-KEM public keys/ciphertexts

## Exercises
1. Easy: Run `python3 code/main.py`. Observe that K-PKE decrypts back to the original 32-byte message, and ML-KEM encaps/decaps produces the same shared secret.
2. Medium: Add a function that prints a histogram of centered CBD coefficients for `eta=2` and `eta=3` (e.g., count `-3..3`), and compare the shapes.
3. Hard: Replace the final “shared secret” usage with a toy hybrid construction: derive two shared secrets (one “classical placeholder”, one ML-KEM), combine with `SHA3-256`, and explain in writing what hybrid is trying to achieve and what it *doesn’t* fix.

## Key Terms
| Term | What people say | What it actually means |
|------|------------------|------------------------|
| KEM | “public-key encryption” | A 3-function API: KeyGen/Encaps/Decaps to agree on a shared key |
| Module-LWE | “LWE but faster” | LWE-like equations over a module of polynomials; supports efficient multiplication |
| `R_q` | “a polynomial ring” | `Z_q[X]/(X^N+1)` where multiplication wraps with a sign flip |
| Compression | “drop bits” | Lossy scaling from mod-`q` to `d` bits per coefficient, reversible *enough* under noise bounds |
| FO transform | “CCA wrapper” | Turns CPA PKE into CCA KEM by deriving coins from hashes and checking re-encryption |
| Implicit rejection | “no ⊥ output” | On failure, derive a pseudorandom-looking shared key instead of returning an error |

## Further Reading
- NIST, *FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard* (2024) — the ML-KEM standard.
- CRYSTALS Team, *Kyber Specification* (v3.x) — background on the pre-standard Kyber design and parameter sets.
- “FO transform” notes and analyses — how re-encryption checks avoid chosen-ciphertext oracles, and what implementations must do to stay side-channel safe.
