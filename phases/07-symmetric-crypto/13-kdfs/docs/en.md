# KDFs — HKDF, PBKDF2, Argon2, scrypt
> Derive *many* safe keys from *one* secret — and never treat passwords like keys.

**Type:** Build
**Languages:** Python
**Prerequisites:** `07-symmetric-crypto/09-sha-256`, `07-symmetric-crypto/12-hmac`
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** why key separation matters even with “one master key”
- **Compute** HKDF Extract/Expand outputs for a given `(salt, ikm, info, L)`
- **Implement** HKDF-SHA256 and PBKDF2-HMAC-SHA256 from scratch
- **Distinguish** secret-input KDFs (HKDF) vs password KDFs (PBKDF2/scrypt/Argon2)
- **Apply** a review checklist to pick KDF parameters and avoid footguns

## The Problem

You ship a system that needs multiple keys: one for encryption, one for MACs, one for nonces, one for “token signing”, one for key wrapping, and so on. The tempting shortcut is to reuse the same key everywhere or to “just hash the master key a few times.” That’s how you end up with brittle designs where one compromise cascades into everything, or where two protocol contexts accidentally share a key.

Passwords make this worse. A password is not a key: it’s low-entropy and guessable. If you feed a password directly into AES/HMAC, you’re giving attackers a fast offline guessing oracle. You need a password KDF with a work factor (and ideally memory hardness) so guessing becomes expensive.

KDFs solve both problems:
- **HKDF** safely derives many independent subkeys from a high-entropy secret.
- **PBKDF2 / scrypt / Argon2** turn a password into a key *slowly* (and with memory costs for the modern choices).

## The Concept

Think in terms of two categories:

| What you start with | Typical source | What you want | Use | KDF family |
|---|---|---|---|---|
| **High-entropy secret** | ECDH shared secret, random seed, master key | many subkeys | key separation, protocol contexts | **HKDF** |
| **Low-entropy password** | user password, passphrase | one key (+ verifier) | password hashing / encryption keys | **PBKDF2 / scrypt / Argon2** |

### HKDF mental model (Extract then Expand)

HKDF is two steps:

1. **Extract:** turn your input secret `IKM` into a fixed-size pseudorandom key `PRK`
   - `PRK = HMAC(salt, IKM)`
2. **Expand:** generate output keying material `OKM` of any length `L`
   - `T(1) = HMAC(PRK, T(0) || info || 0x01)`, with `T(0)=empty`
   - `T(2) = HMAC(PRK, T(1) || info || 0x02)`
   - `OKM = T(1) || T(2) || ...` (truncate to `L`)

The `info` string is how you enforce **domain separation**: different contexts (e.g., `"enc"`, `"mac"`, `"nonces"`, `"handshake v2"`) produce unrelated keys.

### Password KDF mental model (make guessing expensive)

Password KDFs exist because attackers can guess passwords offline. Your goal is to make each guess:
- CPU-expensive (**PBKDF2**: many HMAC rounds)
- and ideally memory-expensive (**scrypt / Argon2**: large RAM requirements)

Key variables:
- `salt`: unique per password (prevents rainbow tables and makes hashes non-reusable)
- `work factor`: iterations / memory / parallelism
- encoding: always define bytes vs text (UTF-8) explicitly

## Build It

### Step 1: HKDF Extract (PRK)
```python
def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def hkdf_extract_sha256(salt: bytes, ikm: bytes) -> bytes:
    if salt == b"":
        salt = b"\x00" * hashlib.sha256().digest_size
    return hmac_sha256(salt, ikm)
```
Extract turns a possibly-variable-length secret input (`ikm`) into a fixed-size pseudorandom key (`prk`). A non-empty random `salt` is strongly recommended; it “randomizes” extraction and gives you defense-in-depth across contexts.

### Step 2: HKDF Expand + Key Separation
```python
def hkdf_expand_sha256(prk: bytes, info: bytes, length: int) -> bytes:
    if length < 0:
        raise ValueError("length must be >= 0")
    hash_len = hashlib.sha256().digest_size
    if length > 255 * hash_len:
        raise ValueError("length too large for HKDF (max 255*HashLen)")
    if length == 0:
        return b""

    okm = bytearray()
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac_sha256(prk, t + info + bytes([counter]))
        okm.extend(t)
        counter += 1
    return bytes(okm[:length])


def hkdf_sha256(ikm: bytes, length: int, salt: bytes = b"", info: bytes = b"") -> bytes:
    prk = hkdf_extract_sha256(salt=salt, ikm=ikm)
    return hkdf_expand_sha256(prk=prk, info=info, length=length)


@dataclass(frozen=True)
class DerivedKeys:
    enc_key: bytes
    mac_key: bytes
    nonce_key: bytes


def derive_subkeys_hkdf(master_secret: bytes, salt: bytes, context: bytes) -> DerivedKeys:
    info = b"cfs:kdf:v1:" + context
    okm = hkdf_sha256(master_secret, length=32 + 32 + 12, salt=salt, info=info)
    enc_key = okm[:32]
    mac_key = okm[32:64]
    nonce_key = okm[64:76]
    return DerivedKeys(enc_key=enc_key, mac_key=mac_key, nonce_key=nonce_key)
```
Expand is where you “name” what a key is used for. The same `master_secret` can safely produce unrelated keys as long as you commit to unique `info`/`context` values per use.

### Step 3: PBKDF2-HMAC-SHA256 (password -> key)
```python
def pbkdf2_hmac_sha256(password: bytes, salt: bytes, iterations: int, dklen: int) -> bytes:
    if iterations <= 0:
        raise ValueError("iterations must be >= 1")
    if dklen <= 0:
        raise ValueError("dklen must be >= 1")
    hlen = hashlib.sha256().digest_size

    def prf(msg: bytes) -> bytes:
        return hmac_sha256(password, msg)

    blocks = (dklen + hlen - 1) // hlen
    out = bytearray()
    for block_index in range(1, blocks + 1):
        u = prf(salt + block_index.to_bytes(4, "big"))
        t = bytearray(u)
        for _ in range(2, iterations + 1):
            u = prf(u)
            for i in range(hlen):
                t[i] ^= u[i]
        out.extend(t)
    return bytes(out[:dklen])
```
PBKDF2 makes password guessing slower by repeating a PRF (here: HMAC-SHA256) many times. It’s still widely deployed, but it’s **not memory-hard**, so modern GPUs/ASICs can brute-force it faster than scrypt/Argon2 for the same “user-visible” latency.

### Step 4: scrypt (memory-hard password KDF)
```python
def _is_power_of_two(n: int) -> bool:
    return n > 0 and (n & (n - 1) == 0)


def scrypt_kdf(
    password: bytes,
    salt: bytes,
    *,
    n: int,
    r: int,
    p: int,
    dklen: int,
    maxmem: int = 0,
) -> bytes:
    if n <= 1 or not _is_power_of_two(n):
        raise ValueError("n must be a power of two > 1")
    if r <= 0 or p <= 0:
        raise ValueError("r and p must be >= 1")
    if dklen <= 0:
        raise ValueError("dklen must be >= 1")
    return hashlib.scrypt(password, salt=salt, n=n, r=r, p=p, dklen=dklen, maxmem=maxmem)
```
scrypt increases the cost of each password guess by requiring significant memory, not just CPU. That makes large-scale brute-force attacks harder to accelerate on specialized hardware.

Run it:
python3 code/main.py

## Use It

Production equivalents (prefer these over handwritten crypto):

- **Python `cryptography`**: `HKDF(...)`, `PBKDF2HMAC(...)`, `Scrypt(...)`
- **libsodium**: `crypto_kdf_*` for subkeys; `crypto_pwhash_argon2id*` for passwords
- **OpenSSL**: `EVP_KDF` for HKDF/PBKDF2/scrypt (API depends on version)
- **Argon2 (recommended for passwords)**: `argon2id` via libsodium or `argon2-cffi`

Rule of thumb:
- Deriving subkeys from a shared secret / master key: **HKDF**
- Storing/verifying passwords or deriving keys from passwords: **Argon2id** (or **scrypt**; PBKDF2 for legacy compatibility)

## Pitfalls

- **Using HKDF on passwords**: HKDF is fast; it does not slow down guessing.
- **Reusing `info`/context labels**: if two parts of a system derive keys with identical `info`, they silently share key material.
- **Confusing `salt` roles**: HKDF salt is not the same as a password salt; PBKDF2/scrypt salts must be unique per password and stored alongside the hash.
- **Too-small work factors**: PBKDF2 iterations or scrypt/Argon2 memory set too low becomes “fast hashing”.
- **Encoding bugs**: `"pässwörd"` as UTF-8 bytes is not the same as a platform-default encoding; always define encoding explicitly.

## Ship It

This lesson ships a reusable PR-review artifact: a KDF decision guide + audit checklist.

- Open `outputs/kdf-review-checklist.md`
- Use it when reviewing any code that derives keys, hashes passwords, or uses “master secrets”
- Paste the checklist into a PR and force explicit answers on salts, contexts, and parameters

## Exercises

1. Easy. Run `python3 code/main.py`. Observe that HKDF produces different subkeys when `context` changes.
2. Medium. Extend `derive_subkeys_hkdf()` to also derive a 32-byte `wrap_key` and a 32-byte `export_key` and print them in `main()`.
3. Hard. Use `cryptography.hazmat.primitives.kdf` to compute HKDF and scrypt outputs and cross-check against `tests/vectors.json`.

## Key Terms

| Term | What people say | What it actually means |
|---|---|---|
| KDF | “a hash” | A construction that transforms secret inputs into safe key material for specific uses |
| Key separation | “different keys” | Deriving independent subkeys per context so compromise doesn’t cascade |
| Salt | “random bytes” | Public uniqueness/randomness that defeats precomputation and binds derivations to an instance |
| Info / context | “metadata” | Domain-separation label that makes HKDF outputs independent across uses |
| Work factor | “iterations/memory” | Tunable cost per password guess (CPU and/or RAM) |

## Further Reading

- IETF, *HMAC-based Extract-and-Expand Key Derivation Function (HKDF)* (RFC 5869) — HKDF definition and test vectors.
- IETF, *PKCS #5: Password-Based Cryptography Specification Version 2.1* (RFC 8018) — PBKDF2 specification.
- IETF, *The scrypt Password-Based Key Derivation Function* (RFC 7914) — memory-hard KDF and test vectors.
- IETF, *Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications* (RFC 9106) — Argon2id guidance.
