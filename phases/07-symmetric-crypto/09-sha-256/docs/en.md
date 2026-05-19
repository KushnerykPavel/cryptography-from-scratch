# SHA-256 from Scratch
> 64-byte blocks + 32-bit words + 64 rounds → one 256-bit digest.

**Type:** Build
**Languages:** Python
**Prerequisites:** `07-symmetric-crypto/06-block-cipher-modes`
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** what a hash function guarantees (and what it doesn’t).
- **Compute** SHA-256 padding for a given message length.
- **Implement** SHA-256 (padding, message schedule, compression, digest) from scratch.
- **Distinguish** hashing from MACs and why `hash(key || msg)` is not HMAC.
- **Apply** SHA-256 safely in real APIs (bytes vs hex, domain separation, avoid footguns).

## The Problem
You’re building an API and you need a compact fingerprint of “some bytes” that you can store, transmit, or compare. You might want to verify a download, identify content (git-like), or commit to a message before revealing it. You reach for SHA-256 because “it’s everywhere”.

If you treat SHA-256 as a magical checksum, you’ll ship subtle failures: hashing a Unicode string inconsistently (different encodings), comparing digests incorrectly, or (worst) trying to build authentication with `sha256(secret || message)` and thinking it’s a MAC.

This lesson makes SHA-256 concrete: what happens to your message (padding), how 512-bit blocks turn into a 256-bit digest (compression), and which real-world mistakes SHA-256 can’t protect you from.

## The Concept
SHA-256 is a Merkle–Damgård hash:

- It processes the message in **512-bit blocks** (64 bytes).
- It maintains an internal **chaining value** `H` (8 × 32-bit words = 256 bits).
- Each block runs a **compression function**: `H <- Compress(H, block)`.
- The final `H` is the digest.

High-level shape:

```
M ──pad──▶ blocks B0, B1, ... ──▶ Compress ──▶ digest
             H0 ───────────────▶ H1 ────────▶ ...
```

Two details matter a lot in practice:

1. **Padding includes the message length (in bits).** That makes the input unambiguous.
2. **Merkle–Damgård has structure.** If you misuse a plain hash as a MAC, you can get length-extension vulnerabilities.

Inside each block, SHA-256 uses 32-bit word operations:

- rotations (`ROTR`)
- shifts (`>>`)
- boolean mixing (`Ch`, `Maj`)
- two “big” mixing functions (`Σ0`, `Σ1`)
- two “small” mixing functions (`σ0`, `σ1`)

Those feed 64 rounds driven by fixed constants `K[0..63]` and a message schedule `W[0..63]`.

## Build It

### Step 1: 32-bit word operations
SHA-256 is defined over 32-bit words. In Python, integers are unbounded, so we must explicitly mask back down to 32 bits after additions/rotations.

```python
def _u32(x: int) -> int:
    return x & 0xFFFFFFFF


def rotr32(x: int, n: int) -> int:
    if not (0 <= n <= 31):
        raise ValueError("n must be in [0, 31]")
    x = _u32(x)
    return _u32((x >> n) | (x << (32 - n)))


def _ch(x: int, y: int, z: int) -> int:
    return (x & y) ^ (~x & z)


def _maj(x: int, y: int, z: int) -> int:
    return (x & y) ^ (x & z) ^ (y & z)


def _Sigma0(x: int) -> int:
    return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22)


def _Sigma1(x: int) -> int:
    return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25)


def _sigma0(x: int) -> int:
    return rotr32(x, 7) ^ rotr32(x, 18) ^ (_u32(x) >> 3)


def _sigma1(x: int) -> int:
    return rotr32(x, 17) ^ rotr32(x, 19) ^ (_u32(x) >> 10)
```

### Step 2: Merkle–Damgård padding (SHA-256 flavor)
SHA-256 pads the message so its total length is a multiple of 64 bytes, with the last 8 bytes storing the original message length in bits.

```python
def sha256_padding(message_len_bytes: int) -> bytes:
    if message_len_bytes < 0:
        raise ValueError("message_len_bytes must be non-negative")

    bit_len = message_len_bytes * 8
    if bit_len >= 1 << 64:
        raise ValueError("message too long for SHA-256 length field")

    pad = bytearray()
    pad.append(0x80)
    while ((message_len_bytes + len(pad)) % 64) != 56:
        pad.append(0)
    pad.extend(bit_len.to_bytes(8, "big"))
    return bytes(pad)


def _iter_chunks(data: bytes, chunk_size: int) -> Iterable[bytes]:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    for i in range(0, len(data), chunk_size):
        yield data[i : i + chunk_size]
```

### Step 3: Compression function (64 rounds)
Each 64-byte chunk expands into 64 32-bit words `W[0..63]`, then runs 64 rounds mixing the working state `(a..h)` and constants `K[0..63]`.

```python
def _sha256_compress(h: List[int], chunk: bytes) -> None:
    if len(chunk) != 64:
        raise ValueError("chunk must be 64 bytes")

    w = [0] * 64
    for i in range(16):
        w[i] = int.from_bytes(chunk[i * 4 : (i + 1) * 4], "big")
    for i in range(16, 64):
        w[i] = _u32(_sigma1(w[i - 2]) + w[i - 7] + _sigma0(w[i - 15]) + w[i - 16])

    a, b, c, d, e, f, g, hh = h

    for i in range(64):
        t1 = _u32(hh + _Sigma1(e) + _ch(e, f, g) + _K[i] + w[i])
        t2 = _u32(_Sigma0(a) + _maj(a, b, c))
        hh = g
        g = f
        f = e
        e = _u32(d + t1)
        d = c
        c = b
        b = a
        a = _u32(t1 + t2)

    h[0] = _u32(h[0] + a)
    h[1] = _u32(h[1] + b)
    h[2] = _u32(h[2] + c)
    h[3] = _u32(h[3] + d)
    h[4] = _u32(h[4] + e)
    h[5] = _u32(h[5] + f)
    h[6] = _u32(h[6] + g)
    h[7] = _u32(h[7] + hh)
```

### Step 4: One-shot hashing + streaming API
Now we can build a complete hash function (one-shot), and a small streaming wrapper that behaves like `hashlib.sha256` (update/digest/hexdigest).

```python
def sha256(message: bytes) -> bytes:
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("message must be bytes-like")

    data = bytes(message)
    data += sha256_padding(len(data))

    h = _IV[:]
    for chunk in _iter_chunks(data, 64):
        _sha256_compress(h, chunk)

    return b"".join(x.to_bytes(4, "big") for x in h)


def sha256_hex(message: bytes) -> str:
    return sha256(message).hex()


@dataclass
class SHA256:
    _h: List[int]
    _total_len: int
    _buf: bytes

    def __init__(self, data: bytes = b""):
        self._h = _IV[:]
        self._total_len = 0
        self._buf = b""
        if data:
            self.update(data)

    def copy(self) -> "SHA256":
        clone = SHA256()
        clone._h = self._h[:]
        clone._total_len = self._total_len
        clone._buf = self._buf
        return clone

    def update(self, data: bytes) -> None:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be bytes-like")

        if not data:
            return

        self._total_len += len(data)
        data_bytes = self._buf + bytes(data)

        full_len = (len(data_bytes) // 64) * 64
        for chunk in _iter_chunks(data_bytes[:full_len], 64):
            _sha256_compress(self._h, chunk)
        self._buf = data_bytes[full_len:]

    def digest(self) -> bytes:
        clone = self.copy()
        clone.update(sha256_padding(clone._total_len))
        if clone._buf:
            raise AssertionError("buffer must be empty after final padding")
        return b"".join(x.to_bytes(4, "big") for x in clone._h)

    def hexdigest(self) -> str:
        return self.digest().hex()
```

Run it:
python3 code/main.py

## Use It
In production, use audited implementations:

- Python: `hashlib.sha256(data).digest()` / `.hexdigest()`
- OpenSSL CLI: `openssl dgst -sha256 <file>`
- libsodium: `crypto_hash_sha256` (when you *really* need SHA-256 specifically)

Typical uses:

- content fingerprints (dedupe, caching keys)
- verifying downloads / artifacts (integrity when the expected digest comes from a trusted channel)
- building blocks inside higher-level schemes (HMAC, HKDF, signatures, Merkle trees)

## Pitfalls
- **Hashing is not authentication.** `sha256(secret || msg)` is not a MAC; use HMAC (next lesson) or an AEAD.
- **Length extension.** Merkle–Damgård hashes (including SHA-256) are vulnerable when misused as a MAC or in certain “token = hash(secret || msg)” designs.
- **String/bytes confusion.** Decide one canonical encoding (`UTF-8`) and hash bytes, not “whatever Python prints”.
- **Hex vs bytes mix-ups.** A 32-byte digest is 64 hex chars; don’t double-encode (hashing hex text instead of bytes).
- **Comparing digests unsafely.** When hashes are used as secrets (e.g., API tokens), compare in constant time (stdlib: `hmac.compare_digest`).

## Ship It
Save `outputs/prompt-sha-256-review-checklist.md` and use it as a PR review checklist whenever you see hashing in real code (passwords, tokens, “signed links”, integrity checks, or “MAC-like” constructs).

## Exercises
1. Easy. Run `python3 code/main.py`. Observe that the streaming API matches `hashlib.sha256`.
2. Medium. Extend `main()` to hash a 1 MiB message in 1-byte chunks and confirm it still matches `hashlib`.
3. Hard. Find (or write) a piece of code that uses `sha256(secret || msg)` as an “auth token”. Replace it with HMAC and add a test that would have caught the bug.

## Key Terms
| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Hash function | “Checksum” | A deterministic function mapping any-length input to fixed-length output with preimage/second-preimage/collision resistance goals. |
| Merkle–Damgård | “Iterate a compressor” | A construction that hashes blocks by chaining a compression function; has structural properties (e.g., length extension) if misused. |
| Compression function | “The hash round” | The fixed-size function that updates the chaining value for one block. |
| Digest | “The hash” | The final fixed-length output (for SHA-256, 32 bytes). |
| Length extension | “You can append without the key” | Given `H(m)` and `len(m)`, an attacker can compute `H(m || pad(m) || x)` for chosen `x` for Merkle–Damgård hashes. |

## Further Reading
- NIST, *FIPS 180-4: Secure Hash Standard* (2015) — the SHA-2 specification (padding, constants, and full pseudocode).
- IETF, *RFC 6234: US Secure Hash Algorithms (SHA and SHA-based HMAC and HKDF)* (2011) — test vectors and interoperability guidance.
- Jean-Philippe Aumasson, *Serious Cryptography* (2017) — practical guidance on using hashes, MACs, and KDFs safely.
