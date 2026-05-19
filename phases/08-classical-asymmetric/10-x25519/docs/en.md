# X25519 (Curve25519 ECDH)
> Clamp a scalar, run the Montgomery ladder, then KDF the shared secret.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** `phases/03-elliptic-curves/04-montgomery-ladder`, `phases/03-elliptic-curves/06-montgomery-curve25519`, `phases/08-classical-asymmetric/04-diffie-hellman`  
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain what X25519 computes — and why it only uses the u-coordinate
- Compute an ECDH shared secret — from two X25519 key pairs
- Implement X25519 scalar multiplication — clamping + Montgomery ladder (RFC 7748)
- Distinguish shared-secret bytes from session keys — a KDF is not optional
- Apply a practical review checklist — encodings, all-zero check, KDF context, authentication

## The Problem

Modern secure channels need **forward secrecy**: if a server key leaks tomorrow, past recorded traffic should still be safe. Static RSA key transport can’t give you that. The standard fix is **ephemeral Diffie-Hellman**: each connection does a fresh key agreement, then derives symmetric keys.

In most real protocols (TLS 1.3, Noise, Signal-style handshakes), the default DH primitive is **X25519**. It’s fast, has a simple wire format (32 bytes), and is designed to be implemented in a constant-time style using a regular “ladder” of field operations.

But it’s also easy to misuse: the inputs are *little-endian bytes* (not big-endian integers), the output is *not a ready-to-use key*, and protocols often need an **all-zero shared-secret check** to avoid known edge cases with malicious public inputs. This lesson builds X25519 from scratch so you can reason about these details and review real integrations.

## The Concept

X25519 is a *function*, standardized in RFC 7748, that performs scalar multiplication on Curve25519 in Montgomery form:

- Field prime: `p = 2^255 - 19`
- Curve (Montgomery form): `v^2 = u^3 + 486662·u^2 + u (mod p)`
- Base point u-coordinate: `u = 9`, encoded as `09 00 00 ... 00` (32 bytes)

The API is intentionally narrow:

- Input scalar `k`: 32 bytes (little-endian), **clamped** by masking/setting specific bits
- Input point `u`: 32 bytes (little-endian), interpreted as a field element (reduced mod `p`)
- Output: 32 bytes encoding of the resulting **u-coordinate**

Two rules are easy to miss:

1. **Clamping (scalar decoding).** For X25519, you clear the 3 low bits of the first byte, clear the top bit of the last byte, and set the second-highest bit of the last byte. This forces `k` into a safe shape that avoids certain edge cases.
2. **All-zero check (protocol rule).** RFC 7748 notes that if you multiply by a small-order/invalid input point, X25519 can output the all-zero value. Many ECDH protocols *abort* if the shared secret is all-zero.

We’ll implement the RFC 7748 Montgomery ladder (u-coordinate-only arithmetic). It keeps two points in projective x/z form and performs one “double-and-add” ladder step per scalar bit.

## Build It

### Step 1: Clamp scalars + decode/encode u-coordinates

X25519 works on 32-byte strings, but the math is done on integers mod `p`. This step defines the exact byte↔integer conversions from RFC 7748:

- Scalars are clamped, then decoded as little-endian integers.
- u-coordinates mask the unused top bit on decode, and outputs ensure that bit is zero.

```python
X25519_P = 2**255 - 19
X25519_A24 = 121665
X25519_BASEPOINT_U = 9
X25519_BASEPOINT_BYTES = bytes([X25519_BASEPOINT_U] + [0] * 31)


def clamp_scalar(scalar: bytes) -> bytes:
    if len(scalar) != 32:
        raise ValueError("scalar must be 32 bytes")
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return bytes(k)


def decode_scalar_25519(scalar: bytes) -> int:
    return int.from_bytes(clamp_scalar(scalar), "little")


def decode_u_coordinate(u: bytes) -> int:
    if len(u) != 32:
        raise ValueError("u-coordinate must be 32 bytes")
    u_list = bytearray(u)
    u_list[31] &= 127
    return int.from_bytes(u_list, "little")


def encode_u_coordinate(u: int) -> bytes:
    if u < 0:
        raise ValueError("u-coordinate must be non-negative")
    out = (u % X25519_P).to_bytes(32, "little")
    out_list = bytearray(out)
    out_list[31] &= 127
    return bytes(out_list)
```

### Step 2: Conditional swap (cswap)

The Montgomery ladder uses a conditional swap to avoid secret-dependent branches in constant-time implementations. Python can’t promise constant-time behavior here, but we keep the structure so you can recognize the pattern in real code.

```python
def cswap(swap: int, a: int, b: int) -> tuple[int, int]:
    if swap & 1:
        return b, a
    return a, b
```

### Step 3: The Montgomery ladder (u-coordinate scalar multiplication)

This is the core: given an integer scalar `k` and a u-coordinate `u`, compute `[k]u` over Curve25519 using RFC 7748’s ladder formulas. Internally it tracks `(x2, z2)` and `(x3, z3)` in projective form and performs 255 ladder steps.

```python
def x25519_int(k: int, u: int) -> int:
    if k < 0:
        raise ValueError("scalar must be non-negative")
    if u < 0:
        raise ValueError("u-coordinate must be non-negative")

    x1 = u % X25519_P
    x2, z2 = 1, 0
    x3, z3 = x1, 1
    swap = 0

    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        x2, x3 = cswap(swap, x2, x3)
        z2, z3 = cswap(swap, z2, z3)
        swap = kt

        a = (x2 + z2) % X25519_P
        aa = (a * a) % X25519_P
        b = (x2 - z2) % X25519_P
        bb = (b * b) % X25519_P
        e = (aa - bb) % X25519_P
        c = (x3 + z3) % X25519_P
        d = (x3 - z3) % X25519_P
        da = (d * a) % X25519_P
        cb = (c * b) % X25519_P
        x3 = ((da + cb) % X25519_P) ** 2 % X25519_P
        z3 = (x1 * (((da - cb) % X25519_P) ** 2 % X25519_P)) % X25519_P
        x2 = (aa * bb) % X25519_P
        z2 = (e * ((aa + X25519_A24 * e) % X25519_P)) % X25519_P

    x2, x3 = cswap(swap, x2, x3)
    z2, z3 = cswap(swap, z2, z3)

    z2_inv = pow(z2, X25519_P - 2, X25519_P)
    return (x2 * z2_inv) % X25519_P
```

### Step 4: Byte-level API + ECDH + all-zero check + HKDF

Now we wrap the integer ladder in the RFC 7748 byte API, compute public keys using the fixed base point, and implement a safe ECDH helper that rejects the all-zero output. Finally, we derive a session key with HKDF-SHA256 (stdlib-only).

```python
def x25519(scalar: bytes, u_coordinate: bytes) -> bytes:
    k = decode_scalar_25519(scalar)
    u = decode_u_coordinate(u_coordinate)
    return encode_u_coordinate(x25519_int(k, u))


def x25519_base(scalar: bytes) -> bytes:
    return x25519(scalar, X25519_BASEPOINT_BYTES)


def is_all_zero(b: bytes) -> bool:
    acc = 0
    for x in b:
        acc |= x
    return acc == 0


def hkdf_sha256(*, ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    if length <= 0:
        raise ValueError("length must be positive")

    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
        if counter > 255:
            raise ValueError("length too large for HKDF")
    return okm[:length]


def ecdh_shared_secret(*, private_scalar: bytes, peer_public_key: bytes) -> bytes:
    shared = x25519(private_scalar, peer_public_key)
    if is_all_zero(shared):
        raise ValueError("all-zero shared secret (possible small-order/invalid input)")
    return shared
```

Run it:

`python3 code/main.py`

## Use It

In production, do **not** implement X25519 yourself. Use a vetted library and (ideally) a high-level protocol construction.

- **Python (`cryptography`)**: `X25519PrivateKey.generate()` and `.exchange(peer_public_key)` for ECDH; use HKDF from the same library and bind transcript/context. (Key format is “Raw” 32 bytes for X25519.)
- **libsodium**: prefer `crypto_kx_*` (high-level key exchange). If you truly need raw X25519, use `crypto_scalarmult_curve25519()` / `crypto_scalarmult_curve25519_base()`.
- **OpenSSL / BoringSSL**: use the built-in X25519 group and let the TLS/handshake layer handle transcripts and key derivation.

Rule of thumb: **X25519 gives key material, not a key.** Always run a KDF with context, and don’t forget authentication (signatures/certificates/PSK/Noise pattern) to avoid MITM.

## Pitfalls

1. **Endianness mismatch.** X25519 inputs/outputs are *little-endian* 32-byte strings. Treating them as big-endian breaks interoperability.
2. **Using the raw shared secret as an AES key.** Always run HKDF (or protocol KDF) and bind context (protocol name/version, both public keys, transcript hash).
3. **Skipping the all-zero check.** Protocols often abort if the shared secret is all-zero to mitigate small-order/invalid public inputs.
4. **Unauthenticated DH (MITM).** X25519 alone does not authenticate peers; you need signatures/certificates, PSK, or a protocol like Noise/TLS that authenticates.
5. **Rolling your own implementation.** Constant-time behavior and field arithmetic side-channels matter; use vetted libraries.

## Ship It

Save and reuse the integration-review prompt at:

`outputs/prompt-x25519-ecdh-integration-review.md`

Use it to review PRs that add or modify X25519 usage:

- Paste the handshake/KDF code + a short protocol description.
- Ask the prompt to enumerate correctness/security issues (endianness, all-zero check, transcript binding, authentication).
- Treat any “roll your own” X25519 implementation as a red flag unless you have a strong, audited reason.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe the RFC 7748 test vector output and the Alice/Bob shared secret match.
2. Medium. The helper `x25519_iterated()` is already implemented in `code/main.py`. Extend the demo to print `x25519_iterated(iterations=1, ...)` for the RFC iterative test vector and compare to `tests/vectors.json`.
3. Hard. Integrate X25519 into a real handshake: use a vetted library API (e.g., Python `cryptography`) to do ECDH, then derive two independent keys with HKDF (one for encryption, one for authentication) while binding the transcript and both public keys.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| X25519 | “Curve25519” | The RFC 7748 scalar-multiplication function on Curve25519’s Montgomery form (u-coordinate-only API). |
| u-coordinate | “The x-coordinate” | The Montgomery `u` value; X25519 inputs/outputs only this coordinate (encoded little-endian). |
| Clamping | “Fix the private key bits” | Mask/set specific scalar bits before decoding to force a safe scalar shape. |
| Montgomery ladder | “Side-channel-safe scalar mult” | A regular sequence of operations per scalar bit; a building block for constant-time implementations. |
| All-zero check | “Reject bad keys” | Abort if the shared secret is all-zero (can indicate small-order/invalid public input in some protocols). |

## Further Reading

- Langley, Hamburg, Turner — *RFC 7748: Elliptic Curves for Security* (2016) — The standard definition of X25519/X448, including test vectors and the all-zero check note.
- Bernstein — *Curve25519: new Diffie-Hellman speed records* (2006) — Design motivations and performance/security properties of Curve25519.
- Kleppmann — *Implementing Curve25519/X25519: A Tutorial on Elliptic Curve Cryptography* (2020) — A gentle walkthrough of the ladder and coordinate-only arithmetic.
