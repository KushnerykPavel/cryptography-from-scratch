# Ed25519 from Scratch
> Deterministic Schnorr-style signatures on a fast Edwards curve.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** `phases/03-elliptic-curves/05-edwards-curves`, `phases/08-classical-asymmetric/08-schnorr`  
**Time:** ~90 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** why Ed25519 is “Schnorr-like” — and what’s different about it.
- **Compute** the verification equation `s·B = R + H(R,A,M)·A` at a high level.
- **Implement** Ed25519 key derivation, signing, and verification from RFC 8032.
- **Distinguish** curve arithmetic (points/scalars) from protocol glue (byte encodings, domain separation).
- **Apply** a practical checklist to integrate Ed25519 safely in real systems.

## The Problem

You need signatures that are *fast*, *small*, and *hard to misuse*. In real systems (APIs, signing services, CI/CD attestations, blockchain transactions, DID documents), signatures are an everyday tool — but the failure modes are brutal: ambiguous message encoding, nonce mistakes, and “verify the wrong bytes” bugs routinely become production incidents.

Ed25519 is a modern default because it is fast, uses compact 32-byte public keys / 64-byte signatures, and avoids the most common ECDSA foot-guns (especially nonce handling) by being deterministic. But that only helps if you understand what *exactly* is being signed and verified, and how the 32-byte point encoding works.

This lesson builds an educational Ed25519 implementation end-to-end (stdlib-only) so you can reason about signatures as *bytes ↔ scalars ↔ points* — and review real production integrations with confidence.

## The Concept

Ed25519 is EdDSA instantiated over the Edwards curve “edwards25519”. Conceptually, it’s a Schnorr-style signature over an elliptic-curve group:

- Secret key seed (32 bytes) is hashed with SHA-512.
- The first half becomes a scalar `a` (after **clamping** bits).
- The second half becomes a secret “prefix”.
- Nonce `r` is deterministic: `r = SHA512(prefix || message) mod L`.
- Commitment point `R = r·B` (where `B` is the base point).
- Challenge `k = SHA512(R_enc || A_enc || message) mod L`.
- Response scalar `s = r + k·a (mod L)`.
- Signature is `sig = R_enc || s`.
- Verification checks the group equation: `s·B = R + k·A`.

Two encodings matter:

1. Scalars are little-endian integers reduced mod the group order `L`.
2. Points are 32 bytes: the `y` coordinate (255 bits, little-endian) plus one bit storing the parity of `x`.

## Build It

### Step 1: Encode/decode points
Ed25519 signatures are *bytes first*: both `R` and `A` are exchanged in compressed 32-byte form. We need reversible point encoding to connect “signature bytes” to “curve points”.

```python
ED25519_P = 2**255 - 19
ED25519_A = (-1) % ED25519_P
ED25519_D = (-121665 * pow(121666, ED25519_P - 2, ED25519_P)) % ED25519_P
ED25519_L = 2**252 + 27742317777372353535851937790883648493
ED25519_SQRT_M1 = pow(2, (ED25519_P - 1) // 4, ED25519_P)
ED25519_B_ENC = bytes.fromhex(
    "5866666666666666666666666666666666666666666666666666666666666666"
)


@dataclass(frozen=True)
class Point:
    x: int
    y: int


def mod_inv(a: int, p: int) -> int:
    a %= p
    if a == 0:
        raise ValueError("inverse does not exist")
    return pow(a, p - 2, p)


def _sqrt_mod_p_25519(a: int) -> int | None:
    p = ED25519_P
    a %= p
    if a == 0:
        return 0

    x = pow(a, (p + 3) // 8, p)
    if (x * x - a) % p != 0:
        x = (x * ED25519_SQRT_M1) % p
    if (x * x - a) % p != 0:
        return None
    return x


def ed25519_is_on_curve(p: Point) -> bool:
    x, y = p.x % ED25519_P, p.y % ED25519_P
    x2 = (x * x) % ED25519_P
    y2 = (y * y) % ED25519_P
    left = (ED25519_A * x2 + y2) % ED25519_P
    right = (1 + ED25519_D * x2 % ED25519_P * y2) % ED25519_P
    return left == right


def ed25519_encode(p: Point) -> bytes:
    if not ed25519_is_on_curve(p):
        raise ValueError("point is not on curve")
    x, y = p.x % ED25519_P, p.y % ED25519_P
    out = bytearray(y.to_bytes(32, "little"))
    out[31] |= (x & 1) << 7
    return bytes(out)


def ed25519_decode(enc: bytes) -> Point:
    if len(enc) != 32:
        raise ValueError("encoding must be 32 bytes")
    sign = (enc[31] >> 7) & 1
    y = int.from_bytes(enc, "little") & ((1 << 255) - 1)
    if y >= ED25519_P:
        raise ValueError("invalid encoding (y out of range)")

    y2 = (y * y) % ED25519_P
    u = (y2 - 1) % ED25519_P
    v = (ED25519_D * y2 + 1) % ED25519_P
    x2 = u * mod_inv(v, ED25519_P) % ED25519_P
    x = _sqrt_mod_p_25519(x2)
    if x is None:
        raise ValueError("invalid encoding (no square root)")
    if x & 1 != sign:
        x = (-x) % ED25519_P

    p = Point(x, y)
    if not ed25519_is_on_curve(p):
        raise ValueError("decoded point is not on curve")
    return p
```

This step is the bridge between “protocol bytes” and “group elements”: if you get this wrong, you can’t trust anything above it.

### Step 2: Scalar multiplication
Signing and verification are just scalar multiplications plus point addition. We use extended Edwards coordinates to avoid modular inversions in the main loop.

```python
@dataclass(frozen=True)
class ExtPoint:
    X: int
    Y: int
    Z: int
    T: int


def ed25519_identity() -> Point:
    return Point(0, 1)


def ed25519_to_ext(p: Point) -> ExtPoint:
    if not ed25519_is_on_curve(p):
        raise ValueError("point is not on curve")
    x, y = p.x % ED25519_P, p.y % ED25519_P
    return ExtPoint(x, y, 1, (x * y) % ED25519_P)


def ed25519_from_ext(p: ExtPoint) -> Point:
    zinv = mod_inv(p.Z, ED25519_P)
    x = (p.X * zinv) % ED25519_P
    y = (p.Y * zinv) % ED25519_P
    r = Point(x, y)
    if not ed25519_is_on_curve(r):
        raise ValueError("invalid extended point (not on curve)")
    return r


def ed25519_ext_identity() -> ExtPoint:
    return ExtPoint(0, 1, 1, 0)


def ed25519_ext_neg(p: ExtPoint) -> ExtPoint:
    return ExtPoint((-p.X) % ED25519_P, p.Y % ED25519_P, p.Z % ED25519_P, (-p.T) % ED25519_P)


def ed25519_ext_add(p: ExtPoint, q: ExtPoint) -> ExtPoint:
    pX, pY, pZ, pT = p.X % ED25519_P, p.Y % ED25519_P, p.Z % ED25519_P, p.T % ED25519_P
    qX, qY, qZ, qT = q.X % ED25519_P, q.Y % ED25519_P, q.Z % ED25519_P, q.T % ED25519_P

    A = (pY - pX) * (qY - qX) % ED25519_P
    B = (pY + pX) * (qY + qX) % ED25519_P
    C = (2 * ED25519_D % ED25519_P) * pT % ED25519_P * qT % ED25519_P
    D = (2 * pZ) % ED25519_P * qZ % ED25519_P
    E = (B - A) % ED25519_P
    F = (D - C) % ED25519_P
    G = (D + C) % ED25519_P
    H = (B + A) % ED25519_P
    X3 = E * F % ED25519_P
    Y3 = G * H % ED25519_P
    T3 = E * H % ED25519_P
    Z3 = F * G % ED25519_P
    return ExtPoint(X3, Y3, Z3, T3)


def ed25519_ext_double(p: ExtPoint) -> ExtPoint:
    pX, pY, pZ = p.X % ED25519_P, p.Y % ED25519_P, p.Z % ED25519_P

    A = (pX * pX) % ED25519_P
    B = (pY * pY) % ED25519_P
    C = (2 * pZ * pZ) % ED25519_P
    D = (-A) % ED25519_P
    E = ((pX + pY) * (pX + pY) - A - B) % ED25519_P
    G = (D + B) % ED25519_P
    F = (G - C) % ED25519_P
    H = (D - B) % ED25519_P
    X3 = E * F % ED25519_P
    Y3 = G * H % ED25519_P
    T3 = E * H % ED25519_P
    Z3 = F * G % ED25519_P
    return ExtPoint(X3, Y3, Z3, T3)


def ed25519_scalar_mul(k: int, p: ExtPoint) -> ExtPoint:
    if k == 0:
        return ed25519_ext_identity()
    if k < 0:
        return ed25519_scalar_mul(-k, ed25519_ext_neg(p))

    acc = ed25519_ext_identity()
    addend = p
    while k > 0:
        if k & 1:
            acc = ed25519_ext_add(acc, addend)
        addend = ed25519_ext_double(addend)
        k >>= 1
    return acc


def ed25519_ext_eq(p: ExtPoint, q: ExtPoint) -> bool:
    return (p.X * q.Z - q.X * p.Z) % ED25519_P == 0 and (p.Y * q.Z - q.Y * p.Z) % ED25519_P == 0
```

This step gives you the group operations needed for `R = r·B`, `A = a·B`, and the verification equation.

### Step 3: Derive a public key
Ed25519 starts from a 32-byte seed. We hash it, clamp bits to form the secret scalar `a`, and compute `A = a·B`.

```python
def sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def sha512_mod_l(data: bytes) -> int:
    return int.from_bytes(sha512(data), "little") % ED25519_L


def ed25519_secret_expand(secret: bytes) -> tuple[int, bytes]:
    if len(secret) != 32:
        raise ValueError("secret must be 32 bytes")
    h = sha512(secret)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def ed25519_secret_to_public(secret: bytes) -> bytes:
    a, _prefix = ed25519_secret_expand(secret)
    b = ed25519_to_ext(ed25519_decode(ED25519_B_ENC))
    A = ed25519_scalar_mul(a, b)
    return ed25519_encode(ed25519_from_ext(A))
```

This is the bridge from “seed bytes” to the public key bytes you can distribute.

### Step 4: Sign and verify
Now we assemble Ed25519: deterministic nonce `r`, commitment `R`, challenge `k`, response `s`, and the verification equation.

```python
def ed25519_sign(secret: bytes, msg: bytes) -> bytes:
    a, prefix = ed25519_secret_expand(secret)
    A = ed25519_secret_to_public(secret)
    r = sha512_mod_l(prefix + msg)

    b = ed25519_to_ext(ed25519_decode(ED25519_B_ENC))
    R = ed25519_scalar_mul(r, b)
    R_enc = ed25519_encode(ed25519_from_ext(R))

    k = sha512_mod_l(R_enc + A + msg)
    s = (r + k * a) % ED25519_L
    return R_enc + s.to_bytes(32, "little")


def ed25519_verify(public: bytes, msg: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False

    try:
        A_aff = ed25519_decode(public)
        R_aff = ed25519_decode(signature[:32])
    except ValueError:
        return False

    s = int.from_bytes(signature[32:], "little")
    if s >= ED25519_L:
        return False

    b = ed25519_to_ext(ed25519_decode(ED25519_B_ENC))
    A = ed25519_to_ext(A_aff)
    R = ed25519_to_ext(R_aff)

    k = sha512_mod_l(signature[:32] + public + msg)
    sB = ed25519_scalar_mul(s, b)
    kA = ed25519_scalar_mul(k, A)
    return ed25519_ext_eq(sB, ed25519_ext_add(R, kA))
```

This is the whole story: once you can evaluate this equation, Ed25519 stops being magic.

Run it:

`python3 code/main.py`

## Use It

Use an audited implementation in production. Good defaults:

- **Go:** `crypto/ed25519` (sign/verify; key types are explicit)
- **Rust:** `ed25519-dalek` (with `signature` traits); `ring` for hardened primitives
- **Python:** `cryptography` (Ed25519 keys/sign/verify) or `PyNaCl` (libsodium bindings)
- **libsodium / NaCl:** widely deployed, battle-tested Ed25519

Rule of thumb: from-scratch code is for understanding; real systems use audited libraries plus careful protocol encoding.

## Pitfalls

- **Signing the “wrong bytes”.** If your app signs JSON strings, whitespace and key order can change the bytes without changing the “meaning”.
- **No domain separation.** A signature valid in one protocol may be replayed in another if you don’t bind a context string into what’s signed.
- **Accepting malformed inputs.** Lenient decoding or skipping `s < L` checks can lead to malleability and weird edge behavior.
- **Trusting attacker-provided public keys.** Verification proves “whoever owns this key signed”; it does not prove the key is authorized.
- **Assuming Ed25519 fixes everything.** It helps with nonce misuse, but it doesn’t solve replay, downgrade, or key-substitution attacks.

## Ship It

Save this reusable checklist and use it in code reviews:

- `outputs/ed25519-integration-checklist.md`

Practice: pick any PR in your own codebase that adds signature verification, and walk through the checklist items one by one.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe that the derived public key and the signature are deterministic and verification returns `True`.
2. Medium. In `code/main.py`, change `msg` in `_demo_step_4_sign_and_verify()` and confirm the signature changes and verification still passes.
3. Hard. Integrate a production library in a separate scratch script: generate a key, sign a message, and confirm the signature matches `ed25519_sign()` for the same seed+message (RFC 8032 test vectors are a good starting point).

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| EdDSA | “Modern EC signatures” | A Schnorr-style signature family standardized with specific encoding and hashing rules. |
| Ed25519 | “The default signature scheme” | EdDSA instantiated over edwards25519 with SHA-512 and 32/64-byte keys/signatures. |
| Clamping | “Mask some bits” | A fixed bit-twiddle of the hashed seed to form the signing scalar with safe structure. |
| Compressed point | “32-byte curve point” | `y` (255 bits, little-endian) plus one bit carrying the parity of `x`. |
| Domain separation | “Add a prefix” | Binding a protocol context into the signed bytes to prevent cross-protocol replay. |

## Further Reading

- Josefsson & Liusvaara, *RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)* (2017) — definitive spec + test vectors.
- Bernstein et al., *Ed25519: high-speed high-security signatures* (2011) — design motivation and performance/security context.
- Langley et al., *BoringSSL / libsodium Ed25519 docs* (ongoing) — practical guidance for real-world usage.
