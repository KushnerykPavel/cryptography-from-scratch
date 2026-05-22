# Bitcoin Crypto Stack — secp256k1, SHA-256, Schnorr
> Bitcoin spending is “hash it twice, then prove you know the key” — and every one of those words has sharp edges.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 03 · 07 (secp256k1), Phase 09 · 01 (Hash Commitments), Phase 09 · 04 (Merkle Trees)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain how Bitcoin combines SHA-256, secp256k1, and Schnorr signatures.
- Compute `SHA256`, `HASH256` (double SHA-256), and BIP340 `tagged_hash`.
- Implement x-only public key generation and BIP340 Schnorr sign/verify.
- Distinguish `txid` hashing from the actual transaction *sighash* that gets signed.
- Apply published test vectors to validate a signature implementation.

## The Problem

You are reviewing Bitcoin/Taproot signing code in a wallet, hardware signer, bridge, or custody system. The code “looks right” — it hashes something, does secp256k1 math, and outputs a 64-byte signature — but tiny mismatches cause catastrophic outcomes: signatures that don’t verify, signatures that verify for the wrong message, or signatures that leak the private key when nonces go wrong.

Bitcoin is especially unforgiving because it uses the same building blocks everywhere: SHA-256 in block hashing and transaction IDs, secp256k1 for keys, and (post-Taproot) BIP340 Schnorr signatures. If you don’t know the exact conventions (x-only keys, even-Y rules, tagged hashing), it’s easy to write code that is “almost Bitcoin” — and “almost Bitcoin” is broken.

This lesson builds a minimal, stdlib-only reference you can run and test. The goal isn’t performance; it’s to develop a reviewer’s intuition for what must be checked and why.

## The Concept

Bitcoin’s “crypto stack” is a pipeline:

1. **Hashing.** SHA-256 is used directly, and also as `HASH256(data) = SHA256(SHA256(data))` (“double SHA-256”). Transaction IDs, block headers, and Merkle trees use this pattern.
2. **Curve group.** secp256k1 is the elliptic curve group where keys live:
   - Field prime `p = 2^256 - 2^32 - 977`
   - Curve equation: `y^2 ≡ x^3 + 7 (mod p)`
   - Group order `n` defines the private key range: `1 ≤ d ≤ n-1`
3. **Schnorr (BIP340).** A signature is 64 bytes: `sig = r || s` where `r` is the x-coordinate of a nonce point `R` and `s` is a scalar modulo `n`.

Two BIP340 conventions matter for safety and interoperability:

- **X-only public keys.** Public keys are encoded as 32-byte x-coordinates. When turning an x-coordinate into a point, you pick the point with **even y** (`lift_x`). This removes an ambiguity that would otherwise create malleability.
- **Tagged hashing.** BIP340 uses domain separation:
  `tagged_hash(tag, m) = SHA256(SHA256(tag) || SHA256(tag) || m)`
  Tags like `"BIP0340/aux"`, `"BIP0340/nonce"`, `"BIP0340/challenge"` make sure hashes from one purpose can’t be replayed as hashes for another.

Verification works by reconstructing `R` from the signature and public key:

- Compute `e = int(tagged_hash("BIP0340/challenge", r||P||m)) mod n`
- Check that `R = s⋅G - e⋅P` is not infinity, has even y, and `x(R) = r`

## Build It

### Step 1: SHA-256, HASH256, tagged_hash
```python
def int_to_bytes(x: int, length: int) -> bytes:
    if x < 0:
        raise ValueError("x must be >= 0")
    return x.to_bytes(length, "big")


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def bytes_xor(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hash256(data: bytes) -> bytes:
    return sha256(sha256(data))


def tagged_hash(tag: str, msg: bytes) -> bytes:
    tag_hash = sha256(tag.encode("utf-8"))
    return sha256(tag_hash + tag_hash + msg)
```
These are the hashing primitives you’ll see all over Bitcoin code: single SHA-256, double SHA-256 (“HASH256”), and BIP340’s tagged hashes for domain separation.

### Step 2: secp256k1 points + scalar multiplication
```python
@dataclass(frozen=True)
class Point:
    x: int
    y: int


ECPoint = Point | None


SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_A = 0
SECP256K1_B = 7
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_G = Point(
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def is_on_curve(point: ECPoint) -> bool:
    if point is None:
        return True
    x = point.x % SECP256K1_P
    y = point.y % SECP256K1_P
    return (y * y - (x * x * x + SECP256K1_A * x + SECP256K1_B)) % SECP256K1_P == 0


def require_on_curve(point: ECPoint) -> None:
    if not is_on_curve(point):
        raise ValueError("point is not on secp256k1")


def has_even_y(point: Point) -> bool:
    return (point.y % 2) == 0


def point_neg(point: ECPoint) -> ECPoint:
    require_on_curve(point)
    if point is None:
        return None
    return Point(point.x % SECP256K1_P, (-point.y) % SECP256K1_P)


def point_add(p: ECPoint, q: ECPoint) -> ECPoint:
    require_on_curve(p)
    require_on_curve(q)

    if p is None:
        return q
    if q is None:
        return p

    if (p.x - q.x) % SECP256K1_P == 0 and (p.y + q.y) % SECP256K1_P == 0:
        return None

    if p == q:
        if p.y % SECP256K1_P == 0:
            return None
        lam = (3 * p.x * p.x + SECP256K1_A) * pow(2 * p.y, SECP256K1_P - 2, SECP256K1_P)
    else:
        lam = (q.y - p.y) * pow(q.x - p.x, SECP256K1_P - 2, SECP256K1_P)

    lam %= SECP256K1_P
    x3 = (lam * lam - p.x - q.x) % SECP256K1_P
    y3 = (lam * (p.x - x3) - p.y) % SECP256K1_P
    out: ECPoint = Point(x3, y3)
    require_on_curve(out)
    return out


def point_mul(k: int, point: ECPoint) -> ECPoint:
    require_on_curve(point)
    if point is None or k == 0:
        return None
    if k < 0:
        return point_mul(-k, point_neg(point))

    acc: ECPoint = None
    addend: ECPoint = point

    while k:
        if k & 1:
            acc = point_add(acc, addend)
        addend = point_add(addend, addend)
        k >>= 1

    return acc


def lift_x(x: int) -> Point | None:
    if x >= SECP256K1_P:
        return None
    y_sq = (pow(x, 3, SECP256K1_P) + SECP256K1_B) % SECP256K1_P
    y = pow(y_sq, (SECP256K1_P + 1) // 4, SECP256K1_P)
    if pow(y, 2, SECP256K1_P) != y_sq:
        return None
    y_even = y if (y & 1) == 0 else (SECP256K1_P - y)
    point = Point(x, y_even)
    require_on_curve(point)
    return point


def xonly_bytes(point: Point) -> bytes:
    return int_to_bytes(point.x % SECP256K1_P, 32)
```
This is the minimum elliptic curve machinery needed for BIP340: point add, scalar multiply, and `lift_x` for x-only pubkeys (choose the even-y point).

### Step 3: BIP340 Schnorr keygen + sign + verify
```python
def pubkey_gen_xonly(seckey32: bytes) -> bytes:
    if len(seckey32) != 32:
        raise ValueError("seckey must be 32 bytes")
    d0 = bytes_to_int(seckey32)
    if not (1 <= d0 <= SECP256K1_N - 1):
        raise ValueError("seckey must be an integer in the range 1..n-1")
    P = point_mul(d0, SECP256K1_G)
    assert P is not None
    return xonly_bytes(P)


def schnorr_sign(msg: bytes, seckey32: bytes, aux_rand32: bytes) -> bytes:
    if len(seckey32) != 32:
        raise ValueError("seckey must be 32 bytes")
    if len(aux_rand32) != 32:
        raise ValueError(f"aux_rand must be 32 bytes instead of {len(aux_rand32)}")

    d0 = bytes_to_int(seckey32)
    if not (1 <= d0 <= SECP256K1_N - 1):
        raise ValueError("seckey must be an integer in the range 1..n-1")

    P = point_mul(d0, SECP256K1_G)
    assert P is not None
    d = d0 if has_even_y(P) else SECP256K1_N - d0

    t = bytes_xor(int_to_bytes(d, 32), tagged_hash("BIP0340/aux", aux_rand32))
    k0 = bytes_to_int(tagged_hash("BIP0340/nonce", t + xonly_bytes(P) + msg)) % SECP256K1_N
    if k0 == 0:
        raise RuntimeError("failure: k0 is 0")

    R = point_mul(k0, SECP256K1_G)
    assert R is not None
    k = SECP256K1_N - k0 if not has_even_y(R) else k0

    e = bytes_to_int(tagged_hash("BIP0340/challenge", xonly_bytes(R) + xonly_bytes(P) + msg)) % SECP256K1_N
    sig = xonly_bytes(R) + int_to_bytes((k + e * d) % SECP256K1_N, 32)
    if not schnorr_verify(msg, xonly_bytes(P), sig):
        raise RuntimeError("created signature does not pass verification")
    return sig


def schnorr_verify(msg: bytes, pubkey32: bytes, sig64: bytes) -> bool:
    if len(pubkey32) != 32:
        raise ValueError("pubkey must be 32 bytes")
    if len(sig64) != 64:
        raise ValueError("sig must be 64 bytes")

    P = lift_x(bytes_to_int(pubkey32))
    r = bytes_to_int(sig64[0:32])
    s = bytes_to_int(sig64[32:64])

    if P is None or r >= SECP256K1_P or s >= SECP256K1_N:
        return False

    e = bytes_to_int(tagged_hash("BIP0340/challenge", sig64[0:32] + pubkey32 + msg)) % SECP256K1_N
    R = point_add(point_mul(s, SECP256K1_G), point_mul(SECP256K1_N - e, P))
    if R is None:
        return False
    if not has_even_y(R):
        return False
    return (R.x % SECP256K1_P) == r
```
This is the heart of Taproot-era Bitcoin signature validation: x-only public keys, tagged nonce derivation, and verification by recomputing `R = sG - eP` and comparing x-coordinates under the even-Y convention.

### Step 4: A runnable demo that prints each step
```python
def _hx(b: bytes) -> str:
    return b.hex()


def main():
    print("=== Step 1: SHA-256 and tagged hashing ===")
    data = b"hello"
    print("sha256('hello') =", _hx(sha256(data)))
    print("hash256('hello') =", _hx(hash256(data)))
    print("tagged_hash('BIP0340/aux', 32x00) =", _hx(tagged_hash("BIP0340/aux", b"\x00" * 32)))
    print()

    print("=== Step 2: secp256k1 points and scalar multiplication ===")
    require_on_curve(SECP256K1_G)
    two_g = point_add(SECP256K1_G, SECP256K1_G)
    assert two_g is not None
    print("G.x =", hex(SECP256K1_G.x))
    print("2G.x =", hex(two_g.x))
    k = 7
    p7 = point_mul(k, SECP256K1_G)
    assert p7 is not None
    print("7G.x =", hex(p7.x))
    print("7G has even y? =", has_even_y(p7))
    print()

    print("=== Step 3: BIP340 Schnorr sign/verify ===")
    seckey = int_to_bytes(3, 32)
    pubkey = pubkey_gen_xonly(seckey)
    msg = b"\x00" * 32
    aux = b"\x00" * 32
    sig = schnorr_sign(msg, seckey, aux)
    ok = schnorr_verify(msg, pubkey, sig)
    print("pubkey (x-only) =", _hx(pubkey))
    print("sig =", _hx(sig))
    print("verify =", ok)
    print()

    print("=== Step 4: Double-SHA256 'txid'-style hashing ===")
    tx_like = b"version=1|in=...|out=...|locktime=0"
    txid = hash256(tx_like)
    sig2 = schnorr_sign(txid, seckey, b"\x01" * 32)
    ok2 = schnorr_verify(txid, pubkey, sig2)
    print("tx_like =", tx_like.decode("utf-8"))
    print("txid = hash256(tx_like) =", _hx(txid))
    print("sig(txid) =", _hx(sig2))
    print("verify(sig, txid) =", ok2)
```
This `main()` is deliberately “show your work”: it prints concrete inputs and outputs for each step so you can sanity-check your mental model as you read.

Run it:
python3 code/main.py

## Use It

In real systems, you never ship handwritten curve code. Use audited implementations and treat signature code like consensus-critical parsing:

| What you need | Production-grade option | Notes |
|---|---|---|
| secp256k1 ECDSA/Schnorr | `libsecp256k1` (Bitcoin Core’s library) | Constant-time and heavily reviewed. |
| Bitcoin transaction signing | Bitcoin Core / hardware wallet firmware | Correct sighash rules matter more than the curve math. |
| Rust | `rust-bitcoin` + `secp256k1` crate | Wraps `libsecp256k1` for safety and ergonomics. |
| Python (bindings) | `secp256k1`/`coincurve` (bindings) | Convenience for tooling; still relies on native code. |

## Pitfalls

1. **Signing the wrong thing.** Bitcoin does not sign the `txid`; it signs a context-specific *sighash* (and Taproot uses tagged hashes). “Hash the transaction bytes and sign” is not enough.
2. **Forgetting the even-Y convention.** BIP340’s x-only keys require `lift_x` and even-y normalization. Missing this causes interoperability failures and can reintroduce malleability.
3. **Skipping range checks.** Verification must reject `r ≥ p` and `s ≥ n` before doing group operations.
4. **Bad nonce handling.** Reusing a nonce (or letting an attacker influence it) can leak the private key. BIP340’s deterministic tagged nonce derivation is there for a reason.
5. **Non-constant-time operations.** Any secret-dependent branching or memory access (like double-and-add) is a side-channel risk in signers.

## Ship It

Save and reuse the reviewer prompt in `outputs/prompt-bip340-schnorr-review.md`. Use it when:

- Reviewing wallet / signer / bridge code that claims “BIP340 Schnorr support”.
- Auditing key parsing and signature verification logic (especially x-only keys).
- Writing PR review checklists for consensus-adjacent code.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe that the BIP340 test vector with `seckey=3` produces the published signature.
2. Medium. Extend the demo to sign two different “tx_like” byte strings and show that `hash256(tx_like)` changes (and so does the signature).
3. Hard. Replace the affine point arithmetic with Jacobian coordinates (still in pure Python) and measure the speedup for `test_sign_verify_roundtrip`.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| SHA-256 | “Bitcoin’s hash” | A 256-bit hash function used throughout Bitcoin. |
| HASH256 | “double SHA” | `SHA256(SHA256(m))`, used for txids, block IDs, Merkle nodes. |
| secp256k1 | “Bitcoin’s curve” | The elliptic curve group where private/public keys live. |
| x-only pubkey | “just 32 bytes” | 32-byte x-coordinate plus the convention “use the even-y point”. |
| lift_x | “recover the pubkey point” | Map x → (x, y) by taking a modular square root and choosing even y. |
| tagged_hash | “domain-separated hash” | `SHA256(SHA256(tag)||SHA256(tag)||m)` to avoid cross-protocol confusion. |
| nonce (k) | “randomizer” | Secret scalar used once per signature; reuse leaks keys. |
| (r, s) | “the signature” | Encodes an x-coordinate `r` and scalar `s` that must satisfy `R = sG - eP`. |

## Further Reading

- Pieter Wuille, Jonas Nick, Tim Ruffing, “BIP340: Schnorr Signatures for secp256k1” (2020) — The specification + reference code + test vectors used here.
- SECG, “SEC 2: Recommended Elliptic Curve Domain Parameters” (v2.0) — Defines secp256k1 curve parameters and encodings.
- NIST, “FIPS 180-4: Secure Hash Standard” (2015) — SHA-256 definition.
- Andreas M. Antonopoulos, “Mastering Bitcoin” (2nd ed., 2017) — Practical Bitcoin transaction structure and signing context.
