# DSA & ECDSA from Scratch
> One secret key, many signatures — but only if the nonce never betrays you.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** Phase 01 modular inverses; Phase 03 elliptic-curve point addition + scalar multiplication  
**Time:** ~90 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** why the nonce `k` is the security linchpin of DSA/ECDSA
- **Compute** the signing and verification equations for DSA and ECDSA
- **Implement** deterministic nonce generation (`RFC 6979`-style) and sign/verify
- **Distinguish** DSA over a finite-field subgroup vs. ECDSA over an elliptic-curve group
- **Apply** basic hardening: input validation and low-`s` normalization

## The Problem
You want signatures: a public-key way to say “this message came from someone who knows the private key.” That shows up everywhere: software update signing, git commit signing, API request signing, blockchain transactions, and authentication protocols.

DSA/ECDSA are deceptively small formulas with one critical trap: the per-signature nonce `k`. If `k` is ever reused (or even biased), attackers can often recover your private key from just a couple of signatures. Real-world incidents have happened from broken RNGs, VM snapshots, forked processes, or “almost-random” nonces.

This lesson builds DSA and ECDSA end-to-end, then demonstrates how nonce reuse instantly leaks the key on a toy DSA instance.

## The Concept
Both schemes live in a cyclic group of order `q` (or `n`). You have:

- A generator (`g` for DSA, `G` for ECDSA)
- A private key (`x` for DSA, `d` for ECDSA)
- A public key (`y = g^x (mod p)` for DSA, `Q = d·G` for ECDSA)

### DSA (finite-field subgroup)
Parameters: primes `p`, `q` with `q | (p-1)`, generator `g` of a subgroup of order `q`.

Sign:
- Choose nonce `k ∈ [1, q-1]`
- `r = (g^k mod p) mod q`
- `s = k^{-1} ( H(m) + x·r ) mod q`

Verify:
- `w = s^{-1} mod q`
- `u1 = H(m)·w mod q`, `u2 = r·w mod q`
- `v = ( g^{u1} · y^{u2} mod p ) mod q`
- Accept iff `v == r`

### ECDSA (elliptic-curve group)
Parameters: elliptic curve with base point `G` of order `n`.

Sign:
- Choose nonce `k ∈ [1, n-1]`
- `R = k·G`, `r = R.x mod n`
- `s = k^{-1} ( H(m) + r·d ) mod n`

Verify:
- `w = s^{-1} mod n`
- `u1 = H(m)·w mod n`, `u2 = r·w mod n`
- `X = u1·G + u2·Q`
- Accept iff `X.x mod n == r`

### Why `k` reuse is fatal
If two signatures reuse the same `k` (so they share the same `r`), then you can solve for `k` and the private key with modular algebra. That’s not a theoretical edge case — it’s the most famous signature failure mode in practice.

## Build It

### Step 1: Modular inverses and hashing-to-int
```python
def int_to_bytes(x: int, length: int) -> bytes:
    if x < 0:
        raise ValueError("x must be >= 0")
    return x.to_bytes(length, "big")


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


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


def bits2int(b: bytes, qlen: int) -> int:
    x = bytes_to_int(b)
    blen = 8 * len(b)
    if blen > qlen:
        x >>= blen - qlen
    return x


def hash_to_int(message: bytes, q: int, hashfunc=hashlib.sha256) -> int:
    return bits2int(hashfunc(message).digest(), q.bit_length())
```
Signatures need modular inverses (`k^{-1}` and `s^{-1}`), and they need a way to map a message hash into the integer range expected by the group order (`q` or `n`). Here we follow the common “leftmost bits” convention: if the hash is longer than the group order, we truncate.

### Step 2: Deterministic nonces (RFC 6979-style)
```python
def int2octets(x: int, rolen: int) -> bytes:
    return int_to_bytes(x, rolen)


def bits2octets(h1: bytes, q: int, qlen: int, rolen: int) -> bytes:
    z1 = bits2int(h1, qlen)
    z2 = z1 % q
    return int2octets(z2, rolen)


def rfc6979_generate_k(x: int, h1: bytes, q: int, hashfunc=hashlib.sha256) -> int:
    qlen = q.bit_length()
    holen = hashfunc().digest_size
    rolen = (qlen + 7) // 8

    bx = int2octets(x, rolen) + bits2octets(h1, q, qlen, rolen)
    v = b"\x01" * holen
    k = b"\x00" * holen

    k = hmac.new(k, v + b"\x00" + bx, hashfunc).digest()
    v = hmac.new(k, v, hashfunc).digest()
    k = hmac.new(k, v + b"\x01" + bx, hashfunc).digest()
    v = hmac.new(k, v, hashfunc).digest()

    while True:
        t = b""
        while len(t) < rolen:
            v = hmac.new(k, v, hashfunc).digest()
            t += v

        candidate = bits2int(t, qlen)
        if 1 <= candidate < q:
            return candidate

        k = hmac.new(k, v + b"\x00", hashfunc).digest()
        v = hmac.new(k, v, hashfunc).digest()
```
In production you either need a good RNG or (more commonly today) deterministic nonces. RFC 6979 turns “private key + message hash” into a pseudo-random `k` via HMAC, so signatures stay safe even if the RNG is broken.

### Step 3: DSA sign/verify + the nonce-reuse break
```python
DSA_P = 1019
DSA_Q = 509
DSA_G = pow(2, (DSA_P - 1) // DSA_Q, DSA_P)


def dsa_public_key(p: int, g: int, x: int) -> int:
    if x <= 0:
        raise ValueError("private key must be > 0")
    return pow(g, x, p)


def dsa_sign(
    message: bytes,
    p: int,
    q: int,
    g: int,
    x: int,
    *,
    k: int | None = None,
    hashfunc=hashlib.sha256,
) -> tuple[int, int]:
    if k is None:
        h1 = hashfunc(message).digest()
        k = rfc6979_generate_k(x, h1, q, hashfunc)
    k %= q
    if k == 0:
        raise ValueError("k must be non-zero modulo q")

    r = pow(g, k, p) % q
    if r == 0:
        raise ValueError("r must be non-zero")

    e = hash_to_int(message, q, hashfunc)
    s = (mod_inv(k, q) * (e + (x % q) * r)) % q
    if s == 0:
        raise ValueError("s must be non-zero")
    return r, s


def dsa_verify(
    message: bytes,
    p: int,
    q: int,
    g: int,
    y: int,
    signature: tuple[int, int],
    *,
    hashfunc=hashlib.sha256,
) -> bool:
    r, s = signature
    if not (1 <= r < q and 1 <= s < q):
        return False

    e = hash_to_int(message, q, hashfunc)
    w = mod_inv(s, q)
    u1 = (e * w) % q
    u2 = (r * w) % q
    v = (pow(g, u1, p) * pow(y, u2, p) % p) % q
    return v == r


def recover_private_key_from_nonce_reuse(
    q: int,
    e1: int,
    e2: int,
    r: int,
    s1: int,
    s2: int,
) -> tuple[int, int]:
    if (s1 - s2) % q == 0:
        raise ValueError("s1 must differ from s2 (mod q)")
    k = ((e1 - e2) * mod_inv((s1 - s2) % q, q)) % q
    x = ((s1 * k - e1) * mod_inv(r, q)) % q
    return k, x
```
We implement DSA over a tiny “toy” subgroup (so you can see numbers and attacks clearly). The important part is the structure: `r` comes from the nonce, and `s` mixes the nonce inverse with the private key and message hash. The `recover_private_key_from_nonce_reuse` function demonstrates the real-world disaster case: if two signatures reuse the same nonce, the private key becomes solvable with a few modular inverses.

### Step 4: Elliptic-curve group (secp256k1)
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
    55066263022277343669578718895168534326250603453777594175500187360389116729240,
    32670510020758816978083085130507043184471273380659243275938904335757337482424,
)


def is_on_secp256k1(point: ECPoint) -> bool:
    if point is None:
        return True
    x, y = point.x % SECP256K1_P, point.y % SECP256K1_P
    return (y * y - (x * x * x + SECP256K1_A * x + SECP256K1_B)) % SECP256K1_P == 0


def require_on_secp256k1(point: ECPoint) -> None:
    if not is_on_secp256k1(point):
        raise ValueError("point is not on secp256k1")


def point_neg_secp256k1(point: ECPoint) -> ECPoint:
    require_on_secp256k1(point)
    if point is None:
        return None
    return Point(point.x % SECP256K1_P, (-point.y) % SECP256K1_P)


def point_add_secp256k1(p: ECPoint, q: ECPoint) -> ECPoint:
    require_on_secp256k1(p)
    require_on_secp256k1(q)

    if p is None:
        return q
    if q is None:
        return p

    if p.x % SECP256K1_P == q.x % SECP256K1_P and (p.y + q.y) % SECP256K1_P == 0:
        return None

    if p != q:
        lam = (q.y - p.y) * mod_inv(q.x - p.x, SECP256K1_P)
    else:
        if p.y % SECP256K1_P == 0:
            return None
        lam = (3 * p.x * p.x + SECP256K1_A) * mod_inv(2 * p.y, SECP256K1_P)

    lam %= SECP256K1_P
    x3 = (lam * lam - p.x - q.x) % SECP256K1_P
    y3 = (lam * (p.x - x3) - p.y) % SECP256K1_P
    result: ECPoint = Point(x3, y3)
    require_on_secp256k1(result)
    return result


def scalar_mul_secp256k1(k: int, point: ECPoint) -> ECPoint:
    require_on_secp256k1(point)
    if point is None or k == 0:
        return None
    if k < 0:
        return scalar_mul_secp256k1(-k, point_neg_secp256k1(point))

    acc: ECPoint = None
    addend: ECPoint = point

    while k > 0:
        if k & 1:
            acc = point_add_secp256k1(acc, addend)
        addend = point_add_secp256k1(addend, addend)
        k >>= 1

    return acc
```
ECDSA replaces “modular exponentiation in a subgroup” with “scalar multiplication on an elliptic curve.” Everything else about the signature equations stays structurally similar — especially the role of the nonce `k`.

### Step 5: ECDSA sign/verify and low-`s` normalization
```python
def ecdsa_public_key(d: int) -> Point:
    if not (1 <= d < SECP256K1_N):
        raise ValueError("private key must be in [1, n-1]")
    q = scalar_mul_secp256k1(d, SECP256K1_G)
    if q is None:
        raise ValueError("invalid private key")
    return q


def normalize_s_low_s(n: int, signature: tuple[int, int]) -> tuple[int, int]:
    r, s = signature
    if s > n // 2:
        return r, n - s
    return r, s


def ecdsa_sign(
    message: bytes,
    d: int,
    *,
    k: int | None = None,
    hashfunc=hashlib.sha256,
    low_s: bool = True,
) -> tuple[int, int]:
    if not (1 <= d < SECP256K1_N):
        raise ValueError("private key must be in [1, n-1]")

    e = hash_to_int(message, SECP256K1_N, hashfunc)

    if k is None:
        h1 = hashfunc(message).digest()
        k = rfc6979_generate_k(d, h1, SECP256K1_N, hashfunc)
    k %= SECP256K1_N
    if k == 0:
        raise ValueError("k must be non-zero modulo n")

    r_point = scalar_mul_secp256k1(k, SECP256K1_G)
    if r_point is None:
        raise ValueError("k produced point at infinity")
    r = r_point.x % SECP256K1_N
    if r == 0:
        raise ValueError("r must be non-zero")

    s = (mod_inv(k, SECP256K1_N) * (e + r * d)) % SECP256K1_N
    if s == 0:
        raise ValueError("s must be non-zero")

    signature = (r, s)
    if low_s:
        signature = normalize_s_low_s(SECP256K1_N, signature)
    return signature


def ecdsa_verify(
    message: bytes,
    q: Point,
    signature: tuple[int, int],
    *,
    hashfunc=hashlib.sha256,
) -> bool:
    require_on_secp256k1(q)
    r, s = signature
    if not (1 <= r < SECP256K1_N and 1 <= s < SECP256K1_N):
        return False

    e = hash_to_int(message, SECP256K1_N, hashfunc)
    w = mod_inv(s, SECP256K1_N)
    u1 = (e * w) % SECP256K1_N
    u2 = (r * w) % SECP256K1_N
    x_point = point_add_secp256k1(
        scalar_mul_secp256k1(u1, SECP256K1_G), scalar_mul_secp256k1(u2, q)
    )
    if x_point is None:
        return False
    return (x_point.x % SECP256K1_N) == r
```
ECDSA has a second practical pitfall: signature malleability. If `(r, s)` verifies, then `(r, n-s)` also verifies. Many systems (notably Bitcoin and other chains) standardize “low-`s`” signatures to make signatures canonical and avoid malleability-based surprises in higher-level protocols.

Run it:

`python3 code/main.py`

## Use It
Real implementations use constant-time arithmetic, hardened parsing, and safe randomness / deterministic nonce generation.

- **Python**: `cryptography` (ECDSA), PyCryptodome (DSA/ECDSA)
- **Go**: `crypto/ecdsa` (ECDSA), `crypto/dsa` (legacy DSA)
- **Rust**: `k256` / `p256` crates (ECDSA), `ring` (ECDSA)
- **OpenSSL**: `EVP_PKEY` APIs (DSA/ECDSA)

## Pitfalls
- **Nonce reuse (`k`)**: two signatures with the same `k` can leak the private key.
- **Biased / weak `k`**: even without exact reuse, structure in `k` can enable lattice attacks.
- **Skipping range checks**: accepting `r=0`, `s=0`, or out-of-range values leads to weird edge cases and potential bypasses.
- **Signature malleability**: `(r, s)` and `(r, n-s)` both verify; many protocols demand low-`s`.
- **Hash/domain mismatch**: using the wrong hash or truncation rules changes what is actually being signed.

## Ship It
Save and reuse the audit prompt in `outputs/prompt-dsa-ecdsa-review-checklist.md` when reviewing PRs that “just add ECDSA signatures” — it catches the real failure modes (nonce handling, malleability, encoding, and key validation).

## Exercises
1. Easy. Run `python3 code/main.py`. Observe that `(r, s)` and `(r, n-s)` both verify for ECDSA when low-`s` normalization is disabled.
2. Medium. Change the demo private key `d` in `main()` from `1` to another small integer (e.g. `2`, `3`, `7`). Re-run and observe that the deterministic signature changes, but verification still passes.
3. Hard. Production integration: using an audited library in your language of choice, enforce low-`s` signatures and strict DER parsing (if applicable), then write a test that rejects high-`s` signatures.

## Key Terms
| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Nonce `k` | “Random number used once” | Per-signature secret that must be unpredictable and never reused; it hides the private key in the signature equation. |
| Group order (`q` / `n`) | “Size of the group” | The size of the cyclic subgroup generated by `g`/`G`; all signature arithmetic is done modulo this value. |
| Generator (`g` / `G`) | “A base point” | A fixed element whose multiples cover the subgroup used for security. |
| Low-`s` | “Canonical signatures” | A normalization rule (usually `s ≤ n/2`) that removes a simple ECDSA malleability (`s ↦ n-s`). |
| Malleability | “Different signatures for the same message” | Multiple encodings/representations verify the same message; can break higher-level protocols that assume uniqueness. |

## Further Reading
- NIST, *FIPS 186-4: Digital Signature Standard* (2013) — the formal definition of DSA/ECDSA algorithms and validation rules.
- T. Pornin, *RFC 6979: Deterministic Usage of the Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA)* (2013) — how to generate safe deterministic nonces.
- Hankerson, Menezes, Vanstone, *Guide to Elliptic Curve Cryptography* (2004) — practical ECC background and implementation pitfalls.
