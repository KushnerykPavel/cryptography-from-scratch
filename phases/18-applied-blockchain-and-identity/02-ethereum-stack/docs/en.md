# Ethereum Crypto Stack — Keccak-256, secp256k1, EIP-55, EIP-191
> Ethereum is hashes + signatures + encodings — get one byte wrong and everything breaks.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** Phase 0 (Bytes/Hex hygiene), Phase 3 (elliptic-curve group law), Phase 10 (hash functions)  
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** why Ethereum uses Keccak-256 (not FIPS SHA3-256)
- **Compute** an Ethereum address from a secp256k1 public key
- **Implement** Keccak-256 (sponge + Keccak-f[1600]) in pure Python
- **Distinguish** raw ECDSA signing from EIP-191 `personal_sign` hashing
- **Apply** EIP-55 checksums to catch common address typos

## The Problem
You keep seeing “sha3” in Ethereum code, “keccak256” in Solidity, and `sha3_256` in Python. They sound identical, but they are **not** identical. If you hash with the wrong function, you won’t match transaction hashes, function selectors, contract addresses, or signatures produced by real wallets.

Even if your hash is right, Ethereum is full of encoding boundaries: big-endian vs little-endian integers, “uncompressed public key” vs “public key bytes without the 0x04 prefix”, and “hex string bytes” vs “raw bytes”. Most production bugs in wallet/contract integrations are not “crypto is broken” bugs — they’re **one wrong encoding step** bugs.

This lesson gives you a working mental model (and a runnable script) for the core crypto pipeline: Keccak-256 → secp256k1 ECDSA → address derivation → EIP-55 checksum → EIP-191 signed message hashing.

## The Concept
Ethereum’s everyday cryptography is mostly four pieces:

| Layer | What it does | Ethereum uses |
|---|---|---|
| Hash | Maps bytes → 32 bytes | **Keccak-256** (often mislabeled “sha3”) |
| Signature | Proves “this key approved this hash” | **ECDSA over secp256k1** |
| Address | Short identifier for a public key | last 20 bytes of `keccak256(pubkey_xy)` |
| Checksum | Human typo protection | **EIP-55** (mixed-case hex) |

### Keccak-256 vs SHA3-256 (the trap)
Both are based on the same Keccak-f[1600] permutation, but they use **different padding/domain separation**:

| Function | Padding suffix (byte) | Empty-string digest |
|---|---:|---|
| Keccak-256 (Ethereum) | `0x01` | `c5d246…a470` |
| SHA3-256 (FIPS 202) | `0x06` | `a7ffc6…434a` |

### Address derivation (EOA)
Given an **uncompressed** secp256k1 public key `04 || X || Y` (65 bytes), Ethereum drops the `0x04` and hashes the remaining 64 bytes:

`addr = keccak256(X || Y)[12:]` (keep the last 20 bytes)

### EIP-55 checksum
EIP-55 uses the Keccak-256 hash of the **lowercase hex address string** (no `0x`) to decide which hex letters to capitalize. It’s a checksum that doesn’t change the bytes — only the casing.

### EIP-191 (`personal_sign`) hashing
Wallets typically don’t sign raw message bytes. They sign:

`keccak256("\x19Ethereum Signed Message:\n" + len(message) + message)`

This prevents an attacker from reusing a signature on a “human message” as a valid signature on some other structured payload.

## Build It
### Step 1: Keccak-256 (Ethereum's keccak256)
This is a sponge construction: absorb input into a 1600-bit state, apply `Keccak-f[1600]` permutations, then squeeze out 32 bytes.

```python
def _rotl64(x: int, n: int) -> int:
    n &= 63
    return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF


_KECCAK_RHO_OFFSETS = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]

_KECCAK_ROUND_CONSTANTS = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
]


def keccak_f1600(state: list[int]) -> list[int]:
    if len(state) != 25:
        raise ValueError("state must have 25 lanes (64-bit ints)")

    a = state[:]
    for rc in _KECCAK_ROUND_CONSTANTS:
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [_rotl64(c[(x + 1) % 5], 1) ^ c[(x - 1) % 5] for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x + 5 * y] ^= d[x]

        b = [0] * 25
        for x in range(5):
            for y in range(5):
                v = _rotl64(a[x + 5 * y], _KECCAK_RHO_OFFSETS[x][y])
                b[y + 5 * ((2 * x + 3 * y) % 5)] = v

        for x in range(5):
            for y in range(5):
                a[x + 5 * y] = b[x + 5 * y] ^ ((~b[((x + 1) % 5) + 5 * y]) & b[((x + 2) % 5) + 5 * y])
                a[x + 5 * y] &= 0xFFFFFFFFFFFFFFFF

        a[0] ^= rc

    return a


def keccak_256(data: bytes) -> bytes:
    rate = 136  # 1088 bits
    state = [0] * 25

    offset = 0
    while offset + rate <= len(data):
        block = data[offset : offset + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[8 * i : 8 * (i + 1)], "little")
        state = keccak_f1600(state)
        offset += rate

    tail = bytearray(data[offset:])
    padlen = rate - len(tail)
    padded = tail + bytearray(padlen)
    padded[len(tail)] ^= 0x01
    padded[rate - 1] ^= 0x80
    for i in range(rate // 8):
        state[i] ^= int.from_bytes(padded[8 * i : 8 * (i + 1)], "little")
    state = keccak_f1600(state)

    out = bytearray()
    while len(out) < 32:
        for i in range(rate // 8):
            out += int(state[i] & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        if len(out) >= 32:
            break
        state = keccak_f1600(state)
    return bytes(out[:32])


def keccak_256_hex(data: bytes) -> str:
    return keccak_256(data).hex()
```

### Step 2: secp256k1 public key + ECDSA
ECDSA depends on elliptic-curve scalar multiplication. To keep signatures deterministic for testing (and safer than random-`k`), we generate `k` using RFC 6979 (HMAC-SHA256).

```python
import hashlib
import hmac


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _inv_mod(a: int, m: int) -> int:
    if a == 0:
        raise ZeroDivisionError("division by zero")
    return pow(a, -1, m)


SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_A = 0
SECP256K1_B = 7
SECP256K1_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
SECP256K1_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

Point = tuple[int, int] | None


def is_on_secp256k1(point: Point) -> bool:
    if point is None:
        return True
    x, y = point
    if not (0 <= x < SECP256K1_P and 0 <= y < SECP256K1_P):
        return False
    return (y * y - (x * x * x + SECP256K1_B)) % SECP256K1_P == 0


def secp256k1_point_add(p: Point, q: Point) -> Point:
    if p is None:
        return q
    if q is None:
        return p

    x1, y1 = p
    x2, y2 = q
    if x1 == x2 and (y1 + y2) % SECP256K1_P == 0:
        return None

    if p == q:
        m = (3 * x1 * x1 + SECP256K1_A) * _inv_mod(2 * y1 % SECP256K1_P, SECP256K1_P)
    else:
        m = (y2 - y1) * _inv_mod((x2 - x1) % SECP256K1_P, SECP256K1_P)
    m %= SECP256K1_P

    x3 = (m * m - x1 - x2) % SECP256K1_P
    y3 = (m * (x1 - x3) - y1) % SECP256K1_P
    return (x3, y3)


def secp256k1_scalar_mul(k: int, point: Point) -> Point:
    if k % SECP256K1_N == 0 or point is None:
        return None
    if k < 0:
        raise ValueError("negative scalar not supported")
    if not is_on_secp256k1(point):
        raise ValueError("point not on curve")

    acc = None
    addend = point
    while k:
        if k & 1:
            acc = secp256k1_point_add(acc, addend)
        addend = secp256k1_point_add(addend, addend)
        k >>= 1
    return acc


def secp256k1_public_key_uncompressed(privkey: int) -> bytes:
    if not (1 <= privkey < SECP256K1_N):
        raise ValueError("invalid secp256k1 private key")
    g = (SECP256K1_GX, SECP256K1_GY)
    pub = secp256k1_scalar_mul(privkey, g)
    if pub is None:
        raise ValueError("unexpected point at infinity")
    x, y = pub
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def _bits2int(b: bytes, qlen: int) -> int:
    i = int.from_bytes(b, "big")
    blen = len(b) * 8
    if blen > qlen:
        i >>= blen - qlen
    return i


def _int2octets(x: int, rolen: int) -> bytes:
    return x.to_bytes(rolen, "big")


def _bits2octets(b: bytes, q: int) -> bytes:
    qlen = q.bit_length()
    z1 = _bits2int(b, qlen)
    z2 = z1 % q
    rolen = (qlen + 7) // 8
    return _int2octets(z2, rolen)


def _rfc6979_generate_k(msg_hash: bytes, x: int, q: int, hashfunc=hashlib.sha256) -> int:
    qlen = q.bit_length()
    rolen = (qlen + 7) // 8
    bx = _int2octets(x, rolen) + _bits2octets(msg_hash, q)

    v = b"\x01" * hashfunc().digest_size
    k = b"\x00" * hashfunc().digest_size

    k = hmac.new(k, v + b"\x00" + bx, hashfunc).digest()
    v = hmac.new(k, v, hashfunc).digest()
    k = hmac.new(k, v + b"\x01" + bx, hashfunc).digest()
    v = hmac.new(k, v, hashfunc).digest()

    while True:
        t = b""
        while len(t) < rolen:
            v = hmac.new(k, v, hashfunc).digest()
            t += v
        secret = _bits2int(t, qlen)
        if 1 <= secret < q:
            return secret
        k = hmac.new(k, v + b"\x00", hashfunc).digest()
        v = hmac.new(k, v, hashfunc).digest()


def ecdsa_sign_rfc6979(privkey: int, msg_hash: bytes) -> tuple[int, int]:
    if not (1 <= privkey < SECP256K1_N):
        raise ValueError("invalid secp256k1 private key")
    if len(msg_hash) != 32:
        raise ValueError("expected a 32-byte message hash")

    z = _bytes_to_int(msg_hash)
    g = (SECP256K1_GX, SECP256K1_GY)

    while True:
        k = _rfc6979_generate_k(msg_hash, privkey, SECP256K1_N, hashlib.sha256)
        p = secp256k1_scalar_mul(k, g)
        if p is None:
            continue
        r = p[0] % SECP256K1_N
        if r == 0:
            continue
        s = (_inv_mod(k, SECP256K1_N) * (z + r * privkey)) % SECP256K1_N
        if s == 0:
            continue
        return r, s


def ecdsa_verify(pubkey_uncompressed: bytes, msg_hash: bytes, signature: tuple[int, int]) -> bool:
    if len(pubkey_uncompressed) != 65 or pubkey_uncompressed[0] != 0x04:
        return False
    if len(msg_hash) != 32:
        return False
    r, s = signature
    if not (1 <= r < SECP256K1_N and 1 <= s < SECP256K1_N):
        return False

    x = int.from_bytes(pubkey_uncompressed[1:33], "big")
    y = int.from_bytes(pubkey_uncompressed[33:65], "big")
    q = (x, y)
    if not is_on_secp256k1(q):
        return False

    z = _bytes_to_int(msg_hash)
    w = _inv_mod(s, SECP256K1_N)
    u1 = (z * w) % SECP256K1_N
    u2 = (r * w) % SECP256K1_N
    g = (SECP256K1_GX, SECP256K1_GY)
    p = secp256k1_point_add(secp256k1_scalar_mul(u1, g), secp256k1_scalar_mul(u2, q))
    if p is None:
        return False
    return (p[0] % SECP256K1_N) == r


def der_encode_ecdsa_signature(r: int, s: int) -> bytes:
    def enc_int(x: int) -> bytes:
        if x <= 0:
            raise ValueError("ECDSA r,s must be positive")
        b = x.to_bytes((x.bit_length() + 7) // 8, "big")
        if b[0] & 0x80:
            b = b"\x00" + b
        return b"\x02" + bytes([len(b)]) + b

    r_enc = enc_int(r)
    s_enc = enc_int(s)
    seq = r_enc + s_enc
    return b"\x30" + bytes([len(seq)]) + seq


def ecdsa_normalize_low_s(signature: tuple[int, int]) -> tuple[int, int]:
    r, s = signature
    if not (1 <= r < SECP256K1_N and 1 <= s < SECP256K1_N):
        raise ValueError("invalid ECDSA signature")
    if s > SECP256K1_N // 2:
        s = SECP256K1_N - s
    return r, s


def ecdsa_sign_sha256_der(privkey: int, message: bytes) -> str:
    sig = ecdsa_sign_rfc6979(privkey, sha256(message))
    r, s = ecdsa_normalize_low_s(sig)
    return der_encode_ecdsa_signature(r, s).hex().upper()
```

### Step 3: Ethereum address derivation
Ethereum addresses are the last 20 bytes of `keccak256(pubkey_xy)`. EIP-55 is a checksum encoded in capitalization.

```python
def ethereum_address_from_pubkey_uncompressed(pubkey_uncompressed: bytes) -> str:
    if len(pubkey_uncompressed) != 65 or pubkey_uncompressed[0] != 0x04:
        raise ValueError("expected 65-byte uncompressed public key with 0x04 prefix")
    h = keccak_256(pubkey_uncompressed[1:])
    return "0x" + h[-20:].hex()


def eip55_checksum_address(address_hex: str) -> str:
    addr = address_hex.lower()
    if addr.startswith("0x"):
        addr = addr[2:]
    if len(addr) != 40 or any(c not in "0123456789abcdef" for c in addr):
        raise ValueError("expected 20-byte hex address (40 hex chars)")
    h = keccak_256(addr.encode("ascii")).hex()
    out = []
    for i, c in enumerate(addr):
        if c in "abcdef" and int(h[i], 16) >= 8:
            out.append(c.upper())
        else:
            out.append(c)
    return "0x" + "".join(out)
```

### Step 4: EIP-191 personal_sign message hash
Wallet “sign message” flows usually sign a prefixed hash (EIP-191), not raw bytes.

```python
def eip191_personal_message_hash(message: bytes) -> bytes:
    prefix = b"\x19Ethereum Signed Message:\n" + str(len(message)).encode("ascii") + message
    return keccak_256(prefix)
```

Run it:

```bash
python3 code/main.py
```

## Use It
Production equivalents (don’t ship the from-scratch code):

| Task | Production choice | Notes |
|---|---|---|
| Keccak-256 | `eth-hash` / `Crypto.Hash.keccak` | Python’s `hashlib.sha3_256` is **not** Keccak-256 |
| secp256k1 + ECDSA | `coincurve` / `cryptography` (secp256k1 curve support) | Use constant-time implementations |
| Addresses + EIP-55 | `eth_utils.to_checksum_address` | Also validates formatting |
| Message signing | `eth_account` / wallets | Prefer EIP-712 typed data when possible |

## Pitfalls
- Using `hashlib.sha3_256` and calling it “keccak256” — it will silently mismatch real Ethereum hashes.
- Hashing the **hex string** of a public key/address instead of the raw bytes (or vice versa).
- Including the `0x04` prefix in the public key when deriving an address (Ethereum excludes it).
- Accepting non-canonical ECDSA signatures (e.g., “high-s” malleability) when a protocol expects canonicalized signatures.
- Mixing up EIP-191 (`personal_sign`) vs signing a raw transaction hash vs EIP-712 typed data.

## Ship It
Save the reusable checklist in `outputs/ethereum-crypto-review-checklist.md` and use it when:
- reviewing wallet/contract integrations,
- debugging mismatched signatures or addresses,
- auditing “keccak256 / sha3” usage in codebases.

## Exercises
1. Easy: Run `python3 code/main.py`. Observe how `keccak256("")` differs from `sha3_256("")`.
2. Medium: Change `msg = b"hello"` to `msg = b"hello!"` and observe how the EIP-191 personal hash and signature change.
3. Hard: Demonstrate ECDSA malleability by showing that `(r, s)` and `(r, n−s)` both verify, then decide where your code should enforce “low-s”.

## Key Terms
| Term | What people say | What it actually means |
|---|---|---|
| Keccak-256 | “Ethereum SHA3” | Keccak sponge with Ethereum’s padding (different from FIPS SHA-3) |
| secp256k1 | “Bitcoin curve” | Specific elliptic curve over a prime field used for ECDSA |
| ECDSA | “Sign with private key” | A signature scheme over an elliptic-curve group |
| EIP-55 | “Checksummed address” | Capitalization-based checksum over the lowercase address string |
| EIP-191 | “personal_sign” | Prefix-based message hashing to prevent signing ambiguous payloads |

## Further Reading
- Gavin Wood et al., *Ethereum Yellow Paper* — formal spec; includes address derivation and Keccak usage
- Buterin & Van de Sande, *EIP-55: Mixed-case checksum address encoding* — checksum algorithm
- SECG, *SEC 2: Recommended Elliptic Curve Domain Parameters* — secp256k1 parameters
- Pornin, *RFC 6979: Deterministic Usage of DSA and ECDSA* — deterministic nonces
- Antonopoulos & Wood, *Mastering Ethereum*, Chapter 4 — Keccak vs SHA3 + EIP-55 worked example
