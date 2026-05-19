# Authenticated Encryption (AEAD) — GCM, CCM, OCB
> Encrypt the message, authenticate the whole context.

**Type:** Build
**Languages:** Python
**Prerequisites:** `07-symmetric-crypto/05-aes`, `07-symmetric-crypto/06-block-cipher-modes`
**Time:** ~90 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** what AEAD protects (and what it doesn’t)
- **Compute** how GCM builds a tag from AAD and ciphertext
- **Implement** AES-GCM (encrypt + decrypt + verify) from scratch
- **Distinguish** GCM vs CCM vs OCB at a design level
- **Apply** a nonce/AAD checklist to real APIs

## The Problem

You encrypt an API request body with AES-CTR (or AES-CBC) and ship it over the network. It “looks random”, so you assume it’s safe. A week later, you learn that encryption alone does **not** stop attackers from modifying the ciphertext. In many modes, a bit flip in ciphertext causes a predictable bit flip in the decrypted plaintext — which is enough to change `"role=user"` into `"role=admin"` or `"amount=1000"` into `"amount=9000"`.

To fix this, teams often “add a MAC”… and then accidentally MAC the wrong thing, MAC the plaintext instead of the ciphertext, forget to authenticate headers/metadata, reuse a nonce, or verify the MAC too late. AEAD modes (Authenticated Encryption with Associated Data) exist to make the *right* combination the default: confidentiality + integrity + authenticity, with explicit support for authenticating unencrypted metadata (AAD).

## The Concept

An **AEAD** takes four inputs:

- `key` — secret
- `nonce` (aka IV) — public but must be **unique per key**
- `plaintext` — encrypted + authenticated
- `aad` — authenticated but not encrypted (e.g., headers, record ids, protocol version)

And it returns:

- `ciphertext` — same length as plaintext (for CTR-like modes)
- `tag` — authentication tag (a MAC bound to `nonce || aad || ciphertext`)

Three popular AEADs:

| Mode | Rough structure | Why people pick it |
|------|------------------|--------------------|
| **GCM** | `CTR` encryption + `GHASH` authentication | Fast with hardware; common in TLS/IPsec; very sensitive to nonce reuse |
| **CCM** | `CTR` encryption + `CBC-MAC` authentication | Simpler building blocks; common in constrained/IoT protocols |
| **OCB** | one-pass offset-based design | Very efficient (one pass) and elegant; check standardization / licensing constraints for your environment |

In **GCM**, the key idea is:

- Encryption is AES-CTR (so nonce reuse leaks `pt1 ^ pt2`).
- Authentication is a polynomial hash over `GF(2^128)` (GHASH) of `aad` and `ciphertext`.
- The final tag is derived by encrypting a nonce-derived block and XORing GHASH output.

## Build It

### Step 1: AES block encryption
```python
def aes_expand_key(key: bytes) -> list[bytes]:
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes")
    nk = len(key) // 4
    nr = nk + 6
    nb = 4

    w: list[bytes] = [b""] * (nb * (nr + 1))
    for i in range(nk):
        w[i] = key[4 * i : 4 * i + 4]

    for i in range(nk, nb * (nr + 1)):
        temp = w[i - 1]
        if i % nk == 0:
            temp = _sub_word(_rot_word(temp))
            temp = bytes([temp[0] ^ RCON[i // nk], temp[1], temp[2], temp[3]])
        elif nk > 6 and i % nk == 4:
            temp = _sub_word(temp)
        w[i] = _xor_bytes(w[i - nk], temp)

    round_keys: list[bytes] = []
    for r in range(nr + 1):
        round_keys.append(b"".join(w[4 * r : 4 * r + 4]))
    return round_keys


def aes_encrypt_block(key: bytes, block: bytes) -> bytes:
    if len(block) != 16:
        raise ValueError("AES block must be 16 bytes")
    round_keys = aes_expand_key(key)
    nr = len(round_keys) - 1

    state = _bytes_to_state(block)
    _add_round_key(state, round_keys[0])

    for r in range(1, nr):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[r])

    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, round_keys[nr])
    return _state_to_bytes(state)
```
This provides the 16-byte “core permutation” that we’ll use both for CTR keystream generation and for the GCM tag derivation.

### Step 2: CTR keystream (GCTR) with a 32-bit counter
```python
def inc32(block: bytes) -> bytes:
    if len(block) != 16:
        raise ValueError("inc32 expects 16 bytes")
    prefix = block[:12]
    ctr = int.from_bytes(block[12:], "big")
    ctr = (ctr + 1) & 0xFFFFFFFF
    return prefix + ctr.to_bytes(4, "big")


def gctr(key: bytes, icb: bytes, data: bytes) -> bytes:
    if len(icb) != 16:
        raise ValueError("icb must be 16 bytes")
    if not data:
        return b""

    out = bytearray()
    cb = icb
    for block in _chunks(data, 16):
        stream = aes_encrypt_block(key, cb)
        out.extend(_xor_bytes(block, stream[: len(block)]))
        cb = inc32(cb)
    return bytes(out)
```
CTR mode is “XOR with a keystream”: `ciphertext = plaintext ^ stream`. That makes it fast and parallel — and also means nonce reuse turns it into a two-time pad.

### Step 3: GHASH (polynomial hashing in GF(2^128))
```python
def gf128_mul(x: int, y: int) -> int:
    if x < 0 or x >= 1 << 128 or y < 0 or y >= 1 << 128:
        raise ValueError("gf128_mul inputs must be 128-bit integers")
    r = 0xE1000000000000000000000000000000
    z = 0
    v = x
    for i in range(128):
        if (y >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ r
        else:
            v >>= 1
    return z


def ghash(h: bytes, data: bytes) -> bytes:
    if len(h) != 16:
        raise ValueError("H must be 16 bytes")
    if len(data) % 16 != 0:
        raise ValueError("GHASH input must be a multiple of 16 bytes (pad before calling)")
    h_int = _from_u128be(h)
    y = 0
    for block in _chunks(data, 16):
        y ^= _from_u128be(block)
        y = gf128_mul(y, h_int)
    return _u128be(y)
```
GHASH authenticates `aad` and `ciphertext` together. It’s not a general-purpose hash; it’s a *keyed* hash designed specifically for GCM.

### Step 4: AES-GCM encrypt/decrypt (AEAD)
```python
def gcm_encrypt(
    key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"", tag_len: int = 16
) -> tuple[bytes, bytes]:
    if len(nonce) != 12:
        raise ValueError("this educational implementation supports 12-byte nonces only")
    if tag_len != 16:
        raise ValueError("this educational implementation supports 16-byte tags only")

    h = aes_encrypt_block(key, b"\x00" * 16)
    j0 = nonce + b"\x00\x00\x00\x01"
    ciphertext = gctr(key, inc32(j0), plaintext)

    a_padded = _pad16(aad)
    c_padded = _pad16(ciphertext)
    lengths = _u64be(len(aad) * 8) + _u64be(len(ciphertext) * 8)
    s = ghash(h, a_padded + c_padded + lengths)
    tag = gctr(key, j0, s)
    return ciphertext, tag


def gcm_decrypt(
    key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes, tag: bytes
) -> bytes:
    if len(tag) != 16:
        raise ValueError("tag must be 16 bytes")
    pt = gctr(key, inc32(nonce + b"\x00\x00\x00\x01"), ciphertext)
    _, computed_tag = gcm_encrypt(key, nonce, pt, aad=aad, tag_len=16)
    if not hmac.compare_digest(computed_tag, tag):
        raise ValueError("authentication failed")
    return pt
```
This is the AEAD contract: decryption must *verify the tag* (and reject on failure) before treating the plaintext as valid.

### Step 5: Pack `nonce|ciphertext|tag` for transport
```python
@dataclass(frozen=True)
class PackedAEAD:
    nonce: bytes
    ciphertext: bytes
    tag: bytes

    def to_bytes(self) -> bytes:
        return self.nonce + self.ciphertext + self.tag

    @staticmethod
    def from_bytes(data: bytes, nonce_len: int = 12, tag_len: int = 16) -> "PackedAEAD":
        if len(data) < nonce_len + tag_len:
            raise ValueError("packed message too short")
        nonce = data[:nonce_len]
        tag = data[-tag_len:]
        ciphertext = data[nonce_len:-tag_len]
        return PackedAEAD(nonce=nonce, ciphertext=ciphertext, tag=tag)
```
Real systems have to serialize AEAD outputs. A common pattern is `nonce || ciphertext || tag` (and you must define exact lengths and endianness in a spec).

Run it:
python3 code/main.py

## Use It

Use audited libraries in production. Example equivalents:

- **PyCryptodome (Python)**: `AES.new(key, AES.MODE_GCM, nonce=nonce)` then `encrypt_and_digest()` / `decrypt_and_verify()`
- **OpenSSL (C)**: EVP API (`EVP_aes_128_gcm`, `EVP_EncryptUpdate`, `EVP_CIPHER_CTX_ctrl` for tag)
- **TLS stacks**: almost always use AEAD suites by default

For CCM and OCB, see the standards below:

- CCM is standardized by NIST (SP 800-38C)
- OCB is standardized by the IETF (RFC 7253)

## Pitfalls

- **Nonce reuse** (same `key` + same `nonce`) breaks confidentiality for GCM/CCM/OCB-style CTR encryption.
- **Not verifying the tag** (or verifying it too late) turns AEAD back into unauthenticated encryption.
- **Incorrect AAD**: forgetting to authenticate metadata (ids, protocol version, algorithm choices) enables substitution attacks.
- **Truncated tags without a threat model**: short tags reduce integrity; they can be fine in some settings, but must be justified.
- **Treating “IV” as secret**: nonces/IVs are usually public; design formats and storage accordingly.

## Ship It

This lesson ships a PR-review artifact: an AEAD decision guide + checklist.

- Open `outputs/aead-review-checklist.md`
- Use it when reviewing any code that encrypts or decrypts application data
- Paste the checklist into a PR description and mark each item explicitly

## Exercises

1. Easy. Run `python3 code/main.py`. Observe that nonce reuse leaks `ct1 ^ ct2 == pt1 ^ pt2`.
2. Medium. Extend `PackedAEAD` to include a 1-byte version field and treat it as AAD (authenticated, not encrypted).
3. Hard. Integrate AES-GCM from a real library (PyCryptodome or OpenSSL) and cross-check against `tests/vectors.json`.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| AEAD | “encryption with a MAC” | One API that provides confidentiality + integrity + authenticity, plus AAD |
| Nonce / IV | “random bytes” | Public value that must be unique per key (random is one way to get uniqueness) |
| AAD | “headers” | Data that stays in the clear but is authenticated by the tag |
| Tag | “MAC” | Short authenticator bound to `(nonce, aad, ciphertext)` under the key |
| GCM / CCM / OCB | “modes” | AEAD constructions that combine encryption + authentication in specific ways |

## Further Reading

- NIST, *Recommendation for Block Cipher Modes of Operation: GCM and GMAC* (SP 800-38D)
- NIST, *Recommendation for Block Cipher Modes of Operation: the CCM Mode* (SP 800-38C)
- IETF, *The OCB Authenticated-Encryption Algorithm* (RFC 7253)
