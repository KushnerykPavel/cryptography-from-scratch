# Stream Ciphers — ChaCha20 from Scratch
> Encrypt by XORing with a keystream — and never reuse the same `(key, nonce)`.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 07 · 01 (One-Time Pad)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain why stream ciphers are “XOR with a pseudorandom keystream”.
- Distinguish key vs nonce vs counter — and state the uniqueness rule.
- Implement the ChaCha20 quarter round and 20-round block function.
- Compute keystream bytes and apply them to encrypt/decrypt data.
- Apply a real-world integration checklist to avoid nonce-reuse and missing integrity.

## The Problem

You want fast encryption for arbitrary-length data: chat messages, files, video, database fields, or network packets. A one-time pad would be perfect — XOR plaintext with truly random bytes — except generating and distributing a one-time pad as long as every message is impractical.

Stream ciphers solve the “OTP but reusable” problem: they generate a long keystream from a short secret key. But they also introduce a new foot-gun: **if you ever reuse the same keystream for two different messages, you get the two-time pad failure** (`c1 ⊕ c2 = p1 ⊕ p2`). In real systems, that keystream reuse usually comes from a nonce bug: repeated nonces, counter wraparound, or “random nonces” without collision planning.

This lesson gives you a concrete, modern stream cipher (ChaCha20), shows the exact bytes it produces (RFC test vectors), and demonstrates the classic keystream-reuse attack so you can recognize and prevent it in production designs.

## The Concept

### Stream cipher = keystream generator + XOR

A stream cipher turns a short secret key into a long pseudorandom keystream:

```
keystream = StreamCipher(key, nonce, counter, length)
ciphertext = plaintext XOR keystream
plaintext  = ciphertext XOR keystream
```

XOR is its own inverse. Encryption and decryption are the same operation.

### Key vs nonce vs counter

| Item | Secret? | Size (ChaCha20-IETF) | What it’s for |
|------|---------|----------------------|---------------|
| key | yes | 32 bytes | the long-term secret |
| nonce | no | 12 bytes | ensures keystream uniqueness per message |
| counter | no | 4 bytes | selects which 64-byte keystream block you’re in |

**The rule that keeps you safe:** never reuse the same `(key, nonce)` pair. If you do, the keystream repeats, and the two-time pad leak appears.

### Why ChaCha20 (and not RC4)

RC4 is historically important and widely broken in practice due to biases and protocol misuse. ChaCha20 is modern, fast in software, and standardized for Internet protocols.

ChaCha20 generates keystream in **64-byte blocks**. Each block is produced by mixing a 16-word (16×32-bit) state with ARX operations: **A**ddition mod 2³², **R**otation, and **X**OR.

## Build It

### Step 1: XOR with a keystream (bytes + hex utilities)
```python
def xor_bytes(a: bytes, b: bytes) -> bytes:
    a = _require_bytes(a, "a")
    b = _require_bytes(b, "b")
    if len(a) != len(b):
        raise ValueError("inputs must have the same length")
    return bytes(x ^ y for x, y in zip(a, b))


def xor_with_keystream(data: bytes, keystream: bytes) -> bytes:
    data = _require_bytes(data, "data")
    keystream = _require_bytes(keystream, "keystream")
    if len(keystream) < len(data):
        raise ValueError("keystream must be at least as long as data")
    return bytes(x ^ y for x, y in zip(data, keystream[: len(data)]))
```
This is the entire stream-cipher interface: generate a keystream, XOR it with data. Everything else in this lesson is about generating a keystream that “looks random” to an attacker.

### Step 2: ChaCha20 quarter round (ARX mixing)
```python
def rotl32(x: int, n: int) -> int:
    x = _require_int(x, "x")
    n = _require_int(n, "n")
    if n < 0 or n >= 32:
        raise ValueError("n must be in [0, 31]")
    x &= U32_MASK
    return ((x << n) & U32_MASK) | (x >> (32 - n))


def quarter_round(a: int, b: int, c: int, d: int) -> tuple[int, int, int, int]:
    a = _require_int(a, "a") & U32_MASK
    b = _require_int(b, "b") & U32_MASK
    c = _require_int(c, "c") & U32_MASK
    d = _require_int(d, "d") & U32_MASK

    a = (a + b) & U32_MASK
    d ^= a
    d = rotl32(d, 16)

    c = (c + d) & U32_MASK
    b ^= c
    b = rotl32(b, 12)

    a = (a + b) & U32_MASK
    d ^= a
    d = rotl32(d, 8)

    c = (c + d) & U32_MASK
    b ^= c
    b = rotl32(b, 7)

    return a, b, c, d
```
The quarter round is the fundamental ChaCha operation. The full block function applies it in a specific pattern (columns then diagonals) for 20 rounds total.

### Step 3: The ChaCha20 block function (64 keystream bytes)
```python
def _chacha20_state(key: bytes, counter: int, nonce: bytes) -> list[int]:
    key = _require_bytes(key, "key")
    nonce = _require_bytes(nonce, "nonce")
    counter = _require_int(counter, "counter")

    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")
    if counter < 0 or counter > U32_MASK:
        raise ValueError("counter must be a 32-bit unsigned integer")

    constants = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    key_words = [_le_u32_to_int(key[i : i + 4]) for i in range(0, 32, 4)]
    nonce_words = [_le_u32_to_int(nonce[i : i + 4]) for i in range(0, 12, 4)]
    return constants + key_words + [counter] + nonce_words


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    state = _chacha20_state(key, counter, nonce)
    working = _rounds_20(state)
    out_words = [(w + s) & U32_MASK for w, s in zip(working, state)]
    return b"".join(_int_to_le_u32(w) for w in out_words)
```
This takes `(key, nonce, counter)` and outputs **exactly 64 bytes** of keystream (one block). It’s also the piece you can validate against RFC 8439 test vectors.

### Step 4: Keystream → encryption, plus the nonce-reuse disaster
```python
def chacha20_keystream(key: bytes, nonce: bytes, initial_counter: int, length: int) -> bytes:
    key = _require_bytes(key, "key")
    nonce = _require_bytes(nonce, "nonce")
    initial_counter = _require_int(initial_counter, "initial_counter")
    length = _require_int(length, "length")

    if length < 0:
        raise ValueError("length must be >= 0")
    if initial_counter < 0 or initial_counter > U32_MASK:
        raise ValueError("initial_counter must be a 32-bit unsigned integer")

    blocks: list[bytes] = []
    remaining = length
    counter = initial_counter
    while remaining > 0:
        blocks.append(chacha20_block(key, counter, nonce))
        counter = (counter + 1) & U32_MASK
        remaining -= 64
    return b"".join(blocks)[:length]


def chacha20_encrypt(plaintext: bytes, key: bytes, nonce: bytes, initial_counter: int = 1) -> bytes:
    plaintext = _require_bytes(plaintext, "plaintext")
    keystream = chacha20_keystream(key, nonce, initial_counter, len(plaintext))
    return xor_with_keystream(plaintext, keystream)


def chacha20_decrypt(ciphertext: bytes, key: bytes, nonce: bytes, initial_counter: int = 1) -> bytes:
    ciphertext = _require_bytes(ciphertext, "ciphertext")
    keystream = chacha20_keystream(key, nonce, initial_counter, len(ciphertext))
    return xor_with_keystream(ciphertext, keystream)
```
To encrypt arbitrary-length data, you concatenate enough 64-byte blocks to match the message length, then XOR. If you ever reuse the same `(key, nonce)` for two messages, the keystream repeats and you recreate the two-time pad (`c1 ⊕ c2 = p1 ⊕ p2`).

Run it:
`python3 code/main.py`

## Use It

Prefer an audited library and prefer an **AEAD** construction (stream cipher + authenticator), e.g. ChaCha20-Poly1305.

- **libsodium**: `crypto_aead_chacha20poly1305_ietf_*` (recommended), `crypto_stream_chacha20_xor_*` (raw stream; avoid unless you add integrity separately).
- **Python `cryptography`**: `cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305`.
- **RustCrypto**: `chacha20` + `poly1305` crates, or higher-level AEAD crate `chacha20poly1305`.

## Pitfalls

1. **Nonce reuse** (same key, same nonce) — catastrophic: `c1 ⊕ c2 = p1 ⊕ p2`.
2. **No integrity** — stream ciphers are malleable: flipping a ciphertext bit flips the corresponding plaintext bit.
3. **Counter reuse / wraparound** — ChaCha20 uses a 32-bit block counter; reusing a counter with the same `(key, nonce)` repeats keystream blocks.
4. **“Random nonce” without collision planning** — at scale, collisions happen; prefer deterministic nonces (counters) or track used nonces per key.
5. **Using RC4** — biases + protocol vulnerabilities; it’s obsolete.

## Ship It

Save the reusable checklist at `outputs/stream-cipher-integration-checklist.md`. Use it when:
- designing an encryption format (what goes on the wire),
- reviewing a PR that “adds encryption”,
- verifying nonce/counter rules and integrity coverage.

## Exercises

1. Easy: Run `python3 code/main.py`. Observe that nonce reuse makes `c1 ⊕ c2 = p1 ⊕ p2`.
2. Medium: Add a `seek` helper that decrypts from an arbitrary byte offset by computing the correct block counter and skipping bytes within the first block.
3. Hard: Replace raw ChaCha20 with an AEAD in a real library (e.g. libsodium or `cryptography`) and design a packet format that includes `nonce || ciphertext || tag`.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| keystream | “random bytes” | pseudorandom bytes derived from `(key, nonce, counter)` |
| nonce | “random IV” | non-secret uniqueness value; must not repeat per key |
| counter | “block number” | selects which 64-byte keystream block you’re using |
| malleability | “ciphertext can be edited” | bit flips in ciphertext cause predictable bit flips in plaintext |
| two-time pad | “OTP reuse attack” | reusing keystream leaks `p1 ⊕ p2` via `c1 ⊕ c2` |
| AEAD | “encryption + MAC” | scheme that provides confidentiality + integrity in one construction |

## Further Reading

- IETF, *RFC 8439: ChaCha20 and Poly1305 for IETF Protocols* (2018) — the standard you should implement/test against.
- Daniel J. Bernstein, *ChaCha, a variant of Salsa20* (2008) — design rationale and core primitive.
- Ferguson, Schneier, Kohno, *Cryptography Engineering* (2010) — practical “how not to shoot yourself” guidance.
