# Bytes, Hex, Base64 — Encoding Hygiene

> Most crypto bugs start as “string vs bytes” bugs. Encode at the boundary, use bytes internally, and be strict when decoding.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 00 · 01 (Dev Environment)
**Time:** ~45 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Distinguish between encoding (hex, base64) and encryption, and explain why encoding provides no secrecy
- Implement hex encoding and decoding from scratch using nibble-level bit manipulation
- Implement base64 encoding and decoding from scratch including padding rules for non-multiple-of-3 inputs
- Apply strict boundary decoding rules to reject non-canonical hex and base64 inputs in cryptographic contexts
- Identify common encoding bugs that lead to security vulnerabilities, such as signing a string instead of its decoded bytes

## The Problem

Cryptography is a bytes-in / bytes-out discipline.

- hashes, MACs, signatures, keys, ciphertexts: all **bytes**
- most “real world” formats: all **text** (JSON, HTTP headers, env vars, YAML)

So you keep crossing the boundary:

- an RFC gives you a test vector as **hex**
- a web API gives you a key as **base64**
- your code expects **bytes**

If you don’t have encoding hygiene, you will eventually ship one of these:

- you hash the **string** `"Zm9v"` instead of the **bytes** `b"foo"`
- you compare two **hex strings** case-insensitively and accidentally accept a non-canonical value
- you accept “loose” base64 (missing padding / whitespace) and create multiple spellings of the “same” key
- you log secrets because they “look harmless” in hex/base64

This lesson makes you fluent in the three representations you will use constantly in later phases: `bytes`, hex, base64.

## The Concept

### Encoding is not encryption

Hex and base64 are **encodings**: reversible ways to represent bytes using printable characters.

- Encoding answers: “How do I *represent* these bytes in text?”
- Encryption answers: “How do I *hide* these bytes from an attacker?”

### The boundary diagram

Keep one invariant: **inside your crypto code, everything is bytes**.

```
           (human / JSON / CLI / RFC)
text (str) ------------------------------+
  |                                      |
  | encode (UTF-8)                       | decode (hex/base64)
  v                                      v
bytes (b"...")  <--------------------  bytes (decoded)
  |
  | encode (hex/base64) for transport
  v
text (ASCII)
```

### When to use what

| Representation | Good for | Bad for |
|---|---|---|
| `bytes` | internal crypto operations | printing / JSON |
| hex | RFC vectors, debugging, short IDs | large payloads (2× expansion) |
| base64 | compact transport (4/3 expansion) | human eyeballing; “looks like text” foot-guns |

### Canonical forms matter

In security code, “multiple spellings of the same value” is a bug.

- hex: decide on lowercase vs uppercase, no whitespace, no `0x`, even length
- base64: decide if you require `=` padding, no whitespace, standard alphabet vs urlsafe

When decoding, be strict unless you have a strong reason not to.

## Build It

All code for this lesson lives in `code/main.py`.

### Step 1: bytes ⇄ text (UTF-8)

Python separates **text** (`str`) from **bytes** (`bytes`). Crypto wants bytes.

```python
def to_bytes(text: str, *, encoding: str = "utf-8") -> bytes:
    return text.encode(encoding)

def from_bytes(data: bytes, *, encoding: str = "utf-8", errors: str = "strict") -> str:
    return data.decode(encoding, errors=errors)
```

Rule: decode bytes to text only when you know the bytes are really that encoding (usually UTF-8). Otherwise keep bytes.

### Step 2: hex encode/decode (from scratch)

Hex is base-16 with a 1-byte → 2-hex-character mapping:

- each byte is two nibbles: `hi = b >> 4`, `lo = b & 0x0F`
- each nibble maps to a character in `0123456789abcdef` (or uppercase)

```python
_HEX_LOWER = "0123456789abcdef"

def hex_encode(data: bytes, *, uppercase: bool = False) -> str:
    alphabet = "0123456789ABCDEF" if uppercase else _HEX_LOWER
    out = []
    for b in data:
        out.append(alphabet[b >> 4])
        out.append(alphabet[b & 0x0F])
    return "".join(out)
```

For decoding, be strict: even length, and only `[0-9a-fA-F]`.

### Step 3: base64 encode/decode (from scratch)

Base64 packs bytes into 6-bit digits.

```
3 bytes = 24 bits  ->  4 base64 chars (4 × 6 bits)

aaaa aabb  bbbb cccc  ccdd dddd  (bit groups)
```

Padding (`=`) exists because input length may not be a multiple of 3:

- 1 leftover byte ⇒ output ends with `==`
- 2 leftover bytes ⇒ output ends with `=`

### Step 4: strict decoding (the hygiene part)

In cryptographic contexts, treat decoding like parsing:

- reject non-hex / non-base64 characters
- reject odd-length hex
- reject base64 with “weird” padding (`=` only at the end, only in the final 4-char block)

You can always build a “loose” decoder later for interoperability. Start strict.

Run it:

```
python3 code/main.py
```

## Use It

Your from-scratch code builds intuition. For real work, prefer standard libraries:

```python
import base64
import binascii

hx = binascii.hexlify(b"foo").decode("ascii")   # "666f6f"
b = binascii.unhexlify(hx)                      # b"foo"

s = base64.b64encode(b"foo").decode("ascii")    # "Zm9v"
b = base64.b64decode(s, validate=True)          # b"foo"
```

Two practical rules:

1. Decode at the boundary (JSON/env/CLI/RFC) and carry bytes internally.
2. When comparing secrets, compare **bytes**, not encodings (`hmac.compare_digest` is your friend).

## Attack It

Encoding bugs are attacker-controlled input bugs. Two common failure modes:

### Attack 1: “base64 is encryption”

If you store secrets as base64 because “it looks random”, you created a secret that can be recovered by anyone who can read the string.

Base64 is not secrecy. It’s a printable wrapper around bytes.

### Attack 2: sign the wrong thing (string vs bytes)

If you sign an API field as a base64 string, but a verifier later decodes and re-encodes (or allows missing padding), you can end up with multiple string spellings for the same bytes.

Security rule: if the “real value” is bytes, sign/verify the bytes, not a presentation string.

## Ship It

This lesson ships a reusable review prompt:

- `outputs/prompt-encoding-hygiene-checklist.md`

Use it whenever you review code that parses hex/base64 keys, hashes, signatures, ciphertexts, or test vectors.

## Exercises

1. Easy: take a byte string, print it as hex and base64, then round-trip back to the original bytes.
2. Medium: write a “loose” base64 decoder that allows missing padding and whitespace, then explain why you would not use it in signature verification code.
3. Hard: find a place in your own code (or a library) that logs secrets as hex/base64, and write a safer logging rule for it.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| bytes | “binary string” | raw 8-bit values (`0..255`) |
| text encoding | “UTF-8 is just bytes” | mapping between Unicode text and bytes |
| hex | “encryption” | base16 encoding of bytes |
| base64 | “hash-looking string” | base64 encoding of bytes (not secret) |
| canonical form | “same value” | one unique spelling accepted by your protocol |

## Test Vectors

Source: RFC 4648 (Base-N Encodings), Section 10.

Code must pass all vectors in `tests/vectors.json`.

## Further Reading

- [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648) — base16/base32/base64 definitions and test vectors
- [Python `base64`](https://docs.python.org/3/library/base64.html) and [Python `binascii`](https://docs.python.org/3/library/binascii.html) — standard encoders/decoders
