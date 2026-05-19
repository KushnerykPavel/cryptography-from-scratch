# BLAKE2 & BLAKE3
> BLAKE3 is “BLAKE2s + a Merkle tree”: fast, parallel, and an XOF by design.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 7 · 09 (SHA-256), Phase 7 · 10 (SHA-3 / Keccak)
**Time:** ~60 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** why BLAKE3’s tree structure avoids length extension and enables parallelism.
- **Compute** BLAKE2s digests (unkeyed + keyed) and validate the RFC 7693 self-test digest.
- **Implement** a correct BLAKE3 compression function and tree mode in pure Python (stdlib-only).
- **Distinguish** between `hash`, `keyed_hash`, and `derive_key` (domain separation and use-cases).
- **Apply** BLAKE3’s XOF output to derive fixed-size subkeys and verify file/content integrity.

## The Problem
You need a hash that is both *cryptographically strong* and *fast enough* to be used everywhere: content-addressed storage, file integrity, build caches, Git-like object IDs, deduplication, message authentication, and key derivation.

If you “just pick something” and treat it like a black box, real systems break in subtle ways:
- You might choose a hash that is vulnerable to **length extension** and accidentally build a broken MAC.
- You might truncate outputs too aggressively (e.g., 64-bit digests) and ship collision risks into IDs.
- You might mix up “hashing” with “key derivation” and end up with brittle, non-domain-separated keys.

BLAKE2 and BLAKE3 exist to make the *fast path* also the *safe path*: built-in keying, built-in XOF, and (for BLAKE3) built-in tree hashing for parallelism and verified streaming.

## The Concept
### BLAKE2 in one sentence
**BLAKE2 is a fast, modern hash with an optional built-in key, so it can act like a MAC without wrapping it in HMAC.**

In Python’s stdlib you get BLAKE2 as `hashlib.blake2s` and `hashlib.blake2b` (RFC 7693). Key features:
- variable digest size (1–32 bytes for BLAKE2s; 1–64 for BLAKE2b)
- optional key (keyed hashing / MAC-like)
- optional “personalization” / “salt” fields (domain separation for *hashing*, not passwords)

### BLAKE3 in one sentence
**BLAKE3 is a tree hash built on a BLAKE2s-like compression function, so it parallelizes well and is an XOF by default.**

Mental model: split input into **1024-byte chunks**, hash each chunk, then combine chunk hashes up a binary tree:

```
chunks (1 KiB each):  C0      C1      C2      C3
chunk CVs:            H0      H1      H2      H3
parents:                 P01      P23
root:                         R
output: XOF(R, counter=0,1,2,...) -> any length
```

Modes (domain-separated):

| Mode | Input | Secret? | What you get | Typical use |
|------|-------|---------|--------------|-------------|
| `hash` | bytes | No | digest / XOF | integrity, identifiers |
| `keyed_hash` | bytes + 32-byte key | Yes | MAC / PRF / XOF | authenticators, tokens |
| `derive_key` | context string + key material | Yes-ish | derived subkey(s) | subkeys for protocols |

## Build It
### Step 1: BLAKE2s in the stdlib + RFC 7693 self-test digest
Use `hashlib.blake2s` for real work, and validate you’re wired correctly by reproducing the RFC 7693 “hash of hashes” self-test digest.

```python
import hashlib

def _u32(x: int) -> int:
    return x & 0xFFFFFFFF

def blake2s_256(data: bytes) -> bytes:
    return hashlib.blake2s(data, digest_size=32).digest()

def _rfc7693_selftest_seq(length: int, seed: int) -> bytes:
    a = _u32(0xDEAD4BAD * seed)
    b = 1
    out = bytearray()
    for _ in range(length):
        t = _u32(a + b)
        a = b
        b = t
        out.append((t >> 24) & 0xFF)
    return bytes(out)

def blake2s_rfc7693_selftest_digest() -> bytes:
    md_lens = [16, 20, 28, 32]
    in_lens = [0, 3, 64, 65, 255, 1024]

    ctx = hashlib.blake2s(digest_size=32)
    for outlen in md_lens:
        for inlen in in_lens:
            msg = _rfc7693_selftest_seq(inlen, seed=inlen)
            ctx.update(hashlib.blake2s(msg, digest_size=outlen).digest())

            key = _rfc7693_selftest_seq(outlen, seed=outlen)
            ctx.update(hashlib.blake2s(msg, digest_size=outlen, key=key).digest())
    return ctx.digest()
```

This step gives you two “known good” anchors:
- `BLAKE2s-256("abc")` (simple KAT)
- `blake2s_selftest_digest()` (covers keyed/unkeyed and multiple input/output lengths)

### Step 2: Implement the BLAKE3 compression function
BLAKE3’s compression is a 32-bit ARX (add-rotate-xor) mixer, derived from BLAKE2s but reduced to 7 rounds and with a fixed message schedule per round.

```python
import struct

def _ror32(x: int, n: int) -> int:
    return ((x >> n) | ((x << (32 - n)) & 0xFFFFFFFF)) & 0xFFFFFFFF

def _words_from_le_bytes_32(b: bytes, count: int) -> list[int]:
    needed = count * 4
    if len(b) < needed:
        b = b + b"\x00" * (needed - len(b))
    return list(struct.unpack("<" + ("I" * count), b[:needed]))

IV = [
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
]

MSG_SCHEDULE = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
]

def _blake3_g(state: list[int], a: int, b: int, c: int, d: int, mx: int, my: int) -> None:
    state[a] = _u32(state[a] + state[b] + mx)
    state[d] = _ror32(state[d] ^ state[a], 16)
    state[c] = _u32(state[c] + state[d])
    state[b] = _ror32(state[b] ^ state[c], 12)
    state[a] = _u32(state[a] + state[b] + my)
    state[d] = _ror32(state[d] ^ state[a], 8)
    state[c] = _u32(state[c] + state[d])
    state[b] = _ror32(state[b] ^ state[c], 7)

def _blake3_round(state: list[int], msg: list[int], schedule: list[int]) -> None:
    _blake3_g(state, 0, 4, 8, 12, msg[schedule[0]], msg[schedule[1]])
    _blake3_g(state, 1, 5, 9, 13, msg[schedule[2]], msg[schedule[3]])
    _blake3_g(state, 2, 6, 10, 14, msg[schedule[4]], msg[schedule[5]])
    _blake3_g(state, 3, 7, 11, 15, msg[schedule[6]], msg[schedule[7]])

    _blake3_g(state, 0, 5, 10, 15, msg[schedule[8]], msg[schedule[9]])
    _blake3_g(state, 1, 6, 11, 12, msg[schedule[10]], msg[schedule[11]])
    _blake3_g(state, 2, 7, 8, 13, msg[schedule[12]], msg[schedule[13]])
    _blake3_g(state, 3, 4, 9, 14, msg[schedule[14]], msg[schedule[15]])

def blake3_compress(
    chaining_value_words: list[int],
    block_words: list[int],
    block_len: int,
    counter: int,
    flags: int,
) -> list[int]:
    state = list(chaining_value_words) + IV[:4] + [
        _u32(counter),
        _u32(counter >> 32),
        _u32(block_len),
        _u32(flags),
    ]

    for schedule in MSG_SCHEDULE:
        _blake3_round(state, block_words, schedule)

    for i in range(8):
        state[i] = _u32(state[i] ^ state[i + 8])
        state[i + 8] = _u32(state[i + 8] ^ chaining_value_words[i])
    return state
```

This is the “engine.” Everything else (tree hashing, XOF, keyed modes) builds on repeated calls to `blake3_compress`.

### Step 3: Implement chunking + the Merkle tree + XOF output
Now we wrap compression in the tree mode: 1024-byte chunks, a stack of subtree chaining values, and a root output function that can generate any number of bytes.

```python
from dataclasses import dataclass

BLOCK_LEN = 64
CHUNK_LEN = 1024
OUT_LEN = 32

CHUNK_START = 1 << 0
CHUNK_END = 1 << 1
PARENT = 1 << 2
ROOT = 1 << 3
KEYED_HASH = 1 << 4
DERIVE_KEY_CONTEXT = 1 << 5
DERIVE_KEY_MATERIAL = 1 << 6

def _le_bytes_from_words_32(words: list[int]) -> bytes:
    return b"".join(struct.pack("<I", _u32(w)) for w in words)

@dataclass(frozen=True)
class _Blake3Output:
    input_cv_words: list[int]
    block_bytes: bytes
    block_len: int
    counter: int
    flags: int

    def _block_words(self) -> list[int]:
        return _words_from_le_bytes_32(self.block_bytes, 16)

    def chaining_value_words(self) -> list[int]:
        words = blake3_compress(
            self.input_cv_words,
            self._block_words(),
            self.block_len,
            self.counter,
            self.flags,
        )
        return words[:8]

    def root_output_bytes(self, out_len: int) -> bytes:
        if out_len < 0:
            raise ValueError("out_len must be non-negative")
        out = bytearray()
        output_block_counter = 0
        block_words = self._block_words()
        while len(out) < out_len:
            words = blake3_compress(
                self.input_cv_words,
                block_words,
                self.block_len,
                output_block_counter,
                self.flags | ROOT,
            )
            out.extend(_le_bytes_from_words_32(words))
            output_block_counter += 1
        return bytes(out[:out_len])

class _Blake3ChunkState:
    def __init__(self, key_words: list[int], chunk_counter: int, flags: int):
        self._key_words = key_words
        self._chunk_counter = chunk_counter
        self._flags = flags
        self._cv_words = list(key_words)
        self._block = bytearray(b"\x00" * BLOCK_LEN)
        self._block_len = 0
        self._blocks_compressed = 0

    def length(self) -> int:
        return self._blocks_compressed * BLOCK_LEN + self._block_len

    def _start_flag(self) -> int:
        return CHUNK_START if self._blocks_compressed == 0 else 0

    def update(self, data: bytes) -> None:
        offset = 0
        while offset < len(data):
            if self._block_len == BLOCK_LEN:
                block_words = _words_from_le_bytes_32(bytes(self._block), 16)
                words = blake3_compress(
                    self._cv_words,
                    block_words,
                    BLOCK_LEN,
                    self._chunk_counter,
                    self._flags | self._start_flag(),
                )
                self._cv_words = words[:8]
                self._blocks_compressed += 1
                self._block_len = 0
                self._block[:] = b"\x00" * BLOCK_LEN

            want = BLOCK_LEN - self._block_len
            take = min(want, len(data) - offset)
            self._block[self._block_len : self._block_len + take] = data[offset : offset + take]
            self._block_len += take
            offset += take

    def output(self) -> _Blake3Output:
        output_flags = self._flags | self._start_flag() | CHUNK_END
        return _Blake3Output(
            input_cv_words=list(self._cv_words),
            block_bytes=bytes(self._block),
            block_len=self._block_len,
            counter=self._chunk_counter,
            flags=output_flags,
        )

def _blake3_parent_output(left_cv_words: list[int], right_cv_words: list[int], key_words: list[int], flags: int) -> _Blake3Output:
    block_words = list(left_cv_words) + list(right_cv_words)
    return _Blake3Output(
        input_cv_words=list(key_words),
        block_bytes=_le_bytes_from_words_32(block_words),
        block_len=BLOCK_LEN,
        counter=0,
        flags=flags | PARENT,
    )

def _blake3_add_chunk_cv(cv_stack: list[list[int]], new_cv_words: list[int], total_chunks: int, key_words: list[int], flags: int) -> None:
    chunk_counter = total_chunks
    while (chunk_counter & 1) == 0:
        left_cv_words = cv_stack.pop()
        new_cv_words = _blake3_parent_output(left_cv_words, new_cv_words, key_words, flags).chaining_value_words()
        chunk_counter >>= 1
    cv_stack.append(new_cv_words)

def blake3_hash_xof(data: bytes, out_len: int = OUT_LEN) -> bytes:
    key_words = list(IV)
    flags = 0
    return _blake3_hash_xof(key_words, flags, data, out_len)

def _blake3_hash_xof(key_words: list[int], flags: int, data: bytes, out_len: int) -> bytes:
    cv_stack: list[list[int]] = []
    chunk_state = _Blake3ChunkState(key_words, chunk_counter=0, flags=flags)

    offset = 0
    while offset < len(data):
        if chunk_state.length() == CHUNK_LEN:
            chunk_cv = chunk_state.output().chaining_value_words()
            total_chunks = chunk_state._chunk_counter + 1
            _blake3_add_chunk_cv(cv_stack, chunk_cv, total_chunks, key_words, flags)
            chunk_state = _Blake3ChunkState(key_words, chunk_counter=total_chunks, flags=flags)

        want = CHUNK_LEN - chunk_state.length()
        take = min(want, len(data) - offset)
        chunk_state.update(data[offset : offset + take])
        offset += take

    output = chunk_state.output()
    parent_nodes_remaining = len(cv_stack)
    while parent_nodes_remaining > 0:
        parent_nodes_remaining -= 1
        left_parent_cv = cv_stack[parent_nodes_remaining]
        output = _blake3_parent_output(left_parent_cv, output.chaining_value_words(), key_words, flags)

    return output.root_output_bytes(out_len)

def blake3_test_input(length: int) -> bytes:
    return bytes((i % 251) for i in range(length))
```

This step is the “BLAKE3 = BLAKE2s + tree” payoff: the stack merge logic makes the tree shape deterministic without building an explicit tree.

### Step 4: Add keyed_hash and derive_key modes (domain separation)
Keyed hashing uses a 32-byte key as the initial chaining value and sets a mode flag. Key derivation is a two-stage process: hash the context string to a “context key,” then keyed-hash the key material under a different flag.

```python
def blake3_hash(data: bytes, out_len: int = OUT_LEN) -> bytes:
    return blake3_hash_xof(data, out_len=out_len)

def blake3_keyed_hash(key: bytes, data: bytes, out_len: int = OUT_LEN) -> bytes:
    if len(key) != OUT_LEN:
        raise ValueError("BLAKE3 keyed_hash key must be 32 bytes")
    key_words = _words_from_le_bytes_32(key, 8)
    flags = KEYED_HASH
    return _blake3_hash_xof(key_words, flags, data, out_len)

def blake3_derive_key(context: str, key_material: bytes, out_len: int = OUT_LEN) -> bytes:
    context_key = _blake3_hash_xof(list(IV), DERIVE_KEY_CONTEXT, context.encode("utf-8"), OUT_LEN)
    key_words = _words_from_le_bytes_32(context_key, 8)
    return _blake3_hash_xof(key_words, DERIVE_KEY_MATERIAL, key_material, out_len)
```

In real systems, **domain separation** is the point: different flags mean the same bytes cannot “accidentally” collide across roles (hash vs MAC vs KDF).

Run it:

python3 code/main.py

## Use It
Use the from-scratch code only for learning. For production, use audited implementations:

| Language | BLAKE2 | BLAKE3 | Notes |
|----------|--------|--------|------|
| Python | `hashlib.blake2s/blake2b` | `blake3` (PyPI, Rust-backed) | stdlib has BLAKE2 but not BLAKE3 |
| Rust | `blake2` crate (RustCrypto) | `blake3` crate | fastest, battle-tested |
| CLI | `b2sum` (varies by distro) | `b3sum` | great for files and CI integrity |

Decision rule:
- If you need **stdlib-only Python**, BLAKE2s is available today.
- If you need **very fast large-input hashing**, or **XOF/keyed/KDF in one primitive**, BLAKE3 is a strong default in modern stacks.

## Pitfalls
1. **Using BLAKE3 as a password hash.** It’s designed to be fast; use Argon2/scrypt instead.
2. **Treating strings as bytes without defining encoding.** Always choose an explicit encoding (`utf-8`) and be consistent across languages.
3. **Truncating too aggressively.** A 64-bit digest is fine for non-adversarial checksums, not for untrusted identifiers.
4. **Reusing the same key without domain separation.** Prefer `derive_key` with a stable, hardcoded context string to get per-purpose subkeys.
5. **Confusing `keyed_hash` with encryption.** A MAC authenticates; it does not hide plaintext.

## Ship It
Save the reusable checklist at `outputs/prompt-blake2-blake3-review-checklist.md`.

Use it when:
- reviewing a PR that introduces BLAKE2/BLAKE3
- choosing between hash / MAC / KDF APIs
- auditing digest truncation, encoding, and domain separation decisions

## Exercises
1. **Easy.** Run `python3 code/main.py`. Observe that BLAKE3 produces identical first 32 bytes whether you request 32 bytes or 64 bytes (XOF prefix property).
2. **Medium.** Add a helper `blake3_file(path)` that reads a file in 64 KiB chunks and hashes it (streaming). Confirm the result matches hashing the full file contents in one shot.
3. **Hard.** Integrate a production BLAKE3 implementation (e.g., `b3sum` or Rust `blake3` crate) into a build cache: store `(blake3(file), size)` for every artifact and validate on load. Document where you must **not** truncate outputs.

## Key Terms
| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Compression function | “the hash’s core” | Fixed-size mixer that updates state from one block |
| Chaining value (CV) | “internal hash state” | The 32-byte value that links blocks/chunks in the tree |
| XOF | “hash of any length” | An extendable-output function; you can read N bytes safely |
| Domain separation | “different uses don’t collide” | Explicit tagging so the same bytes in different roles don’t share a domain |
| Keyed hash | “a MAC” | A PRF/MAC-like construction using a secret key |

## Further Reading
- Saarinen & Aumasson, “RFC 7693: The BLAKE2 Cryptographic Hash and Message Authentication Code (MAC)” (2015) — BLAKE2 specification and self-test module.
- Aumasson et al., “The BLAKE3 Hashing Framework” (Internet-Draft) — tree hashing, flags, and XOF framing.
- O’Connor et al., “BLAKE3 — one function, fast everywhere” (paper) — design rationale and performance.
- BLAKE3-team, “BLAKE3 reference implementation + official test vectors” — interop and KATs.
