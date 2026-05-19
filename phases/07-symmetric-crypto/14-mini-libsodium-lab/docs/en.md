# Symmetric Lab — Build a Mini libsodium
> Wrap primitives in an API that makes the right thing the only easy thing.

**Type:** Build
**Languages:** Python
**Prerequisites:** `07-symmetric-crypto/08-chacha20-poly1305`, `07-symmetric-crypto/12-hmac`, `07-symmetric-crypto/13-kdfs`
**Time:** ~90 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** why a "bag of primitives" is not the same as a safe crypto API
- **Implement** secretbox, auth, kdf, pwhash, and secretstream on top of ChaCha20-Poly1305 + HKDF
- **Distinguish** what each libsodium operation protects (confidentiality vs. integrity vs. authenticity)
- **Apply** domain separation and automatic nonce management to eliminate common footguns
- **Compute** how nonce counters prevent reuse across a streaming session

## The Problem

You now know how to use ChaCha20-Poly1305, HMAC-SHA256, HKDF, and PBKDF2. The primitives work. But each primitive has sharp edges: you must choose a nonce, you must choose a key, you must authenticate the right bytes, you must separate domains, you must store salts. Every choice is an opportunity for a bug that won't show up in tests.

Real systems do not hand raw primitives to application developers. libsodium — used by WireGuard, Signal Protocol, Tor, Keybase, and dozens of production systems — solves this by exposing a small set of opinionated, composable operations. Each operation has exactly the inputs it needs and no more. Nonces are generated automatically. Key separation is built in. Wrong usage is rejected at the API boundary rather than silently producing broken output.

This lab builds a minimal version of libsodium's symmetric API from the primitives you already know. You will see concretely how correct API design turns unsafe primitives into safe operations, and what choices the designer made to achieve that.

## The Concept

libsodium organizes symmetric crypto into five operations:

| Operation | What it does | Underlying primitive |
|-----------|-------------|---------------------|
| **secretbox** | Authenticated encryption (one message, one key) | ChaCha20-Poly1305 AEAD |
| **auth / auth_verify** | MAC — prove a message came from a key-holder | HMAC-SHA256 |
| **kdf_derive_from_key** | Split a master key into independent subkeys | HKDF-SHA256 |
| **pwhash** | Derive a key from a password (slow, salted) | PBKDF2 / scrypt / Argon2id |
| **secretstream** | Authenticated streaming (many chunks, one session) | ChaCha20-Poly1305 with sequential nonces |

### The nonce problem

Every AEAD requires a nonce that must never repeat for a given key. This is the hardest rule for application developers to follow. libsodium's `secretbox_easy` requires the caller to pass a nonce — but our mini version removes that responsibility entirely by prepending a fresh random nonce to every box:

```
box = rand_nonce(12 bytes) || tag(16 bytes) || ciphertext
```

The caller cannot forget the nonce because the API generates and embeds it. The receiver cannot forget to extract it because the format is self-contained.

### Key separation with kdf

A single master key should never be used directly for encryption, authentication, and nonce generation. `kdf_derive_from_key` uses HKDF to derive independent subkeys:

```
info = ctx (8 bytes) || subkey_id (8 bytes, little-endian)
subkey = HKDF-SHA256(IKM=master_key, info=info, length=subkey_len)
```

Different `subkey_id` values → unrelated keys, even with the same master key. Different `ctx` values → isolated key spaces across application modules.

### Streaming with sequential counters

`secretstream` manages nonces automatically across multiple messages. A random 8-byte base nonce is exchanged at session start. Each chunk's 12-byte nonce is:

```
nonce[i] = nonce_base (8 bytes) || counter_i (4 bytes, big-endian)
```

A chunk replayed at a different position will fail authentication because the nonce will not match. A message dropped from the sequence will cause all subsequent pulls to fail because the counter is irreversibly incremented.

## Build It

### Step 1: secretbox — AEAD with automatic nonce management

The internal `_secretbox_with_nonce` is deterministic (for testing). The public `secretbox` generates its own nonce and prepends it to the output.

```python
SECRETBOX_KEYBYTES = 32
SECRETBOX_NONCEBYTES = 12
SECRETBOX_MACBYTES = 16


def secretbox_keygen() -> bytes:
    return os.urandom(SECRETBOX_KEYBYTES)


def _secretbox_with_nonce(key: bytes, nonce: bytes, message: bytes, aad: bytes = b"") -> bytes:
    if len(key) != SECRETBOX_KEYBYTES:
        raise ValueError(f"key must be {SECRETBOX_KEYBYTES} bytes")
    if len(nonce) != SECRETBOX_NONCEBYTES:
        raise ValueError(f"nonce must be {SECRETBOX_NONCEBYTES} bytes")
    ciphertext, tag = _aead_encrypt(key, nonce, aad, message)
    return nonce + tag + ciphertext


def secretbox(key: bytes, message: bytes, aad: bytes = b"") -> bytes:
    nonce = os.urandom(SECRETBOX_NONCEBYTES)
    return _secretbox_with_nonce(key, nonce, message, aad)


def secretbox_open(key: bytes, box: bytes, aad: bytes = b"") -> bytes:
    if len(key) != SECRETBOX_KEYBYTES:
        raise ValueError(f"key must be {SECRETBOX_KEYBYTES} bytes")
    min_len = SECRETBOX_NONCEBYTES + SECRETBOX_MACBYTES
    if len(box) < min_len:
        raise ValueError("box too short")
    nonce = box[:SECRETBOX_NONCEBYTES]
    tag = box[SECRETBOX_NONCEBYTES:SECRETBOX_NONCEBYTES + SECRETBOX_MACBYTES]
    ciphertext = box[SECRETBOX_NONCEBYTES + SECRETBOX_MACBYTES:]
    return _aead_decrypt(key, nonce, aad, ciphertext, tag)
```

`secretbox` returns a self-contained blob: nonce (12 B) || tag (16 B) || ciphertext. The receiver extracts all three fields from that one blob. The caller never touches the nonce.

### Step 2: auth — HMAC-SHA256 message authentication

Encryption and authentication are separate primitives. `auth` gives you a MAC without encryption — useful for tokens, API request signing, and integrity checks on public data.

```python
AUTH_KEYBYTES = 32
AUTH_BYTES = 32


def auth_keygen() -> bytes:
    return os.urandom(AUTH_KEYBYTES)


def auth(key: bytes, message: bytes) -> bytes:
    return _hmac.new(key, message, hashlib.sha256).digest()


def auth_verify(key: bytes, message: bytes, tag: bytes) -> bool:
    expected = auth(key, message)
    return _hmac.compare_digest(expected, tag)
```

`auth_verify` uses `hmac.compare_digest` — a constant-time comparison that prevents timing attacks. Never use `==` to compare MACs.

### Step 3: kdf — HKDF subkey derivation

One master key produces many independent subkeys by varying `subkey_id` and `ctx`. The `ctx` label (exactly 8 bytes) is a human-readable domain identifier that isolates key spaces between modules.

```python
KDF_KEYBYTES = 32
KDF_CONTEXTBYTES = 8
KDF_BYTES_MIN = 16
KDF_BYTES_MAX = 64


def kdf_keygen() -> bytes:
    return os.urandom(KDF_KEYBYTES)


def kdf_derive_from_key(subkey_len: int, subkey_id: int, ctx: bytes, key: bytes) -> bytes:
    if len(key) != KDF_KEYBYTES:
        raise ValueError(f"key must be {KDF_KEYBYTES} bytes")
    if len(ctx) != KDF_CONTEXTBYTES:
        raise ValueError(f"ctx must be exactly {KDF_CONTEXTBYTES} bytes")
    if not (KDF_BYTES_MIN <= subkey_len <= KDF_BYTES_MAX):
        raise ValueError(f"subkey_len must be {KDF_BYTES_MIN}..{KDF_BYTES_MAX}")
    info = ctx + subkey_id.to_bytes(8, "little")
    return _hkdf_sha256(ikm=key, length=subkey_len, info=info)
```

The `info` string encodes both the context label and the subkey ID, ensuring HKDF produces unrelated output for each combination. Changing either `ctx` or `subkey_id` produces an entirely different subkey.

### Step 4: pwhash — password-based key derivation

Passwords are not keys: they have low entropy and are guessable. `pwhash` stretches a password by iterating PBKDF2-SHA256 many times, making each guess expensive for an attacker. The `pwhash_str` helper wraps it into a self-contained storage format.

```python
PWHASH_SALTBYTES = 32
PWHASH_OPSLIMIT_INTERACTIVE = 131072
PWHASH_OPSLIMIT_MODERATE = 524288
PWHASH_OPSLIMIT_SENSITIVE = 2097152


def pwhash(outlen: int, passwd: bytes, salt: bytes,
           opslimit: int = PWHASH_OPSLIMIT_INTERACTIVE) -> bytes:
    if len(salt) < 1:
        raise ValueError("salt must not be empty")
    if outlen < 1:
        raise ValueError("outlen must be >= 1")
    if opslimit < 1:
        raise ValueError("opslimit must be >= 1")
    return hashlib.pbkdf2_hmac("sha256", passwd, salt, opslimit, outlen)


def pwhash_str(passwd: bytes, opslimit: int = PWHASH_OPSLIMIT_INTERACTIVE) -> bytes:
    salt = os.urandom(PWHASH_SALTBYTES)
    tag = pwhash(32, passwd, salt, opslimit)
    return salt + opslimit.to_bytes(4, "big") + tag


def pwhash_str_verify(stored: bytes, passwd: bytes) -> bool:
    if len(stored) < PWHASH_SALTBYTES + 4 + 32:
        return False
    salt = stored[:PWHASH_SALTBYTES]
    opslimit = int.from_bytes(stored[PWHASH_SALTBYTES:PWHASH_SALTBYTES + 4], "big")
    expected_tag = stored[PWHASH_SALTBYTES + 4:]
    actual_tag = pwhash(32, passwd, salt, opslimit)
    return _hmac.compare_digest(actual_tag, expected_tag)
```

`pwhash_str` stores `salt || opslimit || tag` together so verification is self-contained. The `opslimit` is embedded so you can increase it in the future and still verify old hashes.

### Step 5: secretstream — multi-message streaming AEAD

`secretstream` manages a session that encrypts a sequence of chunks. Each chunk gets a unique nonce derived from a random base and an auto-incrementing counter. The session state (key + base nonce + counter) is never exposed to the caller.

```python
SECRETSTREAM_KEYBYTES = 32
SECRETSTREAM_HEADERBYTES = 8


@dataclass
class SecretstreamState:
    key: bytes
    nonce_base: bytes
    counter: int = field(default=0)


def secretstream_keygen() -> bytes:
    return os.urandom(SECRETSTREAM_KEYBYTES)


def secretstream_init_push(key: bytes) -> Tuple[SecretstreamState, bytes]:
    nonce_base = os.urandom(SECRETSTREAM_HEADERBYTES)
    state = SecretstreamState(key=key, nonce_base=nonce_base)
    return state, nonce_base


def secretstream_init_pull(key: bytes, header: bytes) -> SecretstreamState:
    return SecretstreamState(key=key, nonce_base=header)


def _stream_nonce(state: SecretstreamState) -> bytes:
    return state.nonce_base + state.counter.to_bytes(4, "big")


def secretstream_push(state: SecretstreamState, message: bytes, ad: bytes = b"") -> bytes:
    nonce = _stream_nonce(state)
    ciphertext, tag = _aead_encrypt(state.key, nonce, ad, message)
    state.counter += 1
    return tag + ciphertext


def secretstream_pull(state: SecretstreamState, chunk: bytes, ad: bytes = b"") -> bytes:
    if len(chunk) < SECRETBOX_MACBYTES:
        raise ValueError("chunk too short")
    tag = chunk[:SECRETBOX_MACBYTES]
    ciphertext = chunk[SECRETBOX_MACBYTES:]
    nonce = _stream_nonce(state)
    plaintext = _aead_decrypt(state.key, nonce, ad, ciphertext, tag)
    state.counter += 1
    return plaintext
```

The receiver calls `secretstream_init_pull(key, header)` where `header` is the 8-byte base nonce sent by the sender. Both sides advance their counters in lockstep. A replayed or reordered chunk fails authentication because the counters diverge.

Run it:
```
python3 code/main.py
```

## Use It

Production equivalents — use these instead of the educational version:

| Operation | libsodium (C) | Python (`PyNaCl`) | Python (`cryptography`) |
|-----------|--------------|-------------------|------------------------|
| secretbox | `crypto_secretbox_easy` | `nacl.secret.SecretBox` | `AESGCM` / `ChaCha20Poly1305` |
| auth | `crypto_auth` | `nacl.hash.blake2b` (keyed) | `HMAC` |
| kdf | `crypto_kdf_derive_from_key` | — | `HKDF` |
| pwhash | `crypto_pwhash` (Argon2id) | `nacl.pwhash.argon2id` | `Argon2id`, `Scrypt` |
| secretstream | `crypto_secretstream_xchacha20poly1305_*` | — | — |

libsodium uses XChaCha20 (192-bit nonce) for secretbox and secretstream, which eliminates the random-nonce-collision risk for very large-scale deployments. Our version uses a 96-bit nonce, which is safe as long as you do not generate billions of messages per key.

For Python projects, `PyNaCl` is a direct binding to libsodium and the closest production equivalent. `cryptography` gives you the same underlying primitives with more control.

## Pitfalls

- **Splitting secretbox across two calls**: computing the tag in one place and the ciphertext in another breaks the AEAD guarantee. Encrypt and authenticate must be atomic.
- **Reusing a secretstream state after failure**: if `secretstream_pull` raises, the counter has not advanced. Resuming the same state with the next chunk will use the wrong nonce. Treat any authentication failure as fatal and create a new session.
- **Using `pwhash` with HKDF instead of `kdf_derive_from_key`**: HKDF is not slow. Using HKDF on a password gives an attacker a fast offline attack target. `pwhash` → passwords. `kdf` → high-entropy secrets.
- **Checking `auth_verify` with `==`**: `tag == auth(key, msg)` leaks timing information that can be exploited to forge tags in some environments. Always use `hmac.compare_digest`.
- **Empty ctx or repeated ctx in kdf**: two modules using the same `ctx` and `subkey_id` silently share key material. Treat `ctx` as a globally unique 8-byte label and document it.

## Ship It

This lesson ships a reusable artifact: `outputs/mini-libsodium-api-guide.md`.

Open it to find:
- A table mapping each operation to its production equivalent
- An API usage checklist you can paste into a PR
- A threat model summary: what each operation protects and what it does not

Use it when reviewing any symmetric crypto integration in your team's codebase.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe that `secretbox` produces a different box each run even for the same key and message. Find the nonce in the output and explain why it differs.
2. Medium. Extend `kdf_derive_from_key` to also support an optional `salt` argument (passed through to HKDF's extract phase). Update `tests/test_vectors.py` to test that the same `(key, ctx, subkey_id)` with different salts produces different subkeys.
3. Hard. Replace the PBKDF2 inside `pwhash` with `hashlib.scrypt`. Expose `n`, `r`, `p` parameters as an alternative "mode" and store them alongside the salt in `pwhash_str`. Benchmark both modes and compute how many guesses/second an attacker can perform on the PBKDF2 version vs the scrypt version on your hardware.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| secretbox | "encrypt a message" | Encrypt-then-MAC with automatic nonce management; returns a self-contained blob |
| nonce | "number used once" | A per-message value that must be unique per key; reuse destroys AEAD security |
| domain separation | "different keys for different things" | Using distinct `info` / `ctx` labels so HKDF outputs are provably independent |
| opslimit | "cost factor" | Iteration count in PBKDF2/scrypt/Argon2; controls how slow one password guess is |
| streaming AEAD | "chunked encryption" | A session that authenticates each chunk independently but uses sequential nonces to prevent replay and reorder |

## Further Reading

- Frank Denis, *libsodium documentation* — authoritative API reference and design rationale for each operation.
- IETF, *ChaCha20 and Poly1305 for IETF Protocols* (RFC 8439) — specification for the AEAD underlying secretbox and secretstream.
- IETF, *HMAC-based Extract-and-Expand Key Derivation Function (HKDF)* (RFC 5869) — the KDF underlying `kdf_derive_from_key`.
- IETF, *PKCS #5: Password-Based Cryptography Specification* (RFC 8018) — PBKDF2 specification used in `pwhash`.
- Jean-Philippe Aumasson, *Serious Cryptography* (2017) — Chapter 5 (stream ciphers) and Chapter 8 (authenticated encryption) cover the primitives composed here.
