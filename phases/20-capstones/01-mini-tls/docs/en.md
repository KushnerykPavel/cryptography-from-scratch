# Build a Mini TLS 1.3 Library

> Every secure connection on the internet is a four-message protocol built on the primitives you already know.

**Type:** Build
**Languages:** Python
**Prerequisites:** ECDH, AES-GCM, HKDF, digital signatures, certificate basics
**Time:** ~90 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain how TLS 1.3 combines DH key exchange, HKDF, and AEAD into a single handshake
- Compute the TLS 1.3 key schedule: early_secret → handshake_secret → master_secret → traffic keys
- Implement HKDF-Extract, HKDF-Expand, and the TLS 1.3 HKDF-Expand-Label wrapper from scratch
- Distinguish handshake-traffic secrets from application-traffic secrets and explain why there are two layers
- Apply the record-layer nonce construction (base_iv XOR sequence_number) and explain why nonce reuse breaks AEAD security

## The Problem

You need to send a password to a web server. The network is hostile: every packet passes through routers you don't control, some of which are actively eavesdropping. Encrypting the payload helps, but then how do you agree on a key with a server you've never talked to before? You can't pre-share a key with every web server on the internet.

The classic answer is public-key cryptography: exchange a Diffie-Hellman ephemeral key over the untrusted network, derive a symmetric key from that exchange, and encrypt everything with it. But that alone doesn't stop a man in the middle who intercepts both sides and runs two separate DH exchanges, one with each party. You also need authentication — a way to prove the server is who it claims to be.

TLS 1.3 solves all of this in four messages and roughly 30 milliseconds. It ties together Diffie-Hellman key exchange, HKDF key derivation, digital signatures for authentication, and authenticated encryption for the data stream. Building a stripped-down version from scratch reveals exactly which piece does which job — and why removing any one of them breaks the whole system.

## The Concept

### The four-message handshake

```
Client                              Server
  |                                    |
  |-- ClientHello (DH public key) ---->|
  |<-- ServerHello (DH public key) ----|
  |<-- {EncryptedExtensions}           |
  |<-- {Certificate, CertVerify}       |
  |<-- {Finished} --------------------|
  |-- {Finished} --------------------->|
  |                                    |
  |<====== Application Data ==========>|
```

Messages in `{}` are already encrypted with handshake-traffic keys. Application data uses a separate set of keys derived later.

### The key schedule

TLS 1.3 uses HKDF to derive every key from a single chain. The chain has three salted HKDF-Extract steps:

| Step | Salt | IKM | Output |
|------|------|-----|--------|
| 1 | `0^32` | `0^32` (no PSK) | `early_secret` |
| 2 | `Derive-Secret(early, "derived", "")` | ECDHE shared | `handshake_secret` |
| 3 | `Derive-Secret(hs, "derived", "")` | `0^32` | `master_secret` |

From each secret, `Derive-Secret` branches off label-specific traffic secrets:

```
handshake_secret
  ├── Derive-Secret(hs, "c hs traffic", transcript) → client_hs_traffic
  └── Derive-Secret(hs, "s hs traffic", transcript) → server_hs_traffic

master_secret
  ├── Derive-Secret(ms, "c ap traffic", transcript) → client_ap_traffic
  └── Derive-Secret(ms, "s ap traffic", transcript) → server_ap_traffic
```

Each traffic secret then yields a `key` (32 bytes) and `iv` (12 bytes) via `HKDF-Expand-Label`.

### HKDF-Expand-Label

The TLS 1.3 wire format for the `info` field of HKDF-Expand is:

```
HkdfLabel = uint16(length) || uint8(len(label)) || "tls13 " + label
                            || uint8(len(context)) || context
```

This is a compact struct that prevents label collisions across protocol versions.

### Nonce construction

To avoid reusing a nonce with the same key (which catastrophically breaks GCM), TLS 1.3 XORs the per-record sequence number into the static IV:

```
nonce = write_iv XOR (seq_number padded to iv_length with leading zeros)
```

Sequence 0 → `write_iv XOR 0...0 = write_iv`. Sequence 1 → first bit flips. The nonces are unique as long as you never exceed 2^64 records per key.

## Build It

### Step 1: Finite-field DH key exchange

```python
_DH_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74
_DH_G = 2


def dh_generate_keypair(private_int: int) -> Tuple[int, int]:
    """Return (private, public) given a private scalar integer."""
    pub = pow(_DH_G, private_int, _DH_P)
    return private_int, pub


def dh_compute_shared(private_int: int, peer_public: int) -> bytes:
    """Compute shared secret bytes (big-endian, 32 bytes)."""
    shared = pow(peer_public, private_int, _DH_P)
    return shared.to_bytes(32, "big")
```

Diffie-Hellman over a finite field is the simplest key exchange that works with only `pow()`. Both parties pick a random private scalar, publish `g^private mod p`, and compute `peer_public^private mod p`. By the commutativity of modular exponentiation, both sides arrive at the same shared secret. In production TLS 1.3 this is replaced by X25519 (a Montgomery-ladder scalar multiplication on Curve25519), but the algebraic structure is identical.

### Step 2: HKDF-Extract and HKDF-Expand

```python
def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract: PRK = HMAC-Hash(salt, IKM)."""
    if not salt:
        salt = bytes(HASH_LEN)
    return _hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand: produce `length` bytes of keying material."""
    if length > 255 * HASH_LEN:
        raise ValueError("requested length too large for HKDF-Expand")
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = _hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def hkdf_expand_label(secret: bytes, label: str, context: bytes, length: int) -> bytes:
    full_label = b"tls13 " + label.encode()
    hkdf_label = (
        struct.pack(">H", length)
        + struct.pack("B", len(full_label)) + full_label
        + struct.pack("B", len(context)) + context
    )
    return hkdf_expand(secret, hkdf_label, length)


def derive_secret(secret: bytes, label: str, messages_hash: bytes) -> bytes:
    """Derive-Secret(Secret, Label, Messages) — RFC 8446 §7.1."""
    return hkdf_expand_label(secret, label, messages_hash, HASH_LEN)
```

HKDF-Extract "concentrates" randomness from potentially weak or structured key material into a uniformly random pseudo-random key (PRK). HKDF-Expand then stretches that PRK into as many bytes as needed. The `info` field binds the output to a specific purpose — changing `info` produces completely different output. `hkdf_expand_label` is TLS 1.3's standard wrapper that ensures every derived key carries both the protocol version ("tls13 ") and a human-readable label so no two keys can collide even if they share the same parent secret.

### Step 3: HMAC-based AEAD

```python
def _derive_aead_subkeys(key: bytes) -> Tuple[bytes, bytes]:
    material = hkdf_expand(key, b"hmac-aead-ks", 2 * HASH_LEN)
    return material[:HASH_LEN], material[HASH_LEN:]


def _hmac_keystream(ks_key: bytes, nonce: bytes, length: int) -> bytes:
    """Generate `length` pseudo-random bytes via HMAC-SHA256 counter mode."""
    stream = b""
    counter = 0
    while len(stream) < length:
        block = _hmac.new(
            ks_key, nonce + struct.pack(">Q", counter), hashlib.sha256
        ).digest()
        stream += block
        counter += 1
    return stream[:length]


def aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Encrypt plaintext, returning ciphertext || tag (tag = last 32 bytes)."""
    if len(nonce) != AEAD_IV_LEN:
        raise ValueError(f"nonce must be {AEAD_IV_LEN} bytes")
    ks_key, auth_key = _derive_aead_subkeys(key)
    stream = _hmac_keystream(ks_key, nonce, len(plaintext))
    ct = bytes(p ^ s for p, s in zip(plaintext, stream))
    tag = _hmac.new(auth_key, nonce + ct + aad, hashlib.sha256).digest()
    return ct + tag


def aead_decrypt(key: bytes, nonce: bytes, ciphertext_and_tag: bytes, aad: bytes = b"") -> bytes:
    """Decrypt, verifying the authentication tag.  Raises ValueError on failure."""
    if len(nonce) != AEAD_IV_LEN:
        raise ValueError(f"nonce must be {AEAD_IV_LEN} bytes")
    if len(ciphertext_and_tag) < AEAD_TAG_LEN:
        raise ValueError("input too short to contain a tag")
    ct, tag = ciphertext_and_tag[:-AEAD_TAG_LEN], ciphertext_and_tag[-AEAD_TAG_LEN:]
    ks_key, auth_key = _derive_aead_subkeys(key)
    expected_tag = _hmac.new(auth_key, nonce + ct + aad, hashlib.sha256).digest()
    if not _hmac.compare_digest(tag, expected_tag):
        raise ValueError("AEAD tag verification failed")
    stream = _hmac_keystream(ks_key, nonce, len(ct))
    return bytes(c ^ s for c, s in zip(ct, stream))
```

Python's standard library has no AES, so this uses HMAC-SHA256 as a PRF to build a CTR-mode-like keystream (Encrypt) and a separate HMAC tag over `nonce || ciphertext || aad` (then MAC, i.e., Encrypt-then-MAC). The two sub-keys come from a single HKDF-Expand call so that the keystream key and auth key are independent. In production, replace this entire construction with `cryptography.hazmat.primitives.ciphers.aead.AESGCM` or `ChaCha20Poly1305`.

### Step 4: TLS 1.3 key schedule

```python
def build_key_schedule(ecdhe_shared: bytes, transcript_ch_sh: bytes) -> KeySchedule:
    ks = KeySchedule()
    zeros = bytes(HASH_LEN)
    empty_hash = hashlib.sha256(b"").digest()

    ks.early_secret = hkdf_extract(zeros, zeros)

    derived_early = derive_secret(ks.early_secret, "derived", empty_hash)
    ks.handshake_secret = hkdf_extract(derived_early, ecdhe_shared)

    ks.client_hs_traffic = derive_secret(ks.handshake_secret, "c hs traffic", transcript_ch_sh)
    ks.server_hs_traffic = derive_secret(ks.handshake_secret, "s hs traffic", transcript_ch_sh)

    derived_hs = derive_secret(ks.handshake_secret, "derived", empty_hash)
    ks.master_secret = hkdf_extract(derived_hs, zeros)

    ks.client_ap_traffic = derive_secret(ks.master_secret, "c ap traffic", transcript_ch_sh)
    ks.server_ap_traffic = derive_secret(ks.master_secret, "s ap traffic", transcript_ch_sh)

    ks.client_finished_key = hkdf_expand_label(ks.client_hs_traffic, "finished", b"", HASH_LEN)
    ks.server_finished_key = hkdf_expand_label(ks.server_hs_traffic, "finished", b"", HASH_LEN)

    ks.client_write_key = hkdf_expand_label(ks.client_ap_traffic, "key", b"", AEAD_KEY_LEN)
    ks.client_write_iv  = hkdf_expand_label(ks.client_ap_traffic, "iv",  b"", AEAD_IV_LEN)
    ks.server_write_key = hkdf_expand_label(ks.server_ap_traffic, "key", b"", AEAD_KEY_LEN)
    ks.server_write_iv  = hkdf_expand_label(ks.server_ap_traffic, "iv",  b"", AEAD_IV_LEN)

    return ks
```

This is a direct translation of RFC 8446 §7.1. Each `HKDF-Extract` step "mixes in" new secret material (the ECDHE shared secret at step 2, zeros at step 3) while the `Derive-Secret` calls branch off labeled traffic secrets that carry the current transcript hash. Binding secrets to the transcript means a passive observer who records the handshake cannot derive the same keys even if they later compromise the server's long-term key — provided the server discards the ephemeral DH private key after the handshake (forward secrecy).

### Step 5: Finished messages and record layer

```python
def make_finished(finished_key: bytes, transcript_hash: bytes) -> Finished:
    """Build a Finished message per RFC 8446 §4.4.4."""
    verify_data = _hmac.new(finished_key, transcript_hash, hashlib.sha256).digest()
    return Finished(verify_data=verify_data)


def verify_finished(finished_key: bytes, transcript_hash: bytes, msg: Finished) -> bool:
    expected = _hmac.new(finished_key, transcript_hash, hashlib.sha256).digest()
    return _hmac.compare_digest(expected, msg.verify_data)


@dataclass
class RecordLayer:
    write_key: bytes
    write_iv: bytes
    read_key: bytes
    read_iv: bytes
    _write_seq: int = field(default=0, init=False)
    _read_seq: int = field(default=0, init=False)

    def _make_nonce(self, base_iv: bytes, seq: int) -> bytes:
        seq_bytes = struct.pack(">Q", seq).rjust(AEAD_IV_LEN, b"\x00")
        return bytes(a ^ b for a, b in zip(base_iv, seq_bytes))

    def encrypt(self, plaintext: bytes, content_type: int = 23) -> bytes:
        nonce = self._make_nonce(self.write_iv, self._write_seq)
        aad = struct.pack(">BHH", content_type, 0x0303, len(plaintext) + AEAD_TAG_LEN)
        blob = aead_encrypt(self.write_key, nonce, plaintext, aad)
        self._write_seq += 1
        return blob

    def decrypt(self, blob: bytes, content_type: int = 23) -> bytes:
        nonce = self._make_nonce(self.read_iv, self._read_seq)
        aad = struct.pack(">BHH", content_type, 0x0303, len(blob))
        plaintext = aead_decrypt(self.read_key, nonce, blob, aad)
        self._read_seq += 1
        return plaintext
```

The Finished message is a MAC over the entire handshake transcript using a key derived from the handshake-traffic secret. If either side's Finished fails to verify, the handshake aborts — any tampering with ClientHello or ServerHello changes the transcript hash and breaks the MAC. The record layer then wraps every application message with a per-record nonce (base IV XOR sequence number) and AEAD authentication, committing both the content and the record header into the tag.

Run it:
```
python3 code/main.py
```

## Use It

| Component | This lesson | Production library |
|-----------|-------------|-------------------|
| DH key exchange | Finite-field DH over 256-bit prime | X25519 (`cryptography.hazmat.primitives.asymmetric.x25519`) |
| HKDF | Hand-rolled HMAC-SHA256 | `cryptography.hazmat.primitives.kdf.hkdf.HKDF` |
| AEAD | HMAC-based CTR + EtM | AES-256-GCM or ChaCha20-Poly1305 (`cryptography.hazmat.primitives.ciphers.aead`) |
| TLS handshake | Simplified 2-message demo | Full TLS 1.3 via `ssl` (stdlib) or `pyOpenSSL` / `trustme` |
| Certificates | Omitted | X.509 via `cryptography.x509` |
| Record layer | Single writer, no key update | `ssl.SSLSocket` with automatic key updates |

## Pitfalls

- **Nonce reuse**: Using the same `(key, nonce)` pair twice destroys AEAD confidentiality. The record layer must increment the sequence number before every `encrypt` call; never reset it without a key update.
- **Decrypting before verifying the tag**: Any code path that reads plaintext bytes before `hmac.compare_digest` completes creates a padding-oracle or timing oracle. In `aead_decrypt`, the tag check must happen first.
- **Skipping the transcript hash**: Deriving traffic keys without binding them to the transcript allows a MITM to substitute their own ServerHello while the client still derives the same keys — the Finished check is what closes this gap.
- **Using the handshake-traffic key for application data**: Handshake-traffic keys are for `EncryptedExtensions`, `Certificate`, and `Finished` only. Application data uses a separate key derived from `master_secret`. Mixing them leaks the session if handshake keys are compromised.
- **`==` for tag comparison**: Python's `==` on bytes is not constant-time on all implementations. Always use `hmac.compare_digest` for tag and Finished verification to prevent timing side-channels.

## Ship It

Save a reusable TLS 1.3 implementation checklist to `outputs/tls-handshake-checklist.md`. You can paste it into any PR that touches TLS configuration or a custom TLS implementation to quickly flag the most common mistakes.

## Exercises

1. Easy: Run `python3 code/main.py`. Observe all six steps. Verify that `shared_match: True` and both roundtrip checks print `True`. Identify which step produces `early_secret` and trace why it is the same value regardless of the ECDHE exchange.
2. Medium: Modify `run_handshake` to simulate a MITM attack: intercept the DH public keys and substitute your own. Show that both sides compute different `transcript` hashes and therefore produce different `Finished.verify_data` values, causing the handshake to fail.
3. Hard: Replace the toy finite-field DH with a real X25519 implementation using only Python integers (implement the Montgomery ladder over the curve25519 prime `2^255 - 19`). Verify that `dh_compute_shared` still passes all existing tests and that the shared secret is 32 bytes.

## Key Terms

| Term | What people say | What it actually means |
|------|-----------------|------------------------|
| HKDF-Extract | "Derive a key from the DH output" | `HMAC(salt, IKM)` — collapses potentially non-uniform key material into a fixed-length PRK |
| HKDF-Expand-Label | "Stretch the key with a label" | Structured HKDF-Expand call that prefixes "tls13 " to every label, preventing cross-version collisions |
| Transcript hash | "Hash of the handshake" | SHA-256 over the concatenated handshake messages; binds all derived secrets to the exact bytes exchanged |
| Handshake-traffic secret | "Keys for the handshake" | Derived before the master secret; encrypts Certificate and Finished but discarded after the handshake completes |
| Forward secrecy | "PFS" | Property that compromising the server's long-term key after the fact cannot decrypt previously recorded sessions, because ephemeral DH keys were discarded |
| Record layer | "TLS record" | The framing around each encrypted chunk: content type, protocol version, length, then AEAD ciphertext+tag |
| Nonce | "IV" | A 12-byte value that must be unique per `(key, message)` pair; TLS 1.3 builds it by XORing the static IV with the 64-bit sequence number |

## Further Reading

- Rescorla, "The Transport Layer Security (TLS) Protocol Version 1.3" RFC 8446 (2018) — the primary specification; §7.1 is the key schedule, §5.3 is the record nonce construction
- Krawczyk & Eronen, "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)" RFC 5869 (2010) — the underlying KDF used throughout TLS 1.3
- Dowling et al., "A Cryptographic Analysis of the TLS 1.3 Handshake Protocol" (2021) — formal security proof covering the key schedule and authentication guarantees
- Bhargavan et al., "Transcript Collision Attacks: Breaking Authentication in TLS, IKE, and SSH" (2016) — explains why transcript binding (and HKDF-Expand-Label) matters
