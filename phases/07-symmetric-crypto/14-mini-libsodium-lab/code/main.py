"""
Mini libsodium — a pure-stdlib opinionated symmetric crypto API.

Builds a clean, hard-to-misuse API from the primitives covered in
lessons 08-13: ChaCha20-Poly1305, HMAC-SHA256, HKDF, and PBKDF2.

Run:
  python3 code/main.py

Educational implementation. Not constant-time. Not production-safe.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import os
import struct
from dataclasses import dataclass, field
from typing import Tuple


# ================================================================
# Internal primitives (ChaCha20 + Poly1305, taught in lesson 08)
# ================================================================

def _u32(x: int) -> int:
    return x & 0xFFFFFFFF


def _rotl32(x: int, n: int) -> int:
    x = _u32(x)
    return _u32((x << n) | (x >> (32 - n)))


def _le_u32(data: bytes) -> int:
    return struct.unpack("<I", data)[0]


def _u32_le(x: int) -> bytes:
    return struct.pack("<I", _u32(x))


def _quarter_round(a: int, b: int, c: int, d: int) -> Tuple[int, int, int, int]:
    a = _u32(a + b); d ^= a; d = _rotl32(d, 16)
    c = _u32(c + d); b ^= c; b = _rotl32(b, 12)
    a = _u32(a + b); d ^= a; d = _rotl32(d, 8)
    c = _u32(c + d); b ^= c; b = _rotl32(b, 7)
    return a, b, c, d


def _chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    constants = [b"expa", b"nd 3", b"2-by", b"te k"]
    s = [0] * 16
    for i in range(4):
        s[i] = _le_u32(constants[i])
    for i in range(8):
        s[4 + i] = _le_u32(key[i * 4:(i + 1) * 4])
    s[12] = counter
    s[13] = _le_u32(nonce[0:4])
    s[14] = _le_u32(nonce[4:8])
    s[15] = _le_u32(nonce[8:12])
    w = s[:]
    for _ in range(10):
        w[0], w[4], w[8], w[12] = _quarter_round(w[0], w[4], w[8], w[12])
        w[1], w[5], w[9], w[13] = _quarter_round(w[1], w[5], w[9], w[13])
        w[2], w[6], w[10], w[14] = _quarter_round(w[2], w[6], w[10], w[14])
        w[3], w[7], w[11], w[15] = _quarter_round(w[3], w[7], w[11], w[15])
        w[0], w[5], w[10], w[15] = _quarter_round(w[0], w[5], w[10], w[15])
        w[1], w[6], w[11], w[12] = _quarter_round(w[1], w[6], w[11], w[12])
        w[2], w[7], w[8], w[13] = _quarter_round(w[2], w[7], w[8], w[13])
        w[3], w[4], w[9], w[14] = _quarter_round(w[3], w[4], w[9], w[14])
    out = bytearray()
    for i in range(16):
        out += _u32_le(w[i] + s[i])
    return bytes(out)


def _chacha20_xor(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    out = bytearray()
    block_counter = counter
    for i in range(0, len(data), 64):
        block = _chacha20_block(key, block_counter, nonce)
        chunk = data[i:i + 64]
        out += bytes(x ^ y for x, y in zip(chunk, block))
        block_counter = _u32(block_counter + 1)
    return bytes(out)


def _poly1305_clamp(r: bytes) -> bytes:
    r = bytearray(r)
    for i in (3, 7, 11, 15):
        r[i] &= 0x0F
    for i in (4, 8, 12):
        r[i] &= 0xFC
    return bytes(r)


def _poly1305_mac(msg: bytes, key: bytes) -> bytes:
    r = int.from_bytes(_poly1305_clamp(key[:16]), "little")
    s = int.from_bytes(key[16:], "little")
    p = (1 << 130) - 5
    a = 0
    for i in range(0, len(msg), 16):
        block = msg[i:i + 16]
        n = int.from_bytes(block + b"\x01", "little")
        a = ((a + n) * r) % p
    tag_int = (a + s) & ((1 << 128) - 1)
    return tag_int.to_bytes(16, "little")


def _pad16(data: bytes) -> bytes:
    rem = len(data) % 16
    return b"" if rem == 0 else b"\x00" * (16 - rem)


def _aead_encrypt(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
    otk = _chacha20_block(key, 0, nonce)[:32]
    ciphertext = _chacha20_xor(key, 1, nonce, plaintext)
    mac_data = (
        aad + _pad16(aad)
        + ciphertext + _pad16(ciphertext)
        + struct.pack("<Q", len(aad))
        + struct.pack("<Q", len(ciphertext))
    )
    tag = _poly1305_mac(mac_data, otk)
    return ciphertext, tag


def _aead_decrypt(key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    otk = _chacha20_block(key, 0, nonce)[:32]
    mac_data = (
        aad + _pad16(aad)
        + ciphertext + _pad16(ciphertext)
        + struct.pack("<Q", len(aad))
        + struct.pack("<Q", len(ciphertext))
    )
    expected = _poly1305_mac(mac_data, otk)
    if not _hmac.compare_digest(expected, tag):
        raise ValueError("secretbox: authentication failed")
    return _chacha20_xor(key, 1, nonce, ciphertext)


# ================================================================
# Internal: HKDF-SHA256 (from lesson 13 pattern)
# ================================================================

def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    return _hmac.new(key, data, hashlib.sha256).digest()


def _hkdf_sha256(ikm: bytes, length: int, salt: bytes = b"", info: bytes = b"") -> bytes:
    if not salt:
        salt = b"\x00" * 32
    prk = _hmac_sha256(salt, ikm)
    okm = bytearray()
    t = b""
    counter = 1
    while len(okm) < length:
        t = _hmac_sha256(prk, t + info + bytes([counter]))
        okm.extend(t)
        counter += 1
    return bytes(okm[:length])


# ================================================================
# Step 1: secretbox — symmetric AEAD with nonce management
# ================================================================

SECRETBOX_KEYBYTES = 32
SECRETBOX_NONCEBYTES = 12
SECRETBOX_MACBYTES = 16


def secretbox_keygen() -> bytes:
    return os.urandom(SECRETBOX_KEYBYTES)


def _secretbox_with_nonce(key: bytes, nonce: bytes, message: bytes, aad: bytes = b"") -> bytes:
    """Deterministic secretbox for testing — nonce must be provided externally."""
    if len(key) != SECRETBOX_KEYBYTES:
        raise ValueError(f"key must be {SECRETBOX_KEYBYTES} bytes")
    if len(nonce) != SECRETBOX_NONCEBYTES:
        raise ValueError(f"nonce must be {SECRETBOX_NONCEBYTES} bytes")
    ciphertext, tag = _aead_encrypt(key, nonce, aad, message)
    return nonce + tag + ciphertext


def secretbox(key: bytes, message: bytes, aad: bytes = b"") -> bytes:
    """Encrypt and authenticate message. Returns nonce || tag || ciphertext."""
    nonce = os.urandom(SECRETBOX_NONCEBYTES)
    return _secretbox_with_nonce(key, nonce, message, aad)


def secretbox_open(key: bytes, box: bytes, aad: bytes = b"") -> bytes:
    """Decrypt and verify a secretbox blob. Raises ValueError on authentication failure."""
    if len(key) != SECRETBOX_KEYBYTES:
        raise ValueError(f"key must be {SECRETBOX_KEYBYTES} bytes")
    min_len = SECRETBOX_NONCEBYTES + SECRETBOX_MACBYTES
    if len(box) < min_len:
        raise ValueError("box too short")
    nonce = box[:SECRETBOX_NONCEBYTES]
    tag = box[SECRETBOX_NONCEBYTES:SECRETBOX_NONCEBYTES + SECRETBOX_MACBYTES]
    ciphertext = box[SECRETBOX_NONCEBYTES + SECRETBOX_MACBYTES:]
    return _aead_decrypt(key, nonce, aad, ciphertext, tag)


# ================================================================
# Step 2: auth — HMAC-SHA256 message authentication
# ================================================================

AUTH_KEYBYTES = 32
AUTH_BYTES = 32


def auth_keygen() -> bytes:
    return os.urandom(AUTH_KEYBYTES)


def auth(key: bytes, message: bytes) -> bytes:
    """Compute HMAC-SHA256 authentication tag."""
    return _hmac.new(key, message, hashlib.sha256).digest()


def auth_verify(key: bytes, message: bytes, tag: bytes) -> bool:
    """Verify HMAC-SHA256 tag in constant time. Returns True if valid."""
    expected = auth(key, message)
    return _hmac.compare_digest(expected, tag)


# ================================================================
# Step 3: kdf — HKDF-based subkey derivation
# ================================================================

KDF_KEYBYTES = 32
KDF_CONTEXTBYTES = 8
KDF_BYTES_MIN = 16
KDF_BYTES_MAX = 64


def kdf_keygen() -> bytes:
    return os.urandom(KDF_KEYBYTES)


def kdf_derive_from_key(subkey_len: int, subkey_id: int, ctx: bytes, key: bytes) -> bytes:
    """
    Derive an independent subkey using HKDF-SHA256.

    - subkey_len: bytes to produce (KDF_BYTES_MIN..KDF_BYTES_MAX)
    - subkey_id: 64-bit integer; different IDs produce independent subkeys
    - ctx: exactly 8 bytes; domain label, e.g. b"payments"
    - key: master key (KDF_KEYBYTES bytes)
    """
    if len(key) != KDF_KEYBYTES:
        raise ValueError(f"key must be {KDF_KEYBYTES} bytes")
    if len(ctx) != KDF_CONTEXTBYTES:
        raise ValueError(f"ctx must be exactly {KDF_CONTEXTBYTES} bytes")
    if not (KDF_BYTES_MIN <= subkey_len <= KDF_BYTES_MAX):
        raise ValueError(f"subkey_len must be {KDF_BYTES_MIN}..{KDF_BYTES_MAX}")
    info = ctx + subkey_id.to_bytes(8, "little")
    return _hkdf_sha256(ikm=key, length=subkey_len, info=info)


# ================================================================
# Step 4: pwhash — password-based key derivation (PBKDF2-SHA256)
# ================================================================

PWHASH_SALTBYTES = 32
PWHASH_OPSLIMIT_INTERACTIVE = 131072
PWHASH_OPSLIMIT_MODERATE = 524288
PWHASH_OPSLIMIT_SENSITIVE = 2097152


def pwhash(
    outlen: int,
    passwd: bytes,
    salt: bytes,
    opslimit: int = PWHASH_OPSLIMIT_INTERACTIVE,
) -> bytes:
    """
    Derive a key from a password using PBKDF2-HMAC-SHA256.

    - outlen: bytes of key material to produce
    - passwd: password encoded as bytes (use UTF-8)
    - salt: random bytes, unique per password (use PWHASH_SALTBYTES)
    - opslimit: iteration count; use PWHASH_OPSLIMIT_* constants
    """
    if len(salt) < 1:
        raise ValueError("salt must not be empty")
    if outlen < 1:
        raise ValueError("outlen must be >= 1")
    if opslimit < 1:
        raise ValueError("opslimit must be >= 1")
    return hashlib.pbkdf2_hmac("sha256", passwd, salt, opslimit, outlen)


def pwhash_str(passwd: bytes, opslimit: int = PWHASH_OPSLIMIT_INTERACTIVE) -> bytes:
    """Hash a password for storage. Returns salt || opslimit(4-BE) || tag."""
    salt = os.urandom(PWHASH_SALTBYTES)
    tag = pwhash(32, passwd, salt, opslimit)
    return salt + opslimit.to_bytes(4, "big") + tag


def pwhash_str_verify(stored: bytes, passwd: bytes) -> bool:
    """Verify a password against a pwhash_str blob. Returns True if correct."""
    if len(stored) < PWHASH_SALTBYTES + 4 + 32:
        return False
    salt = stored[:PWHASH_SALTBYTES]
    opslimit = int.from_bytes(stored[PWHASH_SALTBYTES:PWHASH_SALTBYTES + 4], "big")
    expected_tag = stored[PWHASH_SALTBYTES + 4:]
    actual_tag = pwhash(32, passwd, salt, opslimit)
    return _hmac.compare_digest(actual_tag, expected_tag)


# ================================================================
# Step 5: secretstream — multi-message streaming AEAD
# ================================================================

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
    """
    Initialize an encryption stream.
    Returns (state, header). Send header to the receiver before any chunks.
    """
    if len(key) != SECRETSTREAM_KEYBYTES:
        raise ValueError(f"key must be {SECRETSTREAM_KEYBYTES} bytes")
    nonce_base = os.urandom(SECRETSTREAM_HEADERBYTES)
    state = SecretstreamState(key=key, nonce_base=nonce_base)
    return state, nonce_base


def secretstream_init_pull(key: bytes, header: bytes) -> SecretstreamState:
    """Initialize a decryption stream from the sender's header."""
    if len(key) != SECRETSTREAM_KEYBYTES:
        raise ValueError(f"key must be {SECRETSTREAM_KEYBYTES} bytes")
    if len(header) != SECRETSTREAM_HEADERBYTES:
        raise ValueError(f"header must be {SECRETSTREAM_HEADERBYTES} bytes")
    return SecretstreamState(key=key, nonce_base=header)


def _stream_nonce(state: SecretstreamState) -> bytes:
    return state.nonce_base + state.counter.to_bytes(4, "big")


def secretstream_push(state: SecretstreamState, message: bytes, ad: bytes = b"") -> bytes:
    """Encrypt and authenticate one chunk. Returns tag (16 B) || ciphertext."""
    nonce = _stream_nonce(state)
    ciphertext, tag = _aead_encrypt(state.key, nonce, ad, message)
    state.counter += 1
    return tag + ciphertext


def secretstream_pull(state: SecretstreamState, chunk: bytes, ad: bytes = b"") -> bytes:
    """Decrypt and verify one chunk. Raises ValueError on authentication failure."""
    if len(chunk) < SECRETBOX_MACBYTES:
        raise ValueError("chunk too short")
    tag = chunk[:SECRETBOX_MACBYTES]
    ciphertext = chunk[SECRETBOX_MACBYTES:]
    nonce = _stream_nonce(state)
    plaintext = _aead_decrypt(state.key, nonce, ad, ciphertext, tag)
    state.counter += 1
    return plaintext


# ================================================================
# Helpers
# ================================================================

def _hex(b: bytes) -> str:
    return b.hex()


def _print_step(n: int, name: str) -> None:
    print(f"\n=== Step {n}: {name} ===")


# ================================================================
# main
# ================================================================

def main() -> None:
    _print_step(1, "secretbox — symmetric AEAD with nonce management")

    key = secretbox_keygen()
    message = b"send 100 USD to Alice"
    aad = b"v1:payment"

    box = secretbox(key, message, aad=aad)
    recovered = secretbox_open(key, box, aad=aad)

    print(f"  key       : {_hex(key)}")
    print(f"  message   : {message!r}")
    print(f"  box       : {_hex(box)[:48]}...  ({len(box)} bytes)")
    print(f"  nonce     : {_hex(box[:12])}  (first 12 bytes of box)")
    print(f"  tag       : {_hex(box[12:28])}  (bytes 12-28)")
    print(f"  recovered : {recovered!r}")
    print(f"  roundtrip : {recovered == message}")

    try:
        secretbox_open(key, box, aad=b"wrong-aad")
        print("  tamper-aad: FAIL (should have raised)")
    except ValueError as e:
        print(f"  tamper-aad: rejected — {e}")

    _print_step(2, "auth — HMAC-SHA256 message authentication")

    auth_key = auth_keygen()
    msg = b"transfer: Alice -> Bob, $500"
    tag = auth(auth_key, msg)
    print(f"  message   : {msg!r}")
    print(f"  tag       : {_hex(tag)}")
    print(f"  verify ok : {auth_verify(auth_key, msg, tag)}")
    print(f"  tampered  : {auth_verify(auth_key, msg + b'!', tag)}")

    _print_step(3, "kdf — derive independent subkeys from a master key")

    master = kdf_keygen()
    ctx = b"payments"
    enc_key = kdf_derive_from_key(32, subkey_id=0, ctx=ctx, key=master)
    mac_key = kdf_derive_from_key(32, subkey_id=1, ctx=ctx, key=master)
    nonce_key = kdf_derive_from_key(16, subkey_id=2, ctx=ctx, key=master)

    print(f"  master    : {_hex(master)}")
    print(f"  enc_key   : {_hex(enc_key)}")
    print(f"  mac_key   : {_hex(mac_key)}")
    print(f"  nonce_key : {_hex(nonce_key)}")
    print(f"  all differ: {len({enc_key, mac_key, bytes(nonce_key)}) == 3}")

    _print_step(4, "pwhash — derive a key from a password")

    salt = bytes(range(PWHASH_SALTBYTES))
    passwd = b"hunter2"
    derived = pwhash(32, passwd, salt, opslimit=65536)
    print(f"  password  : {passwd!r}")
    print(f"  salt      : {_hex(salt)[:16]}...")
    print(f"  derived   : {_hex(derived)}")

    stored = pwhash_str(passwd, opslimit=65536)
    print(f"  stored    : {_hex(stored)[:32]}...  ({len(stored)} bytes)")
    print(f"  verify ok : {pwhash_str_verify(stored, passwd)}")
    print(f"  wrong pw  : {pwhash_str_verify(stored, b'wrongpass')}")

    _print_step(5, "secretstream — multi-message streaming AEAD")

    stream_key = secretstream_keygen()
    push_state, header = secretstream_init_push(stream_key)
    pull_state = secretstream_init_pull(stream_key, header)

    messages = [b"chunk 0: hello", b"chunk 1: world", b"chunk 2: done"]
    chunks = [secretstream_push(push_state, m, ad=b"stream-v1") for m in messages]
    recovered_msgs = [secretstream_pull(pull_state, c, ad=b"stream-v1") for c in chunks]

    print(f"  header    : {_hex(header)}")
    for i, (orig, rec) in enumerate(zip(messages, recovered_msgs)):
        print(f"  chunk {i}   : {orig!r}  match={orig == rec}")

    print()
    print("All mini-libsodium steps complete.")


if __name__ == "__main__":
    main()
