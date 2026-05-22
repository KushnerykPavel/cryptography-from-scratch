"""
Mini TLS 1.3 Library — educational implementation.

Run:
  python3 code/main.py

This lesson assembles a simplified TLS 1.3-like handshake and record layer
from first principles using only the Python standard library.  It covers:

  1. Finite-field DH key exchange (stand-in for X25519 / ECDH)
  2. HKDF-Extract and HKDF-Expand (RFC 5869) with the TLS 1.3 HKDF-Expand-Label
     wrapper (RFC 8446 §7.1)
  3. A HMAC-based AEAD (CTR-like keystream from HMAC-SHA256, authenticated with a
     second HMAC tag) — a pure-stdlib stand-in for AES-GCM
  4. The TLS 1.3 key schedule: early_secret → handshake_secret → master_secret,
     deriving client/server handshake-traffic and application-traffic secrets
  5. Simplified ClientHello / ServerHello / Finished messages
  6. Record-layer encrypt/decrypt for application data

Everything is deterministic given fixed inputs — no os.urandom in the demo path.

⚠️  Educational only.  Not constant-time.  Not production-safe.  Do not deploy.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import struct
from dataclasses import dataclass, field
from typing import List, Tuple


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HASH_LEN = 32          # SHA-256 output length in bytes
AEAD_KEY_LEN = 32      # HMAC-AEAD key length
AEAD_IV_LEN = 12       # nonce length (matches TLS 1.3 AES-GCM convention)
AEAD_TAG_LEN = 32      # HMAC tag length

# 256-bit prime for finite-field DH.  Using the leading 256 bits of the
# RFC 3526 group-14 prime — large enough to illustrate the concept, small
# enough to compute quickly.
_DH_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74
_DH_G = 2


# ---------------------------------------------------------------------------
# § 1  Finite-field DH key exchange (stand-in for X25519 / ECDH)
# ---------------------------------------------------------------------------

def dh_generate_keypair(private_int: int) -> Tuple[int, int]:
    """Return (private, public) given a private scalar integer."""
    pub = pow(_DH_G, private_int, _DH_P)
    return private_int, pub


def dh_compute_shared(private_int: int, peer_public: int) -> bytes:
    """Compute shared secret bytes (big-endian, 32 bytes)."""
    shared = pow(peer_public, private_int, _DH_P)
    return shared.to_bytes(32, "big")


# ---------------------------------------------------------------------------
# § 2  HKDF (RFC 5869) + TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1)
# ---------------------------------------------------------------------------

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
    """
    HKDF-Expand-Label as defined in RFC 8446 §7.1:

        HkdfLabel = struct {
            uint16  length;
            opaque  label<7..255>;   // "tls13 " + label
            opaque  context<0..255>;
        }
    """
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


# ---------------------------------------------------------------------------
# § 3  HMAC-based AEAD  (stand-in for AES-GCM; stdlib has no AES)
#
# Construction:
#   material       = HKDF-Expand(key, "hmac-aead-ks", 2*32)
#   keystream_key  = material[:32]
#   auth_key       = material[32:]
#   keystream      = HMAC-SHA256(keystream_key, nonce || counter) repeated
#   ciphertext     = plaintext XOR keystream
#   tag            = HMAC-SHA256(auth_key, nonce || ciphertext || aad)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# § 4  TLS 1.3 key schedule (RFC 8446 §7.1)
# ---------------------------------------------------------------------------

@dataclass
class KeySchedule:
    early_secret: bytes = field(default_factory=lambda: b"")
    handshake_secret: bytes = field(default_factory=lambda: b"")
    master_secret: bytes = field(default_factory=lambda: b"")
    client_hs_traffic: bytes = field(default_factory=lambda: b"")
    server_hs_traffic: bytes = field(default_factory=lambda: b"")
    client_ap_traffic: bytes = field(default_factory=lambda: b"")
    server_ap_traffic: bytes = field(default_factory=lambda: b"")
    client_finished_key: bytes = field(default_factory=lambda: b"")
    server_finished_key: bytes = field(default_factory=lambda: b"")
    client_write_key: bytes = field(default_factory=lambda: b"")
    client_write_iv: bytes = field(default_factory=lambda: b"")
    server_write_key: bytes = field(default_factory=lambda: b"")
    server_write_iv: bytes = field(default_factory=lambda: b"")


def build_key_schedule(ecdhe_shared: bytes, transcript_ch_sh: bytes) -> KeySchedule:
    """
    TLS 1.3 key schedule for a 0-RTT-free, PSK-free handshake.

        early_secret        = HKDF-Extract(0^32, 0^32)
        derived_early       = Derive-Secret(early_secret, "derived", "")
        handshake_secret    = HKDF-Extract(derived_early, ECDHE)
        client_hs_traffic   = Derive-Secret(hs, "c hs traffic", CH..SH hash)
        server_hs_traffic   = Derive-Secret(hs, "s hs traffic", CH..SH hash)
        derived_hs          = Derive-Secret(hs, "derived", "")
        master_secret       = HKDF-Extract(derived_hs, 0^32)
        client_ap_traffic   = Derive-Secret(ms, "c ap traffic", CH..SH hash)
        server_ap_traffic   = Derive-Secret(ms, "s ap traffic", CH..SH hash)
    """
    ks = KeySchedule()
    zeros = bytes(HASH_LEN)
    empty_hash = hashlib.sha256(b"").digest()

    # Early secret
    ks.early_secret = hkdf_extract(zeros, zeros)

    # Handshake secret
    derived_early = derive_secret(ks.early_secret, "derived", empty_hash)
    ks.handshake_secret = hkdf_extract(derived_early, ecdhe_shared)

    # Traffic secrets from handshake
    ks.client_hs_traffic = derive_secret(ks.handshake_secret, "c hs traffic", transcript_ch_sh)
    ks.server_hs_traffic = derive_secret(ks.handshake_secret, "s hs traffic", transcript_ch_sh)

    # Master secret
    derived_hs = derive_secret(ks.handshake_secret, "derived", empty_hash)
    ks.master_secret = hkdf_extract(derived_hs, zeros)

    # Application traffic secrets
    ks.client_ap_traffic = derive_secret(ks.master_secret, "c ap traffic", transcript_ch_sh)
    ks.server_ap_traffic = derive_secret(ks.master_secret, "s ap traffic", transcript_ch_sh)

    # Finished keys
    ks.client_finished_key = hkdf_expand_label(ks.client_hs_traffic, "finished", b"", HASH_LEN)
    ks.server_finished_key = hkdf_expand_label(ks.server_hs_traffic, "finished", b"", HASH_LEN)

    # Write keys / IVs for application data
    ks.client_write_key = hkdf_expand_label(ks.client_ap_traffic, "key", b"", AEAD_KEY_LEN)
    ks.client_write_iv  = hkdf_expand_label(ks.client_ap_traffic, "iv",  b"", AEAD_IV_LEN)
    ks.server_write_key = hkdf_expand_label(ks.server_ap_traffic, "key", b"", AEAD_KEY_LEN)
    ks.server_write_iv  = hkdf_expand_label(ks.server_ap_traffic, "iv",  b"", AEAD_IV_LEN)

    return ks


# ---------------------------------------------------------------------------
# § 5  Simplified TLS 1.3 handshake messages
# ---------------------------------------------------------------------------

@dataclass
class ClientHello:
    random: bytes           # 32-byte client random
    dh_public: int          # client ephemeral DH public value


@dataclass
class ServerHello:
    random: bytes           # 32-byte server random
    dh_public: int          # server ephemeral DH public value


@dataclass
class Finished:
    verify_data: bytes      # HMAC-SHA256(finished_key, transcript_hash)


def make_finished(finished_key: bytes, transcript_hash: bytes) -> Finished:
    """Build a Finished message per RFC 8446 §4.4.4."""
    verify_data = _hmac.new(finished_key, transcript_hash, hashlib.sha256).digest()
    return Finished(verify_data=verify_data)


def verify_finished(finished_key: bytes, transcript_hash: bytes, msg: Finished) -> bool:
    """Verify a Finished message.  Returns True iff the MAC is correct."""
    expected = _hmac.new(finished_key, transcript_hash, hashlib.sha256).digest()
    return _hmac.compare_digest(expected, msg.verify_data)


def hash_transcript(messages: List[bytes]) -> bytes:
    """SHA-256 hash of the concatenated handshake messages."""
    h = hashlib.sha256()
    for m in messages:
        h.update(m)
    return h.digest()


def serialize_hello(hello: ClientHello | ServerHello) -> bytes:
    """Simple wire format: random (32) || dh_public (32 big-endian)."""
    return hello.random + hello.dh_public.to_bytes(32, "big")


# ---------------------------------------------------------------------------
# § 6  Record layer
# ---------------------------------------------------------------------------

@dataclass
class RecordLayer:
    """
    Maintains per-direction nonce counters.

    Nonce = write_iv XOR (sequence_number as 64-bit big-endian, left-padded to
    AEAD_IV_LEN), matching RFC 8446 §5.3.
    """
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
        """Encrypt one TLS record.  Returns ciphertext || tag blob."""
        nonce = self._make_nonce(self.write_iv, self._write_seq)
        aad = struct.pack(">BHH", content_type, 0x0303, len(plaintext) + AEAD_TAG_LEN)
        blob = aead_encrypt(self.write_key, nonce, plaintext, aad)
        self._write_seq += 1
        return blob

    def decrypt(self, blob: bytes, content_type: int = 23) -> bytes:
        """Decrypt one TLS record blob.  Raises ValueError on tag failure."""
        nonce = self._make_nonce(self.read_iv, self._read_seq)
        aad = struct.pack(">BHH", content_type, 0x0303, len(blob))
        plaintext = aead_decrypt(self.read_key, nonce, blob, aad)
        self._read_seq += 1
        return plaintext


# ---------------------------------------------------------------------------
# § 7  Full handshake helper
# ---------------------------------------------------------------------------

def run_handshake(
    client_dh_private: int,
    server_dh_private: int,
    client_random: bytes,
    server_random: bytes,
) -> Tuple[KeySchedule, RecordLayer, RecordLayer]:
    """
    Run a simplified TLS 1.3 handshake between two virtual parties.

    Returns (key_schedule, client_record_layer, server_record_layer).
    The two record layers are wired so client.encrypt() → server.decrypt()
    and server.encrypt() → client.decrypt().
    """
    # ClientHello
    _, c_pub = dh_generate_keypair(client_dh_private)
    ch = ClientHello(random=client_random, dh_public=c_pub)
    ch_bytes = serialize_hello(ch)

    # ServerHello
    _, s_pub = dh_generate_keypair(server_dh_private)
    sh = ServerHello(random=server_random, dh_public=s_pub)
    sh_bytes = serialize_hello(sh)

    # ECDHE shared secret
    shared_client = dh_compute_shared(client_dh_private, s_pub)
    shared_server = dh_compute_shared(server_dh_private, c_pub)
    assert shared_client == shared_server, "DH shared secret mismatch"
    ecdhe = shared_client

    # Key schedule
    transcript = hash_transcript([ch_bytes, sh_bytes])
    ks = build_key_schedule(ecdhe, transcript)

    # Finished messages (verify both directions)
    s_fin = make_finished(ks.server_finished_key, transcript)
    c_fin = make_finished(ks.client_finished_key, transcript)
    assert verify_finished(ks.server_finished_key, transcript, s_fin)
    assert verify_finished(ks.client_finished_key, transcript, c_fin)

    # Build record layers for application data
    client_rl = RecordLayer(
        write_key=ks.client_write_key,
        write_iv=ks.client_write_iv,
        read_key=ks.server_write_key,
        read_iv=ks.server_write_iv,
    )
    server_rl = RecordLayer(
        write_key=ks.server_write_key,
        write_iv=ks.server_write_iv,
        read_key=ks.client_write_key,
        read_iv=ks.client_write_iv,
    )
    return ks, client_rl, server_rl


# ---------------------------------------------------------------------------
# § 8  Demo / main
# ---------------------------------------------------------------------------

def main() -> None:
    print("=== Step 1: Finite-field DH key exchange ===")
    client_priv = 0xDEADBEEFCAFEBABE0102030405060708090A0B0C0D0E0F101112131415161718
    server_priv = 0xFEEDFACEDEADC0DE1A2B3C4D5E6F70718293A4B5C6D7E8F9AABBCCDDEEFF00

    c_priv, c_pub = dh_generate_keypair(client_priv)
    s_priv, s_pub = dh_generate_keypair(server_priv)
    shared_c = dh_compute_shared(c_priv, s_pub)
    shared_s = dh_compute_shared(s_priv, c_pub)
    print("  client_pub  :", hex(c_pub)[:18], "...")
    print("  server_pub  :", hex(s_pub)[:18], "...")
    print("  shared_match:", shared_c == shared_s)
    print("  shared_secret:", shared_c.hex())

    print()
    print("=== Step 2: HKDF-Extract and HKDF-Expand ===")
    salt = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    ikm  = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    prk  = hkdf_extract(salt, ikm)
    okm  = hkdf_expand(prk, b"test-info", 42)
    print("  PRK (hex):", prk.hex())
    print("  OKM (42B):", okm.hex())

    print()
    print("=== Step 3: HMAC-based AEAD encrypt / decrypt ===")
    aead_key   = bytes(range(32))
    aead_nonce = bytes(range(12))
    plaintext  = b"Hello, TLS 1.3 world!"
    aad        = b"additional-authenticated-data"
    blob       = aead_encrypt(aead_key, aead_nonce, plaintext, aad)
    recovered  = aead_decrypt(aead_key, aead_nonce, blob, aad)
    print("  plaintext :", plaintext)
    print("  ciphertext:", blob[:-AEAD_TAG_LEN].hex())
    print("  tag       :", blob[-AEAD_TAG_LEN:].hex())
    print("  recovered :", recovered)
    print("  roundtrip :", recovered == plaintext)

    print()
    print("=== Step 4: TLS 1.3 key schedule ===")
    client_random_val = bytes(range(32))
    server_random_val = bytes(range(31, -1, -1))
    ch_obj = ClientHello(random=client_random_val, dh_public=c_pub)
    sh_obj = ServerHello(random=server_random_val, dh_public=s_pub)
    ch_bytes = serialize_hello(ch_obj)
    sh_bytes = serialize_hello(sh_obj)
    transcript = hash_transcript([ch_bytes, sh_bytes])
    ks = build_key_schedule(shared_c, transcript)
    print("  early_secret       :", ks.early_secret.hex())
    print("  handshake_secret   :", ks.handshake_secret.hex())
    print("  master_secret      :", ks.master_secret.hex())
    print("  client_hs_traffic  :", ks.client_hs_traffic.hex())
    print("  server_hs_traffic  :", ks.server_hs_traffic.hex())
    print("  client_write_key   :", ks.client_write_key.hex())
    print("  server_write_key   :", ks.server_write_key.hex())

    print()
    print("=== Step 5: Finished messages ===")
    c_fin = make_finished(ks.client_finished_key, transcript)
    s_fin = make_finished(ks.server_finished_key, transcript)
    c_ok  = verify_finished(ks.client_finished_key, transcript, c_fin)
    s_ok  = verify_finished(ks.server_finished_key, transcript, s_fin)
    print("  client_finished.verify_data :", c_fin.verify_data.hex())
    print("  server_finished.verify_data :", s_fin.verify_data.hex())
    print("  client_finished_valid       :", c_ok)
    print("  server_finished_valid       :", s_ok)

    print()
    print("=== Step 6: Full handshake + application data ===")
    ks2, c_rl, s_rl = run_handshake(
        client_dh_private=client_priv,
        server_dh_private=server_priv,
        client_random=client_random_val,
        server_random=server_random_val,
    )
    msg_c2s = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    msg_s2c = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"

    blob_c2s  = c_rl.encrypt(msg_c2s)
    plain_c2s = s_rl.decrypt(blob_c2s)
    blob_s2c  = s_rl.encrypt(msg_s2c)
    plain_s2c = c_rl.decrypt(blob_s2c)

    print("  client→server (encrypted, first 32B):", blob_c2s[:32].hex(), "...")
    print("  server decrypted                     :", plain_c2s)
    print("  server→client (encrypted, first 32B):", blob_s2c[:32].hex(), "...")
    print("  client decrypted                     :", plain_s2c)
    print("  roundtrip c→s:", plain_c2s == msg_c2s)
    print("  roundtrip s→c:", plain_s2c == msg_s2c)


if __name__ == "__main__":
    main()
