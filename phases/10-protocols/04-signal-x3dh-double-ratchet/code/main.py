"""Signal-style session setup (X3DH) + per-message key evolution (Double Ratchet).

This is an educational, stdlib-only implementation that demonstrates the moving
pieces behind Signal/WhatsApp-style secure messaging:
1) X25519 + HKDF primitives
2) X3DH-style handshake to derive a 32-byte shared secret + associated data
3) Double Ratchet state machine (DH ratchet + symmetric KDF chains)
4) Out-of-order handling via skipped message keys

Run:
  python3 code/main.py

Notes:
- Educational implementation. Not constant-time. Not production-safe.
- This omits several production details (Ed25519 signatures, header encryption,
  protocol framing, identity binding UX, replay protections, etc.).
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass


HASHLEN = 32
TAGLEN = 16

X25519_BASEPOINT = (9).to_bytes(32, "little")
X3DH_SALT = b"\x00" * HASHLEN
X3DH_INFO = b"cryptography-from-scratch:X3DH"

DR_RK_INFO = b"cryptography-from-scratch:DoubleRatchet:RK"
DR_CK_INFO = b"cryptography-from-scratch:DoubleRatchet:CK"

AEAD_ENC_INFO = b"cryptography-from-scratch:AEAD:enc"
AEAD_MAC_INFO = b"cryptography-from-scratch:AEAD:mac"

MAX_SKIP = 50


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))


def hkdf_extract_sha256(salt: bytes | None, ikm: bytes) -> bytes:
    if salt is None:
        salt = b"\x00" * HASHLEN
    return hmac_sha256(salt, ikm)


def hkdf_expand_sha256(prk: bytes, info: bytes, length: int) -> bytes:
    if len(prk) != HASHLEN:
        raise ValueError("prk must be 32 bytes")
    if length < 0:
        raise ValueError("length must be non-negative")
    if length > 255 * HASHLEN:
        raise ValueError("length too large")

    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac_sha256(prk, t + info + bytes([counter]))
        out += t
        counter += 1
    return out[:length]


def hkdf_sha256(salt: bytes | None, ikm: bytes, info: bytes, length: int) -> bytes:
    prk = hkdf_extract_sha256(salt, ikm)
    return hkdf_expand_sha256(prk, info, length)


P_25519 = (1 << 255) - 19
A24_25519 = 121665


def _cswap(swap: int, x2: int, x3: int) -> tuple[int, int]:
    mask = -swap
    dummy = mask & (x2 ^ x3)
    return x2 ^ dummy, x3 ^ dummy


def _clamp_scalar(k: bytes) -> bytes:
    if len(k) != 32:
        raise ValueError("X25519 scalar must be 32 bytes")
    k_list = bytearray(k)
    k_list[0] &= 248
    k_list[31] &= 127
    k_list[31] |= 64
    return bytes(k_list)


def x25519_private_key_from_seed(seed: bytes) -> bytes:
    return _clamp_scalar(sha256(seed))


def x25519_public_key(private_key: bytes) -> bytes:
    return x25519(private_key, X25519_BASEPOINT)


def x25519(private_key: bytes, public_u: bytes) -> bytes:
    k = _clamp_scalar(private_key)
    if len(public_u) != 32:
        raise ValueError("X25519 public u-coordinate must be 32 bytes")

    k_int = int.from_bytes(k, "little")
    x1 = int.from_bytes(public_u, "little") % P_25519
    x2, z2 = 1, 0
    x3, z3 = x1, 1
    swap = 0

    for t in range(254, -1, -1):
        k_t = (k_int >> t) & 1
        swap ^= k_t
        x2, x3 = _cswap(swap, x2, x3)
        z2, z3 = _cswap(swap, z2, z3)
        swap = k_t

        a = (x2 + z2) % P_25519
        aa = (a * a) % P_25519
        b = (x2 - z2) % P_25519
        bb = (b * b) % P_25519
        e = (aa - bb) % P_25519
        c = (x3 + z3) % P_25519
        d = (x3 - z3) % P_25519
        da = (d * a) % P_25519
        cb = (c * b) % P_25519
        x3 = ((da + cb) ** 2) % P_25519
        z3 = (x1 * ((da - cb) ** 2)) % P_25519
        x2 = (aa * bb) % P_25519
        z2 = (e * (aa + (A24_25519 * e) % P_25519)) % P_25519

    x2, x3 = _cswap(swap, x2, x3)
    z2, z3 = _cswap(swap, z2, z3)

    if z2 == 0:
        raise ValueError("invalid X25519 input (z2=0)")
    inv_z2 = pow(z2, P_25519 - 2, P_25519)
    result = (x2 * inv_z2) % P_25519
    return result.to_bytes(32, "little")


def x25519_is_all_zero(shared_secret: bytes) -> bool:
    return all(b == 0 for b in shared_secret)


def x3dh_kdf(dh_outputs: bytes, info: bytes = X3DH_INFO) -> bytes:
    return hkdf_sha256(X3DH_SALT, dh_outputs, info, 32)


def x3dh_associated_data(alice_ik_pub: bytes, bob_ik_pub: bytes) -> bytes:
    if len(alice_ik_pub) != 32 or len(bob_ik_pub) != 32:
        raise ValueError("identity public keys must be 32 bytes")
    return alice_ik_pub + bob_ik_pub


def x3dh_initiator(
    ik_a_priv: bytes,
    ek_a_priv: bytes,
    ik_b_pub: bytes,
    spk_b_pub: bytes,
    opk_b_pub: bytes | None = None,
) -> tuple[bytes, bytes]:
    dh1 = x25519(ik_a_priv, spk_b_pub)
    dh2 = x25519(ek_a_priv, ik_b_pub)
    dh3 = x25519(ek_a_priv, spk_b_pub)
    dh_concat = dh1 + dh2 + dh3
    if opk_b_pub is not None:
        dh4 = x25519(ek_a_priv, opk_b_pub)
        dh_concat += dh4
    sk = x3dh_kdf(dh_concat)
    ad = x3dh_associated_data(x25519_public_key(ik_a_priv), ik_b_pub)
    return sk, ad


def x3dh_responder(
    ik_b_priv: bytes,
    spk_b_priv: bytes,
    ik_a_pub: bytes,
    ek_a_pub: bytes,
    opk_b_priv: bytes | None = None,
) -> tuple[bytes, bytes]:
    dh1 = x25519(spk_b_priv, ik_a_pub)
    dh2 = x25519(ik_b_priv, ek_a_pub)
    dh3 = x25519(spk_b_priv, ek_a_pub)
    dh_concat = dh1 + dh2 + dh3
    if opk_b_priv is not None:
        dh4 = x25519(opk_b_priv, ek_a_pub)
        dh_concat += dh4
    sk = x3dh_kdf(dh_concat)
    ad = x3dh_associated_data(ik_a_pub, x25519_public_key(ik_b_priv))
    return sk, ad


def kdf_rk(rk: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
    if len(rk) != 32:
        raise ValueError("rk must be 32 bytes")
    okm = hkdf_sha256(rk, dh_out, DR_RK_INFO, 64)
    return okm[:32], okm[32:]


def kdf_ck(ck: bytes) -> tuple[bytes, bytes]:
    if len(ck) != 32:
        raise ValueError("ck must be 32 bytes")
    okm = hkdf_sha256(None, ck, DR_CK_INFO, 64)
    return okm[:32], okm[32:]


def _keystream(key: bytes, length: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        out += hmac_sha256(key, counter.to_bytes(4, "big"))
        counter += 1
    return out[:length]


def aead_encrypt(mk: bytes, plaintext: bytes, associated_data: bytes) -> tuple[bytes, bytes]:
    if len(mk) != 32:
        raise ValueError("mk must be 32 bytes")
    enc_key = hkdf_sha256(None, mk, AEAD_ENC_INFO, 32)
    mac_key = hkdf_sha256(None, mk, AEAD_MAC_INFO, 32)
    ciphertext = xor_bytes(plaintext, _keystream(enc_key, len(plaintext)))
    tag_full = hmac_sha256(mac_key, associated_data + ciphertext)
    return ciphertext, tag_full[:TAGLEN]


def aead_decrypt(mk: bytes, ciphertext: bytes, tag: bytes, associated_data: bytes) -> bytes:
    if len(tag) != TAGLEN:
        raise ValueError("invalid tag length")
    enc_key = hkdf_sha256(None, mk, AEAD_ENC_INFO, 32)
    mac_key = hkdf_sha256(None, mk, AEAD_MAC_INFO, 32)
    expected = hmac_sha256(mac_key, associated_data + ciphertext)[:TAGLEN]
    if not hmac.compare_digest(expected, tag):
        raise ValueError("authentication failed")
    return xor_bytes(ciphertext, _keystream(enc_key, len(ciphertext)))


def serialize_header(dh_pub: bytes, pn: int, n: int) -> bytes:
    if len(dh_pub) != 32:
        raise ValueError("dh_pub must be 32 bytes")
    if pn < 0 or n < 0:
        raise ValueError("pn/n must be non-negative")
    return dh_pub + pn.to_bytes(4, "big") + n.to_bytes(4, "big")


@dataclass
class RatchetState:
    dhs_priv: bytes
    dhs_pub: bytes
    dhr_pub: bytes | None
    rk: bytes
    cks: bytes | None
    ckr: bytes | None
    ns: int
    nr: int
    pn: int
    mkskipped: dict[tuple[bytes, int], bytes]


def generate_dh(seed: bytes | None = None) -> tuple[bytes, bytes]:
    if seed is None:
        priv = _clamp_scalar(os.urandom(32))
    else:
        priv = x25519_private_key_from_seed(seed)
    return priv, x25519_public_key(priv)


def dh(dh_priv: bytes, dh_pub: bytes) -> bytes:
    shared = x25519(dh_priv, dh_pub)
    if x25519_is_all_zero(shared):
        raise ValueError("all-zero shared secret (small-order point)")
    return shared


def dr_init_alice(sk: bytes, bob_ratchet_pub: bytes, seed: bytes) -> RatchetState:
    dhs_priv, dhs_pub = generate_dh(seed=seed)
    rk, cks = kdf_rk(sk, dh(dhs_priv, bob_ratchet_pub))
    return RatchetState(
        dhs_priv=dhs_priv,
        dhs_pub=dhs_pub,
        dhr_pub=bob_ratchet_pub,
        rk=rk,
        cks=cks,
        ckr=None,
        ns=0,
        nr=0,
        pn=0,
        mkskipped={},
    )


def dr_init_bob(sk: bytes, bob_ratchet_priv: bytes, bob_ratchet_pub: bytes) -> RatchetState:
    return RatchetState(
        dhs_priv=_clamp_scalar(bob_ratchet_priv),
        dhs_pub=bob_ratchet_pub,
        dhr_pub=None,
        rk=sk,
        cks=None,
        ckr=None,
        ns=0,
        nr=0,
        pn=0,
        mkskipped={},
    )


def dr_skip_message_keys(state: RatchetState, until: int) -> None:
    if until < 0:
        raise ValueError("until must be non-negative")
    if state.ckr is None:
        return
    if state.nr + MAX_SKIP < until:
        raise ValueError("too many skipped keys")
    if state.dhr_pub is None:
        raise ValueError("missing dhr_pub for skip")
    while state.nr < until:
        state.ckr, mk = kdf_ck(state.ckr)
        state.mkskipped[(state.dhr_pub, state.nr)] = mk
        state.nr += 1


def dr_dh_ratchet(state: RatchetState, received_dh_pub: bytes, seed: bytes) -> None:
    state.pn = state.ns
    state.ns = 0
    state.nr = 0
    state.dhr_pub = received_dh_pub

    state.rk, state.ckr = kdf_rk(state.rk, dh(state.dhs_priv, state.dhr_pub))

    state.dhs_priv, state.dhs_pub = generate_dh(seed=seed)
    state.rk, state.cks = kdf_rk(state.rk, dh(state.dhs_priv, state.dhr_pub))


def dr_try_skipped_message_key(state: RatchetState, dh_pub: bytes, n: int) -> bytes | None:
    key = (dh_pub, n)
    mk = state.mkskipped.get(key)
    if mk is None:
        return None
    del state.mkskipped[key]
    return mk


def dr_encrypt(state: RatchetState, plaintext: bytes, ad: bytes) -> tuple[bytes, bytes, bytes]:
    if state.cks is None:
        raise ValueError("cannot encrypt without a sending chain key (cks)")
    state.cks, mk = kdf_ck(state.cks)
    header = serialize_header(state.dhs_pub, state.pn, state.ns)
    state.ns += 1
    ciphertext, tag = aead_encrypt(mk, plaintext, ad + header)
    return header, ciphertext, tag


def dr_decrypt(state: RatchetState, header: bytes, ciphertext: bytes, tag: bytes, ad: bytes, seed: bytes) -> bytes:
    if len(header) != 40:
        raise ValueError("invalid header length")
    dh_pub = header[:32]
    pn = int.from_bytes(header[32:36], "big")
    n = int.from_bytes(header[36:40], "big")

    skipped = dr_try_skipped_message_key(state, dh_pub, n)
    if skipped is not None:
        return aead_decrypt(skipped, ciphertext, tag, ad + header)

    if state.dhr_pub != dh_pub:
        dr_skip_message_keys(state, pn)
        dr_dh_ratchet(state, dh_pub, seed=seed)

    dr_skip_message_keys(state, n)
    if state.ckr is None:
        raise ValueError("cannot decrypt without a receiving chain key (ckr)")
    state.ckr, mk = kdf_ck(state.ckr)
    state.nr += 1
    return aead_decrypt(mk, ciphertext, tag, ad + header)


def _hx(b: bytes) -> str:
    return b.hex()


def main():
    print("=== Step 1: X25519 + HKDF building blocks ===")
    alice_priv = bytes.fromhex(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    )
    bob_priv = bytes.fromhex(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
    )
    alice_pub = x25519_public_key(alice_priv)
    bob_pub = x25519_public_key(bob_priv)
    shared_a = x25519(alice_priv, bob_pub)
    shared_b = x25519(bob_priv, alice_pub)
    print("alice_pub:", _hx(alice_pub))
    print("bob_pub:  ", _hx(bob_pub))
    print("shared_a: ", _hx(shared_a))
    print("shared_b: ", _hx(shared_b))
    print("HKDF demo:", _hx(hkdf_sha256(b"salt", b"ikm", b"info", 16)))

    print("\n=== Step 2: X3DH: derive a shared session secret ===")
    ik_a_priv = x25519_private_key_from_seed(b"Alice IK")
    ek_a_priv = x25519_private_key_from_seed(b"Alice EK")
    ik_b_priv = x25519_private_key_from_seed(b"Bob IK")
    spk_b_priv = x25519_private_key_from_seed(b"Bob SPK")
    ik_a_pub = x25519_public_key(ik_a_priv)
    ek_a_pub = x25519_public_key(ek_a_priv)
    ik_b_pub = x25519_public_key(ik_b_priv)
    spk_b_pub = x25519_public_key(spk_b_priv)

    sk_a, ad_a = x3dh_initiator(ik_a_priv, ek_a_priv, ik_b_pub, spk_b_pub, opk_b_pub=None)
    sk_b, ad_b = x3dh_responder(ik_b_priv, spk_b_priv, ik_a_pub, ek_a_pub, opk_b_priv=None)
    print("SK(A):", _hx(sk_a))
    print("SK(B):", _hx(sk_b))
    print("AD:  ", _hx(ad_a))
    print("match:", sk_a == sk_b and ad_a == ad_b)

    print("\n=== Step 3: Double Ratchet state + KDF chains ===")
    alice_state = dr_init_alice(sk_a, bob_ratchet_pub=spk_b_pub, seed=b"Alice DR DH0")
    bob_state = dr_init_bob(sk_b, bob_ratchet_priv=spk_b_priv, bob_ratchet_pub=spk_b_pub)
    print("alice initial RK:", _hx(alice_state.rk))
    print("alice initial CKs:", _hx(alice_state.cks or b""))  # should exist for Alice
    print("bob initial CKs:", bob_state.cks is not None, "CKr:", bob_state.ckr is not None)

    print("\n=== Step 4: Message flow: out-of-order decryption via skipped keys ===")
    headers: list[bytes] = []
    cts: list[bytes] = []
    tags: list[bytes] = []
    for i in range(3):
        h, c, t = dr_encrypt(alice_state, f"msg-{i}".encode(), ad_a)
        headers.append(h)
        cts.append(c)
        tags.append(t)
        print(f"sent msg-{i} header={_hx(h)} ct={_hx(c)} tag={_hx(t)}")

    order = [1, 0, 2]
    for idx in order:
        pt = dr_decrypt(bob_state, headers[idx], cts[idx], tags[idx], ad_b, seed=b"Bob DR DH1")
        print(f"recv idx={idx} -> {pt.decode()}")


if __name__ == "__main__":
    main()
