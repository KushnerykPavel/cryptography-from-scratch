"""
Protocol Lab — Build a Mini Signal (Educational)

What this file does:
- Implements a tiny, self-contained “Signal-like” messaging lab:
  - X3DH-style session setup (asynchronous via a prekey bundle)
  - Double Ratchet message encryption/decryption (toy AEAD)
  - A minimal server that stores prekey bundles and queues messages
  - Safety-number-style identity fingerprinting (TOFU verification demo)

How to run:
  python3 code/main.py

Security warning:
This is an educational implementation. It is not constant-time and is not
production-safe. Use audited libraries for real systems.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass


HASHLEN = 32
TAGLEN = 16
MAX_SKIP = 50

X25519_BASEPOINT = (9).to_bytes(32, "little")
P_25519 = (1 << 255) - 19
A24_25519 = 121665

X3DH_INFO = b"mini-signal-lab/x3dh/sk"
DR_RK_INFO = b"mini-signal-lab/double-ratchet/rk"
DR_CK_INFO = b"mini-signal-lab/double-ratchet/ck"
AEAD_ENC_INFO = b"mini-signal-lab/aead/enc"
AEAD_MAC_INFO = b"mini-signal-lab/aead/mac"
SAFETY_NUMBER_INFO = b"mini-signal-lab/safety-number/v1"


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor requires equal-length inputs")
    return bytes(x ^ y for x, y in zip(a, b, strict=True))


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


def x25519(scalar: bytes, u: bytes) -> bytes:
    if len(scalar) != 32 or len(u) != 32:
        raise ValueError("X25519 inputs must be 32 bytes")

    k = int.from_bytes(_clamp_scalar(scalar), "little")
    x1 = int.from_bytes(u, "little")
    x2 = 1
    z2 = 0
    x3 = x1
    z3 = 1
    swap = 0

    for t in reversed(range(255)):
        k_t = (k >> t) & 1
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
        z3 = (x1 * ((da - cb) ** 2 % P_25519)) % P_25519
        x2 = (aa * bb) % P_25519
        z2 = (e * (aa + A24_25519 * e) % P_25519) % P_25519

    x2, x3 = _cswap(swap, x2, x3)
    z2, z3 = _cswap(swap, z2, z3)
    z2_inv = pow(z2, P_25519 - 2, P_25519)
    out = (x2 * z2_inv) % P_25519
    return out.to_bytes(32, "little")


def x25519_public_key(private_scalar: bytes) -> bytes:
    return x25519(private_scalar, X25519_BASEPOINT)


def x25519_is_all_zero(shared: bytes) -> bool:
    return shared == b"\x00" * 32


def dh(dh_priv: bytes, dh_pub: bytes) -> bytes:
    shared = x25519(dh_priv, dh_pub)
    if x25519_is_all_zero(shared):
        raise ValueError("all-zero shared secret (small-order point)")
    return shared


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
    if len(mk) != 32:
        raise ValueError("mk must be 32 bytes")
    if len(tag) != TAGLEN:
        raise ValueError("invalid tag length")
    enc_key = hkdf_sha256(None, mk, AEAD_ENC_INFO, 32)
    mac_key = hkdf_sha256(None, mk, AEAD_MAC_INFO, 32)
    expected = hmac_sha256(mac_key, associated_data + ciphertext)[:TAGLEN]
    if not hmac.compare_digest(expected, tag):
        raise ValueError("authentication failed")
    return xor_bytes(ciphertext, _keystream(enc_key, len(ciphertext)))


def x3dh_kdf(dh_concat: bytes) -> bytes:
    return hkdf_sha256(None, dh_concat, X3DH_INFO, 32)


def x3dh_associated_data(ik_a_pub: bytes, ik_b_pub: bytes) -> bytes:
    if len(ik_a_pub) != 32 or len(ik_b_pub) != 32:
        raise ValueError("identity public keys must be 32 bytes")
    return ik_a_pub + ik_b_pub


def x3dh_initiator(
    ik_a_priv: bytes,
    ek_a_priv: bytes,
    ik_b_pub: bytes,
    spk_b_pub: bytes,
    opk_b_pub: bytes | None,
) -> tuple[bytes, bytes]:
    dh1 = dh(ik_a_priv, spk_b_pub)
    dh2 = dh(ek_a_priv, ik_b_pub)
    dh3 = dh(ek_a_priv, spk_b_pub)
    dh_concat = dh1 + dh2 + dh3
    if opk_b_pub is not None:
        dh4 = dh(ek_a_priv, opk_b_pub)
        dh_concat += dh4
    sk = x3dh_kdf(dh_concat)
    ad = x3dh_associated_data(x25519_public_key(ik_a_priv), ik_b_pub)
    return sk, ad


def x3dh_responder(
    ik_b_priv: bytes,
    spk_b_priv: bytes,
    ik_a_pub: bytes,
    ek_a_pub: bytes,
    opk_b_priv: bytes | None,
) -> tuple[bytes, bytes]:
    dh1 = dh(spk_b_priv, ik_a_pub)
    dh2 = dh(ik_b_priv, ek_a_pub)
    dh3 = dh(spk_b_priv, ek_a_pub)
    dh_concat = dh1 + dh2 + dh3
    if opk_b_priv is not None:
        dh4 = dh(opk_b_priv, ek_a_pub)
        dh_concat += dh4
    sk = x3dh_kdf(dh_concat)
    ad = x3dh_associated_data(ik_a_pub, x25519_public_key(ik_b_priv))
    return sk, ad


def safety_number(ik_a_pub: bytes, ik_b_pub: bytes) -> str:
    if len(ik_a_pub) != 32 or len(ik_b_pub) != 32:
        raise ValueError("identity public keys must be 32 bytes")

    a = sha256(SAFETY_NUMBER_INFO + ik_a_pub)
    b = sha256(SAFETY_NUMBER_INFO + ik_b_pub)
    mod = 10**30
    a_num = int.from_bytes(a[:16], "big") % mod
    b_num = int.from_bytes(b[:16], "big") % mod
    a_str = str(a_num).zfill(30)
    b_str = str(b_num).zfill(30)
    first, second = sorted([a_str, b_str])
    combined = first + second
    groups = [combined[i : i + 5] for i in range(0, len(combined), 5)]
    return " ".join(groups)


@dataclass(frozen=True)
class PreKeyBundlePublic:
    user_id: str
    ik_pub: bytes
    spk_pub: bytes
    spk_id: int
    opk_id: int | None
    opk_pub: bytes | None


@dataclass(frozen=True)
class PreKeyMessage:
    sender_id: str
    recipient_id: str
    sender_ik_pub: bytes
    sender_ek_pub: bytes
    recipient_spk_id: int
    recipient_opk_id: int | None
    header: bytes
    ciphertext: bytes
    tag: bytes


@dataclass(frozen=True)
class SignalMessage:
    sender_id: str
    recipient_id: str
    header: bytes
    ciphertext: bytes
    tag: bytes


class MiniSignalServer:
    def __init__(self) -> None:
        self._bundles: dict[str, tuple[bytes, bytes, int, dict[int, bytes]]] = {}
        self._mailboxes: dict[str, list[object]] = {}

    def publish_prekeys(self, user_id: str, ik_pub: bytes, spk_pub: bytes, spk_id: int, opk_pubs: dict[int, bytes]) -> None:
        self._bundles[user_id] = (ik_pub, spk_pub, spk_id, dict(opk_pubs))

    def fetch_prekey_bundle(self, user_id: str) -> PreKeyBundlePublic:
        if user_id not in self._bundles:
            raise KeyError(f"unknown user_id: {user_id}")
        ik_pub, spk_pub, spk_id, opks = self._bundles[user_id]
        opk_id: int | None = None
        opk_pub: bytes | None = None
        if opks:
            opk_id = min(opks.keys())
            opk_pub = opks.pop(opk_id)
            self._bundles[user_id] = (ik_pub, spk_pub, spk_id, opks)
        return PreKeyBundlePublic(
            user_id=user_id,
            ik_pub=ik_pub,
            spk_pub=spk_pub,
            spk_id=spk_id,
            opk_id=opk_id,
            opk_pub=opk_pub,
        )

    def deliver(self, msg: object) -> None:
        recipient = getattr(msg, "recipient_id", None)
        if not isinstance(recipient, str):
            raise ValueError("message missing recipient_id")
        self._mailboxes.setdefault(recipient, []).append(msg)

    def drain_mailbox(self, user_id: str) -> list[object]:
        msgs = self._mailboxes.get(user_id, [])
        self._mailboxes[user_id] = []
        return msgs


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


@dataclass
class Session:
    peer_id: str
    peer_ik_pub: bytes
    ad: bytes
    ratchet: RatchetState


class MiniSignalClient:
    def __init__(self, user_id: str, server: MiniSignalServer, seed: bytes) -> None:
        self.user_id = user_id
        self.server = server

        self.ik_priv = x25519_private_key_from_seed(seed + b"/ik")
        self.ik_pub = x25519_public_key(self.ik_priv)
        self.spk_priv = x25519_private_key_from_seed(seed + b"/spk")
        self.spk_pub = x25519_public_key(self.spk_priv)
        self.spk_id = int.from_bytes(sha256(seed + b"/spk-id")[:4], "big")

        self.opk_privs: dict[int, bytes] = {}
        opk_pubs: dict[int, bytes] = {}
        for i in range(5):
            opk_priv = x25519_private_key_from_seed(seed + b"/opk/" + bytes([i]))
            opk_id = i
            self.opk_privs[opk_id] = opk_priv
            opk_pubs[opk_id] = x25519_public_key(opk_priv)
        self._opk_pubs_for_server = opk_pubs

        self.known_identities: dict[str, bytes] = {}
        self.sessions: dict[str, Session] = {}

    def publish_prekeys(self) -> None:
        self.server.publish_prekeys(
            user_id=self.user_id,
            ik_pub=self.ik_pub,
            spk_pub=self.spk_pub,
            spk_id=self.spk_id,
            opk_pubs=self._opk_pubs_for_server,
        )

    def _remember_or_warn_identity(self, peer_id: str, peer_ik_pub: bytes) -> None:
        prev = self.known_identities.get(peer_id)
        if prev is None:
            self.known_identities[peer_id] = peer_ik_pub
            return
        if prev != peer_ik_pub:
            raise ValueError(f"identity key changed for {peer_id} (safety number changed)")

    def get_safety_number(self, peer_id: str, peer_ik_pub: bytes) -> str:
        return safety_number(self.ik_pub, peer_ik_pub)

    def initiate_session(self, peer_id: str, plaintext: bytes, seed: bytes) -> PreKeyMessage:
        bundle = self.server.fetch_prekey_bundle(peer_id)
        self._remember_or_warn_identity(peer_id, bundle.ik_pub)

        ek_priv = x25519_private_key_from_seed(seed + b"/ek/" + peer_id.encode("utf-8"))
        ek_pub = x25519_public_key(ek_priv)

        sk, ad = x3dh_initiator(
            ik_a_priv=self.ik_priv,
            ek_a_priv=ek_priv,
            ik_b_pub=bundle.ik_pub,
            spk_b_pub=bundle.spk_pub,
            opk_b_pub=bundle.opk_pub,
        )

        ratchet = dr_init_alice(sk, bob_ratchet_pub=bundle.spk_pub, seed=seed + b"/dr-alice0")
        header, ct, tag = dr_encrypt(ratchet, plaintext, ad)

        self.sessions[peer_id] = Session(peer_id=peer_id, peer_ik_pub=bundle.ik_pub, ad=ad, ratchet=ratchet)
        return PreKeyMessage(
            sender_id=self.user_id,
            recipient_id=peer_id,
            sender_ik_pub=self.ik_pub,
            sender_ek_pub=ek_pub,
            recipient_spk_id=bundle.spk_id,
            recipient_opk_id=bundle.opk_id,
            header=header,
            ciphertext=ct,
            tag=tag,
        )

    def send(self, peer_id: str, plaintext: bytes) -> SignalMessage:
        sess = self.sessions.get(peer_id)
        if sess is None:
            raise ValueError("no session for peer; initiate_session first")
        header, ct, tag = dr_encrypt(sess.ratchet, plaintext, sess.ad)
        return SignalMessage(sender_id=self.user_id, recipient_id=peer_id, header=header, ciphertext=ct, tag=tag)

    def receive(self, msg: object, seed: bytes) -> bytes:
        if isinstance(msg, PreKeyMessage):
            return self._receive_prekey_message(msg, seed=seed)
        if isinstance(msg, SignalMessage):
            return self._receive_signal_message(msg, seed=seed)
        raise TypeError("unknown message type")

    def _receive_prekey_message(self, msg: PreKeyMessage, seed: bytes) -> bytes:
        self._remember_or_warn_identity(msg.sender_id, msg.sender_ik_pub)

        opk_priv = None
        if msg.recipient_opk_id is not None:
            opk_priv = self.opk_privs.get(msg.recipient_opk_id)
            if opk_priv is None:
                raise ValueError("missing OPK private key (already used?)")
            del self.opk_privs[msg.recipient_opk_id]

        sk, ad = x3dh_responder(
            ik_b_priv=self.ik_priv,
            spk_b_priv=self.spk_priv,
            ik_a_pub=msg.sender_ik_pub,
            ek_a_pub=msg.sender_ek_pub,
            opk_b_priv=opk_priv,
        )

        ratchet = dr_init_bob(sk, bob_ratchet_priv=self.spk_priv, bob_ratchet_pub=self.spk_pub)
        plaintext = dr_decrypt(ratchet, msg.header, msg.ciphertext, msg.tag, ad, seed=seed + b"/dr-bob1")
        self.sessions[msg.sender_id] = Session(peer_id=msg.sender_id, peer_ik_pub=msg.sender_ik_pub, ad=ad, ratchet=ratchet)
        return plaintext

    def _receive_signal_message(self, msg: SignalMessage, seed: bytes) -> bytes:
        sess = self.sessions.get(msg.sender_id)
        if sess is None:
            raise ValueError("no session for peer; expected PreKeyMessage first")
        return dr_decrypt(sess.ratchet, msg.header, msg.ciphertext, msg.tag, sess.ad, seed=seed + b"/dr-recv")


def _hx(b: bytes) -> str:
    return b.hex()


def main():
    print("=== Step 1: Primitives: X25519 + HKDF + toy AEAD ===")
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
    mk = bytes(range(32))
    ct, tag = aead_encrypt(mk, b"hello", associated_data=b"ad")
    pt = aead_decrypt(mk, ct, tag, associated_data=b"ad")
    print("AEAD demo:", "ct=", _hx(ct), "tag=", _hx(tag), "pt=", pt.decode())

    print("\n=== Step 2: Prekeys: server bundles + X3DH session setup ===")
    server = MiniSignalServer()
    alice = MiniSignalClient("alice", server, seed=b"Alice")
    bob = MiniSignalClient("bob", server, seed=b"Bob")
    alice.publish_prekeys()
    bob.publish_prekeys()

    bob_bundle_peek = server.fetch_prekey_bundle("bob")
    print("bob bundle has OPK?", bob_bundle_peek.opk_pub is not None)
    print("safety number (alice<->bob):", alice.get_safety_number("bob", bob_bundle_peek.ik_pub))

    prekey_msg = alice.initiate_session("bob", b"hi bob (prekey)", seed=b"AliceSession0")
    server.deliver(prekey_msg)
    server.deliver(alice.send("bob", b"offline-1"))
    server.deliver(alice.send("bob", b"offline-2"))
    print("alice queued 3 messages while bob is offline")

    print("\n=== Step 3: Double Ratchet: decrypt offline + out-of-order ===")
    mailbox = server.drain_mailbox("bob")
    mailbox = [mailbox[0], mailbox[2], mailbox[1]]  # deliver 2nd/3rd out of order
    for msg in mailbox:
        pt = bob.receive(msg, seed=b"BobRecv0")
        print("bob received:", pt.decode())

    print("\n=== Step 4: Mini client loop: reply + break-in recovery intuition ===")
    server.deliver(bob.send("alice", b"hi alice (reply)"))
    attacker_snapshot = alice.sessions["bob"].ratchet.rk
    print("attacker snapshot: stole alice RK =", _hx(attacker_snapshot))

    for msg in server.drain_mailbox("alice"):
        pt = alice.receive(msg, seed=b"AliceRecv1")
        print("alice received:", pt.decode())

    server.deliver(alice.send("bob", b"post-reply-1"))
    for msg in server.drain_mailbox("bob"):
        pt = bob.receive(msg, seed=b"BobRecv2")
        print("bob received:", pt.decode())


if __name__ == "__main__":
    main()
