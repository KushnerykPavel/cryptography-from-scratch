# Signal Protocol — X3DH & Double Ratchet (Educational)

> **Handshake once, then change keys every message.**

**Type:** Build  
**Languages:** Python  
**Prerequisites:**  
- `phases/07-symmetric-crypto/13-kdfs` (HKDF mindset: extract/expand, info labels)  
- `phases/08-classical-asymmetric/04-diffie-hellman` (DH as “shared secret + KDF”)  
- `phases/10-protocols/03-noise-framework` (transcripts, KDF chains, AEAD shape)  
**Time:** ~120 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** why X3DH enables “send while Bob is offline”
- **Compute** the X3DH DH outputs (DH1..DH3) and bind identities with AD
- **Implement** a Double Ratchet loop (RK/CKs/CKr, header, encrypt/decrypt)
- **Distinguish** the DH ratchet (break-in recovery) from the symmetric ratchet (forward secrecy)
- **Apply** “skipped message keys” to decrypt out-of-order messages

## The Problem

Messaging is asynchronous: Bob goes offline, Alice still needs to send a message that only Bob can read. Even after they have a shared key, you also want “damage containment”: if an attacker compromises Alice’s phone *today*, they shouldn’t be able to decrypt *yesterday’s* messages, and (ideally) they shouldn’t be able to decrypt *all future* messages either once Alice and Bob keep talking.

Vanilla ECDH gives you one shared secret. Use that same key for many messages and you lose forward secrecy: compromise the key once and you lose everything. Rotate keys manually and you lose usability, ordering, and offline delivery.

Signal-style secure messaging solves this with two layers: **X3DH** (asynchronous authenticated key agreement) and the **Double Ratchet** (per-message keys, plus break‑in recovery).

## The Concept

Think in two phases:

1) **X3DH handshake (asynchronous key agreement)**  
Bob publishes a “prekey bundle” to a server (identity key + signed prekey + optional one-time prekeys). Alice fetches it, performs 3 (or 4) DH computations, and KDFs them into a 32‑byte shared secret `SK`. Bob can later recompute the same `SK` when he receives Alice’s first message.

2) **Double Ratchet (key evolution for ongoing messages)**  
Starting from `SK` as the initial **root key**, every message derives a fresh **message key** from a **chain key** (symmetric ratchet). Whenever a new DH ratchet public key arrives, both sides mix a new DH shared secret into the root key, resetting chain keys (DH ratchet). This is what gives “post-compromise security”: after compromise, later DH steps can heal the session.

Minimal state (per party):

| Name | Meaning |
|---|---|
| `RK` | Root key (32 bytes) |
| `DHs` / `DHr` | My DH ratchet keypair / their DH ratchet public key |
| `CKs` / `CKr` | Sending / receiving chain keys |
| `Ns` / `Nr` | Message numbers in current chains |
| `PN` | Length of previous sending chain |
| `MKSKIPPED` | Cached message keys for out-of-order delivery |

This lesson implements a *minimal* Double Ratchet with plaintext headers and a toy AEAD (XOR stream + HMAC tag) using stdlib only.

## Build It

### Step 1: X25519 + HKDF building blocks
We need two primitives:
- **X25519** for ECDH shared secrets.
- **HKDF-SHA256** for turning messy DH outputs into uniform keys, and for key separation (different `info` strings).

```python
import hashlib
import hmac

HASHLEN = 32
X25519_BASEPOINT = (9).to_bytes(32, "little")

P_25519 = (1 << 255) - 19
A24_25519 = 121665


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


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


def x25519_public_key(private_key: bytes) -> bytes:
    return x25519(private_key, X25519_BASEPOINT)


def x25519_is_all_zero(shared_secret: bytes) -> bool:
    return all(b == 0 for b in shared_secret)
```

This gives us reproducible DH shared secrets (with an all‑zero rejection helper) and HKDF for key derivation.

### Step 2: X3DH: derive a shared session secret
X3DH combines three DH results (and sometimes a fourth if Bob provides a one‑time prekey). We then KDF the concatenation into a 32‑byte `SK`, and compute “associated data” `AD` that binds identities.

```python
X3DH_SALT = b"\x00" * HASHLEN
X3DH_INFO = b"cryptography-from-scratch:X3DH"


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
```

This is the “asynchronous handshake” core: Alice can compute `SK` using Bob’s published keys; Bob can later recompute `SK` using Alice’s `IK_A` and `EK_A` from the first message.

### Step 3: Double Ratchet state + KDF chains
We now treat X3DH’s `SK` as the **initial root key** and derive sending/receiving chain keys. Each message uses a unique message key derived from the chain key; each DH ratchet step mixes a fresh DH output into the root key, resetting chains.

```python
from dataclasses import dataclass
import os

DR_RK_INFO = b"cryptography-from-scratch:DoubleRatchet:RK"
DR_CK_INFO = b"cryptography-from-scratch:DoubleRatchet:CK"

AEAD_ENC_INFO = b"cryptography-from-scratch:AEAD:enc"
AEAD_MAC_INFO = b"cryptography-from-scratch:AEAD:mac"

TAGLEN = 16


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))


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
```

This defines the ratchet KDFs, a minimal AEAD shape, and the state container.

### Step 4: Message flow: out-of-order decryption via skipped keys
To decrypt out-of-order messages, we advance the receiving chain to the message number `N`, caching skipped message keys in a dictionary so delayed packets can still be decrypted later.

```python
MAX_SKIP = 50


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
```

This is the heart of “out-of-order tolerance”: you can advance the chain to `N`, cache skipped keys, decrypt the message, and still decrypt late arrivals.

Run it:

```bash
python3 code/main.py
```

## Use It

Production implementations do **not** roll their own crypto primitives:
- **Signal / libsignal:** reference implementation and audited protocol framing.
- **libsodium:** provides X25519 and AEAD primitives (but not full X3DH/Double Ratchet state machines).
- **Matrix Olm:** implements a Signal-like Double Ratchet for 1:1 sessions.

If you ever ship something like this, use audited libraries for:
- X25519 (Curve25519 ECDH)
- HKDF (RFC 5869)
- AEAD (AES‑GCM or ChaCha20‑Poly1305)
- Ed25519 signatures (for signed prekeys)

## Pitfalls

1. **Skipping signature verification on Bob’s signed prekey.** Without it, a malicious server can MITM X3DH.  
2. **Not rejecting all‑zero X25519 shared secrets.** Small‑order points can force predictable shared secrets.  
3. **Reusing message keys.** Any reuse breaks AEAD security assumptions.  
4. **Unbounded skipped‑key storage.** Without `MAX_SKIP`, a malicious peer can DoS memory/CPU.  
5. **Forgetting identity binding.** You need AD / transcript binding and a UI/verification story (safety numbers, key transparency, etc.).

## Ship It

This lesson ships a reusable PR/audit checklist for Signal-style session protocols:
- Open `outputs/signal-x3dh-double-ratchet-review-checklist.md`
- Use it to review any “we implemented Signal-like E2EE” design or PR (including your own)
- It includes concrete checks for X3DH, Double Ratchet, headers, skipped keys, and DoS limits

## Exercises

1. **Easy.** Run `python3 code/main.py`. Observe that Bob can decrypt messages delivered out of order.  
2. **Medium.** Extend X3DH to include an optional one‑time prekey `OPK_B` (add DH4 and pass `opk_b_pub/opk_b_priv`). Add a vector to `tests/vectors.json`.  
3. **Hard.** Replace the toy AEAD with a real audited AEAD (AES‑GCM or ChaCha20‑Poly1305) using a production library, and keep the ratchet logic the same.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| X3DH | “Triple DH handshake” | Asynchronous key agreement using 3–4 DHs + HKDF to derive `SK` |
| Prekey bundle | “Bob’s published keys” | The server-stored public keys Alice fetches to start a session |
| AD (associated data) | “Extra authenticated data” | Identity-binding bytes authenticated by AEAD but not encrypted |
| Root key (`RK`) | “Master key” | The evolving secret mixed with DH outputs to reset chains |
| Chain key (`CK`) | “Per-direction ratchet key” | Secret that advances one-way to derive message keys |
| Message key (`MK`) | “One-time encryption key” | Single-use key to encrypt/authenticate one message |
| DH ratchet | “PCS / healing” | When a new DH public key arrives, mix fresh DH into `RK` |
| Skipped keys | “Out-of-order support” | Cached message keys for delayed packets, bounded by `MAX_SKIP` |

## Further Reading

- Marlinspike, Perrin, *The X3DH Key Agreement Protocol* (2016) — Signal’s asynchronous handshake spec.  
- Perrin, Marlinspike, Schmidt, *The Double Ratchet Algorithm* (2025 revision) — ratchet state machine + skipped keys + header encryption variant.  
- Langley et al., *RFC 7748: Elliptic Curves for Security* (2016) — X25519 definition + test vectors.  
- Krawczyk, Eronen, *RFC 5869: HKDF* (2010) — HKDF extract/expand + test vectors.  
