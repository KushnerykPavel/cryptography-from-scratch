# Noise Protocol Framework — Handshake patterns as a state machine

> A secure handshake is just DH + HKDF + a transcript hash, wired together *exactly right*.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 08 · 04 (Diffie-Hellman), Phase 07 · 12 (HMAC), Phase 07 · 07 (AEAD), Phase 07 · 08 (ChaCha20-Poly1305)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** how Noise turns a “secure channel” into a small state machine (HandshakeState + SymmetricState)
- **Compute** a transcript hash update (`mix_hash`) and see how it binds the handshake to what was actually sent
- **Implement** a minimal Noise-style “symmetric state” (HKDF chaining key + encrypt-and-hash)
- **Distinguish** handshake keys (for *handshake payloads*) from transport keys (for *application data*)
- **Apply** a checklist to review real Noise handshakes (pattern choice, authentication, nonce rules, transcript binding)

## The Problem

It’s easy to say “we’ll do Diffie–Hellman, then encrypt.” It’s hard to ship it safely. Real failures usually aren’t “bad crypto primitives” — they’re **wiring mistakes**: forgetting to authenticate the right thing, reusing nonces, deriving keys without binding the protocol context, or letting an attacker splice messages from different handshakes.

Noise exists because we keep needing the same family of protocols: encrypted tunnels (WireGuard), device pairing, messaging handshakes, and low-level secure transports. Noise gives you a way to assemble these protocols from well-understood pieces — DH, a hash, and an AEAD — while making the *state transitions explicit* and testable.

In this lesson you’ll build a **toy Noise NN handshake** (no authentication) to learn the mechanics. The toy pieces are deliberately simple so you can see the dataflow. Real Noise uses Curve25519, SHA-256/BLAKE2s, and ChaCha20-Poly1305/AES-GCM.

## The Concept

Noise is best understood as two coupled states:

1. **SymmetricState** — the “crypto context” that evolves:
   - `h`: handshake hash (transcript hash)
   - `ck`: chaining key (HKDF salt that gets updated every time we mix in new secret material)
   - `k`: current handshake encryption key (derived from `ck`)
2. **HandshakeState** — a script that says what messages contain:
   - tokens like `e` (send ephemeral), `s` (send static), and DH mixes like `ee`, `es`, `se`, `ss`

The core invariants:

- **Transcript binding**: every byte that goes on the wire gets folded into `h` via `mix_hash(h, data)`.
- **Key schedule as a ratchet**: every time a new secret arrives (a DH result), we run `mix_key(ck, secret)` so future keys depend on it.
- **Encrypt-and-hash**: when a payload is encrypted during the handshake, the ciphertext is also hashed into `h` so both sides agree on the transcript.

### Handshake patterns (mental model)

A Noise pattern is a tiny “program” describing message flow. Example: **NN** (no static keys):

- Message 1 (initiator → responder): send initiator ephemeral `e`
- Message 2 (responder → initiator): send responder ephemeral `e`, compute DH `ee`, then optionally encrypt a payload under the derived handshake key

Noise patterns that matter in practice (names vary by setting):

| Pattern | What it gives you | When you use it |
|--------|--------------------|-----------------|
| `NN` | confidentiality only | bootstrapping / demos / “no identity” channels |
| `IK` | server is authenticated | client knows server’s static key (common for tunnels) |
| `XX` | mutual authentication *after* DH | interactive pairing when neither side has prior keys |

## Build It

### Step 1: hash + HKDF (chaining key)

Noise’s “key schedule” is **HKDF chained over time**: a `ck` value that gets updated whenever we mix in fresh secret material (like a DH output). In parallel, we keep a transcript hash `h` that commits to what was sent.

```python
import hashlib
import hmac

HASHLEN = 32


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def hkdf_sha256(chaining_key: bytes, input_key_material: bytes, num_outputs: int = 2) -> list[bytes]:
    if len(chaining_key) != HASHLEN:
        raise ValueError("chaining_key must be 32 bytes")
    if num_outputs < 1 or num_outputs > 3:
        raise ValueError("num_outputs must be 1..3 (Noise-style HKDF)")

    prk = hmac_sha256(chaining_key, input_key_material)
    out: list[bytes] = []
    t = b""
    for i in range(1, num_outputs + 1):
        t = hmac_sha256(prk, t + bytes([i]))
        out.append(t)
    return out


def initialize_symmetric(protocol_name: str) -> tuple[bytes, bytes]:
    name_bytes = protocol_name.encode("utf-8")
    if len(name_bytes) <= HASHLEN:
        h = name_bytes + b"\x00" * (HASHLEN - len(name_bytes))
    else:
        h = sha256(name_bytes)
    ck = h
    return ck, h


def mix_hash(h: bytes, data: bytes) -> bytes:
    if len(h) != HASHLEN:
        raise ValueError("h must be 32 bytes")
    return sha256(h + data)


def mix_key(ck: bytes, input_key_material: bytes) -> tuple[bytes, bytes]:
    out = hkdf_sha256(ck, input_key_material, num_outputs=2)
    return out[0], out[1]
```

### Step 2: toy Diffie-Hellman (mod prime)

Noise needs a DH primitive. In real deployments this is almost always Curve25519, but for this lesson we use “classic DH mod p” so the math is obvious and stdlib-only.

```python
import random
import secrets

DH_P = (1 << 127) - 1
DH_G = 3
DH_PUB_LEN = 32


def int_to_bytes(n: int, length: int) -> bytes:
    if n < 0:
        raise ValueError("n must be non-negative")
    out = n.to_bytes(length, "big", signed=False)
    if int.from_bytes(out, "big") != n:
        raise ValueError("integer does not fit")
    return out


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big", signed=False)


def encode_dh_public_key(public_key: int) -> bytes:
    if not (1 <= public_key <= DH_P - 1):
        raise ValueError("public_key out of range")
    return int_to_bytes(public_key, DH_PUB_LEN)


def decode_dh_public_key(public_key_bytes: bytes) -> int:
    if len(public_key_bytes) != DH_PUB_LEN:
        raise ValueError("wrong public key length")
    public_key = bytes_to_int(public_key_bytes)
    if not (1 <= public_key <= DH_P - 1):
        raise ValueError("public_key out of range")
    return public_key


def dh_public_key(private_key: int) -> int:
    if not (1 <= private_key <= DH_P - 2):
        raise ValueError("private_key out of range")
    return pow(DH_G, private_key, DH_P)


def dh_keypair(rng: random.Random | None = None) -> tuple[int, int]:
    if rng is None:
        private_key = secrets.randbelow(DH_P - 2) + 1
    else:
        private_key = (rng.getrandbits(256) % (DH_P - 2)) + 1
    return private_key, dh_public_key(private_key)


def dh_shared_secret(private_key: int, public_key: int) -> bytes:
    if not (1 <= public_key <= DH_P - 1):
        raise ValueError("public_key out of range")
    shared = pow(public_key, private_key, DH_P)
    return int_to_bytes(shared, DH_PUB_LEN)
```

### Step 3: symmetric state (mix_hash / mix_key / encrypt_and_hash)

Noise handshakes often have encrypted payloads (identities, certificates, PSK identifiers). The rule is: **encrypt, then hash the ciphertext into the transcript**.

We use a toy “AEAD” to demonstrate the API shape and nonce discipline; it is not secure.

```python
TAGLEN = 16


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))


def _keystream(key: bytes, nonce: int, length: int) -> bytes:
    if len(key) != HASHLEN:
        raise ValueError("key must be 32 bytes")
    if nonce < 0 or nonce >= 1 << 64:
        raise ValueError("nonce must fit uint64")
    nonce_bytes = int_to_bytes(nonce, 8)
    out = bytearray()
    counter = 0
    while len(out) < length:
        counter_bytes = int_to_bytes(counter, 4)
        block = hmac_sha256(key, b"stream" + nonce_bytes + counter_bytes)
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def aead_encrypt(key: bytes, nonce: int, aad: bytes, plaintext: bytes) -> bytes:
    stream = _keystream(key, nonce, len(plaintext))
    ciphertext = xor_bytes(plaintext, stream)
    nonce_bytes = int_to_bytes(nonce, 8)
    tag = hmac_sha256(key, b"tag" + nonce_bytes + aad + ciphertext)[:TAGLEN]
    return ciphertext + tag


def aead_decrypt(key: bytes, nonce: int, aad: bytes, ciphertext_and_tag: bytes) -> bytes:
    if len(ciphertext_and_tag) < TAGLEN:
        raise ValueError("ciphertext too short")
    ciphertext = ciphertext_and_tag[:-TAGLEN]
    tag = ciphertext_and_tag[-TAGLEN:]
    nonce_bytes = int_to_bytes(nonce, 8)
    expected = hmac_sha256(key, b"tag" + nonce_bytes + aad + ciphertext)[:TAGLEN]
    if not hmac.compare_digest(tag, expected):
        raise ValueError("tag mismatch")
    stream = _keystream(key, nonce, len(ciphertext))
    return xor_bytes(ciphertext, stream)


def encrypt_and_hash(k: bytes | None, h: bytes, nonce: int, plaintext: bytes) -> tuple[bytes, bytes]:
    if k is None:
        ciphertext = plaintext
    else:
        ciphertext = aead_encrypt(k, nonce, aad=h, plaintext=plaintext)
    h2 = mix_hash(h, ciphertext)
    return h2, ciphertext


def decrypt_and_hash(k: bytes | None, h: bytes, nonce: int, ciphertext: bytes) -> tuple[bytes, bytes]:
    if k is None:
        plaintext = ciphertext
    else:
        plaintext = aead_decrypt(k, nonce, aad=h, ciphertext_and_tag=ciphertext)
    h2 = mix_hash(h, ciphertext)
    return h2, plaintext
```

### Step 4: Noise NN handshake (toy)

Now we wire the pieces together into the smallest recognizable Noise handshake: **NN** (no authentication). The output is a pair of transport keys in each direction (initiator→responder and responder→initiator).

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class HandshakeResult:
    initiator_tx: bytes
    initiator_rx: bytes
    responder_tx: bytes
    responder_rx: bytes
    handshake_hash: bytes


def noise_nn_handshake(
    initiator_e_priv: int,
    responder_e_priv: int,
    prologue: bytes = b"",
    protocol_name: str = "Noise_NN_25519_SHA256_ToyAEAD",
) -> HandshakeResult:
    ck_i, h_i = initialize_symmetric(protocol_name)
    ck_r, h_r = ck_i, h_i
    if prologue:
        h_i = mix_hash(h_i, prologue)
        h_r = mix_hash(h_r, prologue)

    e_i_pub = dh_public_key(initiator_e_priv)
    msg1 = encode_dh_public_key(e_i_pub)
    h_i = mix_hash(h_i, msg1)
    h_r = mix_hash(h_r, msg1)

    e_r_pub = dh_public_key(responder_e_priv)
    msg2 = encode_dh_public_key(e_r_pub)
    h_r = mix_hash(h_r, msg2)

    ss_r = dh_shared_secret(responder_e_priv, e_i_pub)
    ck_r, k_r = mix_key(ck_r, ss_r)
    h_r, payload2 = encrypt_and_hash(k_r, h_r, nonce=0, plaintext=b"responder:ok")

    h_i = mix_hash(h_i, msg2)
    ss_i = dh_shared_secret(initiator_e_priv, e_r_pub)
    ck_i, k_i = mix_key(ck_i, ss_i)
    h_i, payload_plain = decrypt_and_hash(k_i, h_i, nonce=0, ciphertext=payload2)
    if payload_plain != b"responder:ok":
        raise ValueError("bad responder payload")

    t1_i, t2_i = hkdf_sha256(ck_i, b"", num_outputs=2)
    t1_r, t2_r = hkdf_sha256(ck_r, b"", num_outputs=2)

    return HandshakeResult(
        initiator_tx=t1_i,
        initiator_rx=t2_i,
        responder_tx=t2_r,
        responder_rx=t1_r,
        handshake_hash=h_i,
    )
```

Run it:

```bash
python3 code/main.py
```

## Use It

Noise in production is “choose a pattern + choose primitives + run an audited implementation”.

| Need | Production equivalent |
|------|------------------------|
| Implement Noise in Rust | `snow` (Rust Noise Protocol Framework implementation) |
| Implement Noise in C | `noise-c` / `noise-protocol` family implementations |
| Design / verify patterns | Noise Explorer (pattern visualization + test harness) |
| Real protocol built on Noise | WireGuard (NoiseIK), many messaging transports, device pairing protocols |

In audited stacks you do **not** write the cryptography yourself — you select the pattern, set identity/authentication policy, and ensure nonces and transcript binding are correct.

## Pitfalls

1. **Picking `NN` when you needed authentication.** `NN` is confidential but unauthenticated: a MitM can negotiate two separate handshakes and relay traffic.
2. **Nonce misuse in transport mode.** AEAD nonces must never repeat under the same key; ensure counters are per-direction and never reset on rekey.
3. **Forgetting transcript binding.** If you don’t hash what you send/receive into `h`, you lose key confirmation and open splicing/downgrade bugs.
4. **Not validating DH public keys.** At minimum: range checks / decoding rules; in some groups you also need subgroup checks.
5. **Key confusion (handshake vs transport).** Handshake keys protect handshake payloads; transport keys protect application data. Mixing them breaks forward secrecy and auditability.

## Ship It

Save and reuse the checklist in `outputs/noise-handshake-review-checklist.md` when:

- reviewing a PR that introduces or modifies a Noise handshake,
- selecting a handshake pattern for a new protocol,
- auditing a “custom secure channel” that claims to be Noise-like.

It’s designed to be pasted into a code review comment or into an LLM to drive a structured audit.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe: the initiator’s `tx` key equals the responder’s `rx` key (and vice versa).
2. Medium. Extend: add a new encrypted payload from the initiator to the responder after keys are split (use `aead_encrypt` / `aead_decrypt` with a nonce counter).
3. Hard. Production integration: pick a real Noise library (`snow` in Rust or a C implementation) and implement an authenticated pattern (e.g., `IK`), then compare the high-level state transitions to this lesson’s toy `NN`.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Noise pattern | “A handshake type” | A script for what each message contains (`e`, `s`, `ee`, `es`, `se`, `ss`) |
| Transcript hash (`h`) | “The handshake hash” | A commitment to everything sent/received so far; used as AEAD AAD during the handshake |
| Chaining key (`ck`) | “The key schedule” | An HKDF salt that evolves as new secrets are mixed in; used to derive keys safely |
| `mix_hash` | “Hash the transcript” | Update `h := HASH(h || data)` to bind the protocol state to bytes on the wire |
| `mix_key` | “Derive a new key” | Update `ck` (and derive a temp key) using HKDF with fresh secret input |

## Further Reading

- Trevor Perrin, “The Noise Protocol Framework” (spec) — the canonical description of patterns, state, and functions.
- Trevor Perrin, “Noise Explorer” — visualize patterns and sanity-check message flows.
- Jason A. Donenfeld, “WireGuard” (whitepaper / protocol docs) — a widely deployed Noise-based tunnel protocol.
