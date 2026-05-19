# TLS 1.3 — Handshake Walkthrough
> TLS 1.3 is HKDF over a transcript: if the transcript changes, the keys change.

**Type:** Learn
**Languages:** Python
**Prerequisites:** Phase 7 · 09 (SHA-256), Phase 7 · 12 (HMAC), Phase 7 · 13 (HKDF), Phase 8 · 10 (X25519 ECDH), Phase 7 · 07 (AEAD basics)
**Time:** ~120 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain the TLS 1.3 key schedule as a small set of HKDF calls.
- Compute transcript hashes at the points the handshake binds secrets to messages.
- Implement HKDF-Extract/Expand and TLS 1.3 HKDF-Expand-Label (SHA-256) in pure Python.
- Distinguish handshake traffic secrets vs application traffic secrets and what transcript each one authenticates.
- Apply a review checklist to spot common TLS 1.3 handshake/key-schedule mistakes in real code.

## The Problem

You can use TLS every day and still be unable to answer basic debugging questions: “Why did a client reject the server’s Finished?”, “Why did a middlebox break the connection after ServerHello?”, or “Why does key update work without a new handshake?” When those issues happen, logs often show only “decrypt_error” or “bad_record_mac” — and you’re left guessing.

TLS 1.3 fixes many historical TLS problems, but it does so by making the handshake *cryptographically tight*: every step is bound into a transcript hash, and keys are derived from that transcript via HKDF. If you don’t understand the “HKDF over a transcript” pattern, you can’t reason about what TLS is authenticating, what’s encrypted under which keys, or why a tiny change in handshake bytes produces completely different traffic keys.

This lesson gives you a concrete, runnable key-schedule walkthrough. It does **not** implement a full TLS stack (that’s the next lesson). Instead, you’ll implement the parts you need to read TLS traces, review TLS code, and understand why Finished is the handshake’s “cryptographic receipt.”

## The Concept

TLS 1.3 has many moving parts (extensions, certificate validation, signature schemes, groups, PSKs, 0-RTT), but the cryptographic spine is surprisingly small:

1. Hash the handshake transcript.
2. Use HKDF to derive secrets from (a) a shared secret (ECDHE) and (b) those transcript hashes.
3. Turn traffic secrets into AEAD keys/IVs.
4. Compute Finished `verify_data = HMAC(finished_key, transcript_hash)`.

The key schedule is easiest to remember as *a ladder of secrets*:

| Stage | What it’s for | What it’s derived from |
|------:|---------------|------------------------|
| `early_secret` | PSK/0-RTT (optional) | `HKDF-Extract(0, PSK)` |
| `handshake_secret` | handshake encryption + Finished | `HKDF-Extract(Derive-Secret(early_secret,\"derived\"), ECDHE)` |
| `master_secret` | application encryption + resumption | `HKDF-Extract(Derive-Secret(handshake_secret,\"derived\"), 0)` |

From each “big” secret you derive *traffic secrets* bound to a transcript hash:

- `c hs traffic`, `s hs traffic` are bound to `TH(ClientHello .. ServerHello)`
- `c ap traffic`, `s ap traffic` are bound to `TH(ClientHello .. ServerFinished)`

Finally, every traffic secret produces three important things:

- `key = HKDF-Expand-Label(traffic_secret, "key", "", key_len)`
- `iv  = HKDF-Expand-Label(traffic_secret, "iv",  "", iv_len)`
- `finished_key = HKDF-Expand-Label(traffic_secret, "finished", "", Hash.length)`

…and Finished is just:

```
verify_data = HMAC(finished_key, transcript_hash)
```

## Build It

### Step 1: HKDF + TLS 1.3 labels
This step gives you deterministic building blocks: SHA-256, HMAC-SHA256, HKDF-Extract/Expand, and TLS 1.3’s `HKDF-Expand-Label` wrapper (the `"tls13 "` label prefix is part of the spec). Everything else in this lesson is built out of these functions.

```python
import hashlib
import hmac


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def hex_to_bytes(hex_str: str) -> bytes:
    s = hex_str.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    _require(len(s) % 2 == 0, "hex string must have even length")
    _require(all(c in "0123456789abcdef" for c in s), "invalid hex string")
    return bytes.fromhex(s)


def bytes_to_hex(data: bytes) -> str:
    return data.hex()


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def hkdf_extract_sha256(salt: bytes | None, ikm: bytes) -> bytes:
    if not salt:
        salt = b"\x00" * hashlib.sha256().digest_size
    return hmac_sha256(salt, ikm)


def hkdf_expand_sha256(prk: bytes, info: bytes, length: int) -> bytes:
    hash_len = hashlib.sha256().digest_size
    _require(length >= 0, "length must be non-negative")
    _require(length <= 255 * hash_len, "length too large for HKDF-Expand")

    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac_sha256(prk, t + info + bytes([counter]))
        okm += t
        counter += 1
    return okm[:length]


def tls13_hkdf_label(length: int, label: str, context: bytes) -> bytes:
    _require(0 <= length <= 0xFFFF, "length must fit in uint16")
    label_bytes = b"tls13 " + label.encode("ascii")
    _require(len(label_bytes) <= 255, "label too long")
    _require(len(context) <= 255, "context too long")

    return (
        length.to_bytes(2, "big")
        + bytes([len(label_bytes)])
        + label_bytes
        + bytes([len(context)])
        + context
    )


def hkdf_expand_label_sha256(
    secret: bytes, label: str, context: bytes, length: int
) -> bytes:
    info = tls13_hkdf_label(length=length, label=label, context=context)
    return hkdf_expand_sha256(prk=secret, info=info, length=length)
```

### Step 2: Transcript hash
TLS binds secrets to “everything that happened so far” by hashing the exact handshake bytes. In a real TLS stack, the transcript is the serialized handshake messages (including types and lengths). In this lesson we use a toy transcript made of deterministic byte strings, so you can see the key idea: change the transcript → change every derived secret.

```python
import hashlib
from dataclasses import dataclass
from typing import Iterable


def transcript_hash_sha256(handshake_messages: Iterable[bytes]) -> bytes:
    h = hashlib.sha256()
    for msg in handshake_messages:
        h.update(msg)
    return h.digest()


@dataclass(frozen=True)
class TLS13ToyHandshake:
    client_hello: bytes
    server_hello: bytes
    encrypted_extensions: bytes
    server_certificate: bytes
    server_certificate_verify: bytes
    server_finished: bytes

    def up_to_server_hello(self) -> list[bytes]:
        return [self.client_hello, self.server_hello]

    def up_to_server_finished_exclusive(self) -> list[bytes]:
        return [
            self.client_hello,
            self.server_hello,
            self.encrypted_extensions,
            self.server_certificate,
            self.server_certificate_verify,
        ]

    def up_to_server_finished_inclusive(self) -> list[bytes]:
        return self.up_to_server_finished_exclusive() + [self.server_finished]
```

### Step 3: Key schedule (secrets)
Now you can implement the “ladder of secrets” with a small number of calls. The important detail is the transcript hash each stage uses (ServerHello for handshake traffic; ServerFinished for application traffic).

```python
import hashlib


def derive_secret_sha256(secret: bytes, label: str, transcript_hash: bytes) -> bytes:
    hash_len = hashlib.sha256().digest_size
    return hkdf_expand_label_sha256(
        secret=secret, label=label, context=transcript_hash, length=hash_len
    )


def tls13_key_schedule_sha256(
    shared_secret: bytes, transcript: TLS13ToyHandshake
) -> dict[str, bytes]:
    hash_len = hashlib.sha256().digest_size
    empty_hash = sha256(b"")

    early_secret = hkdf_extract_sha256(salt=None, ikm=b"")
    derived_early = derive_secret_sha256(early_secret, "derived", empty_hash)
    handshake_secret = hkdf_extract_sha256(salt=derived_early, ikm=shared_secret)

    th_server_hello = transcript_hash_sha256(transcript.up_to_server_hello())
    c_hs_traffic = derive_secret_sha256(
        handshake_secret, "c hs traffic", th_server_hello
    )
    s_hs_traffic = derive_secret_sha256(
        handshake_secret, "s hs traffic", th_server_hello
    )

    derived_handshake = derive_secret_sha256(handshake_secret, "derived", empty_hash)
    master_secret = hkdf_extract_sha256(salt=derived_handshake, ikm=b"")

    th_server_finished = transcript_hash_sha256(transcript.up_to_server_finished_inclusive())
    c_ap_traffic_0 = derive_secret_sha256(
        master_secret, "c ap traffic", th_server_finished
    )
    s_ap_traffic_0 = derive_secret_sha256(
        master_secret, "s ap traffic", th_server_finished
    )

    exp_master = derive_secret_sha256(master_secret, "exp master", th_server_finished)
    res_master = derive_secret_sha256(master_secret, "res master", th_server_finished)

    _require(len(early_secret) == hash_len, "unexpected early_secret length")
    return {
        "early_secret": early_secret,
        "handshake_secret": handshake_secret,
        "c_hs_traffic": c_hs_traffic,
        "s_hs_traffic": s_hs_traffic,
        "master_secret": master_secret,
        "c_ap_traffic_0": c_ap_traffic_0,
        "s_ap_traffic_0": s_ap_traffic_0,
        "exp_master": exp_master,
        "res_master": res_master,
    }
```

### Step 4: Finished + key update
Finished is the handshake’s “receipt”: both sides prove they derived the same handshake traffic secret *and* saw the same transcript by sending `verify_data = HMAC(finished_key, transcript_hash)`. After the handshake, KeyUpdate rotates application traffic secrets without redoing authentication.

```python
import hashlib


def traffic_key_iv_sha256(traffic_secret: bytes) -> tuple[bytes, bytes]:
    key = hkdf_expand_label_sha256(
        secret=traffic_secret, label="key", context=b"", length=16
    )
    iv = hkdf_expand_label_sha256(
        secret=traffic_secret, label="iv", context=b"", length=12
    )
    return key, iv


def finished_key_sha256(base_key: bytes) -> bytes:
    hash_len = hashlib.sha256().digest_size
    return hkdf_expand_label_sha256(
        secret=base_key, label="finished", context=b"", length=hash_len
    )


def finished_verify_data_sha256(finished_key: bytes, transcript_hash: bytes) -> bytes:
    return hmac_sha256(finished_key, transcript_hash)


def update_traffic_secret_sha256(traffic_secret: bytes) -> bytes:
    hash_len = hashlib.sha256().digest_size
    return hkdf_expand_label_sha256(
        secret=traffic_secret, label="traffic upd", context=b"", length=hash_len
    )
```

Run it:
python3 code/main.py

## Use It

In production you should not implement TLS yourself. Use a mature TLS stack and let it handle transcript construction, signature verification, and constant-time AEAD.

- **Python:** `ssl` (uses OpenSSL under the hood on most platforms).
- **C/C++:** OpenSSL, BoringSSL.
- **Rust:** rustls (pure-Rust TLS, built on ring/crypto crates).
- **Mozilla:** NSS (Firefox).

When you *do* need to understand the key schedule, use real tooling:

- **Wireshark** + (key log) to decrypt traffic and see transcript boundaries.
- **OpenSSL** `-keylogfile` / environment key logging to inspect secrets in dev.

## Pitfalls

- Building the transcript hash over the *wrong bytes* (missing handshake headers, wrong message order, omitting an extension).
- Forgetting the `"tls13 "` prefix in HKDF labels (or using TLS 1.2-style labels).
- Deriving application traffic secrets from the wrong transcript (e.g., stopping at ServerHello instead of ServerFinished).
- Reusing the same traffic secret for multiple directions (client/server) or multiple epochs (handshake vs application).
- Getting lengths wrong (AES-128-GCM uses 16-byte keys and 12-byte IVs; changing AEAD changes these).

## Ship It

Save and use the checklist in `outputs/tls13-handshake-review-checklist.md` when reviewing TLS-related code:

1. Paste the checklist into a PR review comment when you see TLS handshake logic or custom TLS-like protocols.
2. Use it to confirm: transcript boundaries, labels, key/IV lengths, Finished calculation, and key updates are all correct.
3. Treat any “we built our own TLS” diff as high risk; use the checklist to push the design toward a mature library.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe that changing any transcript message would change every derived secret.
2. Medium. In `code/main.py`, change one transcript string (e.g., ALPN `h2` → `http/1.1`) and re-run. Identify which outputs change and explain *why*.
3. Hard. Use Python’s `ssl` with key logging enabled, capture a TLS 1.3 handshake with Wireshark, and map the real handshake message boundary (ClientHello..ServerHello..ServerFinished) to the transcript-hash checkpoints from this lesson.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Transcript hash | “The handshake hash” | SHA-256 over the serialized handshake messages so far (exact bytes, exact order). |
| HKDF-Extract | “Turn input into a secret” | `PRK = HMAC(salt, IKM)`; mixes entropy and binds it to a salt. |
| HKDF-Expand | “Stretch a secret” | Deterministically expands `PRK` into `L` bytes using HMAC in a chain. |
| HKDF-Expand-Label | “TLS’s HKDF” | TLS 1.3 wrapper that prefixes labels with `"tls13 "` and encodes length/context. |
| Traffic secret | “The session key” | Per-direction, per-epoch secret that derives AEAD keys/IVs and Finished keys. |

## Further Reading

- Rescorla, *The Transport Layer Security (TLS) Protocol Version 1.3* (RFC 8446, 2018) — the spec; Section 7.1 is the key schedule.
- Krawczyk, *HMAC-based Extract-and-Expand Key Derivation Function (HKDF)* (RFC 5869, 2010) — HKDF defined with concrete test vectors.
- Rescorla, *Example Handshake Traces for TLS 1.3* (RFC 8448, 2018) — end-to-end worked examples you can compare to.
