# TLS 1.3 — Implement the Handshake from Scratch
> Everything is HKDF over a transcript hash.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 07 · 09 (SHA-256), Phase 07 · 12 (HMAC), Phase 07 · 13 (KDFs), Phase 10 · 01 (TLS 1.3 Walkthrough)
**Time:** ~120 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain how TLS 1.3 turns a DH shared secret into multiple traffic secrets.
- Compute `HKDF-Extract` and `HKDF-Expand` and verify against RFC 5869 vectors.
- Implement `HKDF-Expand-Label` / `Derive-Secret` and verify against RFC 8448.
- Distinguish “raw transcript bytes” from “transcript hash” and where each is used.
- Apply the key schedule to derive handshake traffic keys and Finished `verify_data`.

## The Problem
TLS 1.3 feels like magic in packet traces: after `ServerHello`, everything turns into encrypted blobs, yet the handshake still authenticates the server and proves both sides derived the *same* keys. If you can’t compute the key schedule yourself, you can’t debug why a handshake fails (wrong transcript, wrong labels, wrong hash, wrong secret), and you can’t audit an implementation for subtle but catastrophic mistakes.

In practice, real incidents come from “small” mismatches: hashing the wrong bytes into the transcript, mixing up client/server traffic secrets, or encoding the `HkdfLabel` wrong by a single length byte. Those bugs don’t look like “crypto broke”; they look like random decryption failures or “bad record MAC”.

This lesson builds the hash-only core of TLS 1.3: HKDF, `HKDF-Expand-Label`, transcript hashing, traffic key derivation, and Finished `verify_data`, validated end-to-end against the canonical RFC 8448 handshake trace.

## The Concept
TLS 1.3 is a *key schedule* that repeatedly takes an input secret and “expands” it into multiple new secrets, each bound to context:

- **Entropy inputs:** PSK (optional) and (EC)DHE shared secret `Z`.
- **Context binding:** the **transcript hash** of handshake messages so far.
- **Derivation tool:** HKDF (extract-then-expand) with a structured label.

Two mental models matter:

1. **Secrets chain.** Each stage produces a secret that becomes the “salt” for the next extract. That’s how TLS 1.3 gets key separation and forward secrecy.
2. **Transcript binding.** Most secrets are derived with `Derive-Secret(secret, label, messages)` where `messages` are the handshake messages so far and the function internally hashes them. If you hash the wrong bytes (or the wrong boundary), everything downstream diverges.

The single most error-prone byte layout in TLS 1.3 is:

```
HkdfLabel = uint16(length) || uint8(len("tls13 " + label)) || "tls13 " + label || uint8(len(context)) || context
```

That’s why we lock this lesson to RFC 5869 (HKDF) and RFC 8448 (TLS 1.3 trace) vectors.

## Build It
### Step 1: HKDF (Extract/Expand)
```python
def _hash_len(hash_name: str) -> int:
    return hashlib.new(hash_name).digest_size


def hmac_digest(hash_name: str, key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hash_name).digest()


def hkdf_extract(hash_name: str, salt: bytes | None, ikm: bytes) -> bytes:
    hash_len = _hash_len(hash_name)
    if not salt:
        salt = b"\x00" * hash_len
    return hmac_digest(hash_name, salt, ikm)


def hkdf_expand(hash_name: str, prk: bytes, info: bytes, length: int) -> bytes:
    if length < 0:
        raise ValueError("length must be non-negative")

    hash_len = _hash_len(hash_name)
    if len(prk) < hash_len:
        raise ValueError("prk must be at least HashLen bytes")

    n = (length + hash_len - 1) // hash_len
    if n > 255:
        raise ValueError("length too large")

    okm_parts: list[bytes] = []
    t = b""
    for i in range(1, n + 1):
        t = hmac_digest(hash_name, prk, t + info + bytes([i]))
        okm_parts.append(t)
    return b"".join(okm_parts)[:length]
```
HKDF is “extract-then-expand”. `Extract` turns input key material into a pseudorandom key (PRK). `Expand` generates as many output bytes as you need by iterating HMAC with a counter. TLS 1.3 uses HKDF everywhere, so we start by matching RFC 5869 vectors.

### Step 2: TLS 1.3 HKDF-Expand-Label
```python
def tls13_hkdf_label(length: int, label: str, context: bytes) -> bytes:
    if length < 0 or length > 0xFFFF:
        raise ValueError("length must fit in uint16")
    if "\x00" in label:
        raise ValueError("label must not contain NUL bytes")
    full_label = ("tls13 " + label).encode("ascii")
    if len(full_label) > 255:
        raise ValueError("label too long")
    if len(context) > 255:
        raise ValueError("context too long")
    return (
        length.to_bytes(2, "big")
        + bytes([len(full_label)])
        + full_label
        + bytes([len(context)])
        + context
    )


def tls13_hkdf_expand_label(
    hash_name: str, secret: bytes, label: str, context: bytes, length: int
) -> bytes:
    info = tls13_hkdf_label(length=length, label=label, context=context)
    return hkdf_expand(hash_name=hash_name, prk=secret, info=info, length=length)
```
TLS 1.3 doesn’t call HKDF-Expand directly; it calls it with a structured `HkdfLabel` and a `"tls13 "` prefix. This is what prevents label collisions across protocols and stages. If you encode the label wrong, your keys won’t match anyone else’s.

### Step 3: Transcript-Hash
```python
def transcript_hash(hash_name: str, messages: Iterable[bytes]) -> bytes:
    h = hashlib.new(hash_name)
    for m in messages:
        h.update(m)
    return h.digest()
```
The transcript is a byte stream of handshake messages. TLS 1.3 uses the hash of that stream (not the raw bytes) as the context for many derived secrets. Here we implement the “hash of concatenation” helper that we’ll reuse everywhere.

### Step 4: Derive-Secret + handshake traffic keys
```python
def tls13_derive_secret(
    hash_name: str, secret: bytes, label: str, messages: Iterable[bytes]
) -> bytes:
    th = transcript_hash(hash_name, messages)
    return tls13_hkdf_expand_label(
        hash_name=hash_name, secret=secret, label=label, context=th, length=_hash_len(hash_name)
    )


@dataclass(frozen=True)
class TLS13TrafficKeys:
    key: bytes
    iv: bytes


def tls13_traffic_keys_aes128gcm_sha256(traffic_secret: bytes) -> TLS13TrafficKeys:
    key = tls13_hkdf_expand_label(
        hash_name="sha256", secret=traffic_secret, label="key", context=b"", length=16
    )
    iv = tls13_hkdf_expand_label(
        hash_name="sha256", secret=traffic_secret, label="iv", context=b"", length=12
    )
    return TLS13TrafficKeys(key=key, iv=iv)
```
`Derive-Secret` is the workhorse: it binds the current secret to the transcript hash and produces a new 32-byte secret (for SHA-256 suites). Once you have a traffic secret, you derive the symmetric record-protection `key` and `iv` using two fixed labels: `"key"` and `"iv"`.

### Step 5: Finished key + verify_data
```python
def tls13_finished_key(hash_name: str, traffic_secret: bytes) -> bytes:
    return tls13_hkdf_expand_label(
        hash_name=hash_name,
        secret=traffic_secret,
        label="finished",
        context=b"",
        length=_hash_len(hash_name),
    )


def tls13_finished_verify_data(
    hash_name: str, finished_key: bytes, handshake_messages: Iterable[bytes]
) -> bytes:
    th = transcript_hash(hash_name, handshake_messages)
    return hmac_digest(hash_name, finished_key, th)
```
The Finished message is “proof we both computed the same handshake keys”. The sender derives a `finished_key` from its handshake traffic secret, then computes `verify_data = HMAC(finished_key, Transcript-Hash(handshake_messages))`. If either side hashed different handshake bytes or derived different keys, Finished verification fails.

Run it:
python3 code/main.py

## Use It
- **OpenSSL / BoringSSL / rustls / NSS** implement the same schedule. You don’t reimplement this in production; you verify behavior and use the library APIs correctly.
- **Key logging:** browsers and OpenSSL support `SSLKEYLOGFILE`, which exports TLS 1.3 traffic secrets so Wireshark can decrypt packets (it’s the same traffic secrets you derived here).
- **Debugging playbook:** when TLS 1.3 breaks, compare (a) chosen ciphersuite hash, (b) transcript bytes and transcript-hash boundary, (c) `HkdfLabel` encoding, (d) client vs server secret selection.

## Pitfalls
- Hashing the wrong bytes into the transcript (record headers, encrypted record bytes, or missing the 4-byte handshake header).
- Getting `HkdfLabel` wrong: missing the `"tls13 "` prefix, wrong length fields, or treating the label as UTF-16/Unicode instead of ASCII.
- Mixing up direction: using `server_handshake_traffic_secret` where `client_handshake_traffic_secret` is required (or vice versa).
- Treating `salt=b""` differently from “salt not provided” in HKDF-Extract (TLS uses explicit zeros in some places).
- Using the wrong hash because you forgot it’s picked by the ciphersuite (`TLS_AES_128_GCM_SHA256` → SHA-256 everywhere in the schedule).

## Ship It
This lesson ships a reusable checklist for reviewing TLS 1.3 key schedule and transcript handling in real code. Use it when reviewing a PR that touches:
- key logging / session key export
- TLS termination / proxies / custom stacks
- QUIC/TLS transcript logic

Artifact: `outputs/tls13-key-schedule-audit-checklist.md`

## Exercises
1. Easy. Run `code/main.py`. Observe that the derived secrets and Finished `verify_data` match RFC 8448.
2. Medium. Extend `code/main.py` to also derive the *application* traffic key + IV from the application traffic secret in RFC 8448.
3. Hard. Use `SSLKEYLOGFILE` (in a real browser/OpenSSL client) and compare one exported traffic secret to the corresponding secret in the TLS 1.3 schedule (label + transcript boundary included).

## Key Terms
| Term | What people say | What it actually means |
|------|------------------|------------------------|
| HKDF-Extract | “mixes in salt” | `PRK = HMAC(salt, IKM)` (salt is a key; if absent, it’s zeros) |
| HKDF-Expand | “stretches key material” | Iterated HMAC with a counter to output `L` bytes |
| Transcript | “handshake log” | Exact bytes of handshake messages in order |
| Transcript hash | “hash of the transcript” | `Hash(m1 || m2 || ... || mk)` for the chosen suite hash |
| Finished | “handshake integrity check” | `HMAC(finished_key, transcript_hash)` proves key agreement over the same transcript |

## Further Reading
- H. Krawczyk, P. Eronen, *HKDF: HMAC-based Extract-and-Expand Key Derivation Function* (RFC 5869, 2010) — canonical HKDF definition + vectors.
- E. Rescorla, *TLS 1.3* (RFC 8446, 2018) — the key schedule and `HKDF-Expand-Label` definition.
- M. Thomson, *Example Handshake Traces for TLS 1.3* (RFC 8448, 2019) — ground truth hex traces for validating implementations.
