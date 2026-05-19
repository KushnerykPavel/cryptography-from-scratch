# Asymmetric Lab — Build a Mini Signing Service

> Sign bytes, not objects — and bind the signature to its context.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 08: `01-rsa`, `02-rsa-padding` (and you will benefit from `12-deterministic-nonces`)
**Time:** ~120 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- **Explain** what a signature actually covers (exact bytes + context)
- **Compute** a stable payload digest via canonical JSON
- **Implement** RSASSA-PKCS1-v1_5 (SHA-256) signing + verification from scratch
- **Distinguish** integrity/authenticity from freshness (replay protection) in signed APIs
- **Apply** a signing policy that prevents cross-endpoint and replay attacks

## The Problem

You built RSA signatures. Now you need to ship them inside a system: a small service that signs requests (or payloads) and another system that verifies them. This shows up everywhere: webhook verification, firmware update signing, “signed API requests” between microservices, or offline approvals.

In the real world, signatures fail for boring reasons: the verifier hashes a different byte string than the signer (JSON key order, whitespace, Unicode normalization), or the signature is valid but replayable (an attacker resends the same signed payload), or a signature intended for one endpoint is accepted by another (“cross-protocol” / “cross-endpoint” confusion).

This lab makes those failure modes concrete and gives you a minimal signing envelope pattern: canonicalize → hash → bind to method/path/timestamp/nonce → sign → verify → reject replays.

## The Concept

### What are we signing?

A signature is computed over **bytes**. A “Python dict” or “JSON object” is not bytes; it is a data structure that can be serialized in multiple ways.

So the signing pipeline is:

1. Canonicalize the payload into a stable byte string (canonical JSON).
2. Hash those bytes to a fixed-size digest (`SHA-256`).
3. Build a **signature base string** that includes context:
   - HTTP method and path (prevents a signature from being valid on a different endpoint)
   - Timestamp and nonce (enables freshness checks and replay detection)
   - Payload digest (binds the signature to the payload)
4. Sign the base string with the private key; verify with the public key.

### Signature base string (mental model)

We will sign this exact UTF-8 string (newlines are literal):

```
METHOD
/path
timestamp
nonce
sha256(canonical_json(payload))
```

| Field | Why it exists |
|------|----------------|
| `METHOD` + `/path` | Prevents replaying a signature on a different endpoint |
| `timestamp` | Lets the verifier reject old signatures (skew window) |
| `nonce` | Lets the verifier reject duplicates even inside the skew window |
| `payload digest` | Makes the signature cover the payload without signing huge blobs |

### RSA signatures (PKCS#1 v1.5, SHA-256)

RSASSA-PKCS1-v1_5 signs a padded encoding of a message hash:

- Hash the message with SHA-256.
- Wrap the hash in a DER `DigestInfo` structure (algorithm ID + digest).
- Pad to the RSA modulus length:

```
EM = 0x00 || 0x01 || PS (0xff...) || 0x00 || DigestInfo(SHA-256(message))
sig = EM^d mod n
```

This is educational. In production you typically prefer RSA-PSS or modern signature schemes like Ed25519.

## Build It

### Step 1: Canonicalize payloads

Canonical JSON makes “the same object” serialize to the same bytes (stable key order + no pretty-print whitespace). We also add a couple of small helpers: `sha256_hex` and base64url encoding for transporting signatures as text.

```python
import base64
import hashlib
import json
from typing import Any


def canonical_json(obj: Any) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(text: str) -> bytes:
    pad = "=" * ((4 - (len(text) % 4)) % 4)
    return base64.urlsafe_b64decode(text + pad)
```

### Step 2: Implement RSA sign/verify (PKCS#1 v1.5 + SHA-256)

We implement the PKCS#1 v1.5 encoding (`EMSA-PKCS1-v1_5`) and then sign/verify by modular exponentiation. Verification compares the recovered encoded message (`EM`) against the expected one.

```python
import dataclasses
import hashlib
import hmac
from typing import Optional


def _int_to_bytes(value: int, length: int) -> bytes:
    return value.to_bytes(length, "big")


def _bytes_to_int(data: bytes) -> int:
    return int.from_bytes(data, "big")


def _egcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = _egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def modinv(a: int, m: int) -> int:
    g, x, _y = _egcd(a, m)
    if g != 1:
        raise ValueError("inverse does not exist")
    return x % m


SHA256_DIGESTINFO_DER_PREFIX = bytes.fromhex(
    "3031300d060960864801650304020105000420"
)


def emsa_pkcs1_v1_5_encode_sha256(message: bytes, em_len: int) -> bytes:
    digest = hashlib.sha256(message).digest()
    digest_info = SHA256_DIGESTINFO_DER_PREFIX + digest
    if em_len < len(digest_info) + 11:
        raise ValueError("intended encoded message length too short")
    ps = b"\xff" * (em_len - len(digest_info) - 3)
    return b"\x00\x01" + ps + b"\x00" + digest_info


@dataclasses.dataclass(frozen=True)
class RSAKey:
    n: int
    e: int
    d: Optional[int] = None

    def public(self) -> "RSAKey":
        return RSAKey(n=self.n, e=self.e, d=None)

    def size_bytes(self) -> int:
        return (self.n.bit_length() + 7) // 8


def rsa_key_from_primes(p: int, q: int, e: int = 65537) -> RSAKey:
    if p <= 2 or q <= 2:
        raise ValueError("p and q must be primes > 2")
    if p == q:
        raise ValueError("p and q must be distinct")
    n = p * q
    phi = (p - 1) * (q - 1)
    if phi % e == 0:
        raise ValueError("e shares a factor with phi(n)")
    d = modinv(e, phi)
    return RSAKey(n=n, e=e, d=d)


def rsa_sign_pkcs1_v1_5_sha256(private_key: RSAKey, message: bytes) -> bytes:
    if private_key.d is None:
        raise ValueError("private key required for signing")
    k = private_key.size_bytes()
    em = emsa_pkcs1_v1_5_encode_sha256(message, k)
    m = _bytes_to_int(em)
    s = pow(m, private_key.d, private_key.n)
    return _int_to_bytes(s, k)


def rsa_verify_pkcs1_v1_5_sha256(public_key: RSAKey, message: bytes, signature: bytes) -> bool:
    k = public_key.size_bytes()
    if len(signature) != k:
        return False
    s = _bytes_to_int(signature)
    m = pow(s, public_key.e, public_key.n)
    em = _int_to_bytes(m, k)
    expected = emsa_pkcs1_v1_5_encode_sha256(message, k)
    return hmac.compare_digest(em, expected)
```

### Step 3: Define the signing envelope (what the service signs)

We build a signature base string that binds the signature to the request context and the payload digest.

```python
from typing import Any, Dict


def signature_base_string(
    method: str,
    path: str,
    ts: int,
    nonce: str,
    payload: Dict[str, Any],
) -> bytes:
    method_u = method.upper()
    if not method_u:
        raise ValueError("method is required")
    if not path.startswith("/"):
        raise ValueError("path must start with '/'")
    if ts <= 0:
        raise ValueError("ts must be a positive unix timestamp")
    if not nonce:
        raise ValueError("nonce is required")

    payload_digest = sha256_hex(canonical_json(payload))
    base = "\n".join([method_u, path, str(ts), nonce, payload_digest])
    return base.encode("utf-8")


def sign_request(
    private_key: RSAKey,
    key_id: str,
    method: str,
    path: str,
    ts: int,
    nonce: str,
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    base = signature_base_string(method=method, path=path, ts=ts, nonce=nonce, payload=payload)
    sig = rsa_sign_pkcs1_v1_5_sha256(private_key, base)
    return {
        "kid": key_id,
        "alg": "rsa-v1_5-sha256",
        "ts": ts,
        "nonce": nonce,
        "payload": payload,
        "sig": b64url_encode(sig),
    }
```

### Step 4: Verify, enforce freshness, reject replay

Verification is not only crypto. It is also policy: enforce a timestamp window and a nonce cache to prevent replay.

```python
from typing import Any, Dict, MutableSet


def verify_signed_request(
    public_key: RSAKey,
    expected_key_id: str,
    method: str,
    path: str,
    signed: Dict[str, Any],
    *,
    now_ts: int,
    max_skew_s: int,
    used_nonces: MutableSet[str],
) -> None:
    if signed.get("kid") != expected_key_id:
        raise ValueError("unknown key id")
    if signed.get("alg") != "rsa-v1_5-sha256":
        raise ValueError("unsupported algorithm")

    ts = int(signed.get("ts"))
    nonce = str(signed.get("nonce"))
    payload = signed.get("payload")
    sig_text = signed.get("sig")

    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    if not isinstance(sig_text, str) or not sig_text:
        raise ValueError("sig must be a non-empty string")

    if abs(now_ts - ts) > max_skew_s:
        raise ValueError("timestamp outside allowed skew")

    nonce_key = f"{expected_key_id}:{nonce}"
    if nonce_key in used_nonces:
        raise ValueError("replay detected (nonce reuse)")

    base = signature_base_string(method=method, path=path, ts=ts, nonce=nonce, payload=payload)
    sig = b64url_decode(sig_text)
    if not rsa_verify_pkcs1_v1_5_sha256(public_key, base, sig):
        raise ValueError("invalid signature")

    used_nonces.add(nonce_key)
```

Run it:

```bash
python3 code/main.py
```

## Use It

Production equivalents avoid “from-scratch crypto” and usually avoid RSA PKCS#1 v1.5 for new designs:

- **Python `cryptography`**: `RSAPrivateKey.sign(..., padding.PSS(...), hashes.SHA256())` (prefer PSS).
- **PyCryptodome**: `Crypto.Signature.pkcs1_15` (v1.5) and `Crypto.Signature.pss` (PSS).
- **Modern signatures**: Ed25519 (libsodium, RustCrypto, Go `crypto/ed25519`) is commonly simpler and safer for APIs.
- **Key management**: keep the private key in an HSM/KMS; expose a narrow “sign” API, not raw private-key access.

## Pitfalls

- Signing non-canonical JSON (verifier and signer hash different bytes).
- Forgetting to bind the signature to `method`/`path` (signature valid on the wrong endpoint).
- No replay protection (a valid signature can be resent and accepted again).
- Treating the signing service as a general-purpose oracle (attackers can ask it to sign arbitrary data).
- Reusing the same key for multiple protocols/purposes (cross-protocol confusion, harder rotation).

## Ship It

Save the reusable checklist in `outputs/signing-service-audit-checklist.md`. Use it as:

- A PR review checklist for “signed request” changes.
- An incident response checklist when signatures “randomly fail” in production.
- A design prompt when choosing what to sign and how to rotate keys.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe that two differently-ordered JSON objects produce the same canonical bytes and the same payload digest.
2. Medium. Extend `signature_base_string(...)` to also include a `host` (or `audience`) field, and show that a signature for one host does not verify for another.
3. Hard. Replace PKCS#1 v1.5 with RSA-PSS using a real library (Python `cryptography`). Keep the same envelope and verification policy, but swap out the signing primitive.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Canonical JSON | “Normalized JSON” | A deterministic serialization so both sides hash identical bytes |
| Signature base string | “What we sign” | An exact byte string combining context + payload digest |
| Replay attack | “Sending it again” | Reusing a valid signature outside its intended one-time context |
| Key ID (`kid`) | “Which key to use” | A lookup handle so verifiers pick the right public key for a signature |
| RSASSA-PKCS1-v1_5 | “RSA signatures” | A specific padding/encoding scheme; not just `m^d mod n` |

## Further Reading

- Jonsson, Kaliski, *PKCS #1: RSA Cryptography Specifications Version 2.2* (RFC 8017, 2016) — The reference for RSA encryption/signature schemes, including EMSA-PKCS1-v1_5.
- Josefsson, *The Base16, Base32, and Base64 Data Encodings* (RFC 4648, 2006) — Canonical base64 encoding details (base64url variant is widely used in APIs).
