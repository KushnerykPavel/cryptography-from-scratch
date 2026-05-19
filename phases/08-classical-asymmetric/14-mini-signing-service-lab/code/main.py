"""
Mini signing service lab (educational).

What this file does:
- Canonicalizes JSON payloads so signatures are stable.
- Implements RSA PKCS#1 v1.5 signatures with SHA-256 (from scratch, stdlib only).
- Builds a tiny "signing service" envelope that binds a signature to:
  (HTTP method, path, timestamp, nonce, payload digest).

How to run:
  python3 code/main.py

Security note:
This is an educational implementation. It is not constant-time and is not
production-safe. Use audited crypto libraries in real systems.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import json
from typing import Any, Dict, MutableSet, Optional


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


DEMO_RSA_PRIVATE_KEY = rsa_key_from_primes(
    p=11310735288434282191698047522933380471735100170529539592604941208733479310434121001833483590972242985342880012999723658817524894413504449422778426019588297,
    q=9277911524745504922176330999866460172154015379143682173278916442773809086363581166481652108788939950551541370305595455133187670575514803022588242506858727,
    e=65537,
)


def main() -> None:
    key_id = "demo-kid-1"
    private_key = DEMO_RSA_PRIVATE_KEY
    public_key = private_key.public()

    payload_a = {"amount": 1250, "to": "acct_123", "memo": "rent May"}
    payload_b = {"memo": "rent May", "to": "acct_123", "amount": 1250}

    print("=== Step 1: Canonicalize payloads ===")
    canon_a = canonical_json(payload_a)
    canon_b = canonical_json(payload_b)
    print("canonical A:", canon_a.decode("utf-8"))
    print("canonical B:", canon_b.decode("utf-8"))
    print("sha256(canonical):", sha256_hex(canon_a))
    print("same bytes:", hmac.compare_digest(canon_a, canon_b))
    print()

    print("=== Step 2: RSA sign/verify (PKCS#1 v1.5 + SHA-256) ===")
    msg = b"POST\n/v1/sign\nexample"
    sig = rsa_sign_pkcs1_v1_5_sha256(private_key, msg)
    print("message:", msg.decode("utf-8"))
    print("signature (b64url):", b64url_encode(sig))
    print("verify ok:", rsa_verify_pkcs1_v1_5_sha256(public_key, msg, sig))
    tampered = b"POST\n/v1/sign\nEXAMPLE"
    print("verify tampered:", rsa_verify_pkcs1_v1_5_sha256(public_key, tampered, sig))
    print()

    print("=== Step 3: Build a signed request envelope ===")
    method = "POST"
    path = "/v1/sign"
    ts = 1716050000
    nonce = "n-0001"
    signed = sign_request(
        private_key=private_key,
        key_id=key_id,
        method=method,
        path=path,
        ts=ts,
        nonce=nonce,
        payload=payload_a,
    )
    print("signed request:", json.dumps(signed, sort_keys=True, indent=2))
    used_nonces: set[str] = set()
    verify_signed_request(
        public_key=public_key,
        expected_key_id=key_id,
        method=method,
        path=path,
        signed=signed,
        now_ts=ts,
        max_skew_s=300,
        used_nonces=used_nonces,
    )
    print("verify ok: True")
    print()

    print("=== Step 4: Reject tampering and replay ===")
    tampered_signed = dict(signed)
    tampered_signed["payload"] = dict(payload_a)
    tampered_signed["payload"]["amount"] = 9999
    try:
        verify_signed_request(
            public_key=public_key,
            expected_key_id=key_id,
            method=method,
            path=path,
            signed=tampered_signed,
            now_ts=ts,
            max_skew_s=300,
            used_nonces=set(),
        )
        print("tamper verify ok: True (unexpected)")
    except ValueError as e:
        print("tamper verify error:", str(e))

    try:
        verify_signed_request(
            public_key=public_key,
            expected_key_id=key_id,
            method=method,
            path=path,
            signed=signed,
            now_ts=ts,
            max_skew_s=300,
            used_nonces=used_nonces,
        )
        print("replay verify ok: True (unexpected)")
    except ValueError as e:
        print("replay verify error:", str(e))

    try:
        verify_signed_request(
            public_key=public_key,
            expected_key_id=key_id,
            method="GET",
            path=path,
            signed=signed,
            now_ts=ts,
            max_skew_s=300,
            used_nonces=set(),
        )
        print("method swap verify ok: True (unexpected)")
    except ValueError as e:
        print("method swap verify error:", str(e))


if __name__ == "__main__":
    main()
