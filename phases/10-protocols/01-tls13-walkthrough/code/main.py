"""
TLS 1.3 handshake walkthrough (toy, deterministic).

This script implements the TLS 1.3 key schedule pieces you can safely study
offline: transcript hashing, HKDF(-Expand-Label), traffic secrets, and Finished
verification.

Run:
  python3 code/main.py
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Iterable


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


def transcript_hash_sha256(handshake_messages: Iterable[bytes]) -> bytes:
    h = hashlib.sha256()
    for msg in handshake_messages:
        h.update(msg)
    return h.digest()


def derive_secret_sha256(secret: bytes, label: str, transcript_hash: bytes) -> bytes:
    hash_len = hashlib.sha256().digest_size
    return hkdf_expand_label_sha256(
        secret=secret, label=label, context=transcript_hash, length=hash_len
    )


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


def _demo_step_1_primitives() -> None:
    print("=== Step 1: HKDF + TLS 1.3 labels ===")

    ikm = b"\x0b" * 22
    salt = bytes(range(13))
    info = bytes(range(0xF0, 0xF0 + 10))
    prk = hkdf_extract_sha256(salt=salt, ikm=ikm)
    okm = hkdf_expand_sha256(prk=prk, info=info, length=42)

    print("IKM:", bytes_to_hex(ikm))
    print("salt:", bytes_to_hex(salt))
    print("info:", bytes_to_hex(info))
    print("PRK:", bytes_to_hex(prk))
    print("OKM[42]:", bytes_to_hex(okm))

    label = tls13_hkdf_label(length=16, label="key", context=b"")
    print("HKDF-Label(key,16):", bytes_to_hex(label))


def _demo_step_2_transcript_hash() -> TLS13ToyHandshake:
    print("=== Step 2: Transcript hash ===")

    transcript = TLS13ToyHandshake(
        client_hello=b"ClientHello(versions=tls13,ciphers=TLS_AES_128_GCM_SHA256)",
        server_hello=b"ServerHello(selected=tls13,group=x25519)",
        encrypted_extensions=b"EncryptedExtensions(alpn=h2)",
        server_certificate=b"Certificate(chain=example.com)",
        server_certificate_verify=b"CertificateVerify(sig=toy)",
        server_finished=b"Finished(verify_data=??)",
    )

    th1 = transcript_hash_sha256(transcript.up_to_server_hello())
    th2 = transcript_hash_sha256(transcript.up_to_server_finished_exclusive())

    print("transcript_hash(ClientHello..ServerHello):", bytes_to_hex(th1))
    print("transcript_hash(+..CertificateVerify):", bytes_to_hex(th2))
    return transcript


def _demo_step_3_key_schedule(transcript: TLS13ToyHandshake) -> dict[str, bytes]:
    print("=== Step 3: Key schedule (secrets) ===")

    shared_secret = sha256(b"toy x25519 shared secret")
    secrets = tls13_key_schedule_sha256(shared_secret=shared_secret, transcript=transcript)

    print("shared_secret:", bytes_to_hex(shared_secret))
    for name in [
        "early_secret",
        "handshake_secret",
        "c_hs_traffic",
        "s_hs_traffic",
        "master_secret",
        "c_ap_traffic_0",
        "s_ap_traffic_0",
    ]:
        print(f"{name}:", bytes_to_hex(secrets[name]))

    c_key, c_iv = traffic_key_iv_sha256(secrets["c_hs_traffic"])
    s_key, s_iv = traffic_key_iv_sha256(secrets["s_hs_traffic"])
    print("client_hs_key:", bytes_to_hex(c_key))
    print("client_hs_iv :", bytes_to_hex(c_iv))
    print("server_hs_key:", bytes_to_hex(s_key))
    print("server_hs_iv :", bytes_to_hex(s_iv))
    return secrets


def _demo_step_4_finished_and_update(
    transcript: TLS13ToyHandshake, secrets: dict[str, bytes]
) -> None:
    print("=== Step 4: Finished + key update ===")

    th_server_finished_exclusive = transcript_hash_sha256(
        transcript.up_to_server_finished_exclusive()
    )
    s_finished_key = finished_key_sha256(secrets["s_hs_traffic"])
    s_verify = finished_verify_data_sha256(
        finished_key=s_finished_key, transcript_hash=th_server_finished_exclusive
    )

    print("server_finished_key:", bytes_to_hex(s_finished_key))
    print("server_verify_data:", bytes_to_hex(s_verify))

    th_server_finished_inclusive = transcript_hash_sha256(
        transcript.up_to_server_finished_inclusive()
    )
    c_finished_key = finished_key_sha256(secrets["c_hs_traffic"])
    c_verify = finished_verify_data_sha256(
        finished_key=c_finished_key, transcript_hash=th_server_finished_inclusive
    )
    print("client_finished_key:", bytes_to_hex(c_finished_key))
    print("client_verify_data:", bytes_to_hex(c_verify))

    next_server_app = update_traffic_secret_sha256(secrets["s_ap_traffic_0"])
    next_key, next_iv = traffic_key_iv_sha256(next_server_app)
    print("s_ap_traffic_1:", bytes_to_hex(next_server_app))
    print("s_ap_key_1   :", bytes_to_hex(next_key))
    print("s_ap_iv_1    :", bytes_to_hex(next_iv))


def main() -> None:
    _demo_step_1_primitives()
    transcript = _demo_step_2_transcript_hash()
    secrets = _demo_step_3_key_schedule(transcript)
    _demo_step_4_finished_and_update(transcript, secrets)


if __name__ == "__main__":
    main()
