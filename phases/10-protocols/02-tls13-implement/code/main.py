"""
TLS 1.3 key schedule + Finished (RFC 8446 / RFC 8448) from scratch (stdlib only).

This script implements the parts of a TLS 1.3 handshake that are pure hashing:
- HKDF (Extract/Expand) (RFC 5869)
- TLS 1.3 HKDF-Expand-Label / Derive-Secret (RFC 8446)
- Transcript-Hash over handshake messages
- Handshake traffic secrets, traffic keys, and Finished verify_data (RFC 8448 trace)

Run:
  python3 code/main.py
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Iterable


def _hex_to_bytes(s: str) -> bytes:
    return bytes.fromhex("".join(s.split()))


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


def transcript_hash(hash_name: str, messages: Iterable[bytes]) -> bytes:
    h = hashlib.new(hash_name)
    for m in messages:
        h.update(m)
    return h.digest()


def tls13_derive_secret(
    hash_name: str, secret: bytes, label: str, messages: Iterable[bytes]
) -> bytes:
    th = transcript_hash(hash_name, messages)
    return tls13_hkdf_expand_label(
        hash_name=hash_name, secret=secret, label=label, context=th, length=_hash_len(hash_name)
    )


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


RFC5869_TC1_IKM = _hex_to_bytes("0b" * 22)
RFC5869_TC1_SALT = _hex_to_bytes("000102030405060708090a0b0c")
RFC5869_TC1_INFO = _hex_to_bytes("f0f1f2f3f4f5f6f7f8f9")
RFC5869_TC1_PRK = _hex_to_bytes(
    "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
)
RFC5869_TC1_OKM = _hex_to_bytes(
    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
    "34007208d5b887185865"
)


RFC8448_CLIENT_HELLO = _hex_to_bytes(
    """
    01 00 00 c0 03 03 cb 34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff a2
    1a 8d 99 12 ec 18 a2 ef 62 83 02 4d ec e7 00 00 06 13 01 13 03 13 02 01
    00 00 91 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00
    0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00
    23 00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2 3d 8e
    43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a af 2c 00 2b 00
    03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03 02 03 08 04 08 05 08 06
    04 01 05 01 06 01 02 01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c
    00 02 40 01
    """
)
RFC8448_SERVER_HELLO = _hex_to_bytes(
    """
    02 00 00 56 03 03 a6 af 06 a4 12 18 60 dc 5e 6e 60 24 9c d3 4c 95 93 0c
    8a c5 cb 14 34 da c1 55 77 2e d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24
    00 1d 00 20 c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25
    3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04
    """
)
RFC8448_ENCRYPTED_EXTENSIONS = _hex_to_bytes(
    """
    08 00 00 24 00 22 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01
    01 02 01 03 01 04 00 1c 00 02 40 01 00 00 00 00
    """
)
RFC8448_CERTIFICATE = _hex_to_bytes(
    """
    0b 00 01 b9 00 00 01 b5 00 01 b0 30 82 01 ac 30 82 01 15 a0 03 02 01 02
    02 01 02 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 30 0e 31 0c 30 0a
    06 03 55 04 03 13 03 72 73 61 30 1e 17 0d 31 36 30 37 33 30 30 31 32 33
    35 39 5a 17 0d 32 36 30 37 33 30 30 31 32 33 35 39 5a 30 0e 31 0c 30 0a
    06 03 55 04 03 13 03 72 73 61 30 81 9f 30 0d 06 09 2a 86 48 86 f7 0d 01
    01 01 05 00 03 81 8d 00 30 81 89 02 81 81 00 b4 bb 49 8f 82 79 30 3d 98
    08 36 39 9b 36 c6 98 8c 0c 68 de 55 e1 bd b8 26 d3 90 1a 24 61 ea fd 2d
    e4 9a 91 d0 15 ab bc 9a 95 13 7a ce 6c 1a f1 9e aa 6a f9 8c 7c ed 43 12
    09 98 e1 87 a8 0e e0 cc b0 52 4b 1b 01 8c 3e 0b 63 26 4d 44 9a 6d 38 e2
    2a 5f da 43 08 46 74 80 30 53 0e f0 46 1c 8c a9 d9 ef bf ae 8e a6 d1 d0
    3e 2b d1 93 ef f0 ab 9a 80 02 c4 74 28 a6 d3 5a 8d 88 d7 9f 7f 1e 3f 02
    03 01 00 01 a3 1a 30 18 30 09 06 03 55 1d 13 04 02 30 00 30 0b 06 03 55
    1d 0f 04 04 03 02 05 a0 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 03
    81 81 00 85 aa d2 a0 e5 b9 27 6b 90 8c 65 f7 3a 72 67 17 06 18 a5 4c 5f
    8a 7b 33 7d 2d f7 a5 94 36 54 17 f2 ea e8 f8 a5 8c 8f 81 72 f9 31 9c f3
    6b 7f d6 c5 5b 80 f2 1a 03 01 51 56 72 60 96 fd 33 5e 5e 67 f2 db f1 02
    70 2e 60 8c ca e6 be c1 fc 63 a4 2a 99 be 5c 3e b7 10 7c 3c 54 e9 b9 eb
    2b d5 20 3b 1c 3b 84 e0 a8 b2 f7 59 40 9b a3 ea c9 d9 1d 40 2d cc 0c c8
    f8 96 12 29 ac 91 87 b4 2b 4d e1 00 00
    """
)
RFC8448_CERTIFICATE_VERIFY = _hex_to_bytes(
    """
    0f 00 00 84 08 04 00 80 5a 74 7c 5d 88 fa 9b d2 e5 5a b0 85 a6 10 15 b7
    21 1f 82 4c d4 84 14 5a b3 ff 52 f1 fd a8 47 7b 0b 7a bc 90 db 78 e2 d3
    3a 5c 14 1a 07 86 53 fa 6b ef 78 0c 5e a2 48 ee aa a7 85 c4 f3 94 ca b6
    d3 0b be 8d 48 59 ee 51 1f 60 29 57 b1 54 11 ac 02 76 71 45 9e 46 44 5c
    9e a5 8c 18 1e 81 8e 95 b8 c3 fb 0b f3 27 84 09 d3 be 15 2a 3d a5 04 3e
    06 3d da 65 cd f5 ae a2 0d 53 df ac d4 2f 74 f3
    """
)
RFC8448_SERVER_FINISHED = _hex_to_bytes(
    """
    14 00 00 20 9b 9b 14 1d 90 63 37 fb d2 cb dc e7 1d f4 de da 4a b4 2c 30
    95 72 cb 7f ff ee 54 54 b7 8f 07 18
    """
)
RFC8448_CLIENT_FINISHED = _hex_to_bytes(
    """
    14 00 00 20 a8 ec 43 6d 67 76 34 ae 52 5a c1 fc eb e1 1a 03 9e c1 76 94
    fa c6 e9 85 27 b6 42 f2 ed d5 ce 61
    """
)

RFC8448_EARLY_SECRET = _hex_to_bytes(
    "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"
)
RFC8448_DERIVED_SECRET = _hex_to_bytes(
    "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"
)
RFC8448_SHARED_SECRET = _hex_to_bytes(
    "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d"
)
RFC8448_HANDSHAKE_SECRET = _hex_to_bytes(
    "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac"
)
RFC8448_TRANSCRIPT_CH_SH = _hex_to_bytes(
    "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"
)
RFC8448_CLIENT_HS_TRAFFIC_SECRET = _hex_to_bytes(
    "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"
)
RFC8448_SERVER_HS_TRAFFIC_SECRET = _hex_to_bytes(
    "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"
)
RFC8448_CLIENT_HS_KEY = _hex_to_bytes("dbfaa693d1762c5b666af5d950258d01")
RFC8448_CLIENT_HS_IV = _hex_to_bytes("5bd3c71b836e0b76bb73265f")
RFC8448_SERVER_FINISHED_KEY = _hex_to_bytes(
    "008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8"
)
RFC8448_SERVER_FINISHED_VERIFY_DATA = _hex_to_bytes(
    "9b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718"
)
RFC8448_CLIENT_FINISHED_KEY = _hex_to_bytes(
    "b80ad01015fb2f0bd65ff7d4da5d6bf83f84821d1f87fdc7d3c75b5a7b42d9c4"
)
RFC8448_CLIENT_FINISHED_VERIFY_DATA = _hex_to_bytes(
    "a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61"
)


def _print_step(n: int, name: str) -> None:
    print(f"=== Step {n}: {name} ===")


def _print_hex(name: str, b: bytes) -> None:
    print(f"{name}: {b.hex()}")


def _check_hex(name: str, got: bytes, expected: bytes) -> None:
    ok = got == expected
    _print_hex(name, got)
    print(f"match: {ok}")
    if not ok:
        raise AssertionError(f"{name} mismatch")
    print()


def main() -> None:
    _print_step(1, "HKDF (Extract/Expand)")
    prk = hkdf_extract("sha256", RFC5869_TC1_SALT, RFC5869_TC1_IKM)
    okm = hkdf_expand("sha256", prk, RFC5869_TC1_INFO, 42)
    _check_hex("RFC5869 test case 1 PRK", prk, RFC5869_TC1_PRK)
    _check_hex("RFC5869 test case 1 OKM", okm, RFC5869_TC1_OKM)

    _print_step(2, "TLS 1.3 HKDF-Expand-Label")
    info_key = tls13_hkdf_label(16, "key", b"")
    info_iv = tls13_hkdf_label(12, "iv", b"")
    _check_hex("HKDF label info (key, 16)", info_key, _hex_to_bytes("001009746c733133206b657900"))
    _check_hex("HKDF label info (iv, 12)", info_iv, _hex_to_bytes("000c08746c73313320697600"))

    _print_step(3, "Transcript-Hash")
    th_ch_sh = transcript_hash("sha256", [RFC8448_CLIENT_HELLO, RFC8448_SERVER_HELLO])
    _check_hex("Transcript hash(ClientHello..ServerHello)", th_ch_sh, RFC8448_TRANSCRIPT_CH_SH)

    _print_step(4, "Handshake traffic secrets + traffic keys")
    zeros = b"\x00" * 32
    early_secret = hkdf_extract("sha256", zeros, zeros)
    _check_hex("early_secret", early_secret, RFC8448_EARLY_SECRET)

    derived_secret = tls13_derive_secret("sha256", early_secret, "derived", [])
    _check_hex("derived_secret (handshake)", derived_secret, RFC8448_DERIVED_SECRET)

    handshake_secret = hkdf_extract("sha256", derived_secret, RFC8448_SHARED_SECRET)
    _check_hex("handshake_secret", handshake_secret, RFC8448_HANDSHAKE_SECRET)

    c_hs = tls13_derive_secret(
        "sha256", handshake_secret, "c hs traffic", [RFC8448_CLIENT_HELLO, RFC8448_SERVER_HELLO]
    )
    s_hs = tls13_derive_secret(
        "sha256", handshake_secret, "s hs traffic", [RFC8448_CLIENT_HELLO, RFC8448_SERVER_HELLO]
    )
    _check_hex("client_handshake_traffic_secret", c_hs, RFC8448_CLIENT_HS_TRAFFIC_SECRET)
    _check_hex("server_handshake_traffic_secret", s_hs, RFC8448_SERVER_HS_TRAFFIC_SECRET)

    client_keys = tls13_traffic_keys_aes128gcm_sha256(c_hs)
    _check_hex("client_handshake_key", client_keys.key, RFC8448_CLIENT_HS_KEY)
    _check_hex("client_handshake_iv", client_keys.iv, RFC8448_CLIENT_HS_IV)

    _print_step(5, "Finished verify_data")
    server_finished_key = tls13_finished_key("sha256", s_hs)
    _check_hex("server_finished_key", server_finished_key, RFC8448_SERVER_FINISHED_KEY)
    server_verify_data = tls13_finished_verify_data(
        "sha256",
        server_finished_key,
        [
            RFC8448_CLIENT_HELLO,
            RFC8448_SERVER_HELLO,
            RFC8448_ENCRYPTED_EXTENSIONS,
            RFC8448_CERTIFICATE,
            RFC8448_CERTIFICATE_VERIFY,
        ],
    )
    _check_hex("server Finished.verify_data", server_verify_data, RFC8448_SERVER_FINISHED_VERIFY_DATA)

    client_finished_key = tls13_finished_key("sha256", c_hs)
    _check_hex("client_finished_key", client_finished_key, RFC8448_CLIENT_FINISHED_KEY)
    client_verify_data = tls13_finished_verify_data(
        "sha256",
        client_finished_key,
        [
            RFC8448_CLIENT_HELLO,
            RFC8448_SERVER_HELLO,
            RFC8448_ENCRYPTED_EXTENSIONS,
            RFC8448_CERTIFICATE,
            RFC8448_CERTIFICATE_VERIFY,
            RFC8448_SERVER_FINISHED,
        ],
    )
    _check_hex("client Finished.verify_data", client_verify_data, RFC8448_CLIENT_FINISHED_VERIFY_DATA)

    print("done")


if __name__ == "__main__":
    main()
