"""
KDFs (Key Derivation Functions) in pure stdlib Python.

This lesson implements:
- HKDF-SHA256 (RFC 5869) for deriving multiple keys from a high-entropy secret
- PBKDF2-HMAC-SHA256 (RFC 8018) for deriving keys from passwords (CPU-hard)
- scrypt (RFC 7914) via Python's stdlib hashlib.scrypt (memory-hard)

Run:
  python3 code/main.py
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def hkdf_extract_sha256(salt: bytes, ikm: bytes) -> bytes:
    if salt == b"":
        salt = b"\x00" * hashlib.sha256().digest_size
    return hmac_sha256(salt, ikm)


def hkdf_expand_sha256(prk: bytes, info: bytes, length: int) -> bytes:
    if length < 0:
        raise ValueError("length must be >= 0")
    hash_len = hashlib.sha256().digest_size
    if length > 255 * hash_len:
        raise ValueError("length too large for HKDF (max 255*HashLen)")
    if length == 0:
        return b""

    okm = bytearray()
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac_sha256(prk, t + info + bytes([counter]))
        okm.extend(t)
        counter += 1
    return bytes(okm[:length])


def hkdf_sha256(ikm: bytes, length: int, salt: bytes = b"", info: bytes = b"") -> bytes:
    prk = hkdf_extract_sha256(salt=salt, ikm=ikm)
    return hkdf_expand_sha256(prk=prk, info=info, length=length)


def pbkdf2_hmac_sha256(password: bytes, salt: bytes, iterations: int, dklen: int) -> bytes:
    if iterations <= 0:
        raise ValueError("iterations must be >= 1")
    if dklen <= 0:
        raise ValueError("dklen must be >= 1")
    hlen = hashlib.sha256().digest_size

    def prf(msg: bytes) -> bytes:
        return hmac_sha256(password, msg)

    blocks = (dklen + hlen - 1) // hlen
    out = bytearray()
    for block_index in range(1, blocks + 1):
        u = prf(salt + block_index.to_bytes(4, "big"))
        t = bytearray(u)
        for _ in range(2, iterations + 1):
            u = prf(u)
            for i in range(hlen):
                t[i] ^= u[i]
        out.extend(t)
    return bytes(out[:dklen])


def _is_power_of_two(n: int) -> bool:
    return n > 0 and (n & (n - 1) == 0)


def scrypt_kdf(
    password: bytes,
    salt: bytes,
    *,
    n: int,
    r: int,
    p: int,
    dklen: int,
    maxmem: int = 0,
) -> bytes:
    if n <= 1 or not _is_power_of_two(n):
        raise ValueError("n must be a power of two > 1")
    if r <= 0 or p <= 0:
        raise ValueError("r and p must be >= 1")
    if dklen <= 0:
        raise ValueError("dklen must be >= 1")
    return hashlib.scrypt(password, salt=salt, n=n, r=r, p=p, dklen=dklen, maxmem=maxmem)


@dataclass(frozen=True)
class DerivedKeys:
    enc_key: bytes
    mac_key: bytes
    nonce_key: bytes


def derive_subkeys_hkdf(master_secret: bytes, salt: bytes, context: bytes) -> DerivedKeys:
    info = b"cfs:kdf:v1:" + context
    okm = hkdf_sha256(master_secret, length=32 + 32 + 12, salt=salt, info=info)
    enc_key = okm[:32]
    mac_key = okm[32:64]
    nonce_key = okm[64:76]
    return DerivedKeys(enc_key=enc_key, mac_key=mac_key, nonce_key=nonce_key)


def _h(b: bytes) -> str:
    return b.hex()


def main() -> None:
    print("=== Step 1: HKDF Extract (PRK) ===")
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    prk = hkdf_extract_sha256(salt=salt, ikm=ikm)
    print("ikm =", _h(ikm))
    print("salt =", _h(salt))
    print("prk =", _h(prk))
    print()

    print("=== Step 2: HKDF Expand + Key Separation ===")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    okm = hkdf_expand_sha256(prk=prk, info=info, length=42)
    print("info =", _h(info))
    print("okm(42) =", _h(okm))
    keys = derive_subkeys_hkdf(
        master_secret=b"master secret bytes that are high-entropy",
        salt=b"session salt",
        context=b"tls-like handshake transcript hash",
    )
    print("enc_key =", _h(keys.enc_key))
    print("mac_key =", _h(keys.mac_key))
    print("nonce_key =", _h(keys.nonce_key))
    print()

    print("=== Step 3: PBKDF2-HMAC-SHA256 (password -> key) ===")
    password = b"password"
    pbkdf2_salt = b"salt"
    dk = pbkdf2_hmac_sha256(password=password, salt=pbkdf2_salt, iterations=4096, dklen=32)
    builtin = hashlib.pbkdf2_hmac("sha256", password, pbkdf2_salt, 4096, 32)
    print("password =", password.decode("utf-8"))
    print("salt =", pbkdf2_salt.decode("utf-8"))
    print("dk(4096,32) =", _h(dk))
    print("matches hashlib.pbkdf2_hmac =", hmac.compare_digest(dk, builtin))
    print()

    print("=== Step 4: scrypt (memory-hard password KDF) ===")
    s1 = scrypt_kdf(b"", b"", n=16, r=1, p=1, dklen=64)
    s2 = scrypt_kdf(b"password", b"NaCl", n=1024, r=8, p=16, dklen=64)
    print("scrypt('', '', N=16,r=1,p=1,dklen=64) =", _h(s1))
    print("scrypt('password','NaCl', N=1024,r=8,p=16,dklen=64) =", _h(s2))


if __name__ == "__main__":
    main()
