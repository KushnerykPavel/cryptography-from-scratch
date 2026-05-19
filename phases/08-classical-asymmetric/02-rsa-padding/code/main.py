"""
RSA padding in practice: PKCS#1 v1.5 (legacy), OAEP (encryption), PSS (signatures).

Run:
  python3 code/main.py

This is an educational, non-constant-time implementation for learning and test vectors.
Do not use it in production.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass


def i2osp(x: int, x_len: int) -> bytes:
    if x < 0:
        raise ValueError("i2osp: negative integer")
    if x >= 256**x_len:
        raise ValueError("i2osp: integer too large")
    return x.to_bytes(x_len, "big")


def os2ip(x: bytes) -> int:
    return int.from_bytes(x, "big")


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor_bytes: length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))


def mgf1(seed: bytes, mask_len: int, hash_name: str = "sha256") -> bytes:
    h_len = hashlib.new(hash_name).digest_size
    if mask_len < 0:
        raise ValueError("mgf1: negative length")
    if mask_len > (2**32) * h_len:
        raise ValueError("mgf1: mask too long")

    out = bytearray()
    for counter in range(0, -(-mask_len // h_len)):
        c = counter.to_bytes(4, "big")
        out.extend(hashlib.new(hash_name, seed + c).digest())
    return bytes(out[:mask_len])


def eme_pkcs1_v1_5_encode(
    message: bytes,
    k: int,
    *,
    ps: bytes | None = None,
    rng: secrets.SystemRandom | None = None,
) -> bytes:
    if len(message) > k - 11:
        raise ValueError("eme_pkcs1_v1_5_encode: message too long")

    ps_len = k - len(message) - 3
    if ps is None:
        rng = rng or secrets.SystemRandom()
        ps_buf = bytearray()
        while len(ps_buf) < ps_len:
            b = rng.randrange(1, 256)
            ps_buf.append(b)
        ps = bytes(ps_buf)

    if len(ps) != ps_len:
        raise ValueError("eme_pkcs1_v1_5_encode: bad PS length")
    if any(b == 0 for b in ps):
        raise ValueError("eme_pkcs1_v1_5_encode: PS must be nonzero")

    return b"\x00\x02" + ps + b"\x00" + message


def eme_pkcs1_v1_5_decode(em: bytes) -> bytes:
    if len(em) < 11:
        raise ValueError("eme_pkcs1_v1_5_decode: decryption error")
    if em[0] != 0x00 or em[1] != 0x02:
        raise ValueError("eme_pkcs1_v1_5_decode: decryption error")

    try:
        sep = em.index(b"\x00", 2)
    except ValueError as exc:
        raise ValueError("eme_pkcs1_v1_5_decode: decryption error") from exc

    if sep < 10:
        raise ValueError("eme_pkcs1_v1_5_decode: decryption error")
    if any(b == 0 for b in em[2:sep]):
        raise ValueError("eme_pkcs1_v1_5_decode: decryption error")
    return em[sep + 1 :]


def oaep_encode(
    message: bytes,
    k: int,
    *,
    label: bytes = b"",
    hash_name: str = "sha256",
    seed: bytes | None = None,
    rng: secrets.SystemRandom | None = None,
) -> bytes:
    h_len = hashlib.new(hash_name).digest_size
    if k < 2 * h_len + 2:
        raise ValueError("oaep_encode: modulus too short")
    if len(message) > k - 2 * h_len - 2:
        raise ValueError("oaep_encode: message too long")

    l_hash = hashlib.new(hash_name, label).digest()
    ps = b"\x00" * (k - len(message) - 2 * h_len - 2)
    db = l_hash + ps + b"\x01" + message

    if seed is None:
        rng = rng or secrets.SystemRandom()
        seed = bytes(rng.randrange(0, 256) for _ in range(h_len))
    if len(seed) != h_len:
        raise ValueError("oaep_encode: bad seed length")

    db_mask = mgf1(seed, k - h_len - 1, hash_name)
    masked_db = xor_bytes(db, db_mask)
    seed_mask = mgf1(masked_db, h_len, hash_name)
    masked_seed = xor_bytes(seed, seed_mask)
    return b"\x00" + masked_seed + masked_db


def oaep_decode(
    em: bytes,
    k: int,
    *,
    label: bytes = b"",
    hash_name: str = "sha256",
) -> bytes:
    h_len = hashlib.new(hash_name).digest_size
    if len(em) != k:
        raise ValueError("oaep_decode: decryption error")
    if k < 2 * h_len + 2:
        raise ValueError("oaep_decode: decryption error")
    if em[0] != 0x00:
        raise ValueError("oaep_decode: decryption error")

    masked_seed = em[1 : 1 + h_len]
    masked_db = em[1 + h_len :]
    seed_mask = mgf1(masked_db, h_len, hash_name)
    seed = xor_bytes(masked_seed, seed_mask)
    db_mask = mgf1(seed, k - h_len - 1, hash_name)
    db = xor_bytes(masked_db, db_mask)

    l_hash = hashlib.new(hash_name, label).digest()
    if db[:h_len] != l_hash:
        raise ValueError("oaep_decode: decryption error")

    rest = db[h_len:]
    one_pos = rest.find(b"\x01")
    if one_pos == -1:
        raise ValueError("oaep_decode: decryption error")
    if any(b != 0 for b in rest[:one_pos]):
        raise ValueError("oaep_decode: decryption error")
    return rest[one_pos + 1 :]


_HASH_DER_PREFIX = {
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha1": bytes.fromhex("3021300906052b0e03021a05000414"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}


def emsa_pkcs1_v1_5_encode(message: bytes, em_len: int, *, hash_name: str = "sha256") -> bytes:
    if hash_name not in _HASH_DER_PREFIX:
        raise ValueError(f"emsa_pkcs1_v1_5_encode: unsupported hash {hash_name}")
    digest = hashlib.new(hash_name, message).digest()
    t = _HASH_DER_PREFIX[hash_name] + digest
    if em_len < len(t) + 11:
        raise ValueError("emsa_pkcs1_v1_5_encode: intended encoded message too short")
    ps = b"\xff" * (em_len - len(t) - 3)
    return b"\x00\x01" + ps + b"\x00" + t


def pss_encode(
    message_hash: bytes,
    em_bits: int,
    *,
    hash_name: str = "sha256",
    salt: bytes | None = None,
    salt_len: int | None = None,
    rng: secrets.SystemRandom | None = None,
) -> bytes:
    h_len = hashlib.new(hash_name).digest_size
    if len(message_hash) != h_len:
        raise ValueError("pss_encode: bad hash length")

    if salt is None:
        salt_len = h_len if salt_len is None else salt_len
        rng = rng or secrets.SystemRandom()
        salt = bytes(rng.randrange(0, 256) for _ in range(salt_len))

    s_len = len(salt)
    em_len = (em_bits + 7) // 8
    if em_len < h_len + s_len + 2:
        raise ValueError("pss_encode: encoding error")

    m_prime = b"\x00" * 8 + message_hash + salt
    h = hashlib.new(hash_name, m_prime).digest()
    ps = b"\x00" * (em_len - s_len - h_len - 2)
    db = ps + b"\x01" + salt
    db_mask = mgf1(h, em_len - h_len - 1, hash_name)
    masked_db = bytearray(xor_bytes(db, db_mask))

    left = 8 * em_len - em_bits
    if left:
        masked_db[0] &= 0xFF >> left

    return bytes(masked_db) + h + b"\xbc"


def pss_verify(
    message_hash: bytes,
    em: bytes,
    em_bits: int,
    *,
    hash_name: str = "sha256",
    salt_len: int | None = None,
) -> bool:
    h_len = hashlib.new(hash_name).digest_size
    if len(message_hash) != h_len:
        return False

    em_len = (em_bits + 7) // 8
    salt_len = h_len if salt_len is None else salt_len
    if len(em) != em_len:
        return False
    if em_len < h_len + salt_len + 2:
        return False
    if em[-1] != 0xBC:
        return False

    masked_db = em[: em_len - h_len - 1]
    h = em[em_len - h_len - 1 : em_len - 1]

    left = 8 * em_len - em_bits
    if left and (masked_db[0] & (0xFF << (8 - left))) != 0:
        return False

    db_mask = mgf1(h, em_len - h_len - 1, hash_name)
    db = bytearray(xor_bytes(masked_db, db_mask))
    if left:
        db[0] &= 0xFF >> left

    ps_len = em_len - h_len - salt_len - 2
    if any(b != 0 for b in db[:ps_len]):
        return False
    if db[ps_len] != 0x01:
        return False

    salt = bytes(db[-salt_len:])
    m_prime = b"\x00" * 8 + message_hash + salt
    h2 = hashlib.new(hash_name, m_prime).digest()
    return h == h2


def rsaep(n: int, e: int, m: int) -> int:
    if m < 0 or m >= n:
        raise ValueError("rsaep: message representative out of range")
    return pow(m, e, n)


def rsadp(n: int, d: int, c: int) -> int:
    if c < 0 or c >= n:
        raise ValueError("rsadp: ciphertext representative out of range")
    return pow(c, d, n)


def rsaes_oaep_encrypt(
    message: bytes,
    n: int,
    e: int,
    *,
    label: bytes = b"",
    hash_name: str = "sha256",
    seed: bytes | None = None,
) -> bytes:
    k = (n.bit_length() + 7) // 8
    em = oaep_encode(message, k, label=label, hash_name=hash_name, seed=seed)
    c = rsaep(n, e, os2ip(em))
    return i2osp(c, k)


def rsaes_oaep_decrypt(
    ciphertext: bytes,
    n: int,
    d: int,
    *,
    label: bytes = b"",
    hash_name: str = "sha256",
) -> bytes:
    k = (n.bit_length() + 7) // 8
    if len(ciphertext) != k:
        raise ValueError("rsaes_oaep_decrypt: decryption error")
    m = rsadp(n, d, os2ip(ciphertext))
    em = i2osp(m, k)
    return oaep_decode(em, k, label=label, hash_name=hash_name)


def rsaes_pkcs1_v1_5_encrypt(
    message: bytes,
    n: int,
    e: int,
    *,
    ps: bytes | None = None,
) -> bytes:
    k = (n.bit_length() + 7) // 8
    em = eme_pkcs1_v1_5_encode(message, k, ps=ps)
    c = rsaep(n, e, os2ip(em))
    return i2osp(c, k)


def rsaes_pkcs1_v1_5_decrypt(ciphertext: bytes, n: int, d: int) -> bytes:
    k = (n.bit_length() + 7) // 8
    if len(ciphertext) != k:
        raise ValueError("rsaes_pkcs1_v1_5_decrypt: decryption error")
    m = rsadp(n, d, os2ip(ciphertext))
    em = i2osp(m, k)
    return eme_pkcs1_v1_5_decode(em)


def rsassa_pkcs1_v1_5_sign(message: bytes, n: int, d: int, *, hash_name: str = "sha256") -> bytes:
    k = (n.bit_length() + 7) // 8
    em = emsa_pkcs1_v1_5_encode(message, k, hash_name=hash_name)
    s = rsadp(n, d, os2ip(em))
    return i2osp(s, k)


def rsassa_pkcs1_v1_5_verify(
    message: bytes, signature: bytes, n: int, e: int, *, hash_name: str = "sha256"
) -> bool:
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    m = rsaep(n, e, os2ip(signature))
    em = i2osp(m, k)
    try:
        expected = emsa_pkcs1_v1_5_encode(message, k, hash_name=hash_name)
    except ValueError:
        return False
    return secrets.compare_digest(em, expected)


def rsassa_pss_sign(
    message: bytes,
    n: int,
    d: int,
    *,
    hash_name: str = "sha256",
    salt: bytes | None = None,
    salt_len: int | None = None,
) -> bytes:
    k = (n.bit_length() + 7) // 8
    em_bits = n.bit_length() - 1
    m_hash = hashlib.new(hash_name, message).digest()
    em = pss_encode(m_hash, em_bits, hash_name=hash_name, salt=salt, salt_len=salt_len)
    s = rsadp(n, d, os2ip(em))
    return i2osp(s, k)


def rsassa_pss_verify(
    message: bytes,
    signature: bytes,
    n: int,
    e: int,
    *,
    hash_name: str = "sha256",
    salt_len: int | None = None,
) -> bool:
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    em_bits = n.bit_length() - 1
    m_hash = hashlib.new(hash_name, message).digest()
    m = rsaep(n, e, os2ip(signature))
    em = i2osp(m, (em_bits + 7) // 8)
    return pss_verify(m_hash, em, em_bits, hash_name=hash_name, salt_len=salt_len)


@dataclass(frozen=True)
class DemoRSAKey:
    n: int
    e: int
    d: int

    @property
    def k(self) -> int:
        return (self.n.bit_length() + 7) // 8


DEMO_KEY = DemoRSAKey(
    n=int(
        "7cbe48af537f6704d2e9ee153b9e0a8829623b863d08318d59d9996ee5243848"
        "da5ca0f1fefafad85cb4e35f44ac655dedfb10843014fb1285e5df36363e6d74"
        "6c7855579989bab89cc03be8cdb18e09197bd57865a808ab140a9038f07db78c"
        "c5f0b8fb714895c790d59179a51fe356d24e636076d839df001b14b3d7782539",
        16,
    ),
    e=65537,
    d=int(
        "3b9ecaa89974cbed1f4d55506aa5178d8a91fbb72616737086a01cd846c66fec"
        "4a0979970ff22ed01847106129366860636cdab1033613e5ff7f25970887ffd1"
        "b2dff665579a7364c41f244977868a72b67bdc85280146fbfe267c28c7c3b00d"
        "04276d8244a7e485d5d73e3b6dba35b9c85f42e3fbf82623305046787ea270cd",
        16,
    ),
)


def _step_header(n: int, name: str) -> None:
    print(f"=== Step {n}: {name} ===")


def main() -> None:
    key = DEMO_KEY

    _step_header(1, "Bytes and masks (I2OSP/OS2IP, XOR, MGF1)")
    seed = bytes.fromhex("00010203")
    mask = mgf1(seed, 32, "sha256")
    print("mgf1(seed=00010203, len=32) =", mask.hex())

    _step_header(2, "PKCS#1 v1.5 encryption padding (legacy)")
    msg_v15 = b"v1.5 test"
    ps = bytes([(i % 254) + 1 for i in range(key.k - len(msg_v15) - 3)])
    em_v15 = eme_pkcs1_v1_5_encode(msg_v15, key.k, ps=ps)
    print("eme_pkcs1_v1_5_encode(...) prefix =", em_v15[:16].hex(), "...")
    print("decode roundtrip =", eme_pkcs1_v1_5_decode(em_v15))

    _step_header(3, "OAEP encode/decode (encryption padding)")
    msg_oaep = b"hello oaep"
    oaep_seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    em_oaep = oaep_encode(msg_oaep, key.k, hash_name="sha256", seed=oaep_seed)
    print("oaep_encode(...).len =", len(em_oaep))
    print("oaep_decode(oaep_encode(m)) =", oaep_decode(em_oaep, key.k, hash_name="sha256"))

    _step_header(4, "RSA-OAEP encrypt/decrypt + RSA-PSS sign/verify")
    ct_oaep = rsaes_oaep_encrypt(msg_oaep, key.n, key.e, hash_name="sha256", seed=oaep_seed)
    pt_oaep = rsaes_oaep_decrypt(ct_oaep, key.n, key.d, hash_name="sha256")
    print("rsaes_oaep_encrypt(m) =", ct_oaep.hex()[:32], "...")
    print("rsaes_oaep_decrypt(c) =", pt_oaep)

    pss_msg = b"pss message"
    pss_salt = bytes.fromhex("a0" * 32)
    sig_pss = rsassa_pss_sign(pss_msg, key.n, key.d, hash_name="sha256", salt=pss_salt)
    ok_pss = rsassa_pss_verify(pss_msg, sig_pss, key.n, key.e, hash_name="sha256", salt_len=32)
    print("rsassa_pss_sign(m) =", sig_pss.hex()[:32], "...")
    print("rsassa_pss_verify(m, sig) =", ok_pss)

    _step_header(5, "Why raw RSA breaks (determinism + malleability)")
    m_int = os2ip(b"\x01" + b"\x00" * 15)
    c1 = rsaep(key.n, key.e, m_int)
    c2 = rsaep(key.n, key.e, m_int)
    print("raw RSA deterministic:", c1 == c2)

    r = 3
    c_malleated = (c1 * pow(r, key.e, key.n)) % key.n
    m_malleated = rsadp(key.n, key.d, c_malleated)
    print("malleability: Dec(c * r^e) == m*r mod n:", m_malleated == (m_int * r) % key.n)


if __name__ == "__main__":
    main()
