"""
Lamport one-time signatures (OTS) from scratch (educational).

This script implements a minimal Lamport OTS over SHA-256 and demonstrates:
- deterministic key generation from a seed (for reproducible demos/tests),
- signing and verifying,
- why reusing a one-time key leaks secrets.

Run:
  python3 code/main.py

⚠️ Educational implementation. Not constant-time. Not production-safe.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass


N_BITS = 256
SECRET_SIZE = 32
PRG_DOMAIN = b"CRYPTO-FROM-SCRATCH/lamport-ots/prg/v1"


def sha256(data: bytes) -> bytes:
    _require_bytes("data", data)
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return sha256(data).hex()


def bits_msb(data: bytes) -> list[int]:
    _require_bytes("data", data)
    out: list[int] = []
    for b in data:
        for i in range(7, -1, -1):
            out.append((b >> i) & 1)
    return out


def prg_sha256(seed: bytes, nbytes: int, *, domain: bytes = PRG_DOMAIN) -> bytes:
    _require_bytes("seed", seed)
    _require_bytes("domain", domain)
    if not isinstance(nbytes, int):
        raise TypeError("nbytes must be int")
    if nbytes < 0:
        raise ValueError("nbytes must be >= 0")

    out = bytearray()
    counter = 0
    while len(out) < nbytes:
        ctr = counter.to_bytes(4, "big")
        out.extend(hashlib.sha256(domain + seed + ctr).digest())
        counter += 1
    return bytes(out[:nbytes])


@dataclass(frozen=True)
class LamportPrivateKey:
    zero: list[bytes]
    one: list[bytes]


@dataclass(frozen=True)
class LamportPublicKey:
    zero: list[bytes]
    one: list[bytes]


def lamport_keygen(*, seed: bytes | None = None) -> tuple[LamportPrivateKey, LamportPublicKey]:
    if seed is not None:
        _require_bytes("seed", seed)

    total = 2 * N_BITS * SECRET_SIZE
    material = prg_sha256(seed, total) if seed is not None else secrets.token_bytes(total)

    sk0: list[bytes] = []
    sk1: list[bytes] = []
    off = 0
    for _ in range(N_BITS):
        sk0.append(material[off : off + SECRET_SIZE])
        off += SECRET_SIZE
    for _ in range(N_BITS):
        sk1.append(material[off : off + SECRET_SIZE])
        off += SECRET_SIZE

    pk0 = [sha256(x) for x in sk0]
    pk1 = [sha256(x) for x in sk1]
    return LamportPrivateKey(sk0, sk1), LamportPublicKey(pk0, pk1)


def lamport_fingerprint_public(pk: LamportPublicKey) -> str:
    _require_public_key(pk)
    h = hashlib.sha256()
    for x in pk.zero:
        h.update(x)
    for x in pk.one:
        h.update(x)
    return h.hexdigest()


def lamport_fingerprint_signature(sig: list[bytes]) -> str:
    _require_signature(sig)
    h = hashlib.sha256()
    for x in sig:
        h.update(x)
    return h.hexdigest()


def lamport_sign(message: bytes, sk: LamportPrivateKey) -> list[bytes]:
    _require_bytes("message", message)
    _require_private_key(sk)

    digest = sha256(message)
    bits = bits_msb(digest)
    if len(bits) != N_BITS:
        raise AssertionError("unexpected digest size")

    sig: list[bytes] = []
    for i, b in enumerate(bits):
        sig.append(sk.one[i] if b else sk.zero[i])
    return sig


def lamport_verify(message: bytes, sig: list[bytes], pk: LamportPublicKey) -> bool:
    _require_bytes("message", message)
    _require_public_key(pk)

    if not isinstance(sig, list):
        raise TypeError("sig must be list[bytes]")
    if len(sig) != N_BITS:
        return False
    for x in sig:
        if not isinstance(x, (bytes, bytearray)):
            return False
        if len(x) != SECRET_SIZE:
            return False

    digest = sha256(message)
    bits = bits_msb(digest)
    if len(bits) != N_BITS:
        raise AssertionError("unexpected digest size")

    for i, b in enumerate(bits):
        want = pk.one[i] if b else pk.zero[i]
        if sha256(sig[i]) != want:
            return False
    return True


def lamport_reuse_leakage(messages: list[bytes], sk: LamportPrivateKey) -> dict[str, int]:
    if not isinstance(messages, list):
        raise TypeError("messages must be list[bytes]")
    for m in messages:
        _require_bytes("message", m)
    _require_private_key(sk)

    have0 = [False] * N_BITS
    have1 = [False] * N_BITS
    for m in messages:
        digest = sha256(m)
        bits = bits_msb(digest)
        for i, b in enumerate(bits):
            if b:
                have1[i] = True
            else:
                have0[i] = True

    fully = sum(1 for i in range(N_BITS) if have0[i] and have1[i])
    return {
        "messages": len(messages),
        "fully_revealed_positions": fully,
        "partially_revealed_positions": N_BITS - sum(1 for i in range(N_BITS) if not have0[i] and not have1[i]),
    }


def _require_bytes(name: str, value: object) -> None:
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError(f"{name} must be bytes")


def _require_private_key(sk: LamportPrivateKey) -> None:
    if not isinstance(sk, LamportPrivateKey):
        raise TypeError("sk must be LamportPrivateKey")
    _require_key_parts(sk.zero, sk.one, what="private key")


def _require_public_key(pk: LamportPublicKey) -> None:
    if not isinstance(pk, LamportPublicKey):
        raise TypeError("pk must be LamportPublicKey")
    _require_key_parts(pk.zero, pk.one, what="public key")


def _require_key_parts(zero: object, one: object, *, what: str) -> None:
    if not isinstance(zero, list) or not isinstance(one, list):
        raise TypeError(f"{what} parts must be lists")
    if len(zero) != N_BITS or len(one) != N_BITS:
        raise ValueError(f"{what} must have {N_BITS} elements in each part")
    for part in (zero, one):
        for x in part:
            if not isinstance(x, (bytes, bytearray)):
                raise TypeError(f"{what} elements must be bytes")
            if len(x) != SECRET_SIZE:
                raise ValueError(f"{what} elements must be {SECRET_SIZE} bytes")


def _require_signature(sig: object) -> None:
    if not isinstance(sig, list):
        raise TypeError("sig must be list[bytes]")
    if len(sig) != N_BITS:
        raise ValueError(f"sig must have {N_BITS} elements")
    for x in sig:
        if not isinstance(x, (bytes, bytearray)):
            raise TypeError("sig elements must be bytes")
        if len(x) != SECRET_SIZE:
            raise ValueError(f"sig elements must be {SECRET_SIZE} bytes")


def _print_step(n: int, name: str) -> None:
    print(f"=== Step {n}: {name} ===")


def _fmt_b(n: int) -> str:
    return f"{n:,} bytes"


def main() -> None:
    _print_step(1, "Hash-to-bits (SHA-256)")
    msg = b"lamport demo message"
    digest = sha256(msg)
    bits = bits_msb(digest)
    print("message:", msg)
    print("sha256(message):", digest.hex())
    print("first 16 bits:", "".join(str(b) for b in bits[:16]))
    print()

    _print_step(2, "Key generation (deterministic from seed)")
    seed = b"demo-seed-for-lamport-ots"
    sk, pk = lamport_keygen(seed=seed)
    print("public key fingerprint:", lamport_fingerprint_public(pk))
    print("public key size:", _fmt_b(2 * N_BITS * SECRET_SIZE))
    print("private key size:", _fmt_b(2 * N_BITS * SECRET_SIZE))
    print()

    _print_step(3, "Sign a message (reveal one secret per hash bit)")
    sig = lamport_sign(msg, sk)
    print("signature fingerprint:", lamport_fingerprint_signature(sig))
    print("sig[0] (hex):", sig[0].hex())
    print()

    _print_step(4, "Verify + why OTS keys must not be reused")
    ok = lamport_verify(msg, sig, pk)
    print("verify(message, sig, pk):", ok)
    ok2 = lamport_verify(msg + b"!", sig, pk)
    print("verify(modified_message, same_sig, pk):", ok2)
    leak = lamport_reuse_leakage([b"m1", b"m2", b"m3"], sk)
    print("reusing one key to sign 3 messages reveals:")
    for k in sorted(leak.keys()):
        print(f"- {k}: {leak[k]}")


if __name__ == "__main__":
    main()
