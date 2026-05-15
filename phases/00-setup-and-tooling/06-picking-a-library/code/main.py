from __future__ import annotations

from dataclasses import dataclass
from importlib import metadata


@dataclass(frozen=True)
class UseCase:
    name: str
    needs_hash: bool = False
    needs_hmac: bool = False
    needs_safe_compare: bool = False
    needs_aead: bool = False
    wants_misuse_resistant_api: bool = True
    wants_minimal_deps: bool = True


@dataclass(frozen=True)
class Candidate:
    name: str
    dist: str | None
    has_hash: bool
    has_hmac: bool
    has_safe_compare: bool
    has_aead: bool
    misuse_resistant: bool
    low_level_footguns: bool


def _dist_version(dist: str) -> str | None:
    try:
        return metadata.version(dist)
    except metadata.PackageNotFoundError:
        return None


def _score(use_case: UseCase, c: Candidate) -> int:
    score = 0

    if use_case.needs_hash and c.has_hash:
        score += 2
    if use_case.needs_hmac and c.has_hmac:
        score += 2
    if use_case.needs_safe_compare and c.has_safe_compare:
        score += 2
    if use_case.needs_aead and c.has_aead:
        score += 3

    if use_case.wants_misuse_resistant_api and c.misuse_resistant:
        score += 2

    if use_case.wants_minimal_deps and c.dist is None:
        score += 2

    if use_case.wants_misuse_resistant_api and c.low_level_footguns:
        score -= 2

    return score


def recommend(use_case: UseCase, candidates: list[Candidate]) -> list[tuple[int, Candidate]]:
    ranked = [(_score(use_case, c), c) for c in candidates]
    ranked.sort(key=lambda t: (t[0], t[1].name), reverse=True)
    return ranked


def demo_stdlib_hash_hmac() -> None:
    import hashlib
    import hmac
    import secrets

    msg = b"hello"
    key = b"k" * 32

    digest = hashlib.sha256(msg).digest()
    tag = hmac.new(key, msg, hashlib.sha256).digest()
    ok = secrets.compare_digest(tag, tag)

    assert len(digest) == 32
    assert len(tag) == 32
    assert ok is True


def demo_cryptography_aead() -> None:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

    msg = b"attack at dawn"
    aad = b"header"
    nonce = b"\x01" * 12

    key_aes = b"\x02" * 32
    aead_aes = AESGCM(key_aes)
    ct = aead_aes.encrypt(nonce, msg, aad)
    pt = aead_aes.decrypt(nonce, ct, aad)
    assert pt == msg

    key_chacha = b"\x03" * 32
    aead_chacha = ChaCha20Poly1305(key_chacha)
    ct2 = aead_chacha.encrypt(nonce, msg, aad)
    pt2 = aead_chacha.decrypt(nonce, ct2, aad)
    assert pt2 == msg


def main() -> None:
    candidates = [
        Candidate(
            name="stdlib",
            dist=None,
            has_hash=True,
            has_hmac=True,
            has_safe_compare=True,
            has_aead=False,
            misuse_resistant=True,
            low_level_footguns=False,
        ),
        Candidate(
            name="cryptography",
            dist="cryptography",
            has_hash=False,
            has_hmac=False,
            has_safe_compare=False,
            has_aead=True,
            misuse_resistant=True,
            low_level_footguns=False,
        ),
        Candidate(
            name="PyNaCl (libsodium-style)",
            dist="PyNaCl",
            has_hash=False,
            has_hmac=False,
            has_safe_compare=False,
            has_aead=True,
            misuse_resistant=True,
            low_level_footguns=False,
        ),
        Candidate(
            name="PyCryptodome (classic primitives)",
            dist="pycryptodome",
            has_hash=True,
            has_hmac=True,
            has_safe_compare=False,
            has_aead=True,
            misuse_resistant=False,
            low_level_footguns=True,
        ),
    ]

    print("crypto library picker (course rubric, educational)")
    print()

    print("installed versions:")
    for c in candidates:
        if c.dist is None:
            print(f"  {c.name}: (stdlib)")
            continue
        v = _dist_version(c.dist)
        status = v if v is not None else "NOT INSTALLED"
        print(f"  {c.name}: {status}")
    print()

    use_cases = [
        UseCase(
            name="Hash + HMAC + safe compare",
            needs_hash=True,
            needs_hmac=True,
            needs_safe_compare=True,
            wants_misuse_resistant_api=True,
            wants_minimal_deps=True,
        ),
        UseCase(
            name="Encrypt+authenticate messages (AEAD)",
            needs_aead=True,
            wants_misuse_resistant_api=True,
            wants_minimal_deps=False,
        ),
        UseCase(
            name="Explore low-level primitives (learning/legacy)",
            needs_hash=True,
            needs_aead=True,
            wants_misuse_resistant_api=False,
            wants_minimal_deps=False,
        ),
    ]

    for u in use_cases:
        print(f"use case: {u.name}")
        ranked = recommend(u, candidates)
        for score, c in ranked:
            print(f"  score {score:>2}  {c.name}")
        print()

    demo_stdlib_hash_hmac()
    demo_cryptography_aead()
    print("demos: OK")


if __name__ == "__main__":
    main()
