"""
PQ Migration Lab — Audit a Real Codebase (toy model).

What this file does:
- Scans a tiny "codebase" (in-memory files) for cryptographic dependencies.
- Demonstrates algorithm negotiation with policy (algorithm agility).
- Simulates a *hybrid* key schedule that combines a classical shared secret and a PQ-KEM shared secret.
- Generates a concrete, checklist-style migration plan.

Run:
  python3 code/main.py

Educational implementation. Not constant-time. Not production-safe.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
import re
from typing import Iterable


class PolicyError(ValueError):
    pass


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """
    HKDF-Extract with HMAC-SHA256.

    If salt is empty, HKDF uses an all-zero salt of HashLen bytes.
    """
    if not salt:
        salt = b"\x00" * 32
    return hmac_sha256(salt, ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand with HMAC-SHA256."""
    if length < 0:
        raise ValueError("length must be non-negative")
    if length > 255 * 32:
        raise ValueError("length too large for HKDF-Expand")
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac_sha256(prk, t + info + bytes([counter]))
        okm += t
        counter += 1
    return okm[:length]


def hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)


def transcript_hash(messages: Iterable[bytes]) -> bytes:
    """
    Transcript hash with length-prefixing to avoid ambiguity.

    For each message m:
      H = SHA256( H || u32(len(m)) || m )
    """
    h = hashlib.sha256()
    for m in messages:
        if not isinstance(m, (bytes, bytearray)):
            raise TypeError("messages must be bytes")
        m = bytes(m)
        h.update(len(m).to_bytes(4, "big"))
        h.update(m)
    return h.digest()


def is_pq_algorithm(name: str) -> bool:
    return name.startswith("PQC-")


def parse_hybrid_name(name: str) -> tuple[str, str] | None:
    """
    Parse HYBRID(a,b) where a and b are algorithm names without commas.
    Returns (a, b) or None if not a HYBRID name.
    """
    if not (name.startswith("HYBRID(") and name.endswith(")")):
        return None
    inner = name[len("HYBRID(") : -1]
    if "," not in inner:
        return None
    left, right = inner.split(",", 1)
    left, right = left.strip(), right.strip()
    if not left or not right:
        return None
    return left, right


def kex_has_pq(name: str) -> bool:
    if is_pq_algorithm(name):
        return True
    parts = parse_hybrid_name(name)
    if not parts:
        return False
    return is_pq_algorithm(parts[0]) or is_pq_algorithm(parts[1])


def server_select_kex(client_offered: list[str], server_preference: list[str]) -> str:
    """
    Deterministic server-side selection: first server preference that the client offered.
    Raises PolicyError if there is no overlap.
    """
    client_set = set(client_offered)
    for candidate in server_preference:
        if candidate in client_set:
            return candidate
    raise PolicyError("no mutually supported KEX found")


def enforce_kex_policy(selected: str, require_pq: bool) -> None:
    if require_pq and not kex_has_pq(selected):
        raise PolicyError("policy requires a PQ-capable KEX (PQ-only or HYBRID)")


def _int_from_hash(tag: bytes, seed: bytes) -> int:
    return int.from_bytes(sha256(tag + seed), "big")


def toy_dh_keypair(p: int, g: int, seed: bytes) -> tuple[int, int]:
    """
    Deterministic, toy Diffie–Hellman keypair for demos/tests.
    Not cryptographically safe.
    """
    priv = (_int_from_hash(b"toy-dh-priv:", seed) % (p - 2)) + 2
    pub = pow(g, priv, p)
    return priv, pub


def toy_dh_shared(p: int, priv: int, peer_pub: int) -> bytes:
    shared_int = pow(peer_pub, priv, p)
    shared_bytes = shared_int.to_bytes((p.bit_length() + 7) // 8, "big")
    return sha256(b"toy-dh-shared:" + shared_bytes)


def toy_kem_keygen(seed: bytes) -> tuple[bytes, bytes]:
    """
    Deterministic toy KEM keygen.
    sk = SHA256("sk" || seed)
    pk = SHA256("pk" || sk)
    """
    sk = sha256(b"sk:" + seed)
    pk = sha256(b"pk:" + sk)
    return pk, sk


def toy_kem_encapsulate(pk: bytes, seed: bytes) -> tuple[bytes, bytes]:
    """
    Deterministic toy KEM encapsulation.
    ct = SHA256("ct" || pk || seed)
    ss = SHA256("ss" || pk || ct)
    """
    ct = sha256(b"ct:" + pk + seed)
    ss = sha256(b"ss:" + pk + ct)
    return ct, ss


def toy_kem_decapsulate(sk: bytes, ct: bytes) -> bytes:
    pk = sha256(b"pk:" + sk)
    return sha256(b"ss:" + pk + ct)


def derive_hybrid_session_key(
    *,
    classical_shared: bytes,
    pq_shared: bytes,
    transcript: bytes,
    info: bytes,
    length: int = 32,
) -> bytes:
    """
    A simple hybrid combiner:
      Z = classical_shared || pq_shared
      PRK = HKDF-Extract(salt=transcript, IKM=Z)
      key = HKDF-Expand(PRK, info, length)
    """
    z = classical_shared + pq_shared
    prk = hkdf_extract(transcript, z)
    return hkdf_expand(prk, info, length)


@dataclasses.dataclass(frozen=True)
class CryptoFinding:
    path: str
    primitive: str
    detail: str


CRYPTO_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("RSA", re.compile(r"\bRSA\b|rsa_", re.IGNORECASE)),
    ("ECDSA", re.compile(r"\bECDSA\b|secp256r1|prime256v1", re.IGNORECASE)),
    ("ECDH", re.compile(r"\bECDH\b|x25519|secp256r1", re.IGNORECASE)),
    ("TLS", re.compile(r"\bTLS\b|ssl|https://", re.IGNORECASE)),
    ("SHA-1", re.compile(r"\bSHA-?1\b", re.IGNORECASE)),
    ("SHA-256", re.compile(r"\bSHA-?256\b", re.IGNORECASE)),
    ("AES-GCM", re.compile(r"\bAES\b.*\bGCM\b|AESGCM", re.IGNORECASE)),
    ("PQC", re.compile(r"\bPQC\b|ML-?KEM|Kyber|Dilithium|SPHINCS", re.IGNORECASE)),
    ("Isogeny", re.compile(r"\bSIKE\b|\bSIDH\b|isogen", re.IGNORECASE)),
]


def scan_crypto_usage(files: dict[str, str]) -> list[CryptoFinding]:
    findings: list[CryptoFinding] = []
    for path, content in files.items():
        for primitive, pat in CRYPTO_PATTERNS:
            for m in pat.finditer(content):
                span = content[max(0, m.start() - 20) : min(len(content), m.end() + 20)]
                findings.append(CryptoFinding(path=path, primitive=primitive, detail=span.strip()))
    return findings


def summarize_findings(findings: list[CryptoFinding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.primitive] = counts.get(f.primitive, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def build_migration_plan(
    *,
    findings: list[CryptoFinding],
    selected_kex: str,
    require_pq: bool,
) -> list[str]:
    counts = summarize_findings(findings)
    plan: list[str] = []

    plan.append("Inventory: list protocols, libraries, and cert/key formats per service boundary.")
    if counts.get("SHA-1", 0) > 0:
        plan.append("Risk: SHA-1 usage found — remove immediately (collisions, ecosystem bans).")
    if counts.get("RSA", 0) > 0:
        plan.append("Plan: stage RSA deprecation (switch to ECDSA now, PQ signatures later).")
    if counts.get("Isogeny", 0) > 0:
        plan.append("Risk: isogeny/SIKE references found — treat as unsafe unless you have a very specific, reviewed reason.")

    if require_pq:
        plan.append(f"Policy: require PQ-capable KEX — negotiated: {selected_kex}.")
    else:
        plan.append(f"Policy: PQ optional — negotiated: {selected_kex}.")

    plan.append("Rollout: implement algorithm agility + telemetry (who negotiates what, where).")
    plan.append("Rollout: ship hybrid first (classical + PQ), then later remove classical when safe.")
    plan.append("Ops: add canary, feature flags, and downgrade alarms (unexpected negotiation results).")
    plan.append("Governance: document crypto policy, key lifetimes, and incident response for breaks.")
    return plan


def _demo_codebase_files() -> dict[str, str]:
    return {
        "services/api/tls_config.py": """
TLS_VERSION = "1.2"
CIPHERS = ["ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-ECDSA-AES128-GCM-SHA256"]
""".strip(),
        "services/payments/crypto.py": """
# legacy
SIG_ALG = "RSA"
HASH = "SHA-1"
""".strip(),
        "services/edge/README.md": """
We terminate TLS and use X25519 for ECDH.
PQC experiment: HYBRID(X25519,PQC-MLKEM-768)
""".strip(),
        "research/isogeny_notes.txt": """
Old notes about SIKE/SIDH (do not use in production).
""".strip(),
    }


def demo_inventory() -> tuple[list[CryptoFinding], dict[str, int]]:
    files = _demo_codebase_files()
    findings = scan_crypto_usage(files)
    summary = summarize_findings(findings)
    return findings, summary


def demo_negotiation() -> tuple[str, bytes]:
    client_offered = [
        "X25519",
        "HYBRID(X25519,PQC-MLKEM-768)",
        "PQC-MLKEM-768",
    ]
    server_preference = [
        "HYBRID(X25519,PQC-MLKEM-768)",
        "X25519",
        "PQC-MLKEM-768",
    ]

    selected = server_select_kex(client_offered, server_preference)
    enforce_kex_policy(selected, require_pq=True)
    transcript = transcript_hash(
        [
            b"client_offered:" + ",".join(client_offered).encode(),
            b"server_selected:" + selected.encode(),
        ]
    )
    return selected, transcript


def demo_hybrid_key_schedule(transcript: bytes) -> dict[str, str]:
    p = 2**127 - 1
    g = 3

    client_seed = b"client-seed"
    server_seed = b"server-seed"

    c_priv, c_pub = toy_dh_keypair(p, g, client_seed)
    s_priv, s_pub = toy_dh_keypair(p, g, server_seed)

    classical_c = toy_dh_shared(p, c_priv, s_pub)
    classical_s = toy_dh_shared(p, s_priv, c_pub)
    assert classical_c == classical_s

    pk, sk = toy_kem_keygen(b"kem-keygen-seed")
    ct, pq_c = toy_kem_encapsulate(pk, b"kem-encap-seed")
    pq_s = toy_kem_decapsulate(sk, ct)
    assert pq_c == pq_s

    session_key = derive_hybrid_session_key(
        classical_shared=classical_c,
        pq_shared=pq_c,
        transcript=transcript,
        info=b"pq-migration-lab v1 session key",
        length=32,
    )

    return {
        "client_dh_pub": hex(c_pub),
        "server_dh_pub": hex(s_pub),
        "kem_ct": ct.hex(),
        "transcript_hash": transcript.hex(),
        "session_key": session_key.hex(),
    }


def main():
    print("=== Step 1: Inventory crypto usage ===")
    findings, summary = demo_inventory()
    print("summary:", json.dumps(summary, indent=2, sort_keys=True))
    print("sample findings (first 6):")
    for f in findings[:6]:
        print(f"  - {f.path}: {f.primitive}: {f.detail!r}")
    print()

    print("=== Step 2: Negotiate algorithms (policy + agility) ===")
    selected, transcript = demo_negotiation()
    print("selected_kex:", selected)
    print("transcript_hash:", transcript.hex())
    print()

    print("=== Step 3: Hybrid key schedule (classical + PQ) ===")
    out = demo_hybrid_key_schedule(transcript)
    print("inputs → outputs:")
    print("  client_dh_pub:", out["client_dh_pub"][:22] + "…")
    print("  server_dh_pub:", out["server_dh_pub"][:22] + "…")
    print("  kem_ct:", out["kem_ct"][:32] + "…")
    print("  session_key:", out["session_key"])
    print()

    print("=== Step 4: Produce a migration plan ===")
    plan = build_migration_plan(
        findings=findings,
        selected_kex=selected,
        require_pq=True,
    )
    for i, item in enumerate(plan, 1):
        print(f"{i:>2}. {item}")


if __name__ == "__main__":
    main()
