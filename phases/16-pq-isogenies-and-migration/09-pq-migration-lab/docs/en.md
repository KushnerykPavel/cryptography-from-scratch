# PQ Migration Lab — Audit a Real Codebase
> Migration is not “swap an algorithm”. It’s inventory → policy → rollout → telemetry.

**Type:** Build
**Languages:** Python
**Prerequisites:** `05-nist-pqc-standards`, `06-hybrid-tls`, `07-crypto-agility`, `08-harvest-now-decrypt-later`
**Time:** ~120 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** why PQ migration is mostly systems work, not math.
- **Compute** a hybrid session key using `HKDF-Extract` + `HKDF-Expand`.
- **Implement** deterministic algorithm negotiation with a policy gate.
- **Distinguish** PQ-only vs hybrid vs classical deployments (and when each is sane).
- **Apply** an audit checklist to find crypto dependencies and migration risks.

## The Problem

You don’t migrate to PQC by changing `RSA` to `PQC-*` in one file. Real systems have *multiple* crypto boundaries: TLS termination, service-to-service mTLS, JWT signing, database encryption, KMS envelope keys, backups, long-lived archives, and “helpful” legacy code nobody wants to touch. Each boundary has its own algorithms, key lifetimes, libraries, and operational constraints.

If you skip the audit and jump straight to “pick a PQ algorithm”, you will ship one of the classic failures: an algorithm that isn’t actually used (negotiation falls back), a partial migration that breaks clients, or a “hybrid” design that accidentally throws away the security of one component. In the worst case, you lock yourself into a dead end: a code path that cannot rotate keys, cannot change algorithms, and cannot even *tell* you what it negotiated in production.

This lesson is a lab: you build a small migration toolchain (inventory + negotiation + hybrid key schedule + plan output) that mirrors the shape of a real migration, without requiring any external libraries.

## The Concept

Think of PQ migration as a four-loop control system:

1. **Inventory (visibility).** What crypto is used where? Which protocol version? Which library? Which key format? Which lifetime?
2. **Policy (decision).** What is allowed today? What is banned? What is “must be hybrid”? What is “PQC-only”?
3. **Rollout (change).** Canaries, feature flags, compatibility windows, key rotation, staged removal.
4. **Telemetry (feedback).** What do clients negotiate? Where do handshakes fail? Are we seeing downgrades or unexpected fallbacks?

Two migration ideas matter in almost every real deployment:

- **Algorithm agility:** protocols and code paths must support changing algorithms without redesigning the system.
- **Hybridization:** for key establishment, you often run a classical exchange *and* a PQ KEM and then combine the shared secrets with a KDF. Hybrid lets you ship sooner (compatibility + defense-in-depth) and remove legacy later.

In this lab we model “hybridization” with a simple combiner:

| Input | Meaning |
|------:|---------|
| `classical_shared` | classical key exchange output (e.g., ECDH) |
| `pq_shared` | PQ KEM shared secret |
| `transcript` | hash of the negotiated parameters (what was offered/selected) |
| `HKDF` | extractor + expander to make a session key |

If you don’t bind the negotiation into the transcript, you invite “silent fallback”: endpoints think they’re using a stronger mode, but an attacker (or a misconfig) forces a weaker one.

## Build It

### Step 1: Inventory crypto usage
```python
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
```
You can’t migrate what you can’t see. This step implements a tiny “codebase scanner”: it searches a set of files for crypto-ish strings and emits structured findings plus a sorted summary. In a real system this becomes a dependency graph: *service* → *protocol boundary* → *library* → *key type* → *lifetime*.

### Step 2: Negotiate algorithms (policy + agility)
```python
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
```
Migration is a negotiation problem before it is a cryptography problem. This step models two realities: (1) algorithm names are data, so you must parse/validate them, and (2) “supporting PQC” is meaningless unless your policy *forces* the stronger mode where required.

### Step 3: Hybrid key schedule (classical + PQ)
```python
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
```
Hybridization is “run two key establishments, then combine.” The *combiner* is the part people get wrong: you must treat both inputs as secrets, extract randomness (so biases don’t leak), and bind the transcript (so a downgrade changes the key).

### Step 4: Produce a migration plan
```python
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
```
The end-product of an audit is not “we should use PQC”. It’s a prioritized plan with concrete actions: immediate bans (SHA-1), staging steps (RSA → ECDSA → PQ signatures), and rollout mechanics (telemetry + canaries + downgrade alarms).

Run it:
`python3 code/main.py`

## Use It

Where this maps in production:

| Problem in this lab | Production equivalent |
|---|---|
| `scan_crypto_usage()` | SBOM + code search + config inventory + TLS handshake telemetry |
| `server_select_kex()` | TLS group/KEM negotiation policy + config rollout |
| `derive_hybrid_session_key()` | Standardized key schedule (e.g., HKDF-based) with transcript binding |
| `build_migration_plan()` | Written crypto policy + migration runbook + tracking spreadsheet |

Concrete tools/places to look (pick what matches your stack):
- **TLS:** your terminating proxy / load balancer / service mesh. Verify what it *actually negotiates* in logs/metrics.
- **Crypto libraries:** OpenSSL/BoringSSL/AWS-LC, language runtimes, and any “crypto glue” wrappers your org uses.
- **PQC experimentation:** use well-maintained PQC providers/libraries rather than hand-rolled code; treat “hybrid” as a protocol-level feature, not an application hack.

## Pitfalls

1. **“Supported” isn’t “used”.** The library supports PQC, but your policy allows fallback, and production always negotiates classical.
2. **No transcript binding.** You combine secrets but don’t bind the negotiation into the KDF context → silent downgrade risk.
3. **Key-size shock.** PQ public keys/ciphertexts are much larger; you blow MTUs, certificates, handshake buffers, or HSM limits.
4. **Non-rotatable keys.** You migrate algorithms but leave key lifetimes unchanged (long-lived certs/archives remain vulnerable).
5. **One-way migration.** You deploy PQ-only too early and strand old clients; hybrid is often the bridge that keeps you moving.

## Ship It

Save and reuse: `outputs/pq-migration-audit-checklist.md`.

Use it in real work:
1. Paste it into a PR review when someone touches TLS/crypto code.
2. Paste it into an incident channel when a crypto break lands (“what do we check first?”).
3. Use it as the template for a service-by-service migration ticket series.

## Exercises

1. **Easy.** Run `python3 code/main.py`. Observe: (a) which primitives are detected, (b) which KEX is selected, and (c) that the session key changes if you change the transcript messages.
2. **Medium.** Extend `CRYPTO_PATTERNS` with 3 patterns from your real stack (e.g., `Ed25519`, `JWT`, `argon2`). Re-run and confirm the inventory summary changes.
3. **Hard.** Pick a real service boundary (browser→edge, edge→API, API→DB). Write a one-page migration plan using the shipped checklist: inventory, policy, rollout, telemetry. Include at least one “downgrade alarm” you would instrument.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| PQ migration | “Switch to quantum-safe crypto” | Multi-boundary rollout: inventory + policy + staged deployment + monitoring. |
| Algorithm agility | “We can upgrade later” | Negotiation + config + telemetry that actually allows changing algorithms safely. |
| Hybrid KEX | “Use both ECDH and PQC” | Run two exchanges/KEMs and combine secrets with a KDF so either component can contribute security. |
| Transcript binding | “Include it in the hash” | Negotiated parameters influence the derived keys; different negotiation ⇒ different keys. |
| HKDF | “A hash-based KDF” | Extract (randomness extraction) then expand (key stretching with context). |

## Further Reading

- NIST, *PQC Standardization Process: Announcing Four Candidates to be Standardized* (2022) — the “what are we migrating to?” baseline.
- NIST, *NIST IR 8413: Status Report on the Third Round of the NIST PQC Standardization Process* (2022) — rationale, tradeoffs, and recommendations.
- NIST, *SP 800-56C Rev. 2: Recommendation for Key-Derivation Methods in Key-Establishment Schemes* (2020) — includes guidance for “hybrid shared secrets”.
- IETF, *RFC 9180: Hybrid Public Key Encryption (HPKE)* (2022) — a modern HKDF-based key schedule template.
- Castryck & Decru, *An Efficient Key Recovery Attack on SIDH* (2022) — why “candidate algorithms” can fail abruptly (migration must be operationally ready).
