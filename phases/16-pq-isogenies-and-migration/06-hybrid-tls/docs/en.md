# Hybrid TLS — Classical + PQ

> Hybrid key exchange: “safe if either survives,” but only if you combine secrets and bind the transcript correctly.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** Phase 8 Lesson 4 (Diffie–Hellman), Phase 16 Lesson 5 (NIST PQC Standards Tour)  
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain why PQ migration starts with hybrid TLS
- Compute HKDF-Extract / HKDF-Expand (HMAC-SHA256) from RFC vectors
- Implement a toy “classical + PQ” hybrid shared secret combiner using a KDF
- Distinguish transcript-bound key schedules from “just hash the secret”
- Apply a migration checklist to review a hybrid TLS rollout plan

## The Problem

Your TLS deployment is “secure” today because ECDHE is believed hard. But “harvest now, decrypt later” means an attacker can record today’s traffic and decrypt it in the future if a breakthrough happens (new math, better algorithms, large quantum computers).

If you flip the switch to “pure PQ” tomorrow, you take on a different risk: you are deploying brand-new cryptography at Internet scale. Even if the PQ primitive is sound, implementations, negotiation logic, and ecosystem edges can fail in surprising ways.

Hybrid TLS is the practical bridge: negotiate a classical key exchange *and* a PQ KEM in the same handshake, then combine the two shared secrets so that the final session keys stay secure as long as **at least one** of the two assumptions holds.

## The Concept

### “Either survives” is not automatic

Hybrid security is a goal, not a guarantee. You must ensure:

1. **Both secrets influence the final keys.** If your combiner can “accidentally ignore” one input (length mismatch, truncation, parsing ambiguity), you silently lose hybrid security.
2. **The transcript is bound.** Session keys must depend on what was negotiated (algorithms, parameters, identities). Otherwise, downgrade and cross-protocol attacks become easier.

### A mental model: AND-at-negotiation, OR-at-security

In a hybrid handshake you *run both* algorithms (so negotiation is an “AND”), but you *want security* if either assumption holds (an “OR”).

The usual pattern is:

| Input | Meaning |
|---|---|
| `ss_classical` | ECDHE shared secret bytes |
| `ss_pq` | KEM shared secret bytes |
| `hybrid_secret` | `HKDF( ss_classical || ss_pq )` (or similar combiner) |
| `traffic_keys` | `HKDF( hybrid_secret, transcript_hash )` |

### Why you need a KDF combiner

Even if both secrets are “good,” they may have different distributions, lengths, and edge-case behaviors. A KDF combiner:

- normalizes everything to a fixed-length key material
- provides domain separation with labels (`info`)
- gives you a single “secret” to feed into the rest of the TLS key schedule

## Build It

### Step 1: HKDF (HMAC-SHA256)
```python
import hashlib
import hmac


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def hkdf_extract_sha256(salt: bytes, ikm: bytes) -> bytes:
    if not salt:
        salt = b"\x00" * 32
    return hmac_sha256(salt, ikm)


def hkdf_expand_sha256(prk: bytes, info: bytes, length: int) -> bytes:
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


def hkdf_sha256(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    return hkdf_expand_sha256(hkdf_extract_sha256(salt, ikm), info, length)
```
HKDF is the standard way TLS turns “some shared secret bytes” into uniform key material. In hybrid settings you use it twice: once to *combine* secrets safely, and again to *derive* traffic secrets while binding to the handshake transcript.

### Step 2: Toy classical shared secret (Diffie–Hellman)
```python
def int_to_fixed_length_bytes(x: int, length: int) -> bytes:
    if x < 0:
        raise ValueError("x must be non-negative")
    if length <= 0:
        raise ValueError("length must be positive")
    return x.to_bytes(length, "big")


def dh_public_key(p: int, g: int, sk: int) -> int:
    if sk <= 0:
        raise ValueError("secret key must be positive")
    if p <= 2:
        raise ValueError("p must be > 2")
    if not (1 < g < p):
        raise ValueError("g must be in (1, p)")
    return pow(g, sk, p)


def dh_shared_secret_int(p: int, pk_other: int, sk: int) -> int:
    if sk <= 0:
        raise ValueError("secret key must be positive")
    if not (1 <= pk_other < p):
        raise ValueError("peer public key out of range")
    return pow(pk_other, sk, p)


def toy_dh_shared_secret_bytes(p: int, g: int, sk_a: int, sk_b: int, length: int) -> bytes:
    pk_a = dh_public_key(p, g, sk_a)
    pk_b = dh_public_key(p, g, sk_b)
    ss_a = dh_shared_secret_int(p, pk_b, sk_a)
    ss_b = dh_shared_secret_int(p, pk_a, sk_b)
    if ss_a != ss_b:
        raise AssertionError("DH mismatch (should never happen)")
    return int_to_fixed_length_bytes(ss_a, length)
```
Real TLS uses ECDHE, not finite-field DH like this toy. But conceptually it’s the same: both sides compute the *same* shared secret bytes without ever sending the secret itself.

### Step 3: Toy PQ shared secret (KEM encap/decap)
```python
def toy_kem_keypair_from_seed(seed: bytes) -> tuple[bytes, bytes]:
    sk = sha256(b"sk:" + seed)
    pk = sha256(b"pk:" + sk)
    return sk, pk


def toy_kem_encapsulate(pk: bytes, seed: bytes) -> tuple[bytes, bytes]:
    tag = hmac_sha256(pk, b"ct:" + seed)[:16]
    ct = tag + seed
    ss = sha256(b"ss:" + pk + seed)
    return ct, ss


def toy_kem_decapsulate(sk: bytes, ct: bytes) -> bytes:
    if len(ct) < 16:
        raise ValueError("ciphertext too short")
    pk = sha256(b"pk:" + sk)
    tag = ct[:16]
    seed = ct[16:]
    expected_tag = hmac_sha256(pk, b"ct:" + seed)[:16]
    if tag != expected_tag:
        raise ValueError("invalid ciphertext")
    return sha256(b"ss:" + pk + seed)
```
This is a deliberately insecure “KEM-shaped object” that lets you practice the plumbing: a ciphertext `ct` and a shared secret `ss_pq` that only the holder of `sk` can reproduce. In real hybrid TLS, `ss_pq` comes from a standardized KEM like ML‑KEM (Kyber).

### Step 4: Combine secrets and bind the transcript
```python
def transcript_hash_sha256(messages: list[bytes]) -> bytes:
    return sha256(b"|".join(messages))


def combine_hybrid_secret_concat_hkdf(ss_classical: bytes, ss_pq: bytes) -> bytes:
    zero_salt = b"\x00" * 32
    return hkdf_sha256(zero_salt, ss_classical + ss_pq, b"hybrid secret", 32)


def derive_tls13_like_secrets(hybrid_secret: bytes, transcript_hash: bytes) -> dict[str, bytes]:
    zero_salt = b"\x00" * 32
    handshake_secret = hkdf_sha256(zero_salt, hybrid_secret, b"handshake" + transcript_hash, 32)
    master_secret = hkdf_sha256(zero_salt, handshake_secret, b"master" + transcript_hash, 32)
    client_app_traffic = hkdf_sha256(
        zero_salt, master_secret, b"c ap traffic" + transcript_hash, 32
    )
    server_app_traffic = hkdf_sha256(
        zero_salt, master_secret, b"s ap traffic" + transcript_hash, 32
    )
    return {
        "handshake_secret": handshake_secret,
        "master_secret": master_secret,
        "client_app_traffic": client_app_traffic,
        "server_app_traffic": server_app_traffic,
    }
```
The combiner here is “concatenate then HKDF with a fixed label,” which makes the output a uniform 32-byte secret derived from *both* inputs. The transcript hash then ensures you get different traffic keys if the negotiated parameters change (the whole point of preventing downgrade and cross-protocol confusion).

Run it:

`python3 code/main.py`

## Use It

In production you do not write TLS by hand. You configure and verify a library implementation:

| Goal | Where it shows up |
|---|---|
| Hybrid key exchange (ECDHE + KEM) | TLS 1.3 key_share extension with additional KEM share |
| KEM implementations | `liboqs` / OpenSSL provider ecosystems; PQ-capable forks for experimentation |
| Safer rollout patterns | canary %, dual-stack endpoints, telemetry, abort/rollback paths |

If you need to integrate PQ KEMs today, treat it as *crypto agility engineering*: configuration knobs, negotiation policy, observability, and tight error handling matter as much as math.

## Pitfalls

1. **No transcript binding.** If derived keys ignore what was negotiated, downgrade attacks become much easier.
2. **Ambiguous combining.** “Just concatenate” without a KDF can lead to parsing/encoding mistakes (variable lengths, missing domain separation).
3. **Silent fallback on KEM failure.** If decapsulation fails and you continue with `ss_pq = 0...0`, you’ve turned hybrid into “classical only” without noticing.
4. **Mismatched ordering across implementations.** `HKDF(ss_classical || ss_pq)` is not the same as `HKDF(ss_pq || ss_classical)`.
5. **Treating hybrid as a one-time switch.** Real rollouts require capability signaling, version pinning, monitoring, and rollback plans.

## Ship It

This lesson ships a reusable review artifact:

- `outputs/hybrid-tls-migration-checklist.md`

Use it as a PR-review checklist or a design-review prompt when:

- adding PQ/hybrid ciphers/groups to a TLS termination stack
- rolling out hybrid TLS behind a load balancer / service mesh
- documenting crypto agility requirements for teams

## Exercises

1. Easy: Run `python3 code/main.py`. Observe that `ss_pq(encap) == ss_pq(decap)` and that the transcript hash changes derived secrets.
2. Medium: Add a second combiner `combine_hybrid_secret_xor_hkdf(ss_classical, ss_pq)` that XORs equal-length inputs then runs HKDF. Compare outputs and list pros/cons.
3. Hard: Write a “downgrade simulation”: compute secrets using two different transcript hashes (one that omits the PQ negotiation) and explain how transcript binding prevents confusing the two handshakes.

## Key Terms

| Term | What people say | What it actually means |
|---|---|---|
| Hybrid TLS | “TLS but PQ” | A handshake that runs classical + PQ key exchange and combines secrets via a KDF |
| KEM | “Public-key encryption replacement” | An API that outputs `(ciphertext, shared_secret)` and supports deterministic decapsulation |
| Transcript hash | “Hash of handshake messages” | The binding that makes keys depend on what was negotiated and authenticated |
| HKDF | “A hash” | A KDF (HMAC-based) that extracts and expands key material with salt/info labels |
| Crypto agility | “Just swap algorithms” | Engineering capability: negotiate, deploy, measure, and rollback cryptography safely |

## Further Reading

- Krawczyk, “HKDF: Extract-and-Expand Key Derivation Function” (RFC 5869, 2010) — HKDF definition and test vectors used in this lesson.
- Rescorla, “The Transport Layer Security (TLS) Protocol Version 1.3” (RFC 8446, 2018) — the real key schedule and transcript binding model this lesson imitates.
