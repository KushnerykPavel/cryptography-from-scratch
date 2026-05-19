# OPAQUE — Asymmetric PAKE (Educational)
> **The server stores an envelope it can’t open; the client proves the password without sending it.**

**Type:** Build  
**Languages:** Python  
**Prerequisites:**  
- `phases/07-symmetric-crypto/12-hmac` (MAC mindset + constant-time compare)  
- `phases/07-symmetric-crypto/13-kdfs` (HKDF labels + key separation)  
- `phases/08-classical-asymmetric/04-diffie-hellman` (DH groups + validation)  
- `phases/10-protocols/04-signal-x3dh-double-ratchet` (3DH intuition + transcript binding)  
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** why OPAQUE avoids sending passwords (even during registration)
- **Compute** a DH-style OPRF flow: blind → evaluate → finalize
- **Implement** Store/Recover to derive client key material from a hardened password
- **Distinguish** “server-stored envelope” from “server-stored password hash”
- **Apply** a checklist to review real OPAQUE integrations (validation, stretching, enumeration defenses)

## The Problem

In the classic “username + password” model, the server must store *something* that lets it verify logins. If that “something” is a salted password hash, then a database leak becomes an **offline dictionary attack**: the attacker can try password guesses locally until one matches the stored verifier.

PAKEs aim to fix this by letting the client prove knowledge of the password *without* revealing it. But many PAKEs still require the server to store a password-derived verifier that can be checked offline if stolen, or they require both sides to know the password (not acceptable for a real client/server system).

OPAQUE (an **augmented PAKE**) gives you a practical client/server story: the server holds a secret OPRF key (like a “pepper”) and stores an **opaque envelope** per user. If the database leaks, the attacker still has to do expensive guessing, and they can’t just replay a verifier. On successful login, the client and server also get a fresh **session key** for a secure channel.

## The Concept

OPAQUE is easiest to see as three parts that compose:

| Part | What it does | Why it matters |
|---|---|---|
| OPRF | Client inputs password; server inputs secret key; client learns `oprf_output` | Server never sees the raw password, but the output is consistent per password and server key |
| Key recovery (Envelope) | Client derives deterministic AKE key material from `randomized_password` and an envelope nonce | Server stores a blob it cannot use to impersonate the client |
| AKE (3DH-style) | Both sides mix static + ephemeral DH results plus transcript binding | You get mutual authentication + a session key (and forward secrecy from ephemerals) |

Two mental models help:

1) **“Server secret salt” without trusting the server with your password.**  
The OPRF key plays a role similar to a salt/pepper that’s unknown to attackers who only steal the database.

2) **Envelope = “locked box of key material”.**  
The server stores `(envelope_nonce, auth_tag)` plus a client public key. The client can only “open” (verify/recover) it if it recomputes the same `randomized_password` from the correct password *and* the server’s OPRF evaluation.

This lesson implements a toy OPAQUE-style flow in a prime-order subgroup using stdlib only. It’s meant to teach wiring, not to be deployed.

## Build It

### Step 1: Prime-order group + encoding helpers
We need a group where “DH-like” operations make sense and where we can validate received elements. For this educational build we use the quadratic-residue subgroup of the RFC 3526 2048-bit MODP prime (a prime-order subgroup), plus a simple `hash_to_group()` that maps a password to a group element.

```python
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import secrets


HASHLEN = 32
Nh = 32
Nm = 32
Nn = 32
Nseed = 32

PBKDF2_ITERS = 6000


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def parse_hex_int(text: str) -> int:
    cleaned = "".join(ch for ch in text if ch.strip()).replace("0x", "").replace("0X", "")
    if not cleaned:
        raise ValueError("empty hex string")
    return int(cleaned, 16)


def modexp(base: int, exponent: int, modulus: int) -> int:
    if modulus <= 0:
        raise ValueError("modulus must be positive")
    if exponent < 0:
        raise ValueError("exponent must be non-negative")

    base %= modulus
    result = 1
    e = exponent
    while e:
        if e & 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        e >>= 1
    return result


def egcd(a: int, b: int) -> tuple[int, int, int]:
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)


def modinv(a: int, modulus: int) -> int:
    a %= modulus
    if a == 0:
        raise ValueError("inverse does not exist")
    g, x, _ = egcd(a, modulus)
    if g != 1:
        raise ValueError("inverse does not exist")
    return x % modulus


def int_to_bytes(value: int, length: int | None = None) -> bytes:
    if value < 0:
        raise ValueError("value must be non-negative")
    if length is None:
        length = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(length, "big")


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))


def hkdf_extract_sha256(salt: bytes | None, ikm: bytes) -> bytes:
    if salt is None:
        salt = b"\x00" * HASHLEN
    return hmac_sha256(salt, ikm)


def hkdf_expand_sha256(prk: bytes, info: bytes, length: int) -> bytes:
    if len(prk) != HASHLEN:
        raise ValueError("prk must be 32 bytes")
    if length < 0:
        raise ValueError("length must be non-negative")
    if length > 255 * HASHLEN:
        raise ValueError("length too large")

    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac_sha256(prk, t + info + bytes([counter]))
        out += t
        counter += 1
    return out[:length]


def i2osp_u16(n: int) -> bytes:
    if not (0 <= n <= 0xFFFF):
        raise ValueError("u16 out of range")
    return n.to_bytes(2, "big")


def encode_len_prefixed(data: bytes) -> bytes:
    return i2osp_u16(len(data)) + data


@dataclass(frozen=True)
class PrimeOrderGroup:
    name: str
    p: int
    q: int
    g: int

    @property
    def byte_len(self) -> int:
        return (self.p.bit_length() + 7) // 8

    def serialize_elem(self, x: int) -> bytes:
        return int_to_bytes(x, self.byte_len)

    def validate_elem(self, x: int) -> None:
        if not (2 <= x <= self.p - 2):
            raise ValueError("element out of range")
        if modexp(x, self.q, self.p) != 1:
            raise ValueError("element not in subgroup")


RFC3526_GROUP14_P_HEX = """
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
"""


def rfc3526_group14_subgroup_qr() -> PrimeOrderGroup:
    p = parse_hex_int(RFC3526_GROUP14_P_HEX)
    q = (p - 1) // 2
    g = modexp(2, 2, p)
    group = PrimeOrderGroup(name="RFC3526 group14 QR subgroup", p=p, q=q, g=g)
    group.validate_elem(group.g)
    return group


def hash_to_scalar(password: bytes, group: PrimeOrderGroup) -> int:
    digest = sha256(b"cryptography-from-scratch:OPAQUE:HashToScalar:" + password)
    x = int.from_bytes(digest, "big") % group.q
    if x == 0:
        x = 1
    return x


def hash_to_group(password: bytes, group: PrimeOrderGroup) -> int:
    x = hash_to_scalar(password, group)
    elem = modexp(group.g, x, group.p)
    if elem == 1:
        raise ValueError("hash_to_group mapped to identity")
    return elem
```

This gives us: (a) DH arithmetic via exponentiation, (b) element validation (subgroup membership), and (c) a stable mapping from a password to a group element.

### Step 2: OPRF (blind → evaluate → finalize) + password hardening
The OPRF lets the client learn `oprf_output = F_k(password)` without revealing the password to the server. The client blinds the password-derived element, the server exponentiates with its secret `oprf_key`, and the client unblinds and hashes the result. We then run a slow-ish stretching step (PBKDF2 here for stdlib portability) and derive a 32-byte `randomized_password`.

```python
def oprf_blind(password: bytes, blind: int, group: PrimeOrderGroup) -> int:
    blind %= group.q
    if blind == 0:
        raise ValueError("blind must be non-zero")
    _ = modinv(blind, group.q)
    input_elem = hash_to_group(password, group)
    blinded = modexp(input_elem, blind, group.p)
    group.validate_elem(blinded)
    return blinded


def oprf_evaluate(blinded_element: int, oprf_key: int, group: PrimeOrderGroup) -> int:
    oprf_key %= group.q
    if oprf_key == 0:
        raise ValueError("oprf_key must be non-zero")
    group.validate_elem(blinded_element)
    evaluated = modexp(blinded_element, oprf_key, group.p)
    group.validate_elem(evaluated)
    return evaluated


def oprf_finalize(password: bytes, blind: int, evaluated_element: int, group: PrimeOrderGroup) -> bytes:
    group.validate_elem(evaluated_element)
    inv = modinv(blind, group.q)
    unblinded = modexp(evaluated_element, inv, group.p)
    group.validate_elem(unblinded)

    unblinded_bytes = group.serialize_elem(unblinded)
    hash_input = (
        encode_len_prefixed(password)
        + encode_len_prefixed(unblinded_bytes)
        + b"Finalize"
    )
    return sha256(hash_input)


def stretch_password(oprf_output: bytes, *, iters: int = PBKDF2_ITERS) -> bytes:
    if iters <= 0:
        raise ValueError("iters must be positive")
    stretched = hashlib.pbkdf2_hmac("sha256", oprf_output, b"cryptography-from-scratch:OPAQUE:Stretch", iters, dklen=Nh)
    prk = hkdf_extract_sha256(b"", oprf_output + stretched)
    return hkdf_expand_sha256(prk, b"cryptography-from-scratch:OPAQUE:RandomizedPassword", Nh)
```

In real deployments you typically use a memory-hard function like Argon2id for the stretching step and a proper hash-to-group for `HashToGroup`.

### Step 3: Store/Recover the envelope (client key recovery)
During registration, the client derives a deterministic “client static keypair” from `randomized_password` and an `envelope_nonce`, and then stores an `Envelope` on the server that authenticates the cleartext credentials. During login, the client recomputes the same keys and verifies the envelope tag; if the password is wrong, recovery fails.

```python
def derive_dh_keypair_from_seed(seed: bytes, group: PrimeOrderGroup) -> tuple[int, int]:
    if len(seed) != Nseed:
        raise ValueError("seed must be 32 bytes")
    sk = int.from_bytes(sha256(b"cryptography-from-scratch:OPAQUE:DHKeyPair:" + seed), "big") % group.q
    if sk == 0:
        sk = 1
    pk = modexp(group.g, sk, group.p)
    group.validate_elem(pk)
    return sk, pk


def encode_cleartext_credentials(
    *,
    server_public_key: int,
    client_public_key: int,
    server_identity: bytes,
    client_identity: bytes,
    group: PrimeOrderGroup,
) -> bytes:
    spk = group.serialize_elem(server_public_key)
    cpk = group.serialize_elem(client_public_key)
    return (
        b"OPAQUE-CredentialsV1"
        + encode_len_prefixed(server_identity)
        + encode_len_prefixed(client_identity)
        + encode_len_prefixed(spk)
        + encode_len_prefixed(cpk)
    )


@dataclass(frozen=True)
class Envelope:
    nonce: bytes
    auth_tag: bytes

    def to_bytes(self) -> bytes:
        if len(self.nonce) != Nn:
            raise ValueError("bad envelope nonce length")
        if len(self.auth_tag) != Nm:
            raise ValueError("bad envelope auth_tag length")
        return self.nonce + self.auth_tag

    @staticmethod
    def from_bytes(data: bytes) -> "Envelope":
        if len(data) != Nn + Nm:
            raise ValueError("bad envelope length")
        return Envelope(nonce=data[:Nn], auth_tag=data[Nn:])


def store_envelope(
    *,
    randomized_password: bytes,
    server_public_key: int,
    server_identity: bytes,
    client_identity: bytes,
    envelope_nonce: bytes,
    group: PrimeOrderGroup,
) -> tuple[Envelope, int, bytes, bytes]:
    if len(randomized_password) != Nh:
        raise ValueError("randomized_password must be 32 bytes")
    if len(envelope_nonce) != Nn:
        raise ValueError("envelope_nonce must be 32 bytes")
    group.validate_elem(server_public_key)

    masking_key = hkdf_expand_sha256(randomized_password, b"MaskingKey", Nh)
    auth_key = hkdf_expand_sha256(randomized_password, envelope_nonce + b"AuthKey", Nh)
    export_key = hkdf_expand_sha256(randomized_password, envelope_nonce + b"ExportKey", Nh)
    seed = hkdf_expand_sha256(randomized_password, envelope_nonce + b"PrivateKey", Nseed)

    _, client_public_key = derive_dh_keypair_from_seed(seed, group)
    cleartext = encode_cleartext_credentials(
        server_public_key=server_public_key,
        client_public_key=client_public_key,
        server_identity=server_identity,
        client_identity=client_identity,
        group=group,
    )
    auth_tag = hmac_sha256(auth_key, envelope_nonce + cleartext)
    envelope = Envelope(nonce=envelope_nonce, auth_tag=auth_tag)
    return envelope, client_public_key, masking_key, export_key


def recover_envelope(
    *,
    randomized_password: bytes,
    server_public_key: int,
    envelope: Envelope,
    server_identity: bytes,
    client_identity: bytes,
    group: PrimeOrderGroup,
) -> tuple[int, bytes, bytes]:
    if len(randomized_password) != Nh:
        raise ValueError("randomized_password must be 32 bytes")
    group.validate_elem(server_public_key)
    if len(envelope.nonce) != Nn:
        raise ValueError("envelope nonce length")
    if len(envelope.auth_tag) != Nm:
        raise ValueError("envelope auth_tag length")

    auth_key = hkdf_expand_sha256(randomized_password, envelope.nonce + b"AuthKey", Nh)
    export_key = hkdf_expand_sha256(randomized_password, envelope.nonce + b"ExportKey", Nh)
    seed = hkdf_expand_sha256(randomized_password, envelope.nonce + b"PrivateKey", Nseed)
    client_private_key, client_public_key = derive_dh_keypair_from_seed(seed, group)

    cleartext = encode_cleartext_credentials(
        server_public_key=server_public_key,
        client_public_key=client_public_key,
        server_identity=server_identity,
        client_identity=client_identity,
        group=group,
    )
    expected_tag = hmac_sha256(auth_key, envelope.nonce + cleartext)
    if not hmac.compare_digest(envelope.auth_tag, expected_tag):
        raise ValueError("EnvelopeRecoveryError")
    return client_private_key, cleartext, export_key
```

The key idea: the server stores an envelope, but only a client who can recompute `randomized_password` can pass the MAC check and recover its AKE key material.

### Step 4: Toy OPAQUE-3DH AKE (KE1 / KE2 / KE3)
Now we combine the pieces into an authenticated key exchange: the client sends `KE1` (blinded password + an ephemeral keyshare), the server responds with `KE2` (OPRF evaluation + masked envelope + server ephemeral keyshare + server MAC), and the client finishes with `KE3` (client MAC). Both sides derive the same session key only if the password is correct and both MACs verify.

```python
@dataclass(frozen=True)
class RegistrationRecord:
    client_public_key: int
    masking_key: bytes
    envelope: Envelope


@dataclass(frozen=True)
class CredentialRequest:
    blinded_message: int


@dataclass(frozen=True)
class CredentialResponse:
    evaluated_message: int
    masking_nonce: bytes
    masked_response: bytes


@dataclass(frozen=True)
class AuthRequest:
    client_nonce: bytes
    client_public_keyshare: int


@dataclass(frozen=True)
class AuthResponse:
    server_nonce: bytes
    server_public_keyshare: int
    server_mac: bytes


@dataclass(frozen=True)
class KE1:
    credential_request: CredentialRequest
    auth_request: AuthRequest


@dataclass(frozen=True)
class KE2:
    credential_response: CredentialResponse
    auth_response: AuthResponse


@dataclass(frozen=True)
class KE3:
    client_mac: bytes


def serialize_ke1(ke1: KE1, group: PrimeOrderGroup) -> bytes:
    return (
        group.serialize_elem(ke1.credential_request.blinded_message)
        + ke1.auth_request.client_nonce
        + group.serialize_elem(ke1.auth_request.client_public_keyshare)
    )


def serialize_credential_response(cr: CredentialResponse, group: PrimeOrderGroup) -> bytes:
    return group.serialize_elem(cr.evaluated_message) + cr.masking_nonce + cr.masked_response


def preamble(
    *,
    client_identity: bytes,
    ke1: KE1,
    server_identity: bytes,
    credential_response: CredentialResponse,
    server_nonce: bytes,
    server_public_keyshare: int,
    group: PrimeOrderGroup,
    context: bytes = b"",
) -> bytes:
    if len(server_nonce) != Nn:
        raise ValueError("server_nonce must be 32 bytes")
    return (
        b"OPAQUEv1-"
        + encode_len_prefixed(context)
        + encode_len_prefixed(client_identity)
        + serialize_ke1(ke1, group)
        + encode_len_prefixed(server_identity)
        + serialize_credential_response(credential_response, group)
        + server_nonce
        + group.serialize_elem(server_public_keyshare)
    )


def dh_shared_secret_bytes(*, sk: int, pk: int, group: PrimeOrderGroup) -> bytes:
    if not (1 <= sk < group.q):
        raise ValueError("bad DH scalar")
    group.validate_elem(pk)
    shared = modexp(pk, sk, group.p)
    group.validate_elem(shared)
    return group.serialize_elem(shared)


def derive_ake_keys(*, ikm: bytes, preamble_bytes: bytes) -> tuple[bytes, bytes, bytes]:
    prk = hkdf_extract_sha256(b"", ikm)
    transcript_hash = sha256(preamble_bytes)
    handshake_secret = hkdf_expand_sha256(prk, b"HandshakeSecret|" + transcript_hash, HASHLEN)
    session_key = hkdf_expand_sha256(prk, b"SessionKey|" + transcript_hash, HASHLEN)
    km2 = hkdf_expand_sha256(handshake_secret, b"ServerMAC", HASHLEN)
    km3 = hkdf_expand_sha256(handshake_secret, b"ClientMAC", HASHLEN)
    return km2, km3, session_key


@dataclass
class ClientAkeState:
    password: bytes
    blind: int
    client_identity: bytes
    client_nonce: bytes
    client_secret: int
    ke1: KE1


@dataclass
class ServerAkeState:
    expected_client_mac: bytes
    session_key: bytes


def client_start(
    *,
    password: bytes,
    client_identity: bytes,
    blind: int,
    client_nonce: bytes,
    client_keyshare_seed: bytes,
    group: PrimeOrderGroup,
) -> ClientAkeState:
    if len(client_nonce) != Nn:
        raise ValueError("client_nonce must be 32 bytes")
    blinded_message = oprf_blind(password, blind, group)
    credential_request = CredentialRequest(blinded_message=blinded_message)
    client_secret, client_public_keyshare = derive_dh_keypair_from_seed(client_keyshare_seed, group)
    auth_request = AuthRequest(client_nonce=client_nonce, client_public_keyshare=client_public_keyshare)
    ke1 = KE1(credential_request=credential_request, auth_request=auth_request)
    return ClientAkeState(
        password=password,
        blind=blind,
        client_identity=client_identity,
        client_nonce=client_nonce,
        client_secret=client_secret,
        ke1=ke1,
    )
```

This step is completed in `code/main.py` by wiring the full KE1/KE2/KE3 flow and printing the resulting session key (and showing that a wrong password fails during envelope recovery).

Run it:
`python3 code/main.py`

## Use It

Production-grade OPAQUE implementations exist, and you should prefer them over rolling your own:

- **Rust:** `opaque-ke` (RFC 9807-based)
- **C:** `libopaque` (e.g. used by projects in the ecosystem)
- **Go:** several RFC 9807 implementations (check maintenance + audits)
- **JavaScript:** OPAQUE client/server libraries exist, but treat them as security-critical code and look for audits

When evaluating a library, look for:
- strict element parsing + subgroup checks
- memory-hard stretching (Argon2id) with good parameters
- constant-time comparisons
- client-enumeration defenses (fake records + masked responses)
- test vectors and interop tests against the RFC

## Pitfalls

1. **Skipping group-element validation.** If you don’t check subgroup membership, you can get invalid-curve/small-subgroup style breaks.
2. **Using a “hash-to-group” that isn’t a real hash-to-curve/group.** A toy map is fine for learning, not for security.
3. **Weak or misconfigured stretching.** Too few iterations (or no memory-hard KSF) makes offline guessing cheap after compromise.
4. **Leaking existence of users.** If the server replies differently for missing accounts (timing, error messages, structure), you reintroduce enumeration risk.
5. **Not binding identities/transcripts.** If you don’t MAC the correct transcript (`preamble`), you risk message splicing and unknown-key-share bugs.

## Ship It

This lesson ships a reusable review artifact: `outputs/opaque-review-checklist.md`.

Use it to review a PR/design that claims “OPAQUE login”:
- paste the checklist into a review comment
- check group validation, stretching, envelope handling, and transcript/MAC wiring
- verify the implementation can’t be used as “password oracle” (enumeration/timing)

## Exercises

1. Easy. Run `python3 code/main.py`. Observe that the session keys match, and that a wrong password is rejected with `EnvelopeRecoveryError`.
2. Medium. Extend `code/main.py` to run the same login flow twice with fresh client/server *ephemeral* seeds, and confirm the session key changes each time (forward secrecy intuition).
3. Hard. Replace the PBKDF2-based `stretch_password()` with a *memory-hard* KSF (Argon2id or scrypt) in a separate branch, and write down how you would choose parameters for a mobile client vs a backend service.

## Key Terms

| Term | What people say | What it actually means |
|---|---|---|
| PAKE | “password key exchange” | A protocol to authenticate with a password and derive a shared key without revealing the password |
| aPAKE | “client/server PAKE” | A PAKE where the server can store a verifier and still can’t impersonate the client after DB compromise |
| OPRF | “oblivious PRF” | A two-party protocol: server holds key `k`, client holds input `x`, client learns `F_k(x)` without revealing `x` |
| Envelope | “encrypted blob on the server” | Server-stored data authenticated under keys derived from the hardened password; the server can’t use it to log in |
| `export_key` | “extra key” | A stable client-only key you can use after authentication for app-specific encryption or key derivation |

## Further Reading

- Bourdrez et al., **RFC 9807: The OPAQUE Augmented Password-Authenticated Key Exchange (aPAKE) Protocol** (2025) — The standardized OPAQUE protocol and a 3DH instantiation.
- CFRG, **RFC 9497: Oblivious Pseudorandom Functions (OPRFs) Using Prime-Order Groups** (2023) — OPRF protocol details, API shapes, and finalize inputs.
- Jarecki et al., **OPAQUE: An Asymmetric PAKE Protocol** (Eurocrypt 2018) — The underlying design and security analysis.
