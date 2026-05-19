# Key Encapsulation vs Key Agreement

> Key agreement is a conversation; a KEM is a package: ciphertext in, shared key out.

**Type:** Learn
**Languages:** Python
**Prerequisites:** `phases/08-classical-asymmetric/04-diffie-hellman`, `phases/08-classical-asymmetric/10-x25519`
**Time:** ~45 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain why protocols still need authentication even if they “have a shared key”
- Distinguish key agreement APIs from KEM APIs (who sends what, when)
- Implement a toy DH key agreement and a DH-based KEM wrapper (Encaps/Decaps)
- Apply transcript/context binding so the same DH value can’t be reused across protocols
- Compute and compare derived session keys for KA, KEM, and a hybrid mix

## The Problem

You’re reviewing a PR that “adds post-quantum” to a handshake. The author says: “We replaced ECDH with ML‑KEM, everything still works.” But the new flow has different message shapes, different failure cases, and a different API surface (Encaps/Decaps instead of “compute shared secret”). If you don’t understand **KEM vs key agreement**, it’s easy to approve code that looks plausible yet subtly breaks security properties like context binding, downgrade resistance, or (worst) authentication.

This confusion shows up in real systems:

- TLS 1.3 uses (EC)DHE key agreement and then derives multiple traffic keys via HKDF. Post-quantum migration introduces KEMs and “hybrid” handshakes, which mix secrets from more than one algorithm.
- HPKE (Hybrid Public Key Encryption) is explicitly **KEM + KDF + AEAD**. If you think “KEM = encryption”, you’ll misuse it.

This lesson gives you a clean mental model and a runnable toy implementation that makes the interface differences concrete.

## The Concept

Both patterns aim for the same end state: both parties obtain the same *shared secret* (or derived session keys). The difference is **how the protocol is shaped**.

### Two interface shapes

| Property | Key agreement (KA) | Key encapsulation (KEM) |
|---|---|---|
| Core idea | Two parties exchange public values and “meet in the middle” | Sender creates a ciphertext that “encapsulates” key material for the receiver |
| Minimal message flow | Usually 2 messages (A→B: pkA, B→A: pkB) | 1 message (A→B: ct) if pkB is already known |
| Primitive API shape | `shared = Agree(skA, pkB)` and `shared = Agree(skB, pkA)` | `(ct, ss) = Encaps(pkB)` and `ss = Decaps(skB, ct)` |
| Where it shows up | TLS (EC)DHE, Noise, Signal-style handshakes | HPKE, post-quantum KEMs (e.g., ML‑KEM), KEM-based hybrids |
| What it does *not* give you | Authentication | Authentication |

### A practical mental model

- **Key agreement is a conversation.** It naturally fits interactive handshakes: both sides contribute ephemeral keys, then both derive secrets.
- **A KEM is a package.** The sender uses the receiver’s public key, produces a ciphertext `ct` (the “package”), and both sides derive the same shared secret `ss`.

Important: KEM and KA are not enemies. You can often build a KEM-like flow *from* key agreement by making the receiver’s public key “known ahead of time” (published/static), and having the sender send only an ephemeral public key as the ciphertext/encapsulation.

### Context binding (the thing that prevents “key reuse bugs”)

Even if two runs produce the same underlying mathematical DH value, you should not treat it as “the session key”. Real protocols feed shared secrets into a KDF with:

- **labels / suite IDs** (domain separation),
- **transcript hashes** (bind to what was negotiated),
- and **application info** (bind to which protocol / purpose).

We’ll implement that binding with HKDF-SHA256 and a simple transcript hash helper.

## Build It

### Step 1: HKDF-SHA256 + transcript hashing

This step gives you two tools we’ll reuse throughout:

- HKDF-SHA256 to turn “weird” shared secrets into uniformly-sized session keys.
- A transcript hash to bind derived keys to specific message flows / context.

```python
def u32be(value: int) -> bytes:
    if not (0 <= value <= 0xFFFFFFFF):
        raise ValueError("value out of range for u32")
    return value.to_bytes(4, "big")


def encode_length_prefixed(parts: Iterable[bytes]) -> bytes:
    out = b""
    for p in parts:
        out += u32be(len(p)) + p
    return out


def transcript_hash(parts: Iterable[bytes]) -> bytes:
    return hashlib.sha256(encode_length_prefixed(parts)).digest()


def hkdf_sha256(*, ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    if length <= 0:
        raise ValueError("length must be positive")

    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
        if counter > 255:
            raise ValueError("length too large for HKDF")
    return okm[:length]
```

### Step 2: 2-message DH key agreement (derive a session key)

Key agreement gives both parties the same DH value `Z`. But the protocol needs a *session key*, so we bind `Z` to a transcript and run it through HKDF.

```python
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


def i2osp(value: int, length: int) -> bytes:
    if value < 0:
        raise ValueError("value must be non-negative")
    if length <= 0:
        raise ValueError("length must be positive")
    return value.to_bytes(length, "big")


def os2ip(data: bytes) -> int:
    return int.from_bytes(data, "big")


@dataclass(frozen=True)
class DHGroup:
    name: str
    p: int
    g: int

    def __post_init__(self) -> None:
        if self.p <= 2:
            raise ValueError("p must be > 2")
        if not (2 <= self.g <= self.p - 2):
            raise ValueError("g must be in [2, p-2]")

    @property
    def element_bytes(self) -> int:
        return max(1, (self.p.bit_length() + 7) // 8)


TOY_GROUP = DHGroup(name="toy (p=23, g=5)", p=23, g=5)


def dh_public_key(*, group: DHGroup, private_key: int) -> int:
    if not (2 <= private_key <= group.p - 2):
        raise ValueError("private key out of range")
    return modexp(group.g, private_key, group.p)


def validate_dh_public_key(*, group: DHGroup, public_key: int) -> None:
    if not (2 <= public_key <= group.p - 2):
        raise ValueError("public key out of range")


def dh_shared_secret(*, group: DHGroup, private_key: int, peer_public_key: int) -> int:
    validate_dh_public_key(group=group, public_key=peer_public_key)
    if not (2 <= private_key <= group.p - 2):
        raise ValueError("private key out of range")
    return modexp(peer_public_key, private_key, group.p)


def serialize_group_element(*, group: DHGroup, element: int) -> bytes:
    if not (0 <= element < group.p):
        raise ValueError("element out of range")
    return i2osp(element, group.element_bytes)


def derive_session_key_from_dh(
    *,
    group: DHGroup,
    dh_shared: int,
    context: bytes,
    length: int = 32,
) -> bytes:
    dh_bytes = serialize_group_element(group=group, element=dh_shared)
    salt = hashlib.sha256(b"cryptography-from-scratch:dh").digest()
    return hkdf_sha256(ikm=dh_bytes, salt=salt, info=context, length=length)


def ka_2msg_session_key(
    *,
    group: DHGroup,
    alice_private: int,
    bob_private: int,
    info: bytes,
    length: int = 32,
) -> tuple[bytes, bytes, bytes]:
    alice_public = dh_public_key(group=group, private_key=alice_private)
    bob_public = dh_public_key(group=group, private_key=bob_private)

    transcript = transcript_hash(
        [
            b"KA-2msg",
            serialize_group_element(group=group, element=alice_public),
            serialize_group_element(group=group, element=bob_public),
            info,
        ]
    )

    z_ab = dh_shared_secret(group=group, private_key=alice_private, peer_public_key=bob_public)
    z_ba = dh_shared_secret(group=group, private_key=bob_private, peer_public_key=alice_public)
    if z_ab != z_ba:
        raise RuntimeError("key agreement did not match (should never happen)")

    context = encode_length_prefixed([b"KA", transcript])
    key_a = derive_session_key_from_dh(group=group, dh_shared=z_ab, context=context, length=length)
    key_b = derive_session_key_from_dh(group=group, dh_shared=z_ba, context=context, length=length)
    return key_a, key_b, transcript
```

### Step 3: A KEM view of DH (Encaps/Decaps API)

A KEM exposes a different interface: the sender runs `Encaps(pkR)` and sends a ciphertext `enc`; the receiver runs `Decaps(skR, enc)` and gets the same shared secret.

In DH-based KEMs, the “ciphertext” is often just the sender’s ephemeral public key, plus a KDF that binds context (suite id, identities, info).

```python
def deserialize_group_element(*, group: DHGroup, data: bytes) -> int:
    if len(data) != group.element_bytes:
        raise ValueError("wrong element length")
    x = os2ip(data)
    if not (0 <= x < group.p):
        raise ValueError("element out of range")
    return x


def dhkem_encap(
    *,
    group: DHGroup,
    recipient_public_key: int,
    sender_ephemeral_private: int,
    info: bytes,
    length: int = 32,
    suite_id: bytes = b"DHKEM-TOY-HKDF-SHA256",
) -> tuple[bytes, bytes]:
    validate_dh_public_key(group=group, public_key=recipient_public_key)
    sender_ephemeral_public = dh_public_key(group=group, private_key=sender_ephemeral_private)
    enc = serialize_group_element(group=group, element=sender_ephemeral_public)
    dh = dh_shared_secret(
        group=group, private_key=sender_ephemeral_private, peer_public_key=recipient_public_key
    )

    pk_r = serialize_group_element(group=group, element=recipient_public_key)
    kem_context = encode_length_prefixed([b"KEM", suite_id, enc, pk_r, info])
    shared = derive_session_key_from_dh(group=group, dh_shared=dh, context=kem_context, length=length)
    return enc, shared


def dhkem_decap(
    *,
    group: DHGroup,
    recipient_private_key: int,
    enc: bytes,
    info: bytes,
    length: int = 32,
    suite_id: bytes = b"DHKEM-TOY-HKDF-SHA256",
) -> bytes:
    pk_e = deserialize_group_element(group=group, data=enc)
    validate_dh_public_key(group=group, public_key=pk_e)
    pk_r = dh_public_key(group=group, private_key=recipient_private_key)
    dh = dh_shared_secret(group=group, private_key=recipient_private_key, peer_public_key=pk_e)

    pk_r_bytes = serialize_group_element(group=group, element=pk_r)
    kem_context = encode_length_prefixed([b"KEM", suite_id, enc, pk_r_bytes, info])
    return derive_session_key_from_dh(group=group, dh_shared=dh, context=kem_context, length=length)
```

### Step 4: Hybrid mixing (combine multiple secrets safely)

Hybrid handshakes commonly compute more than one “shared secret” (e.g., classical + post-quantum) and then mix them into a single session key schedule. You should not just XOR raw outputs together unless the protocol says so; use a KDF with clear context.

```python
def mix_secrets(*, secrets_list: Iterable[bytes], context: bytes, length: int = 32) -> bytes:
    joined = encode_length_prefixed(secrets_list)
    salt = hashlib.sha256(b"cryptography-from-scratch:mix").digest()
    return hkdf_sha256(ikm=joined, salt=salt, info=context, length=length)
```

Run it:
```bash
python3 code/main.py
```

## Use It

Production systems expose both patterns:

- **Key agreement APIs:** libsodium `crypto_kx_*` style APIs derive client/server TX/RX keys from two keypairs; TLS 1.3 uses (EC)DHE shared secrets and an HKDF-based key schedule.
- **KEM APIs:** OpenSSL 3 has `EVP_PKEY_encapsulate()` / `EVP_PKEY_decapsulate()` for KEM algorithms; HPKE standardizes KEM + KDF + AEAD.

As a reviewer, look for the primitive boundary:

- If you see `Encaps(pk)->(ct, ss)` / `Decaps(sk, ct)->ss`, you’re in **KEM land**.
- If you see `Agree(sk, pk)->Z` on *both* sides, you’re in **key agreement land** (or a KEM constructed from DH).

## Pitfalls

1. **Treating the DH/KEM output as “the key”.** Always run the shared secret through a KDF with protocol-specific `info` and labels.
2. **No transcript binding.** If the derived key doesn’t commit to the negotiated parameters/messages, you can get “unknown key share” / cross-protocol confusion bugs.
3. **Assuming KEM implies authentication.** It doesn’t. You still need signatures, certificates, PSKs, or an authenticated channel.
4. **Mixing hybrid secrets ad hoc.** Use an explicit KDF construction; don’t invent concatenation/XOR rules in a vacuum.
5. **Skipping input validation / edge-case checks.** In real DH/X25519 you need group checks (or explicit all-zero shared-secret checks) and robust decoding rules.

## Ship It

Save the decision + review checklist to `outputs/kem-vs-key-agreement-decision-guide.md` and use it when:

- reviewing a handshake PR (TLS/Noise/Signal-like),
- integrating HPKE,
- or evaluating a post-quantum/hybrid migration design.

Treat it as a “PR review template”: paste it into your review and answer each question.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe that Step 2 (KA) and Step 3 (KEM) both “agree” but produce different derived keys due to different context binding.
2. Medium. Change the `info=` inputs in Step 2 or Step 3 and confirm the derived keys change even when the underlying DH shared secret stays the same.
3. Hard. Extend the demo to output *two* traffic keys (client→server and server→client) by using different `info` labels (e.g., `b"tx"` vs `b"rx"`), and explain why direction separation matters.

## Key Terms

| Term | What people say | What it actually means |
|---|---|---|
| Key agreement | “ECDH / DH gives you an encryption key” | It gives you a shared secret `Z` that must be run through a KDF with context. |
| KEM | “It’s like public-key encryption” | It’s an API that outputs `(ciphertext, shared_secret)`; you typically still need a DEM/AEAD for data. |
| Encapsulation / Decapsulation | “Encrypt / decrypt” | Encaps makes `ct` + `ss`; Decaps recomputes `ss` from `ct` (or fails). |
| Transcript hash | “Hash of the handshake” | A compact commitment to what was said/negotiated, used to bind keys to the session. |
| Hybrid | “Use two algorithms at once” | Combine multiple secrets with a KDF so breaking one doesn’t break the session. |

## Further Reading

- Krawczyk, “HKDF: Extract-and-Expand Key Derivation Function (RFC 5869)” (2010) — the canonical KDF used throughout modern key schedules.
- Rescorla, “TLS 1.3 (RFC 8446)” (2018) — shows how (EC)DHE shared secrets feed an HKDF-based key schedule.
- Barnes et al., “HPKE (RFC 9180)” (2022) — standardizes KEM + KDF + AEAD for encryption to a public key.
- NIST, “FIPS 203: ML‑KEM” (2024) — a standardized post-quantum KEM (KeyGen/Encaps/Decaps interface).
