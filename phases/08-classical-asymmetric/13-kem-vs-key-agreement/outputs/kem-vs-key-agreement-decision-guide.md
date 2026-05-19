---
name: KEM vs Key Agreement — Decision + Review Checklist
description: A paste-ready checklist for selecting (and reviewing) KEM vs key agreement in handshakes, HPKE, and PQ/hybrid migrations.
phase: 08-classical-asymmetric
lesson: 13-kem-vs-key-agreement
---

# KEM vs Key Agreement — Decision + Review Checklist

Use this as a PR review template. It’s intentionally concrete: you should be able to answer every question from a diff + protocol doc.

## 1) What problem are we solving?

- Are we establishing keys for a long-lived secure channel (TLS/Noise/VPN), or doing one-shot “encrypt to a public key” (HPKE-style)?
- Do we need **forward secrecy** (fresh session keys even if long-term keys leak later)?
- Do we need **authentication** (prove who we’re talking to), or is this purely confidentiality?

## 2) Which primitive shape matches the protocol?

### Choose **key agreement** when:

- Both parties are online and can exchange messages (interactive handshake).
- You want both sides to contribute ephemeral keys (common for forward secrecy).
- The API is symmetric: both sides run something like `Agree(sk, pk) -> shared`.

### Choose a **KEM** when:

- You want a one-way “package” interface: `(ct, ss) = Encaps(pkR)` and `ss = Decaps(skR, ct)`.
- The receiver’s public key is already known (cert, prekey bundle, directory).
- You’re integrating a post-quantum primitive that *only* exposes KeyGen/Encaps/Decaps (e.g., ML‑KEM).
- You’re using HPKE (KEM + KDF + AEAD is the whole point).

## 3) Message-flow sanity check (most common bug source)

- If your protocol is described as **KA** but only one side sends a value, are you actually doing a KEM-like flow (static receiver key + sender ephemeral)?
- If your protocol is described as **KEM** but both sides exchange public keys, are you actually doing key agreement (or a KEM built from DH)?

## 4) Key schedule checklist (non-negotiable)

- Does the code treat the KA/KEM output as a *shared secret*, not as “the encryption key”?
- Is there a KDF (usually HKDF) that:
  - includes a **suite id / labels** for domain separation,
  - includes a **transcript hash / context** so keys are bound to the session,
  - derives separate keys for separate purposes (handshake keys vs application keys; tx vs rx)?

Red flag: `session_key = shared_secret[:32]` or any “use raw bytes as key” behavior.

## 5) Authentication checklist (easy to accidentally drop)

- What authenticates the peer?
  - signatures/certificates?
  - a PSK?
  - an authenticated out-of-band key?
- Where is the authentication *bound into the transcript* that the KDF uses?

Red flag: “we use KEM so MITM is impossible.” KEM does not authenticate.

## 6) Validation + failure behavior checklist

- Are peer inputs validated/decoded safely?
  - DH / ECDH often has group/encoding edge cases (some protocols require all-zero shared-secret checks).
  - KEMs typically define explicit failure behavior; the decapsulation path must match the spec.
- On failure, do we abort the handshake / key derivation cleanly?

Red flag: silently proceeding with an all-zero key, or “if decap fails, use zeros”.

## 7) Hybrid / migration checklist

If this is a classical + PQ hybrid:

- Are the secrets mixed using an explicit KDF construction (not ad hoc concatenation/XOR unless the spec says so)?
- Is the hybrid mix bound to a transcript/suite id?
- Are downgrade checks present (negotiation can’t be stripped)?

## 8) A quick decision summary

- “Interactive channel handshake” → key agreement (often (EC)DHE) + KDF + authentication.
- “Encrypt to a public key / offline recipient key” → KEM (HPKE-style) + KDF + AEAD.
- “Post-quantum primitive integration” → likely KEM interface, possibly hybrid with classical KA.

