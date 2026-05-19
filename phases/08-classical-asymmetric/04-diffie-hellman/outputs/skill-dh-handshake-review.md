---
name: dh-handshake-review
description: Review a DH/ECDH handshake design for MITM risk, validation, KDF usage, and forward secrecy.
version: 1.0.0
phase: 8
lesson: 4
tags: [diffie-hellman, ecdh, tls, noise, authentication, hkdf, forward-secrecy, crypto-review]
---

Paste a DH/ECDH handshake description (design doc, PR summary, protocol transcript). I will review it using this checklist and return:

- A one-paragraph **risk summary** (what could realistically go wrong).
- A **pass / fix / redesign** verdict.
- A short list of **actionable fixes** with concrete wording you can put into the spec/PR.

Checklist:

1. **Threat model clarity**
   - Is the attacker passive-only, or can they modify packets (active MITM)?
   - Are replay, downgrade, and unknown-key-share considered?

2. **Authentication (MITM prevention)**
   - What authenticates the peer’s DH/ECDH public key?
     - Certificates + signatures (TLS-style)?
     - PSK (pre-shared key) with a secure handshake?
     - PAKE (password-authenticated key exchange) if only a password exists?
   - If the answer is “nothing”: flag as **MITM-broken by design**.

3. **Key freshness + forward secrecy**
   - Are DH/ECDH private keys **ephemeral per session**?
   - If static keys are used, what compromise history becomes decryptable?
   - Are nonces / transcript hashes mixed to ensure distinct sessions derive distinct keys?

4. **Parameter and public-key validation**
   - For finite-field DH:
     - Is `p` a standardized safe prime group or a standardized subgroup group?
     - Are received public keys range-checked (`2 <= y <= p-2`)?
     - If using a prime-order subgroup (order `q`), is `y^q mod p == 1` enforced?
   - For ECDH:
     - Are points validated (on-curve, correct subgroup / cofactor handling)?
     - Is X25519 used (which has built-in clamping/cofactor behavior) where appropriate?

5. **KDF and transcript binding**
   - Is the raw DH shared secret fed into a KDF (HKDF is the default)?
   - Does the KDF `info` include:
     - protocol name + version,
     - role labels (client/server),
     - negotiated parameters/ciphers,
     - (ideally) a transcript hash?
   - Are separate keys derived for encryption vs authentication (key separation)?

6. **Key confirmation**
   - Is there an explicit MAC/signature step proving both sides derived the same key?
   - If not, is the first encrypted record used implicitly as confirmation?

7. **Side-channel and implementation realities**
   - Are private-key operations constant-time (or at least using audited libraries)?
   - Is secret material wiped/contained appropriately?
   - Are RNG requirements explicit (and tested)?

Red flags (call these out explicitly):

- “We do Diffie-Hellman and then encrypt” with no authentication step.
- Reusing DH private exponents across sessions.
- Using a custom or homegrown DH group.
- Using the raw shared secret directly as an AES key (no KDF / no context binding).
- Accepting peer public keys without subgroup/curve validation.

Output format:

Return a memo with:
- **Handshake summary**
- **Main risks** (bulleted)
- **Verdict** (pass / fix / redesign)
- **Fix list** (each fix: what to change + why + how to test it)
