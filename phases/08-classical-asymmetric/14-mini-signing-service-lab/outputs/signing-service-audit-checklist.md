---
name: signing-service-audit-checklist
description: PR review + design checklist for signed request / signing service schemes
phase: 8
lesson: 14
---

Use this checklist to review a “signed request” protocol, a signing service API, or a webhook verification implementation.

Goal: make sure signatures cover the right bytes, are bound to the right context, and cannot be replayed.

## 1) Bytes, not objects

- What *exact bytes* are signed? Is it written down as a spec (not “we sign the JSON”)?
- Is there a canonicalization step (canonical JSON, protobuf, CBOR, a fixed header format)?
- Are Unicode and encoding rules explicit (UTF-8, normalization, forbidden control chars)?
- Are there deterministic test vectors that signers and verifiers can share and reproduce?

## 2) Context binding (domain separation)

A signature should be valid only for one meaning.

- Does the signature cover `method` and `path` (or an equivalent operation identifier)?
- Does it cover the intended audience (host/service name/tenant/account ID)?
- Does it cover the protocol version and algorithm identifier?
- Are keys separated by purpose (e.g., webhooks vs admin approvals vs firmware)?

## 3) Freshness and replay protection

- Is there a timestamp with an explicit skew window (e.g., ±300s)?
- Is there a nonce or unique request ID?
- Does the verifier keep a cache of seen `(kid, nonce)` (or `(kid, request_id)`) values?
- What is the nonce cache TTL, and how is it sized? What happens under load (eviction policy)?
- If stateful replay protection is impossible, is the protocol explicitly idempotent and safe under replay?

## 4) Key management and rotation

- Where is the private key stored (KMS/HSM vs app memory)?
- Is the signing API narrowly scoped (sign only well-formed, policy-checked statements)?
- Is there a `kid` and a clear public-key lookup mechanism?
- Is rotation supported (multiple active keys, deprecation window, deterministic verification behavior)?
- Are signing events logged with minimal sensitive data (no raw payloads if they are secret)?

## 5) Algorithm choices and crypto hygiene

- Are you using an audited library (not custom RSA/ECDSA code)?
- If RSA: do you prefer RSA-PSS for new designs? If not, why not?
- If using “legacy” algorithms (RSA PKCS#1 v1.5), is the verifier strict and tested against edge cases?
- Is signature comparison constant-time (`compare_digest` equivalents)?

## 6) Error handling and observability

- Does the verifier return generic errors to clients (avoid detailed oracle behavior)?
- Are failures distinguishable in logs/metrics (bad signature vs stale timestamp vs replay)?
- Is there enough telemetry to debug “why verification fails” without leaking secrets?

## 7) “What breaks if…?” checks

- If an attacker reorders JSON keys or adds insignificant whitespace, does verification still work?
- If a signed request is replayed to a different endpoint, does verification fail?
- If the same signed request is replayed within the skew window, does verification fail?
- If a future version adds a field, does old verification logic behave safely (versioning rules)?

## Output expectations for a good design

- A one-page spec describing the exact signed bytes and fields.
- Deterministic test vectors for at least: canonicalization, base string, signature.
- A verifier that enforces context binding + timestamp window + replay rejection.
- A key rotation story that is tested in staging before prod.

