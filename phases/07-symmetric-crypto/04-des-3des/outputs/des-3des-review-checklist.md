---
name: "DES/3DES (TDEA) Review Checklist"
description: "A practical checklist for identifying DES/3DES usage, assessing risk, and migrating safely."
phase: "07-symmetric-crypto"
lesson: "04-des-3des"
---

# DES/3DES (TDEA) Review Checklist

Use this when you see `DES`, `3DES`, `TDEA`, `DESede`, `EVP_des_*`, or 8-byte block assumptions in code or configs.

## 1) Identify exactly what is used
- Is it **DES** (single) or **3DES/TDEA** (triple)?
- If 3DES: is it **three-key** (K1, K2, K3 all different) or **two-key** (K3 = K1)?
- What is the **mode** (ECB/CBC/CFB/OFB/CTR)? Is an AEAD used (almost never with 3DES)?
- What is the **padding** (NoPadding/PKCS#7/ISO7816-4/implicit)? For fixed-size data, is it truly block-aligned?
- What is the **IV/nonce** source? Is it random/unique per message? Is there any chance of IV reuse?

## 2) Classify the usage: encrypting new data vs legacy-only
- Is the system **encrypting new data** with DES/3DES today?
- Or is it **decrypting/unwrap/verifying legacy data only**?
- Where does the ciphertext travel (at rest, on the wire, across trust boundaries)?
- Is there a compliance boundary that forbids new 3DES encryption after **2023-12-31** per NIST transition guidance?

## 3) Check the block-size risk (64-bit blocks)
3DES has a 64-bit block size. Ask:
- How much data is encrypted per **(key, IV)** before key rotation?
- Any long-lived sessions/tunnels that might exceed ~2^32 blocks (~34 GB) under one key? If yes, treat as high risk.

## 4) Watch for common implementation traps
- **ECB used “because it’s simpler”** (patterns leak; identical blocks encrypt identically).
- **Implicit all-zero IV** or reused IV in CBC/CFB/OFB (catastrophic for some use cases).
- **Key parity confusion** (some APIs require odd parity; others silently adjust or reject keys).
- **DESede naming mismatch**: some platforms call 2-key 3DES and 3-key 3DES the same thing.
- **Silent truncation**: passing a 16-byte key where the API expects 24 bytes (or vice-versa).

## 5) Migration plan (minimum-safe path)
- If you must interop: implement **dual-stack**:
  - Accept legacy decrypt/verify paths for DES/3DES.
  - Stop issuing new encryptions under DES/3DES.
- Choose a target:
  - **AES-GCM** (preferred) or **ChaCha20-Poly1305**.
  - If you must separate: AES-CTR + HMAC (encrypt-then-MAC) with strict nonce rules.
- Define and document:
  - Versioned ciphertext format (algorithm id, nonce/IV, tag, ciphertext).
  - Key rotation + maximum bytes per key policy.
  - Backward-compatibility window and a deletion/reencryption timeline.

## 6) Questions to ask in code review
- “What compatibility requirement forces DES/3DES here?”
- “Are we encrypting new data or only decrypting old records?”
- “What’s the mode, IV policy, and maximum bytes per key?”
- “Can we switch to AES-GCM without breaking existing clients?”
- “Do we have test vectors and interop tests with another implementation?”

