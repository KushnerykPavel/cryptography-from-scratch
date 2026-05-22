---
name: Ethereum Crypto Review Checklist
description: A byte-level checklist to debug and review Keccak-256, secp256k1 ECDSA, EIP-55, and EIP-191 usage in wallet/contract integrations.
phase: 18-applied-blockchain-and-identity
lesson: 02-ethereum-stack
---

# Ethereum Crypto Review Checklist

Use this when:
- a signature verifies in one tool but fails in another,
- an address checksum doesn’t match,
- your “keccak256” output differs from Solidity/web3,
- you’re reviewing code that handles addresses/signatures/hashes.

## 1) Hash function sanity (Keccak vs SHA-3)
- Confirm the empty-string vector:
  - `keccak256("") == c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470`
  - `sha3_256("") == a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a`
- Search for suspicious names:
  - “sha3” used as a synonym for “keccak256”
  - `hashlib.sha3_256` used where Ethereum expects Keccak-256

## 2) Bytes vs hex strings (the #1 integration bug)
For every hash/sign step, write down: “what exact bytes are being hashed/signed?”
- If you see `hex()` / `toString("hex")` / `encode("utf-8")`, confirm the intention:
  - Hashing the ASCII hex string (e.g., `"001d..."`) is different from hashing the raw bytes (`0x00 0x1d ...`).
- If you see JSON, confirm:
  - field order
  - whitespace
  - unicode normalization
  - whether you should hash structured data (EIP-712) instead of raw JSON

## 3) Address derivation (EOA)
- Confirm the public key format:
  - Uncompressed pubkey is `0x04 || X || Y` (65 bytes).
  - Address derivation uses **only** `X || Y` (64 bytes), not the `0x04`.
- Confirm the address step:
  - `addr = keccak256(X||Y)[12:]` (last 20 bytes)
- Confirm you’re not confusing:
  - EOA address derivation vs `CREATE` / `CREATE2` contract address derivation

## 4) EIP-55 checksum rules
- Input to the checksum hash is:
  - lowercase hex address string (40 hex chars), **no `0x`**
- Uppercase rule:
  - uppercase hex letter if the corresponding nibble of `keccak256(lowercase_hex)` is `>= 8`
- Validate behavior:
  - lowercase-only addresses are valid bytes but carry no checksum
  - mixed-case implies checksum intent; reject mismatches

## 5) Signature type and message hashing
Decide which category you’re in:
- **Transaction signing:** sign the transaction hash (RLP/EIP-1559 domain rules), Keccak-256.
- **personal_sign (EIP-191):** sign `keccak256("\x19Ethereum Signed Message:\n" + len(message) + message)`.
- **Typed data (EIP-712):** sign the EIP-712 structured hash (domain separator + struct hash).

If verification fails, the first question is:
“Are the signer and verifier hashing the *exact same bytes*?”

## 6) ECDSA canonicalization and malleability
- Many Ethereum contexts require “low-s” signatures:
  - If `s > n/2`, canonicalize to `s' = n - s`.
- If you accept both (r, s) and (r, n−s), you may enable signature malleability:
  - same signer/message, different signature bytes
  - can break replay protection and signed-message tracking

## 7) Quick debug workflow (copy/paste)
Fill this out when debugging:
- Input bytes (hex): `…`
- Hash function: `keccak256` / `sha3_256` / `sha256` / other
- Hash output (hex): `…`
- Signature type: tx / personal_sign / typed_data
- Signed preimage (hex): `…`
- Signature `(r,s)` (hex): `…`
- Low-s applied? yes/no
- Derived address (raw): `0x…`
- Address checksummed (EIP-55): `0x…`

