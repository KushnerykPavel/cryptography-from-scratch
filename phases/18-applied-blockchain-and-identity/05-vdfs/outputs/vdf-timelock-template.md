---
name: vdf-timelock-template
description: A copy/paste template and design checklist for integrating VDF-based time-lock puzzles into protocol design — covering parameter selection, puzzle distribution, decryption flow, and failure modes.
phase: 18-applied-blockchain-and-identity
lesson: 05-vdfs
---

# VDF Time-Lock Protocol Design Template

Use this template when you need a commitment that becomes readable only after
a guaranteed sequential delay — without a trusted party holding a key in escrow.

---

## 1) What are you locking?

- What byte string is being encrypted?  (auction bid, private key, signed message?)
- What is the maximum acceptable plaintext size?  (XOR-keystream covers any length if you extend with a counter)
- Does the ciphertext need integrity protection?  If yes, append an HMAC or use an AEAD
  scheme keyed from `KDF(y)` instead of raw XOR.

---

## 2) Choose the delay parameter T

```
T_seconds ≈ T / squarings_per_second_on_fastest_hardware
```

| T | ~delay on modern CPU (single core) | Notes |
|---|------------------------------------|-------|
| 10^6 | ~1 second | Quick puzzles, online auctions |
| 10^7 | ~10 seconds | Short-lived secrets |
| 10^8 | ~100 seconds | Medium commitments |
| 10^9 | ~15 minutes | Block-level randomness beacons |

Benchmark on target hardware, then multiply by a safety factor (2–5×) to account
for faster ASICs.  Remember: the fastest solver sets the effective delay for everyone.

---

## 3) Choose the RSA modulus N

| Option | Size | Notes |
|--------|------|-------|
| Demo/toy | 92-bit (this lesson) | Never use in production |
| Research | 512-bit | Factorable in hours with cloud hardware |
| Minimum production | 1024-bit | Chiavdf uses 1024-bit |
| Recommended | 2048-bit | Standard RSA security recommendation |

**Trapdoor-free generation**: use a multi-party computation ceremony so that no
single party learns `p` and `q`.  If any party knows the factorisation they can
compute `φ(N)` and shortcut all T squarings to `O(log T)`.

---

## 4) Input selection (x)

```
x = H(public_nonce || context_tag) mod N
```

- Derive `x` deterministically from a public, unpredictable nonce (e.g., a block hash
  committed before the puzzle is set).
- Never let the puzzle creator choose `x` freely — they could search for an `x` that
  produces a favourable `y`.
- Ensure `1 < x < N` and `gcd(x, N) == 1` (reject otherwise).

---

## 5) Encryption

```python
# Sender
x = H(nonce || context) % (N - 2) + 1     # input, derived from public nonce
y = vdf_eval(x, T, N)                      # solve VDF (takes time T)
key = sha256(y.to_bytes(16, "big"))        # 256-bit key from VDF output
ciphertext = AEAD_encrypt(key, plaintext)  # or XOR-keystream for simple cases
puzzle = {"x": x, "T": T, "N": N, "ciphertext": ciphertext.hex()}
publish(puzzle)
```

---

## 6) Solving (receiver)

```python
# Anyone solving the puzzle
x, T, N, ciphertext = parse(puzzle)
y = vdf_eval(x, T, N)                      # sequential squarings
key = sha256(y.to_bytes(16, "big"))
plaintext = AEAD_decrypt(key, ciphertext)
```

Optional: generate a Wesolowski proof `(y, π)` so others can verify the solution
without re-running all T squarings.

---

## 7) Proof distribution

If multiple parties need to verify the solution efficiently:

```python
y, pi = vdf_eval_with_proof(x, T, N)
assert vdf_verify(x, T, y, pi, N)
broadcast({"y": y, "pi": pi})
```

Verifiers run `vdf_verify` — cheap, no T squarings needed.

---

## 8) Failure modes

| Failure | Cause | Mitigation |
|---------|-------|------------|
| Pre-computation attack | Attacker knows `x` before the puzzle is published | Derive `x` from a future-committed nonce |
| ASIC speedup | Custom hardware reduces effective delay | Choose large T with hardware safety factor |
| Factorisation of N | Attacker learns `p` and `q` | Trapdoor-free MPC ceremony for N |
| Weak challenge l | Small l reduces Wesolowski soundness | Use a ≥128-bit prime challenge |
| Ciphertext malleability | XOR lacks integrity | Add HMAC or use AEAD |
| N too small | Factored by EC-method or NFS | Use ≥1024-bit N in production |

---

## 9) Checklist before deploying

- [ ] `N` generated with trapdoor-free ceremony
- [ ] `|N|` ≥ 1024 bits (2048 recommended)
- [ ] `x` derived from an unpredictable public nonce committed before puzzle creation
- [ ] `T` calibrated to the fastest known squaring hardware with safety margin
- [ ] Wesolowski proof generated and published alongside `y` for cheap verification
- [ ] Ciphertext uses AEAD (not raw XOR) for integrity
- [ ] Challenge `l` derived as a uniformly random ≥128-bit prime
- [ ] No party knows the factorisation of `N`
