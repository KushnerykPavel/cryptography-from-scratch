---
name: prompt-reed-solomon-ecc-review
description: Audit checklist + prompt for reviewing a Reed-Solomon (GF(256)) encoder/decoder and fail-safe integration
phase: 6
lesson: 4
---

You are reviewing a **Reed-Solomon (RS) encoder/decoder** implementation over bytes (typically GF(256)). Your job is to catch silent math mismatches and unsafe “decode even when it failed” behavior.

Ask the developer for:
- The full code parameters: `(n, k)` or `nsym = n-k`, whether it is systematic, and where parity is placed
- The finite field definition: `GF(2^8)` primitive polynomial (e.g., `0x11D`) and generator element (e.g., `2`)
- The syndrome convention: which roots are used (e.g., `α^0..α^{nsym-1}` vs shifted)
- The decoder algorithm steps (BM/EEA + Chien + Forney), and whether erasures are supported
- Test vectors and how they were generated (second implementation, spec, or known library)

Then audit in this order.

## 1) Parameter and convention alignment (hard fail if inconsistent)

Verify these match across encoder, syndrome computation, and decoder:
- Same primitive polynomial and generator element
- Same `nsym` (parity symbol count)
- Same notion of “position”: is index `0` the highest-degree coefficient or the first transmitted byte?
- Same roots for generator polynomial and syndromes (a one-off shift breaks decoding)

If two implementations “both use RS(255, 223)” but use different polynomials/roots, they will not interoperate.

## 2) Finite-field sanity checks (must hold)

Require quick invariants:
- `gf_mul(x, 0) == 0`, `gf_mul(x, 1) == x`
- For `x != 0`: `gf_mul(x, gf_inv(x)) == 1`
- For random `x,y != 0`: `gf_div(gf_mul(x, y), y) == x`

If they use log/exp tables, demand a no-LUT multiply to cross-check table generation.

## 3) Encoder invariants (must hold)

For random messages `m`:
- `codeword = encode(m)` has length `len(m)+nsym`
- `syndromes(codeword)` are all zero
- A single-byte change produces non-zero syndromes (detection works)

If systematic encoding is claimed, confirm the codeword begins with the message bytes exactly.

## 4) Decoder safety (do not allow silent corruption)

Ask: “What is the guaranteed correction radius?”
- With `nsym` parity symbols, max unknown symbol errors is `t = nsym//2`.

Then require:
- After correction, recompute syndromes; if any syndrome is non-zero, treat as **decode failure**.
- The decoder returns an explicit error/exception on failure (not a “best effort” payload).
- The integration layer (callers) propagates failure instead of silently using output.

Threat model note: in adversarial contexts, accepting a miscorrected payload is often worse than rejecting.

## 5) Tests (minimum bar)

Require:
- Deterministic vectors: known `(field, nsym)`, known `msg -> codeword`, known corrupted `codeword -> decoded`
- Roundtrip tests for up to `t` random symbol errors
- Failure tests for `t+1` errors (must fail, not miscorrect)
- Cross-check against a second implementation (library/spec) for at least one parameter set

## Output format

Produce:
- A short list of **interop risks** (field parameters, syndrome roots, index conventions)
- A short list of **decoder safety risks** (failure signaling, syndrome re-check)
- A go/no-go recommendation for:
  - toy demo (often OK)
  - production comms/storage (usually “use a hardened library/hardware”)
  - adversarial context (must fail closed)

