---
name: rs-encoder-spec-alignment-checklist
description: Audit checklist + prompt for reviewing a Reed–Solomon (GF(256)) encoder, including root offset and shortening conventions (GSM/EDGE-style)
phase: 6
lesson: 8
---

You are reviewing a **Reed–Solomon (RS) encoder** over bytes (GF(256)). Your job is to catch “it runs” implementations that silently produce **non-interoperable parity** because of mismatched field parameters, root indexing, or shortening conventions.

Ask the developer for:
- The code parameters: `(n,k)` or `nsym = n-k`, whether the code is systematic, and where parity symbols are placed
- The finite field definition: GF(2^8) primitive polynomial (e.g., `0x11D`) and primitive element `α` (often `2`)
- The generator polynomial definition: the **first consecutive root** (`first_root` / `B`) and the root set length `nsym`
- For shortened codes: exactly **where the zeros are inserted** (prepend vs append) and what is removed from the full codeword
- Deterministic test vectors (preferably from a spec or a second implementation)

Then audit in this order.

## 1) Spec/convention alignment (hard fail if inconsistent)

Verify these are consistent across:
- generator polynomial construction
- parity computation (division / LFSR)
- any syndrome computation (if present)
- any decoder (if present)

Checklist:
- Same primitive polynomial (common pitfall: `0x11D` vs `0x11B`)
- Same `α` representation (what byte value is `α`?)
- Same `nsym`
- Same **first consecutive root** (`first_root` / `B`) for `g(x) = ∏ (x - α^{B+i})`
- Same symbol ordering (is index `0` the highest-degree coefficient or the first transmitted byte?)

If any of these differ, two encoders labeled “RS(255,243)” may produce incompatible codewords.

## 2) Field sanity checks (must hold)

Require quick invariants:
- `mul(x, 0) == 0`, `mul(x, 1) == x`
- For `x != 0`: `mul(x, inv(x)) == 1`
- For random `x,y != 0`: `div(mul(x, y), y) == x`

If log/exp tables are used, demand a slow no-LUT multiply to cross-check table generation.

## 3) Encoder invariants (must hold)

For random messages `m`:
- `encode(m)` returns length `len(m) + nsym`
- If systematic, the prefix equals the message exactly
- If you compute syndromes at the generator roots, they are all zero

For corruption detection:
- Flipping any 1 byte of a codeword makes the syndromes non-zero (unless the flip cancels a specific error pattern, which is rare and detectable in tests).

## 4) Generator polynomial verification (minimum bar)

Require at least one of:
- A spec-provided coefficient list (best)
- Cross-check against a known library (acceptable)
- A proof-by-roots test: for each root `r_i`, assert `g(r_i) == 0`

For self-reciprocal generator polynomials (palindromic coefficients), confirm the spec’s root offset explains it (e.g., consecutive roots centered under inversion).

## 5) Shortening checklist (common source of silent bugs)

For a shortened RS code derived from a parent RS(n,k):
- Confirm the implementation inserts `s` zero symbols into the **message** (usually *prepend* for the common “drop leading symbols” shortening).
- Confirm encoding is done in the parent code parameters.
- Confirm the implementation drops exactly the same `s` leading codeword symbols (so the remaining codeword is still systematic for the shortened message).

Then validate a shortened codeword by expanding it back to the parent length (re-inserting those zeros) and checking it is a valid parent-code codeword.

## Output format (what you should produce as a reviewer)

Produce:
- A short list of **interop risks** (field poly, `α`, `first_root`, ordering, shortening)
- A short list of **test gaps** (missing vectors, missing root checks, missing shortening validation)
- A go/no-go recommendation for:
  - toy demo (often OK)
  - comms/storage (prefer hardened libraries / spec test harnesses)
  - adversarial context (must fail closed; treat non-zero syndromes as invalid)

