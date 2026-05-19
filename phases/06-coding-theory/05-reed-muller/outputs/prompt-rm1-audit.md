---
name: prompt-rm1-audit
description: Audit checklist + prompt for reviewing an RM(1,m) (Hadamard) encoder/decoder (ordering, WHT decode, failure safety)
phase: 6
lesson: 5
---

You are reviewing an **RM(1,m)** (first-order Reed-Muller / Hadamard) encoder+decoder implementation. Your job is to catch silent correctness bugs and unsafe “correction” behavior.

Do not proceed until the developer states these conventions precisely (hard fail if unclear):

## 1) Conventions (must be explicit)

- Point ordering: how do they map positions `0..n-1` to points `x ∈ {0,1}^m`?
  - Example: `x` is the integer index and bit `i` is variable `x_i` (LSB = `x0`), with points enumerated `x=0..2^m-1`.
- Variable naming/order: which bit corresponds to `x0`, `x1`, ...?
- Message coefficient order:
  - `RM(1,m)`: is it `[a0, a1, ..., am]` (constant term then linear terms)?
  - For general `RM(r,m)`: how do they order monomials (by degree then lexicographic indices, etc.)?
- Codeword definition:
  - Are they using “truth table of f(x)” where `codeword[x] = f(x)`?
  - Or a transposed convention (`codeword` as values on a different ordering)?
- Decoder promise:
  - Unique decode radius only, or “best effort” always?
  - What happens when decoding is ambiguous / beyond radius? (Must fail closed in real systems.)

## 2) Encoder correctness (matrix/basis invariants)

If they build a generator matrix `G` from monomial truth tables:

- Confirm `G` rows correspond to the stated monomial order.
- Confirm `RM(1,m)` has `k = m+1` rows: `1, x0, x1, ..., x(m-1)`.
- Confirm encoding is linear over GF(2):
  - `encode(a XOR b) == encode(a) XOR encode(b)` for multiple test cases.
- Confirm they validate inputs:
  - `0 <= r <= m`, message length equals `k`, bits are in `{0,1}`.

## 3) WHT decoder correctness (RM(1,m))

If they decode via Walsh-Hadamard transform:

- Confirm the bit-to-sign mapping:
  - Common choice: bit `0 -> +1`, bit `1 -> -1` (i.e., `1 - 2*b`).
- Confirm the correlation definition matches the encoder’s point ordering:
  - A mismatch here will “decode” consistently to the wrong coefficients.
- Confirm how they recover the constant term `a0`:
  - Usually from the sign of the best correlation peak.
- Require a deterministic test suite:
  - Exhaustive roundtrip for a small `m` (e.g., `m=3`, all `2^(m+1)` messages)
  - Exhaustive single-bit flip correction for that `m`

## 4) Safety (avoid silent miscorrection)

Key facts to ask them to state:

- `RM(1,m)` minimum distance is `d = 2^(m-1)`.
- Unique hard-decision correction radius is `t = floor((d-1)/2) = 2^(m-2) - 1`.

Audit these safety behaviors:

- If the implementation is used beyond `t`, does it:
  - detect failure and refuse to return a decoded message, or
  - silently return a “closest” affine function? (Unsafe in production without an outer integrity check.)
- If it is used in an adversarial setting, require an outer integrity mechanism:
  - CRC for accidental corruption
  - authentication (MAC/signature) for adversarial tampering

## 5) Minimum test plan (non-negotiable)

Require:

- Deterministic vectors for:
  - parameters `(n,k,d)` for at least one `(r,m)`
  - a known message → known codeword for `RM(1,m)` and one for `RM(2,m)` (small `m`)
  - a known single-bit-flipped received word → decoded coefficients
- Property tests:
  - encoder linearity
  - `RM(1,m)` exhaustive roundtrip for small `m`
  - `RM(1,m)` exhaustive single-bit correction for small `m`
  - input validation rejects wrong lengths / non-bits / invalid parameters

## Output format

Produce:
- A bullet list of correctness risks (naming exact modules/functions)
- A bullet list of missing tests and the simplest way to add them
- A go/no-go recommendation for:
  - demo / educational use
  - production reliability (accidental corruption)
  - adversarial setting (assume “no” without authentication framing)

