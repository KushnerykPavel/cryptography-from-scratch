---
name: goppa-codes-review-checklist
description: PR/audit checklist for Goppa/alternant matrix generation and decoding assumptions (McEliece/Niederreiter context)
phase: 06-coding-theory
lesson: 06-goppa-codes
---

# Goppa / Alternant Codes — Review Checklist

Use this when reviewing code that claims to implement Goppa codes, alternant codes, Classic McEliece key generation, Niederreiter syndrome generation, or “code-based crypto” matrix routines.

## 1) Parameters and invariants

- [ ] Parameters are explicit and consistent: `m` (field degree), `t` (deg(g)), `n` (support length), `k` (dimension).
- [ ] The code states (or asserts) expected shapes: `H_GF` is `t × n` over GF(2^m); `H_bin` is `(m·t) × n` over GF(2).
- [ ] The intended security level / parameter set is named (if this is a crypto implementation), not “picked ad hoc”.

## 2) Field definition (GF(2^m))

- [ ] The reduction polynomial `p(x)` is stated and encoded unambiguously (e.g., `0b10011` for `x^4 + x + 1`).
- [ ] The basis is stated: polynomial basis vs normal basis vs something else.
- [ ] All arithmetic is constant-time where secrets may flow (crypto code): no secret-dependent branches or table indices.
- [ ] `inv(0)` is rejected and cannot occur on valid inputs.

## 3) Goppa polynomial `g(x)`

- [ ] `deg(g) = t` is correct and the leading coefficient is nonzero (monic if that is required by the spec).
- [ ] If the design assumes square-free / separable `g(x)`, there is a check or the construction guarantees it.
- [ ] Any randomness used to sample `g(x)` is domain-separated and uses a validated CSPRNG (crypto code).

## 4) Support selection `L`

- [ ] `L` elements are distinct and in GF(2^m).
- [ ] The implementation enforces `g(L_i) != 0` for every support element.
- [ ] Support sampling is deterministic when required (test vectors, reproducibility), and randomized only when explicitly intended (keygen).

## 5) Parity-check construction

Checklist for the standard alternant form:

- [ ] `H_GF[i,j] = L_j^i / g(L_j)` (or an equivalent, documented variant).
- [ ] Exponentiation uses field multiplication (not integer exponentiation).
- [ ] Division is implemented as multiplication by `inv(g(L_j))` in the same field.
- [ ] There are shape/rank sanity checks (e.g., rank close to `m·t` for typical parameters).

## 6) Binary expansion / embedding

- [ ] The mapping GF(2^m) → `{0,1}^m` is precisely defined (bit ordering, coefficient ordering).
- [ ] The chosen mapping is consistent everywhere (keygen, encode, syndrome, decode).
- [ ] Tests cover basis/bit-order regressions (these are common and catastrophic).

## 7) Encoding and consistency checks

- [ ] Codewords satisfy `H_bin · c^T = 0` for many test cases (not just one).
- [ ] Generator matrix construction (if used) is documented: nullspace basis, systematic form, or spec-defined method.
- [ ] Any systematic form is validated (pivoting, permutations) and preserved across serialization/deserialization.

## 8) Decoding expectations (security-critical)

- [ ] If this is McEliece/Niederreiter, decoding is implemented only with the secret structure (Patterson-style or equivalent), not with generic decoding.
- [ ] Error weight bounds are enforced: attempt to decode only up to the designed radius (or spec-defined bound).
- [ ] Failure modes are explicit and side-channel safe (constant-time failure handling where required).

## 9) Tests and vectors

- [ ] Deterministic vectors exist for field ops (`mul`, `inv`, `div`), polynomial evaluation, and matrix construction.
- [ ] There are property tests: `a·inv(a)=1` for `a!=0`, distributivity, syndrome-zero for encoded codewords.
- [ ] Vectors include a `source` explanation and are stable across platforms/architectures.

## 10) Red flags (stop and ask)

- [ ] “Works on my machine” without vectors or parameter-set references.
- [ ] Unstated field basis or ambiguous bit order.
- [ ] Secret-dependent branches/tables in field inversions or polynomial operations.
- [ ] Randomized support/goppa polynomial without a clear threat model and spec alignment.

