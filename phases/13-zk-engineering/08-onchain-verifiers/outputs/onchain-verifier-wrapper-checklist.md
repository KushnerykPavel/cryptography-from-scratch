---
name: On-Chain Verifier Wrapper Checklist
description: Practical PR/audit checklist for integrating zk verifiers on EVM-style chains (ABI, range checks, upgrades, governance)
phase: 13-zk-engineering
lesson: 08-onchain-verifiers
---

# On-Chain Verifier Wrapper Checklist (EVM)

Use this as a PR review template whenever a project adds or changes a ZK verifier contract (Groth16/Plonk/STARK verifier, recursion verifier, etc.). The goal is not “the proof verifies”, but “the *right statement* verifies under the *right conditions* forever”.

## 1) Statement & inputs

- [ ] Public inputs are documented as a table: index → name → type → meaning → constraints (range, encoding, endianness).
- [ ] `pubSignals.length` is enforced to the exact expected length.
- [ ] Each public input is range-checked against the SNARK scalar field (`< SNARK_SCALAR_FIELD`) when applicable.
- [ ] Any non-field inputs (addresses, amounts, timestamps) are encoded deterministically into field elements (and the encoding is documented and tested).
- [ ] If the circuit expects a hash (Poseidon/SHA/Keccak), the on-chain side uses the same hash function and input packing as the circuit.

## 2) ABI & calldata

- [ ] The wrapper’s function signature matches the caller exactly (types, order, dynamic vs fixed).
- [ ] If `proof` is `bytes`, the wrapper enforces an exact `proof.length` (or a tight range) to avoid ambiguous decoding paths.
- [ ] Calldata construction is tested end-to-end (off-chain code → contract call) with at least one known-good proof and one known-bad proof.
- [ ] No use of `abi.encodePacked` for hashing multiple dynamic values without a length domain separator.

## 3) Domain separation & replay

- [ ] The proven statement binds to the correct domain: chain, verifier identity, and application instance.
  - Examples: include `chainId`, contract address, rollup id, app id, or a version tag inside the statement.
- [ ] Replays are handled:
  - [ ] nullifier uniqueness enforced (if privacy-style circuit),
  - [ ] state root / block number progression enforced (if rollup-style circuit),
  - [ ] proofs cannot be replayed across different contracts/environments.

## 4) Verification key (VK) lifecycle

- [ ] The verification key is effectively immutable (embedded constants in the verifier) or pinned by an explicit registry with governance.
- [ ] Any “verifier upgrade” is treated as a statement change:
  - [ ] upgrade proposal includes the new circuit identifier and a migration plan,
  - [ ] timelock + on-chain announcement window,
  - [ ] emergency halt plan if the new verifier is wrong.
- [ ] If multiple circuits are supported, selection is explicit and authenticated (no user-controlled “pick a verifier” footgun).

## 5) Gas & DoS safety

- [ ] Worst-case calldata size is bounded.
- [ ] Verification cost is bounded (no attacker-controlled loops over unbounded arrays).
- [ ] If batching is supported, batch size is bounded and memory growth is considered.
- [ ] Failure mode is cheap (invalid proof should fail fast with minimal work).

## 6) Testing & monitoring

- [ ] Test vectors exist for:
  - [ ] a known-good proof/public inputs pair,
  - [ ] a proof with a single-bit flip,
  - [ ] out-of-range public inputs (`>= SNARK_SCALAR_FIELD`),
  - [ ] wrong `pubSignals.length`.
- [ ] CI runs verification tests against the deployed bytecode (or a forked chain) whenever possible.
- [ ] On-chain events/logging: emit a succinct event on success/failure if it helps monitoring, without leaking sensitive data.

## 7) Security review cues

- [ ] Any custom pre-verification logic (hashing, parsing, compression) is minimized and audited like cryptography.
- [ ] No unchecked arithmetic that can affect validity decisions (unchecked loops are fine if bounds are enforced).
- [ ] External calls around verification are carefully ordered (verify first, then mutate state).

## “Stop the merge” red flags

- Public inputs aren’t range-checked and the verifier expects field elements.
- `pubSignals.length` is not enforced.
- The verifier is upgradable without governance and timelock.
- Off-chain and on-chain disagree on how inputs are packed/hashed.
