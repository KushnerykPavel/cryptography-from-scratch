# ZK Rollup Audit Checklist

Use this checklist when auditing a ZK rollup implementation — bridge contract,
prover, sequencer, or SDK.

---

## 1. State Root

- [ ] State root is computed over **sorted** accounts (deterministic ordering)
- [ ] Each account leaf hashes `address || balance` (not just balance)
- [ ] Root recomputed after every batch, not cached from a previous round
- [ ] Genesis root matches what the L1 contract was initialised with
- [ ] Root encoding is consistent (hex vs bytes vs uint256) across L1 and L2

---

## 2. Batch / Transaction Validity

- [ ] Every transfer has `amount > 0`
- [ ] Sender account exists in current state
- [ ] Recipient account exists in current state
- [ ] Sender balance `>= amount` before transfer (no overdraft)
- [ ] Total supply is conserved: `sum(new_balances) == sum(old_balances)`
- [ ] Replay protection: each tx has a unique nonce or sequence number

---

## 3. Proof Structure

- [ ] Proof binds to `old_root` — cannot be applied from a different state
- [ ] Proof binds to `new_root` — verifier cannot substitute a fraudulent result
- [ ] Proof includes `tx_hash` — cannot be replayed with different transactions
- [ ] Proof is rejected if any root field is zeroed / missing
- [ ] L1 verifier contract checks `old_root == current_root` before accepting

---

## 4. R1CS / Circuit Correctness

- [ ] `from_new = from_bal - amount` encoded as a constraint (not assumed)
- [ ] `to_new = to_bal + amount` encoded as a constraint
- [ ] Non-negativity (`from_bal >= amount`) uses a proper range proof sub-circuit
- [ ] No unconstrained witness variables (every private input is constrained)
- [ ] Public inputs to the verifier match what the L1 contract passes in

---

## 5. Groth16 / Plonk Verifier (if applicable)

- [ ] Trusted setup ceremony output is the correct one for this circuit
- [ ] Verifier key (vk) is immutable / stored on-chain
- [ ] Pairing check uses the correct elliptic curve (BN254, BLS12-381, …)
- [ ] Proof deserialization rejects malformed inputs before expensive operations
- [ ] Verifier is generated from the same circuit version as the prover

---

## 6. Sequencer / Prover Integration

- [ ] Sequencer cannot reorder transactions to front-run users (MEV protection)
- [ ] Prover timeout / fallback does not allow unproven batches to be finalised
- [ ] Forced transaction inclusion path exists (censorship resistance)
- [ ] Prover output is deterministic for the same inputs (no randomness leaks)

---

## 7. Bridge / Withdrawal Security

- [ ] Withdrawal only unlocks after proof is verified on L1
- [ ] Withdrawal root matches the L2 state root at the claimed block
- [ ] Double-withdrawal prevented (nullifier or burn-on-claim)
- [ ] Emergency exit path does not bypass ZK verification

---

## 8. Known Attack Patterns

| Attack | What to check |
|--------|--------------|
| Malformed proof accepted | Verifier rejects all-zero / identity-element proofs |
| State root mismatch | L1 contract rejects proof if `old_root` doesn't match stored root |
| Replay across chains | Chain ID is included in proof public inputs |
| Underconstrained circuit | Audit R1CS for variables used in output but not constrained in input |
| Trusted setup compromise | Verify ceremony transcript and check for known toxic waste |
| Sequencer censorship | Check that forced-inclusion mechanism is functional and tested |
