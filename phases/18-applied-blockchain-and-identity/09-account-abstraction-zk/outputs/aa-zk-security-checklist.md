# Account Abstraction & ZK Accounts — Pre-Deployment Security Checklist

## Smart Account Validation

- [ ] `validateUserOp` reverts (does not return false) on any malformed input
- [ ] Nonce is checked and incremented atomically inside `validateUserOp`
- [ ] The proof is bound to the specific UserOperation hash (sender + nonce + calldata + fees)
- [ ] Replayed proofs from old nonces are rejected
- [ ] The commitment / public key is set once at deployment and cannot be updated without re-authentication
- [ ] Signature malleability is handled (Schnorr: check `s < ORDER`; ECDSA: reject high-s)

## ZK Proof Security

- [ ] Schnorr nonces are generated with fresh randomness or RFC 6979 determinism — never reused
- [ ] The hash used for the Fiat-Shamir challenge includes ALL public inputs (R, commitment, op_hash)
- [ ] Scalar arithmetic uses `mod (N-1)` (group order), not `mod N` (field prime)
- [ ] Proof verification does not require the prover's secret key
- [ ] The ZK circuit (if used) has been audited for soundness and completeness

## Paymaster Security

- [ ] Paymaster signed data includes an expiry timestamp or block number
- [ ] Paymaster signed data includes a nonce to prevent replay of the same sponsorship
- [ ] Rate limiting is enforced per sender to prevent paymaster drain
- [ ] Paymaster only sponsors operations matching an explicit policy (amount, calldata selector, or whitelist)
- [ ] Paymaster `validatePaymasterUserOp` is gas-bounded to avoid DoS

## Bundler Hardening

- [ ] Bundler simulates each UserOp before inclusion (`eth_estimateUserOperationGas`)
- [ ] Bundler enforces storage access rules to prevent cross-UserOp interference
- [ ] Bundler rejects UserOps that would revert during simulation
- [ ] Bundle `total_fee` is verified to cover EntryPoint gas costs
- [ ] Bundler checks for duplicate nonces across ops in the same bundle

## Deployment Checklist

- [ ] EntryPoint address matches the canonical ERC-4337 singleton (not a fork)
- [ ] Smart account factory uses `CREATE2` for deterministic addresses
- [ ] Account init code hash is included in address derivation
- [ ] Upgrade path (if any) uses a timelocked proxy with guardian multisig
- [ ] Unused paymaster balances can be recovered by the owner

## References

- ERC-4337 spec: https://eips.ethereum.org/EIPS/eip-4337
- eth-infinitism reference implementation: https://github.com/eth-infinitism/account-abstraction
- Safe{Wallet} ERC-4337 module: https://github.com/safe-global/safe-modules
