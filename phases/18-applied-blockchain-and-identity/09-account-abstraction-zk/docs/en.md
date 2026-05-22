# Account Abstraction & ZK Accounts
> Smart accounts replace "sign with your private key" with "prove you know your key" — and the proof is a real ZK argument.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 18 · 01 (Bitcoin Stack / Schnorr), Phase 18 · 08 (ZK Rollups)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain what ERC-4337 account abstraction is and why it exists.
- Compute a smart-account commitment and deterministic address from an owner key.
- Implement a Schnorr / Fiat-Shamir NIZK proof of discrete-log knowledge as account authorization.
- Distinguish standard EOA signing from ZK-proof-based smart account validation.
- Apply paymaster policies and the bundler flow to package UserOperations.

## The Problem

Every Ethereum address today is an Externally Owned Account (EOA): a private key controls it, and authorization is a single ECDSA signature over a transaction. That model is rigid. Recovering a lost key is impossible. Sponsoring gas for a user requires them to hold ETH first. Adding 2-of-3 multisig or social recovery requires deploying custom contracts with bespoke signing logic.

ERC-4337 ("account abstraction without consensus changes") separates _what to execute_ from _who authorizes it_. A **UserOperation** is a higher-level intent object. **Smart accounts** are contracts that implement their own `validateUserOp` method, so the validation logic can be any computation — including a ZK proof. A **Paymaster** can sponsor the gas fees, checked against a policy. A **Bundler** collects UserOps, validates them off-chain, and submits a single transaction to the EntryPoint contract.

This lesson builds each piece from scratch. The "ZK proof" is a Schnorr identification protocol made non-interactive with Fiat-Shamir — this is a genuine NIZK proof of knowledge of discrete log. The group arithmetic uses a toy multiplicative group (Z_N* where N = 2^31 − 1, a Mersenne prime) so you can follow every number.

## The Concept

### ERC-4337 actors

| Actor | Role |
|---|---|
| User | Builds and signs a `UserOperation` |
| Smart account | On-chain contract; implements `validateUserOp(UserOp, proof) → bool` |
| Paymaster | On-chain contract; can sponsor gas if policy is satisfied |
| Bundler | Off-chain node; validates, bundles, and submits ops via EntryPoint |
| EntryPoint | Singleton on-chain contract; calls account + paymaster + executes |

### Smart account commitment

Instead of storing a raw private key, the smart account stores a **commitment** — a public key derived from the private key:

```
commitment = G^sk mod N
```

This is the discrete-log assumption: given `commitment`, you cannot recover `sk` in polynomial time. The account address is derived deterministically from the commitment (toy: first 8 hex digits).

### Schnorr ZK proof (Fiat-Shamir)

To authorize a UserOperation without revealing `sk`, the owner runs a **sigma protocol** made non-interactive:

| Step | Prover | Verifier |
|---|---|---|
| 1 | Pick nonce `k`; send `R = G^k mod N` | |
| 2 | | Send challenge `e = H(R ‖ commitment ‖ op_hash)` |
| 3 | Send response `s = (k + sk·e) mod (N−1)` | |
| 4 | | Check `G^s ≡ R · commitment^e (mod N)` |

Fiat-Shamir collapses rounds 2–3: the challenge is computed by the prover as a hash, making the protocol non-interactive. The verifier only needs `(R, s)` and the stored `commitment` — it never sees `sk`.

**Why `mod (N−1)` for scalars?** In Z_N* (N prime), the group order is `N−1` (Fermat's little theorem). Exponents must be reduced mod `N−1`, not mod `N`.

### Paymaster policy

A paymaster checks two conditions before sponsoring a UserOp:

1. `user_op.max_fee ≤ policy.max_fee`
2. `user_op.sender ∈ policy.whitelist` (if the whitelist is non-empty)

### Bundler flow

```
UserOp₁, UserOp₂, ... → validate each proof → pack into bundle → submit EntryPoint tx
```

## Build It

### Step 1: Group parameters and helpers

```python
_AA_N: int = 2**31 - 1        # Field prime (Mersenne)
_AA_G: int = 3                 # Generator of Z_N*
_AA_ORDER: int = _AA_N - 1    # Group order (Fermat: a^(N-1) ≡ 1 mod N)

def _op_hash(user_op: dict) -> int:
    """Canonical hash of a UserOperation (excluding the proof field)."""
    op_copy = {k: v for k, v in sorted(user_op.items()) if k != "proof"}
    serialised = json.dumps(op_copy, sort_keys=True, separators=(",", ":")).encode()
    return _sha256_int(serialised) % _AA_ORDER
```

Excluding `proof` from the hash prevents a circular dependency when computing the proof.

### Step 2: Create a smart account

```python
def aa_compute_address(owner_sk: int) -> str:
    pk = pow(_AA_G, owner_sk, _AA_N)
    return "0x" + hex(pk)[2:].zfill(16)[:16]

def aa_create_account(owner_sk: int) -> dict:
    commitment = pow(_AA_G, owner_sk, _AA_N)
    return {
        "address": aa_compute_address(owner_sk),
        "commitment": commitment,
        "nonce": 0,
    }
```

`commitment = G^sk mod N` is the on-chain public state. The address is derived from it deterministically — same as `CREATE2` determinism in production.

### Step 3: Create a UserOperation

```python
def aa_create_user_op(account: dict, calldata: bytes, max_fee: int) -> dict:
    return {
        "sender": account["address"],
        "nonce": account["nonce"],
        "calldata": calldata.hex(),
        "max_fee": max_fee,
        "proof": None,
    }
```

The `proof` field starts as `None` and is filled by `aa_create_zk_proof`.

### Step 4: Generate the ZK proof

```python
def aa_create_zk_proof(owner_sk: int, user_op: dict) -> tuple[int, int]:
    commitment = pow(_AA_G, owner_sk, _AA_N)
    op_h = _op_hash(user_op)

    # Deterministic nonce (Fiat-Shamir)
    k = _sha256_int(
        owner_sk.to_bytes(8, "big") + op_h.to_bytes(32, "big")
    ) % _AA_ORDER
    if k == 0:
        k = 1

    R = pow(_AA_G, k, _AA_N)
    e = _sha256_int(
        R.to_bytes(8, "big")
        + commitment.to_bytes(8, "big")
        + op_h.to_bytes(32, "big")
    ) % _AA_ORDER

    s = (k + owner_sk * e) % _AA_ORDER
    return (R, s)
```

The response `s = (k + sk·e) mod ORDER` is computed mod `N−1` (the group order).

### Step 5: Validate the UserOperation

```python
def aa_validate_user_op(account: dict, user_op: dict, proof: tuple[int, int]) -> bool:
    R, s = proof
    commitment = account["commitment"]
    op_h = _op_hash(user_op)

    e = _sha256_int(
        R.to_bytes(8, "big")
        + commitment.to_bytes(8, "big")
        + op_h.to_bytes(32, "big")
    ) % _AA_ORDER

    lhs = pow(_AA_G, s, _AA_N)
    rhs = R * pow(commitment, e, _AA_N) % _AA_N
    return lhs == rhs
```

No private key is used. The verifier only needs `(R, s, commitment, op_hash)`.

### Step 6: Paymaster and Bundler

```python
def aa_paymaster_check(user_op: dict, policy: dict) -> bool:
    if user_op["max_fee"] > policy.get("max_fee", 0):
        return False
    whitelist = policy.get("whitelist", [])
    if whitelist and user_op["sender"] not in whitelist:
        return False
    return True

def aa_bundle_ops(user_ops: list[dict]) -> dict:
    total_fee = sum(op["max_fee"] for op in user_ops)
    payload = json.dumps(user_ops, sort_keys=True, separators=(",", ":")).encode()
    bundle_hash = hashlib.sha256(payload).hexdigest()
    return {"bundle_hash": bundle_hash, "ops": user_ops, "total_fee": total_fee}

def aa_verify_bundle(bundle: dict, accounts: list[dict]) -> bool:
    account_by_addr = {acc["address"]: acc for acc in accounts}
    for op in bundle["ops"]:
        acc = account_by_addr.get(op["sender"])
        if acc is None:
            return False
        proof = op.get("proof")
        if proof is None:
            return False
        if not aa_validate_user_op(acc, op, proof):
            return False
    return True
```

Run it:
```
python3 code/main.py
```

## Use It

In production, ERC-4337 smart accounts use secp256k1 ECDSA or WebAuthn P-256 signatures. ZK-based accounts use Groth16 or PLONK circuits (e.g., via Circom/SnarkJS or Risc0). Libraries: [eth-infinitism/account-abstraction](https://github.com/eth-infinitism/account-abstraction), [ZKEmail wallet](https://github.com/zkemail/email-wallet), [Privy embedded wallets](https://privy.io). The Bundler spec is [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337).

## Pitfalls

1. **Scalar modulus confusion.** Schnorr responses must use `% (N-1)` (group order), not `% N`. Using the wrong modulus breaks verification for most inputs.
2. **Hashing the proof field.** If `op_hash` includes the `proof` field, creating a proof and verifying it become circular. Always exclude `proof` from the operation hash.
3. **Nonce replay.** Reusing a Schnorr nonce `k` with different challenges leaks `sk` algebraically. Use deterministic nonces (RFC 6979 style) or fresh randomness.
4. **Address derivation collisions.** Truncating the public key to 8 hex digits is only safe in a toy setting. Production accounts use CREATE2 with the full init code hash.
5. **Missing paymaster nonce.** A real paymaster must include a nonce or expiry in the sponsored data, or the same signed UserOp can be replayed until the paymaster runs out of funds.

## Ship It

See `outputs/aa-zk-security-checklist.md` for a pre-deployment checklist covering smart-account validation, paymaster security, and bundler hardening.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe that `bad proof valid = False` and `bundle valid = True`.
2. Medium. Add account nonce enforcement: increment `account["nonce"]` after each successful validation and reject ops with stale nonces.
3. Hard. Replace the toy group with secp256k1 scalar multiplication (reuse `point_mul` from lesson 01) and implement a full BIP340-compatible Schnorr proof.

## Key Terms

| Term | What people say | What it actually means |
|---|---|---|
| ERC-4337 | "account abstraction" | Standard for smart contract wallets using UserOperations without protocol changes |
| UserOperation | "UserOp" | Pseudo-transaction object that encodes intent + authorization for a smart account |
| Bundler | "the bundler" | Off-chain node that validates and submits batches of UserOps to EntryPoint |
| Paymaster | "gas sponsor" | Contract that pays gas for a UserOp on behalf of the sender |
| Commitment | "public key" | `G^sk mod N` — stores the verifiable representation of the secret |
| Fiat-Shamir | "making it non-interactive" | Replacing the verifier's random challenge with a hash of the public inputs |
| NIZK | "ZK proof" | Non-Interactive Zero-Knowledge proof — proves knowledge without revealing it |

## Further Reading

- Buterin et al., [EIP-4337: Account Abstraction Using Alt Mempool](https://eips.ethereum.org/EIPS/eip-4337) (2021) — the canonical spec
- Schnorr, "Efficient Signature Generation by Smart Cards" (1991) — original sigma protocol
- Boneh & Shoup, [A Graduate Course in Applied Cryptography](https://toc.cryptobook.us/) ch. 19 — sigma protocols and Fiat-Shamir
- [eth-infinitism/account-abstraction](https://github.com/eth-infinitism/account-abstraction) — reference EntryPoint implementation
