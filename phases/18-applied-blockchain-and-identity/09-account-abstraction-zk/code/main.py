"""
Account Abstraction & ZK Accounts (educational): ERC-4337 UserOperation,
smart-account commitment, ECDSA-like ZK proof of key knowledge, Paymaster,
and Bundler flow.

This lesson models the "ZK proof" as a Schnorr identification protocol made
non-interactive via Fiat-Shamir — which IS a NIZK proof of knowledge of a
discrete logarithm (knowledge of sk such that G^sk = commitment mod N).

Toy group: multiplicative group Z_N* where N = 2**31 - 1 (Mersenne prime).
Group order = N - 1 = 2**31 - 2 (since N is prime, |Z_N*| = N-1).
Generator G = 3.

Run:
  python3 code/main.py
"""

from __future__ import annotations

import hashlib
import json

# ---------------------------------------------------------------------------
# Toy group parameters (Z_N* where N is a Mersenne prime)
# ---------------------------------------------------------------------------
_AA_N: int = 2**31 - 1        # Field prime (2147483647)
_AA_G: int = 3                 # Generator of Z_N*
_AA_ORDER: int = _AA_N - 1    # Group order = N - 1 (Fermat: a^(N-1) ≡ 1 mod N)


def _modinv(a: int, m: int) -> int:
    """Modular inverse via Fermat's little theorem (m must be prime)."""
    return pow(a, m - 2, m)


def _sha256_int(data: bytes) -> int:
    """SHA-256 digest as integer."""
    return int(hashlib.sha256(data).hexdigest(), 16)


def _op_hash(user_op: dict) -> int:
    """Canonical hash of a UserOperation (excluding the proof field)."""
    op_copy = {k: v for k, v in sorted(user_op.items()) if k != "proof"}
    serialised = json.dumps(op_copy, sort_keys=True, separators=(",", ":")).encode()
    return _sha256_int(serialised) % _AA_ORDER


# ---------------------------------------------------------------------------
# Smart account lifecycle
# ---------------------------------------------------------------------------

def aa_compute_address(owner_sk: int) -> str:
    """Deterministic account address = 0x + hex(G^sk mod N)[:16] (toy address)."""
    pk = pow(_AA_G, owner_sk, _AA_N)
    return "0x" + hex(pk)[2:].zfill(16)[:16]


def aa_create_account(owner_sk: int) -> dict:
    """Create a smart account with a commitment = G^sk mod N (public key).

    Fields:
      address    — deterministic toy address
      commitment — G^sk mod N (the on-chain public key / verifier state)
      nonce      — starts at 0, incremented per UserOp
    """
    commitment = pow(_AA_G, owner_sk, _AA_N)
    return {
        "address": aa_compute_address(owner_sk),
        "commitment": commitment,
        "nonce": 0,
    }


def aa_create_user_op(account: dict, calldata: bytes, max_fee: int) -> dict:
    """Create an unsigned UserOperation dict.

    Fields mirror ERC-4337: sender, nonce, calldata (hex), max_fee, proof.
    """
    return {
        "sender": account["address"],
        "nonce": account["nonce"],
        "calldata": calldata.hex(),
        "max_fee": max_fee,
        "proof": None,
    }


def aa_create_zk_proof(owner_sk: int, user_op: dict) -> tuple[int, int]:
    """Create a NIZK proof of knowledge of owner_sk (Schnorr / Fiat-Shamir).

    This is a sigma protocol for discrete-log knowledge:
      - Prover knows sk  such that  G^sk ≡ commitment (mod N)
    Made non-interactive by Fiat-Shamir:
      1. Choose deterministic nonce k = SHA256(sk || op_hash) mod ORDER
      2. Commitment R = G^k mod N
      3. Challenge  e = SHA256(R || commitment || op_hash) mod ORDER
      4. Response   s = (k + sk * e) mod ORDER

    Returns (R, s) — the proof (also a valid Schnorr signature).
    Scalars are computed mod (N-1) = group order.
    """
    commitment = pow(_AA_G, owner_sk, _AA_N)
    op_h = _op_hash(user_op)

    # Deterministic nonce (Fiat-Shamir style)
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


def aa_validate_user_op(account: dict, user_op: dict, proof: tuple[int, int]) -> bool:
    """Validate a UserOperation NIZK proof without knowing owner_sk.

    Schnorr verification:
      G^s ≡ R * commitment^e  (mod N)
    where e = SHA256(R || commitment || op_hash) mod ORDER.

    The verifier only needs (R, s, commitment) — the secret key is never revealed.
    """
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


# ---------------------------------------------------------------------------
# Paymaster
# ---------------------------------------------------------------------------

def aa_paymaster_check(user_op: dict, policy: dict) -> bool:
    """Check if a UserOperation is covered by a Paymaster policy.

    Policy fields:
      max_fee   — maximum sponsored fee (inclusive)
      whitelist — list of allowed sender addresses (empty = allow all)
    """
    if user_op["max_fee"] > policy.get("max_fee", 0):
        return False
    whitelist = policy.get("whitelist", [])
    if whitelist and user_op["sender"] not in whitelist:
        return False
    return True


# ---------------------------------------------------------------------------
# Bundler
# ---------------------------------------------------------------------------

def aa_bundle_ops(user_ops: list[dict]) -> dict:
    """Package validated UserOperations into a bundle.

    Returns:
      bundle_hash — SHA256 of canonical JSON of all ops (hex)
      ops         — list of user ops
      total_fee   — sum of max_fee across all ops
    """
    total_fee = sum(op["max_fee"] for op in user_ops)
    payload = json.dumps(user_ops, sort_keys=True, separators=(",", ":")).encode()
    bundle_hash = hashlib.sha256(payload).hexdigest()
    return {
        "bundle_hash": bundle_hash,
        "ops": user_ops,
        "total_fee": total_fee,
    }


def aa_verify_bundle(bundle: dict, accounts: list[dict]) -> bool:
    """Verify all UserOps in a bundle.

    Each op must have a valid proof and a matching account in `accounts`
    (matched by sender address).
    """
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


# ---------------------------------------------------------------------------
# main — demo walkthrough
# ---------------------------------------------------------------------------

def main() -> None:
    print("=== Step 1: Create Smart Account ===")
    owner_sk = 424242
    account = aa_create_account(owner_sk)
    print(f"owner_sk          = {owner_sk}")
    print(f"commitment (pk)   = {account['commitment']}")
    print(f"address           = {account['address']}")
    print(f"nonce             = {account['nonce']}")
    print()

    print("=== Step 2: Create UserOperation ===")
    calldata = b"\x12\x34transfer(0xBob,1000)"
    max_fee = 50_000
    user_op = aa_create_user_op(account, calldata, max_fee)
    print(f"sender            = {user_op['sender']}")
    print(f"nonce             = {user_op['nonce']}")
    print(f"calldata          = {user_op['calldata'][:20]}...")
    print(f"max_fee           = {user_op['max_fee']}")
    print()

    print("=== Step 3: Generate ZK Proof ===")
    proof = aa_create_zk_proof(owner_sk, user_op)
    R, s = proof
    print(f"proof.R           = {R}")
    print(f"proof.s           = {s}")
    print()

    print("=== Step 4: Validate UserOperation ===")
    user_op_with_proof = dict(user_op)
    user_op_with_proof["proof"] = (R, s)
    valid = aa_validate_user_op(account, user_op, proof)
    print(f"valid proof       = {valid}")

    # Wrong key should fail
    bad_sk = owner_sk + 1
    bad_proof = aa_create_zk_proof(bad_sk, user_op)
    invalid = aa_validate_user_op(account, user_op, bad_proof)
    print(f"bad proof valid   = {invalid}  (expected False)")
    print()

    print("=== Step 5: Bundler and Paymaster ===")
    # Second account
    sk2 = 7777
    acc2 = aa_create_account(sk2)
    op2 = aa_create_user_op(acc2, b"\xab\xcd", 30_000)
    proof2 = aa_create_zk_proof(sk2, op2)

    policy = {"max_fee": 100_000, "whitelist": [account["address"], acc2["address"]]}
    pm_ok1 = aa_paymaster_check(user_op, policy)
    pm_ok2 = aa_paymaster_check(op2, policy)
    print(f"paymaster op1     = {pm_ok1}")
    print(f"paymaster op2     = {pm_ok2}")

    # Build bundle with proofs attached
    op1_bundled = dict(user_op, proof=(R, s))
    op2_bundled = dict(op2, proof=proof2)
    bundle = aa_bundle_ops([op1_bundled, op2_bundled])
    print(f"bundle_hash       = {bundle['bundle_hash'][:16]}...")
    print(f"total_fee         = {bundle['total_fee']}")

    ok = aa_verify_bundle(bundle, [account, acc2])
    print(f"bundle valid      = {ok}")


if __name__ == "__main__":
    main()
