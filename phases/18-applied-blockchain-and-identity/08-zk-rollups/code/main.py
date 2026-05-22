"""
ZK Rollups — How a Rollup Actually Verifies (educational).

Models a toy token-transfer state machine to demonstrate:
- State as a dict of {address: balance}
- Merkle-root state commitment (sha256 over sorted account pairs)
- Batch of transfers and state transition
- Toy "ZK proof" as a hash-based witness commitment
- R1CS constraint encoding of a single transfer

Run:
  python3 code/main.py
"""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _bytes_hex(b: bytes) -> str:
    return b.hex()


# ---------------------------------------------------------------------------
# State root
# ---------------------------------------------------------------------------

def state_root(state: dict[str, int]) -> bytes:
    """Compute a deterministic commitment to account balances.

    Sorts accounts by address, concatenates SHA-256(address || balance) pairs,
    then hashes the whole concatenation.
    """
    leaf_hashes = b""
    for addr in sorted(state.keys()):
        balance_bytes = state[addr].to_bytes(8, "big")
        leaf_hashes += _sha256(addr.encode() + balance_bytes)
    return _sha256(leaf_hashes)


def rollup_genesis_state(balances: dict[str, int]) -> dict:
    """Create initial state: {address: balance, ..., 'root': state_root_hex}"""
    for addr, bal in balances.items():
        if bal < 0:
            raise ValueError(f"negative genesis balance for {addr}")
    state = dict(balances)
    state["root"] = _bytes_hex(state_root({k: v for k, v in state.items() if k != "root"}))
    return state


# ---------------------------------------------------------------------------
# Transfer application
# ---------------------------------------------------------------------------

def _balances_only(state: dict) -> dict[str, int]:
    """Return state without the 'root' metadata key."""
    return {k: v for k, v in state.items() if k != "root"}


def rollup_apply_transfer(state: dict, tx: dict) -> dict:
    """Apply a single transfer {from, to, amount}. Returns new state or raises."""
    src = tx["from"]
    dst = tx["to"]
    amount = tx["amount"]

    if amount <= 0:
        raise ValueError(f"transfer amount must be positive, got {amount}")

    balances = _balances_only(state)

    if src not in balances:
        raise ValueError(f"sender {src!r} not in state")
    if dst not in balances:
        raise ValueError(f"recipient {dst!r} not in state")
    if balances[src] < amount:
        raise ValueError(
            f"insufficient balance: {src!r} has {balances[src]}, needs {amount}"
        )

    new_balances = dict(balances)
    new_balances[src] -= amount
    new_balances[dst] += amount

    new_state = dict(new_balances)
    new_state["root"] = _bytes_hex(state_root(new_balances))
    return new_state


def rollup_apply_batch(state: dict, txs: list[dict]) -> dict:
    """Apply batch of transfers. Returns new state."""
    current = state
    for tx in txs:
        current = rollup_apply_transfer(current, tx)
    return current


# ---------------------------------------------------------------------------
# Toy ZK proof
# ---------------------------------------------------------------------------

def rollup_prove_batch(old_state: dict, txs: list[dict], new_state: dict) -> dict:
    """Generate a toy 'ZK proof' (hash-based witness commitment).

    proof = {old_root, new_root, tx_hash, witness_hash}
    """
    old_balances = _balances_only(old_state)
    new_balances = _balances_only(new_state)

    old_root = state_root(old_balances)
    new_root = state_root(new_balances)

    tx_hash = _sha256(json.dumps(txs, sort_keys=True).encode())

    # Witness: all balance values before and after each transfer
    witness_str = str(sorted(old_balances.items())) + str(txs) + str(sorted(new_balances.items()))
    witness_hash = _sha256(witness_str.encode())

    return {
        "old_root": _bytes_hex(old_root),
        "new_root": _bytes_hex(new_root),
        "tx_hash": _bytes_hex(tx_hash),
        "witness_hash": _bytes_hex(witness_hash),
    }


def rollup_verify_proof(old_root: bytes, new_root: bytes, proof: dict) -> bool:
    """Verify the toy proof: checks that state roots in the proof match the provided roots."""
    if proof.get("old_root") != _bytes_hex(old_root):
        return False
    if proof.get("new_root") != _bytes_hex(new_root):
        return False
    # A real verifier would also re-execute constraints; here we check root consistency.
    return True


# ---------------------------------------------------------------------------
# R1CS constraint encoding
# ---------------------------------------------------------------------------

def r1cs_encode_transfer(from_bal: int, to_bal: int, amount: int) -> list[tuple]:
    """Encode transfer validity as R1CS constraints.

    Witness variables (by name):
      from_bal   : sender balance before
      to_bal     : recipient balance before
      amount     : transfer amount
      from_new   : sender balance after  = from_bal - amount
      to_new     : recipient balance after = to_bal + amount
      nonneg     : from_bal - amount  (must be >= 0; represented as a witness value)
      one        : constant 1

    Constraints returned as (a_coeffs, b_coeffs, c_coeffs) where each is a dict
    mapping witness variable names to integer coefficients.  The constraint is:
      (sum a_i * w_i) * (sum b_j * w_j) = (sum c_k * w_k)

    1. from_new = from_bal - amount
       Rewrite as: (from_bal - amount - from_new) * 1 = 0
       a = {from_bal:1, amount:-1, from_new:-1}, b = {one:1}, c = {}

    2. to_new = to_bal + amount
       Rewrite as: (to_bal + amount - to_new) * 1 = 0
       a = {to_bal:1, amount:1, to_new:-1}, b = {one:1}, c = {}

    3. nonneg = from_bal - amount  (and nonneg >= 0, checked separately)
       a = {from_bal:1, amount:-1, nonneg:-1}, b = {one:1}, c = {}
    """
    constraints = [
        # Constraint 1: from_new == from_bal - amount
        (
            {"from_bal": 1, "amount": -1, "from_new": -1},
            {"one": 1},
            {},
        ),
        # Constraint 2: to_new == to_bal + amount
        (
            {"to_bal": 1, "amount": 1, "to_new": -1},
            {"one": 1},
            {},
        ),
        # Constraint 3: nonneg == from_bal - amount  (non-negative check)
        (
            {"from_bal": 1, "amount": -1, "nonneg": -1},
            {"one": 1},
            {},
        ),
    ]
    return constraints


def r1cs_check_satisfied(constraints: list[tuple], witness: dict) -> bool:
    """Check all R1CS constraints are satisfied by witness values.

    Each constraint is (a, b, c) where a, b, c are dicts of {var: coeff}.
    The constraint holds when: dot(a, w) * dot(b, w) == dot(c, w).
    """
    def dot(coeffs: dict, w: dict) -> int:
        return sum(coeff * w.get(var, 0) for var, coeff in coeffs.items())

    for a, b, c in constraints:
        lhs = dot(a, witness) * dot(b, witness)
        rhs = dot(c, witness)
        if lhs != rhs:
            return False

    # Extra: non-negativity check on nonneg variable
    if "nonneg" in witness and witness["nonneg"] < 0:
        return False

    return True


# ---------------------------------------------------------------------------
# main demo
# ---------------------------------------------------------------------------

def main():
    print("=== Step 1: Genesis State ===")
    genesis = rollup_genesis_state({
        "alice": 100,
        "bob": 50,
        "carol": 75,
        "dave": 25,
    })
    for addr in ["alice", "bob", "carol", "dave"]:
        print(f"  {addr}: {genesis[addr]}")
    print(f"  state root: {genesis['root'][:32]}...")
    print()

    print("=== Step 2: Batch Transfers ===")
    batch = [
        {"from": "alice", "to": "bob",   "amount": 20},
        {"from": "carol", "to": "dave",  "amount": 10},
        {"from": "bob",   "to": "carol", "amount": 5},
    ]
    new_state = rollup_apply_batch(genesis, batch)
    for addr in ["alice", "bob", "carol", "dave"]:
        delta = new_state[addr] - genesis[addr]
        sign = "+" if delta >= 0 else ""
        print(f"  {addr}: {genesis[addr]} → {new_state[addr]}  ({sign}{delta})")
    print(f"  new state root: {new_state['root'][:32]}...")
    print()

    print("=== Step 3: Generate ZK Proof (toy) ===")
    old_balances = {k: v for k, v in genesis.items() if k != "root"}
    new_balances = {k: v for k, v in new_state.items() if k != "root"}
    old_root = state_root(old_balances)
    new_root = state_root(new_balances)
    proof = rollup_prove_batch(genesis, batch, new_state)
    print(f"  old_root:     {proof['old_root'][:32]}...")
    print(f"  new_root:     {proof['new_root'][:32]}...")
    print(f"  tx_hash:      {proof['tx_hash'][:32]}...")
    print(f"  witness_hash: {proof['witness_hash'][:32]}...")
    print()

    print("=== Step 4: Verify Proof ===")
    ok = rollup_verify_proof(old_root, new_root, proof)
    print(f"  Proof valid: {ok}")
    # Try with wrong old_root
    bad_root = bytes(32)
    bad_ok = rollup_verify_proof(bad_root, new_root, proof)
    print(f"  Wrong old_root rejected: {not bad_ok}")
    print()

    print("=== Step 5: R1CS Constraints ===")
    from_bal, to_bal, amount = 100, 50, 20
    from_new = from_bal - amount
    to_new   = to_bal   + amount
    nonneg   = from_bal - amount

    constraints = r1cs_encode_transfer(from_bal, to_bal, amount)
    print(f"  Transfer: {from_bal} → sender, {to_bal} → recipient, amount={amount}")
    print(f"  Number of R1CS constraints: {len(constraints)}")

    witness = {
        "from_bal": from_bal,
        "to_bal":   to_bal,
        "amount":   amount,
        "from_new": from_new,
        "to_new":   to_new,
        "nonneg":   nonneg,
        "one":      1,
    }
    satisfied = r1cs_check_satisfied(constraints, witness)
    print(f"  Constraints satisfied (valid transfer): {satisfied}")

    # Bad witness: sender can't cover the transfer
    bad_witness = dict(witness)
    bad_witness["nonneg"] = -5  # overdraft
    bad_satisfied = r1cs_check_satisfied(constraints, bad_witness)
    print(f"  Constraints satisfied (overdraft witness): {bad_satisfied}")


if __name__ == "__main__":
    main()
