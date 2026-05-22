# ZK Rollups — How a Rollup Actually Verifies
> A rollup is a blockchain that proves its own correctness to a cheaper chain.

**Type:** Learn
**Languages:** Python
**Prerequisites:** Phase 09 · 04 (Merkle Trees), Phase 13 (ZK Engineering basics), Phase 18 · 01 (Bitcoin Stack)
**Time:** ~60 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain what a ZK rollup is and why it improves blockchain throughput.
- Compute a deterministic state root from account balances.
- Implement batch transfer application with balance conservation checks.
- Encode a single transfer as R1CS constraints and check witness satisfaction.
- Distinguish a toy hash-commitment proof from a real SNARK.

## The Problem

Layer-1 blockchains (Ethereum, Bitcoin) are deliberately slow — every node re-executes every transaction to agree on state. That costs roughly 15–30 transactions per second on Ethereum. DeFi, payments, and gaming need thousands per second.

ZK rollups solve this by moving execution off-chain: a sequencer applies hundreds of transactions, computes the new state, then posts a single cryptographic proof to L1. The proof is succinct — it takes a few milliseconds to verify on-chain regardless of how many transactions were batched — and it guarantees that every state transition was valid without re-running anything.

To audit a ZK rollup, write an integration layer, or review a bridge contract you need to understand three things: what "state" means in this model, how validity is encoded as arithmetic constraints (R1CS / Plonk), and what a verifier actually checks. This lesson builds each piece as runnable Python.

## The Concept

### The rollup pipeline

```
L2 users submit txs
       │
       ▼
 Sequencer batches txs
       │
       ▼
 Prover: old_state + txs → new_state + ZK proof
       │
       ▼
 L1 Verifier: check proof (milliseconds, ~200k gas)
 State root updated on-chain
```

### State root

The state is a map `{address → balance}`. To commit to this map on-chain we need a single hash — the *state root*:

```
state_root = SHA256( SHA256(addr_0 || bal_0) || SHA256(addr_1 || bal_1) || … )
```

Addresses are sorted before hashing so the root is deterministic regardless of insertion order.

### R1CS (Rank-1 Constraint System)

A ZK proof system doesn't execute code directly — it checks arithmetic constraints. A transfer `amount` from `A` to `B` is valid iff:

| Constraint | Meaning |
|-----------|---------|
| `from_new = from_bal - amount` | sender balance decreases correctly |
| `to_new = to_bal + amount` | recipient balance increases correctly |
| `nonneg = from_bal - amount ≥ 0` | sender can cover the transfer |

Each constraint is written as `(a · w) × (b · w) = (c · w)` where `w` is the witness vector and `a, b, c` are linear combinations (coefficient vectors). A SNARK prover creates a proof that all constraints are satisfied for some private witness, without revealing the witness itself.

### Toy proof vs real SNARK

| Property | This lesson | Real Groth16 / Plonk |
|----------|------------|----------------------|
| Proof size | 4 hashes (~128 bytes) | ~200 bytes (Groth16) |
| Zero-knowledge | No — verifier sees roots | Yes — nothing leaks |
| Succinctness | O(n) hashes | O(1) pairing operations |
| Trusted setup | None needed | Ceremony required (Groth16) |
| Soundness | Computational (SHA-256) | Cryptographic (elliptic pairings) |

The toy proof here demonstrates the *structure* — old root, new root, tx commitment, witness commitment — not the cryptographic guarantees.

## Build It

### Step 1: State root

```python
def state_root(state: dict[str, int]) -> bytes:
    leaf_hashes = b""
    for addr in sorted(state.keys()):
        balance_bytes = state[addr].to_bytes(8, "big")
        leaf_hashes += _sha256(addr.encode() + balance_bytes)
    return _sha256(leaf_hashes)
```

Sorting by address is the key insight: the same logical state always produces the same root. The two-level hash (per-account leaf then root) is a simplified Merkle tree with a single layer.

### Step 2: Genesis state

```python
def rollup_genesis_state(balances: dict[str, int]) -> dict:
    for addr, bal in balances.items():
        if bal < 0:
            raise ValueError(f"negative genesis balance for {addr}")
    state = dict(balances)
    state["root"] = _bytes_hex(state_root({k: v for k, v in state.items() if k != "root"}))
    return state
```

The genesis state is the initial account snapshot. The `root` field is stored alongside balances for convenience; functions that compute the next root strip it with `_balances_only`.

### Step 3: Apply a single transfer

```python
def rollup_apply_transfer(state: dict, tx: dict) -> dict:
    src, dst, amount = tx["from"], tx["to"], tx["amount"]
    if amount <= 0:
        raise ValueError(f"transfer amount must be positive, got {amount}")
    balances = _balances_only(state)
    if src not in balances:
        raise ValueError(f"sender {src!r} not in state")
    if dst not in balances:
        raise ValueError(f"recipient {dst!r} not in state")
    if balances[src] < amount:
        raise ValueError(f"insufficient balance: {src!r} has {balances[src]}, needs {amount}")
    new_balances = dict(balances)
    new_balances[src] -= amount
    new_balances[dst] += amount
    new_state = dict(new_balances)
    new_state["root"] = _bytes_hex(state_root(new_balances))
    return new_state
```

Every transfer check maps directly to an R1CS constraint (Step 5). This is the executable specification that the prover encodes as arithmetic.

### Step 4: Batch and toy proof

```python
def rollup_apply_batch(state: dict, txs: list[dict]) -> dict:
    current = state
    for tx in txs:
        current = rollup_apply_transfer(current, tx)
    return current

def rollup_prove_batch(old_state, txs, new_state) -> dict:
    old_root    = state_root(_balances_only(old_state))
    new_root    = state_root(_balances_only(new_state))
    tx_hash     = _sha256(json.dumps(txs, sort_keys=True).encode())
    witness_str = str(sorted(_balances_only(old_state).items())) + str(txs) + \
                  str(sorted(_balances_only(new_state).items()))
    witness_hash = _sha256(witness_str.encode())
    return {
        "old_root":     _bytes_hex(old_root),
        "new_root":     _bytes_hex(new_root),
        "tx_hash":      _bytes_hex(tx_hash),
        "witness_hash": _bytes_hex(witness_hash),
    }

def rollup_verify_proof(old_root: bytes, new_root: bytes, proof: dict) -> bool:
    if proof.get("old_root") != _bytes_hex(old_root):
        return False
    if proof.get("new_root") != _bytes_hex(new_root):
        return False
    return True
```

`tx_hash` binds the verifier to a specific batch so the proof cannot be replayed with different transactions. `witness_hash` represents the prover's commitment to the execution trace — in a real system this would be a polynomial commitment.

### Step 5: R1CS constraints

```python
def r1cs_encode_transfer(from_bal, to_bal, amount) -> list[tuple]:
    return [
        # from_new == from_bal - amount
        ({"from_bal": 1, "amount": -1, "from_new": -1}, {"one": 1}, {}),
        # to_new == to_bal + amount
        ({"to_bal": 1, "amount": 1, "to_new": -1},     {"one": 1}, {}),
        # nonneg == from_bal - amount  (checked >= 0 separately)
        ({"from_bal": 1, "amount": -1, "nonneg": -1},  {"one": 1}, {}),
    ]

def r1cs_check_satisfied(constraints, witness) -> bool:
    def dot(coeffs, w):
        return sum(c * w.get(v, 0) for v, c in coeffs.items())
    for a, b, c in constraints:
        if dot(a, witness) * dot(b, witness) != dot(c, witness):
            return False
    if "nonneg" in witness and witness["nonneg"] < 0:
        return False
    return True
```

Each `(a, b, c)` tuple encodes one multiplication gate: `(a·w) * (b·w) = c·w`. When `b = {one: 1}` the gate degenerates to a linear check — exactly what addition and subtraction need. The non-negativity check is a range constraint; in Plonk/Groth16 this becomes a range proof sub-circuit.

Run it:
```
python3 code/main.py
```

Expected output (roots truncated):
```
=== Step 1: Genesis State ===
  alice: 100  bob: 50  carol: 75  dave: 25
  state root: 27937d7c...

=== Step 2: Batch Transfers ===
  alice: 100 → 80  (-20)
  ...

=== Step 4: Verify Proof ===
  Proof valid: True
  Wrong old_root rejected: True

=== Step 5: R1CS Constraints ===
  Constraints satisfied (valid transfer): True
  Constraints satisfied (overdraft witness): False
```

## Use It

| Component | Production library | Notes |
|-----------|-------------------|-------|
| ZK proof generation | `gnark` (Go), `circom` + `snarkjs` (JS) | Groth16 / Plonk circuits |
| EVM verifier | Solidity `Verifier.sol` generated by snarkjs | ~200k gas per proof |
| State management | `zksync-era` SDK, `starknet.py` | Full rollup stacks |
| R1CS / constraint writing | `arkworks-rs` (Rust), `halo2` (Rust) | Production constraint systems |
| Merkle state | `sparse-merkle-tree` (JS/Rust) | Sparse trees for large account sets |

## Pitfalls

1. **Non-deterministic state root.** If addresses are not sorted before hashing, the same account set can produce different roots on different machines. Always sort before committing.
2. **Total supply not conserved.** Every transfer must satisfy `sum(balances_after) == sum(balances_before)`. Add an assertion in your batch verifier or an explicit conservation constraint.
3. **Replay attacks on proofs.** A proof without a tx commitment (`tx_hash`) can be replayed with a different batch that happens to transition between the same roots. Always include the transaction data in the proof.
4. **Confusing L1 and L2 state roots.** The L1 contract stores the last verified L2 state root. A sequencer posting a proof for the wrong previous root will be rejected. Track `old_root` → `new_root` chains carefully.
5. **Range constraints are hard.** Non-negativity (`from_bal >= amount`) requires a bit decomposition or lookup argument in real R1CS. The toy `nonneg >= 0` check here is not zero-knowledge and is not encoded as a multiplication gate.

## Ship It

This lesson produces `outputs/zk-rollup-checklist.md` — a checklist for auditing a ZK rollup implementation. Use it when reviewing a rollup bridge contract, a prover implementation, or an L2 sequencer.

## Exercises

1. **Easy.** Run `python3 code/main.py`. Add a fifth account `"eve": 0` to the genesis and observe how the state root changes.
2. **Medium.** Add a `rollup_total_supply(state)` function and assert it is conserved after every batch. Try crafting a batch that would break conservation and confirm your assertion catches it.
3. **Hard.** Replace the toy `witness_hash` proof with a real Merkle inclusion proof: implement a proper binary Merkle tree for account balances and prove that a specific account's balance is included in the state root without revealing other accounts.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|------------------------|
| Rollup | "L2" | An off-chain execution environment that posts compressed state + proof to L1 |
| State root | "root hash" | A single hash committing to the entire account balance map |
| Sequencer | "the node" | The entity that orders and batches transactions on L2 |
| Prover | "the ZK prover" | Generates a succinct proof that the batch was executed correctly |
| Witness | "the trace" | The private intermediate values (balances, amounts) that satisfy the constraints |
| R1CS | "the circuit" | Rank-1 Constraint System — arithmetic equations the witness must satisfy |
| SNARK | "the proof" | Succinct Non-interactive ARgument of Knowledge — small, fast-to-verify proof |
| Groth16 | "the proving scheme" | A pairing-based SNARK with ~200-byte proofs and millisecond verification |

## Further Reading

- Buterin, *An Incomplete Guide to Rollups* (2021, vitalik.eth.lv) — intuitive overview of optimistic vs ZK rollups
- Ben-Sasson et al., *Scalable, transparent, and post-quantum secure computational integrity* (2018) — the STARKs paper
- Groth, *On the Size of Pairing-based Non-interactive Arguments* (2016) — the Groth16 construction
- Boneh & Shoup, *A Graduate Course in Applied Cryptography* Ch. 22 (2023) — SNARKs from first principles
- zkSync documentation, *How zkSync Era Works* (2024) — production rollup architecture walkthrough
