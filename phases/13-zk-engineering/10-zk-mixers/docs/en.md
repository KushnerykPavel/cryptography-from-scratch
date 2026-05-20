# ZK Privacy — Tornado-Style Mixers
> Privacy = commitments in an accumulator + a nullifier “spent set”.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** Phase 9 · 04 (Merkle Trees), Phase 13 · 01 (Circom Circuits), Phase 13 · 08 (On-Chain Verifiers)  
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** how a Tornado-style mixer achieves unlinkability using commitments + a Merkle root.
- **Compute** a Merkle root and inclusion path for a deposit commitment.
- **Implement** a toy mixer verifier: membership check + nullifier double-spend prevention.
- **Distinguish** public inputs (root, nullifier hash, recipient) from private witness (leaf index, Merkle path, secrets).
- **Apply** an integration checklist to avoid common mixer failures (proof theft, reorgs, UX leaks).

## The Problem

You want to pay someone without revealing *which* of your earlier deposits funded the payment. On a public ledger, that’s hard: every transaction and account balance is linkable by default. If you “just use a new address,” chain analysis still often links you through timing, amount patterns, and intermediate hops.

Mixers (like Tornado Cash) solve a narrower problem: you deposit into a fixed-size anonymity set, then later withdraw in a way that proves *some deposit* is being spent, without revealing which one. If implemented correctly, observers can’t link the withdrawal to a specific deposit.

The tricky part is not the word “ZK” — it’s the engineering surface area: how deposits are accumulated, how withdrawals prevent double spends, what’s public vs private, how proofs are bound to recipients to stop mempool theft, and what operational mistakes quietly destroy privacy.

## The Concept

A Tornado-style mixer is built from three ideas:

1) **A note** you keep off-chain  
You generate two random 256-bit values:
- `secret` (private)
- `nullifier` (private)

You store a note like `mixer-v1:<secret_hex>:<nullifier_hex>`. Losing the note means losing the funds.

2) **A commitment** you publish on-chain  
You compute:

`commitment = H(secret, nullifier)`

and deposit it. The contract stores commitments as leaves in an append-only Merkle tree. The Merkle root is a compact commitment to the full set of deposits.

3) **A withdrawal statement** the chain can verify  
To withdraw, you publish (as public inputs):
- `root` — which deposit set you’re claiming membership in
- `nullifier_hash = H(nullifier)` — unique tag for the note, used for double-spend prevention
- `recipient`, `relayer`, `fee` — who gets paid, who relays, and what fee is allowed

And you provide a ZK proof that:
- you know `(secret, nullifier)` such that `commitment = H(secret, nullifier)` is a leaf in the Merkle tree for `root`
- the `nullifier_hash` matches your `nullifier`

In a real SNARK/PLONK, the Merkle path and leaf index are **private witness**. In this lesson we do not build a SNARK, so our “proof” includes the Merkle path and leaks the leaf index. That’s fine: we’re learning the invariants and what must be bound.

Public vs private at a glance:

| Item | Where it lives | Why it exists |
|---|---|---|
| `commitment` | on-chain (leaf) | Adds you to the anonymity set |
| `root` | on-chain (public input) | Freezes the set you claim membership in |
| `nullifier_hash` | on-chain (public input + spent set) | Prevents double spending without revealing the deposit |
| `recipient/relayer/fee` | on-chain (public input) | Prevents proof theft + supports relayed withdrawals |
| Merkle path + leaf index | private witness (in real ZK) | Proves membership without revealing which leaf |
| `secret/nullifier` | private witness | The secret material behind the note |

## Build It

### Step 1: Notes, commitments, and nullifiers
```python
NOTE_PREFIX = "mixer-v1"
NOTE_PART_LEN = 32  # bytes (256-bit secrets / nullifiers)


def format_note(secret: bytes, nullifier: bytes) -> str:
    if not isinstance(secret, (bytes, bytearray)) or not isinstance(nullifier, (bytes, bytearray)):
        raise TypeError("secret and nullifier must be bytes")
    secret_b = bytes(secret)
    nullifier_b = bytes(nullifier)
    if len(secret_b) != NOTE_PART_LEN or len(nullifier_b) != NOTE_PART_LEN:
        raise ValueError(f"secret/nullifier must be {NOTE_PART_LEN} bytes")
    return f"{NOTE_PREFIX}:{secret_b.hex()}:{nullifier_b.hex()}"


def commitment(secret: bytes, nullifier: bytes) -> bytes:
    if not isinstance(secret, (bytes, bytearray)) or not isinstance(nullifier, (bytes, bytearray)):
        raise TypeError("secret and nullifier must be bytes")
    secret_b = bytes(secret)
    nullifier_b = bytes(nullifier)
    if len(secret_b) != NOTE_PART_LEN or len(nullifier_b) != NOTE_PART_LEN:
        raise ValueError(f"secret/nullifier must be {NOTE_PART_LEN} bytes")
    return tagged_hash("mixer.commitment.v1", secret_b, nullifier_b)


def nullifier_hash(nullifier: bytes) -> bytes:
    if not isinstance(nullifier, (bytes, bytearray)):
        raise TypeError("nullifier must be bytes")
    nullifier_b = bytes(nullifier)
    if len(nullifier_b) != NOTE_PART_LEN:
        raise ValueError(f"nullifier must be {NOTE_PART_LEN} bytes")
    return tagged_hash("mixer.nullifier.v1", nullifier_b)
```

The mixer note never goes on-chain. The chain sees only `commitment` (deposit) and later `nullifier_hash` (withdraw). If the same `nullifier_hash` appears twice, the second spend is rejected.

### Step 2: Append-only Merkle tree for deposits
```python
def merkle_leaf_hash(leaf: bytes) -> bytes:
    if not isinstance(leaf, (bytes, bytearray)):
        raise TypeError("leaf must be bytes")
    return sha256(b"\x00" + bytes(leaf))


def merkle_node_hash(left: bytes, right: bytes) -> bytes:
    if not isinstance(left, (bytes, bytearray)) or not isinstance(right, (bytes, bytearray)):
        raise TypeError("node children must be bytes")
    return sha256(b"\x01" + bytes(left) + bytes(right))


def merkle_root(leaves: Sequence[bytes]) -> bytes:
    if not isinstance(leaves, (list, tuple)):
        raise TypeError("leaves must be a list/tuple of bytes")
    if len(leaves) == 0:
        return sha256(b"")

    level = [merkle_leaf_hash(leaf) for leaf in leaves]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level = level + [level[-1]]
        nxt = []
        for i in range(0, len(level), 2):
            nxt.append(merkle_node_hash(level[i], level[i + 1]))
        level = nxt
    return level[0]
```

The Merkle root is a compact commitment to the deposit set. Withdrawals prove membership against a root.

### Step 3: Bind withdrawals to recipient/relayer/fee (mempool theft defense)
```python
@dataclass(frozen=True)
class WithdrawalStatement:
    root_hex: str
    nullifier_hash_hex: str
    recipient: str
    relayer: str
    fee_wei: int


def withdrawal_digest(statement: WithdrawalStatement) -> str:
    root = bytes.fromhex(statement.root_hex)
    nf = bytes.fromhex(statement.nullifier_hash_hex)
    recipient_b = address_bytes(statement.recipient)
    relayer_b = address_bytes(statement.relayer)
    fee_b = int(statement.fee_wei).to_bytes(32, "big")
    return tagged_hash("mixer.withdraw_statement.v1", root, nf, recipient_b, relayer_b, fee_b).hex()
```

If the proof statement does *not* commit to the recipient, an attacker can copy a pending withdrawal and redirect funds. Tornado-style mixers commit to these values in-circuit, so changing them breaks verification.

### Step 4: Prove/verify a withdrawal (not ZK — we reveal the path)
```python
def prove_withdrawal(
    leaves: Sequence[bytes],
    secret: bytes,
    nullifier: bytes,
    leaf_index: int,
    recipient: str,
    relayer: str,
    fee_wei: int,
) -> WithdrawalProof:
    com = commitment(secret, nullifier)
    if leaf_index < 0 or leaf_index >= len(leaves):
        raise IndexError("leaf_index out of range")
    if leaves[leaf_index] != com:
        raise ValueError("leaf at index does not match commitment(secret,nullifier)")

    root_hex = merkle_root(leaves).hex()
    statement = WithdrawalStatement(
        root_hex=root_hex,
        nullifier_hash_hex=nullifier_hash(nullifier).hex(),
        recipient=recipient,
        relayer=relayer,
        fee_wei=int(fee_wei),
    )
    proof_digest_hex = withdrawal_digest(statement)
    path = merkle_inclusion_proof(leaves, leaf_index)
    path_json = [{"side": side, "hash_hex": sib.hex()} for side, sib in path]
    return WithdrawalProof(
        statement=statement,
        leaf_index=leaf_index,
        merkle_path=path_json,
        proof_digest_hex=proof_digest_hex,
    )
```

This function mirrors what a prover *must* know and bind. In real ZK, the proof would not reveal `leaf_index` or the Merkle path; those are private witness.

### Step 5: Mixer state machine (deposits + spent nullifiers)
```python
class Mixer:
    def __init__(self):
        self._leaves: List[bytes] = []
        self._spent_nullifiers: set[bytes] = set()

    @property
    def leaves(self) -> List[bytes]:
        return list(self._leaves)

    def root_hex(self) -> str:
        return merkle_root(self._leaves).hex()

    def deposit(self, com: bytes) -> int:
        if not isinstance(com, (bytes, bytearray)) or len(bytes(com)) != 32:
            raise ValueError("commitment must be 32 bytes")
        self._leaves.append(bytes(com))
        return len(self._leaves) - 1

    def is_spent(self, nf_hash: bytes) -> bool:
        return bytes(nf_hash) in self._spent_nullifiers

    def mark_spent(self, nf_hash: bytes) -> None:
        self._spent_nullifiers.add(bytes(nf_hash))

    def withdraw(self, proof: WithdrawalProof) -> Dict[str, object]:
        if not verify_withdrawal(self._leaves, proof):
            raise ValueError("invalid withdrawal proof")
        nf = bytes.fromhex(proof.statement.nullifier_hash_hex)
        if self.is_spent(nf):
            raise ValueError("nullifier already spent (double spend)")
        self.mark_spent(nf)
        return {
            "recipient": proof.statement.recipient,
            "relayer": proof.statement.relayer,
            "fee_wei": proof.statement.fee_wei,
            "root_hex": proof.statement.root_hex,
            "nullifier_hash_hex": proof.statement.nullifier_hash_hex,
            "proof_digest_hex": proof.proof_digest_hex,
        }
```

The on-chain contract is basically this: store deposit commitments, store spent nullifiers, and verify the withdrawal statement/proof against a recent root.

Run it:
`python3 code/main.py`

## Use It

Production systems don’t “use a mixer library” so much as they compose multiple audited components:

- **Circuits**: Circom / Noir / Halo2 circuits that implement the membership + nullifier constraints and bind `recipient/relayer/fee`.
- **Merkle trees**: on-chain incremental Merkle tree logic (or off-chain tree + on-chain root registry).
- **ZK tooling**: snarkjs, halo2 tooling, or prover services; trusted setup considerations for Groth16.
- **Relayers**: infrastructure that submits withdrawals so the recipient address is not linked to the depositor’s funding address.
- **Wallet UX**: note storage, root selection, retry logic, and privacy-preserving timing defaults.

Concrete equivalents:
- Tornado Cash (historical): deposit commitments + Merkle roots + nullifiers + Groth16 proofs.
- Semaphore-style identity systems: also “Merkle membership with private leaf”, but the nullifier is usually per-signal to prevent double-votes.

## Pitfalls

1. **Proof theft (recipient not bound).** If the proof statement doesn’t commit to `recipient`, a mempool sniffer can steal withdrawals.
2. **Root freshness and reorgs.** If you accept any historical root forever, reorgs and root mismatches can break withdrawals; if you accept too few roots, UX becomes brittle.
3. **Nullifier set bugs.** If `nullifier_hash` isn’t unique per note (or can collide by construction), you can get false double-spends or real double-spends.
4. **Privacy leaks outside the proof.** Timing, gas price, and withdrawal patterns often deanonymize even “perfect” cryptography.
5. **Relayer trust assumptions.** Relayers can censor, overcharge, or leak metadata; build retry and fee caps into the statement.

## Ship It

Use `outputs/zk-mixer-integration-checklist.md` as a PR review and threat-model checklist for mixer-like systems (mixers, voting nullifiers, airdrop claim nullifiers). Paste it into issues/PRs and fill it out before you ship.

## Exercises

1. Easy: Run `python3 code/main.py`. Observe that changing the recipient breaks verification and a second withdrawal is rejected as a double spend.
2. Medium: Extend the demo to support a “root history” list (e.g., keep the last N roots) and add a test vector that withdraws against an older root.
3. Hard: Write a “privacy kill list” for your own app: list at least 10 non-cryptographic signals (timing, RPC provider logs, withdrawal batching, fee patterns) that could still link deposit ↔ withdrawal and propose mitigations.

## Key Terms

| Term | What people say | What it actually means |
|---|---|---|
| Commitment | “a hash of a secret” | A value that binds to hidden data (`secret,nullifier`) without revealing it |
| Note | “the secret string” | The off-chain object you must keep to withdraw; losing it is losing funds |
| Merkle root | “a tree hash” | A compact commitment to the set of deposits you can withdraw from |
| Nullifier | “prevents double spend” | A per-note secret used to derive a public one-time tag for spending |
| Withdrawal statement | “public inputs” | The exact values the proof must bind: root + nullifier hash + recipient/fee |

## Further Reading

- “Tornado Cash” Documentation (2019–2022) — system architecture: commitments, Merkle tree, nullifiers, relayers.
- Barry WhiteHat et al., “Tornado Cash: Privacy on Ethereum” — design rationale and tradeoffs around root management and relayers.
- Vitalik Buterin, “An incomplete guide to rollups” (2021) — useful background on on-chain verification/integration and calldata tradeoffs.
