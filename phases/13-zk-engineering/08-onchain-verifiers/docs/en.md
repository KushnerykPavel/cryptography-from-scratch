# On-Chain Verifiers — Calldata, Range Checks, and Defensive Wrappers
> Verifier math is fixed; integration bugs are optional.

**Type:** Build
**Languages:** Python
**Prerequisites:** `../01-circom`, `../02-snarkjs`, `../04-arkworks`
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** why on-chain verifiers fail in practice (integration, not cryptography)
- **Compute** ABI offsets and calldata gas for verifier calls
- **Implement** a minimal ABI encoder/decoder for `(bytes, uint256[])`
- **Distinguish** “uint256” (EVM) from “field element” (SNARK scalar field)
- **Apply** a defensive wrapper checklist before deploying verifiers

## The Problem

You generated a proof off-chain, `verify()` returns `true` locally, and yet your L1 contract rejects the transaction. Or worse: it accepts something you didn’t intend, because your “public inputs” are not validated as *field elements* (they’re just `uint256`).

On-chain verification is a brutal interface: it’s fixed-cost cryptography + an unforgiving ABI boundary. The proving system can be perfect and you still ship a broken verifier because you passed arguments in the wrong order, forgot to enforce `pubSignals.length`, or let a value exceed the SNARK scalar field.

This lesson builds a tiny, runnable model of the engineering surface area: ABI encoding/decoding, range checks, rough gas accounting, and generating a Solidity wrapper around a verifier you got from a tool (snarkjs/noir/halo2).

## The Concept

Think of an on-chain verifier as two layers:

| Layer | What it does | Typical bugs |
|---|---|---|
| **Cryptography** | Pairings / MSM / hashes on curve/field elements | Rare (tool-generated, heavily reused) |
| **Integration** | ABI, calldata layout, input validation, upgrades, domain separation | Common (app-specific glue) |

Three engineering facts that drive most incidents:

1. **ABI offsets are part of the interface.** For dynamic types (`bytes`, `uint256[]`) the head contains offsets. If you build calldata wrong, the verifier reads garbage.
2. **Public signals must be field elements.** `uint256` can hold values outside the circuit field; many verifiers must explicitly reject `pubSignals[i] >= SNARK_SCALAR_FIELD`.
3. **Gas is dominated by a few precompiles.** For Groth16-on-BN254, the pairing check has a large fixed component; calldata bytes cost adds a linear term that surprises people.

We’ll implement just enough ABI logic to make these points concrete.

## Build It

### Step 1: uint256 words and 32-byte padding
```python
U256_MOD = 1 << 256


def u256(value: int) -> int:
    if not isinstance(value, int):
        raise TypeError("u256 expects int")
    if value < 0 or value >= U256_MOD:
        raise ValueError("u256 out of range")
    return value


def int_to_be(value: int, length: int) -> bytes:
    if length < 0:
        raise ValueError("length must be non-negative")
    if value < 0:
        raise ValueError("value must be non-negative")
    if value >= 1 << (8 * length) and length != 0:
        raise ValueError("value does not fit in length bytes")
    return value.to_bytes(length, "big")


def be_to_int(data: bytes) -> int:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("be_to_int expects bytes")
    return int.from_bytes(data, "big")


def encode_uint256(value: int) -> bytes:
    return int_to_be(u256(value), 32)


def decode_uint256(word32: bytes) -> int:
    if not isinstance(word32, (bytes, bytearray)) or len(word32) != 32:
        raise ValueError("uint256 word must be 32 bytes")
    return be_to_int(word32)


def ceil32(n: int) -> int:
    if n < 0:
        raise ValueError("n must be non-negative")
    return (n + 31) // 32 * 32


def pad_right_32(data: bytes) -> bytes:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("pad_right_32 expects bytes")
    pad_len = ceil32(len(data)) - len(data)
    return bytes(data) + b"\x00" * pad_len
```
Every ABI word is 32 bytes. `uint256` is big-endian and left-padded with zeros; dynamic byte blobs are right-padded to a multiple of 32.

### Step 2: ABI-encode `(bytes, uint256[])` (strict mode)
```python
def abi_encode_bytes(data: bytes) -> bytes:
    return encode_uint256(len(data)) + pad_right_32(data)


def abi_decode_bytes(encoded: bytes, offset: int) -> bytes:
    if offset % 32 != 0:
        raise ValueError("offset must be 32-byte aligned")
    if offset < 0 or offset + 32 > len(encoded):
        raise ValueError("offset out of range")
    length = decode_uint256(encoded[offset : offset + 32])
    start = offset + 32
    end = start + length
    if end > len(encoded):
        raise ValueError("bytes length out of range")
    padded_end = offset + 32 + ceil32(length)
    if padded_end > len(encoded):
        raise ValueError("bytes padding out of range")
    if any(encoded[end:padded_end]):
        raise ValueError("non-zero padding in bytes")
    return encoded[start:end]


def abi_encode_uint256_array(values: list[int]) -> bytes:
    out = [encode_uint256(len(values))]
    out.extend(encode_uint256(v) for v in values)
    return b"".join(out)


def abi_decode_uint256_array(encoded: bytes, offset: int) -> list[int]:
    if offset % 32 != 0:
        raise ValueError("offset must be 32-byte aligned")
    if offset < 0 or offset + 32 > len(encoded):
        raise ValueError("offset out of range")
    n = decode_uint256(encoded[offset : offset + 32])
    base = offset + 32
    end = base + 32 * n
    if end > len(encoded):
        raise ValueError("array length out of range")
    return [decode_uint256(encoded[base + 32 * i : base + 32 * (i + 1)]) for i in range(n)]


def abi_encode_verify_args(proof: bytes, public_signals: list[int]) -> bytes:
    head_size = 2 * 32
    proof_tail = abi_encode_bytes(proof)
    sig_tail = abi_encode_uint256_array(public_signals)
    off_proof = head_size
    off_sig = head_size + len(proof_tail)
    return encode_uint256(off_proof) + encode_uint256(off_sig) + proof_tail + sig_tail


def abi_decode_verify_args(encoded: bytes) -> tuple[bytes, list[int]]:
    if len(encoded) < 64 or len(encoded) % 32 != 0:
        raise ValueError("encoded args must be >= 64 bytes and 32-byte aligned")
    off_proof = decode_uint256(encoded[0:32])
    off_sig = decode_uint256(encoded[32:64])
    if off_proof != 64:
        raise ValueError("expected proof tail immediately after head (strict mode)")
    if off_sig % 32 != 0:
        raise ValueError("signals offset not aligned")
    if off_sig < 64 or off_sig > len(encoded):
        raise ValueError("signals offset out of range")
    proof = abi_decode_bytes(encoded, off_proof)
    proof_tail_len = 32 + ceil32(len(proof))
    if off_sig != 64 + proof_tail_len:
        raise ValueError("expected signals tail immediately after proof tail (strict mode)")
    sigs = abi_decode_uint256_array(encoded, off_sig)
    return proof, sigs
```
This is the ABI shape you hit when your verifier takes `bytes` plus `uint256[]`. We implement a strict decoder that rejects ambiguous encodings (misaligned offsets, non-zero padding, tail gaps).

### Step 3: range checks (uint256 vs field element) + a toy “proof”
```python
import hashlib

BN254_SCALAR_FIELD = (
    21888242871839275222246405745257275088548364400416034343698204186575808495617
)


def validate_public_signals(
    public_signals: list[int], *, expected_len: int, field_modulus: int = BN254_SCALAR_FIELD
) -> None:
    if len(public_signals) != expected_len:
        raise ValueError("unexpected public signal count")
    for x in public_signals:
        if not isinstance(x, int):
            raise TypeError("public signals must be ints")
        if x < 0 or x >= field_modulus:
            raise ValueError("public signal out of field")


def toy_proof_digest(vk_id: str, proof_body: bytes, public_signals: list[int]) -> bytes:
    if not isinstance(vk_id, str):
        raise TypeError("vk_id must be str")
    h = hashlib.sha256()
    h.update(vk_id.encode("utf-8"))
    h.update(abi_encode_uint256_array(public_signals))
    h.update(proof_body)
    return h.digest()


def make_toy_proof(vk_id: str, proof_body: bytes, public_signals: list[int]) -> bytes:
    digest = toy_proof_digest(vk_id, proof_body, public_signals)
    return proof_body + digest


def toy_verify_proof(vk_id: str, proof: bytes, public_signals: list[int]) -> bool:
    if len(proof) < 32:
        return False
    body = proof[:-32]
    got = proof[-32:]
    want = toy_proof_digest(vk_id, body, public_signals)
    return got == want
```
On-chain, the verifier will interpret public signals as field elements. If you don’t enforce that in your wrapper, you’re relying on “whatever the autogenerated verifier happens to do”.

### Step 4: rough gas math + generate a Solidity wrapper
```python
from dataclasses import dataclass

def calldata_gas_cost(data: bytes, *, zero_cost: int = 4, nonzero_cost: int = 16) -> int:
    if zero_cost < 0 or nonzero_cost < 0:
        raise ValueError("gas costs must be non-negative")
    total = 0
    for b in data:
        total += zero_cost if b == 0 else nonzero_cost
    return total


@dataclass(frozen=True)
class BN254VerifierCostModel:
    ecadd_gas: int = 150
    ecmul_gas: int = 6000
    pairing_base_gas: int = 45000
    pairing_per_pair_gas: int = 34000


def estimate_bn254_groth16_verify_gas(
    *,
    public_input_count: int,
    pairing_pairs: int = 4,
    model: BN254VerifierCostModel = BN254VerifierCostModel(),
    calldata: bytes = b"",
) -> int:
    if public_input_count < 0:
        raise ValueError("public_input_count must be non-negative")
    if pairing_pairs < 0:
        raise ValueError("pairing_pairs must be non-negative")
    msm_muls = public_input_count + 1
    msm_adds = public_input_count
    gas = 0
    gas += msm_muls * model.ecmul_gas
    gas += msm_adds * model.ecadd_gas
    if pairing_pairs:
        gas += model.pairing_base_gas + pairing_pairs * model.pairing_per_pair_gas
    gas += calldata_gas_cost(calldata)
    return gas


@dataclass(frozen=True)
class VerifierMeta:
    name: str
    expected_public_inputs: int
    field_modulus: int = BN254_SCALAR_FIELD
    proof_is_bytes: bool = True


def generate_solidity_wrapper(meta: VerifierMeta) -> str:
    if meta.expected_public_inputs < 0:
        raise ValueError("expected_public_inputs must be non-negative")
    n = meta.expected_public_inputs
    p = meta.field_modulus
    name = meta.name
    return "\n".join(
        [
            "pragma solidity ^0.8.20;",
            "",
            f"interface I{name} {{",
            "    function verifyProof(bytes calldata proof, uint256[] calldata pubSignals) external view returns (bool);",
            "}",
            "",
            f"contract {name}Wrapper {{",
            f"    I{name} public immutable verifier;",
            "",
            f"    uint256 constant SNARK_SCALAR_FIELD = {p};",
            f"    uint256 constant EXPECTED_PUBSIGNALS = {n};",
            "",
            f"    constructor(address verifier_) {{ verifier = I{name}(verifier_); }}",
            "",
            "    function verify(bytes calldata proof, uint256[] calldata pubSignals) external view returns (bool) {",
            "        if (pubSignals.length != EXPECTED_PUBSIGNALS) return false;",
            "        unchecked {",
            "            for (uint256 i = 0; i < pubSignals.length; i++) {",
            "                if (pubSignals[i] >= SNARK_SCALAR_FIELD) return false;",
            "            }",
            "        }",
            "        return verifier.verifyProof(proof, pubSignals);",
            "    }",
            "}",
            "",
        ]
    )
```
The point of this wrapper is not to re-implement the verifier. It’s to enforce “app invariants” (expected length, field range) *before* calling the autogenerated cryptography.

Run it:
python3 code/main.py

## Use It

Production equivalents:

- **Circom + snarkjs (Groth16/Plonk):** generate a Solidity verifier and calldata (`snarkjs zkey export solidityverifier ...`, `snarkjs zkey export soliditycalldata ...`).
- **Noir:** generates verifiers for target chains; you still wrap inputs and upgrade paths.
- **Halo2 / arkworks / gnark:** typically verify off-chain, or generate verifiers for specific runtimes (EVM, WASM, native); the boundary is always “bytes + public inputs”.

Rule of thumb: treat the autogenerated verifier as a *cryptographic library*. Put all application logic (input shaping, replay protection, upgrades, governance) outside it.

## Pitfalls

- **Missing `pubSignals.length` check:** a truncated array can pass decoding but represent a different statement.
- **Missing `SNARK_SCALAR_FIELD` check:** `uint256` is larger than the circuit field; out-of-range inputs can cause unexpected behavior or verification mismatches.
- **Wrong calldata ordering / offsets:** proof and public inputs swapped is a common integration bug when “proof” is passed as `bytes` instead of a fixed struct.
- **Upgradable verifier without VK pinning:** changing the verifier changes the statement being proven; treat verifier changes like consensus upgrades.
- **Assuming gas is “just precompiles”:** calldata bytes and memory expansion can matter, especially when batching proofs or using large public input vectors.

## Ship It

Save the on-chain verifier review checklist in `outputs/onchain-verifier-wrapper-checklist.md`. Use it as:

- a PR review template whenever you integrate a new circuit/verifier,
- an audit checklist for upgrades (new verification key, new circuit, new chain),
- a deploy gate (“no checkmark → no mainnet deploy”).

## Exercises

1. Easy. Run `python3 code/main.py`. Observe the ABI-encoded length and how decoding recovers `(proof, pubSignals)`.
2. Medium. Add a third public input and update `expected_public_inputs`. Re-run and compare the rough gas estimate.
3. Hard. Extend the wrapper generator to also enforce a maximum `proof.length` (or exact proof length) and to include an allowlist of acceptable verifier addresses (simulating key rotation governance).

## Key Terms

| Term | What people say | What it actually means |
|---|---|---|
| ABI encoding | “How Solidity packs arguments” | A deterministic byte layout with 32-byte words and offsets for dynamic types |
| Public signals | “Public inputs” | The circuit’s public field elements, not arbitrary `uint256` |
| SNARK scalar field | “The modulus” | The prime that defines valid field element range for signals/scalars |
| Verifier wrapper | “Glue code” | A contract that enforces app invariants before calling an autogenerated verifier |
| Precompile | “Built-in crypto” | A special address with native execution for expensive primitives (pairings/MSM) |

## Further Reading

- Ethereum EIP-1108, *Reduce alt_bn128 precompile gas costs* (2018) — why Groth16 verification became practical on-chain.
- Ethereum EIP-2028, *Transaction data gas cost reduction* (2019) — calldata bytes became cheaper, changing rollup economics.
- Solidity docs, *Contract ABI Specification* — the authoritative head/tail and offset rules for dynamic arguments.
