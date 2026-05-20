"""On-chain verifiers: ABI encoding, range checks, and a "wrapper" generator.

This lesson is an engineering tutorial, not a full zkSNARK implementation.
It demonstrates (1) how verifier calldata is encoded, (2) why range checks
matter, (3) how to estimate verification cost at a very rough level, and
(4) how to generate a defensive Solidity wrapper around a verifier.

Run: python3 code/main.py
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


U256_MOD = 1 << 256

# BN254 scalar field order used by many Groth16 verifiers on EVM.
BN254_SCALAR_FIELD = (
    21888242871839275222246405745257275088548364400416034343698204186575808495617
)


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


def _hex(b: bytes) -> str:
    return "0x" + b.hex()


def main():
    meta = VerifierMeta(name="Groth16Verifier", expected_public_inputs=2)

    print("=== Step 1: uint256 words are 32-byte big-endian ===")
    x = 123456789
    w = encode_uint256(x)
    print(f"  x = {x}")
    print(f"  word = {_hex(w)}")
    print(f"  decode(word) = {decode_uint256(w)}")

    print()
    print("=== Step 2: ABI-encode (bytes, uint256[]) without a selector ===")
    proof_body = b"demo-proof-body"
    pub = [7, 42]
    encoded = abi_encode_verify_args(make_toy_proof("vk-demo", proof_body, pub), pub)
    print(f"  pubSignals = {pub}")
    print(f"  encoded args bytes = {len(encoded)}")
    proof2, pub2 = abi_decode_verify_args(encoded)
    print(f"  decoded pubSignals = {pub2}")
    print(f"  decoded proof bytes = {len(proof2)}")

    print()
    print("=== Step 3: range-check public signals (field elements) ===")
    validate_public_signals(pub2, expected_len=meta.expected_public_inputs, field_modulus=meta.field_modulus)
    ok = toy_verify_proof("vk-demo", proof2, pub2)
    print(f"  toy_verify_proof(...) = {ok}")
    bad_pub = [pub2[0], meta.field_modulus]
    try:
        validate_public_signals(bad_pub, expected_len=meta.expected_public_inputs, field_modulus=meta.field_modulus)
    except ValueError as e:
        print(f"  bad pubSignals rejected: {e}")

    print()
    print("=== Step 4: estimate gas + generate a defensive wrapper ===")
    est = estimate_bn254_groth16_verify_gas(
        public_input_count=meta.expected_public_inputs,
        pairing_pairs=4,
        calldata=encoded,
    )
    print(f"  rough gas estimate (BN254 Groth16 shape) = {est}")
    wrapper = generate_solidity_wrapper(meta)
    lines = wrapper.splitlines()
    print("  Solidity wrapper preview:")
    for line in lines[:12]:
        print("   ", line)


if __name__ == "__main__":
    main()
