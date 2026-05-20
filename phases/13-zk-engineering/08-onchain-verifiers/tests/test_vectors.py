import json
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
CODE_DIR = HERE.parent / "code"
sys.path.insert(0, str(CODE_DIR))

import main as m  # noqa: E402


def _hex(b: bytes) -> str:
    return "0x" + b.hex()


def _unhex(s: str) -> bytes:
    if not isinstance(s, str) or not s.startswith("0x"):
        raise TypeError("expected 0x-prefixed hex string")
    return bytes.fromhex(s[2:])


def _load_vectors():
    p = HERE / "vectors.json"
    return json.loads(p.read_text(encoding="utf-8"))


def _run_vector(vec):
    op = vec["op"]
    inputs = vec["inputs"]
    expected = vec["expected"]

    if op == "encode_uint256":
        got = _hex(m.encode_uint256(inputs["value"]))
        assert got == expected
        return

    if op == "decode_uint256":
        got = m.decode_uint256(_unhex(inputs["word"]))
        assert got == expected
        return

    if op == "abi_encode_bytes":
        got = _hex(m.abi_encode_bytes(_unhex(inputs["data"])))
        assert got == expected
        return

    if op == "abi_encode_uint256_array":
        got = _hex(m.abi_encode_uint256_array(inputs["values"]))
        assert got == expected
        return

    if op == "abi_encode_verify_args":
        got = _hex(m.abi_encode_verify_args(_unhex(inputs["proof"]), inputs["public_signals"]))
        assert got == expected
        return

    if op == "abi_decode_verify_args":
        proof, pub = m.abi_decode_verify_args(_unhex(inputs["encoded"]))
        got = {"proof": _hex(proof), "public_signals": pub}
        assert got == expected
        return

    if op == "calldata_gas_cost":
        got = m.calldata_gas_cost(_unhex(inputs["data"]))
        assert got == expected
        return

    if op == "estimate_bn254_groth16_verify_gas":
        got = m.estimate_bn254_groth16_verify_gas(
            public_input_count=inputs["public_input_count"],
            pairing_pairs=inputs["pairing_pairs"],
            calldata=_unhex(inputs["calldata"]),
        )
        assert got == expected
        return

    if op == "toy_verify_proof":
        got = m.toy_verify_proof(inputs["vk_id"], _unhex(inputs["proof"]), inputs["public_signals"])
        assert got == expected
        return

    raise ValueError(f"unknown op: {op}")


def test_vectors():
    data = _load_vectors()
    for vec in data["vectors"]:
        _run_vector(vec)


def test_encode_decode_roundtrip():
    values = [0, 1, 2, 123456789, (1 << 255), (1 << 256) - 1]
    for v in values:
        assert m.decode_uint256(m.encode_uint256(v)) == v


def test_abi_roundtrip_verify_args():
    proof = m.make_toy_proof("vk-x", b"abc", [7, 42])
    encoded = m.abi_encode_verify_args(proof, [7, 42])
    proof2, pub2 = m.abi_decode_verify_args(encoded)
    assert proof2 == proof
    assert pub2 == [7, 42]


def test_abi_decode_rejects_non_strict_offsets():
    proof = m.make_toy_proof("vk-x", b"abc", [7, 42])
    encoded = m.abi_encode_verify_args(proof, [7, 42])
    tampered = bytearray(encoded)
    tampered[31] = 0x80
    try:
        m.abi_decode_verify_args(bytes(tampered))
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_validate_public_signals_rejects_out_of_field():
    ok = [0, m.BN254_SCALAR_FIELD - 1]
    m.validate_public_signals(ok, expected_len=2, field_modulus=m.BN254_SCALAR_FIELD)
    bad = [0, m.BN254_SCALAR_FIELD]
    try:
        m.validate_public_signals(bad, expected_len=2, field_modulus=m.BN254_SCALAR_FIELD)
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_toy_proof_tamper_fails():
    pub = [7, 42]
    proof = m.make_toy_proof("vk-x", b"abc", pub)
    assert m.toy_verify_proof("vk-x", proof, pub) is True
    tampered = proof[:-1] + bytes([proof[-1] ^ 1])
    assert m.toy_verify_proof("vk-x", tampered, pub) is False


def test_calldata_gas_monotone_per_byte():
    z = b"\x00"
    nz = b"\x01"
    assert m.calldata_gas_cost(z) < m.calldata_gas_cost(nz)


if __name__ == "__main__":
    try:
        import pytest  # type: ignore
    except ModuleNotFoundError:
        test_vectors()
        test_encode_decode_roundtrip()
        test_abi_roundtrip_verify_args()
        test_abi_decode_rejects_non_strict_offsets()
        test_validate_public_signals_rejects_out_of_field()
        test_toy_proof_tamper_fails()
        test_calldata_gas_monotone_per_byte()
        print("all tests pass")
        raise SystemExit(0)
    else:
        rc = pytest.main([__file__])
        if rc == 0:
            print("all tests pass")
        raise SystemExit(rc)
