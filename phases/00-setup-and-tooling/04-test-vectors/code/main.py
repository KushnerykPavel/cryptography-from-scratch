from __future__ import annotations

import hashlib
import json
from pathlib import Path


def _hex_value(ch: str) -> int:
    o = ord(ch)
    if 48 <= o <= 57:
        return o - 48
    if 97 <= o <= 102:
        return o - 97 + 10
    if 65 <= o <= 70:
        return o - 65 + 10
    raise ValueError(f"non-hex character: {ch!r}")


def hex_decode(hex_str: str) -> bytes:
    if len(hex_str) % 2 != 0:
        raise ValueError("hex string must have even length")
    out = bytearray()
    for i in range(0, len(hex_str), 2):
        hi = _hex_value(hex_str[i])
        lo = _hex_value(hex_str[i + 1])
        out.append((hi << 4) | lo)
    return bytes(out)


def _ensure(cond: bool, msg: str) -> None:
    if not cond:
        raise ValueError(msg)


def load_vectors_file(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    validate_vectors_file(data)
    return data


def validate_vectors_file(data: object) -> None:
    _ensure(isinstance(data, dict), "vectors file must be a JSON object")
    _ensure(isinstance(data.get("source"), str) and data["source"].strip(), "missing 'source' string")
    vectors = data.get("vectors")
    _ensure(isinstance(vectors, list), "missing 'vectors' list")

    for i, v in enumerate(vectors):
        _ensure(isinstance(v, dict), f"vector[{i}] must be an object")
        _ensure(isinstance(v.get("op"), str) and v["op"].strip(), f"vector[{i}] missing 'op' string")
        has_expected = "expected" in v
        has_error = "expected_error" in v
        _ensure(has_expected ^ has_error, f"vector[{i}] must contain exactly one of expected/expected_error")
        if has_error:
            _ensure(isinstance(v["expected_error"], str), f"vector[{i}] expected_error must be a string")


def _message_bytes(vector: dict) -> bytes:
    has_ascii = "msg_ascii" in vector
    has_hex = "msg_hex" in vector
    if has_ascii and has_hex:
        raise ValueError("vector must not include both msg_ascii and msg_hex")
    if has_ascii:
        msg = vector["msg_ascii"]
        if not isinstance(msg, str):
            raise ValueError("msg_ascii must be a string")
        return msg.encode("utf-8")
    if has_hex:
        msg_hex = vector["msg_hex"]
        if not isinstance(msg_hex, str):
            raise ValueError("msg_hex must be a string")
        return hex_decode(msg_hex)
    raise ValueError("vector must include msg_ascii or msg_hex")


def _dispatch(vector: dict):
    op = vector["op"]

    if op == "sha256":
        msg = _message_bytes(vector)
        return hashlib.sha256(msg).hexdigest()

    if op == "hex_decode":
        hx = vector.get("hex", None)
        if not isinstance(hx, str):
            raise ValueError("hex must be a string")
        return hex_decode(hx).hex()

    raise ValueError(f"unknown op: {op}")


def run_vectors(vectors: list[dict]) -> None:
    for i, v in enumerate(vectors):
        if "expected_error" in v:
            try:
                _dispatch(v)
            except ValueError as err:
                if str(err) != v["expected_error"]:
                    raise AssertionError(
                        f"vector[{i}] wrong error: got {str(err)!r}, expected {v['expected_error']!r}"
                    ) from err
            else:
                raise AssertionError(f"vector[{i}] expected error but did not raise")
            continue

        got = _dispatch(v)
        expected = v["expected"]
        if got != expected:
            raise AssertionError(f"vector[{i}] mismatch: got {got!r}, expected {expected!r}")


def main() -> None:
    lesson_dir = Path(__file__).resolve().parents[1]
    vectors_path = lesson_dir / "tests" / "vectors.json"

    data = load_vectors_file(vectors_path)
    vectors = data["vectors"]
    run_vectors(vectors)

    print("Test vectors harness: OK")
    print(f"Source: {data['source']}")
    print(f"Vectors: {len(vectors)}")


if __name__ == "__main__":
    main()
