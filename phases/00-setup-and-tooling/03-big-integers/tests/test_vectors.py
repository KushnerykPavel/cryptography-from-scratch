import importlib.util
import json
import sys
from pathlib import Path


LESSON = Path(__file__).resolve().parents[1]
MODULE_PATH = LESSON / "code" / "main.py"
VECTORS_PATH = LESSON / "tests" / "vectors.json"


spec = importlib.util.spec_from_file_location("big_integers_main", MODULE_PATH)
main = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = main
spec.loader.exec_module(main)


def _b(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


def call(vector):
    op = vector["op"]

    if op == "os2ip":
        return main.os2ip(_b(vector["x_hex"]))
    if op == "i2osp":
        return main.i2osp(vector["x"], vector["x_len"]).hex()
    if op == "uint_to_bytes_be":
        length = vector.get("length", None)
        return main.uint_to_bytes_be(vector["x"], length).hex()
    if op == "split_uint_le_limbs":
        return main.split_uint_le_limbs(vector["x"], limb_bits=vector.get("limb_bits", 32))
    if op == "combine_uint_le_limbs":
        return main.combine_uint_le_limbs(vector["limbs"], limb_bits=vector.get("limb_bits", 32))
    if op == "add_le_limbs":
        return main.add_le_limbs(vector["a"], vector["b"], limb_bits=vector.get("limb_bits", 32))

    raise AssertionError(f"unknown op: {op}")


def test_vectors():
    vectors = json.loads(VECTORS_PATH.read_text())["vectors"]
    for vector in vectors:
        if "expected_error" in vector:
            try:
                call(vector)
            except ValueError as error:
                assert str(error) == vector["expected_error"]
            else:
                raise AssertionError(f"{vector['op']} did not raise")
            continue

        assert call(vector) == vector["expected"]


if __name__ == "__main__":
    test_vectors()
    print("vector harness passed")

