import json
import os
import sys

HERE = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as le  # noqa: E402


def _b(hex_str: str) -> bytes:
    if hex_str == "":
        return b""
    return bytes.fromhex(hex_str)


def test_vectors():
    with open(os.path.join(HERE, "vectors.json"), "r", encoding="utf-8") as f:
        data = json.load(f)

    for vec in data["vectors"]:
        op = vec["op"]
        if op == "md4_digest":
            got = le.md4_digest(_b(vec["msg_hex"])).hex()
        else:
            raise ValueError(f"unknown op in vectors.json: {op}")
        assert got == vec["expected_hex"], f"vector failed: op={op}"


def test_length_extension_forges_secret_prefix_mac():
    key = b"YELLOW_SUBMARINE"
    msg = b"comment=hello&admin=false"
    suffix = b"&admin=true"
    mac = le.secret_prefix_mac_md4(key, msg)

    forged_msg, forged_mac = le.md4_length_extension_attack(mac, msg, suffix, key_len_guess=len(key))
    assert le.secret_prefix_mac_md4(key, forged_msg) == forged_mac

    forged_msg2, forged_mac2 = le.md4_length_extension_attack(mac, msg, suffix, key_len_guess=len(key) + 1)
    assert le.secret_prefix_mac_md4(key, forged_msg2) != forged_mac2


if __name__ == "__main__":
    tests = [
        test_vectors,
        test_length_extension_forges_secret_prefix_mac,
    ]
    for t in tests:
        t()
    print("all tests pass")

