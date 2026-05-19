import json
import sys
import unittest
from pathlib import Path


THIS_DIR = Path(__file__).resolve().parent
CODE_DIR = THIS_DIR.parent / "code"
sys.path.insert(0, str(CODE_DIR))

import main as tls13  # noqa: E402


def _bhex(s: str) -> bytes:
    if s is None:
        return b""
    s = s.strip()
    if s == "":
        return b""
    return bytes.fromhex(s)


class TestVectors(unittest.TestCase):
    def test_vectors(self) -> None:
        vectors_path = THIS_DIR / "vectors.json"
        data = json.loads(vectors_path.read_text(encoding="utf-8"))
        for vec in data["vectors"]:
            name = vec.get("name", vec["op"])
            op = vec["op"]
            expected = _bhex(vec["expected"])

            if op == "hkdf_extract":
                got = tls13.hkdf_extract(
                    vec["hash"], _bhex(vec.get("salt", "")), _bhex(vec.get("ikm", ""))
                )
            elif op == "hkdf_expand":
                got = tls13.hkdf_expand(
                    vec["hash"],
                    _bhex(vec["prk"]),
                    _bhex(vec.get("info", "")),
                    int(vec["length"]),
                )
            elif op == "tls13_hkdf_label":
                got = tls13.tls13_hkdf_label(
                    length=int(vec["length"]),
                    label=str(vec["label"]),
                    context=_bhex(vec.get("context", "")),
                )
            elif op == "transcript_hash":
                messages = [_bhex(m) for m in vec.get("messages", [])]
                got = tls13.transcript_hash(vec["hash"], messages)
            elif op == "tls13_derive_secret":
                messages = [_bhex(m) for m in vec.get("messages", [])]
                got = tls13.tls13_derive_secret(
                    vec["hash"], _bhex(vec["secret"]), vec["label"], messages
                )
            elif op == "tls13_hkdf_expand_label":
                got = tls13.tls13_hkdf_expand_label(
                    hash_name=vec["hash"],
                    secret=_bhex(vec["secret"]),
                    label=vec["label"],
                    context=_bhex(vec.get("context", "")),
                    length=int(vec["length"]),
                )
            elif op == "tls13_finished_key":
                got = tls13.tls13_finished_key(vec["hash"], _bhex(vec["traffic_secret"]))
            elif op == "tls13_finished_verify_data":
                messages = [_bhex(m) for m in vec.get("messages", [])]
                got = tls13.tls13_finished_verify_data(
                    vec["hash"], _bhex(vec["finished_key"]), messages
                )
            else:
                raise AssertionError(f"unknown op: {op}")

            self.assertEqual(got, expected, f"vector failed: {name}")

    def test_hkdf_expand_zero_length(self) -> None:
        prk = b"\x11" * 32
        out = tls13.hkdf_expand("sha256", prk, b"info", 0)
        self.assertEqual(out, b"")

    def test_tls13_hkdf_label_rejects_nul(self) -> None:
        with self.assertRaises(ValueError):
            tls13.tls13_hkdf_label(16, "bad\x00label", b"")

    def test_transcript_hash_order_matters(self) -> None:
        a = b"A"
        b = b"B"
        h1 = tls13.transcript_hash("sha256", [a, b])
        h2 = tls13.transcript_hash("sha256", [b, a])
        self.assertNotEqual(h1, h2)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestVectors)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.wasSuccessful():
        print("all tests pass")
        raise SystemExit(0)
    raise SystemExit(1)

