import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (
    build_deterministic_targz_from_inmemory_files,
    canonical_json_bytes,
    ed25519_private_key_from_seed,
    manifest_from_inmemory_files,
    sha256_bytes,
    sign_tree_hash_hex,
    verify_tree_hash_signature,
)


def _data_bytes(file_obj: dict) -> bytes:
    has_ascii = "data_ascii" in file_obj
    has_hex = "data_hex" in file_obj
    if has_ascii and has_hex:
        raise ValueError("file must not include both data_ascii and data_hex")
    if has_ascii:
        v = file_obj["data_ascii"]
        if not isinstance(v, str):
            raise ValueError("data_ascii must be a string")
        return v.encode("utf-8")
    if has_hex:
        v = file_obj["data_hex"]
        if not isinstance(v, str):
            raise ValueError("data_hex must be a string")
        return bytes.fromhex(v)
    raise ValueError("file must include data_ascii or data_hex")


def _files_list(v: dict) -> list[tuple[str, bytes]]:
    files = v["files"]
    if not isinstance(files, list):
        raise ValueError("files must be a list")
    out: list[tuple[str, bytes]] = []
    for i, f in enumerate(files):
        if not isinstance(f, dict):
            raise ValueError(f"files[{i}] must be an object")
        path = f.get("path")
        if not isinstance(path, str) or not path:
            raise ValueError(f"files[{i}].path must be a non-empty string")
        out.append((path, _data_bytes(f)))
    return out


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]
        if op == "manifest_hash":
            files = _files_list(v)
            manifest = manifest_from_inmemory_files(files)
            got_manifest_sha256 = sha256_bytes(canonical_json_bytes(manifest))
            assert got_manifest_sha256 == v["expected_manifest_sha256"]
            assert manifest["tree_hash"] == v["expected_tree_hash"]
        elif op == "artifact_sha256":
            files = _files_list(v)
            artifact = build_deterministic_targz_from_inmemory_files(files)
            got = sha256_bytes(artifact)
            assert got == v["expected_sha256"]
        elif op == "ed25519_signature":
            seed = bytes.fromhex(v["seed_hex"])
            priv = ed25519_private_key_from_seed(seed)
            msg = v["tree_hash_hex"]
            sig = sign_tree_hash_hex(priv, msg)
            assert sig.hex() == v["expected_sig_hex"]
            ok = verify_tree_hash_signature(priv.public_key(), msg, sig)
            assert ok is True
        elif op == "ed25519_verify_fail":
            seed = bytes.fromhex(v["seed_hex"])
            priv = ed25519_private_key_from_seed(seed)
            msg = v["tree_hash_hex"]
            sig = bytes.fromhex(v["sig_hex"])
            ok = verify_tree_hash_signature(priv.public_key(), msg, sig)
            assert ok is False
        else:
            raise AssertionError(f"unknown op {op}")


if __name__ == "__main__":
    test_vectors()
    print("all vectors pass")

