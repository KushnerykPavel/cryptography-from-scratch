from __future__ import annotations

import argparse
import fnmatch
import gzip
import hashlib
import io
import json
import tarfile
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json_bytes(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _norm_relpath(p: str) -> str:
    s = p.replace("\\", "/")
    while s.startswith("./"):
        s = s[2:]
    if s.startswith("/"):
        s = s[1:]
    if not s or s == ".":
        raise ValueError("invalid relative path")
    if "//" in s:
        while "//" in s:
            s = s.replace("//", "/")
    parts = s.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError("invalid relative path")
    return s


@dataclass(frozen=True)
class FileEntry:
    path: str
    size: int
    sha256: str


def manifest_from_inmemory_files(files: list[tuple[str, bytes]]) -> dict:
    entries: list[FileEntry] = []
    for p, data in files:
        rel = _norm_relpath(p)
        entries.append(FileEntry(path=rel, size=len(data), sha256=sha256_bytes(data)))
    entries.sort(key=lambda e: e.path)

    files_payload = [{"path": e.path, "size": e.size, "sha256": e.sha256} for e in entries]
    tree_hash = sha256_bytes(canonical_json_bytes({"files": files_payload}))
    return {"version": 1, "files": files_payload, "tree_hash": tree_hash}


def build_deterministic_targz_from_inmemory_files(files: list[tuple[str, bytes]]) -> bytes:
    normalized: list[tuple[str, bytes]] = [(_norm_relpath(p), data) for (p, data) in files]
    normalized.sort(key=lambda t: t[0])

    buf = io.BytesIO()
    gz = gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=9, mtime=0, filename="")
    with tarfile.open(fileobj=gz, mode="w|") as tf:
        for rel, data in normalized:
            ti = tarfile.TarInfo(rel)
            ti.size = len(data)
            ti.mtime = 0
            ti.uid = 0
            ti.gid = 0
            ti.uname = ""
            ti.gname = ""
            ti.mode = 0o644
            tf.addfile(ti, io.BytesIO(data))
    gz.close()
    return buf.getvalue()


def ed25519_private_key_from_seed(seed32: bytes) -> Ed25519PrivateKey:
    if len(seed32) != 32:
        raise ValueError("ed25519 seed must be 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(seed32)


def ed25519_public_key_bytes(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(Encoding.Raw, PublicFormat.Raw)


def ed25519_private_key_bytes(priv: Ed25519PrivateKey) -> bytes:
    return priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def sign_tree_hash_hex(priv: Ed25519PrivateKey, tree_hash_hex: str) -> bytes:
    msg = bytes.fromhex(tree_hash_hex)
    if len(msg) != 32:
        raise ValueError("tree_hash must be a 32-byte SHA-256 hex digest")
    return priv.sign(msg)


def verify_tree_hash_signature(pub: Ed25519PublicKey, tree_hash_hex: str, signature: bytes) -> bool:
    msg = bytes.fromhex(tree_hash_hex)
    if len(msg) != 32:
        raise ValueError("tree_hash must be a 32-byte SHA-256 hex digest")
    try:
        pub.verify(signature, msg)
    except Exception:
        return False
    return True


def _read_included_files(root: Path, include: tuple[str, ...], exclude: tuple[str, ...]) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    for p in sorted(root.rglob("*")):
        if p.is_dir():
            continue
        rel = p.relative_to(root).as_posix()
        if include and not any(fnmatch.fnmatch(rel, pat) for pat in include):
            continue
        if any(fnmatch.fnmatch(rel, pat) for pat in exclude):
            continue
        if p.is_symlink():
            raise ValueError(f"symlinks not supported: {rel}")
        out.append((rel, p.read_bytes()))
    return out


def build_release_bundle(
    *,
    root: Path,
    include: tuple[str, ...],
    exclude: tuple[str, ...],
    signing_seed32: bytes,
) -> tuple[bytes, dict, bytes, bytes]:
    files = _read_included_files(root, include, exclude)
    manifest = manifest_from_inmemory_files(files)
    artifact = build_deterministic_targz_from_inmemory_files(files)

    priv = ed25519_private_key_from_seed(signing_seed32)
    pub = priv.public_key()
    sig = sign_tree_hash_hex(priv, manifest["tree_hash"])
    pub_raw = ed25519_public_key_bytes(pub)

    return artifact, manifest, sig, pub_raw


def _cmd_demo() -> None:
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    files = [("README.txt", b"hello\n"), ("bin/tool.py", b"print('ok')\n")]

    manifest = manifest_from_inmemory_files(files)
    artifact = build_deterministic_targz_from_inmemory_files(files)

    priv = ed25519_private_key_from_seed(seed)
    pub = priv.public_key()
    sig = sign_tree_hash_hex(priv, manifest["tree_hash"])
    ok = verify_tree_hash_signature(pub, manifest["tree_hash"], sig)

    print("demo: deterministic artifact + signed manifest")
    print(f"  files: {len(manifest['files'])}")
    print(f"  tree_hash: {manifest['tree_hash']}")
    print(f"  artifact_sha256: {sha256_bytes(artifact)}")
    print(f"  signature_ok: {ok}")
    if not ok:
        raise SystemExit("signature verification failed")


def _cmd_build(args: argparse.Namespace) -> None:
    root = Path(args.root).resolve()
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    seed32 = bytes.fromhex(args.seed_hex)
    if len(seed32) != 32:
        raise SystemExit("seed must be 64 hex chars (32 bytes)")

    include = tuple(args.include or ())
    exclude = tuple(args.exclude or ())
    artifact, manifest, sig, pub_raw = build_release_bundle(
        root=root, include=include, exclude=exclude, signing_seed32=seed32
    )

    (out_dir / "release.tar.gz").write_bytes(artifact)
    (out_dir / "manifest.json").write_bytes(canonical_json_bytes(manifest) + b"\n")
    (out_dir / "manifest.sig").write_bytes(sig)
    (out_dir / "ed25519_public_key.raw").write_bytes(pub_raw)

    print("release bundle written:")
    print(f"  root: {root}")
    print(f"  out:  {out_dir}")
    print(f"  tree_hash: {manifest['tree_hash']}")
    print(f"  artifact_sha256: {sha256_bytes(artifact)}")


def main() -> None:
    p = argparse.ArgumentParser(description="Reproducible build + signed manifest demo tool (educational).")
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("demo", help="Run a small deterministic demo build.").set_defaults(fn=lambda _a: _cmd_demo())

    pb = sub.add_parser("build", help="Build a deterministic tar.gz + signed manifest for a directory.")
    pb.add_argument("--root", required=True, help="Directory to package.")
    pb.add_argument("--out-dir", required=True, help="Output directory for release bundle files.")
    pb.add_argument(
        "--seed-hex",
        required=True,
        help="32-byte Ed25519 seed as hex (educational; store keys safely in real systems).",
    )
    pb.add_argument("--include", action="append", help="Glob to include (repeatable). Default: include all files.")
    pb.add_argument("--exclude", action="append", default=["**/__pycache__/**"], help="Glob to exclude (repeatable).")
    pb.set_defaults(fn=_cmd_build)

    args = p.parse_args()
    if args.cmd is None:
        p.print_help()
        return
    args.fn(args)


if __name__ == "__main__":
    main()
