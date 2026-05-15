import importlib
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class CheckResult:
    name: str
    ok: bool
    detail: str


def _is_venv() -> bool:
    base_prefix = getattr(sys, "base_prefix", sys.prefix)
    return sys.prefix != base_prefix


def _try_dist_version(dist_name: str) -> str | None:
    try:
        from importlib import metadata

        return metadata.version(dist_name)
    except Exception:
        return None


def _try_module_version(module) -> str | None:
    v = getattr(module, "__version__", None)
    if isinstance(v, str) and v.strip():
        return v.strip()
    return None


def check_import(dist_name: str, import_name: str | None = None) -> CheckResult:
    name = import_name or dist_name
    try:
        module = importlib.import_module(name)
    except Exception as e:
        return CheckResult(name=dist_name, ok=False, detail=f"import failed: {e.__class__.__name__}: {e}")
    version = _try_dist_version(dist_name) or _try_module_version(module)
    return CheckResult(name=dist_name, ok=True, detail=version or "import ok")


def check_command(argv: list[str]) -> CheckResult:
    exe = argv[0]
    path = shutil.which(exe)
    if path is None:
        return CheckResult(name=exe, ok=False, detail="not found in PATH")
    try:
        out = subprocess.check_output(argv, stderr=subprocess.STDOUT, text=True, timeout=3)
        line = out.strip().splitlines()[0] if out.strip() else ""
        return CheckResult(name=exe, ok=True, detail=line or "ok")
    except Exception as e:
        return CheckResult(name=exe, ok=False, detail=f"failed: {e.__class__.__name__}: {e}")


def _print_section(title: str) -> None:
    print()
    print(title)
    print("-" * len(title))


def _print_results(results: list[CheckResult]) -> None:
    width = max(len(r.name) for r in results) if results else 0
    for r in results:
        status = "OK" if r.ok else "MISSING"
        print(f"{r.name:<{width}}  {status:<7}  {r.detail}")


def main() -> None:
    print("Crypto from Scratch — Dev Environment Check")
    print()
    print(f"Python:     {sys.version.split()[0]}")
    print(f"Executable: {sys.executable}")
    print(f"Platform:   {platform.platform()}")
    print(f"Venv:       {'yes' if _is_venv() else 'no'}")

    _print_section("Python packages (from requirements.txt)")
    pkgs: list[tuple[str, str | None]] = [
        ("cryptography", None),
        ("pycryptodome", "Crypto"),
        ("gmpy2", None),
        ("sympy", None),
        ("numpy", None),
        ("galois", None),
        ("fpylll", None),
        ("py_ecc", "py_ecc"),
        ("ecdsa", None),
        ("pynacl", "nacl"),
        ("pytest", None),
        ("hypothesis", None),
    ]
    pkg_results = [check_import(dist, imp) for dist, imp in pkgs]
    _print_results(pkg_results)

    _print_section("Optional system tools")
    tools = [
        ["git", "--version"],
        ["openssl", "version"],
        ["rustc", "--version"],
        ["cargo", "--version"],
        ["node", "--version"],
        ["pnpm", "--version"],
        ["sage", "--version"],
    ]
    tool_results = [check_command(argv) for argv in tools]
    _print_results(tool_results)

    _print_section("Next steps")
    if not _is_venv():
        print("Activate your virtual environment, then reinstall dependencies:")
        print("  source .venv/bin/activate")
        print("  python -m pip install -r requirements.txt")
    else:
        missing = [r.name for r in pkg_results if not r.ok]
        if missing:
            print("Some packages failed to import. Reinstall inside this venv:")
            print("  python -m pip install -r requirements.txt")
            print(f"Missing: {', '.join(missing)}")
        else:
            print("Python stack looks good. You're ready for Phase 00 → Lesson 02.")


if __name__ == "__main__":
    main()
