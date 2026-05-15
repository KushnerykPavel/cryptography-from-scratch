# Dev Environment — Python, Rust, Node, Crypto Stack

> Reproducibility is a security property. Treat your toolchain like part of the cryptosystem.

**Type:** Learn
**Languages:** Python (optional: Rust, Node.js, SageMath)
**Prerequisites:** None
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## The Problem

This course is hundreds of hours of code, tests, and RFC/NIST test vectors. If your environment is flaky, you will spend more time fighting installs than learning cryptography.

Crypto tooling is also unusually sensitive to system details:

- big-integer backends (`gmpy2`) often require native wheels or system libraries
- lattice tooling (`fpylll`) depends on compiled components
- “it runs on my machine” is not acceptable when you’re comparing against test vectors

The goal of this lesson is a boring outcome: you can run every future lesson with the same Python, the same dependencies, and the same outputs, across machines.

## The Concept

Think of your crypto dev environment as a stack. You build it bottom-up.

```
[4] "Crypto and Protocol Libraries"
    cryptography, PyCryptodome, PyNaCl, ecdsa, ...

[3] "Math Tooling"
    gmpy2, sympy, galois, fpylll, numpy, py_ecc, ...

[2] "Language Runtime + Environment"
    Python 3.12+, virtualenv, dependency manager

[1] "System Foundation"
    git, compiler toolchain, OpenSSL, build headers, editor
```

Rules that keep you sane:

1. **One repo, one virtual environment.** Never install course deps globally.
2. **Never use `sudo pip install`.** If you need `sudo`, you installed into the wrong place.
3. **Pin and verify.** A passing test vector suite is your “it works” proof.
4. **Prefer audited libraries for anything real.** This course’s code is for understanding, not deployment.

## Build It

### Step 1: Create a clean Python environment

From the repo root:

```bash
python -V
python -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -r requirements.txt
```

Quick sanity check:

```bash
python -c "import sys; print(sys.executable); print(sys.version)"
```

If `sys.executable` points outside `.venv`, you are not in the virtual environment.

### Step 2: Verify your crypto/math stack

Run the course verification script:

```bash
python phases/00-setup-and-tooling/01-dev-environment/code/main.py
```

It prints a report covering:

- Python version + virtual environment status
- key imports from `requirements.txt`
- optional tools (`git`, `openssl`, `rustc`, `node`, `sage`) if present

If something fails to import, don’t “fix” it by random reinstalls. First answer:

- are you inside `.venv`?
- did `pip install -r requirements.txt` finish without errors?
- are you on a platform that requires a compiler toolchain for some packages?

### Step 3: Optional toolchains (for later phases)

You can complete early phases with Python only. Later phases may optionally use:

- **Rust** for performance-critical implementations and constant-time hygiene
- **Node.js** for web demos and tooling (where appropriate)
- **SageMath** as an independent math oracle for cross-checking algebra

Verify availability (if installed):

```bash
rustc --version
node --version
sage --version
```

If you don’t have these installed yet, skip them. This course should not be blocked on optional tooling.

## Use It

Use this environment checklist whenever you switch machines or hit “works yesterday, fails today”:

- activate `.venv`
- rerun `phases/00-setup-and-tooling/01-dev-environment/code/main.py`
- run a small, fast test from a completed phase (Phase 1 is a good smoke test)

When you reach lessons that compare against known vectors, treat “matches vectors” as the source of truth, not “seems plausible”.

## Attack It

Environment mistakes become security mistakes:

- dependency drift silently changes arithmetic behavior and breaks reproducibility
- supply-chain compromise lands in your import path before your crypto code runs
- global installs make it impossible to know what you’re executing

Your defense is boring engineering: isolated environments, pinned dependencies, and tests driven by public vectors.

## Ship It

- `phases/00-setup-and-tooling/01-dev-environment/code/main.py` is the verification script.
- `phases/00-setup-and-tooling/01-dev-environment/outputs/prompt-env-check.md` is a prompt you can use with an AI assistant to diagnose environment issues systematically.

## Exercises

1. **Easy.** Run the verification script, then deliberately deactivate `.venv` and run it again. Explain the difference in the report.
2. **Medium.** Create a second virtual environment in a different folder and install a different version of one package. Show how the report detects drift.
3. **Hard.** Make a minimal “smoke test” command you can run before every lesson (activate `.venv`, run env check, run one quick test file from Phase 1).

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|------------------------|
| virtual environment | “a Python folder” | an isolated interpreter + site-packages set |
| dependency drift | “minor version bumps” | your code changes without you changing your code |
| reproducibility | “it runs” | same inputs produce the same outputs on a fresh machine |
| supply chain | “npm problems” | third-party code runs inside your process before yours |

## Test Vectors

Not applicable for this lesson. This lesson exists to make future vector-driven lessons runnable and reproducible.

## Further Reading

- [Python Packaging User Guide](https://packaging.python.org/en/latest/) — a mental model of venvs, wheels, and installs
- [The `cryptography` project](https://cryptography.io/en/latest/) — audited library docs (use this in real systems)
