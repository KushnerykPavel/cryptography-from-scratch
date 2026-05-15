# Picking a Crypto Library — When and Why

> Pick primitives, not “crypto”. Choose misuse-resistant APIs with strong maintenance and real-world adoption.

**Type:** Learn  
**Languages:** Python  
**Prerequisites:** Phase 00 · 02 (Bytes/Hex/Base64), Phase 00 · 04 (Test Vectors), Phase 00 · 05 (Constant-Time Thinking)  
**Time:** ~45 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain why “use an audited library” is not enough without API + maintenance criteria
- Identify the top library failure modes: misuse-prone APIs, stale maintenance, unsafe defaults, and supply-chain risk
- Build a simple rubric for evaluating a library and apply it to a concrete use case
- Know the “default stack” for this course in Python: stdlib for hashes/HMAC, `cryptography` for AEAD and key handling, and when (not) to reach for alternatives

## The Problem

In this course you will implement primitives “from scratch” to understand them — and then immediately switch to an audited library in **Use It**.

If you pick the wrong library, or use the right library the wrong way, you can still ship broken crypto:

- You pick a library that offers AES “encryption” but nudges you into ECB/CBC without integrity. You ship malleable ciphertexts.
- You pick a library that is unmaintained. A vulnerability is found, but your dependency never gets patched.
- You pick a library with sharp edges: raw RSA, raw ECDSA, raw AES-CTR. Your code “works”, but the API makes misuse easy.
- You compare tags with `==` (Phase 00 · 05). Timing becomes an oracle.
- You trust a GitHub repo because it has stars. Then a supply-chain attack swaps in a malicious release.

This lesson gives you a repeatable decision process. The goal is not “the one true library”. The goal is: **given a task, choose a library + API surface that makes the safe thing the easy thing**.

## The Concept

### Crypto library selection is an engineering decision

You are selecting three things at once:

1) **The primitives** (AEAD vs “AES”, KDF vs “hashing passwords”, signature scheme)  
2) **The API** (misuse-resistant vs foot-guns)  
3) **The project** (maintenance, review, adoption, releases, security posture)

A good library can still be used unsafely if it exposes unsafe primitives too easily. And a safe API can still be a bad choice if the project is abandoned.

### A practical rubric (score it, then decide)

Use a simple checklist. You don’t need perfect information — you need to avoid obvious mistakes.

**A) Security posture**

- Does it explicitly support the safe, modern construction for your task (e.g., AEAD, not “AES mode selection”)?
- Does it document *misuse resistance* and the intended safe path?
- Does it call out side channels and constant-time behavior explicitly where it matters?

**B) Maintenance + adoption**

- Is it actively maintained (recent releases, issues triaged)?
- Is it widely used in serious projects?
- Does it have security reporting guidance and a history of patching issues?

**C) API ergonomics**

- Does it make safe defaults easy?
- Does it reduce dangerous choices (e.g., avoid exposing raw RSA unless necessary)?
- Does it make encoding boundaries explicit (bytes vs hex/base64 strings)?

**D) Supply-chain + reproducibility**

- Can you pin versions and verify hashes?
- Are builds reproducible (or at least consistent) for your environment?
- Do you understand how it ships native code and whether that matters?

### “Default stack” for this course (Python)

This course uses a small set of well-known libraries to keep the surface area manageable:

| Task | Prefer | Why |
|---|---|---|
| Hash (SHA-256, SHA-512) | Python stdlib `hashlib` | Stable, widely deployed, no extra dependency |
| HMAC | Python stdlib `hmac` | Correct-by-default HMAC construction |
| Safe comparison | `hmac.compare_digest` / `secrets.compare_digest` | Timing hygiene (Phase 00 · 05) |
| AEAD (AES-GCM / ChaCha20-Poly1305) | `cryptography` | Misuse-resistant AEAD APIs |
| Low-level “classic primitives” (learning, legacy) | `pycryptodome` (carefully) | Useful for exploration; easy to misuse if you pick the wrong mode |
| libsodium-style APIs | `PyNaCl` | High-level primitives; good ergonomics for some tasks |

Your job is to keep “learning code” and “shipping code” separated:

- **Build It**: educational, from-scratch, slow, not constant-time.
- **Use It**: audited library, safe API surface, stable vectors, careful boundaries.

## Build It

All code for this lesson lives in `code/main.py`.

This is a tooling lesson: the “build” is a reusable evaluation pattern you’ll apply throughout the course whenever you choose a dependency.

### Step 1: Encode your requirements

Before you compare libraries, write your requirements in plain language:

- What is the task? (encrypt+authenticate a message, verify a signature, derive a key, store a password hash)
- What are the constraints? (language, platform, FIPS, performance, streaming, interoperability)
- What are you *not* doing? (e.g., “we do not implement raw RSA ourselves”)

In `code/main.py`, you will represent this as a small `UseCase`.

### Step 2: Score candidate libraries

Create a tiny rubric that scores candidates against the axes above and prints a short recommendation.

The goal is not to “compute truth”. The goal is to **force explicit tradeoffs** so you don’t pick a library by vibes.

Run:

```bash
python phases/00-setup-and-tooling/06-picking-a-library/code/main.py
```

## Use It

### Hashing and HMAC (stdlib)

Prefer stdlib when it fits:

```python
import hashlib, hmac

digest = hashlib.sha256(b"msg").digest()
tag = hmac.new(b"key", b"msg", hashlib.sha256).digest()
ok = hmac.compare_digest(tag, tag)
```

### AEAD encryption (cryptography)

Prefer AEAD APIs (encrypt + authenticate):

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = AESGCM.generate_key(bit_length=256)
aead = AESGCM(key)
nonce = b"\x00" * 12
ct = aead.encrypt(nonce, b"msg", b"aad")
pt = aead.decrypt(nonce, ct, b"aad")
```

Notice what you *don’t* do:

- you don’t pick ECB/CBC,
- you don’t manually add PKCS#7 padding,
- you don’t bolt on “MAC later”.

## Attack It

This lesson’s “attack” is what happens when the library selection (or API selection) is wrong.

### Attack 1: “Encryption without authentication”

If an API leads you into CBC/CTR without an integrity check, you will eventually ship malleable ciphertexts (bit-flipping attacks). AEAD exists so you don’t have to remember the pitfalls each time.

### Attack 2: “Unsafe defaults and foot-guns”

If a library’s “happy path” exposes raw primitives (raw RSA, raw AES modes, manual padding), it’s easy to build something that passes happy-path tests but fails under adversarial input.

### Attack 3: Supply-chain surprises

“Popular on GitHub” is not a security model. Pin versions, review diffs on upgrades, and keep the dependency set small. (Phase 00 · 08 will go deeper on reproducibility.)

## Ship It

This lesson ships a reusable checklist prompt you can use whenever you need to choose (or review) a crypto dependency:

- `outputs/prompt-crypto-library-picker.md`

## Exercises

1. **Easy:** Pick one crypto task (e.g., “encrypt config at rest”) and write your requirements in 5 bullets: primitive, constraints, threat model.
2. **Medium:** Apply the rubric to two candidates (e.g., `cryptography` vs `pycryptodome`) and justify which one you’d pick for AEAD in a production Python service.
3. **Hard:** Find one “foot-gun API” in a crypto library’s docs (raw mode selection, manual padding, raw RSA) and write a short note describing the misuse it enables and the safer alternative API.

## Key Terms

| Term | What people say | What it actually means |
|---|---|---|
| Audit | “It was audited.” | A specific review scope at a specific time; not a forever-guarantee |
| Misuse-resistant API | “It’s easy to use.” | The safe construction is the default, and unsafe paths are harder |
| AEAD | “Authenticated encryption.” | Encrypt + authenticate as one primitive (e.g., AES-GCM, ChaCha20-Poly1305) |
| Constant-time | “No timing leaks.” | No secret-dependent control flow/memory access (Phase 00 · 05) |
| Supply chain | “It’s just a dependency.” | Your security includes how you fetch/build/update dependencies |
| FIPS | “Government-approved.” | A compliance requirement that can constrain library choices and builds |

## Test Vectors

N/A — this is a Learn/tooling lesson. Later primitive lessons must cite RFC/NIST vectors in `tests/vectors.json`.

## Further Reading

- [PyCA cryptography documentation](https://cryptography.io/en/latest/) — high-level recipes and safe APIs
- [libsodium / NaCl documentation](https://doc.libsodium.org/) — high-level primitives and design goals
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) — safe defaults and common pitfalls
