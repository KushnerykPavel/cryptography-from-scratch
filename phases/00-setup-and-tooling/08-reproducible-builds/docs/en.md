# Reproducible Builds & Signed Releases

> If you can’t reproduce it and verify it, you can’t trust it.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 00 · 04 (Test Vectors), 06 (Picking a Library), 07 (Threat Modeling)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain what “reproducible build” means (and what it doesn’t)
- Build a deterministic artifact (byte-for-byte stable) from a set of files
- Create a build manifest with per-file hashes and a single “tree hash”
- Sign and verify a release manifest with Ed25519 (using an audited library)

## The Problem

You download a “release zip” for a crypto tool. It contains `verify.py`, a binary, and a `README`.

How do you know it’s the real release?

- A compromised mirror can swap the file.
- A compromised maintainer account can publish a malicious release.
- A dependency update can change the build output without you noticing.
- Even without an attacker, non-deterministic packaging makes it impossible to compare “what I built” vs “what you built”.

In cryptography, this is not a side concern. **Your update channel is part of the cryptosystem.**

Later in the course you’ll implement primitives. Before that, you need a workflow for trusting *the code you run*:

- deterministic artifacts (so differences are meaningful),
- strong hashing (so you can compare),
- signed manifests (so you can attribute and verify).

## The Concept

There are two distinct properties people mix up:

1) **Reproducible build** (determinism)
   - Given the same inputs, you produce the *same bytes*.
   - If two parties build independently and get the same hash, they likely built the same thing.

2) **Signed release** (authenticity)
   - A trusted key signs a statement about the release (usually a hash).
   - Anyone with the public key can verify the statement wasn’t tampered with.

You want both:

- Reproducibility makes verification *possible*.
- Signatures make verification *attributable* (who vouched for this hash?).

### What is actually being “signed”?

You rarely sign “a folder”. You sign a *digest* of a deterministic representation:

- **Manifest**: a list of files + their hashes
- **Tree hash**: one hash summarizing the manifest

```
files → (sorted list + per-file SHA-256) → manifest.json → tree_hash → signature
```

If a single file changes, its SHA-256 changes, the tree hash changes, and the signature no longer validates.

### Determinism: the non-obvious foot-guns

Even if file contents are identical, artifacts can differ because of:

- file order in an archive
- timestamps embedded into gzip headers or tar metadata
- user/group IDs stored in tar entries
- “generated” files that include current time / random IDs

Reproducibility is mostly about **removing accidental variability**.

## Build It

All code for this lesson lives in `code/main.py`.

### Step 1: Build a deterministic manifest

We start with a manifest that is stable across machines:

- list files in a deterministic order (sorted paths)
- hash bytes, not filenames
- serialize JSON in a canonical way (sorted keys, stable separators)

The manifest includes:

- `files[]`: `{path, size, sha256}`
- `tree_hash`: SHA-256 of the canonical manifest payload (a single summary hash)

This is the “test vectors” mindset (Phase 00 · 04) applied to builds: define the byte-level contract first.

### Step 2: Build a deterministic archive (tar.gz)

Now we package the same file set into a deterministic artifact:

- fixed gzip `mtime=0` and empty gzip filename
- fixed tar entry metadata (mtime/uid/gid/uname/gname)
- add files in the same sorted order as the manifest

The point is not “tar.gz is special”. The point is: your packaging must have a stable encoding.

### Step 3: Sign the manifest tree hash (Ed25519)

We sign the tree hash, not the archive:

- the manifest is small and human-reviewable
- the archive can be rebuilt and checked against the manifest

We use Ed25519 via the audited `cryptography` library (Phase 00 · 06). This lesson is not about implementing Ed25519 — it’s about wiring a trustworthy release verification path.

Run the demo:

```bash
python phases/00-setup-and-tooling/08-reproducible-builds/code/main.py demo
```

## Use It

Real-world release verification tends to look like one of these:

- **Signed git tags / commits** (GPG or SSH signatures): “this source tree commit is authentic”
- **Signed release artifacts** (GPG, minisign): “this tarball hash is authentic”
- **Keyless signing with transparency logs** (Sigstore/cosign): “this artifact was signed by an identity, recorded publicly”

For supply-chain and build integrity, also learn the idea behind:

- **SLSA provenance**: signed attestations about how a build happened (what repo, what commit, what builder)
- **TUF** (The Update Framework): designing update systems that survive key compromise and mirror compromise

In Python specifically, the smallest practical win is still boring:

- pin dependencies (lockfiles)
- verify hashes when installing
- keep build steps deterministic (avoid timestamps/randomness in generated outputs)

## Attack It

This is a tooling lesson. The attack is “you verified the wrong thing”.

### Attack 1: Unsigned downloads (mirror swap)

If your release is not signed, a mirror attacker can replace:

- the artifact,
- the README,
- the install script.

Your build might be reproducible, but you have no authentic statement of which hash was intended.

### Attack 2: Signing the wrong boundary

Common failure patterns:

- signing only the filename/version (“v1.2.3”) instead of the content hash
- signing a manifest that omits some files (attacker slips in an extra file)
- hashing text instead of bytes (encoding ambiguity)

The defense is always the same: define exactly which bytes are covered, and test it like vectors.

## Ship It

This lesson ships two reusable prompts/checklists:

- `outputs/prompt-reproducible-release-checklist.md`
- `outputs/prompt-release-verification-playbook.md`

## Exercises

1. **Easy:** Add a file to a demo directory, rebuild the manifest, and observe which hashes change (file hash, tree hash, signature validity).
2. **Medium:** Modify the archive builder to refuse symlinks. Explain why symlinks complicate reproducibility and verification.
3. **Hard:** Design a “two-person rule” release flow: one key signs the manifest, a second key co-signs it. Define what compromise this protects against.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|------------------------|
| reproducible build | “it builds on my machine” | independent builds produce identical bytes for the same inputs |
| deterministic artifact | “same output” | archive/installer bytes don’t change because of timestamps/order/metadata |
| manifest | “list of files” | explicit mapping from file paths to hashes (and sizes) |
| tree hash | “a hash of the build” | one digest summarizing the entire manifest |
| signed release | “verified download” | a public-key signature over a digest statement |
| provenance | “build metadata” | who/what/when produced an artifact (often signed) |

## Test Vectors

Source: project-internal determinism vectors. This lesson is not a cryptographic primitive; vectors validate:

- canonical JSON encoding for the manifest
- deterministic archive hashing
- signature verification behavior

## Further Reading

- [reproducible-builds.org](https://reproducible-builds.org/) — definitions, common sources of non-determinism, and ecosystem guidance
- [SLSA (Supply-chain Levels for Software Artifacts)](https://slsa.dev/) — build provenance and integrity model
- [Sigstore](https://www.sigstore.dev/) — keyless signing + transparency logs
- [The Update Framework (TUF)](https://theupdateframework.io/) — robust design for secure update systems
