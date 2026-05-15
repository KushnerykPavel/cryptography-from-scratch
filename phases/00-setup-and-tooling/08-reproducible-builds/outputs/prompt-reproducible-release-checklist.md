# Reproducible Release Checklist (Crypto/Tooling)

You are reviewing a release process for a cryptography-heavy project. Produce a checklist with concrete verification steps.

## Inputs

- Repository URL:
- Release version/tag:
- Target artifact(s): (wheel/sdist/tar.gz/binary)
- Public key distribution method: (pinned key, WKD, transparency log, etc.)

## Checklist

### Reproducibility (determinism)

- Are all build inputs pinned? (compiler/runtime versions, dependencies, lockfiles)
- Is the artifact creation deterministic?
  - stable file ordering in archives
  - fixed timestamps (or stripped)
  - fixed uid/gid/uname/gname where applicable
  - no random IDs embedded into outputs
- Can two independent builders produce identical artifact hashes from the same commit?

### Hashing (content identity)

- Is there a manifest listing every file included (and only those files)?
- Are hashes computed over bytes (not strings / filenames)?
- Are encodings and canonicalization rules explicit? (JSON canonical form, newline normalization policy)
- Is there a single “tree hash” summarizing the manifest?

### Signing (authenticity)

- What exactly is signed? (tree hash vs artifact vs tag)
- Is the signature scheme modern and misuse-resistant? (Ed25519, Sigstore, etc.)
- Is the verification key distribution safe? (pinned in repo/docs, multiple channels, transparency logs)
- Is key rotation addressed? (revocation, expiry, emergency rotation path)

### Threat model alignment

- Which attacker does this protect against?
  - mirror compromise
  - dependency drift
  - maintainer account compromise
  - build system compromise
- What is explicitly out of scope?

### CI and evidence

- Does CI produce and publish:
  - manifest
  - tree hash
  - signature
  - build provenance (if available)
- Are outputs stored immutably (release assets, transparency log, append-only store)?

## Deliverable

Return:

1) A pass/fail checklist with short rationales
2) The top 3 highest-impact fixes to make the release verifiable and reproducible
