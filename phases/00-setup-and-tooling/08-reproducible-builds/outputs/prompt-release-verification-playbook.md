# Release Verification Playbook (Consumer-Side)

You are verifying a downloaded release artifact. Produce a step-by-step playbook that a careful engineer can follow.

## Goals

- Verify authenticity (it was produced by the expected identity)
- Verify integrity (bytes were not modified)
- Verify reproducibility (if source is available, you can rebuild and compare)

## Steps

1) Identify the trusted key source
   - Where is the public key pinned (docs, repo, multiple channels)?
   - How do you detect key rotation or key compromise?

2) Obtain the artifact + manifest + signature
   - Artifact: `release.tar.gz` (or wheel, binary)
   - Manifest: `manifest.json` (list of files + hashes)
   - Signature: `manifest.sig` (signature over the manifest tree hash)

3) Verify the signature
   - Verify the signature using the pinned public key
   - Fail closed on parse errors or missing files

4) Verify the manifest matches the artifact
   - Recompute per-file hashes from the artifact contents
   - Ensure the artifact contains:
     - all files in the manifest
     - no extra files not listed in the manifest

5) Optional: rebuild from source and compare
   - Check out the signed tag/commit
   - Use the pinned toolchain + lockfile
   - Rebuild the artifact deterministically
   - Compare artifact hash against the released hash

6) Record evidence
   - Save: artifact hash, manifest tree hash, signature verification result, key fingerprint, date verified
   - If this is for production, store evidence in an immutable log

## Output format

Return a short “verification report” with:

- Artifact hash:
- Manifest tree hash:
- Signature verified: yes/no (and why)
- Reproducible rebuild match: yes/no/not attempted
- Risk notes:
