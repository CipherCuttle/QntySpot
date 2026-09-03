# QntySpot deployment identity V0

This document defines the non-execution identity artifact proposed for the
canonical QntySpot external-authority contract.  It is a prerequisite for a
future authority receipt; it does not issue, verify, or raise authority.

```text
SCHEMA                    = qntyspot.deployment_identity.v0
METHOD                    = sha256-canonical-source-manifest-v1
CANONICAL_QNTYSPOT_COMMIT = 982a0b38d9226523679c8e59c6abc22ccb5242fd
STATUS                    = PENDING_CANONICALIZATION
```

## Identity method

The implementation digest is:

```text
SHA256(canonical_json({
  "implementation_identity_inputs": {
    "canonicalization": "canonical_json(sort_keys=true,separators=(',', ':'),ensure_ascii=true)",
    "file_manifest": [
      {"path": relative_posix_path, "sha256": SHA256(file_bytes)},
      ...
    ],
    "file_selection": "explicit SOURCE_PATHS: pyproject.toml and canonical qntyspot Python package",
    "repository_commit": "982a0b38d9226523679c8e59c6abc22ccb5242fd",
    "repository_identity": "CipherCuttle/QntySpot"
  },
  "implementation_identity_method": "sha256-canonical-source-manifest-v1",
  "schema": "qntyspot.deployment_identity.v0"
}))
```

`SOURCE_PATHS` is an explicit, reviewed list in
`scripts/derive_deployment_identity.py`.  It contains `pyproject.toml` and all
canonical Python files under `qntyspot/`, including the external-authority
consumer and execution-session contract.  The artifact records every path and
file digest, so the exact inputs can be independently checked without trusting
the generator.

The identity excludes filesystem roots, hostnames, environment values, file
modes, timestamps, Git object encodings, private material, network calls, and
signing.  The helper has no Git dependency and does not derive identity from a
Git object id.  Canonical-commit and clean-checkout validation are separate
operator/reviewer steps; Git’s commit id remains a separate authority-policy
field and is not used as the implementation digest.

Changing any listed source or packaging input changes the implementation
digest.  Adding an unlisted Python file fails closed and requires a reviewed
update to this identity mechanism, so a material runtime file cannot silently
survive under the old digest.

## Boundary

The artifact is nonsecret evidence only.  It grants no capability, creates no
authority receipt, accesses no production root key, calls no venue/RPC, signs
no bytes, and deploys no capital.  This candidate must be merged on the
canonical QntySpot main branch before its implementation digest can be used in
a first-grant policy.
