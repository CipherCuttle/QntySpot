# QntySpot deployment identity V0R1

This document defines the corrected non-execution deployment identity
candidate. It is evidence only: it issues no authority, accesses no
production root key, signs no bytes, calls no venue or RPC, and deploys no
capital.

```text
SCHEMA                    = qntyspot.deployment_identity.v0r1
METHOD                    = sha256-canonical-source-manifest-v2
CANONICAL_QNTYSPOT_COMMIT = 35ee98fa72086e430a6288c4855a6fbc111a5181
STATUS                    = SUPERSEDES_DEPLOYMENT_IDENTITY_V0_FOR_AUTHORITY_BINDING
```

## Identity method

The implementation digest is the SHA-256 digest of the canonical JSON
encoding of this material:

```text
{
  "implementation_identity": {
    "canonicalization": "canonical_json(sort_keys=true,separators=(',', ':'),ensure_ascii=true)",
    "file_manifest": [
      {"path": relative_posix_path, "sha256": SHA256(file_bytes)},
      ...
    ],
    "file_selection": "explicit SOURCE_PATHS: pyproject.toml and canonical qntyspot Python package",
    "repository_identity": "CipherCuttle/QntySpot"
  },
  "implementation_identity_method": "sha256-canonical-source-manifest-v2",
  "schema": "qntyspot.deployment_identity.v0r1"
}
```

`repository_commit` is deliberately absent from the hashed material. The
resulting evidence artifact records it separately under `provenance`, so an
administrative merge can change the evidence-artifact digest without changing
the implementation digest.

`SOURCE_PATHS` remains an explicit, reviewed list in
`scripts/derive_deployment_identity.py`. It contains `pyproject.toml` and all
canonical Python files under `qntyspot/`. The helper fails closed if the
package contains any non-cache file outside that list, including an
unexpected Python or native module. It does not hash tests, docs, artifacts,
`.git`, host files, caches, virtual environments, filesystem modes, timestamps,
environment values, Git object encodings, or private material.

## Relationship to V1

`artifacts/DEPLOYMENT_IDENTITY_V0.json` and its sidecar remain preserved as
historical V1 evidence. V1 included `repository_commit` in its implementation
identity material. Its implementation digest therefore changed from
`a1803ecbb16b91cb66cacd811f997b170b4e8c2cebf43c05830d1d314825f96c` before the
administrative merge to
`1595ed2139729c875c975a0a7b2ccb2e2145e2ba6ac7add79f304e07fae7f2f7` after the
merge, although the runtime file set and contents were unchanged.

This V0R1 artifact explicitly supersedes V1 for future authority binding. It
does not rewrite or erase the historical V1 record.

## Authority boundary

`AuthorityPolicyRefV0.permitted_repository_commit` continues to bind exactly
to `ExecutionSessionV0.repository_commit`, and
`AuthorityPolicyRefV0.permitted_implementation_digest` continues to bind
exactly to `ExecutionSessionV0.implementation_digest`. The two bindings remain
mechanically independent. The source phase ceiling remains `SHADOW`, and this
candidate is not a production first-grant binding until the repair is merged
and re-derived from canonical main.
