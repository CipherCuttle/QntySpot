# Robinhood testnet taker declaration V0

This is a nonsecret, network-scoped operator declaration for the first
production authority-receipt SHADOW-path proof. It applies only to
`evm:46630`; historical qualification evidence for the same public address on
`evm:4663` remains separate and does not establish testnet authority.

```text
SCHEMA                    = qntyspot.robinhood_testnet_taker_declaration.v0
NETWORK_ID                = evm:46630
ROLE                      = qntyspot-robinhood-testnet-taker
TAKER_ADDRESS             = 0x1324d87e24e1657f6fe6805de814bb6873052106
VENUE_ID                  = 0x-swap-v2-robinhood-chain
SOURCE_PHASE_CEILING      = SHADOW
SIGNING_AUTHORIZED        = false
CAPITAL_AUTHORIZED        = false
ACCOUNT_CONTROL_PROVEN    = false
PRIVATE_KEY_CONTROL_PROVEN = false
```

PUBLIC ACCOUNT IDENTITY != PRIVATE ACCOUNT CONTROL

THIS DECLARATION DOES NOT PROVE CONTROL.

The declaration does not prove private-key ownership, account custody,
signing authority, execution authority, capital authority, approval
authority, or transaction-submission authority. No private signing material
is accessed, and this artifact does not authorize runtime behavior.

The artifact is canonical JSON and its `.sha256` sidecar covers the exact
artifact bytes. It is governance/evidence only and is intentionally excluded
from the V2 implementation `SOURCE_PATHS` manifest.

## V0R1 repaired declaration provenance

The repaired nonsecret declaration is stored in
`artifacts/ROBINHOOD_TESTNET_TAKER_DECLARATION_V0R1.json`. Its commit fields
have distinct meanings:

```text
PROVENANCE_PARENT_COMMIT = 46ab538de59c67a8af8f230bb7e494378392b614
REPAIRED_SOURCE_COMMIT   = 742870f915588309053ac21298ce22ee2b6540c4
```

`qntyspot_parent_commit` is the repair branch's canonical parent and is
provenance only. `repaired_source_commit` is the first exact Git commit whose
tree contains the repaired runtime venue identity and derives the declared
`sha256-canonical-source-manifest-v2` implementation digest
`d06b6eb98c5a33ae9ef7a12af7ef2626d9a176894ef13dad97fafe99481812de`.

The pre-canonicalization authority representability fixture binds
`AuthorityPolicyRefV0.permitted_repository_commit` to
`REPAIRED_SOURCE_COMMIT`, not the provenance parent. The future production
binding remains deferred to the actual canonical merge SHA for PR #15; that
SHA is intentionally not pre-frozen here.

## V0R2 successor declaration — current venue-binding repair

The repair-phase successor declaration is stored in
`artifacts/ROBINHOOD_TESTNET_TAKER_DECLARATION_V0R2.json`, with its exact
artifact digest in the adjacent `.sha256` sidecar. It succeeds V0R1 without
rewriting that historical declaration.

```text
SCHEMA                    = qntyspot.robinhood_testnet_taker_declaration.v0r2
BASE_QNTYSPOT_CANONICAL   = 095572b0d94d7edf055246a3829de94467fc07d0
IMPLEMENTATION_METHOD     = sha256-canonical-source-manifest-v2
IMPLEMENTATION_DIGEST     = 7fdd08cbb60de858d4eab7031a8463f29b62648be4b88104f6bd031c23a32826
NETWORK_ID                = evm:46630
TAKER_ADDRESS             = 0x1324d87e24e1657f6fe6805de814bb6873052106
VENUE_ID                  = robinhood-chain-testnet-external-transaction
TRANSACTION_ORIGIN        = EXTERNAL_TO_QNTYSPOT
SOURCE_PHASE_CEILING      = RECONCILE_ONLY
SIGNING_AUTHORIZED        = false
CAPITAL_AUTHORIZED        = false
ACCOUNT_CONTROL_PROVEN    = false
PRIVATE_KEY_CONTROL_PROVEN = false
```

V0R2 identifies one explicitly supplied, externally created Robinhood Chain
Testnet transaction for observation and reconciliation. It proves no
private-key control, account control, signing, transaction construction,
approval creation, submission, or capital authority. It does not issue an
AuthorityRoot grant or establish effective Level-1 authority; a current
external grant remains required, and live capital remains forbidden.

The V0R2 venue identity is deliberately distinct from the historical Robinhood
mainnet 0x SHADOW quote path on `evm:4663`. It does not imply 0x routing, a DEX,
liquidity, or successful settlement.
