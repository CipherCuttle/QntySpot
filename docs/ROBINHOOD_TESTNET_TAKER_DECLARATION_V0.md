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
