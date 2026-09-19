# Ink V0F live router preflight qualification

This directory freezes the read-only first-live router/allowance preflight for
the Ink V0F path. No transaction, approval, signature, wrapping, or capital
movement occurred.

Qualification workflow run:

`35397911195`

At common Ink block `56269204`, both canonical public RPC providers agreed on:

- legacy InkySwap V1 router runtime bytecode SHA-256
  `64ec5d32d5ce6eb632cad54cb7de2653e7aec19fdad0b641b16c0b1a1f52ba7b`;
- router `factory()` =
  `0x458c5d5b75ccba22651d2c5b61cb1ea1e0b0f95d`;
- router `WETH()` =
  `0x4200000000000000000000000000000000000006`;
- WETH allowance from the frozen taker to the router = `0`;
- KRAKMASK allowance from the frozen taker to the router = `0`.

Provider heads were `56269206` and `56269209`, so the common-block evidence
was fresh and inside the configured head-lag/age bounds.

Canonical evidence:

`INK_V0F_LIVE_ROUTER_PREFLIGHT_V0.json`

Evidence SHA-256:

`3f8be5378da5e2ddb8df5845ffd9e2ea84131a46ffe9a94c1b0d397fe2850b0c`

This is qualification evidence only. The binding source ceiling remains
`RECONCILE_ONLY`.


## Fresh Level-3 preflight — 2026-09-19

Workflow run:

`35410499834`

Canonical QntySpot runtime identity:

- repository commit: `af5edb2eaf9e6ab55a8295da4a9cb5f2e7d549b6`
- implementation digest: `f0f3dfb14ddc5be1b2b500fdd4bf134f37dc63c56116e8be39a5496b95db707a`

Fresh two-provider observation:

- common block: `56280402`
- provider heads: `56280402`, `56280404`
- router bytecode SHA-256: `64ec5d32d5ce6eb632cad54cb7de2653e7aec19fdad0b641b16c0b1a1f52ba7b`
- factory: `0x458c5d5b75ccba22651d2c5b61cb1ea1e0b0f95d`
- WETH: `0x4200000000000000000000000000000000000006`
- frozen taker WETH allowance to router: `0`
- frozen taker KRAKMASK allowance to router: `0`

Canonical evidence:

`INK_V0F_LIVE_ROUTER_PREFLIGHT_V1.json`

Evidence SHA-256:

`e55ffb3c6242783dcdaffacb0593e095c88424c459e4cd542f9b9a39871d212c`

This run was read-only. It created no approval, signature, grant, transaction,
submission attempt, or capital movement.
