# Ink V0B read-only qualification

The V0B adapter is intentionally one bounded fixture:

| Fact | Frozen value |
|---|---|
| Chain | Ink mainnet, chain ID `57073` |
| Public RPC A | `https://rpc-gel.inkonchain.com` |
| Public RPC B | `https://rpc-qnd.inkonchain.com` |
| Base / token0 | KRAKMASK `0x32bCB803f696C99Eb263D60a05CAfD8689026575` |
| Quote / token1 | WETH9 `0x4200000000000000000000000000000000000006` |
| V2 factory | `0x458c5d5b75ccba22651d2c5b61cb1ea1e0b0f95d` |
| V2 pool | `0xeD11eD4B195e84bA9b74c4D6CE13B7A43b354264` |
| Runtime bytecode SHA-256 | `c5c2b764b882b8c18004fe5ce77d8649dd8c26cea265f663b16196708d22bf20` |
| Fee semantics | fixed `997 / 1000` (0.3%) |

The runtime uses lowercase canonical addresses. It independently checks the
pool's non-empty runtime bytecode and pinned SHA-256, calls `factory()`, calls
the factory's `getPair(KRAKMASK,WETH9)`, verifies `token0()`/`token1()`, and
reads `getReserves()` from both RPC providers at `min(head_A, head_B)`. The
provider-derived facts must agree exactly.

The fixed-fee assumption is supported by the deployed Uniswap V2 pair
semantics and InkySwap's public V2 documentation, which states that V2 pools
use a fixed 0.3% fee:

- https://inkyswap.com/liquidity/create?fee=3000&newPool=false&tokenA=0x4200000000000000000000000000000000000006&tokenB=0x97F9Fe646B85bFAdCD7F437Dfcd38333D599f473&version=v2
- https://docs.inkyswap.com/trading/swap-tokens

The adapter performs a constant-product market quote only. It does not build
router calldata, perform transaction simulation, sign, approve, or broadcast.
The live qualification artifacts are write-once canonical JSON records under
`qualifications/ink_v0b/` and can be replayed without network access.
