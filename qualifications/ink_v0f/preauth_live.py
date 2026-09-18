from __future__ import annotations

from pathlib import Path

from qntyspot.canon import canonical_json_str
from qntyspot.ink import INK_RPC_ENDPOINTS, InkShadowAdapter, JsonRpcClient, KRAKMASK_ADDRESS, WETH9_ADDRESS
from qntyspot.ink_v0f_execution import consume_ink_v0f_router_artifact
from qntyspot.ink_v0f_preauth import InkV0FLiveVerifier

ROOT = Path(__file__).resolve().parents[2]
ROUTER_ARTIFACT = ROOT / "artifacts/ink_v0f/INK_V0F_ROUTER_IDENTITY_V0.json"


def main() -> int:
    providers = tuple(JsonRpcClient(endpoint) for endpoint in INK_RPC_ENDPOINTS)
    if len(providers) != 2:
        raise RuntimeError("Ink V0F qualification requires exactly two canonical RPCs")
    market = InkShadowAdapter(providers).observe()
    router_identity = consume_ink_v0f_router_artifact(ROUTER_ARTIFACT.read_bytes())
    live = InkV0FLiveVerifier(providers, router_identity)
    router = live.observe_router_for_market(market)
    weth_allowance = live.observe_allowance_for_market(
        market,
        token_address=WETH9_ADDRESS,
    )
    krakmask_allowance = live.observe_allowance_for_market(
        market,
        token_address=KRAKMASK_ADDRESS,
    )
    if weth_allowance.allowance_atomic != 0 or krakmask_allowance.allowance_atomic != 0:
        raise RuntimeError("first-live qualification requires zero standing router allowances")

    result = {
        "common_block": market.common_block,
        "krakmask_allowance_atomic": str(krakmask_allowance.allowance_atomic),
        "krakmask_allowance_digest": krakmask_allowance.digest,
        "market_observation_digest": market.digest(),
        "provider_heads": dict(sorted(router.provider_heads.items())),
        "router_observation_digest": router.digest,
        "router_bytecode_sha256": router.bytecode_sha256,
        "router_factory": router.factory_address,
        "router_weth": router.weth_address,
        "schema": "qntyspot.ink_v0f.live_router_preflight_qualification.v0",
        "weth_allowance_atomic": str(weth_allowance.allowance_atomic),
        "weth_allowance_digest": weth_allowance.digest,
    }
    print(canonical_json_str(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
