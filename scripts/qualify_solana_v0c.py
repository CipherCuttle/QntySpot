"""Run the one bounded V0C public-read qualification."""

from __future__ import annotations

import time
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from qntyspot.canon import canonical_json_str
from qntyspot.policy import load_policy_file
from qntyspot.solana import (
    JUPITER_SWAP_V2_BUILD_ENDPOINT,
    QUALIFICATION_TAKER_ADDRESS,
    SOLANA_MAINNET_RPC_ENDPOINT,
    JupiterV2Client,
    SolanaRpcClient,
    SolanaShadowAdapter,
    persist_decision,
    persist_observation,
)


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    policy = load_policy_file(root / "qualifications/solana_v0c/sol_usdc_buy.policy.json")
    now_epoch_s = int(time.time())
    rpc = SolanaRpcClient(SOLANA_MAINNET_RPC_ENDPOINT, max_retries=1)
    jupiter = JupiterV2Client(JUPITER_SWAP_V2_BUILD_ENDPOINT, max_retries=1)
    adapter = SolanaShadowAdapter(rpc, jupiter)
    observation = adapter.observe(
        policy,
        "solana-v0c-qualification-cycle",
        "SOL-USDC-1",
        now_epoch_s=now_epoch_s,
        taker=QUALIFICATION_TAKER_ADDRESS,
    )
    decision = adapter.shadow_decision(
        policy,
        "solana-v0c-qualification-cycle",
        "SOL-USDC-1",
        now_epoch_s=now_epoch_s,
        observation=observation,
        current_slot=observation.slot_after,
        current_block_height=observation.block_height_after,
    )
    persist_observation(root / "qualifications/solana_v0c/SOLANA_MARKET_OBSERVATION_V0.json", observation)
    persist_decision(root / "qualifications/solana_v0c/SHADOW_DECISION_V0.json", decision)
    print(
        canonical_json_str(
            {
                "active_phase": "QNTY_SPOT_V0C_SOLANA_SHADOW",
                "decision": decision.canonical_object(),
                "jupiter_endpoint": jupiter.endpoint,
                "network_reads": rpc.read_count + jupiter.read_count,
                "observation_digest": observation.digest(),
                "proof": {
                    "broadcasts": 0,
                    "live_capital_operations": 0,
                    "secret_reads": 0,
                    "signatures": 0,
                    "wallet_secret_reads": 0,
                },
                "rpc_endpoint": rpc.endpoint,
            }
        )
    )


if __name__ == "__main__":
    main()
