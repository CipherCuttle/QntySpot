"""Bounded read-only chain truth for the Robinhood testnet qualification.

The source accepts an explicitly supplied public transaction identity and an
injected response provider.  It never discovers an account or asset and never
creates transaction material.  Provider responses are untrusted until the
chain, transaction, block, receipt, and transfer-log identities have all been
checked.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from typing import Any

from .canon import canonical_json_bytes, sha256_hex
from .errors import RobinhoodProtocolError
from .execution_contract import ChainObservationV0, ChainPresence, ReceiptStatus
from .keccak import keccak256_hex

__all__ = [
    "ROBINHOOD_TESTNET_CHAIN_ID",
    "ROBINHOOD_TESTNET_NETWORK_ID",
    "ROBINHOOD_TESTNET_VENUE_ID",
    "ROBINHOOD_MAINNET_CHAIN_ID",
    "READ_ONLY_RPC_METHODS",
    "RobinhoodTestnetChainTruthSource",
]

ROBINHOOD_TESTNET_CHAIN_ID = 46630
ROBINHOOD_TESTNET_NETWORK_ID = "evm:46630"
ROBINHOOD_TESTNET_VENUE_ID = "robinhood-chain-testnet-external-transaction"
ROBINHOOD_MAINNET_CHAIN_ID = 4663

READ_ONLY_RPC_METHODS = frozenset(
    {
        "eth_chainId",
        "eth_blockNumber",
        "eth_getBlockByNumber",
        "eth_getBlockByHash",
        "eth_getTransactionByHash",
        "eth_getTransactionReceipt",
    }
)

_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_HASH_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
_QUANTITY_RE = re.compile(r"^0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)$")
_MAX_UINT256 = (1 << 256) - 1
_TRANSFER_TOPIC = "0x" + keccak256_hex(b"Transfer(address,address,uint256)")


def _protocol(message: str) -> RobinhoodProtocolError:
    return RobinhoodProtocolError(message)


def _address(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or _ADDRESS_RE.fullmatch(value) is None:
        raise _protocol(f"{field}: malformed address")
    result = value.lower()
    if int(result[2:], 16) == 0:
        raise _protocol(f"{field}: zero address")
    return result


def _hash(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or _HASH_RE.fullmatch(value) is None:
        raise _protocol(f"{field}: malformed hash")
    return value.lower()


def _quantity(value: Any, *, field: str) -> int:
    if not isinstance(value, str) or _QUANTITY_RE.fullmatch(value) is None:
        raise _protocol(f"{field}: malformed quantity")
    result = int(value[2:], 16)
    if result > _MAX_UINT256:
        raise _protocol(f"{field}: quantity exceeds uint256")
    return result


def _bytes(value: Any, *, field: str, length: int | None = None) -> bytes:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise _protocol(f"{field}: malformed bytes")
    raw = value[2:]
    if len(raw) % 2:
        raise _protocol(f"{field}: odd-length bytes")
    try:
        result = bytes.fromhex(raw)
    except ValueError as exc:
        raise _protocol(f"{field}: malformed bytes") from exc
    if length is not None and len(result) != length:
        raise _protocol(f"{field}: expected {length} bytes")
    return result


def _block_number(value: Any, *, field: str) -> int:
    result = _quantity(value, field=field)
    if result > (1 << 63) - 1:
        raise _protocol(f"{field}: block number exceeds bound")
    return result


def _require_mapping(value: Any, *, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise _protocol(f"{field}: expected object")
    return value


def _topic_address(value: Any, *, field: str) -> str:
    raw = _bytes(value, field=field, length=32)
    if raw[:12] != b"\0" * 12:
        raise _protocol(f"{field}: non-canonical indexed address")
    return _address("0x" + raw[12:].hex(), field=field)


class RobinhoodTestnetChainTruthSource:
    """Produce one validated observation from one injected provider reading."""

    provider_id: str
    rpc_endpoint: str

    def __init__(
        self,
        *,
        provider_id: str,
        rpc_endpoint: str,
        transport: Callable[[str, tuple[Any, ...]], Any] | Mapping[str, Any],
    ) -> None:
        if not isinstance(provider_id, str) or re.fullmatch(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*", provider_id) is None:
            raise _protocol("provider_id: non-portable identity")
        if not isinstance(rpc_endpoint, str) or not rpc_endpoint.startswith("https://"):
            raise _protocol("rpc_endpoint: explicit HTTPS endpoint required")
        if not callable(transport) and not isinstance(transport, Mapping):
            raise TypeError("transport must be an injected callable or fixture mapping")
        self.provider_id = provider_id
        self.rpc_endpoint = rpc_endpoint
        self._transport = transport

    def _call(self, method: str, params: tuple[Any, ...]) -> Any:
        """Call only the fixed read allowlist through the injected provider."""
        if method not in READ_ONLY_RPC_METHODS:
            raise RobinhoodProtocolError("RPC method is outside the read-only allowlist")
        if callable(self._transport):
            return self._transport(method, params)
        if method not in self._transport:
            raise _protocol(f"fixture has no response for {method}")
        value = self._transport[method]
        if callable(value):
            return value(params)
        return value

    def observe(
        self,
        transaction_hash: str,
        *,
        expected_taker: str,
        input_token: str,
        output_token: str,
        observed_at_epoch_s: int,
    ) -> ChainObservationV0:
        tx_hash = _hash(transaction_hash, field="transaction_hash")
        taker = _address(expected_taker, field="expected_taker")
        input_asset = _address(input_token, field="input_token")
        output_asset = _address(output_token, field="output_token")
        if input_asset == output_asset:
            raise _protocol("input_token and output_token must be distinct")
        if type(observed_at_epoch_s) is not int or observed_at_epoch_s < 0:
            raise _protocol("observed_at_epoch_s must be a non-negative integer")

        chain_result = self._call("eth_chainId", ())
        chain_id = _quantity(chain_result, field="eth_chainId")
        if chain_id == ROBINHOOD_MAINNET_CHAIN_ID:
            raise _protocol("Robinhood mainnet is forbidden for this source")
        if chain_id != ROBINHOOD_TESTNET_CHAIN_ID:
            raise _protocol("provider chain id is not Robinhood testnet")

        head_result = self._call("eth_blockNumber", ())
        head_number = _block_number(head_result, field="eth_blockNumber")
        head = _require_mapping(
            self._call("eth_getBlockByNumber", (hex(head_number), False)),
            field="head block",
        )
        head_hash = _hash(head.get("hash"), field="head.hash")
        if _block_number(head.get("number"), field="head.number") != head_number:
            raise _protocol("head number disagrees with eth_blockNumber")

        tx_result = self._call("eth_getTransactionByHash", (tx_hash,))
        evidence: dict[str, Any] = {
            "chain_id": chain_result,
            "head": dict(head),
            "head_number": head_result,
            "input_token": input_asset,
            "output_token": output_asset,
            "provider_id": self.provider_id,
            "rpc_endpoint": self.rpc_endpoint,
            "taker": taker,
            "transaction_hash": tx_hash,
            "transaction": tx_result,
        }
        if tx_result is None:
            return self._observation(
                tx_hash,
                observed_at_epoch_s,
                ChainPresence.ABSENT,
                head_number=head_number,
                head_hash=head_hash,
                evidence=evidence,
            )
        tx = _require_mapping(tx_result, field="transaction")
        if _hash(tx.get("hash"), field="transaction.hash") != tx_hash:
            raise _protocol("transaction hash disagrees with requested hash")
        if _address(tx.get("from"), field="transaction.from") != taker:
            raise _protocol("transaction sender disagrees with configured taker")
        if _quantity(tx.get("chainId"), field="transaction.chainId") != chain_id:
            raise _protocol("transaction chain id disagrees with provider chain")
        tx_block_number = tx.get("blockNumber")
        tx_block_hash = tx.get("blockHash")
        if tx_block_number is None:
            if tx_block_hash is not None:
                raise _protocol("pending transaction carries a block hash")
            evidence["receipt"] = None
            return self._observation(
                tx_hash,
                observed_at_epoch_s,
                ChainPresence.PENDING,
                head_number=head_number,
                head_hash=head_hash,
                evidence=evidence,
            )
        inclusion_number = _block_number(tx_block_number, field="transaction.blockNumber")
        inclusion_hash = _hash(tx_block_hash, field="transaction.blockHash")
        receipt_result = self._call("eth_getTransactionReceipt", (tx_hash,))
        receipt = _require_mapping(receipt_result, field="receipt")
        if _hash(receipt.get("transactionHash"), field="receipt.transactionHash") != tx_hash:
            raise _protocol("receipt transaction hash disagrees with transaction")
        if _hash(receipt.get("blockHash"), field="receipt.blockHash") != inclusion_hash:
            raise _protocol("receipt block hash disagrees with transaction")
        if _block_number(receipt.get("blockNumber"), field="receipt.blockNumber") != inclusion_number:
            raise _protocol("receipt block number disagrees with transaction")
        inclusion_block = _require_mapping(
            self._call("eth_getBlockByHash", (inclusion_hash, False)),
            field="inclusion block",
        )
        if _hash(inclusion_block.get("hash"), field="inclusion.hash") != inclusion_hash:
            raise _protocol("inclusion block hash disagrees with lookup")
        if _block_number(inclusion_block.get("number"), field="inclusion.number") != inclusion_number:
            raise _protocol("inclusion block number disagrees with lookup")
        parent_hash = _hash(inclusion_block.get("parentHash"), field="inclusion.parentHash")
        status_value = _quantity(receipt.get("status"), field="receipt.status")
        if status_value not in (0, 1):
            raise _protocol("receipt status is not success or reverted")
        evidence["receipt"] = dict(receipt)
        evidence["inclusion_block"] = dict(inclusion_block)
        if status_value == 0:
            return self._observation(
                tx_hash,
                observed_at_epoch_s,
                ChainPresence.INCLUDED,
                head_number=head_number,
                head_hash=head_hash,
                block_number=inclusion_number,
                block_hash=inclusion_hash,
                block_parent_hash=parent_hash,
                receipt_status=ReceiptStatus.REVERTED,
                evidence=evidence,
            )
        input_amount, output_amount = self._transfer_amounts(
            receipt.get("logs"),
            taker=taker,
            input_token=input_asset,
            output_token=output_asset,
        )
        evidence["effective_input_atomic"] = str(input_amount)
        evidence["effective_output_atomic"] = str(output_amount)
        return self._observation(
            tx_hash,
            observed_at_epoch_s,
            ChainPresence.INCLUDED,
            head_number=head_number,
            head_hash=head_hash,
            block_number=inclusion_number,
            block_hash=inclusion_hash,
            block_parent_hash=parent_hash,
            receipt_status=ReceiptStatus.SUCCESS,
            effective_input_atomic=input_amount,
            effective_output_atomic=output_amount,
            evidence=evidence,
        )

    @staticmethod
    def _transfer_amounts(
        logs: Any,
        *,
        taker: str,
        input_token: str,
        output_token: str,
    ) -> tuple[int, int]:
        if not isinstance(logs, list):
            raise _protocol("receipt.logs must be an array")
        input_total = 0
        output_total = 0
        for index, raw_log in enumerate(logs):
            log = _require_mapping(raw_log, field=f"receipt.logs[{index}]")
            topics = log.get("topics")
            if not isinstance(topics, list):
                raise _protocol(f"receipt.logs[{index}].topics is malformed")
            if not topics:
                continue
            if not isinstance(topics[0], str) or topics[0].lower() != _TRANSFER_TOPIC:
                continue
            if len(topics) != 3:
                raise _protocol(f"receipt.logs[{index}] Transfer topics are malformed")
            token = _address(log.get("address"), field=f"receipt.logs[{index}].address")
            sender = _topic_address(topics[1], field=f"receipt.logs[{index}].topics[1]")
            recipient = _topic_address(topics[2], field=f"receipt.logs[{index}].topics[2]")
            value = int.from_bytes(_bytes(log.get("data"), field=f"receipt.logs[{index}].data", length=32), "big")
            if value <= 0 or value > _MAX_UINT256:
                raise _protocol(f"receipt.logs[{index}] Transfer amount is outside bounds")
            if token == input_token and sender == taker:
                input_total += value
                if input_total > _MAX_UINT256:
                    raise _protocol("input transfer sum exceeds uint256")
            if token == output_token and recipient == taker:
                output_total += value
                if output_total > _MAX_UINT256:
                    raise _protocol("output transfer sum exceeds uint256")
        if input_total <= 0 or output_total <= 0:
            raise _protocol("receipt does not establish exact token amounts")
        return input_total, output_total

    def _observation(
        self,
        transaction_hash: str,
        observed_at_epoch_s: int,
        presence: ChainPresence,
        *,
        head_number: int,
        head_hash: str,
        evidence: Mapping[str, Any],
        block_number: int | None = None,
        block_hash: str | None = None,
        block_parent_hash: str | None = None,
        receipt_status: ReceiptStatus | None = None,
        effective_input_atomic: int | None = None,
        effective_output_atomic: int | None = None,
    ) -> ChainObservationV0:
        raw_digest = sha256_hex(canonical_json_bytes(dict(evidence)))
        return ChainObservationV0(
            provider_id=self.provider_id,
            transaction_hash=transaction_hash,
            observed_at_epoch_s=observed_at_epoch_s,
            presence=presence,
            raw_evidence_sha256=raw_digest,
            block_number=block_number,
            block_hash=block_hash,
            block_parent_hash=block_parent_hash,
            head_block_number=head_number,
            head_block_hash=head_hash,
            receipt_status=receipt_status,
            effective_input_atomic=effective_input_atomic,
            effective_output_atomic=effective_output_atomic,
        )
