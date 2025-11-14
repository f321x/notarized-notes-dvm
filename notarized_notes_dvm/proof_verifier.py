import asyncio
import logging
from asyncio.queues import QueueFull
from decimal import Decimal
from typing import Optional, AsyncGenerator
from dataclasses import dataclass

# todo: replace connectrum with electrum library as it is now pulled in anyways
from connectrum.client import StratumClient as ElectrumServerClient
from connectrum.svr_info import ServerInfo as ElectrumServerInfo
from connectrum import ElectrumErrorResponse
from cachetools import LRUCache
from electrum_aionostr.event import Event as NostrEvent
from electrum.bitcoin import construct_script, redeem_script_to_address, address_to_script, opcodes

from .util import now, is_hex_str, leaf_hash, node_hash, verify_signature


class UnconfirmedTx(Exception): pass
class InvalidProof(Exception): pass
class MalformedElectrumServerResponseError(Exception): pass


@dataclass(frozen=True, kw_only=True)
class Proof:
    proof_version: int
    notarized_event_id: str
    leaf_hash: str
    proof_txid: str
    proof_block_height: int
    nonce: str
    proof_leaf_value_msat: int
    proof_merkle_index: int
    proof_merkle_hashes: list[tuple[str, int]]
    upvoter_pubkey: Optional[str]
    upvoter_signature: Optional[str]
    chain: Optional[str]

    def __post_init__(self):
        assert isinstance(self.proof_version, int)
        assert is_hex_str(self.notarized_event_id, 32), self.notarized_event_id
        assert is_hex_str(self.leaf_hash, 32), self.leaf_hash
        assert is_hex_str(self.proof_txid, 32), self.proof_txid
        assert isinstance(self.proof_block_height, int)  # most certainly 0
        assert is_hex_str(self.nonce), self.nonce
        assert isinstance(self.proof_leaf_value_msat, int)
        assert isinstance(self.proof_merkle_index, int)
        assert len(self.proof_merkle_hashes) > 0, self.proof_merkle_hashes
        for merkle_hash, value in self.proof_merkle_hashes:
            assert is_hex_str(merkle_hash, 32), merkle_hash
            assert isinstance(value, int), value
        if self.chain is not None:
            assert is_hex_str(self.chain, 32)
            # mainnet only
            assert self.chain in (
                "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000",
                "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
            )
        assert isinstance(self.upvoter_pubkey, str) or self.upvoter_pubkey is None
        if self.upvoter_pubkey is not None:
            assert self.upvoter_signature
        else:
            assert self.upvoter_signature is None

    @classmethod
    def from_nostr_event(cls, notarization_event: NostrEvent) -> 'Proof':
        proof_version = None
        notarized_event_id = None
        leaf_hash = None
        proof_txid = None
        proof_block_height = None
        proof_nonce = None
        proof_leaf_value_msat = None
        proof_merkle_index = None
        proof_merkle_hashes = []
        chain = None
        upvoter_pubkey = None
        upvoter_signature = None

        for tag in notarization_event.tags:
            match tag[0]:
                case 'version':
                    proof_version = int(tag[1])
                case 'e':
                    notarized_event_id = tag[1]
                case 'd':
                    leaf_hash = tag[1]
                case 'n':
                    proof_txid = tag[1]
                    proof_block_height = int(tag[2])
                    proof_nonce = tag[3]
                    proof_leaf_value_msat = int(tag[4])
                    proof_merkle_index = int(tag[5])
                    for hash_value in tag[6].split(','):
                        m_hash, value = hash_value.split(':')
                        proof_merkle_hashes.append((m_hash, int(value)))
                case 'chain':
                    chain = tag[1]
                case 'u':
                    upvoter_pubkey = tag[1]
                    upvoter_signature = tag[3]
                case _:
                    continue

        proof = Proof(
            proof_version=proof_version,
            notarized_event_id=notarized_event_id,
            leaf_hash=leaf_hash,
            proof_txid=proof_txid,
            proof_block_height=proof_block_height,
            nonce=proof_nonce,
            proof_leaf_value_msat=proof_leaf_value_msat,
            proof_merkle_index=proof_merkle_index,
            proof_merkle_hashes=proof_merkle_hashes,
            chain=chain,
            upvoter_pubkey=upvoter_pubkey,
            upvoter_signature=upvoter_signature,
        )
        return proof

    def get_root(self, leaf_h: bytes, leaf_v: int) -> tuple[bytes, int]:
        h, v = leaf_h, leaf_v
        j = self.proof_merkle_index
        for h2, v2 in self.proof_merkle_hashes:
            h2 = bytes.fromhex(h2)
            h = node_hash(h, v, h2, v2) if j%2 == 0 else node_hash(h2, v2, h, v)
            v += v2
            j = j >> 1
        value_sats = v // 1000
        assert value_sats * 1000 == v
        return h, value_sats


@dataclass
class UnverifiedNotarization:
    proof: Proof
    notarization_event: NostrEvent
    next_verification: int = now()
    verification_attempts: int = 1

    def verify_now(self) -> bool:
        return now() > self.next_verification

    def reset_attempts(self):
        self.verification_attempts = 1

    def bump_attempts(self):
        self.verification_attempts += 1

    def verify_in(self, in_sec: int):
        self.next_verification = now() + in_sec


class NotarizationProofVerifier:
    PROOF_VERSION = 0
    MAX_PROOF_VERIFICATION_ATTEMPTS = 10
    TRANSACTION_REQUEST_DELAY_SEC = 30  # how often we request the same txid from the electrum server
    OP_RETURN_MAGIC_BYTES = bytes.fromhex('0021')

    def __init__(self, electrum_server: str):
        self.logger = logging.getLogger('proof-verifier')
        electrum_server: list[str] = electrum_server.split(':')
        assert len(electrum_server) == 3, "provide ELECTRUM_SERVER as host:port:protocol"
        assert electrum_server[2] in ('s', 't'), f"provide electrum server with s or t protocol"
        self.electrum_server_info: ElectrumServerInfo = ElectrumServerInfo(
            hostname=electrum_server[0],
            ports=[electrum_server[2], electrum_server[1]],
            nickname_or_dict='verifier',
        )
        self.electrum_server = None  # type: Optional[ElectrumServerClient]
        self.unverified_proofs = asyncio.Queue(maxsize=20_000)  # type: asyncio.Queue[UnverifiedNotarization]
        self.verified_proofs = asyncio.Queue(maxsize=20_000)  # type: asyncio.Queue[(bool, str, Proof)]  # valid, notarization event id, Proof
        # we can get multiple proofs to verify contained in the same tx, this cache allows to request
        # each txid only once instead of fetching the same tx multiple times for different proofs we want to verify
        self.requested_txids = LRUCache(maxsize=1000)  # type: LRUCache[str, tuple[int, dict]]  # txid -> tuple[last update ts, server resp]
        self.connected = asyncio.Event()

    async def run(self):
        try:
            await self.connect_to_electrum_server()
            await self.verify_proofs()
        finally:
            self.stop()
            await asyncio.sleep(0.1)

    def stop(self):
        if self.electrum_server:
            server_to_close = self.electrum_server
            # set server none so the disconnect cb doesn't try to reconnect
            self.electrum_server = None
            self.connected.clear()
            server_to_close.close()

    async def connect_to_electrum_server(self):
        self.electrum_server = ElectrumServerClient()
        try:
            await self.electrum_server.connect(
                self.electrum_server_info,
                proto_code=self.electrum_server_info['ports'][0],
                use_tor=False,
                disable_cert_verify=True,
                proxy=None,
                short_term=False,
                disconnect_callback=self.electrum_server_disconnected_cb,
            )
        except Exception:
            self.electrum_server = None
            raise
        self.connected.set()

    def electrum_server_disconnected_cb(self, _client: ElectrumServerClient):
        self.electrum_server = None
        self.connected.clear()
        self.logger.exception(f"Electrum server disconnected")
        async def try_reconnect():
            self.logger.info(f"reconnecting to electrum server")
            try:
                await asyncio.wait_for(self.connect_to_electrum_server(), timeout=60)
                self.logger.info(f"reconnected to electrum server")
            except Exception:
                await asyncio.sleep(60)
            return
        # only try to reconnect if server is not None, we set server None on stop()/shutdown
        if self.electrum_server is not None:
            asyncio.run_coroutine_threadsafe(try_reconnect(), asyncio.get_running_loop())

    async def verify(self, unverified_notarization: UnverifiedNotarization):
        await self.unverified_proofs.put(unverified_notarization)

    async def get_verified_proofs(self) -> AsyncGenerator[tuple[bool, str, Proof], None]:
        while True:
            verified_proof = await self.verified_proofs.get()
            yield verified_proof

    async def verify_proofs(self) -> None:
        # this doesn't have to be very fast as it happens concurrently to the requests, so
        # we rather add some generous sleeps to not abuse the electrum server too much
        while True:
            await asyncio.sleep(10)

            notarization = await self.unverified_proofs.get()

            if notarization.verification_attempts > self.MAX_PROOF_VERIFICATION_ATTEMPTS:
                # we couldn't verify this proof, so it gets blacklisted
                self.verified_proofs.put_nowait((False, notarization.notarization_event.id, notarization.proof))
                continue
            if not notarization.verify_now():
                # not ready yet, try again later
                maybe_put_on_queue(notarization, self.unverified_proofs)
                continue

            await self.connected.wait()
            try:
                await self.verify_proof(notarization.proof)
            except UnconfirmedTx:
                self.logger.debug(f"unconfirmed proof tx: {notarization.proof.proof_txid}, "
                                  f"checking again in 30 sec: {notarization.notarization_event.id=}")
                # only consider confirmed transactions for verifications
                notarization.verify_in(30)
                # reset, maybe we increased the counter because it wasn't in our mempool before
                notarization.reset_attempts()
                maybe_put_on_queue(notarization, self.unverified_proofs)
                continue
            except (ElectrumErrorResponse, MalformedElectrumServerResponseError) as e:
                # maybe not in servers mempool yet, or other network (e.g. testnet notarization)
                self.logger.warning(f"electrum server error: {e}", exc_info=isinstance(e, MalformedElectrumServerResponseError))
                notarization.verify_in(notarization.verification_attempts * 30)
                notarization.bump_attempts()
                maybe_put_on_queue(notarization, self.unverified_proofs)
                continue
            except (InvalidProof, Exception):  # definitely invalid, no need to retry
                self.logger.debug(f"proof verification failed: {notarization.notarization_event.id=}", exc_info=True)
                self.verified_proofs.put_nowait((False, notarization.notarization_event.id, notarization.proof))
                continue

            # proof tx is valid and confirmed
            self.logger.debug(f"verified proof: {notarization.notarization_event.id=}")
            self.verified_proofs.put_nowait((True, notarization.notarization_event.id, notarization.proof))

    async def verify_proof(self, proof: Proof):
        tx_info = await self.fetch_tx_from_server(proof.proof_txid)
        try:
            confs = int(tx_info.get('confirmations', 0))
            tx = tx_info['hex']
            assert is_hex_str(tx), tx
            vout: list[dict] = tx_info['vout']
        except Exception as e:
            raise MalformedElectrumServerResponseError("invalid electrum server response") from e
        if confs < 1:
            raise UnconfirmedTx()

        # 1. verify that the hash of the leaf is in the root of the tree
        event_id = bytes.fromhex(proof.notarized_event_id)
        nonce = bytes.fromhex(proof.nonce)
        upvoter_pubkey = bytes.fromhex(proof.upvoter_pubkey or '')
        upvoter_signature = bytes.fromhex(proof.upvoter_signature or '')
        leaf_value = proof.proof_leaf_value_msat
        leaf_h = leaf_hash(event_id, leaf_value, nonce, upvoter_pubkey)
        if upvoter_pubkey:
            if not verify_signature(leaf_h, upvoter_pubkey, upvoter_signature):
                raise InvalidProof('invalid upvoter signature')
        root_hash, root_v = proof.get_root(leaf_h, leaf_value)
        tx_root_hash, csv_delay, txo_value, index, redeem_script = self.parse_tx_outputs(vout)
        if tx_root_hash != root_hash:
            raise InvalidProof('root mismatch')
        # 4. verify that the amount burnt by the tx equals the sum of tree roots
        if txo_value != root_v:
            raise InvalidProof('value mismatch')

    async def fetch_tx_from_server(self, txid: str) -> dict:
        tx_info = None
        if txid_cache := self.requested_txids.get(txid):
            last_req_ts, tx_info = txid_cache
            if now() - last_req_ts > self.TRANSACTION_REQUEST_DELAY_SEC:
                tx_info = None  # request again, outdated

        if tx_info is None:  # no cached info
            assert self.connected.is_set()
            tx_info = await self.electrum_server.RPC(  # type: ignore
                'blockchain.transaction.get',
                txid,
                True,
            )
        self.requested_txids[txid] = (now(), tx_info)  # cache the request
        return tx_info

    def parse_tx_outputs(self, txouts: list[dict]):
        """txouts is 'vout' of getrawtransaction core rpc returned from electrum server"""
        for output in txouts:
            spk = bytes.fromhex(output['scriptPubKey']['hex'])
            if spk.startswith(bytes.fromhex('6a')):  # OP_RETURN
                data = spk[2:]
                if len(data) == 36 and data.startswith(self.OP_RETURN_MAGIC_BYTES):
                    root_hash = data[2:34]
                    csv_delay = int.from_bytes(data[34:], 'big')
                    break
        else:
            raise Exception('op_return output not found')

        redeem_script, scriptpubkey = make_output_script(csv_delay)
        for i, txo in enumerate(txouts):
            output_spk = bytes.fromhex(txo['scriptPubKey']['hex'])
            if output_spk == scriptpubkey:
                break
        else:
            raise Exception('burn output not found')
        txo_value = int(Decimal(txo['value']) * 100_000_000)
        return root_hash, csv_delay, txo_value, i, redeem_script


def maybe_put_on_queue(element, queue: asyncio.Queue) -> None:
    """Try to put element on given queue, drop element if queue is full"""
    try:
        queue.put_nowait(element)
    except QueueFull:
        pass


def make_output_script(csv_delay: int) -> tuple[bytes, bytes]:
    redeem_script = construct_script([csv_delay, opcodes.OP_CHECKSEQUENCEVERIFY, opcodes.OP_DROP, opcodes.OP_TRUE])
    address = redeem_script_to_address('p2wsh', redeem_script)
    scriptpubkey = address_to_script(address)
    return redeem_script, scriptpubkey
