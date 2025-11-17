import asyncio
import json
from collections import defaultdict
from pathlib import Path
from typing import Sequence, Optional

from electrum_aionostr.event import Event as NostrEvent
from aionostr_dvm import AIONostrDVM, NIP89Info
from cachetools import cached, TTLCache

from .util import now
from .proof_verifier import (Proof, UnverifiedNotarization, NotarizationProofVerifier,
                             BitcoinDaemonConfig)


class NotarizedNotesDVM(AIONostrDVM):
    NOTARIZATION_EVENT_KIND = 30021

    def __init__(self, relays: Sequence[str], private_key_hex: str, db_path: Path, bitcoin_daemon_conf: BitcoinDaemonConfig):
        AIONostrDVM.__init__(
            self,
            dvm_name='Notarized Notes',
            relays=relays,
            private_key_hex=private_key_hex,
            service_event_kind=5300,  # content discovery event kind
        )
        self.proof_verifier = NotarizationProofVerifier(bitcoin_daemon_conf)
        self.db_path = db_path if str(db_path).endswith('.json') else Path(str(db_path) + ".json")
        self.db: dict = defaultdict(dict, self.load_db())
        # event ids of proof events we already verified
        self.verified_proofs = self.db['verified']
        self.invalid_proofs = self.db['invalid'] = set(self.db.get('invalid', []))

    async def __aenter__(self):
        await AIONostrDVM.__aenter__(self)
        assert self.taskgroup is not None
        self.taskgroup.create_task(self.proof_verifier.run())
        self.taskgroup.create_task(self.query_notarization_events())
        self.taskgroup.create_task(self.keep_db_up_to_date())
        self.taskgroup.create_task(self.save_verified_proofs())
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.save_db()
        await AIONostrDVM.__aexit__(self, exc_type, exc_val, exc_tb)

    async def query_notarization_events(self):
        query = {
            "kinds": [self.NOTARIZATION_EVENT_KIND],
        }
        async for notarization_event in self.subscribe_to_filter(query):
            if notarization_event.id in self.invalid_proofs:
                continue  # we already tried to verify this event before
            try:
                proof = Proof.from_nostr_event(notarization_event)
            except Exception:
                # self.logger.debug(
                # f"malformed notarization event: {notarization_event.id}: {notarization_event}",
                # exc_info=True
                # )  # spammy as there are other things using the same event kind too
                continue
            if proof.proof_version != self.proof_verifier.PROOF_VERSION:
                self.logger.debug(f"{notarization_event.id} has different proof version {proof.proof_version=}")
                continue
            if proof.notarized_event_id in self.verified_proofs:
                if notarization_event.id in self.verified_proofs[proof.notarized_event_id]['proof_events']:
                    continue
            await self.proof_verifier.verify(UnverifiedNotarization(proof, notarization_event))

    async def save_verified_proofs(self):
        async for verified_proof in self.proof_verifier.get_verified_proofs():
            is_valid, notarization_event_id, proof = verified_proof
            if is_valid:
                self.save_valid_proof(notarization_event_id, proof)
            else:
                self.save_invalid_proof(notarization_event_id)

    def save_invalid_proof(self, notarization_event_id: str):
        self.logger.debug(f"saving invalid notarization event: {notarization_event_id=}")
        self.invalid_proofs.add(notarization_event_id)

    def save_valid_proof(self, notarization_event_id: str, proof: Proof):
        # assert proof.proof_block_height > 0, "we only store confirmed proofs"
        if proof.notarized_event_id in self.verified_proofs:
            event_summary = self.verified_proofs[proof.notarized_event_id]
        else:
            # we need to store the proof event id to ensure it is not counted twice
            event_summary = {
                'proof_events': {},  # dict proof_event_id -> amount
                'total_amount_sat': 0,
            }
        event_summary['proof_events'][notarization_event_id] = proof.proof_leaf_value_msat // 1000
        event_summary['total_amount_sat'] += proof.proof_leaf_value_msat // 1000
        event_summary['last_updated'] = now()
        self.logger.debug(f"saving verified proof, {event_summary=}")
        self.verified_proofs[proof.notarized_event_id] = event_summary

    @cached(cache=TTLCache(maxsize=1, ttl=60))
    def get_sorted_notarized_event_ids(self) -> list[str]:
        current_time = now()
        decay_half_life = 30 * 24 * 3600  # 30 days in seconds

        scored_events = []
        for event_id, summary in self.verified_proofs.items():
            age_seconds = current_time - summary['last_updated']
            decay_factor = 2 ** (-age_seconds / decay_half_life)
            score = summary['total_amount_sat'] * decay_factor
            scored_events.append((event_id, score))

        scored_events.sort(key=lambda x: x[1], reverse=True)
        confirmed_scored_events = [event_id for event_id, _ in scored_events[:500]]
        confirmed_scored_events_set = set(confirmed_scored_events)
        # append unconfirmed, newly notarized events, sorted by descending amount
        mempool_proofs = sorted(self.proof_verifier.get_mempool_proofs().items(), key=lambda x: x[1], reverse=True)
        # sort out the event ids that are already in the confirmed set
        unconfirmed_events = [event_id for event_id, _ in mempool_proofs if event_id not in confirmed_scored_events_set]
        return confirmed_scored_events + unconfirmed_events

    async def handle_request(self, request: NostrEvent) -> Optional[NostrEvent]:
        event_ids = [['e', id] for id in self.get_sorted_notarized_event_ids()]
        tags = [
            ["request", json.dumps(request.to_json_object())],
            ["e", request.id],
            ["p", request.pubkey],
            ["status", "success"],
        ]
        response = NostrEvent(
            kind=6300,
            content=json.dumps(event_ids),
            pubkey=self.pubkey,
            tags=tags,
            expiration_ts=now() + 15552000,
            # ~180d expiry, clients seem to break if the response to a request they sent is
            # not available anymore, and won't request a new one, rendering the dvm broken in this client
            # instance, so the expiry has to be far so the client is hopefully smart enough to just request
            # a new dvm task instead of waiting for a response to a request they sent 180days ago...
            # this seems dumb as a custom feed is very short-lived, and they should request a new feed every
            # time the user opens the custom feed anyway.
        )
        self.logger.debug(f"sending response to request {request.id}")
        return response

    async def get_announcement_info(self) -> Optional[NIP89Info]:
        content = {
            "name": self.dvm_name,
            "displayName": self.dvm_name,
            "website": "notary.electrum.org",
            "picture": "https://image.nostr.build/2f6eb8e1f7175dc9c14fdb6e3b101c2b33a10f8a25db828a686599e35eb4192b.png",
            "about": "Spam-free global feed of notarized notes. notary.electrum.org.",
            "lud16": "x@lnaddress.com",
            "supportsEncryption": False,
            "acceptsNutZaps": False,
            "personalized": False,
            "amount": "free",  # 'free' value seems weird but other dvms do it too...
            "nip90Params": {
                "max_results": {
                    "required": False,
                    "values": [],
                    "description": "This is ignored and just here so clients handle this properly?",
                },
            },
        }
        info = NIP89Info(
            content=content,
        )
        return info

    async def get_kind0_profile_event(self) -> NostrEvent:
        profile_info = {
            'name': self.dvm_name,
            'about': 'Spam-free global feed of notarized notes. notary.electrum.org.',
            'picture': 'https://image.nostr.build/2f6eb8e1f7175dc9c14fdb6e3b101c2b33a10f8a25db828a686599e35eb4192b.png',
            'display_name': self.dvm_name,
            'website': 'notary.electrum.org',
            'lud16': 'x@lnaddress.com',
        }
        profile_event = NostrEvent(
            kind=0,
            content=json.dumps(profile_info),
            tags=[],
            expiration_ts=now() + 31_536_000,  # 1y
            pubkey=self.pubkey,
        )
        return profile_event

    def load_db(self) -> dict:
        if not self.db_path.exists():
            return {}
        with open(self.db_path, 'r') as json_file:
            return json.load(json_file)

    async def save_db(self) -> None:
        def _save_db():
            try:
                with open(self.db_path, 'w') as new_db:
                    self.db['invalid'] = list(self.db['invalid'])  # convert set to list
                    json.dump(self.db, new_db, indent=2, sort_keys=True)
            except Exception:
                self.logger.exception(f"failed to write database")
                return
            self.logger.debug(f"db saved successfully")
        await asyncio.to_thread(_save_db)

    async def keep_db_up_to_date(self):
        """regularly save the db so it doesn't lag too much behind"""
        while True:
            await asyncio.sleep(900)  # 15 min
            await self.save_db()



