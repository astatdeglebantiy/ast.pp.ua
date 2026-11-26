import hashlib
import time
from typing import Literal

import lmdb
import msgspec

from services.core_store.models import new_uuid7_bytes
from services.mail.queue import OutboundRecord


DeliveryEventType = Literal[
    "Delivery",
    "Bounce",
    "Complaint",
]


class DeliveryEvent(msgspec.Struct):
    id: bytes
    outbound_id: bytes
    user_id: bytes
    ses_message_id: str
    event_type: DeliveryEventType
    recipient: str
    occurred_ms: int
    received_ms: int


class DeliveryJournal:
    """
    Persistent, idempotent delivery-event journal.

    Events are associated with an immutable outbound
    message UUID and its owner UUID.

    Provider notifications must be authenticated and
    correlated before calling append().
    """

    def __init__(self, env: lmdb.Environment) -> None:
        self.env = env

        self.db = env.open_db(
            b"delivery_events"
        )

        self.dedup_db = env.open_db(
            b"delivery_event_dedup"
        )

        self.outbound_db = env.open_db(
            b"outbound_queue"
        )

    @staticmethod
    def _now() -> int:
        return int(time.time() * 1000)

    def append(
        self,
        *,
        event_key: str,
        outbound_id: bytes,
        user_id: bytes,
        ses_message_id: str,
        event_type: DeliveryEventType,
        recipient: str,
        occurred_ms: int,
    ) -> tuple[DeliveryEvent, bool]:
        """
        Persist a correlated delivery event.

        Returns:
            (event, True)  - newly inserted
            (event, False) - already processed

        event_key must be a stable unique identity
        of the provider notification, not a newly
        generated value on each HTTP request.
        """

        if not isinstance(event_key, str) or not event_key:
            raise ValueError("Invalid event key")

        if len(event_key) > 512:
            raise ValueError("Event key is too long")

        if not isinstance(outbound_id, bytes) or len(outbound_id) != 16:
            raise ValueError("Invalid outbound UUID")

        if not isinstance(user_id, bytes) or len(user_id) != 16:
            raise ValueError("Invalid user UUID")

        if event_type not in (
            "Delivery",
            "Bounce",
            "Complaint",
        ):
            raise ValueError("Unsupported event type")

        if not isinstance(ses_message_id, str):
            raise ValueError("Invalid SES message ID")

        if not ses_message_id or len(ses_message_id) > 512:
            raise ValueError("Invalid SES message ID")

        if not isinstance(recipient, str):
            raise ValueError("Invalid recipient")

        recipient = recipient.strip().lower()

        if not recipient or len(recipient) > 254:
            raise ValueError("Invalid recipient")

        if not isinstance(occurred_ms, int) or occurred_ms < 0:
            raise ValueError("Invalid event timestamp")

        dedup_key = hashlib.sha256(
            event_key.encode("utf-8")
        ).digest()

        with self.env.begin(write=True) as txn:
            existing_id = txn.get(
                dedup_key,
                db=self.dedup_db,
            )

            if existing_id is not None:
                raw = txn.get(
                    existing_id,
                    db=self.db,
                )

                if raw is None:
                    raise RuntimeError(
                        "Delivery dedup index is inconsistent"
                    )

                existing = msgspec.msgpack.decode(
                    raw,
                    type=DeliveryEvent,
                )

                if (
                    existing.outbound_id != outbound_id
                    or existing.user_id != user_id
                    or existing.ses_message_id != ses_message_id
                    or existing.event_type != event_type
                    or existing.recipient != recipient
                    or existing.occurred_ms != occurred_ms
                ):
                    raise ValueError(
                        "Conflicting delivery event key"
                    )

                return existing, False

            outbound_raw = txn.get(
                outbound_id,
                db=self.outbound_db,
            )

            if outbound_raw is None:
                raise ValueError(
                    "Outbound message not found"
                )

            outbound = msgspec.msgpack.decode(
                outbound_raw,
                type=OutboundRecord,
            )

            if outbound.user_id != user_id:
                raise ValueError(
                    "Outbound owner does not match"
                )

            if outbound.recipient.lower() != recipient:
                raise ValueError(
                    "Outbound recipient does not match"
                )

            event = DeliveryEvent(
                id=new_uuid7_bytes(),
                outbound_id=outbound_id,
                user_id=user_id,
                ses_message_id=ses_message_id,
                event_type=event_type,
                recipient=recipient,
                occurred_ms=occurred_ms,
                received_ms=self._now(),
            )

            inserted = txn.put(
                event.id,
                msgspec.msgpack.encode(event),
                db=self.db,
                overwrite=False,
            )

            if not inserted:
                raise RuntimeError(
                    "Duplicate delivery event UUID"
                )

            txn.put(
                dedup_key,
                event.id,
                db=self.dedup_db,
                overwrite=False,
            )

            return event, True

    def get(
        self,
        event_id: bytes,
    ) -> DeliveryEvent | None:
        with self.env.begin() as txn:
            raw = txn.get(
                event_id,
                db=self.db,
            )

        if raw is None:
            return None

        return msgspec.msgpack.decode(
            raw,
            type=DeliveryEvent,
        )

    def list_for_outbound(
        self,
        outbound_id: bytes,
        limit: int = 100,
    ) -> list[DeliveryEvent]:
        if limit <= 0:
            return []

        events: list[DeliveryEvent] = []

        with self.env.begin() as txn:
            with txn.cursor(db=self.db) as cursor:
                for _, raw in cursor:
                    event = msgspec.msgpack.decode(
                        raw,
                        type=DeliveryEvent,
                    )

                    if event.outbound_id == outbound_id:
                        events.append(event)

        events.sort(
            key=lambda event: (
                event.occurred_ms,
                event.received_ms,
            )
        )

        return events[-limit:]
