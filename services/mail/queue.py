import time
from typing import Literal

import lmdb
import msgspec

from services.core_store.models import new_uuid7_bytes


MailStatus = Literal[
    "queued",
    "sending",
    "accepted",
    "retry",
    "failed",
    "unknown",
    "cancelled",
]


class OutboundRecord(msgspec.Struct):
    id: bytes
    sender: str
    recipient: str
    subject: str
    body: str
    created_ms: int

    status: MailStatus = "queued"
    attempts: int = 0
    updated_ms: int = 0
    last_error: str = ""
    smtp_server: str = ""
    next_attempt_ms: int = 0
    raw_mime: bytes = b""

    # Immutable owner UUID.
    # Empty for legacy records.
    user_id: bytes = b""


class OutboundQueue:
    def __init__(self, env: lmdb.Environment) -> None:
        self.env = env
        self.db = env.open_db(b"outbound_queue")
        self.control_db = env.open_db(b"outbound_control")

    @staticmethod
    def _now() -> int:
        return int(time.time() * 1000)

    def enqueue(
        self,
        sender: str,
        recipient: str,
        subject: str,
        body: str,
    ) -> OutboundRecord:
        now = self._now()

        record = OutboundRecord(
            id=new_uuid7_bytes(),
            sender=sender,
            recipient=recipient,
            subject=subject,
            body=body,
            created_ms=now,
            updated_ms=now,
        )

        with self.env.begin(write=True) as txn:
            inserted = txn.put(
                record.id,
                msgspec.msgpack.encode(record),
                db=self.db,
                overwrite=False,
            )

            if not inserted:
                raise RuntimeError("Duplicate outbound ID")

        return record

    def get(self, message_id: bytes) -> OutboundRecord | None:
        with self.env.begin() as txn:
            raw = txn.get(message_id, db=self.db)

        if raw is None:
            return None

        return msgspec.msgpack.decode(
            raw,
            type=OutboundRecord,
        )

    def list(
        self,
        status: MailStatus | None = None,
        limit: int = 100,
    ) -> list[OutboundRecord]:
        result = []

        with self.env.begin() as txn:
            cursor = txn.cursor(db=self.db)

            for _, raw in cursor:
                record = msgspec.msgpack.decode(
                    raw,
                    type=OutboundRecord,
                )

                if status is not None and record.status != status:
                    continue

                result.append(record)

        result.sort(
            key=lambda item: item.created_ms,
            reverse=True,
        )

        return result[:max(0, limit)]

    def transition(
        self,
        message_id: bytes,
        expected: tuple[MailStatus, ...],
        new_status: MailStatus,
        error: str = "",
        smtp_server: str = "",
        next_attempt_ms: int = 0,
    ) -> OutboundRecord | None:
        with self.env.begin(write=True) as txn:
            if new_status == "sending":
                enabled = txn.get(
                    b"delivery_enabled",
                    db=self.control_db,
                )
                if enabled != b"1":
                    return None

            raw = txn.get(message_id, db=self.db)

            if raw is None:
                return None

            record = msgspec.msgpack.decode(
                raw,
                type=OutboundRecord,
            )

            if record.status not in expected:
                return None

            record.status = new_status
            record.updated_ms = self._now()
            record.last_error = error[:1024]
            record.next_attempt_ms = next_attempt_ms

            if smtp_server:
                record.smtp_server = smtp_server

            if new_status == "sending":
                record.attempts += 1

            txn.put(
                message_id,
                msgspec.msgpack.encode(record),
                db=self.db,
            )

            return record

    def list_due(
        self,
        limit: int = 20,
    ) -> list[OutboundRecord]:
        """
        Return queued messages and retries whose
        next attempt time has arrived.
        """
        if limit <= 0:
            return []

        now = self._now()
        result: list[OutboundRecord] = []

        with self.env.begin() as txn:
            cursor = txn.cursor(db=self.db)

            for _, raw in cursor:
                record = msgspec.msgpack.decode(
                    raw,
                    type=OutboundRecord,
                )

                if record.status not in ("queued", "retry"):
                    continue

                if record.next_attempt_ms > now:
                    continue

                result.append(record)

                if len(result) >= limit:
                    break

        return result

    def recover_inflight(self) -> int:
        """
        Mark interrupted SMTP operations as unknown.

        Do not automatically resend them.
        Only call during exclusive worker startup.
        """
        changed = 0

        with self.env.begin(write=True) as txn:
            cursor = txn.cursor(db=self.db)
            updates: list[tuple[bytes, bytes]] = []

            for key, raw in cursor:
                record = msgspec.msgpack.decode(
                    raw,
                    type=OutboundRecord,
                )

                if record.status != "sending":
                    continue

                record.status = "unknown"
                record.updated_ms = self._now()
                record.next_attempt_ms = 0
                record.last_error = (
                    "Interrupted during SMTP delivery; "
                    "manual review required"
                )

                updates.append((
                    bytes(key),
                    msgspec.msgpack.encode(record),
                ))

            for key, value in updates:
                txn.put(key, value, db=self.db)
                changed += 1

        return changed

    def delivery_enabled(self) -> bool:
        """
        Read persistent automatic delivery state.

        Missing key means disabled (safe default).
        """
        with self.env.begin() as txn:
            value = txn.get(
                b"delivery_enabled",
                db=self.control_db,
            )

        return value == b"1"

    def set_delivery_enabled(
        self,
        enabled: bool,
    ) -> None:
        """
        Persist the automatic delivery switch.
        """
        if not isinstance(enabled, bool):
            raise TypeError("enabled must be bool")

        with self.env.begin(write=True) as txn:
            txn.put(
                b"delivery_enabled",
                b"1" if enabled else b"0",
                db=self.control_db,
            )
