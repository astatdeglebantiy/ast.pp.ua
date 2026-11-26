import hashlib
import re
import secrets
import struct
import time
from pathlib import Path
import lmdb
import msgspec

from .models import (
    MAX_UINT64,
    InviteRecord,
    MailboxFlags,
    MessageRecord,
    SessionRecord,
    UserRecord, new_uuid7_bytes,
)
from ..identity.aliases import AliasRegistry, AliasRecord
from ..identity.tokens import AliasTokens
from ..mail.delivery_events import DeliveryJournal
from ..mail.outbound import build_signed_email
from ..mail.queue import OutboundQueue, OutboundRecord
from ..mail.transport.direct_smtp import validate_address, MAX_MESSAGE_BYTES


PRIMARY_EMAIL_DELAY_MS = 7 * 24 * 60 * 60 * 1000


class PrimaryEmailChangeRequest(msgspec.Struct):
    user_id: bytes
    old_username: str
    new_username: str
    created_ms: int
    execute_after_ms: int


class BinaryStore:
    def __init__(self, data_dir: str | Path, map_size_mb: int = 256) -> None:
        Path(data_dir).mkdir(parents=True, exist_ok=True)
        self.env = lmdb.open(
            str(data_dir),
            map_size=map_size_mb * 1024 * 1024,
            max_dbs=32,
            sync=True,
        )
        self.db_users = self.env.open_db(b"users")
        self.db_msgs = self.env.open_db(b"messages")
        self.db_mbox = self.env.open_db(b"mailbox")
        self.db_sessions = self.env.open_db(b"sessions")
        self.db_invites = self.env.open_db(b"invites")
        self.db_inbound = self.env.open_db(b"inbound_dedup")
        self.db_raw_mail = self.env.open_db(b"raw_mail")
        self.db_primary_email = self.env.open_db(
            b"identity_primary_email"
        )
        self.db_primary_pending = self.env.open_db(
            b"identity_primary_pending"
        )
        self.db_primary_pending_names = self.env.open_db(
            b"identity_primary_pending_names"
        )

        self.outbound = OutboundQueue(self.env)
        self.delivery_events = DeliveryJournal(self.env)

        self.aliases = AliasRegistry(self.env)
        self.alias_tokens = AliasTokens(self.env)

    def close(self) -> None:
        self.env.close()

    # --- Invites & Registration ---
    def has_any_users(self) -> bool:
        with self.env.begin(write=False) as txn:
            return txn.stat(db=self.db_users)["entries"] > 0

    def create_invite(
        self, created_by: str, max_uses: int = 1, ttl_hours: int = 168
    ) -> InviteRecord:
        now_ms = int(time.time() * 1000)
        expires_ms = now_ms + ttl_hours * 3600 * 1000
        with self.env.begin(write=True) as txn:
            while True:
                token = secrets.token_hex(4).upper()
                code = f"AST-{token[:4]}-{token[4:]}"
                inv = InviteRecord(
                    code=code,
                    created_by=created_by,
                    created_ms=now_ms,
                    expires_ms=expires_ms,
                    max_uses=max(1, max_uses),
                )
                if txn.put(
                    code.encode("utf-8"),
                    msgspec.msgpack.encode(inv),
                    db=self.db_invites,
                    overwrite=False,
                ):
                    return inv

    def list_invites(self) -> list[InviteRecord]:
        invites: list[InviteRecord] = []
        with self.env.begin(write=False) as txn:
            cursor = txn.cursor(db=self.db_invites)
            for _, raw in cursor:
                invites.append(msgspec.msgpack.decode(raw, type=InviteRecord))
        invites.sort(key=lambda i: i.created_ms, reverse=True)
        return invites

    def revoke_invite(self, code: str) -> bool:
        key = code.strip().upper().encode("utf-8")
        with self.env.begin(write=True) as txn:
            return txn.delete(key, db=self.db_invites)

    def register_with_invite(self, user: UserRecord, invite_code: str) -> UserRecord:
        user_key = user.username.lower().encode("utf-8")
        now_ms = int(time.time() * 1000)

        with self.env.begin(write=True) as txn:
            if txn.get(user_key, db=self.db_users) is not None:
                raise ValueError("Mailbox already exists")

            if txn.get(
                    b"reserved:" + user_key,
                    db=self.db_primary_email,
            ) is not None:
                raise ValueError("Mailbox name is reserved")

            if txn.get(
                    user_key,
                    db=self.db_primary_pending_names,
            ) is not None:
                raise ValueError("Mailbox name is reserved for pending change")

            is_first_user = txn.stat(db=self.db_users)["entries"] == 0
            if is_first_user:
                user = UserRecord(
                    id=user.id,
                    username=user.username,
                    password_hash=user.password_hash,
                    is_admin=True,
                )
            else:
                norm_code = invite_code.strip().upper()
                if not norm_code:
                    raise ValueError("Invite code is required")

                inv_key = norm_code.encode("utf-8")
                inv_raw = txn.get(inv_key, db=self.db_invites)
                if not inv_raw:
                    raise ValueError("Invalid invite code")

                inv = msgspec.msgpack.decode(inv_raw, type=InviteRecord)
                if now_ms > inv.expires_ms:
                    raise ValueError("Invite code has expired")
                if inv.uses_count >= inv.max_uses:
                    raise ValueError("Invite code has already been used")

                inv.uses_count += 1
                inv.used_by.append(user.username.lower())
                txn.put(inv_key, msgspec.msgpack.encode(inv), db=self.db_invites)

            txn.put(user_key, msgspec.msgpack.encode(user), db=self.db_users)
            return user

    # --- Users ---
    def get_user(self, username: str) -> UserRecord | None:
        key = username.lower().encode("utf-8")
        with self.env.begin(write=False) as txn:
            raw = txn.get(key, db=self.db_users)
            return msgspec.msgpack.decode(raw, type=UserRecord) if raw else None

    def delete_user(self, username: str) -> bytes | None:
        key = username.lower().encode("utf-8")
        with self.env.begin(write=True) as txn:
            raw = txn.get(key, db=self.db_users)
            if not raw:
                return None
            user = msgspec.msgpack.decode(raw, type=UserRecord)

            # Remove pending primary email change and its reservation.
            pending_raw = txn.get(
                user.id,
                db=self.db_primary_pending,
            )

            if pending_raw is not None:
                pending = msgspec.msgpack.decode(
                    pending_raw,
                    type=PrimaryEmailChangeRequest,
                )

                txn.delete(
                    pending.new_username.encode("utf-8"),
                    db=self.db_primary_pending_names,
                )

                txn.delete(
                    user.id,
                    db=self.db_primary_pending,
                )

            txn.delete(key, db=self.db_users)

            # Remove all public aliases belonging to this profile.
            alias_keys: list[bytes] = []

            with txn.cursor(db=self.aliases.db) as cursor:
                for alias_key, raw in cursor:
                    record = msgspec.msgpack.decode(
                        raw,
                        type=AliasRecord,
                    )

                    if (
                        record.target_kind == "profile"
                        and record.target_id == user.id
                    ):
                        alias_keys.append(bytes(alias_key))

            for alias_key in alias_keys:
                txn.delete(alias_key, db=self.aliases.db)

            # Remove the user's rewarded alias slots.
            txn.delete(
                user.id,
                db=self.alias_tokens.balances_db,
            )

            # Preserve grant history for administrative auditing.
            cursor = txn.cursor(db=self.db_mbox)
            keys_to_del: list[bytes] = []
            if cursor.set_range(user.id):
                for mbox_key, _ in cursor:
                    if not mbox_key.startswith(user.id):
                        break
                    keys_to_del.append(bytes(mbox_key))
            for mbox_key in keys_to_del:
                txn.delete(mbox_key, db=self.db_mbox)

            return user.id

    # --- Sessions ---
    def create_session(self, token: str, username: str, ttl_seconds: int = 7 * 86400) -> None:
        expires_ms = int(time.time() * 1000) + ttl_seconds * 1000
        rec = SessionRecord(username=username.lower(), expires_ms=expires_ms)
        with self.env.begin(write=True) as txn:
            txn.put(token.encode("utf-8"), msgspec.msgpack.encode(rec), db=self.db_sessions)

    def get_session_username(self, token: str) -> str | None:
        if not token:
            return None
        key = token.encode("utf-8")
        with self.env.begin(write=False) as txn:
            raw = txn.get(key, db=self.db_sessions)
            if not raw:
                return None
            rec = msgspec.msgpack.decode(raw, type=SessionRecord)

        if rec.expires_ms < int(time.time() * 1000):
            self.delete_session(token)
            return None
        return rec.username

    def delete_session(self, token: str) -> None:
        if not token:
            return
        with self.env.begin(write=True) as txn:
            txn.delete(token.encode("utf-8"), db=self.db_sessions)

    def delete_user_sessions(self, username: str) -> None:
        target = username.lower()
        with self.env.begin(write=True) as txn:
            cursor = txn.cursor(db=self.db_sessions)
            keys_to_del: list[bytes] = []
            for key, raw in cursor:
                rec = msgspec.msgpack.decode(raw, type=SessionRecord)
                if rec.username == target:
                    keys_to_del.append(bytes(key))
            for key in keys_to_del:
                txn.delete(key, db=self.db_sessions)

    # --- Messages ---
    @staticmethod
    def _mbox_key(user_id: bytes, folder: int, created_ms: int, msg_id: bytes) -> bytes:
        inv_ts = MAX_UINT64 - created_ms
        return user_id + struct.pack("!BQ", folder, inv_ts) + msg_id

    def save_local_message(
        self, msg: MessageRecord, recipient_ids: list[bytes], sender_id: bytes
    ) -> None:
        msg_bytes = msgspec.msgpack.encode(msg)
        with self.env.begin(write=True) as txn:
            txn.put(msg.id, msg_bytes, db=self.db_msgs)

            sent_key = self._mbox_key(sender_id, 1, msg.created_ms, msg.id)
            txn.put(
                sent_key,
                msgspec.msgpack.encode(MailboxFlags(folder=1, is_read=True)),
                db=self.db_mbox,
            )

            inbox_flags = msgspec.msgpack.encode(MailboxFlags(folder=0, is_read=False))
            for uid in recipient_ids:
                in_key = self._mbox_key(uid, 0, msg.created_ms, msg.id)
                txn.put(in_key, inbox_flags, db=self.db_mbox)


    def save_inbound_message(
        self,
        msg: MessageRecord,
        recipient_id: bytes,
        raw_email: bytes,
        envelope_sender: str,
        envelope_recipient: str,
    ) -> bool:
        """
        Atomically save an incoming email.

        Returns True for a newly saved message.
        Returns False if this delivery already exists.
        """
        digest = hashlib.sha256()

        sender_bytes = envelope_sender.lower().encode("utf-8")
        recipient_bytes = envelope_recipient.lower().encode("utf-8")

        for value in (sender_bytes, recipient_bytes, raw_email):
            digest.update(len(value).to_bytes(8, "big"))
            digest.update(value)

        delivery_key = digest.digest()

        with self.env.begin(write=True) as txn:
            if txn.get(delivery_key, db=self.db_inbound) is not None:
                return False

            txn.put(
                msg.id,
                msgspec.msgpack.encode(msg),
                db=self.db_msgs,
                overwrite=False,
            )

            txn.put(
                msg.id,
                raw_email,
                db=self.db_raw_mail,
                overwrite=False,
            )

            inbox_key = self._mbox_key(
                recipient_id,
                0,
                msg.created_ms,
                msg.id,
            )

            txn.put(
                inbox_key,
                msgspec.msgpack.encode(
                    MailboxFlags(folder=0, is_read=False)
                ),
                db=self.db_mbox,
            )

            txn.put(
                delivery_key,
                msg.id,
                db=self.db_inbound,
                overwrite=False,
            )

        return True

    def enqueue_external_message(
        self,
        sender: UserRecord,
        recipient: str,
        subject: str,
        body: str,
        private_key_path: str | Path,
    ) -> OutboundRecord:
        """
        Atomically create:
          1. MessageRecord
          2. Sender's Sent mailbox entry
          3. OutboundQueue record with signed MIME

        No SMTP delivery is performed here.
        """
        recipient = validate_address(
            recipient.strip().lower()
        )

        sender_address = (
            f"{sender.username}@ast.pp.ua"
        )

        # Confirm that sender still exists.
        stored_sender = self.get_user(sender.username)

        if (
            stored_sender is None
            or stored_sender.id != sender.id
        ):
            raise ValueError("Sender account not found")

        subject = subject.strip() or "(no subject)"

        now_ms = int(time.time() * 1000)
        message_id = new_uuid7_bytes()

        outbound = OutboundRecord(
            id=message_id,
            sender=sender_address,
            recipient=recipient,
            subject=subject,
            body=body,
            created_ms=now_ms,
            updated_ms=now_ms,
            user_id=sender.id,
        )

        # Build and sign before opening write transaction.
        # Slow operations must not block LMDB writers.
        raw_mime = build_signed_email(
            outbound,
            private_key_path,
        )

        if len(raw_mime) > MAX_MESSAGE_BYTES:
            raise ValueError(
                "Outgoing message exceeds size limit"
            )

        outbound.raw_mime = raw_mime

        message = MessageRecord(
            schema_v=1,
            id=message_id,
            thread_id=new_uuid7_bytes(),
            sender=sender_address,
            recipients=[recipient],
            created_ms=now_ms,
            content_format="markdown",
            subject=subject,
            body_bytes=body.encode("utf-8"),
        )

        sent_key = self._mbox_key(
            sender.id,
            1,
            now_ms,
            message_id,
        )

        sent_flags = msgspec.msgpack.encode(
            MailboxFlags(folder=1, is_read=True)
        )

        # All three records are committed together.
        with self.env.begin(write=True) as txn:
            # Recheck account inside the transaction.
            current_raw = txn.get(
                sender.username.encode("utf-8"),
                db=self.db_users,
            )

            if current_raw is None:
                raise ValueError(
                    "Sender account was deleted"
                )

            current = msgspec.msgpack.decode(
                current_raw,
                type=UserRecord,
            )

            if current.id != sender.id:
                raise ValueError(
                    "Sender account changed"
                )

            if current.username != sender.username:
                raise ValueError(
                    "Sender primary email changed"
                )

            if not re.fullmatch(r"[a-z0-9]{1,32}", current.username):
                raise ValueError(
                    "External sender requires an ASCII primary mailbox"
                )

            if not txn.put(
                message_id,
                msgspec.msgpack.encode(message),
                db=self.db_msgs,
                overwrite=False,
            ):
                raise RuntimeError(
                    "Duplicate message ID"
                )

            if not txn.put(
                sent_key,
                sent_flags,
                db=self.db_mbox,
                overwrite=False,
            ):
                raise RuntimeError(
                    "Duplicate Sent index"
                )

            if not txn.put(
                message_id,
                msgspec.msgpack.encode(outbound),
                db=self.outbound.db,
                overwrite=False,
            ):
                raise RuntimeError(
                    "Duplicate outbound queue ID"
                )

        return outbound

    def list_folder(
        self, user_id: bytes, folder: int = 0, limit: int = 50
    ) -> list[MessageRecord]:
        prefix = user_id + struct.pack("!B", folder)
        results: list[MessageRecord] = []

        with self.env.begin(write=False) as txn:
            cursor = txn.cursor(db=self.db_mbox)
            if not cursor.set_range(prefix):
                return results

            for key, _ in cursor:
                if not key.startswith(prefix):
                    break
                msg_id = key[-16:]
                msg_raw = txn.get(msg_id, db=self.db_msgs)
                if msg_raw:
                    results.append(msgspec.msgpack.decode(msg_raw, type=MessageRecord))
                if len(results) >= limit:
                    break
        return results


    def cancel_own_outbound(
        self,
        user_id: bytes,
        message_id: bytes,
    ) -> bool:
        """
        Cancel a queued outgoing email only if it
        belongs to the user's Sent mailbox.

        Authorization and status change are atomic.
        """
        if len(user_id) != 16 or len(message_id) != 16:
            return False

        prefix = user_id + b"\x01"

        with self.env.begin(write=True) as txn:
            cursor = txn.cursor(db=self.db_mbox)
            owns_message = False

            if cursor.set_range(prefix):
                for key, _ in cursor:
                    if not key.startswith(prefix):
                        break

                    if key[-16:] == message_id:
                        owns_message = True
                        break

            if not owns_message:
                return False

            raw = txn.get(
                message_id,
                db=self.outbound.db,
            )

            if raw is None:
                return False

            record = msgspec.msgpack.decode(
                raw,
                type=OutboundRecord,
            )

            if record.status not in ("queued", "retry"):
                return False

            record.status = "cancelled"
            record.updated_ms = int(time.time() * 1000)
            record.next_attempt_ms = 0
            record.last_error = "Cancelled by sender"

            txn.put(
                message_id,
                msgspec.msgpack.encode(record),
                db=self.outbound.db,
            )

        return True

    def primary_email_change_used(self, user_id: bytes) -> bool:
        if not isinstance(user_id, bytes) or len(user_id) != 16:
            raise ValueError("Invalid user ID")

        with self.env.begin() as txn:
            return txn.get(
                b"used:" + user_id,
                db=self.db_primary_email,
            ) is not None

    def change_primary_email(
            self,
            user_id: bytes,
            old_username: str,
            new_username: str,
    ) -> UserRecord:
        """
        Immediate primary email changes are forbidden.

        Use schedule_primary_email_change() and
        execute_due_primary_email_changes() instead.
        """
        raise RuntimeError(
            "Immediate primary email changes are disabled. "
            "Schedule a seven-day change request instead."
        )

    def get_pending_primary_email(
            self,
            user_id: bytes,
    ) -> PrimaryEmailChangeRequest | None:
        if not isinstance(user_id, bytes) or len(user_id) != 16:
            raise ValueError("Invalid user ID")

        with self.env.begin() as txn:
            raw = txn.get(
                user_id,
                db=self.db_primary_pending,
            )

        if raw is None:
            return None

        return msgspec.msgpack.decode(
            raw,
            type=PrimaryEmailChangeRequest,
        )

    def schedule_primary_email_change(
            self,
            user_id: bytes,
            old_username: str,
            new_username: str,
    ) -> PrimaryEmailChangeRequest:
        if not isinstance(user_id, bytes) or len(user_id) != 16:
            raise ValueError("Invalid user ID")

        old_username = old_username.strip().lower()
        new_username = new_username.strip().lower()

        if re.fullmatch(r"[a-z0-9]{1,32}", new_username) is None:
            raise ValueError(
                "New mailbox name must contain 1–32 Latin letters or digits"
            )

        if new_username == old_username:
            raise ValueError("New email must differ from current email")

        now_ms = int(time.time() * 1000)

        record = PrimaryEmailChangeRequest(
            user_id=user_id,
            old_username=old_username,
            new_username=new_username,
            created_ms=now_ms,
            execute_after_ms=now_ms + PRIMARY_EMAIL_DELAY_MS,
        )

        new_key = new_username.encode("utf-8")

        with self.env.begin(write=True) as txn:
            raw = txn.get(
                old_username.encode("utf-8"),
                db=self.db_users,
            )

            if raw is None:
                raise ValueError("Account not found")

            user = msgspec.msgpack.decode(
                raw,
                type=UserRecord,
            )

            if user.id != user_id:
                raise ValueError("Account identity changed")

            if txn.get(
                    b"used:" + user_id,
                    db=self.db_primary_email,
            ) is not None:
                raise ValueError("Primary email change already used")

            if txn.get(
                    user_id,
                    db=self.db_primary_pending,
            ) is not None:
                raise ValueError("Primary email change already scheduled")

            if txn.get(new_key, db=self.db_users) is not None:
                raise ValueError("Mailbox already exists")

            if txn.get(
                    b"reserved:" + new_key,
                    db=self.db_primary_email,
            ) is not None:
                raise ValueError("Mailbox name is reserved")

            if not txn.put(
                    new_key,
                    user_id,
                    db=self.db_primary_pending_names,
                    overwrite=False,
            ):
                raise ValueError("Mailbox name is already pending")

            txn.put(
                user_id,
                msgspec.msgpack.encode(record),
                db=self.db_primary_pending,
                overwrite=False,
            )

        return record

    def cancel_pending_primary_email(
            self,
            user_id: bytes,
    ) -> bool:
        if not isinstance(user_id, bytes) or len(user_id) != 16:
            raise ValueError("Invalid user ID")

        with self.env.begin(write=True) as txn:
            raw = txn.get(
                user_id,
                db=self.db_primary_pending,
            )

            if raw is None:
                return False

            record = msgspec.msgpack.decode(
                raw,
                type=PrimaryEmailChangeRequest,
            )

            txn.delete(
                record.new_username.encode("utf-8"),
                db=self.db_primary_pending_names,
            )

            txn.delete(
                user_id,
                db=self.db_primary_pending,
            )

        return True

    def execute_due_primary_email_changes(
            self,
            *,
            now_ms: int | None = None,
            limit: int = 20,
    ) -> list[bytes]:
        """
        Apply matured primary email changes atomically.

        Returns IDs of renamed users whose active WebSocket
        connections must be closed by the application.

        This method never performs network operations.
        """
        if now_ms is None:
            now_ms = int(time.time() * 1000)

        if limit < 1:
            raise ValueError("Limit must be positive")

        changed_user_ids: list[bytes] = []

        with self.env.begin(write=True) as txn:
            due: list[PrimaryEmailChangeRequest] = []

            with txn.cursor(db=self.db_primary_pending) as cursor:
                for _, raw in cursor:
                    record = msgspec.msgpack.decode(
                        raw,
                        type=PrimaryEmailChangeRequest,
                    )

                    if record.execute_after_ms <= now_ms:
                        due.append(record)

                    if len(due) >= limit:
                        break

            for record in due:
                old_key = record.old_username.encode("utf-8")
                new_key = record.new_username.encode("utf-8")

                old_raw = txn.get(old_key, db=self.db_users)

                if old_raw is None:
                    # The old account no longer exists.
                    # Remove the orphaned request.
                    txn.delete(
                        new_key,
                        db=self.db_primary_pending_names,
                    )
                    txn.delete(
                        record.user_id,
                        db=self.db_primary_pending,
                    )
                    continue

                current = msgspec.msgpack.decode(
                    old_raw,
                    type=UserRecord,
                )

                if current.id != record.user_id:
                    # Unexpected identity mismatch.
                    # Do not modify either account.
                    continue

                if txn.get(
                        b"used:" + record.user_id,
                        db=self.db_primary_email,
                ) is not None:
                    continue

                if txn.get(new_key, db=self.db_users) is not None:
                    continue

                if txn.get(
                        b"reserved:" + new_key,
                        db=self.db_primary_email,
                ) is not None:
                    continue

                pending_owner = txn.get(
                    new_key,
                    db=self.db_primary_pending_names,
                )

                if pending_owner != record.user_id:
                    continue

                # Find outgoing messages belonging to the old mailbox.
                old_address = f"{record.old_username}@ast.pp.ua"

                outbound_to_cancel: list[OutboundRecord] = []
                has_inflight = False

                with txn.cursor(db=self.outbound.db) as cursor:
                    for _, outbound_raw in cursor:
                        outbound = msgspec.msgpack.decode(
                            outbound_raw,
                            type=OutboundRecord,
                        )

                        # New records have an immutable owner UUID.
                        # Legacy records are matched by their old sender
                        # address, which cannot be reassigned.
                        belongs_to_user = (
                            outbound.user_id == record.user_id
                            if outbound.user_id
                            else outbound.sender.lower() == old_address
                        )

                        if not belongs_to_user:
                            continue

                        if outbound.sender.lower() != old_address:
                            continue

                        if outbound.status == "sending":
                            has_inflight = True
                            break

                        if outbound.status in ("queued", "retry"):
                            outbound_to_cancel.append(outbound)

                # Never rename while an SMTP operation is in progress.
                # The next worker iteration will try again.
                if has_inflight:
                    continue

                renamed = UserRecord(
                    id=current.id,
                    username=record.new_username,
                    password_hash=current.password_hash,
                    is_admin=current.is_admin,
                )

                if not txn.put(
                        new_key,
                        msgspec.msgpack.encode(renamed),
                        db=self.db_users,
                        overwrite=False,
                ):
                    continue

                # Cancel unsent messages atomically with the rename.
                for outbound in outbound_to_cancel:
                    outbound.status = "cancelled"
                    outbound.updated_ms = now_ms
                    outbound.next_attempt_ms = 0
                    outbound.last_error = (
                        "Cancelled: primary email address changed"
                    )

                    txn.put(
                        outbound.id,
                        msgspec.msgpack.encode(outbound),
                        db=self.outbound.db,
                    )

                txn.delete(old_key, db=self.db_users)

                # Permanently consume the one-time change.
                txn.put(
                    b"used:" + record.user_id,
                    new_key,
                    db=self.db_primary_email,
                )

                # Prevent reassignment of the old mailbox name.
                txn.put(
                    b"reserved:" + old_key,
                    record.user_id,
                    db=self.db_primary_email,
                )

                # Revoke all sessions using the previous username.
                session_keys: list[bytes] = []

                with txn.cursor(db=self.db_sessions) as cursor:
                    for session_key, session_raw in cursor:
                        session = msgspec.msgpack.decode(
                            session_raw,
                            type=SessionRecord,
                        )

                        if session.username == record.old_username:
                            session_keys.append(bytes(session_key))

                for session_key in session_keys:
                    txn.delete(session_key, db=self.db_sessions)

                # Remove completed request and name reservation.
                txn.delete(
                    new_key,
                    db=self.db_primary_pending_names,
                )
                txn.delete(
                    record.user_id,
                    db=self.db_primary_pending,
                )

                changed_user_ids.append(record.user_id)

        return changed_user_ids
