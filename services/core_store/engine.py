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
    UserRecord,
)


class BinaryStore:
    def __init__(self, data_dir: str | Path, map_size_mb: int = 256) -> None:
        Path(data_dir).mkdir(parents=True, exist_ok=True)
        self.env = lmdb.open(
            str(data_dir),
            map_size=map_size_mb * 1024 * 1024,
            max_dbs=16,
            sync=True,
        )
        self.db_users = self.env.open_db(b"users")
        self.db_msgs = self.env.open_db(b"messages")
        self.db_mbox = self.env.open_db(b"mailbox")
        self.db_sessions = self.env.open_db(b"sessions")
        self.db_invites = self.env.open_db(b"invites")

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
            txn.delete(key, db=self.db_users)

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
