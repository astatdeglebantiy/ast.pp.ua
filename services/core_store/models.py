import os
import time
import msgspec

MAX_UINT64 = 0xFFFFFFFFFFFFFFFF


def new_uuid7_bytes() -> bytes:
    """Generate a 16-byte time-ordered UUIDv7."""
    ms = time.time_ns() // 1_000_000
    rand = bytearray(os.urandom(10))
    rand[0] = (rand[0] & 0x0F) | 0x70  # Version 7
    rand[2] = (rand[2] & 0x3F) | 0x80  # RFC 4122 variant
    return ms.to_bytes(6, "big") + bytes(rand)


class UserRecord(msgspec.Struct):
    id: bytes
    username: str
    password_hash: str
    is_admin: bool = False


class InviteRecord(msgspec.Struct):
    code: str
    created_by: str
    created_ms: int
    expires_ms: int
    max_uses: int = 1
    uses_count: int = 0
    used_by: list[str] = msgspec.field(default_factory=list)


class MessageRecord(msgspec.Struct):
    schema_v: int
    id: bytes
    thread_id: bytes
    sender: str
    recipients: list[str]
    created_ms: int
    content_format: str  # "markdown"
    subject: str
    body_bytes: bytes


class MailboxFlags(msgspec.Struct, array_like=True):
    folder: int          # 0 = inbox, 1 = sent
    is_read: bool = False


class SessionRecord(msgspec.Struct):
    username: str
    expires_ms: int
