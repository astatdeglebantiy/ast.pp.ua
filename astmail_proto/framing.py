import struct
import zlib
from enum import IntEnum, IntFlag

MAGIC = b"ASTP"
VERSION = 1
HEADER_NO_CRC_FMT = "!4sBBHIII"  # 20 bytes
HEADER_SIZE = 24                  # + 4 bytes CRC32
MAX_PAYLOAD_SIZE = 1_048_576      # 1 MiB per frame


class MsgType(IntEnum):
    AUTH_HELLO = 0x01
    MAIL_SEND = 0x02
    MAIL_EDIT = 0x03
    MAIL_RECALL = 0x04
    ACK_NACK = 0x05
    BLOB_CHUNK = 0x06
    SYNC_DELTA = 0x07
    PING_PONG = 0x08


class FrameFlags(IntFlag):
    NONE = 0x0000
    E2EE = 0x0001
    ZSTD = 0x0002


class FrameError(ValueError):
    pass


def pack_frame(
    msg_type: MsgType,
    payload: bytes,
    *,
    flags: FrameFlags = FrameFlags.NONE,
    stream_id: int = 0,
    seq_num: int = 0,
) -> bytes:
    if len(payload) > MAX_PAYLOAD_SIZE:
        raise FrameError(f"Payload too large: {len(payload)} bytes")

    head_no_crc = struct.pack(
        HEADER_NO_CRC_FMT,
        MAGIC,
        VERSION,
        int(msg_type),
        int(flags),
        stream_id,
        seq_num,
        len(payload),
    )
    crc = zlib.crc32(head_no_crc) & 0xFFFFFFFF
    return head_no_crc + struct.pack("!I", crc) + payload


def unpack_frame(raw: bytes) -> tuple[MsgType, FrameFlags, int, int, bytes]:
    if len(raw) < HEADER_SIZE:
        raise FrameError("Frame shorter than 24-byte header")

    head_no_crc = raw[:20]
    (expected_crc,) = struct.unpack("!I", raw[20:24])
    if (zlib.crc32(head_no_crc) & 0xFFFFFFFF) != expected_crc:
        raise FrameError("Header CRC32 mismatch")

    magic, ver, mtype, flags, stream_id, seq_num, payload_len = struct.unpack(
        HEADER_NO_CRC_FMT, head_no_crc
    )
    if magic != MAGIC:
        raise FrameError(f"Invalid magic: {magic!r}")
    if ver != VERSION:
        raise FrameError(f"Unsupported protocol version: {ver}")
    if len(raw) != HEADER_SIZE + payload_len:
        raise FrameError("Payload length mismatch")

    return MsgType(mtype), FrameFlags(flags), stream_id, seq_num, raw[HEADER_SIZE:]
