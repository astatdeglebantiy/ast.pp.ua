
import time
import unicodedata
from typing import Literal

import lmdb
import msgspec

from services.identity.tokens import FREE_ALIAS_SLOTS

TargetKind = Literal["profile", "channel"]

RESERVED_ALIASES = frozenset({
    "admin",
    "administrator",
    "support",
    "security",
    "system",
    "postmaster",
    "abuse",
    "astmail",
})


class AliasError(ValueError):
    pass


class AliasRecord(msgspec.Struct):
    alias: str
    normalized: str
    target_kind: TargetKind
    target_id: bytes
    created_ms: int


def normalize_alias(
    value: str,
    *,
    allow_admin_alias: bool = False,
) -> str:
    if not isinstance(value, str):
        raise AliasError("Alias must be a string")

    value = unicodedata.normalize(
        "NFKC", value.removeprefix("@")
    )

    if not 3 <= len(value) <= 32:
        raise AliasError("Alias must contain 3–32 characters")

    if value.startswith("_") or value.endswith("_"):
        raise AliasError("Alias cannot start or end with _")

    scripts = set()
    has_letter = False

    for char in value:
        if char in "0123456789_":
            continue

        if not unicodedata.category(char).startswith("L"):
            raise AliasError("Unsupported alias character")

        name = unicodedata.name(char, "")

        if name.startswith("LATIN "):
            scripts.add("latin")
        elif name.startswith("CYRILLIC "):
            scripts.add("cyrillic")
        else:
            raise AliasError("Only Latin and Cyrillic letters")

        has_letter = True

    if not has_letter:
        raise AliasError("Alias must contain a letter")

    if len(scripts) != 1:
        raise AliasError(
            "Cannot mix Latin and Cyrillic letters"
        )

    normalized = value.casefold()

    if normalized in RESERVED_ALIASES:
        if not (allow_admin_alias and normalized == "admin"):
            raise AliasError("Reserved alias")

    return normalized


class AliasRegistry:
    def __init__(self, env: lmdb.Environment) -> None:
        self.env = env
        self.db = env.open_db(b"identity_aliases")
        self.slots_db = env.open_db(b"identity_alias_slots")

    def resolve(self, alias: str) -> AliasRecord | None:
        key = normalize_alias(
            alias,
            allow_admin_alias=True,
        ).encode("utf-8")

        with self.env.begin() as txn:
            raw = txn.get(key, db=self.db)

        if raw is None:
            return None

        return msgspec.msgpack.decode(
            raw,
            type=AliasRecord,
        )

    def claim(
            self,
            alias: str,
            target_kind: TargetKind,
            target_id: bytes,
            *,
            allow_admin_alias: bool = False,
    ) -> AliasRecord:
        normalized = normalize_alias(
            alias,
            allow_admin_alias=allow_admin_alias,
        )

        if target_kind not in ("profile", "channel"):
            raise AliasError("Invalid target kind")

        if not isinstance(target_id, bytes) or len(target_id) != 16:
            raise AliasError("Expected 16-byte target ID")

        record = AliasRecord(
            alias=unicodedata.normalize(
                "NFKC", alias.removeprefix("@")
            ),
            normalized=normalized,
            target_kind=target_kind,
            target_id=target_id,
            created_ms=int(time.time() * 1000),
        )

        key = normalized.encode("utf-8")

        with self.env.begin(write=True) as txn:
            if txn.get(key, db=self.db) is not None:
                raise AliasError("Alias already taken")

            if target_kind == "profile":
                raw = txn.get(target_id, db=self.slots_db)
                rewarded = (
                    int.from_bytes(raw, "big")
                    if raw else 0
                )

                total_slots = FREE_ALIAS_SLOTS + rewarded

                occupied = self._count_owned_txn(
                    txn,
                    "profile",
                    target_id,
                )

                if occupied >= total_slots:
                    raise AliasError(
                        "No available alias slots"
                    )

            inserted = txn.put(
                key,
                msgspec.msgpack.encode(record),
                db=self.db,
                overwrite=False,
            )

            if not inserted:
                raise AliasError("Alias already taken")

        return record

    def release(
        self,
        alias: str,
        target_kind: TargetKind,
        target_id: bytes,
    ) -> bool:
        key = normalize_alias(
            alias,
            allow_admin_alias=True,
        ).encode("utf-8")

        with self.env.begin(write=True) as txn:
            raw = txn.get(key, db=self.db)

            if raw is None:
                return False

            record = msgspec.msgpack.decode(
                raw,
                type=AliasRecord,
            )

            if (
                record.target_kind != target_kind
                or record.target_id != target_id
            ):
                return False

            return txn.delete(key, db=self.db)

    def count_owned(
            self,
            target_kind: TargetKind,
            target_id: bytes,
    ) -> int:
        if target_kind not in ("profile", "channel"):
            raise AliasError("Invalid target kind")

        if not isinstance(target_id, bytes) or len(target_id) != 16:
            raise AliasError("Expected 16-byte target ID")

        with self.env.begin() as txn:
            return self._count_owned_txn(
                txn, target_kind, target_id
            )

    def _count_owned_txn(
            self,
            txn: lmdb.Transaction,
            target_kind: TargetKind,
            target_id: bytes,
    ) -> int:
        count = 0

        with txn.cursor(db=self.db) as cursor:
            for _, raw in cursor:
                record = msgspec.msgpack.decode(
                    raw,
                    type=AliasRecord,
                )

                if (
                        record.target_kind == target_kind
                        and record.target_id == target_id
                ):
                    count += 1

        return count

    def list_owned(
            self,
            target_kind: TargetKind,
            target_id: bytes,
    ) -> list[AliasRecord]:
        if target_kind not in ("profile", "channel"):
            raise AliasError("Invalid target kind")

        if not isinstance(target_id, bytes) or len(target_id) != 16:
            raise AliasError("Expected 16-byte target ID")

        records = []

        with self.env.begin() as txn:
            with txn.cursor(db=self.db) as cursor:
                for _, raw in cursor:
                    record = msgspec.msgpack.decode(
                        raw,
                        type=AliasRecord,
                    )

                    if (
                            record.target_kind == target_kind
                            and record.target_id == target_id
                    ):
                        records.append(record)

        records.sort(key=lambda record: (record.created_ms, record.normalized))
        return records
