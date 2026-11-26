
import time
import uuid

import lmdb
import msgspec


FREE_ALIAS_SLOTS = 1
MAX_REWARDED_SLOTS = 100


class AliasTokenError(ValueError):
    pass


class AliasGrant(msgspec.Struct):
    id: bytes
    user_id: bytes
    admin_id: bytes
    amount: int
    reason: str
    created_ms: int


def validate_id(value: bytes) -> None:
    if not isinstance(value, bytes) or len(value) != 16:
        raise AliasTokenError("Expected 16-byte UUID")


class AliasTokens:
    def __init__(self, env: lmdb.Environment) -> None:
        self.env = env
        self.balances_db = env.open_db(
            b"identity_alias_slots"
        )
        self.grants_db = env.open_db(
            b"identity_alias_grants"
        )

    def rewarded_slots(self, user_id: bytes) -> int:
        validate_id(user_id)

        with self.env.begin() as txn:
            raw = txn.get(
                user_id,
                db=self.balances_db,
            )

        return int.from_bytes(raw, "big") if raw else 0

    def total_slots(self, user_id: bytes) -> int:
        return FREE_ALIAS_SLOTS + self.rewarded_slots(user_id)

    def grant(
        self,
        user_id: bytes,
        admin_id: bytes,
        amount: int,
        reason: str,
    ) -> AliasGrant:
        validate_id(user_id)
        validate_id(admin_id)

        if type(amount) is not int or not 1 <= amount <= 10:
            raise AliasTokenError("Amount must be 1–10")

        if not isinstance(reason, str):
            raise AliasTokenError("Invalid reason")

        reason = reason.strip()

        if not 1 <= len(reason) <= 500:
            raise AliasTokenError("Reason must be 1–500 characters")

        record = AliasGrant(
            id=uuid.uuid4().bytes,
            user_id=user_id,
            admin_id=admin_id,
            amount=amount,
            reason=reason,
            created_ms=int(time.time() * 1000),
        )

        with self.env.begin(write=True) as txn:
            raw = txn.get(
                user_id,
                db=self.balances_db,
            )
            current = int.from_bytes(raw, "big") if raw else 0
            updated = current + amount

            if updated > MAX_REWARDED_SLOTS:
                raise AliasTokenError("Alias slot limit exceeded")

            txn.put(
                user_id,
                updated.to_bytes(8, "big"),
                db=self.balances_db,
            )
            txn.put(
                record.id,
                msgspec.msgpack.encode(record),
                db=self.grants_db,
                overwrite=False,
            )

        return record
