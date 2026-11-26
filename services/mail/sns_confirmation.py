
import json
import os
import uuid
from pathlib import Path
from typing import Any


class SNSConfirmationStorageError(RuntimeError):
    pass


def save_sns_confirmation(
    message: dict[str, Any],
) -> Path:
    """
    Save an already verified SNS confirmation.

    Must only be called after successful SNS signature
    and X.509 certificate chain verification.

    Never follows SubscribeURL and never confirms
    a subscription automatically.
    """
    message_type = message.get("Type")

    if message_type not in (
        "SubscriptionConfirmation",
        "UnsubscribeConfirmation",
    ):
        raise ValueError("Not an SNS confirmation")

    try:
        message_id = str(uuid.UUID(message["MessageId"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Invalid SNS message ID") from exc

    directory = (
        Path.home()
        / ".local"
        / "state"
        / "astmail"
        / "sns-confirmations"
    )

    directory.mkdir(
        mode=0o700,
        parents=True,
        exist_ok=True,
    )

    if directory.is_symlink():
        raise SNSConfirmationStorageError(
            "Confirmation directory cannot be a symlink"
        )

    # Reject a pre-existing directory with unsafe
    # permissions rather than silently changing them.
    stat = directory.stat()

    if stat.st_uid != os.getuid() or stat.st_mode & 0o077:
        raise SNSConfirmationStorageError(
            "Unsafe confirmation directory permissions"
        )

    filename = directory / f"{message_id}.json"

    data = json.dumps(
        message,
        ensure_ascii=False,
        indent=2,
    ).encode("utf-8")

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL

    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    try:
        fd = os.open(
            filename,
            flags,
            0o600,
        )
    except FileExistsError:
        # Repeated SNS delivery: do not overwrite
        # the previously captured message.
        return filename

    try:
        with os.fdopen(fd, "wb") as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
    except Exception:
        filename.unlink(missing_ok=True)
        raise

    return filename
