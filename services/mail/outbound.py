
import os
import re
import time
from pathlib import Path
from typing import Callable

from services.mail.dkim import sign_email
from services.mail.queue import (
    OutboundQueue,
    OutboundRecord,
)
from services.mail.transport.direct_smtp import (
    SMTPPermanentError,
    SMTPResult,
    SMTPTemporaryError,
    create_message,
    send_raw_direct,
)
from services.mail.transport.relay import (
    RelayConfig,
    send_raw_relay,
)


DeliveryFunction = Callable[
    [str, str, bytes],
    SMTPResult,
]


MAX_ATTEMPTS = 5
BASE_RETRY_SECONDS = 30
MAX_RETRY_SECONDS = 3600


def retry_delay_seconds(attempts: int) -> int:
    return min(
        BASE_RETRY_SECONDS * (2 ** max(0, attempts - 1)),
        MAX_RETRY_SECONDS,
    )


def build_signed_email(
    record: OutboundRecord,
    private_key_path: str | Path,
) -> bytes:
    if record.sender.rsplit("@", 1)[-1].lower() != "ast.pp.ua":
        raise ValueError("Invalid outbound sender domain")

    if len(record.id) != 16:
        raise ValueError("Invalid outbound message UUID")

    message = create_message(
        sender=record.sender,
        recipient=record.recipient,
        subject=record.subject,
        body=record.body,
        message_id=f"<{record.id.hex()}@ast.pp.ua>",
    )

    return sign_email(
        message.as_bytes(),
        private_key_path,
    )


def get_delivery_transport() -> DeliveryFunction:
    mode = os.environ.get(
        "ASTMAIL_SMTP_MODE", "disabled"
    ).strip().lower()

    if mode == "direct":
        return send_raw_direct

    if mode == "relay":
        hostname = os.environ.get(
            "ASTMAIL_SMTP_HOST", ""
        ).strip()

        if not hostname:
            raise ValueError(
                "ASTMAIL_SMTP_HOST is required"
            )

        security = os.environ.get(
            "ASTMAIL_SMTP_SECURITY", "starttls"
        ).strip().lower()

        if security not in ("starttls", "ssl"):
            raise ValueError("Invalid SMTP security")

        default_port = (
            465 if security == "ssl" else 587
        )

        config = RelayConfig(
            hostname=hostname,
            port=int(
                os.environ.get(
                    "ASTMAIL_SMTP_PORT",
                    str(default_port),
                )
            ),
            security=security,
            username=os.environ.get(
                "ASTMAIL_SMTP_USER", ""
            ),
            password=os.environ.get(
                "ASTMAIL_SMTP_PASSWORD", ""
            ),
        )

        def deliver(
            sender: str,
            recipient: str,
            raw: bytes,
        ) -> SMTPResult:
            return send_raw_relay(
                config,
                sender,
                recipient,
                raw,
            )

        return deliver

    raise RuntimeError(
        "Outbound SMTP is disabled or misconfigured"
    )


class OutboundService:
    def __init__(
        self,
        queue: OutboundQueue,
        private_key_path: str | Path,
        transport: DeliveryFunction,
    ) -> None:
        self.queue = queue
        self.private_key_path = Path(private_key_path)
        self.transport = transport

    def process_one(
        self,
        message_id: bytes,
    ) -> OutboundRecord | None:
        record = self.queue.transition(
            message_id,
            expected=("queued", "retry"),
            new_status="sending",
        )

        if record is None:
            return None

        try:
            raw = record.raw_mime or build_signed_email(
                record,
                self.private_key_path,
            )

            result = self.transport(
                record.sender,
                record.recipient,
                raw,
            )

        except SMTPPermanentError as exc:
            return self.queue.transition(
                message_id,
                expected=("sending",),
                new_status="failed",
                error=str(exc),
            )



        except SMTPTemporaryError as exc:

            if record.attempts >= MAX_ATTEMPTS:
                return self.queue.transition(
                    message_id,
                    expected=("sending",),
                    new_status="failed",
                    error=(
                        f"Retry limit reached "
                        f"({MAX_ATTEMPTS} attempts): {exc}"
                    ),
                )

            delay_seconds = retry_delay_seconds(
                record.attempts
            )

            next_attempt_ms = (
                    int(time.time() * 1000)
                    + delay_seconds * 1000
            )

            return self.queue.transition(
                message_id,
                expected=("sending",),
                new_status="retry",
                error=str(exc),
                next_attempt_ms=next_attempt_ms,
            )

        except Exception as exc:
            # The SMTP result may be ambiguous.
            # Do not retry automatically.
            return self.queue.transition(
                message_id,
                expected=("sending",),
                new_status="unknown",
                error=(
                    f"{type(exc).__name__}: {exc}"
                ),
            )

        return self.queue.transition(
            message_id,
            expected=("sending",),
            new_status="accepted",
            smtp_server=result.host,
        )
