import re
from datetime import datetime, timezone
from typing import Any

from services.mail.delivery_events import (
    DeliveryEvent,
    DeliveryJournal,
)
from services.mail.queue import OutboundQueue


ASTMAIL_ID_PATTERN = re.compile(r"[0-9a-f]{32}")


def parse_aws_timestamp(value: str) -> int:
    if not isinstance(value, str):
        raise ValueError("Invalid SES timestamp")

    try:
        parsed = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise ValueError(
            "Invalid SES timestamp"
        ) from exc

    if parsed.tzinfo is None:
        raise ValueError(
            "SES timestamp must include timezone"
        )

    timestamp = parsed.astimezone(timezone.utc)
    return int(timestamp.timestamp() * 1000)


def ses_event_recipients(
    event: dict[str, Any],
    event_type: str,
) -> list[str]:
    detail = event.get(event_type.lower())

    if not isinstance(detail, dict):
        raise ValueError(
            f"Missing SES {event_type} details"
        )

    if event_type == "Delivery":
        values = detail.get("recipients")

    elif event_type == "Bounce":
        values = [
            item.get("emailAddress")
            for item in detail.get(
                "bouncedRecipients", []
            )
            if isinstance(item, dict)
        ]

    elif event_type == "Complaint":
        values = [
            item.get("emailAddress")
            for item in detail.get(
                "complainedRecipients", []
            )
            if isinstance(item, dict)
        ]

    else:
        raise ValueError(
            "Unsupported SES event type"
        )

    if not isinstance(values, list):
        raise ValueError("Invalid SES recipients")

    recipients = []

    for value in values:
        if not isinstance(value, str):
            raise ValueError("Invalid SES recipient")

        address = value.strip().lower()

        if not address:
            raise ValueError("Empty SES recipient")

        recipients.append(address)

    return recipients


def process_verified_ses_event(
    *,
    event: dict[str, Any],
    sns_message_id: str,
    queue: OutboundQueue,
    journal: DeliveryJournal,
) -> tuple[DeliveryEvent, bool]:
    """
    Process an already authenticated SNS notification.

    SECURITY:
    Only call after verifying the SNS signature,
    the expected TopicArn, and message type.

    This function must never be exposed directly
    to untrusted HTTP requests.
    """

    if not isinstance(event, dict):
        raise ValueError("Invalid SES event")

    if (
        not isinstance(sns_message_id, str)
        or not sns_message_id
        or len(sns_message_id) > 256
    ):
        raise ValueError(
            "Invalid SNS notification ID"
        )

    event_type = event.get("eventType")

    if event_type not in (
        "Delivery",
        "Bounce",
        "Complaint",
    ):
        raise ValueError(
            "Unsupported SES event type"
        )

    mail = event.get("mail")

    if not isinstance(mail, dict):
        raise ValueError("Missing SES mail object")

    tags = mail.get("tags")

    if not isinstance(tags, dict):
        raise ValueError("Missing SES tags")

    astmail_tags = tags.get("astmail_id")

    if (
        not isinstance(astmail_tags, list)
        or len(astmail_tags) != 1
        or not isinstance(astmail_tags[0], str)
        or ASTMAIL_ID_PATTERN.fullmatch(
            astmail_tags[0]
        ) is None
    ):
        raise ValueError(
            "Invalid ASTMail correlation tag"
        )

    outbound_id = bytes.fromhex(astmail_tags[0])

    outbound = queue.get(outbound_id)

    if outbound is None:
        raise ValueError(
            "Unknown ASTMail outbound message"
        )

    if len(outbound.user_id) != 16:
        raise ValueError(
            "Legacy outbound message has no owner UUID"
        )

    ses_message_id = mail.get("messageId")

    if (
        not isinstance(ses_message_id, str)
        or not ses_message_id
        or len(ses_message_id) > 512
    ):
        raise ValueError("Invalid SES message ID")

    source = mail.get("source")

    if (
        not isinstance(source, str)
        or source.strip().lower() != outbound.sender.lower()
    ):
        raise ValueError(
            "SES sender does not match outbound sender"
        )

    recipients = ses_event_recipients(
        event,
        event_type,
    )

    recipient = outbound.recipient.strip().lower()

    if recipient not in recipients:
        raise ValueError(
            "SES recipient does not match outbound recipient"
        )

    details = event[event_type.lower()]

    occurred_ms = parse_aws_timestamp(
        details.get("timestamp")
    )

    return journal.append(
        event_key=(
            f"sns:{sns_message_id}:{event_type}:"
            f"{recipient}"
        ),
        outbound_id=outbound.id,
        user_id=outbound.user_id,
        ses_message_id=ses_message_id,
        event_type=event_type,
        recipient=recipient,
        occurred_ms=occurred_ms,
    )
