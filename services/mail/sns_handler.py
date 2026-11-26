from typing import Any

import msgspec

from services.mail.delivery_events import DeliveryJournal
from services.mail.queue import OutboundQueue
from services.mail.ses_events import process_verified_ses_event
from services.mail.sns_confirmation import save_sns_confirmation
from services.mail.sns_verify import (
    SNSVerificationError,
    verify_sns_message,
)


MAX_SNS_BODY_BYTES = 256 * 1024


def handle_sns_payload(
    raw_body: bytes,
    *,
    expected_topic_arn: str,
    queue: OutboundQueue,
    journal: DeliveryJournal,
    certificate_pem: bytes | None = None,
) -> dict[str, Any]:
    """
    Handle a signed SNS envelope.

    certificate_pem is for isolated unit tests only.
    Production must use certificate retrieval and
    complete trust validation.

    No HTTP subscription is confirmed automatically.
    """
    if not isinstance(raw_body, bytes):
        raise ValueError("Invalid SNS request body")

    if not 0 < len(raw_body) <= MAX_SNS_BODY_BYTES:
        raise ValueError("Invalid SNS request size")

    try:
        envelope = msgspec.json.decode(
            raw_body,
            type=dict[str, Any],
        )
    except (msgspec.DecodeError, msgspec.ValidationError) as exc:
        raise ValueError("Invalid SNS JSON") from exc

    # Nothing is processed before signature verification.
    verified = verify_sns_message(
        envelope,
        expected_topic_arn=expected_topic_arn,
        certificate_pem=certificate_pem,
    )

    message_type = verified["Type"]

    if message_type in (
            "SubscriptionConfirmation",
            "UnsubscribeConfirmation",
    ):
        save_sns_confirmation(verified)

        return {
            "ok": True,
            "status": "manual_confirmation_required",
            "message_type": message_type,
        }

    if message_type != "Notification":
        raise SNSVerificationError(
            "Unexpected SNS message type"
        )

    try:
        event = msgspec.json.decode(
            verified["Message"].encode("utf-8"),
            type=dict[str, Any],
        )
    except (msgspec.DecodeError, msgspec.ValidationError) as exc:
        raise ValueError("Invalid SES event JSON") from exc

    event_type = event.get("eventType")

    # SES publishes other event types as well.
    # This journal currently handles only these three.
    if event_type not in (
        "Delivery",
        "Bounce",
        "Complaint",
    ):
        return {
            "ok": True,
            "status": "ignored",
        }

    delivery_event, created = process_verified_ses_event(
        event=event,
        sns_message_id=verified["MessageId"],
        queue=queue,
        journal=journal,
    )

    return {
        "ok": True,
        "status": "stored" if created else "duplicate",
        "event_id": delivery_event.id.hex(),
        "outbound_id": delivery_event.outbound_id.hex(),
        "event_type": delivery_event.event_type,
    }
