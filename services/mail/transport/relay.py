import smtplib
import ssl
from dataclasses import dataclass
from typing import Literal

from services.mail.transport.direct_smtp import (
    MAX_MESSAGE_BYTES,
    SMTPDeliveryError,
    SMTPResult,
    create_message,
    validate_address, classify_smtp_error, SMTPPermanentError, SMTPTemporaryError,
)


SecurityMode = Literal["starttls", "ssl"]


@dataclass(frozen=True, slots=True)
class RelayConfig:
    hostname: str
    port: int
    security: SecurityMode
    username: str = ""
    password: str = ""
    timeout: int = 20


def send_via_relay(
    config: RelayConfig,
    sender: str,
    recipient: str,
    subject: str,
    body: str,
) -> SMTPResult:
    sender = validate_address(sender)
    recipient = validate_address(recipient)

    if not config.hostname:
        raise ValueError("SMTP hostname is required")

    if config.security not in ("starttls", "ssl"):
        raise ValueError("Unsupported SMTP security mode")

    if not 1 <= config.port <= 65535:
        raise ValueError("Invalid SMTP port")

    message = create_message(
        sender=sender,
        recipient=recipient,
        subject=subject,
        body=body,
    )

    raw = message.as_bytes()

    if len(raw) > MAX_MESSAGE_BYTES:
        raise SMTPDeliveryError("Message exceeds size limit")

    context = ssl.create_default_context()

    if config.security == "ssl":
        smtp = smtplib.SMTP_SSL(
            host=config.hostname,
            port=config.port,
            timeout=config.timeout,
            context=context,
        )
    else:
        smtp = smtplib.SMTP(
            host=config.hostname,
            port=config.port,
            timeout=config.timeout,
        )

    try:
        with smtp:
            smtp.ehlo()

            if config.security == "starttls":
                if not smtp.has_extn("starttls"):
                    raise SMTPDeliveryError(
                        "Relay does not support STARTTLS"
                    )

                smtp.starttls(context=context)
                smtp.ehlo()

            if config.username:
                if not config.password:
                    raise ValueError(
                        "SMTP password is required"
                    )

                smtp.login(
                    config.username,
                    config.password,
                )

            refused = smtp.sendmail(
                sender,
                [recipient],
                raw,
            )

            if refused:
                raise SMTPDeliveryError(
                    f"Recipient refused: {refused}"
                )

            return SMTPResult(
                host=config.hostname,
                response="Accepted by SMTP relay",
            )

    except smtplib.SMTPException as exc:
        raise SMTPDeliveryError(
            f"SMTP relay failed: {exc}"
        ) from exc


def send_raw_relay(
    config: RelayConfig,
    sender: str,
    recipient: str,
    raw_message: bytes,
) -> SMTPResult:
    """
    Send an already DKIM-signed MIME message
    through an SMTP submission server.
    """
    sender = validate_address(sender)
    recipient = validate_address(recipient)

    if not config.hostname:
        raise ValueError("SMTP relay hostname is required")

    if not 1 <= config.port <= 65535:
        raise ValueError("Invalid SMTP port")

    if not raw_message:
        raise ValueError("Empty MIME message")

    if len(raw_message) > MAX_MESSAGE_BYTES:
        raise ValueError("Message exceeds size limit")

    context = ssl.create_default_context()

    if config.security == "ssl":
        smtp = smtplib.SMTP_SSL(
            config.hostname,
            config.port,
            timeout=config.timeout,
            context=context,
        )
    elif config.security == "starttls":
        smtp = smtplib.SMTP(
            config.hostname,
            config.port,
            timeout=config.timeout,
        )
    else:
        raise ValueError("Invalid SMTP security mode")

    try:
        with smtp:
            smtp.ehlo()

            if config.security == "starttls":
                if not smtp.has_extn("starttls"):
                    raise SMTPDeliveryError(
                        "Relay does not support STARTTLS"
                    )

                smtp.starttls(context=context)
                smtp.ehlo()

            if config.username:
                if not config.password:
                    raise ValueError(
                        "SMTP password is missing"
                    )

                smtp.login(
                    config.username,
                    config.password,
                )

            refused = smtp.sendmail(
                sender,
                [recipient],
                raw_message,
            )

            if refused:
                raise smtplib.SMTPRecipientsRefused(refused)

            return SMTPResult(
                host=config.hostname,
                response="Accepted by SMTP relay",
            )

    except smtplib.SMTPRecipientsRefused as exc:
        response = exc.recipients.get(recipient)

        if response is None:
            raise SMTPDeliveryError(
                f"Unexpected recipient refusal: {exc}"
            ) from exc

        code, detail = response
        message = f"SMTP {code}: {detail!r}"

        if 500 <= code < 600:
            raise SMTPPermanentError(message) from exc

        if 400 <= code < 500:
            raise SMTPTemporaryError(message) from exc

        raise SMTPDeliveryError(message) from exc

    except smtplib.SMTPResponseException as exc:
        raise classify_smtp_error(exc) from exc
