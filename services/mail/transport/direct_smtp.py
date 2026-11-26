import re
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from email.policy import SMTP as SMTP_POLICY
from email.utils import formatdate, make_msgid

import dns.exception
import dns.resolver


SMTP_PORT = 25
SMTP_TIMEOUT = 12
MAX_MESSAGE_BYTES = 8 * 1024 * 1024

ADDRESS_PATTERN = re.compile(
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+"
)


class SMTPDeliveryError(Exception):
    pass


class SMTPPermanentError(SMTPDeliveryError):
    """SMTP explicitly rejected delivery permanently."""


class SMTPTemporaryError(SMTPDeliveryError):
    """SMTP explicitly rejected delivery temporarily."""


@dataclass(frozen=True, slots=True)
class MXServer:
    hostname: str
    priority: int


@dataclass(frozen=True, slots=True)
class SMTPResult:
    host: str
    response: str


def validate_address(address: str) -> str:
    if (
        len(address) > 254
        or not ADDRESS_PATTERN.fullmatch(address)
    ):
        raise ValueError(f"Invalid email address: {address!r}")

    return address


def lookup_mx(domain: str) -> list[MXServer]:
    domain = domain.strip().lower()

    try:
        answers = dns.resolver.resolve(
            domain,
            "MX",
            lifetime=10,
        )
    except dns.exception.DNSException as exc:
        raise SMTPDeliveryError(
            f"MX lookup failed for {domain}: {exc}"
        ) from exc

    servers = [
        MXServer(
            hostname=str(record.exchange).rstrip("."),
            priority=int(record.preference),
        )
        for record in answers
    ]

    # An MX record consisting only of "." means
    # the domain explicitly does not accept email.
    if any(not server.hostname for server in servers):
        raise SMTPDeliveryError(
            f"Domain {domain} does not accept email"
        )

    if not servers:
        raise SMTPDeliveryError(
            f"No MX records for {domain}"
        )

    return sorted(
        servers,
        key=lambda server: server.priority,
    )


def create_message(
    sender: str,
    recipient: str,
    subject: str,
    body: str,
    message_id: str | None = None,
) -> EmailMessage:
    validate_address(sender)
    validate_address(recipient)

    if "\r" in subject or "\n" in subject:
        raise ValueError("Invalid subject")

    message = EmailMessage(policy=SMTP_POLICY)

    message["From"] = sender
    message["To"] = recipient
    message["Subject"] = subject
    message["Date"] = formatdate(localtime=False)
    message["Message-ID"] = (
        message_id
        if message_id is not None
        else make_msgid(domain="ast.pp.ua")
    )
    message.set_content(body, charset="utf-8")

    return message


def probe_mx(recipient: str) -> list[tuple[str, str]]:
    """
    Check MX connectivity and STARTTLS support.
    Does not send an email.
    """
    recipient = validate_address(recipient)
    domain = recipient.rsplit("@", 1)[1]

    results = []

    for server in lookup_mx(domain):
        try:
            with smtplib.SMTP(
                server.hostname,
                SMTP_PORT,
                timeout=SMTP_TIMEOUT,
            ) as smtp:
                smtp.ehlo()

                if not smtp.has_extn("starttls"):
                    raise SMTPDeliveryError(
                        "STARTTLS not supported"
                    )

                smtp.starttls(
                    context=ssl.create_default_context()
                )
                smtp.ehlo()

                results.append((
                    server.hostname,
                    "TLS OK",
                ))

        except (
            OSError,
            smtplib.SMTPException,
            SMTPDeliveryError,
        ) as exc:
            results.append((
                server.hostname,
                f"FAILED: {exc}",
            ))

    return results


def send_direct(
    sender: str,
    recipient: str,
    subject: str,
    body: str,
) -> SMTPResult:
    """
    Deliver one email directly to recipient MX.

    Requires STARTTLS with certificate validation.
    SMTP acceptance does not guarantee inbox delivery.
    """
    sender = validate_address(sender)
    recipient = validate_address(recipient)

    message = create_message(
        sender=sender,
        recipient=recipient,
        subject=subject,
        body=body,
    )

    raw = message.as_bytes()

    if len(raw) > MAX_MESSAGE_BYTES:
        raise SMTPDeliveryError("Email exceeds size limit")

    domain = recipient.rsplit("@", 1)[1]
    servers = lookup_mx(domain)

    failures = []

    for server in servers:
        try:
            with smtplib.SMTP(
                server.hostname,
                SMTP_PORT,
                timeout=SMTP_TIMEOUT,
            ) as smtp:
                smtp.ehlo()

                if not smtp.has_extn("starttls"):
                    raise SMTPDeliveryError(
                        "STARTTLS required"
                    )

                smtp.starttls(
                    context=ssl.create_default_context()
                )
                smtp.ehlo()

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
                    host=server.hostname,
                    response="Accepted by remote SMTP server",
                )

        except (
            OSError,
            smtplib.SMTPException,
            SMTPDeliveryError,
        ) as exc:
            failures.append(
                f"{server.hostname}: {exc}"
            )

            # Permanent SMTP failures should not be
            # retried blindly on other MX servers.
            if isinstance(
                exc,
                smtplib.SMTPResponseException,
            ) and 500 <= exc.smtp_code < 600:
                break

    raise SMTPDeliveryError(
        "Direct SMTP delivery failed: "
        + " | ".join(failures)
    )


def classify_smtp_error(
    exc: smtplib.SMTPResponseException,
) -> SMTPDeliveryError:
    message = f"SMTP {exc.smtp_code}: {exc.smtp_error!r}"

    if 500 <= exc.smtp_code < 600:
        return SMTPPermanentError(message)

    if 400 <= exc.smtp_code < 500:
        return SMTPTemporaryError(message)

    return SMTPDeliveryError(message)


def send_raw_direct(
    sender: str,
    recipient: str,
    raw_message: bytes,
) -> SMTPResult:
    """
    Send an already prepared and DKIM-signed MIME message.

    A network failure during SMTP may have an unknown
    delivery outcome, so it is never classified as
    automatically retryable here.
    """
    sender = validate_address(sender)
    recipient = validate_address(recipient)

    if not raw_message:
        raise ValueError("Empty message")

    if len(raw_message) > MAX_MESSAGE_BYTES:
        raise ValueError("Message exceeds size limit")

    domain = recipient.rsplit("@", 1)[1]
    servers = lookup_mx(domain)

    last_temporary: SMTPTemporaryError | None = None

    for server in servers:
        try:
            with smtplib.SMTP(
                server.hostname,
                SMTP_PORT,
                timeout=SMTP_TIMEOUT,
                local_hostname="ast.pp.ua",
            ) as smtp:
                smtp.ehlo()

                if not smtp.has_extn("starttls"):
                    raise SMTPDeliveryError(
                        "STARTTLS unavailable"
                    )

                smtp.starttls(
                    context=ssl.create_default_context()
                )
                smtp.ehlo()

                refused = smtp.sendmail(
                    sender,
                    [recipient],
                    raw_message,
                )

                if refused:
                    raise SMTPPermanentError(
                        f"Recipient refused: {refused}"
                    )

                return SMTPResult(
                    host=server.hostname,
                    response="Accepted by remote SMTP",
                )

        except smtplib.SMTPResponseException as exc:
            error = classify_smtp_error(exc)

            if isinstance(error, SMTPPermanentError):
                raise error from exc

            if isinstance(error, SMTPTemporaryError):
                last_temporary = error
                continue

            raise error from exc

    if last_temporary is not None:
        raise last_temporary

    raise SMTPDeliveryError(
        "No MX server accepted the message"
    )
