
import base64
import binascii
import re
import ssl

from datetime import datetime, timezone, timedelta
from typing import Any
from urllib.parse import urlsplit
from urllib.request import (
    build_opener,
    HTTPSHandler,
    HTTPRedirectHandler,
    Request as URLRequest,
)

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    padding,
    rsa,
)

from services.mail.sns_chain import (
    SNSChainVerificationError,
    verify_sns_certificate_chain,
)


SNS_REGION = "eu-north-1"
SNS_HOST = f"sns.{SNS_REGION}.amazonaws.com"

CERT_PATH_PATTERN = re.compile(
    r"/SimpleNotificationService-[A-Za-z0-9_-]+\.pem"
)


class SNSVerificationError(ValueError):
    pass


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(
        self, request, fp, code, msg, headers, newurl
    ):
        return None


def validate_sns_timestamp(
    message: dict[str, Any],
    *,
    now: datetime | None = None,
) -> None:
    value = message.get("Timestamp")

    if not isinstance(value, str):
        raise SNSVerificationError(
            "Missing SNS timestamp"
        )

    try:
        parsed = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise SNSVerificationError(
            "Invalid SNS timestamp"
        ) from exc

    if parsed.tzinfo is None:
        raise SNSVerificationError(
            "SNS timestamp requires timezone"
        )

    parsed = parsed.astimezone(timezone.utc)

    if now is None:
        now = datetime.now(timezone.utc)

    if now.tzinfo is None:
        raise ValueError(
            "Verification time must be timezone-aware"
        )

    now = now.astimezone(timezone.utc)

    if parsed > now + timedelta(minutes=5):
        raise SNSVerificationError(
            "SNS timestamp is in the future"
        )

    if message.get("Type") in (
        "SubscriptionConfirmation",
        "UnsubscribeConfirmation",
    ):
        if parsed < now - timedelta(hours=48):
            raise SNSVerificationError(
                "SNS confirmation has expired"
            )


def validate_cert_url(value: str) -> str:
    if not isinstance(value, str):
        raise SNSVerificationError(
            "Invalid certificate URL"
        )

    try:
        url = urlsplit(value)
        port = url.port
    except ValueError as exc:
        raise SNSVerificationError(
            "Invalid certificate URL"
        ) from exc

    if (
        url.scheme != "https"
        or url.hostname != SNS_HOST
        or port not in (None, 443)
        or url.username is not None
        or url.password is not None
        or url.query
        or url.fragment
        or not CERT_PATH_PATTERN.fullmatch(url.path)
    ):
        raise SNSVerificationError(
            "Untrusted SNS certificate URL"
        )

    return value


def validate_sns_signing_certificate(
    certificate: x509.Certificate,
) -> None:
    now = datetime.now(timezone.utc)

    if not (
        certificate.not_valid_before_utc
        <= now
        <= certificate.not_valid_after_utc
    ):
        raise SNSVerificationError(
            "SNS signing certificate is not valid now"
        )

    public_key = certificate.public_key()

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise SNSVerificationError(
            "SNS signing certificate must use RSA"
        )

    if public_key.key_size < 2048:
        raise SNSVerificationError(
            "SNS signing RSA key is too small"
        )

    try:
        constraints = (
            certificate.extensions
            .get_extension_for_class(
                x509.BasicConstraints
            ).value
        )
    except x509.ExtensionNotFound:
        constraints = None

    if constraints is not None and constraints.ca:
        raise SNSVerificationError(
            "SNS signing certificate cannot be a CA"
        )

    try:
        key_usage = (
            certificate.extensions
            .get_extension_for_class(
                x509.KeyUsage
            ).value
        )
    except x509.ExtensionNotFound:
        key_usage = None

    if (
        key_usage is not None
        and not key_usage.digital_signature
    ):
        raise SNSVerificationError(
            "SNS certificate disallows digital signatures"
        )


def signing_payload(
    message: dict[str, Any],
    *,
    confirmation_fields: int = 7,
) -> bytes:
    message_type = message.get("Type")

    if message_type == "Notification":
        fields = [
            "Message",
            "MessageId",
        ]

        if "Subject" in message:
            fields.append("Subject")

        fields.extend([
            "Timestamp",
            "TopicArn",
            "Type",
        ])

    elif message_type in (
            "SubscriptionConfirmation",
            "UnsubscribeConfirmation",
    ):
        fields = [
            "Message",
            "MessageId",
        ]
        if confirmation_fields == 7:
            fields.extend([
                "SubscribeURL",
                "Timestamp",
                "Token",
            ])
        elif confirmation_fields == 5:
            fields.append("Timestamp")
        else:
            raise SNSVerificationError(
                "Unsupported confirmation field count"
            )
        fields.extend([
            "TopicArn",
            "Type",
        ])

    else:
        raise SNSVerificationError(
            "Unsupported SNS message type"
        )

    parts = []

    for field in fields:
        value = message.get(field)

        if not isinstance(value, str):
            raise SNSVerificationError(
                f"Missing SNS field: {field}"
            )

        parts.extend((field, value))

    return (
        "\n".join(parts) + "\n"
    ).encode("utf-8")


def fetch_signing_certificate(url: str) -> bytes:
    validate_cert_url(url)

    opener = build_opener(
        HTTPSHandler(
            context=ssl.create_default_context()
        ),
        NoRedirects(),
    )

    request = URLRequest(
        url,
        headers={
            "Accept": "application/x-pem-file",
        },
    )

    # Short timeout: leave time for verification
    # and processing inside the SNS delivery window.
    with opener.open(request, timeout=4) as response:
        content = response.read(65537)

    if not content or len(content) > 65536:
        raise SNSVerificationError(
            "Invalid SNS certificate size"
        )

    return content


def verify_sns_message(
    message: dict[str, Any],
    *,
    expected_topic_arn: str,
    certificate_pem: bytes | None = None,
) -> dict[str, Any]:
    """
    Verify the SNS envelope before processing it.

    Production:
      - validate expected TopicArn
      - validate signing certificate URL
      - download certificate over HTTPS
      - verify certificate properties and X.509 chain
      - verify the RSA signature
      - validate signed timestamp

    certificate_pem is only for isolated unit tests.
    Do not expose this parameter through HTTP.
    """
    if not isinstance(message, dict):
        raise SNSVerificationError(
            "Invalid SNS message"
        )

    if (
        not isinstance(expected_topic_arn, str)
        or re.fullmatch(
            r"arn:aws:sns:eu-north-1:"
            r"[0-9]{12}:[A-Za-z0-9_-]+",
            expected_topic_arn,
        ) is None
    ):
        raise SNSVerificationError(
            "Invalid expected SNS topic ARN"
        )

    if message.get("TopicArn") != expected_topic_arn:
        raise SNSVerificationError(
            "Unexpected SNS topic"
        )

    cert_url = validate_cert_url(
        message.get("SigningCertURL")
    )

    version = message.get("SignatureVersion")

    if version == "2":
        algorithm = hashes.SHA256()
    elif version == "1":
        algorithm = hashes.SHA1()
    else:
        raise SNSVerificationError(
            "Unsupported SNS signature version"
        )

    payload = signing_payload(message)

    encoded_signature = message.get("Signature")

    if not isinstance(encoded_signature, str):
        raise SNSVerificationError(
            "Missing SNS signature"
        )

    try:
        signature = base64.b64decode(
            encoded_signature,
            validate=True,
        )
    except (ValueError, binascii.Error) as exc:
        raise SNSVerificationError(
            "Invalid SNS signature encoding"
        ) from exc

    pem = (
        certificate_pem
        if certificate_pem is not None
        else fetch_signing_certificate(cert_url)
    )

    try:
        certificate = x509.load_pem_x509_certificate(
            pem
        )
    except ValueError as exc:
        raise SNSVerificationError(
            "Invalid SNS certificate"
        ) from exc

    validate_sns_signing_certificate(certificate)

    if certificate_pem is None:
        try:
            verify_sns_certificate_chain(
                certificate
            )
        except SNSChainVerificationError as exc:
            raise SNSVerificationError(
                "Untrusted SNS signing certificate"
            ) from exc

        # SNSChainTemporaryError intentionally propagates:
        # the HTTP endpoint responds with 503 so that
        # temporary dependency failures can be retried.

    public_key = certificate.public_key()

    try:
        public_key.verify(
            signature,
            payload,
            padding.PKCS1v15(),
            algorithm,
        )
    except InvalidSignature as exc:
        raise SNSVerificationError(
            "SNS signature verification failed"
        ) from exc

    validate_sns_timestamp(message)

    return message
