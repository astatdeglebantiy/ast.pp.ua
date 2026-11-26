
from pathlib import Path

import dkim


DKIM_DOMAIN = b"ast.pp.ua"
DKIM_SELECTOR = b"astmail"

SIGNED_HEADERS = [
    b"from",
    b"to",
    b"subject",
    b"date",
    b"message-id",
    b"mime-version",
    b"content-type",
]


class DKIMSigningError(Exception):
    pass


def sign_email(
    raw_message: bytes,
    private_key_path: str | Path,
) -> bytes:
    """
    Sign a complete RFC 5322 / MIME message.

    The input must already contain CRLF line endings.
    Returns the signed message as bytes.
    """
    if not raw_message:
        raise DKIMSigningError("Empty email")

    if b"\r\n\r\n" not in raw_message:
        raise DKIMSigningError(
            "Invalid MIME message: missing header/body separator"
        )

    key_path = Path(private_key_path)

    try:
        private_key = key_path.read_bytes()
    except OSError as exc:
        raise DKIMSigningError(
            "Cannot read DKIM private key"
        ) from exc

    try:
        signature = dkim.sign(
            message=raw_message,
            selector=DKIM_SELECTOR,
            domain=DKIM_DOMAIN,
            privkey=private_key,
            identity=b"@" + DKIM_DOMAIN,
            canonicalize=(b"relaxed", b"relaxed"),
            include_headers=SIGNED_HEADERS,
        )

    except Exception as exc:
        raise DKIMSigningError(
            "DKIM signing failed"
        ) from exc

    return signature + raw_message
