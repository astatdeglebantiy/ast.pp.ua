
import re
import ssl
import threading
import time
import warnings

from functools import lru_cache
from urllib.parse import urlsplit
from urllib.request import (
    build_opener,
    HTTPHandler,
    HTTPRedirectHandler,
    Request as URLRequest,
)

from cryptography import x509
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
)
from cryptography.x509.verification import (
    PolicyBuilder,
    Store,
    VerificationError,
)


EXPECTED_SNS_DNS = "sns.amazonaws.com"
MAX_INTERMEDIATE_BYTES = 65536

# Successful intermediate downloads are cached for 30 min.
INTERMEDIATE_CACHE_SECONDS = 1800

# Explicitly restricted Amazon Trust Services AIA format.
AMAZON_CA_HOST_PATTERN = re.compile(
    r"crt\.([a-z0-9]+)\.amazontrust\.com",
    re.ASCII,
)

_intermediate_cache = {}
_cache_lock = threading.Lock()


class SNSChainVerificationError(ValueError):
    """The certificate or chain is not trusted."""


class SNSChainTemporaryError(RuntimeError):
    """A temporary dependency failure prevented verification."""


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(
        self, request, fp, code, msg, headers, newurl
    ):
        return None


def _validate_intermediate_url(value: str) -> str:
    """
    Allow only narrowly defined Amazon Trust Services
    intermediate certificate URLs.

    HTTP is allowed here because the downloaded CA is
    UNTRUSTED until its cryptographic chain is verified.
    """
    if not isinstance(value, str):
        raise SNSChainVerificationError(
            "Invalid intermediate CA URL"
        )

    try:
        url = urlsplit(value)
        port = url.port
    except ValueError as exc:
        raise SNSChainVerificationError(
            "Invalid intermediate CA URL"
        ) from exc

    host = url.hostname or ""

    match = AMAZON_CA_HOST_PATTERN.fullmatch(host)

    if (
        url.scheme != "http"
        or match is None
        or url.netloc != host
        or port is not None
        or url.username is not None
        or url.password is not None
        or url.query
        or url.fragment
    ):
        raise SNSChainVerificationError(
            "Untrusted intermediate CA URL"
        )

    identifier = match.group(1)

    if url.path != f"/{identifier}.cer":
        raise SNSChainVerificationError(
            "Unexpected intermediate CA path"
        )

    return value


def _issuer_url(certificate: x509.Certificate) -> str:
    """
    Read AIA from the signing certificate.

    The URL is not trusted simply because it appears
    inside the certificate.
    """
    try:
        aia = certificate.extensions.get_extension_for_class(
            x509.AuthorityInformationAccess
        ).value
    except x509.ExtensionNotFound as exc:
        raise SNSChainVerificationError(
            "SNS certificate has no issuer information"
        ) from exc

    for entry in aia:
        if (
            entry.access_method
            == AuthorityInformationAccessOID.CA_ISSUERS
            and isinstance(
                entry.access_location,
                x509.UniformResourceIdentifier,
            )
        ):
            return _validate_intermediate_url(
                entry.access_location.value
            )

    raise SNSChainVerificationError(
        "SNS intermediate CA URL not found"
    )


def _fetch_intermediate(url: str) -> x509.Certificate:
    url = _validate_intermediate_url(url)

    now = time.monotonic()

    with _cache_lock:
        cached = _intermediate_cache.get(url)

        if cached is not None:
            expires_at, certificate = cached

            if now < expires_at:
                return certificate

    opener = build_opener(
        HTTPHandler(),
        NoRedirects(),
    )

    request = URLRequest(
        url,
        headers={
            "Accept": "application/pkix-cert",
        },
    )

    try:
        with opener.open(request, timeout=4) as response:
            data = response.read(
                MAX_INTERMEDIATE_BYTES + 1
            )
    except (OSError, TimeoutError) as exc:
        raise SNSChainTemporaryError(
            "Intermediate CA download unavailable"
        ) from exc

    if not data or len(data) > MAX_INTERMEDIATE_BYTES:
        raise SNSChainVerificationError(
            "Invalid intermediate certificate size"
        )

    try:
        certificate = x509.load_der_x509_certificate(data)
    except ValueError as exc:
        raise SNSChainVerificationError(
            "Invalid intermediate certificate"
        ) from exc

    # Cache only successfully decoded certificates.
    with _cache_lock:
        _intermediate_cache[url] = (
            time.monotonic() + INTERMEDIATE_CACHE_SECONDS,
            certificate,
        )

    return certificate


@lru_cache(maxsize=1)
def _trusted_roots() -> tuple[x509.Certificate, ...]:
    """
    Load OS-trusted certificates.

    Skip certificates rejected by cryptography instead
    of weakening X.509 validation.

    The root set is refreshed on process restart.
    """
    context = ssl.create_default_context()

    roots = []

    for der in context.get_ca_certs(binary_form=True):
        try:
            with warnings.catch_warnings():
                warnings.simplefilter(
                    "error",
                    CryptographyDeprecationWarning,
                )
                root = x509.load_der_x509_certificate(der)

        except (
            ValueError,
            CryptographyDeprecationWarning,
        ):
            continue

        roots.append(root)

    if not roots:
        raise SNSChainTemporaryError(
            "No usable trusted root certificates"
        )

    return tuple(roots)


def verify_sns_certificate_chain(
    certificate: x509.Certificate,
) -> None:
    """
    Validate the SNS signing certificate using:
      - a tightly restricted Amazon Trust Services AIA
      - an untrusted intermediate CA
      - the operating system's trusted CA roots
      - X.509 server verification for sns.amazonaws.com

    A bad chain is a permanent verification failure.
    Temporary infrastructure failures are distinct.
    """
    url = _issuer_url(certificate)
    intermediate = _fetch_intermediate(url)

    if certificate.issuer != intermediate.subject:
        raise SNSChainVerificationError(
            "Unexpected SNS certificate issuer"
        )

    roots = _trusted_roots()

    try:
        verifier = (
            PolicyBuilder()
            .store(Store(list(roots)))
            .build_server_verifier(
                x509.DNSName(EXPECTED_SNS_DNS)
            )
        )

        verifier.verify(
            certificate,
            [intermediate],
        )

    except VerificationError as exc:
        raise SNSChainVerificationError(
            "SNS certificate chain is not trusted"
        ) from exc
