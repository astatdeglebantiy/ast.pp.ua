import asyncio
import logging
import os

from litestar import Request, post
from litestar.datastructures import State
from litestar.exceptions import HTTPException

from services.mail.sns_handler import (
    MAX_SNS_BODY_BYTES,
    handle_sns_payload,
)
from services.mail.sns_verify import SNSVerificationError


logger = logging.getLogger(__name__)


@post(
    "/api/ses/sns",
    status_code=200,
    request_max_body_size=MAX_SNS_BODY_BYTES,
)
async def receive_sns_event(
    request: Request,
    state: State,
) -> dict:
    """
    Receive Amazon SNS notifications for SES events.

    Disabled by default. SNS signatures and the
    signing certificate trust chain are verified
    by handle_sns_payload() before event processing.
    """

    # Fail closed unless explicitly enabled.
    enabled = os.environ.get(
        "ASTMAIL_SNS_ENABLED", "0"
    ).strip()

    if enabled != "1":
        raise HTTPException(
            status_code=503,
            detail="SNS endpoint is disabled",
        )

    expected_topic_arn = os.environ.get(
        "ASTMAIL_SNS_TOPIC_ARN", ""
    ).strip()

    if not expected_topic_arn:
        logger.error("SNS topic ARN is not configured")
        raise HTTPException(
            status_code=503,
            detail="SNS endpoint is not configured",
        )

    # Expected integration contract:
    # state.store -> BinaryStore instance
    # store.outbound -> OutboundQueue
    # store.delivery_events -> DeliveryJournal
    store = getattr(state, "store", None)

    queue = getattr(store, "outbound", None)
    journal = getattr(store, "delivery_events", None)

    if queue is None or journal is None:
        logger.error("SNS storage dependencies unavailable")
        raise HTTPException(
            status_code=503,
            detail="SNS storage is unavailable",
        )

    # Litestar also enforces request_max_body_size.
    try:
        raw_body = await request.body()
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to read SNS request body")
        raise HTTPException(
            status_code=400,
            detail="Invalid SNS request",
        ) from None

    if not 0 < len(raw_body) <= MAX_SNS_BODY_BYTES:
        raise HTTPException(
            status_code=400,
            detail="Invalid SNS request size",
        )

    try:
        # The existing verifier performs HTTPS certificate
        # retrieval and X.509 verification synchronously.
        # Run it outside the event loop.
        result = await asyncio.to_thread(
            handle_sns_payload,
            raw_body,
            expected_topic_arn=expected_topic_arn,
            queue=queue,
            journal=journal,
        )

    except SNSVerificationError:
        logger.warning("Rejected invalid SNS signature")
        raise HTTPException(
            status_code=403,
            detail="SNS verification failed",
        ) from None

    except ValueError:
        logger.warning("Rejected invalid SNS payload")
        raise HTTPException(
            status_code=400,
            detail="Invalid SNS payload",
        ) from None

    except Exception:
        logger.exception("SNS processing failed")
        raise HTTPException(
            status_code=503,
            detail="SNS processing unavailable",
        ) from None

    logger.info(
        "SNS notification processed: status=%s",
        result.get("status", "unknown"),
    )

    return result
