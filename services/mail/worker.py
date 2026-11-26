
import asyncio
import logging
from pathlib import Path

from services.core_store.engine import BinaryStore
from services.mail.outbound import (
    DeliveryFunction,
    OutboundService,
)


logger = logging.getLogger("astmail.outbound")


async def run_outbound_worker(
    store: BinaryStore,
    stop_event: asyncio.Event,
    transport: DeliveryFunction,
    private_key_path: str | Path,
    poll_interval: float = 5.0,
) -> None:
    """
    Process outbound messages until shutdown.

    Only one worker instance should run against
    an LMDB environment.
    """
    service = OutboundService(
        queue=store.outbound,
        private_key_path=private_key_path,
        transport=transport,
    )

    recovered = store.outbound.recover_inflight()

    if recovered:
        logger.warning(
            "Recovered %d interrupted SMTP deliveries "
            "as unknown",
            recovered,
        )

    logger.info("ASTMail outbound worker started")

    while not stop_event.is_set():
        try:
            if store.outbound.delivery_enabled():
                due = store.outbound.list_due(limit=20)

                for record in due:
                    if stop_event.is_set():
                        break

                    if not store.outbound.delivery_enabled():
                        break

                    result = await asyncio.to_thread(
                        service.process_one,
                        record.id,
                    )

                    if result is not None:
                        logger.info(
                            "Outbound %s: %s (attempt %d)",
                            result.id.hex(),
                            result.status,
                            result.attempts,
                        )

                # SMTP is synchronous; run it off
                # the main ASGI event loop.
                result = await asyncio.to_thread(
                    service.process_one,
                    record.id,
                )

                if result is not None:
                    logger.info(
                        "Outbound %s: %s (attempt %d)",
                        result.id.hex(),
                        result.status,
                        result.attempts,
                    )

        except Exception:
            logger.exception(
                "Outbound worker iteration failed"
            )

        if stop_event.is_set():
            break

        try:
            await asyncio.wait_for(
                stop_event.wait(),
                timeout=poll_interval,
            )
        except asyncio.TimeoutError:
            pass

    logger.info("ASTMail outbound worker stopped")
