import asyncio
import logging

from services.core_store.engine import BinaryStore


logger = logging.getLogger("astmail.identity")


async def run_primary_email_worker(
    store: BinaryStore,
    sockets: dict,
    stop_event: asyncio.Event,
    poll_interval: float = 60.0,
) -> None:
    """
    Execute scheduled primary email changes.

    Pending changes survive server restarts because
    their deadlines are stored in LMDB.
    """
    logger.info("Primary Email Worker started")

    while not stop_event.is_set():
        try:
            changed = await asyncio.to_thread(
                store.execute_due_primary_email_changes,
                limit=20,
            )

            for user_id in changed:
                logger.info(
                    "Primary email changed for user %s",
                    user_id.hex(),
                )

                # Close active WebSocket connections after
                # the LMDB transaction has committed.
                active_sockets = list(
                    sockets.pop(user_id, ())
                )

                for socket in active_sockets:
                    try:
                        await socket.close(
                            code=4001,
                            reason="Primary email changed",
                        )
                    except Exception:
                        logger.exception(
                            "Unable to close user WebSocket"
                        )

        except Exception:
            logger.exception(
                "Primary Email Worker iteration failed"
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

    logger.info("Primary Email Worker stopped")
