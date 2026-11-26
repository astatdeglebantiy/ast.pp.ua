
import asyncio
import hmac
import os
import re
import time

import msgspec
from litestar import Request, Response, post
from litestar.datastructures import State
from litestar.exceptions import (
    HTTPException,
    NotAuthorizedException,
)

from astmail_proto.framing import MsgType, pack_frame
from services.core_store.models import MessageRecord, new_uuid7_bytes
from services.mail.parser import parse_email


MAX_EMAIL_BYTES = 8 * 1024 * 1024

EXTERNAL_MAILBOX_RE = re.compile(r"[a-z0-9]{1,32}", re.ASCII)

def valid_external_mailbox(username: str) -> bool:
    return EXTERNAL_MAILBOX_RE.fullmatch(username) is not None

DOMAIN = "ast.pp.ua"


@post(
    "/api/inbound/email",
    request_max_body_size=MAX_EMAIL_BYTES,
)
async def receive_inbound_email(
    request: Request,
    state: State,
) -> dict[str, str | bool]:
    expected_token = os.environ.get("ASTMAIL_INBOUND_TOKEN", "")
    provided_token = request.headers.get(
        "x-astmail-token", ""
    )

    if (
        not expected_token
        or not hmac.compare_digest(
            provided_token, expected_token
        )
    ):
        raise NotAuthorizedException("Invalid inbound token")

    envelope_sender = request.headers.get(
        "x-astmail-sender", ""
    ).strip().lower()

    envelope_recipient = request.headers.get(
        "x-astmail-recipient", ""
    ).strip().lower()

    if envelope_recipient.count("@") != 1:
        raise HTTPException(
            status_code=422,
            detail="Invalid recipient",
        )

    username, domain = envelope_recipient.split("@", 1)

    if domain != DOMAIN:
        raise HTTPException(
            status_code=422,
            detail="Unsupported recipient domain",
        )

    store = state.store
    user = store.get_user(username)

    if user is None:
        raise HTTPException(
            status_code=422,
            detail="Mailbox does not exist",
        )

    if not valid_external_mailbox(username):
        # Temporary compatibility for an existing
        # Cyrillic mailbox during its migration.
        pending = store.get_pending_primary_email(user.id)

        now_ms = int(time.time() * 1000)

        if (
                pending is None
                or pending.old_username != user.username
                or now_ms >= pending.execute_after_ms
        ):
            raise HTTPException(
                status_code=422,
                detail="Legacy mailbox requires active migration",
            )

    if user is None:
        raise HTTPException(
            status_code=422,
            detail="Mailbox does not exist",
        )

    raw_email = await request.body()

    if not raw_email:
        raise HTTPException(
            status_code=400,
            detail="Empty email",
        )

    try:
        parsed = parse_email(raw_email)
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail="Invalid email",
        ) from exc

    record = MessageRecord(
        schema_v=1,
        id=new_uuid7_bytes(),
        thread_id=new_uuid7_bytes(),
        sender=envelope_sender,
        recipients=[envelope_recipient],
        created_ms=int(time.time() * 1000),
        content_format="markdown",
        subject=parsed.subject,
        body_bytes=parsed.body.encode("utf-8"),
    )

    created = store.save_inbound_message(
        msg=record,
        recipient_id=user.id,
        raw_email=raw_email,
        envelope_sender=envelope_sender,
        envelope_recipient=envelope_recipient,
    )

    if created:
        # A live push is best-effort. The email is already
        # stored durably in LMDB.
        from services.gateway_ws.app import to_wire

        frame = pack_frame(
            MsgType.MAIL_SEND,
            msgspec.msgpack.encode(
                to_wire(record, "inbox")
            ),
        )

        sockets = list(state.sockets.get(user.id, ()))
        if sockets:
            await asyncio.gather(
                *(ws.send_bytes(frame) for ws in sockets),
                return_exceptions=True,
            )

    return {
        "ok": True,
        "status": "stored" if created else "duplicate",
    }
