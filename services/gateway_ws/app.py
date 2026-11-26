import asyncio
import logging
import re
from collections import defaultdict
from contextlib import asynccontextmanager
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import time

from litestar import Litestar, MediaType, Request, Response, WebSocket, get, post, websocket
from litestar.datastructures import State
from litestar.exceptions import (
    ClientException,
    NotAuthorizedException,
    PermissionDeniedException,
    WebSocketDisconnect, HTTPException,
)
from litestar.static_files import create_static_files_router
import msgspec

from astmail_proto.framing import FrameError, MsgType, pack_frame, unpack_frame
from services.core_store.engine import BinaryStore
from services.core_store.models import InviteRecord, MessageRecord, UserRecord, new_uuid7_bytes
from services.gateway_ws.avatar import ensure_brand_favicon, generate_user_avatar_svg
from services.identity.aliases import AliasError
from services.identity.tokens import AliasTokenError
from services.identity.worker import run_primary_email_worker
from services.mail.inbound import receive_inbound_email
from services.mail.outbound import get_delivery_transport
from services.mail.worker import run_outbound_worker

WEB_DIR = Path(__file__).resolve().parents[2] / "web"
DOMAIN = "ast.pp.ua"
ADMIN_USERNAME = os.environ.get("ASTMAIL_ADMIN_USER", "me").lower()
SESSION_COOKIE = "astmail_session"
SESSION_TTL_SECONDS = 7 * 86400
MAILBOX_NAME_PATTERN = re.compile(r"[a-z0-9]{1,32}", re.ASCII)


def valid_mailbox_name(username: str) -> bool:
    return MAILBOX_NAME_PATTERN.fullmatch(username) is not None

# --- Wire protocol schemas ---
class AuthRequest(msgspec.Struct):
    action: str  # "login" | "register"
    username: str
    password: str
    invite_code: str = ""


class DeleteAccountRequest(msgspec.Struct):
    password: str


class CreateInviteRequest(msgspec.Struct):
    max_uses: int = 1
    ttl_hours: int = 168


class RevokeInviteRequest(msgspec.Struct):
    code: str


class SendMailCmd(msgspec.Struct):
    to: str
    subject: str
    body: str


class WireMessage(msgspec.Struct):
    id: str
    folder: str  # "inbox" | "sent"
    sender: str
    recipients: list[str]
    subject: str
    body: str
    created_ms: int


class SyncPayload(msgspec.Struct):
    inbox: list[WireMessage]
    sent: list[WireMessage]


class AckPayload(msgspec.Struct):
    ok: bool
    message: str


# --- Helpers ---
def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return f"{salt.hex()}:{dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    salt_hex, dk_hex = stored.split(":", 1)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), 100_000)
    return hmac.compare_digest(dk.hex(), dk_hex)


def is_https_request(request: Request) -> bool:
    return (
        request.url.scheme == "https"
        or request.headers.get("x-forwarded-proto", "").lower() == "https"
    )


def is_user_admin(user: UserRecord) -> bool:
    return user.is_admin or user.username == ADMIN_USERNAME


def require_session_user(request: Request, store: BinaryStore) -> UserRecord:
    token = request.cookies.get(SESSION_COOKIE, "")
    username = store.get_session_username(token)
    user = store.get_user(username) if username else None
    if not user:
        raise NotAuthorizedException("Not signed in")
    return user

async def read_identity_json(request: Request) -> dict:
    expected_origin = os.environ.get(
        "ASTMAIL_PUBLIC_ORIGIN",
        "https://ast.pp.ua",
    ).rstrip("/")

    if request.headers.get("origin") != expected_origin:
        raise PermissionDeniedException(
            "Invalid request origin"
        )

    content_type = request.headers.get(
        "content-type", ""
    ).split(";", 1)[0].strip().lower()

    if content_type != "application/json":
        raise HTTPException(
            status_code=415,
            detail="JSON required",
        )

    try:
        data = await request.json()
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail="Invalid JSON",
        ) from exc

    if not isinstance(data, dict):
        raise ClientException("Expected JSON object")

    return data

def serialize_invite(inv: InviteRecord, now_ms: int) -> dict:
    return {
        "code": inv.code,
        "created_by": inv.created_by,
        "uses_count": inv.uses_count,
        "max_uses": inv.max_uses,
        "used_by": inv.used_by,
        "expires_ms": inv.expires_ms,
        "is_expired": now_ms > inv.expires_ms,
    }


def to_wire(msg: MessageRecord, folder: str) -> WireMessage:
    return WireMessage(
        id=msg.id.hex(),
        folder=folder,
        sender=msg.sender,
        recipients=msg.recipients,
        subject=msg.subject,
        body=msg.body_bytes.decode("utf-8", errors="replace"),
        created_ms=msg.created_ms,
    )


async def _safe_close_sockets(sockets: list[WebSocket]) -> None:
    for ws in sockets:
        try:
            await ws.close(code=4002, reason="Mailbox deleted")
        except Exception:
            pass


# --- Application lifecycle ---

@asynccontextmanager
async def app_lifespan(app: Litestar):
    ensure_brand_favicon(WEB_DIR)

    db_path = os.environ.get(
        "ASTMAIL_DATA_DIR",
        "./data/lmdb",
    )

    app.state.store = BinaryStore(db_path)
    app.state.sockets = defaultdict(set)

    stop_event = asyncio.Event()
    outbound_task = None

    primary_email_task = asyncio.create_task(
        run_primary_email_worker(
            store=app.state.store,
            sockets=app.state.sockets,
            stop_event=stop_event,
            poll_interval=60.0,
        ),
        name="astmail-primary-email",
    )

    try:
        smtp_mode = os.environ.get(
            "ASTMAIL_SMTP_MODE",
            "disabled",
        ).strip().lower()

        if smtp_mode in ("direct", "relay"):
            key_path = Path(
                os.environ.get(
                    "ASTMAIL_DKIM_KEY",
                    "data/dkim/astmail_private.pem",
                )
            )

            if not key_path.is_file():
                raise RuntimeError(
                    f"DKIM key not found: {key_path}"
                )

            transport = get_delivery_transport()

            outbound_task = asyncio.create_task(
                run_outbound_worker(
                    store=app.state.store,
                    stop_event=stop_event,
                    transport=transport,
                    private_key_path=key_path,
                ),
                name="astmail-outbound",
            )

        else:
            logging.getLogger("astmail.outbound").info(
                "Outbound SMTP disabled"
            )

        yield


    finally:
        stop_event.set()
        try:
            if outbound_task is not None:
                await outbound_task
        finally:
            try:
                await primary_email_task
            finally:
                app.state.store.close()



@get("/api/auth/info")
async def auth_info(state: State) -> dict[str, bool]:
    return {"invite_required": state.store.has_any_users()}


@post("/api/auth")
async def auth(data: AuthRequest, request: Request, state: State) -> Response[dict]:
    username = data.username.strip().lower().split("@")[0]

    if data.action == "register":
        if not valid_mailbox_name(username):
            raise ClientException(
                "Mailbox name must contain 1–32 Latin letters "
                "or digits (a-z, 0-9)"
            )
    else:
        # Preserve login compatibility for existing
        # accounts with Cyrillic usernames.
        if not username or not username.isalnum():
            raise ClientException("Invalid username")
    if len(data.password) < 4:
        raise ClientException("Password must be at least 4 characters")

    store: BinaryStore = state.store
    if data.action == "register":
        candidate = UserRecord(
            id=new_uuid7_bytes(),
            username=username,
            password_hash=hash_password(data.password),
        )
        try:
            user = store.register_with_invite(candidate, data.invite_code)
        except ValueError as err:
            raise ClientException(str(err))
    else:
        user = store.get_user(username)
        if not user or not verify_password(data.password, user.password_hash):
            raise ClientException("Invalid username or password")

    token = secrets.token_urlsafe(32)
    store.create_session(token, username, ttl_seconds=SESSION_TTL_SECONDS)

    resp = Response(
        content={
            "id": user.id.hex(),
            "address": f"{user.username}@{DOMAIN}",
            "username": user.username,
            "is_admin": is_user_admin(user),
        },
        media_type=MediaType.JSON,
    )
    resp.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=SESSION_TTL_SECONDS,
        path="/",
        httponly=True,
        samesite="lax",
        secure=is_https_request(request),
    )
    return resp


@get("/api/me")
async def current_session(request: Request, state: State) -> dict:
    user = require_session_user(request, state.store)

    return {
        "id": user.id.hex(),
        "address": f"{user.username}@{DOMAIN}",
        "username": user.username,
        "is_admin": is_user_admin(user),
    }


@post("/api/logout")
async def logout(request: Request, state: State) -> Response[dict[str, str]]:
    token = request.cookies.get(SESSION_COOKIE, "")
    state.store.delete_session(token)
    resp = Response(content={"status": "signed_out"}, media_type=MediaType.JSON)
    resp.delete_cookie(key=SESSION_COOKIE, path="/")
    return resp


@post("/api/account/delete")
async def delete_account(
    data: DeleteAccountRequest, request: Request, state: State
) -> Response[dict[str, str]]:
    store: BinaryStore = state.store
    user = require_session_user(request, store)
    if not verify_password(data.password, user.password_hash):
        raise ClientException("Incorrect password")

    deleted_uid = store.delete_user(user.username)
    store.delete_user_sessions(user.username)

    if deleted_uid:
        sockets_to_close = list(state.sockets.pop(deleted_uid, ()))
        if sockets_to_close:
            asyncio.create_task(_safe_close_sockets(sockets_to_close))

    resp = Response(
        content={"status": "deleted", "username": user.username},
        media_type=MediaType.JSON,
    )
    resp.delete_cookie(key=SESSION_COOKIE, path="/")
    return resp


# --- Admin Invite Management ---
@get("/api/admin/invites")
async def list_invites(request: Request, state: State) -> dict[str, list[dict]]:
    store: BinaryStore = state.store
    user = require_session_user(request, store)
    if not is_user_admin(user):
        raise PermissionDeniedException("Admin access required")

    now_ms = int(time.time() * 1000)
    return {"invites": [serialize_invite(inv, now_ms) for inv in store.list_invites()]}


@post("/api/admin/invites")
async def create_invite(data: CreateInviteRequest, request: Request, state: State) -> dict:
    store: BinaryStore = state.store
    user = require_session_user(request, store)
    if not is_user_admin(user):
        raise PermissionDeniedException("Admin access required")

    inv = store.create_invite(
        created_by=user.username,
        max_uses=min(max(1, data.max_uses), 100),
        ttl_hours=min(max(1, data.ttl_hours), 8760),
    )
    now_ms = int(time.time() * 1000)
    return serialize_invite(inv, now_ms)


@post("/api/admin/invites/revoke")
async def revoke_invite(data: RevokeInviteRequest, request: Request, state: State) -> dict[str, bool]:
    store: BinaryStore = state.store
    user = require_session_user(request, store)
    if not is_user_admin(user):
        raise PermissionDeniedException("Admin access required")

    return {"revoked": store.revoke_invite(data.code)}

# --- Outbound Mail Status ---

@get("/api/mail/outbound/status")
async def outbound_status(
    request: Request,
    state: State,
) -> dict:
    store: BinaryStore = state.store
    user = require_session_user(request, store)

    sent_messages = store.list_folder(
        user.id,
        folder=1,
        limit=50,
    )

    messages = []

    for message in sent_messages:
        outbound = store.outbound.get(message.id)

        if outbound is None:
            status = "local"
            attempts = 0
            next_attempt_ms = 0
        else:
            status = outbound.status
            attempts = outbound.attempts
            next_attempt_ms = outbound.next_attempt_ms

        messages.append({
            "id": message.id.hex(),
            "status": status,
            "attempts": attempts,
            "next_attempt_ms": next_attempt_ms,
        })

    return {"messages": messages}


@get("/api/admin/outbound")
async def admin_outbound_queue(
    request: Request,
    state: State,
) -> dict:
    store: BinaryStore = state.store
    user = require_session_user(request, store)

    if not is_user_admin(user):
        raise PermissionDeniedException(
            "Admin access required"
        )

    records = store.outbound.list(limit=100)

    return {
        "messages": [
            {
                "id": record.id.hex(),
                "sender": record.sender,
                "recipient": record.recipient,
                "subject": record.subject,
                "status": record.status,
                "attempts": record.attempts,
                "created_ms": record.created_ms,
                "updated_ms": record.updated_ms,
                "next_attempt_ms": record.next_attempt_ms,
                "last_error": record.last_error,
                "smtp_server": record.smtp_server,
            }
            for record in records
        ]
    }

@post("/api/admin/outbound/cancel")
async def admin_cancel_outbound(
    request: Request,
    state: State,
) -> dict:
    store: BinaryStore = state.store
    user = require_session_user(request, store)

    if not is_user_admin(user):
        raise PermissionDeniedException(
            "Admin access required"
        )

    # Protect cookie-authenticated POST endpoint
    # against cross-origin requests.
    expected_origin = os.environ.get(
        "ASTMAIL_PUBLIC_ORIGIN",
        "https://ast.pp.ua",
    ).rstrip("/")

    if request.headers.get("origin") != expected_origin:
        raise PermissionDeniedException(
            "Invalid request origin"
        )

    if request.headers.get(
        "content-type", ""
    ).split(";", 1)[0].strip().lower() != "application/json":
        raise HTTPException(
            status_code=415,
            detail="JSON required",
        )

    data = await request.json()

    if not isinstance(data, dict):
        raise HTTPException(
            status_code=400,
            detail="Invalid request",
        )

    message_id = data.get("id")

    if (
        not isinstance(message_id, str)
        or len(message_id) != 32
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid message ID",
        )

    try:
        raw_id = bytes.fromhex(message_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail="Invalid message ID",
        ) from exc

    updated = store.outbound.transition(
        raw_id,
        expected=("queued", "retry"),
        new_status="cancelled",
        error="Cancelled by administrator",
    )

    if updated is None:
        raise HTTPException(
            status_code=409,
            detail=(
                "Message not found or cannot be cancelled"
            ),
        )

    return {
        "ok": True,
        "id": updated.id.hex(),
        "status": updated.status,
    }

@post("/api/mail/outbound/cancel")
async def cancel_my_outbound(
    request: Request,
    state: State,
) -> dict:
    store: BinaryStore = state.store
    user = require_session_user(request, store)

    expected_origin = os.environ.get(
        "ASTMAIL_PUBLIC_ORIGIN",
        "https://ast.pp.ua",
    ).rstrip("/")

    if request.headers.get("origin") != expected_origin:
        raise PermissionDeniedException(
            "Invalid request origin"
        )

    content_type = request.headers.get(
        "content-type", ""
    ).split(";", 1)[0].strip().lower()

    if content_type != "application/json":
        raise HTTPException(
            status_code=415,
            detail="JSON required",
        )

    data = await request.json()

    if not isinstance(data, dict):
        raise HTTPException(
            status_code=400,
            detail="Invalid request body",
        )

    message_id = data.get("id")

    if (
        not isinstance(message_id, str)
        or len(message_id) != 32
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid message ID",
        )

    try:
        raw_id = bytes.fromhex(message_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail="Invalid message ID",
        ) from exc

    cancelled = store.cancel_own_outbound(
        user_id=user.id,
        message_id=raw_id,
    )

    if not cancelled:
        raise HTTPException(
            status_code=409,
            detail=(
                "Message cannot be cancelled "
                "or does not belong to your mailbox"
            ),
        )

    return {
        "ok": True,
        "id": message_id,
        "status": "cancelled",
    }


@get("/api/admin/outbound/control")
async def admin_outbound_control_get(
    request: Request,
    state: State,
) -> dict:
    store: BinaryStore = state.store
    user = require_session_user(request, store)

    if not is_user_admin(user):
        raise PermissionDeniedException(
            "Admin access required"
        )

    return {
        "enabled": store.outbound.delivery_enabled(),
    }

@post("/api/admin/outbound/control")
async def admin_outbound_control_set(
    request: Request,
    state: State,
) -> dict:
    store: BinaryStore = state.store
    user = require_session_user(request, store)

    if not is_user_admin(user):
        raise PermissionDeniedException(
            "Admin access required"
        )

    expected_origin = os.environ.get(
        "ASTMAIL_PUBLIC_ORIGIN",
        "https://ast.pp.ua",
    ).rstrip("/")

    if request.headers.get("origin") != expected_origin:
        raise PermissionDeniedException(
            "Invalid request origin"
        )

    content_type = request.headers.get(
        "content-type", ""
    ).split(";", 1)[0].strip().lower()

    if content_type != "application/json":
        raise HTTPException(
            status_code=415,
            detail="JSON required",
        )

    data = await request.json()

    if (
        not isinstance(data, dict)
        or type(data.get("enabled")) is not bool
    ):
        raise HTTPException(
            status_code=400,
            detail="Expected JSON boolean: enabled"
        )

    enabled = data["enabled"]

    store.outbound.set_delivery_enabled(enabled)

    return {
        "enabled": store.outbound.delivery_enabled(),
    }

@post("/api/admin/identity/claim-reserved")
async def admin_identity_claim_reserved(
    request: Request,
    state: State,
) -> dict:
    store: BinaryStore = state.store
    user = require_session_user(request, store)

    if not is_user_admin(user):
        raise PermissionDeniedException(
            "Admin access required"
        )

    data = await read_identity_json(request)

    alias = data.get("alias")

    if not isinstance(alias, str):
        raise ClientException("Alias must be a string")

    if alias.removeprefix("@").strip().casefold() != "admin":
        raise ClientException(
            "Only @admin is supported by this endpoint"
        )

    try:
        record = store.aliases.claim(
            alias,
            "profile",
            user.id,
            allow_admin_alias=True,
        )
    except AliasError as exc:
        raise ClientException(str(exc)) from exc

    return {
        "ok": True,
        "alias": record.alias,
        "normalized": record.normalized,
        "owner": user.username,
    }

@post("/api/admin/identity/grant")
async def admin_identity_grant(
    request: Request,
    state: State,
) -> dict:
    store: BinaryStore = state.store
    admin = require_session_user(request, store)

    if not is_user_admin(admin):
        raise PermissionDeniedException(
            "Admin access required"
        )

    data = await read_identity_json(request)

    username = data.get("username")
    amount = data.get("amount")
    reason = data.get("reason")

    if not isinstance(username, str):
        raise ClientException("Invalid username")

    target = store.get_user(username.strip().lower())

    if target is None:
        raise HTTPException(
            status_code=404,
            detail="User not found",
        )

    try:
        grant = store.alias_tokens.grant(
            user_id=target.id,
            admin_id=admin.id,
            amount=amount,
            reason=reason,
        )
    except AliasTokenError as exc:
        raise ClientException(str(exc)) from exc

    return {
        "ok": True,
        "grant_id": grant.id.hex(),
        "username": target.username,
        "amount": grant.amount,
        "reason": grant.reason,
        "total_slots": store.alias_tokens.total_slots(target.id),
    }

@post("/api/identity/aliases/release")
async def identity_release_alias(
    request: Request,
    state: State,
) -> dict:
    store: BinaryStore = state.store
    user = require_session_user(request, store)
    data = await read_identity_json(request)

    alias = data.get("alias")

    if not isinstance(alias, str):
        raise ClientException("Alias must be a string")

    try:
        released = store.aliases.release(
            alias,
            "profile",
            user.id,
        )
    except AliasError as exc:
        raise ClientException(str(exc)) from exc

    if not released:
        raise HTTPException(
            status_code=404,
            detail="Alias not found or not owned",
        )

    return {
        "ok": True,
        "released": True,
    }

@post("/api/identity/aliases")
async def identity_claim_alias(
    request: Request,
    state: State,
) -> dict:
    store: BinaryStore = state.store
    user = require_session_user(request, store)
    data = await read_identity_json(request)

    alias = data.get("alias")

    if not isinstance(alias, str):
        raise ClientException("Alias must be a string")

    try:
        record = store.aliases.claim(
            alias,
            "profile",
            user.id,
        )
    except AliasError as exc:
        raise ClientException(str(exc)) from exc

    return {
        "ok": True,
        "alias": record.alias,
        "normalized": record.normalized,
    }

@get("/api/identity/aliases")
async def identity_list_aliases(
    request: Request,
    state: State,
) -> dict:
    store: BinaryStore = state.store
    user = require_session_user(request, store)

    aliases = store.aliases.list_owned(
        "profile",
        user.id,
    )

    total = store.alias_tokens.total_slots(user.id)

    return {
        "aliases": [
            {
                "alias": record.alias,
                "normalized": record.normalized,
                "created_ms": record.created_ms,
            }
            for record in aliases
        ],
        "slots": {
            "free": 1,
            "rewarded": store.alias_tokens.rewarded_slots(user.id),
            "total": total,
            "used": len(aliases),
            "available": max(0, total - len(aliases)),
        },
    }

@get("/api/account/primary-email")
async def get_primary_email(
    request: Request,
    state: State,
) -> dict:
    store: BinaryStore = state.store
    user = require_session_user(request, store)

    used = store.primary_email_change_used(user.id)
    pending = store.get_pending_primary_email(user.id)

    return {
        "address": f"{user.username}@{DOMAIN}",
        "username": user.username,
        "can_change": not used and pending is None,
        "change_used": used,
        "pending": (
            {
                "new_address": f"{pending.new_username}@{DOMAIN}",
                "created_ms": pending.created_ms,
                "execute_after_ms": pending.execute_after_ms,
            }
            if pending is not None
            else None
        ),
    }

@post("/api/account/primary-email/cancel")
async def cancel_primary_email_change(
    request: Request,
    state: State,
) -> dict:
    store: BinaryStore = state.store
    user = require_session_user(request, store)

    # Проверка Origin и Content-Type.
    await read_identity_json(request)

    cancelled = store.cancel_pending_primary_email(
        user.id
    )

    if not cancelled:
        raise HTTPException(
            status_code=404,
            detail="No pending email change",
        )

    return {
        "ok": True,
        "status": "cancelled",
    }

@post("/api/account/primary-email/change")
async def change_primary_email(
    request: Request,
    state: State,
) -> dict:
    store: BinaryStore = state.store
    user = require_session_user(request, store)

    data = await read_identity_json(request)

    new_username = data.get("username")
    password = data.get("password")

    if not isinstance(new_username, str):
        raise ClientException("New username is required")

    if not isinstance(password, str):
        raise ClientException("Password is required")

    if not verify_password(password, user.password_hash):
        raise ClientException("Incorrect password")

    new_username = new_username.strip().lower()

    if not valid_mailbox_name(new_username):
        raise ClientException(
            "New mailbox name must contain "
            "1–32 Latin letters or digits"
        )

    try:
        pending = store.schedule_primary_email_change(
            user_id=user.id,
            old_username=user.username,
            new_username=new_username,
        )
    except ValueError as exc:
        raise ClientException(str(exc)) from exc

    return {
        "ok": True,
        "status": "pending",
        "current_address": f"{user.username}@{DOMAIN}",
        "new_address": f"{pending.new_username}@{DOMAIN}",
        "execute_after_ms": pending.execute_after_ms,
    }

@get("/api/avatar/{username:str}")
async def user_avatar(username: str) -> Response[str]:
    clean = username.split("@")[0].strip().lower() or "user"
    svg = generate_user_avatar_svg(clean)
    return Response(
        content=svg,
        media_type="image/svg+xml",
        headers={"Cache-Control": "public, max-age=86400"},
    )


@websocket("/v1/ws")
async def astp_ws(socket: WebSocket) -> None:
    token = socket.cookies.get(SESSION_COOKIE, "")
    state = socket.app.state
    store: BinaryStore = state.store
    username = store.get_session_username(token)
    user = store.get_user(username) if username else None

    if not user:
        await socket.close(code=4001, reason="Unauthorized")
        return

    await socket.accept()
    state.sockets[user.id].add(socket)

    try:
        inbox = [to_wire(m, "inbox") for m in store.list_folder(user.id, folder=0)]
        sent = [to_wire(m, "sent") for m in store.list_folder(user.id, folder=1)]
        sync_frame = pack_frame(
            MsgType.SYNC_DELTA,
            msgspec.msgpack.encode(SyncPayload(inbox=inbox, sent=sent)),
        )
        await socket.send_bytes(sync_frame)

        while True:
            raw = await socket.receive_bytes()
            try:
                mtype, _, stream_id, seq_num, payload = unpack_frame(raw)
            except FrameError as err:
                err_bin = msgspec.msgpack.encode(AckPayload(ok=False, message=str(err)))
                await socket.send_bytes(pack_frame(MsgType.ACK_NACK, err_bin))
                continue

            if mtype == MsgType.PING_PONG:
                await socket.send_bytes(
                    pack_frame(MsgType.PING_PONG, b"pong", stream_id=stream_id, seq_num=seq_num)
                )

            elif mtype == MsgType.MAIL_SEND:
                cmd = msgspec.msgpack.decode(payload, type=SendMailCmd)
                target_raw = cmd.to.strip().lower()

                # --- External email ---
                if "@" in target_raw:
                    parts = target_raw.split("@")

                    if len(parts) != 2:
                        nack = msgspec.msgpack.encode(
                            AckPayload(
                                ok=False,
                                message="Invalid email address",
                            )
                        )
                        await socket.send_bytes(
                            pack_frame(
                                MsgType.ACK_NACK,
                                nack,
                                stream_id=stream_id,
                            )
                        )
                        continue

                    target_name, target_domain = parts

                    if target_domain != DOMAIN:
                        try:
                            key_path = Path(
                                os.environ.get(
                                    "ASTMAIL_DKIM_KEY",
                                    "data/dkim/astmail_private.pem",
                                )
                            )

                            outbound = store.enqueue_external_message(
                                sender=user,
                                recipient=target_raw,
                                subject=cmd.subject,
                                body=cmd.body,
                                private_key_path=key_path,
                            )

                        except ValueError as exc:
                            nack = msgspec.msgpack.encode(
                                AckPayload(
                                    ok=False,
                                    message=str(exc),
                                )
                            )
                            await socket.send_bytes(
                                pack_frame(
                                    MsgType.ACK_NACK,
                                    nack,
                                    stream_id=stream_id,
                                )
                            )
                            continue

                        except Exception:
                            import logging

                            logging.getLogger(
                                "astmail.outbound"
                            ).exception(
                                "External mail enqueue failed"
                            )

                            nack = msgspec.msgpack.encode(
                                AckPayload(
                                    ok=False,
                                    message="Unable to queue email",
                                )
                            )
                            await socket.send_bytes(
                                pack_frame(
                                    MsgType.ACK_NACK,
                                    nack,
                                    stream_id=stream_id,
                                )
                            )
                            continue

                        ack = msgspec.msgpack.encode(
                            AckPayload(
                                ok=True,
                                message="Queued for SMTP delivery",
                            )
                        )
                        await socket.send_bytes(
                            pack_frame(
                                MsgType.ACK_NACK,
                                ack,
                                stream_id=stream_id,
                            )
                        )

                        # Push the saved Sent message to
                        # the sender's connected clients.
                        sent_messages = store.list_folder(
                            user.id,
                            folder=1,
                        )

                        saved_message = next(
                            (
                                message
                                for message in sent_messages
                                if message.id == outbound.id
                            ),
                            None,
                        )

                        if saved_message is not None:
                            sent_push = pack_frame(
                                MsgType.MAIL_SEND,
                                msgspec.msgpack.encode(
                                    to_wire(saved_message, "sent")
                                ),
                            )

                            for ws in list(
                                    state.sockets.get(user.id, ())
                            ):
                                try:
                                    await ws.send_bytes(sent_push)
                                except Exception:
                                    pass

                        continue

                # --- Local ASTMail delivery ---
                target_name = target_raw.split("@")[0]

                if not target_name or not target_name.isalnum():
                    nack = msgspec.msgpack.encode(
                        AckPayload(
                            ok=False,
                            message="Invalid local mailbox",
                        )
                    )
                    await socket.send_bytes(
                        pack_frame(
                            MsgType.ACK_NACK,
                            nack,
                            stream_id=stream_id,
                        )
                    )
                    continue

                recipient = store.get_user(target_name)

                if not recipient:
                    nack = msgspec.msgpack.encode(
                        AckPayload(
                            ok=False,
                            message=(
                                f"Mailbox {target_name}@{DOMAIN} "
                                "not found"
                            ),
                        )
                    )
                    await socket.send_bytes(
                        pack_frame(
                            MsgType.ACK_NACK,
                            nack,
                            stream_id=stream_id,
                        )
                    )
                    continue

                now_ms = int(time.time() * 1000)

                msg = MessageRecord(
                    schema_v=1,
                    id=new_uuid7_bytes(),
                    thread_id=new_uuid7_bytes(),
                    sender=f"{user.username}@{DOMAIN}",
                    recipients=[
                        f"{recipient.username}@{DOMAIN}"
                    ],
                    created_ms=now_ms,
                    content_format="markdown",
                    subject=cmd.subject.strip() or "(no subject)",
                    body_bytes=cmd.body.encode("utf-8"),
                )

                store.save_local_message(
                    msg,
                    [recipient.id],
                    user.id,
                )

                ack = msgspec.msgpack.encode(
                    AckPayload(
                        ok=True,
                        message="Sent!",
                    )
                )

                await socket.send_bytes(
                    pack_frame(
                        MsgType.ACK_NACK,
                        ack,
                        stream_id=stream_id,
                    )
                )

                sent_push = pack_frame(
                    MsgType.MAIL_SEND,
                    msgspec.msgpack.encode(
                        to_wire(msg, "sent")
                    ),
                )

                for ws in list(
                        state.sockets.get(user.id, ())
                ):
                    await ws.send_bytes(sent_push)

                inbox_push = pack_frame(
                    MsgType.MAIL_SEND,
                    msgspec.msgpack.encode(
                        to_wire(msg, "inbox")
                    ),
                )

                for ws in list(
                        state.sockets.get(recipient.id, ())
                ):
                    await ws.send_bytes(inbox_push)

    except WebSocketDisconnect:
            pass
    finally:
        state.sockets[user.id].discard(socket)


app = Litestar(
    route_handlers=[
        auth_info,
        auth,
        current_session,
        logout,
        delete_account,
        list_invites,
        create_invite,
        revoke_invite,
        user_avatar,
        astp_ws,
        create_static_files_router(path="/", directories=[WEB_DIR], html_mode=True),
        receive_inbound_email,
        outbound_status,
        admin_outbound_queue,
        admin_cancel_outbound,
        cancel_my_outbound,
        admin_outbound_control_get,
        admin_outbound_control_set,
        identity_list_aliases,
        identity_claim_alias,
        identity_release_alias,
        admin_identity_grant,
        admin_identity_claim_reserved,
        get_primary_email,
        change_primary_email,
        cancel_primary_email_change,
    ],
    lifespan=[app_lifespan],
    debug=True,
)


if __name__ == "__main__":
    from granian import Granian
    from granian.constants import Interfaces

    Granian(
        "services.gateway_ws.app:app",
        address="127.0.0.1",
        port=8000,
        interface=Interfaces.ASGI,
    ).serve()
