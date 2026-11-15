import asyncio
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
from litestar.exceptions import ClientException, NotAuthorizedException, WebSocketDisconnect
from litestar.static_files import create_static_files_router
import msgspec

from astmail_proto.framing import FrameError, MsgType, pack_frame, unpack_frame
from services.core_store.engine import BinaryStore
from services.core_store.models import MessageRecord, UserRecord, new_uuid7_bytes
from services.gateway_ws.avatar import ensure_brand_favicon, generate_user_avatar_svg

WEB_DIR = Path(__file__).resolve().parents[2] / "web"
DOMAIN = "ast.pp.ua"
SESSION_COOKIE = "astmail_session"
SESSION_TTL_SECONDS = 7 * 86400


# --- Wire protocol schemas ---
class AuthRequest(msgspec.Struct):
    action: str  # "login" | "register"
    username: str
    password: str


class DeleteAccountRequest(msgspec.Struct):
    password: str


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


# --- Password hashing and DTO conversion ---
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


# --- Application lifecycle ---
@asynccontextmanager
async def app_lifespan(app: Litestar):
    ensure_brand_favicon(WEB_DIR)
    db_path = os.environ.get("ASTMAIL_DATA_DIR", "./data/lmdb")
    app.state.store = BinaryStore(db_path)
    app.state.sockets = defaultdict(set)  # user_id -> set[WebSocket]
    try:
        yield
    finally:
        app.state.store.close()


@post("/api/auth")
async def auth(data: AuthRequest, request: Request, state: State) -> Response[dict[str, str]]:
    username = data.username.strip().lower().split("@")[0]
    if not username or not username.isalnum():
        raise ClientException("Username must be alphanumeric")
    if len(data.password) < 4:
        raise ClientException("Password must be at least 4 characters")

    store: BinaryStore = state.store
    if data.action == "register":
        user = UserRecord(
            id=new_uuid7_bytes(),
            username=username,
            password_hash=hash_password(data.password),
        )
        try:
            store.create_user(user)
        except ValueError as err:
            raise ClientException(str(err))
    else:
        user = store.get_user(username)
        if not user or not verify_password(data.password, user.password_hash):
            raise ClientException("Invalid username or password")

    token = secrets.token_urlsafe(32)
    store.create_session(token, username, ttl_seconds=SESSION_TTL_SECONDS)

    resp = Response(
        content={"address": f"{username}@{DOMAIN}", "username": username},
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
async def current_session(request: Request, state: State) -> dict[str, str]:
    token = request.cookies.get(SESSION_COOKIE, "")
    store: BinaryStore = state.store
    username = store.get_session_username(token)
    user = store.get_user(username) if username else None
    if not user:
        raise NotAuthorizedException("Not signed in")
    return {"address": f"{user.username}@{DOMAIN}", "username": user.username}


async def _safe_close_sockets(sockets: list[WebSocket]) -> None:
    for ws in sockets:
        try:
            await ws.close(code=4002, reason="Mailbox deleted")
        except Exception:
            pass


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
    token = request.cookies.get(SESSION_COOKIE, "")
    store: BinaryStore = state.store
    username = store.get_session_username(token)
    if not username:
        raise NotAuthorizedException("Invalid or expired session")

    user = store.get_user(username)
    if not user or not verify_password(data.password, user.password_hash):
        raise ClientException("Incorrect password")

    deleted_uid = store.delete_user(username)
    store.delete_user_sessions(username)

    if deleted_uid:
        sockets_to_close = list(state.sockets.pop(deleted_uid, ()))
        if sockets_to_close:
            asyncio.create_task(_safe_close_sockets(sockets_to_close))

    resp = Response(
        content={"status": "deleted", "username": username},
        media_type=MediaType.JSON,
    )
    resp.delete_cookie(key=SESSION_COOKIE, path="/")
    return resp


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
        # 1. Push initial inbox and sent history on connect (SYNC_DELTA)
        inbox = [to_wire(m, "inbox") for m in store.list_folder(user.id, folder=0)]
        sent = [to_wire(m, "sent") for m in store.list_folder(user.id, folder=1)]
        sync_frame = pack_frame(
            MsgType.SYNC_DELTA,
            msgspec.msgpack.encode(SyncPayload(inbox=inbox, sent=sent)),
        )
        await socket.send_bytes(sync_frame)

        # 2. Process incoming binary ASTP frames from the client
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
                if "@" in target_raw and not target_raw.endswith(f"@{DOMAIN}"):
                    nack = msgspec.msgpack.encode(
                        AckPayload(
                            ok=False,
                            message=f"External domains are not enabled yet (only *@{DOMAIN})",
                        )
                    )
                    await socket.send_bytes(pack_frame(MsgType.ACK_NACK, nack, stream_id=stream_id))
                    continue

                target_name = target_raw.split("@")[0]
                recipient = store.get_user(target_name)
                if not recipient:
                    nack = msgspec.msgpack.encode(
                        AckPayload(ok=False, message=f"Mailbox {target_name}@{DOMAIN} not found")
                    )
                    await socket.send_bytes(pack_frame(MsgType.ACK_NACK, nack, stream_id=stream_id))
                    continue

                now_ms = int(time.time() * 1000)
                msg = MessageRecord(
                    schema_v=1,
                    id=new_uuid7_bytes(),
                    thread_id=new_uuid7_bytes(),
                    sender=f"{user.username}@{DOMAIN}",
                    recipients=[f"{recipient.username}@{DOMAIN}"],
                    created_ms=now_ms,
                    content_format="markdown",
                    subject=cmd.subject.strip() or "(no subject)",
                    body_bytes=cmd.body.encode("utf-8"),
                )
                store.save_local_message(msg, [recipient.id], user.id)

                ack = msgspec.msgpack.encode(AckPayload(ok=True, message="Sent!"))
                await socket.send_bytes(pack_frame(MsgType.ACK_NACK, ack, stream_id=stream_id))

                sent_push = pack_frame(
                    MsgType.MAIL_SEND, msgspec.msgpack.encode(to_wire(msg, "sent"))
                )
                for ws in list(state.sockets.get(user.id, ())):
                    await ws.send_bytes(sent_push)

                inbox_push = pack_frame(
                    MsgType.MAIL_SEND, msgspec.msgpack.encode(to_wire(msg, "inbox"))
                )
                for ws in list(state.sockets.get(recipient.id, ())):
                    await ws.send_bytes(inbox_push)

    except WebSocketDisconnect:
        pass
    finally:
        state.sockets[user.id].discard(socket)


app = Litestar(
    route_handlers=[
        auth,
        current_session,
        logout,
        delete_account,
        user_avatar,
        astp_ws,
        create_static_files_router(path="/", directories=[WEB_DIR], html_mode=True),
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
