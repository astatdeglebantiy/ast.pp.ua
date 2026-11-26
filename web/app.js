import { encode, decode } from "https://cdn.jsdelivr.net/npm/@msgpack/msgpack@3/+esm";

import {
  initializeIdentityRewards,
  showIdentityRewards,
  clearIdentityRewards,
} from "./identity-rewards.js?v=2";

import {
  initializeIdentityAliases,
  refreshIdentityAliases,
  clearIdentityAliases,
} from "./identity-aliases.js?v=3";

import {
  initializePrimaryEmail,
  refreshPrimaryEmail,
  clearPrimaryEmail,
} from "./primary-email.js?v=1";

import {
  initializeOutboundAdmin,
  refreshOutboundAdmin,
  clearOutboundAdmin,
} from "./outbound-admin.js?v=9";

const MSG_SEND = 0x02;
const MSG_ACK = 0x05;
const MSG_SYNC = 0x07;
const MAGIC = [0x41, 0x53, 0x54, 0x50]; // "ASTP"

const ROUTE_TITLES = {
  inbox: "Inbox",
  sent: "Sent",
  compose: "Compose",
  account: "Account",
};

// Standard IEEE CRC32 lookup table (matches Python zlib.crc32)
const CRC_TABLE = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
  let c = i;
  for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
  CRC_TABLE[i] = c >>> 0;
}
const crc32 = (bytes) => {
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < bytes.length; i++) crc = CRC_TABLE[(crc ^ bytes[i]) & 0xFF] ^ (crc >>> 8);
  return (crc ^ 0xFFFFFFFF) >>> 0;
};

function packFrame(msgType, payloadBytes) {
  const buf = new ArrayBuffer(24 + payloadBytes.length);
  const view = new DataView(buf);
  const u8 = new Uint8Array(buf);
  u8.set(MAGIC, 0);
  view.setUint8(4, 1);
  view.setUint8(5, msgType);
  view.setUint16(6, 0, false);
  view.setUint32(8, 1, false);
  view.setUint32(12, 0, false);
  view.setUint32(16, payloadBytes.length, false);
  view.setUint32(20, crc32(u8.subarray(0, 20)), false);
  u8.set(payloadBytes, 24);
  return u8;
}

function unpackFrame(ab) {
  const u8 = new Uint8Array(ab);
  const view = new DataView(ab);
  if (u8.length < 24 || crc32(u8.subarray(0, 20)) !== view.getUint32(20, false)) {
    throw new Error("Corrupted ASTP frame");
  }
  const msgType = view.getUint8(5);
  const len = view.getUint32(16, false);
  return { msgType, payload: u8.subarray(24, 24 + len) };
}

const escapeHtml = (s) =>
  s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// --- Client state ---
let ws = null;
let currentUser = null; // { address, username, is_admin }
let authMode = "login"; // "login" | "register"
let inviteRequired = true;
let inboxItems = [];
let sentItems = [];

let cacheDb = null;
let cacheReady = Promise.resolve(null);
let cacheShutdown = Promise.resolve();
let mailboxEpoch = 0;
let pendingCacheWrites = Promise.resolve();

let reconnectTimer = null;
let reconnectAttempt = 0;
let hasServerData = false;

function queueCacheWrite(epoch, operation) {
  const job = pendingCacheWrites
    .catch(() => {})
    .then(async () => {
      const db = await cacheReady;

      if (!db || epoch !== mailboxEpoch) return;

      await operation(db);
    });

  pendingCacheWrites = job.catch(error => {
    console.warn("ASTMail cache write failed:", error);
  });

  return pendingCacheWrites;
}

function cancelReconnect() {
  if (reconnectTimer !== null) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
}

function scheduleReconnect(epoch) {
  if (epoch !== mailboxEpoch || !currentUser) return;

  cancelReconnect();

  if (!navigator.onLine) {
    console.info("ASTMail offline; waiting for network");
    return;
  }

  const base = Math.min(
    30_000,
    500 * 2 ** Math.min(reconnectAttempt++, 6)
  );

  const delay = Math.floor(
    base * (0.8 + Math.random() * 0.4)
  );

  console.info(`ASTMail reconnect in ${delay}ms`);

  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;

    if (epoch === mailboxEpoch && currentUser) {
      connectMailboxSocket(epoch);
    }
  }, delay);
}

window.addEventListener("online", () => {
  if (!currentUser || !navigator.onLine) return;

  const epoch = mailboxEpoch;
  cancelReconnect();

  if (!ws ||
      (ws.readyState !== WebSocket.OPEN &&
       ws.readyState !== WebSocket.CONNECTING)) {
    reconnectAttempt = 0;
    connectMailboxSocket(epoch);
  }
});

const outboundStatuses = new Map();

const OUTBOUND_STATUS_LABELS = Object.freeze({
  local: "Local",
  queued: "Queued",
  sending: "Sending",
  retry: "Retry scheduled",
  accepted: "Accepted by SMTP",
  failed: "Failed",
  unknown: "Delivery uncertain",
  cancelled: "Cancelled",
});

let outboundStatusRequest = 0;

function isSentRoute() {
  return location.hash === "#/sent";
}

function renderMailStatus(message) {
  if (message.folder !== "sent") return "";

  const status = outboundStatuses.get(message.id);

  if (!status) {
    return `<span class="mail-status mail-status-pending">Checking…</span>`;
  }

  const label = OUTBOUND_STATUS_LABELS[status.status] ?? "Unknown";

  const cssClass = [
    "local",
    "queued",
    "sending",
    "retry",
    "accepted",
    "failed",
    "unknown",
  ].includes(status.status)
    ? status.status
    : "unknown";

  return `
    <span class="mail-status mail-status-${cssClass}"
          title="SMTP attempts: ${Number(status.attempts) || 0}">
      ${label}
    </span>
  `;
}

function renderCancelButton(message) {
  if (message.folder !== "sent") return "";

  const delivery = outboundStatuses.get(message.id);

  if (
    !delivery ||
    !["queued", "retry"].includes(delivery.status)
  ) {
    return "";
  }

  return `
    <button
      type="button"
      class="mail-cancel-btn"
      data-id="${escapeHtml(String(message.id))}"
    >Cancel</button>
  `;
}

function updateTabTitle(route = "inbox") {
  if (!currentUser) {
    document.title = "ast.pp.ua — Mail";
    return;
  }
  const label = ROUTE_TITLES[route] || "Mail";
  document.title = `${currentUser.address} · ${label} — ast.pp.ua`;
}

function setAuthMode(mode) {
  authMode = mode;
  document.getElementById("tabLogin").classList.toggle("active", mode === "login");
  document.getElementById("tabRegister").classList.toggle("active", mode === "register");
  document.getElementById("inviteFieldWrap").classList.toggle("hidden", !(mode === "register" && inviteRequired));
  document.getElementById("btnAuthSubmit").textContent = mode === "login" ? "Sign In" : "Create Mailbox";
  document.getElementById("authErr").textContent = "";
}

async function refreshAuthInfo() {
  try {
    const res = await fetch("/api/auth/info");
    if (res.ok) {
      const info = await res.json();
      inviteRequired = Boolean(info.invite_required);
      setAuthMode(authMode);
    }
  } catch {
    // Ignore transient errors
  }
}


function renderFolder(containerId, items, emptyText) {
  const container = document.getElementById(containerId);

  if (!items.length) {
    container.innerHTML = `<p class="muted">${emptyText}</p>`;
    return;
  }

  container.innerHTML = items.map((m) => {
    const time = new Date(m.created_ms).toLocaleTimeString();
    const peer = m.folder === "inbox"
      ? m.sender
      : m.recipients[0];

    const who = m.folder === "inbox"
      ? `From: ${escapeHtml(m.sender)}`
      : `To: ${escapeHtml(m.recipients.join(", "))}`;

    const avatarUrl =
      `/api/avatar/${encodeURIComponent(peer.split("@")[0])}`;

    return `
      <div class="mail-item">
        <img class="mail-avatar" src="${avatarUrl}" alt="" />
        <div class="mail-content">
          <div class="mail-meta">${who} · ${time}</div>

          <div class="mail-subject-line">
            <strong>${escapeHtml(m.subject)}</strong>
            ${renderMailStatus(m)}
            ${renderCancelButton(m)}
          </div>

          <div class="mail-body">${escapeHtml(m.body)}</div>
        </div>
      </div>
    `;
  }).join("");
}


function renderAllMail() {
  document.getElementById("inboxCount").textContent = String(inboxItems.length);
  document.getElementById("sentCount").textContent = String(sentItems.length);
  renderFolder("inboxList", inboxItems, "No incoming messages yet.");
  renderFolder("sentList", sentItems, "No sent messages yet.");
}

async function refreshOutboundStatuses() {
  if (!currentUser || !isSentRoute()) return;

  const user = currentUser;
  const requestId = ++outboundStatusRequest;

  try {
    const response = await fetch(
      "/api/mail/outbound/status",
      {
        credentials: "same-origin",
        cache: "no-store",
      }
    );

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();

    // Ignore results from an old session, route,
    // or a superseded request.
    if (
      requestId !== outboundStatusRequest ||
      currentUser !== user ||
      !isSentRoute()
    ) {
      return;
    }

    if (!Array.isArray(data.messages)) {
      throw new Error("Invalid status response");
    }

    outboundStatuses.clear();

    for (const item of data.messages) {
      if (typeof item.id !== "string") continue;

      outboundStatuses.set(item.id, {
        status: item.status,
        attempts: item.attempts,
        nextAttemptMs: item.next_attempt_ms,
      });
    }

    renderFolder(
      "sentList",
      sentItems,
      "No sent messages yet."
    );

  } catch (error) {
    if (
      requestId === outboundStatusRequest &&
      currentUser === user &&
      isSentRoute()
    ) {
      console.warn(
        "ASTMail outbound status refresh failed:",
        error
      );
    }
  }
}

async function loadInvites() {
  if (!currentUser || !currentUser.is_admin) return;
  const res = await fetch("/api/admin/invites");
  if (!res.ok) return;
  const data = await res.json();
  const listEl = document.getElementById("inviteList");
  if (!data.invites.length) {
    listEl.innerHTML = `<p class="muted">No invite codes generated yet.</p>`;
    return;
  }
  listEl.innerHTML = data.invites.map((inv) => {
    const usedText = inv.used_by.length ? ` · used by: ${escapeHtml(inv.used_by.join(", "))}` : "";
    const status = inv.is_expired ? "Expired" : `${inv.uses_count}/${inv.max_uses} used${usedText}`;
    return `
      <div class="invite-row">
        <div>
          <div class="invite-code">${escapeHtml(inv.code)}</div>
          <div class="muted">${status}</div>
        </div>
        <div class="invite-actions">
          <button type="button" class="sec btn-xs copy-inv" data-code="${escapeHtml(inv.code)}">Copy</button>
          <button type="button" class="danger btn-xs revoke-inv" data-code="${escapeHtml(inv.code)}">Revoke</button>
        </div>
      </div>
    `;
  }).join("");

  listEl.querySelectorAll(".copy-inv").forEach((btn) => {
    btn.addEventListener("click", async () => {
      await navigator.clipboard.writeText(btn.dataset.code);
      btn.textContent = "Copied";
      setTimeout(() => { btn.textContent = "Copy"; }, 1200);
    });
  });
  listEl.querySelectorAll(".revoke-inv").forEach((btn) => {
    btn.addEventListener("click", async () => {
      await fetch("/api/admin/invites/revoke", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: btn.dataset.code }),
      });
      await loadInvites();
    });
  });
}

function showRoute() {
  if (!currentUser) return;
  const raw = location.hash.replace(/^#\/?/, "");
  const route = ["inbox", "sent", "compose", "account"].includes(raw) ? raw : "inbox";
  if (location.hash !== `#/${route}`) {
    location.hash = `#/${route}`;
  }
  document.querySelectorAll(".page").forEach((el) => el.classList.add("hidden"));
  document.getElementById(`page-${route}`).classList.remove("hidden");
  document.querySelectorAll("#navBar a").forEach((a) => {
    a.classList.toggle("active", a.dataset.route === route);
  });
  updateTabTitle(route);
  if (route === "account") {
  initializeIdentityAliases();
  initializePrimaryEmail();

  void refreshIdentityAliases();
  void refreshPrimaryEmail();

  if (currentUser.is_admin) {
    void loadInvites();

    initializeIdentityRewards();
    showIdentityRewards();

    initializeOutboundAdmin();
    void refreshOutboundAdmin();
  }
}
  if (route === "sent") {
    void refreshOutboundStatuses();
  } else {
    ++outboundStatusRequest;
  }
}

function enterSignedOutState(statusMsg = "") {
  ++mailboxEpoch;
  cancelReconnect();

  const opening = cacheReady;
  const writes = pendingCacheWrites;

  cacheDb = null;
  cacheReady = Promise.resolve(null);
  hasServerData = false;

  cacheShutdown = Promise.allSettled([
    opening,
    writes,
  ]).then(results => {
    const opened = results[0];

    if (opened.status === "fulfilled" && opened.value) {
      opened.value.close();
    }
  });
  if (ws) {
    ws.onclose = null;
    ws.close();
    ws = null;
  }
  currentUser = null;
  inboxItems = [];
  sentItems = [];
  clearOutboundAdmin();
  clearIdentityAliases();
  clearPrimaryEmail();
  outboundStatuses.clear();
  ++outboundStatusRequest;
  if (location.hash) {
    history.replaceState(null, "", "/");
  }
  updateTabTitle();
  refreshAuthInfo();

  document.getElementById("userPill").classList.add("hidden");
  document.getElementById("me").textContent = "";
  document.getElementById("navBar").classList.add("hidden");
  document.getElementById("appView").classList.add("hidden");
  document.getElementById("adminInvitesBox").classList.add("hidden");
  document.getElementById("authView").classList.remove("hidden");
  document.getElementById("authPass").value = "";
  document.getElementById("authInvite").value = "";
  document.getElementById("delPass").value = "";
  document.getElementById("delStatus").textContent = "";
  document.getElementById("sendStatus").textContent = "";
  document.getElementById("authErr").textContent = statusMsg;
}

async function startMailbox(user, epoch) {
  let db = null;

  try {
    db = await ASTMailStorage.open(user.id);

    if (epoch !== mailboxEpoch) {
      db.close();
      return null;
    }

    cacheDb = db;

    const cached = await ASTMailStorage.getMessages(db);

    if (epoch !== mailboxEpoch) {
      return db;
    }

    // Never overwrite live server data with older cache data.
    if (!hasServerData) {
      const messages = cached
        .filter(m =>
          typeof m.messageId === "string" &&
          (m.folder === "inbox" || m.folder === "sent") &&
          typeof m.sender === "string" &&
          Array.isArray(m.recipients) &&
          typeof m.subject === "string" &&
          typeof m.body === "string" &&
          typeof m.created_ms === "number"
        )
        .map(m => ({
          ...m,
          id: m.messageId,
        }));

      const newestFirst = (a, b) =>
        b.created_ms - a.created_ms;

      inboxItems = messages
        .filter(m => m.folder === "inbox")
        .sort(newestFirst);

      sentItems = messages
        .filter(m => m.folder === "sent")
        .sort(newestFirst);

      renderAllMail();
    }

    return db;
  } catch (error) {
    console.warn("ASTMail local cache unavailable:", error);

    if (db) {
      db.close();
      if (cacheDb === db) cacheDb = null;
    }

    return null;
  }
}

function connectMailboxSocket(epoch) {
  if (epoch !== mailboxEpoch || !currentUser) return;

  if (
    ws &&
    (ws.readyState === WebSocket.OPEN ||
     ws.readyState === WebSocket.CONNECTING)
  ) {
    return;
  }

  if (epoch !== mailboxEpoch || !currentUser) return;

  const proto = location.protocol === "https:"
    ? "wss://"
    : "ws://";

  const socket = new WebSocket(
    `${proto}${location.host}/v1/ws`
  );

  ws = socket;
  socket.binaryType = "arraybuffer";

  socket.onopen = () => {
    if (epoch !== mailboxEpoch || socket !== ws) return;

    reconnectAttempt = 0;
    cancelReconnect();

    console.info("ASTMail WebSocket connected");
  };

  socket.onmessage = ev => {
    if (epoch !== mailboxEpoch || socket !== ws) return;

    let msgType;
    let obj;

    try {
      const frame = unpackFrame(ev.data);
      msgType = frame.msgType;
      obj = decode(frame.payload);
    } catch (error) {
      console.error("Invalid ASTP response:", error);
      socket.close(1002, "Invalid ASTP frame");
      return;
    }

    if (msgType === MSG_SYNC) {
      if (!Array.isArray(obj.inbox) ||
          !Array.isArray(obj.sent)) {
        socket.close(1002, "Invalid mailbox snapshot");
        return;
      }

      hasServerData = true;

      inboxItems = obj.inbox;
      sentItems = obj.sent;
      renderAllMail();

      const inbox = obj.inbox;
      const sent = obj.sent;

      void queueCacheWrite(epoch, db =>
        ASTMailStorage.replaceSnapshot(db, inbox, sent)
      );

      if (isSentRoute()) {
        void refreshOutboundStatuses();
      }

    } else if (msgType === MSG_SEND) {
      if (!obj || !["inbox", "sent"].includes(obj.folder) ||
          typeof obj.id !== "string") {
        socket.close(1002, "Invalid mail event");
        return;
      }

      hasServerData = true;

      const target = obj.folder === "inbox"
        ? inboxItems
        : sentItems;

      const existing = target.findIndex(m => m.id === obj.id);

      if (existing !== -1) {
        target.splice(existing, 1);
      }

      target.unshift(obj);
      renderAllMail();

      const message = {
        ...obj,
        messageId: obj.id,
        id: `${obj.folder}:${obj.id}`,
      };

      void queueCacheWrite(epoch, db =>
        ASTMailStorage.saveMessage(db, message)
      );

      if (obj.folder === "sent" && isSentRoute()) {
        void refreshOutboundStatuses();
      }

    } else if (msgType === MSG_ACK) {
      const statusEl = document.getElementById("sendStatus");
      statusEl.textContent = obj.message;

      if (obj.ok) {
        document.getElementById("subj").value = "";
        document.getElementById("body").value = "";
      }
    }
  };

  socket.onclose = ev => {
    if (epoch !== mailboxEpoch || socket !== ws) return;

    ws = null;

    if (ev.code === 4001 || ev.code === 4002) {
      enterSignedOutState(ev.reason || "Session ended");
      return;
    }

    document.getElementById("sendStatus").textContent =
      "Disconnected. Reconnecting...";

    scheduleReconnect(epoch);
  };
}

function enterSignedInState(user) {
  currentUser = user;
  if (!user.is_admin) {
    clearIdentityRewards();
  }
  const avatarUrl = `/api/avatar/${encodeURIComponent(user.username)}`;
  document.getElementById("userAvatar").src = avatarUrl;
  document.getElementById("accountAvatar").src = avatarUrl;
  document.getElementById("me").textContent = user.address;
  document.getElementById("accountAddr").textContent = user.address;
  document.getElementById("accountRole").textContent = user.is_admin ? "Admin · Active cookie session" : "Active cookie session";
  document.getElementById("adminInvitesBox").classList.toggle("hidden", !user.is_admin);

  document.getElementById("userPill").classList.remove("hidden");
  document.getElementById("authView").classList.add("hidden");
  document.getElementById("navBar").classList.remove("hidden");
  document.getElementById("appView").classList.remove("hidden");
  showRoute();

  const epoch = ++mailboxEpoch;

  hasServerData = false;
  reconnectAttempt = 0;
  pendingCacheWrites = Promise.resolve();

  cancelReconnect();

  cacheReady = startMailbox(user, epoch);
  connectMailboxSocket(epoch);
}

async function submitAuth() {
  document.getElementById("authErr").textContent = "";
  const res = await fetch("/api/auth", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      action: authMode,
      username: document.getElementById("authUser").value,
      password: document.getElementById("authPass").value,
      invite_code: document.getElementById("authInvite").value,
    }),
  });
  const data = await res.json();
  if (!res.ok) {
    document.getElementById("authErr").textContent = data.detail || "Authentication failed";
    return;
  }
  enterSignedInState(data);
}

async function logout() {
  try {
    const response = await fetch("/api/logout", {
      method: "POST",
    });

    if (!response.ok) {
      throw new Error("Logout request failed");
    }

    const accountId = currentUser?.id;
    enterSignedOutState();

    await cacheShutdown;

    if (accountId) {
      try {
        await ASTMailStorage.clearAccount(accountId);
      } catch (error) {
        console.warn("Unable to clear local mail cache:", error);
      }
    }
  } catch (error) {
    console.error("Logout failed:", error);
    document.getElementById("sendStatus").textContent =
      "Could not sign out";
  }
}

async function deleteMailbox() {
  const statusEl = document.getElementById("delStatus");
  statusEl.textContent = "";
  const password = document.getElementById("delPass").value;
  if (!password) {
    statusEl.textContent = "Enter your password to confirm deletion";
    return;
  }

  try {
    const res = await fetch("/api/account/delete", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password }),
    });
    const text = await res.text();
    let data = {};
    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      data = {};
    }

    if (!res.ok) {
      statusEl.textContent = data.detail || `Failed to delete mailbox (HTTP ${res.status})`;
      return;
    }

    document.getElementById("authUser").value = "";
    enterSignedOutState(`Mailbox ${data.username}@ast.pp.ua deleted.`);
  } catch (err) {
    statusEl.textContent = `Request failed: ${err.message}`;
  }
}

// --- Event bindings ---

document.getElementById("sentList").addEventListener(
  "click",
  async (event) => {
    const button = event.target.closest(".mail-cancel-btn");

    if (!button || button.disabled) return;

    const messageId = button.dataset.id;

    if (!confirm("Cancel this outgoing email?")) {
      return;
    }

    button.disabled = true;
    button.textContent = "Cancelling…";

    try {
      const response = await fetch(
        "/api/mail/outbound/cancel",
        {
          method: "POST",
          credentials: "same-origin",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            id: messageId,
          }),
        }
      );

      if (!response.ok) {
        const error = await response.json()
          .catch(() => ({}));

        throw new Error(
          error.detail || `HTTP ${response.status}`
        );
      }

      // Immediately reflect the confirmed cancellation.
      outboundStatuses.set(messageId, {
        status: "cancelled",
        attempts: 0,
        nextAttemptMs: 0,
      });

      renderFolder(
        "sentList",
        sentItems,
        "No sent messages yet."
      );

      void refreshOutboundStatuses();

    } catch (error) {
      alert(`Cancellation failed: ${error.message}`);
      button.disabled = false;
      button.textContent = "Cancel";
    }
  }
);

document.querySelectorAll(".toggle-pw").forEach((btn) => {
  btn.addEventListener("click", () => {
    const input = document.getElementById(btn.dataset.target);
    const show = input.type === "password";
    input.type = show ? "text" : "password";
    btn.textContent = show ? "Hide" : "Show";
  });
});

document.getElementById("tabLogin").addEventListener("click", () => setAuthMode("login"));
document.getElementById("tabRegister").addEventListener("click", () => setAuthMode("register"));
document.getElementById("btnAuthSubmit").addEventListener("click", submitAuth);
document.getElementById("btnLogout").addEventListener("click", logout);
document.getElementById("btnDeleteAccount").addEventListener("click", deleteMailbox);

document.getElementById("btnCreateInvite").addEventListener("click", async () => {
  const maxUses = parseInt(document.getElementById("invMaxUses").value || "1", 10);
  await fetch("/api/admin/invites", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ max_uses: maxUses }),
  });
  await loadInvites();
});

document.getElementById("btnSend").addEventListener("click", () => {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  const payload = encode({
    to: document.getElementById("to").value,
    subject: document.getElementById("subj").value,
    body: document.getElementById("body").value,
  });
  ws.send(packFrame(MSG_SEND, payload));
});

window.addEventListener("hashchange", showRoute);

// Restore session automatically from HttpOnly cookie on load
refreshAuthInfo();
fetch("/api/me")
  .then((res) => (res.ok ? res.json() : null))
  .then((user) => {
    if (user) enterSignedInState(user);
    else updateTabTitle();
  })
  .catch(() => updateTabTitle());
setInterval(() => {
  if (
    currentUser &&
    isSentRoute() &&
    document.visibilityState === "visible"
  ) {
    void refreshOutboundStatuses();
  }
}, 15_000);