
const STATUS_LABELS = {
  queued: "Queued",
  sending: "Sending",
  retry: "Retry scheduled",
  accepted: "Accepted by SMTP",
  failed: "Failed",
  unknown: "Delivery uncertain",
  cancelled: "Cancelled",
};

const ACTIVE_STATUSES = new Set([
  "queued",
  "sending",
  "retry",
]);

let panel = null;
let list = null;
let summary = null;
let loading = false;
let generation = 0;
let deliveryEnabled = null;
let deliveryButton = null;
let deliveryLabel = null;
let deliveryBusy = false;

function element(tag, className, text) {
  const node = document.createElement(tag);

  if (className) node.className = className;
  if (text !== undefined) node.textContent = String(text);

  return node;
}

function dateText(milliseconds) {
  if (!milliseconds) return "—";

  const date = new Date(milliseconds);

  return Number.isNaN(date.getTime())
    ? "—"
    : date.toLocaleString();
}

async function cancelOutbound(messageId) {
  if (!confirm(
    "Cancel this outgoing email?\n\n" +
    "It will remain in Sent but will not be delivered."
  )) {
    return;
  }

  try {
    const response = await fetch(
      "/api/admin/outbound/cancel",
      {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ id: messageId }),
      }
    );

    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      throw new Error(
        data.detail || `HTTP ${response.status}`
      );
    }

    await refreshOutboundAdmin();

  } catch (error) {
    alert(`Cannot cancel email: ${error.message}`);
  }
}

function renderRecord(record) {
  const row = element("div", "outbound-admin-item");
  const information = element("div", "outbound-admin-info");

  information.append(
    element("strong", "", record.subject || "(no subject)"),
    element("div", "outbound-admin-muted", record.recipient),
    element(
      "div",
      "outbound-admin-muted",
      `From: ${record.sender} · Attempts: ${record.attempts}`
    ),
    element(
      "div",
      "outbound-admin-muted",
      `Created: ${dateText(record.created_ms)}`
    )
  );

  if (record.next_attempt_ms) {
    information.append(
      element(
        "div",
        "outbound-admin-muted",
        `Next attempt: ${dateText(record.next_attempt_ms)}`
      )
    );
  }

  if (record.smtp_server) {
    information.append(
      element(
        "div",
        "outbound-admin-muted",
        `SMTP: ${record.smtp_server}`
      )
    );
  }

  if (record.last_error) {
    const error = element(
      "div",
      "outbound-admin-error",
      record.last_error
    );

    information.append(error);
  }

  const status = element(
    "span",
    "mail-status",
    STATUS_LABELS[record.status] || record.status
  );


  const actions = element(
    "div",
    "outbound-admin-actions"
  );

  actions.append(status);

  if (
    record.status === "queued" ||
    record.status === "retry"
  ) {
    const cancelButton = element(
      "button",
      "sec btn-xs outbound-cancel-button",
      "Cancel"
    );

    cancelButton.type = "button";

    cancelButton.addEventListener("click", async () => {
      cancelButton.disabled = true;

      try {
        await cancelOutbound(record.id);
      } finally {
        cancelButton.disabled = false;
      }
    });

    actions.append(cancelButton);
  }

  row.append(information, actions);
  return row;
}


function renderDeliveryControl() {
  if (!deliveryButton || !deliveryLabel) return;

  const enabled = deliveryEnabled === true;

  deliveryLabel.textContent =
    deliveryEnabled === null
      ? "Loading..."
      : enabled
        ? "Enabled"
        : "Paused";

  deliveryButton.textContent =
    enabled ? "Pause delivery" : "Enable delivery";

  deliveryButton.disabled =
    deliveryBusy || deliveryEnabled === null;

  deliveryButton.classList.toggle(
    "delivery-enabled",
    enabled
  );
}

async function updateDeliveryControl() {
  if (deliveryBusy || deliveryEnabled === null) return;

  const nextEnabled = !deliveryEnabled;

  if (nextEnabled) {
    const confirmed = confirm(
      "Enable automatic SMTP delivery?\n\n" +
      "All queued and retry-scheduled messages " +
      "may be sent, including older messages."
    );

    if (!confirmed) return;
  }

  const requestGeneration = generation;

  deliveryBusy = true;
  renderDeliveryControl();

  try {
    const response = await fetch(
      "/api/admin/outbound/control",
      {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          enabled: nextEnabled,
        }),
      }
    );

    const data = await response.json().catch(() => ({}));

    if (!response.ok || typeof data.enabled !== "boolean") {
      throw new Error(
        data.detail || `HTTP ${response.status}`
      );
    }

    if (requestGeneration !== generation) return;

    deliveryEnabled = data.enabled;

  } catch (error) {
    if (requestGeneration === generation) {
      alert(
        `Cannot change delivery settings: ${error.message}`
      );
    }

  } finally {
    deliveryBusy = false;

    if (requestGeneration === generation) {
      renderDeliveryControl();
    }
  }
}

export function initializeOutboundAdmin() {
  if (panel) return;

  const accountPage = document.getElementById("page-account");

  if (!accountPage) {
    console.warn("Account page not found");
    return;
  }

  panel = element("section", "outbound-admin-panel");
  panel.id = "outboundAdminPanel";

  const header = element("div", "outbound-admin-header");

  const title = element("h3", "", "Outbound Queue");
  const refreshButton = element(
    "button",
    "sec btn-xs",
    "Refresh"
  );

  refreshButton.type = "button";
  refreshButton.addEventListener("click", () => {
    void refreshOutboundAdmin();
  });

  header.append(title, refreshButton);

    const control = element(
    "div",
    "outbound-delivery-control"
  );

  const controlInfo = element(
    "div",
    "outbound-delivery-info"
  );

  controlInfo.append(
    element(
      "strong",
      "",
      "Automatic delivery"
    ),
    element(
      "span",
      "outbound-admin-muted",
      "Allow SMTP Worker to process outgoing mail"
    )
  );

  const controlActions = element(
    "div",
    "outbound-delivery-actions"
  );

  deliveryLabel = element(
    "span",
    "outbound-delivery-label",
    "Loading..."
  );

  deliveryButton = element(
    "button",
    "sec outbound-delivery-button",
    "Enable delivery"
  );

  deliveryButton.type = "button";
  deliveryButton.disabled = true;

  deliveryButton.addEventListener(
    "click",
    () => void updateDeliveryControl()
  );

  controlActions.append(
    deliveryLabel,
    deliveryButton
  );

  control.append(
    controlInfo,
    controlActions
  );
  summary = element(
    "div",
    "outbound-admin-summary",
    "Loading..."
  );

  list = element("div", "outbound-admin-list");

  panel.append(header, control, summary, list);

  const invites = document.getElementById("adminInvitesBox");

  if (invites) {
    invites.insertAdjacentElement("afterend", panel);
  } else {
    accountPage.append(panel);
  }
}

export function clearOutboundAdmin() {
  generation++;

  deliveryEnabled = null;
  deliveryBusy = false;
  renderDeliveryControl();

  if (list) list.replaceChildren();
  if (summary) summary.textContent = "";

  if (panel) panel.hidden = true;
}

export async function refreshOutboundAdmin() {
  initializeOutboundAdmin();

  if (!panel || loading) return;

  const requestGeneration = generation;

  loading = true;
  panel.hidden = false;
  if (!list.children.length) {
    summary.textContent = "Loading outbound queue...";
  }

  try {
    const [response, controlResponse] = await Promise.all([
      fetch("/api/admin/outbound", {
        credentials: "same-origin",
        cache: "no-store",
      }),

      fetch("/api/admin/outbound/control", {
        credentials: "same-origin",
        cache: "no-store",
      }),
    ]);

    if (!controlResponse.ok) {
      throw new Error(
        `Delivery control: HTTP ${controlResponse.status}`
      );
    }

    const controlData = await controlResponse.json();

    if (typeof controlData.enabled !== "boolean") {
      throw new Error("Invalid delivery control response");
    }

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();

    if (!Array.isArray(data.messages)) {
      throw new Error("Invalid queue response");
    }

    if (requestGeneration !== generation) return;

    deliveryEnabled = controlData.enabled;
    renderDeliveryControl();

    const records = data.messages;

    const active = records.filter(
      (record) => ACTIVE_STATUSES.has(record.status)
    ).length;

    const failed = records.filter(
      (record) => record.status === "failed"
    ).length;

    const unknown = records.filter(
      (record) => record.status === "unknown"
    ).length;


    summary.replaceChildren();

    const metrics = [
      ["Active", active],
      ["Failed", failed],
      ["Unknown", unknown],
    ];

    for (const [label, value] of metrics) {
      const metric = element("div", "outbound-metric");

      metric.append(
        element("strong", "outbound-metric-value", value),
        element("span", "outbound-metric-label", label)
      );

      summary.append(metric);
    }


    list.replaceChildren();

    if (!records.length) {
      list.append(
        element(
          "p",
          "outbound-admin-muted",
          "No outgoing messages."
        )
      );
    } else {
      for (const record of records) {
        list.append(renderRecord(record));
      }
    }

  } catch (error) {
    if (requestGeneration === generation) {
      summary.textContent =
        `Unable to load outbound queue: ${error.message}`;
    }
  } finally {
    loading = false;
  }
}
