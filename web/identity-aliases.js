
let panel = null;
let list = null;
let metrics = null;
let input = null;
let addButton = null;
let feedback = null;

let loading = false;
let generation = 0;

function element(tag, className = "", text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = String(text);
  return node;
}

function showFeedback(message, error = false) {
  if (!feedback) return;
  feedback.textContent = message;
  feedback.classList.toggle("identity-error", error);
}

async function apiRequest(url, options = {}) {
  const response = await fetch(url, {
    credentials: "same-origin",
    cache: "no-store",
    ...options,
  });

  let data;
  try {
    data = await response.json();
  } catch {
    throw new Error(`HTTP ${response.status}`);
  }

  if (!response.ok) {
    throw new Error(
      data.detail || data.message || `HTTP ${response.status}`
    );
  }

  return data;
}

function renderAlias(record) {
  const row = element("div", "identity-alias-item");

  const name = element(
    "strong",
    "identity-alias-name",
    `@${record.alias}`
  );

  const button = element(
    "button",
    "sec btn-xs",
    "Release"
  );

  button.type = "button";

  button.addEventListener("click", async () => {
    if (!confirm(`Release @${record.alias}?`)) return;

    button.disabled = true;

    try {
      await apiRequest("/api/identity/aliases/release", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          alias: record.normalized,
        }),
      });

      await refreshIdentityAliases();
      showFeedback(`@${record.alias} released.`);
    } catch (error) {
      showFeedback(error.message, true);
    } finally {
      button.disabled = false;
    }
  });

  row.append(name, button);
  return row;
}

export function initializeIdentityAliases() {
  if (panel) return;

  const accountPage = document.getElementById("page-account");
  if (!accountPage) return;

  panel = element("section", "identity-alias-panel");
  panel.id = "identityAliasPanel";
  panel.hidden = true;

  const header = element("div", "identity-alias-header");

  const heading = element("div");
  heading.append(
    element("h3", "", "Public Aliases"),
    element(
      "p",
      "identity-alias-muted",
      "Manage your public ASTMail usernames"
    )
  );

  const refreshButton = element(
    "button",
    "sec btn-xs",
    "Refresh"
  );

  refreshButton.type = "button";
  refreshButton.addEventListener(
    "click",
    () => void refreshIdentityAliases()
  );

  header.append(heading, refreshButton);

  metrics = element("div", "identity-alias-metrics");
  list = element("div", "identity-alias-list");

  const form = element("form", "identity-alias-form");

  input = element("input", "identity-alias-input");
  input.type = "text";
  input.placeholder = "New alias";
  input.maxLength = 32;
  input.autocomplete = "off";
  input.setAttribute("aria-label", "New public alias");

  addButton = element(
    "button",
    "sec btn-xs",
    "Add alias"
  );
  addButton.type = "submit";

  form.append(input, addButton);

  form.addEventListener("submit", async event => {
    event.preventDefault();

    const alias = input.value.trim();
    if (!alias) return;

    addButton.disabled = true;

    try {
      await apiRequest("/api/identity/aliases", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ alias }),
      });

      input.value = "";
      await refreshIdentityAliases();
      showFeedback(`@${alias.replace(/^@/, "")} created.`);
    } catch (error) {
      showFeedback(error.message, true);
    } finally {
      addButton.disabled = false;
    }
  });

  feedback = element(
    "p",
    "identity-alias-feedback"
  );
  feedback.setAttribute("role", "status");

  panel.append(header, metrics, list, form, feedback);

  const outbound = document.getElementById(
    "outboundAdminPanel"
  );

  const invites = document.getElementById(
    "adminInvitesBox"
  );

  if (outbound) {
    outbound.insertAdjacentElement("beforebegin", panel);
  } else if (invites) {
    invites.insertAdjacentElement("afterend", panel);
  } else {
    accountPage.append(panel);
  }
}

export function clearIdentityAliases() {
  generation++;

  if (panel) panel.hidden = true;
  if (list) list.replaceChildren();
  if (metrics) metrics.replaceChildren();
  if (feedback) feedback.textContent = "";
}

export async function refreshIdentityAliases() {
  initializeIdentityAliases();

  if (!panel || loading) return;

  const requestGeneration = generation;
  loading = true;

  try {
    const data = await apiRequest("/api/identity/aliases");

    if (requestGeneration !== generation) return;

    panel.hidden = false;

    const slots = data.slots;

    metrics.replaceChildren();

    for (const [label, value] of [
      ["Total", slots.total],
      ["Used", slots.used],
      ["Available", slots.available],
    ]) {
      const metric = element("div", "identity-alias-metric");

      metric.append(
        element("strong", "", value),
        element("span", "", label)
      );

      metrics.append(metric);
    }

    list.replaceChildren();

    if (!data.aliases.length) {
      list.append(
        element(
          "p",
          "identity-alias-muted",
          "No public aliases yet."
        )
      );
    } else {
      for (const record of data.aliases) {
        list.append(renderAlias(record));
      }
    }

    input.disabled = slots.available <= 0;
    addButton.disabled = slots.available <= 0;

    input.placeholder =
      slots.available > 0
        ? "New alias"
        : "No available slots";

  } catch (error) {
    if (requestGeneration === generation) {
      showFeedback(error.message, true);
    }
  } finally {
    loading = false;
  }
}
