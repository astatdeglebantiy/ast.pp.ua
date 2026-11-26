const CHANGE_ENABLED = false; // Enable after routing checks.

let panel = null;
let currentAddress = null;
let description = null;
let form = null;
let usernameInput = null;
let passwordInput = null;
let scheduleButton = null;
let pendingBox = null;
let feedback = null;

let generation = 0;
let busy = false;

function element(tag, className = "", text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = String(text);
  return node;
}

function message(text, error = false) {
  if (!feedback) return;
  feedback.textContent = text;
  feedback.classList.toggle("primary-email-error", error);
}

async function request(url, options = {}) {
  const response = await fetch(url, {
    credentials: "same-origin",
    cache: "no-store",
    ...options,
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(
      data.detail || `HTTP ${response.status}`
    );
  }

  return data;
}

function formatDate(milliseconds) {
  return new Date(milliseconds).toLocaleString();
}

function renderState(data) {
  currentAddress.textContent = data.address;

  pendingBox.replaceChildren();

  if (data.pending) {
    form.hidden = true;

    description.textContent =
      "Your primary email change is scheduled.";

    pendingBox.append(
      element(
        "strong",
        "",
        data.pending.new_address
      ),
      element(
        "p",
        "primary-email-muted",
        `Scheduled for ${formatDate(
          data.pending.execute_after_ms
        )}`
      )
    );

    const cancelButton = element(
      "button",
      "sec btn-xs",
      "Cancel Change"
    );

    cancelButton.type = "button";
    cancelButton.disabled = !CHANGE_ENABLED;

    cancelButton.addEventListener("click", async () => {
      if (!confirm("Cancel your scheduled email change?")) {
        return;
      }

      if (busy) return;

      const requestGeneration = generation;
      busy = true;
      cancelButton.disabled = true;

      try {
        await request("/api/account/primary-email/cancel", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({}),
        });

        if (requestGeneration !== generation) return;

        await refreshPrimaryEmail();
        message("Scheduled email change cancelled.");
      } catch (error) {
        if (requestGeneration === generation) {
          message(error.message, true);
        }
      } finally {
        busy = false;
      }
    });

    pendingBox.append(cancelButton);
    return;
  }

  if (data.change_used) {
    form.hidden = true;

    description.textContent =
      "Your one-time primary email change has already been used.";

    return;
  }

  form.hidden = false;

  description.textContent =
    "You can change your primary email once. " +
    "The new address becomes active after 7 days.";

  usernameInput.disabled = !CHANGE_ENABLED;
  passwordInput.disabled = !CHANGE_ENABLED;
  scheduleButton.disabled = !CHANGE_ENABLED;

  if (!CHANGE_ENABLED) {
    pendingBox.append(
      element(
        "p",
        "primary-email-muted",
        "Email changes are temporarily unavailable " +
        "while external mail routing is being verified."
      )
    );
  }
}

export function initializePrimaryEmail() {
  if (panel) return;

  const accountPage = document.getElementById("page-account");
  if (!accountPage) return;

  panel = element("section", "primary-email-panel");
  panel.id = "primaryEmailPanel";
  panel.hidden = true;

  const header = element("div", "primary-email-header");

  header.append(
    element("h3", "", "Primary Email")
  );

  currentAddress = element(
    "strong",
    "primary-email-address",
    "Loading..."
  );

  description = element(
    "p",
    "primary-email-muted"
  );

  form = element("form", "primary-email-form");

  const usernameLabel = element(
    "label",
    "primary-email-field"
  );
  usernameLabel.append(
    element("span", "", "New mailbox username")
  );

  usernameInput = element("input");
  usernameInput.type = "text";
  usernameInput.placeholder = "newusername";
  usernameInput.maxLength = 32;
  usernameInput.autocomplete = "off";
  usernameInput.required = true;

  usernameLabel.append(usernameInput);

  const passwordLabel = element(
    "label",
    "primary-email-field"
  );
  passwordLabel.append(
    element("span", "", "Current password")
  );

  passwordInput = element("input");
  passwordInput.type = "password";
  passwordInput.autocomplete = "current-password";
  passwordInput.required = true;

  passwordLabel.append(passwordInput);

  scheduleButton = element(
    "button",
    "sec primary-email-submit",
    "Schedule Email Change"
  );
  scheduleButton.type = "submit";

  form.append(
    usernameLabel,
    passwordLabel,
    scheduleButton
  );

  pendingBox = element(
    "div",
    "primary-email-pending"
  );

  feedback = element(
    "p",
    "primary-email-feedback"
  );
  feedback.setAttribute("role", "status");

  form.addEventListener("submit", async event => {
    event.preventDefault();

    if (!CHANGE_ENABLED || busy) return;

    const username = usernameInput.value
      .trim()
      .toLowerCase();

    const password = passwordInput.value;

    if (!/^[a-z0-9]{1,32}$/.test(username)) {
      message(
        "Use 1–32 Latin letters or digits.",
        true
      );
      return;
    }

    if (!confirm(
      `Change your primary email to ` +
      `${username}@ast.pp.ua after 7 days?\n\n` +
      "This is a one-time change."
    )) {
      return;
    }

    const requestGeneration = generation;
    busy = true;
    scheduleButton.disabled = true;
    message("");

    try {
      await request(
        "/api/account/primary-email/change",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            username,
            password,
          }),
        }
      );

      if (requestGeneration !== generation) return;

      passwordInput.value = "";
      usernameInput.value = "";

      await refreshPrimaryEmail();
      message("Primary email change scheduled.");

    } catch (error) {
      if (requestGeneration === generation) {
        message(error.message, true);
      }
    } finally {
      busy = false;
      scheduleButton.disabled = !CHANGE_ENABLED;
    }
  });

  panel.append(
    header,
    currentAddress,
    description,
    pendingBox,
    form,
    feedback
  );

  const aliases = document.getElementById(
    "identityAliasPanel"
  );

  if (aliases) {
    aliases.insertAdjacentElement(
      "beforebegin",
      panel
    );
  } else {
    accountPage.append(panel);
  }
}

export function clearPrimaryEmail() {
  generation++;

  if (panel) panel.hidden = true;
  if (pendingBox) pendingBox.replaceChildren();
  if (usernameInput) usernameInput.value = "";
  if (passwordInput) passwordInput.value = "";
  message("");
}

export async function refreshPrimaryEmail() {
  initializePrimaryEmail();

  if (!panel) return;

  const requestGeneration = generation;

  try {
    const data = await request(
      "/api/account/primary-email"
    );

    if (requestGeneration !== generation) return;

    panel.hidden = false;
    renderState(data);

  } catch (error) {
    if (requestGeneration === generation) {
      message(error.message, true);
    }
  }
}
