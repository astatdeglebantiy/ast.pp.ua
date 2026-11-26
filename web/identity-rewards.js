
let panel = null;
let usernameInput = null;
let amountInput = null;
let reasonInput = null;
let submitButton = null;
let feedback = null;

let busy = false;
let generation = 0;

function element(tag, className = "", text) {
  const node = document.createElement(tag);

  if (className) node.className = className;
  if (text !== undefined) {
    node.textContent = String(text);
  }

  return node;
}

function showFeedback(message, isError = false) {
  if (!feedback) return;

  feedback.textContent = message;
  feedback.classList.toggle(
    "identity-reward-error",
    isError
  );
}

async function grantAliasSlots(username, amount, reason) {
  const response = await fetch(
    "/api/admin/identity/grant",
    {
      method: "POST",
      credentials: "same-origin",
      cache: "no-store",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username,
        amount,
        reason,
      }),
    }
  );

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(
      data.detail || `HTTP ${response.status}`
    );
  }

  return data;
}

export function initializeIdentityRewards() {
  if (panel) return;

  const accountPage = document.getElementById(
    "page-account"
  );

  if (!accountPage) return;

  panel = element("section", "identity-rewards-panel");
  panel.id = "identityRewardsPanel";
  panel.hidden = true;

  const header = element("div", "identity-rewards-header");

  header.append(
    element("h3", "", "Alias Rewards"),
    element(
      "p",
      "identity-rewards-muted",
      "Grant permanent alias slots to users"
    )
  );

  const form = element(
    "form",
    "identity-rewards-form"
  );

  const usernameField = element(
    "label",
    "identity-rewards-field"
  );

  usernameField.append(
    element("span", "", "Username")
  );

  usernameInput = element("input");
  usernameInput.type = "text";
  usernameInput.placeholder = "Mailbox username";
  usernameInput.autocomplete = "off";
  usernameInput.required = true;
  usernameInput.maxLength = 64;

  usernameField.append(usernameInput);

  const amountField = element(
    "label",
    "identity-rewards-field"
  );

  amountField.append(
    element("span", "", "Additional slots")
  );

  amountInput = element("input");
  amountInput.type = "number";
  amountInput.min = "1";
  amountInput.max = "10";
  amountInput.step = "1";
  amountInput.value = "1";
  amountInput.required = true;

  amountField.append(amountInput);

  const reasonField = element(
    "label",
    "identity-rewards-field"
  );

  reasonField.append(
    element("span", "", "Reason")
  );

  reasonInput = element("textarea");
  reasonInput.rows = 3;
  reasonInput.maxLength = 500;
  reasonInput.placeholder =
    "За то, что хороший мальчик 🐾";
  reasonInput.required = true;

  reasonField.append(reasonInput);

  submitButton = element(
    "button",
    "sec identity-rewards-submit",
    "Award Alias Slots"
  );

  submitButton.type = "submit";

  feedback = element(
    "p",
    "identity-rewards-feedback"
  );

  feedback.setAttribute("role", "status");

  form.append(
    usernameField,
    amountField,
    reasonField,
    submitButton
  );

  panel.append(header, form, feedback);

  form.addEventListener("submit", async event => {
    event.preventDefault();

    if (busy) return;

    const username = usernameInput.value
      .trim()
      .toLowerCase();

    const amount = Number(amountInput.value);
    const reason = reasonInput.value.trim();

    if (!username) {
      showFeedback("Username is required.", true);
      return;
    }

    if (
      !Number.isInteger(amount) ||
      amount < 1 ||
      amount > 10
    ) {
      showFeedback(
        "Enter between 1 and 10 slots.",
        true
      );
      return;
    }

    if (!reason || reason.length > 500) {
      showFeedback(
        "Reason must contain 1–500 characters.",
        true
      );
      return;
    }

    if (!confirm(
      `Award ${amount} permanent alias slot(s) ` +
      `to ${username}?\n\nReason: ${reason}`
    )) {
      return;
    }

    const requestGeneration = generation;
    busy = true;
    submitButton.disabled = true;
    submitButton.textContent = "Awarding…";
    showFeedback("");

    try {
      const result = await grantAliasSlots(
        username,
        amount,
        reason
      );

      if (requestGeneration !== generation) return;

      showFeedback(
        `Awarded ${result.amount} slot(s) to ` +
        `${result.username}. ` +
        `Total: ${result.total_slots}.`
      );

      reasonInput.value = "";
      amountInput.value = "1";

    } catch (error) {
      if (requestGeneration === generation) {
        showFeedback(error.message, true);
      }
    } finally {
      busy = false;
      submitButton.disabled = false;
      submitButton.textContent = "Award Alias Slots";
    }
  });

  const aliases = document.getElementById(
    "identityAliasPanel"
  );

  const outbound = document.getElementById(
    "outboundAdminPanel"
  );

  if (aliases) {
    aliases.insertAdjacentElement(
      "afterend",
      panel
    );
  } else if (outbound) {
    outbound.insertAdjacentElement(
      "beforebegin",
      panel
    );
  } else {
    accountPage.append(panel);
  }
}

export function showIdentityRewards() {
  initializeIdentityRewards();

  if (panel) panel.hidden = false;
}

export function clearIdentityRewards() {
  generation++;

  if (panel) panel.hidden = true;

  if (usernameInput) usernameInput.value = "";
  if (amountInput) amountInput.value = "1";
  if (reasonInput) reasonInput.value = "";

  showFeedback("");
}
