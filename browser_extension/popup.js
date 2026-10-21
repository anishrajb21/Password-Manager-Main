
const HOST = "com.local_password_manager.autofill";

let port = null;
let nextId = 1;
const pending = new Map();

let activeTab = null;
let activeOrigin = "";

// DOM helpers
const $ = (id) => document.getElementById(id);

function status(message) {
  const element = $("status");
  if (element) element.textContent = message;
}

function setUnlockButtonDisabled(disabled) {
  const button = $("unlockButton");
  if (button) button.disabled = disabled;
}

// Connect to the installed native messaging host.
function connect() {
  if (port) return port;

  try {
    port = chrome.runtime.connectNative(HOST);
    const currentPort = port;

    currentPort.onMessage.addListener((message) => {
      if (!message || message.id === undefined) return;

      const resolve = pending.get(message.id);

      if (resolve) {
        pending.delete(message.id);
        resolve(message);
      }
    });

    currentPort.onDisconnect.addListener(() => {
      const error =
        chrome.runtime.lastError?.message ||
        "Native host disconnected.";

      for (const [id, resolve] of pending) {
        clearTimeout(resolve.timeoutId);
        resolve({
          id,
          ok: false,
          error
        });
      }

      pending.clear();

      if (port === currentPort) {
        port = null;
      }

      if ($("vault")) $("vault").hidden = true;
      if ($("unlock")) $("unlock").hidden = false;

      status(`${error} Check native host installation.`);
    });

    return currentPort;
  } catch (error) {
    port = null;
    throw error;
  }
}

// Send a request to the native host with a timeout.
function request(action, extra = {}) {
  return new Promise((resolve) => {
    let currentPort;

    try {
      currentPort = connect();
    } catch (error) {
      resolve({
        ok: false,
        error: error.message || "Could not connect to native host."
      });
      return;
    }

    const id = nextId++;

    const timeoutId = setTimeout(() => {
      if (pending.has(id)) {
        pending.delete(id);
        resolve({
          id,
          ok: false,
          error: "Native host request timed out."
        });
      }
    }, 10000);

    pending.set(id, Object.assign(
      (message) => resolve(message),
      { timeoutId }
    ));

    try {
      currentPort.postMessage({
        id,
        action,
        origin: activeOrigin,
        ...extra
      });
    } catch (error) {
      clearTimeout(timeoutId);
      pending.delete(id);

      resolve({
        id,
        ok: false,
        error: error.message || "Failed to send native-host request."
      });
    }
  });
}

// Initialize the popup. Unlocking is allowed even on browser pages.
async function init() {
  setUnlockButtonDisabled(false);

  try {
    const tabs = await chrome.tabs.query({
      active: true,
      currentWindow: true
    });

    activeTab = tabs[0] || null;
    activeOrigin = "";

    if (activeTab?.url) {
      try {
        const url = new URL(activeTab.url);

        if (url.protocol === "http:" || url.protocol === "https:") {
          activeOrigin = url.origin;
          $("origin").textContent = `Website: ${activeOrigin}`;
        } else {
          $("origin").textContent =
            "This page cannot receive autofill.";
        }
      } catch {
        $("origin").textContent =
          "This page cannot receive autofill.";
      }
    } else {
      $("origin").textContent =
        "This page cannot receive autofill.";
    }
  } catch (error) {
    activeTab = null;
    activeOrigin = "";

    if ($("origin")) {
      $("origin").textContent =
        "Could not determine the current browser tab.";
    }

    status(error.message || "Popup initialization failed.");
  }

  setUnlockButtonDisabled(false);
}

// Search for saved credentials matching the current website.
async function findMatches() {
  const results = $("results");
  if (!results) return;

  results.replaceChildren();

  if (!activeOrigin) {
    status(
      "Vault unlocked. Open a regular website to check for matching logins."
    );
    return;
  }

  status("Checking saved website matches…");

  const response = await request("site_search");

  if (!response.ok) {
    status(response.error || "Search failed.");
    return;
  }

  const credentials = Array.isArray(response.credentials)
    ? response.credentials
    : [];

  if (credentials.length === 0) {
    results.textContent =
      "No credentials saved for this exact hostname.";
    status("No matching credentials.");
    return;
  }

  for (const credential of credentials) {
    const card = document.createElement("div");
    card.className = "credential";

    const label = document.createElement("div");
    label.textContent =
      `${credential.platform || "Website"} — ` +
      `${credential.username || "Unknown username"}`;

    const button = document.createElement("button");
    button.textContent = "Autofill this login";

    button.addEventListener("click", () => {
      fill(credential);
    });

    card.append(label, button);
    results.append(card);
  }

  status(`${credentials.length} exact-host match(es).`);
}

// Retrieve and autofill the selected credential.
async function fill(credential) {
  if (!activeTab?.id || !activeOrigin) {
    status("Open a regular website before using autofill.");
    return;
  }

  status("Retrieving selected credential…");

  const response = await request("get", {
    platform: credential.platform,
    username: credential.username
  });

  if (!response.ok) {
    status(response.error || "Could not retrieve credential.");
    return;
  }

  if (!response.credential) {
    status("The native host returned no credential.");
    return;
  }

  try {
    await chrome.scripting.executeScript({
      target: { tabId: activeTab.id },
      files: ["content.js"]
    });

    const result = await chrome.tabs.sendMessage(activeTab.id, {
      type: "PM_FILL",
      credential: response.credential
    });

    status(
      result?.ok
        ? "Credential submitted to visible login fields. Review before submitting."
        : result?.error || "No suitable login fields found."
    );
  } catch (error) {
    status(
      "Could not fill this page. Check extension permissions; " +
      "browser-internal pages do not allow autofill."
    );
  }
}

// Unlock the local vault.
$("unlockButton")?.addEventListener("click", async () => {
  const passwordInput = $("master");
  const button = $("unlockButton");
  const password = passwordInput?.value || "";

  if (!password) {
    status("Enter your master password.");
    return;
  }

  if (button) button.disabled = true;
  status("Unlocking local vault…");

  try {
    const response = await request("unlock", {
      master_password: password
    });

    if (passwordInput) passwordInput.value = "";

    if (!response.ok) {
      status(response.error || "Unlock failed.");
      return;
    }

    $("unlock").hidden = true;
    $("vault").hidden = false;

    status("Vault unlocked for this native-host session.");
    await findMatches();
  } catch (error) {
    if (passwordInput) passwordInput.value = "";

    status(error.message || "An unexpected error occurred.");
  } finally {
    // Allow retry after an error.
    if ($("unlock") && !$("unlock").hidden) {
      setUnlockButtonDisabled(false);
    }
  }
});

// Refresh matching credentials.
$("refreshButton")?.addEventListener("click", () => {
  findMatches();
});

// Lock the vault.
$("lockButton")?.addEventListener("click", async () => {
  status("Locking vault…");

  try {
    if (port) {
      await request("lock");
      port.disconnect();
      port = null;
    }
  } catch {
    // The host may already be disconnected.
  }

  $("vault").hidden = true;
  $("unlock").hidden = false;

  if ($("results")) $("results").replaceChildren();
  if ($("master")) $("master").value = "";

  setUnlockButtonDisabled(false);
  status("Vault locked.");
});

// Open the extension dashboard.
$("openDashboard")?.addEventListener("click", () => {
  chrome.tabs.create({
    url: chrome.runtime.getURL("dashboard.html")
  });
});

// Start popup initialization.
init();
