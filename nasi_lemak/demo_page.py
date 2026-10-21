"""Static customer demo shell for the existing gateway.

The page is a thin same-origin client for ``POST /v1/chat/completions``.  The
chat key is typed by the operator, kept in a JavaScript variable only, and sent
as an ``Authorization`` header.  It is never put in a URL, storage, cookie,
console output or page text.  Prompt, response and error text are always
assigned with ``textContent``.

The visual shell follows a compact chat-client layout: a narrow control sidebar
and a spacious conversation with a bottom composer.  It shows the last exchange
for readability, while every submission still sends only the current prompt.
Inline CSS/JS is allowed by an independent hash-based Content-Security-Policy;
there is no remote resource, build step, framework, ``eval`` or inline event
handler.  This module adds no guard, model or audit behaviour of its own.
"""

from __future__ import annotations

import base64
import hashlib
import html


_DEMO_CSS = """
:root {
  color-scheme: dark;
  --bg: #0c0c0c;
  --panel: #111110;
  --surface: #181817;
  --surface-raised: #1f1f1d;
  --line: #2b2b28;
  --line-strong: #3a3a36;
  --text: #ececea;
  --muted: #a6a6a0;
  --amber: #e3aa4b;
  --amber-soft: #2a2114;
  --danger: #ff9c8f;
  --focus: #d8d8d2;
  --radius: 10px;
  font-family: "Segoe UI", system-ui, -apple-system, "Helvetica Neue", Arial, sans-serif;
  font-size: 16px;
}
* { box-sizing: border-box; }
html, body { min-height: 100%; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}
::selection { background: #3a3a35; color: #ffffff; }
* { scrollbar-color: #3d3d38 transparent; scrollbar-width: thin; }
h1, h2, p { margin-top: 0; }
a { color: var(--text); text-decoration-color: var(--line-strong); text-underline-offset: .2em; }
a:hover { text-decoration-color: var(--text); }
button {
  font: inherit;
  color: var(--text);
  background: transparent;
  border: 1px solid var(--line-strong);
  border-radius: 8px;
  padding: .45rem .75rem;
  min-height: 34px;
  cursor: pointer;
}
button:hover:not(:disabled) { background: var(--surface-raised); border-color: #4d4d47; }
button:disabled { cursor: not-allowed; opacity: .45; }
button.primary { background: var(--text); color: #111110; border-color: var(--text); font-weight: 650; }
button.primary:hover:not(:disabled) { background: #ffffff; border-color: #ffffff; }
button.ghost { color: var(--muted); border-color: transparent; }
button.ghost:hover:not(:disabled) { color: var(--text); border-color: var(--line-strong); }
.link-button { border: 0; padding: .2rem 0; min-height: 0; color: var(--muted); font-size: .8rem; text-align: left; }
.link-button:hover:not(:disabled) { background: transparent; color: var(--text); }
input, textarea { font: inherit; color: var(--text); }
input {
  width: 100%;
  padding: .5rem .6rem;
  border: 1px solid var(--line-strong);
  border-radius: 8px;
  background: var(--surface);
}
textarea {
  display: block;
  width: 100%;
  min-height: 3.2rem;
  max-height: 12rem;
  padding: .2rem .25rem;
  border: 0;
  border-radius: 6px;
  background: transparent;
  line-height: 1.55;
  resize: vertical;
}
input::placeholder, textarea::placeholder { color: #96968f; }
input:focus-visible, button:focus-visible, a:focus-visible, [tabindex]:focus-visible {
  outline: 2px solid var(--focus);
  outline-offset: 2px;
}
textarea:focus-visible { outline: 2px solid var(--focus); outline-offset: -2px; }
.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}
.app {
  display: grid;
  grid-template-columns: 268px minmax(0, 1fr);
  height: 100dvh;
  min-height: 100dvh;
}
.sidebar {
  display: flex;
  flex-direction: column;
  gap: .9rem;
  padding: 1rem .8rem;
  min-height: 0;
  overflow-y: auto;
  background: var(--panel);
  border-right: 1px solid var(--line);
}
.brand { display: flex; align-items: center; gap: .6rem; padding: .1rem .2rem .2rem; }
.brand-mark { flex: 0 0 auto; color: var(--text); }
.brand h1 { margin: 0; font-size: .95rem; font-weight: 650; letter-spacing: -.01em; }
.brand-sub { margin: .1rem 0 0; color: var(--muted); font-size: .78rem; }
.new-chat {
  display: flex;
  align-items: center;
  gap: .5rem;
  width: 100%;
  justify-content: flex-start;
  font-size: .88rem;
  font-weight: 550;
  min-height: 38px;
}
.new-chat svg { flex: 0 0 auto; color: var(--muted); }
.side-section { border-top: 1px solid var(--line); padding-top: .85rem; }
.side-section h2 {
  margin: 0 0 .55rem;
  color: var(--muted);
  font-size: .7rem;
  font-weight: 650;
  letter-spacing: .08em;
  text-transform: uppercase;
}
.side-section label { display: block; margin: 0 0 .35rem; color: var(--muted); font-size: .8rem; }
.key-row { display: flex; gap: .4rem; margin-top: .5rem; }
.key-row button { flex: 1 1 auto; }
.key-state { margin: .6rem 0 0; color: var(--muted); font-size: .8rem; line-height: 1.4; }
.hint { margin: .5rem 0 0; color: var(--muted); font-size: .76rem; line-height: 1.5; }
.side-nav a {
  display: block;
  padding: .4rem .5rem;
  margin: 0 -.5rem;
  border-radius: 8px;
  font-size: .86rem;
  text-decoration: none;
}
.side-nav a:hover { background: var(--surface); }
.status-list { display: grid; gap: .38rem; margin-bottom: .55rem; }
.status-row { display: flex; justify-content: space-between; align-items: baseline; gap: .6rem; font-size: .82rem; }
.status-row .label { color: var(--muted); }
.status-row strong { font-weight: 550; font-variant-numeric: tabular-nums; }
.status-row strong[data-kind="inactive"] { color: var(--amber); }
.main { display: flex; flex-direction: column; min-width: 0; min-height: 0; background: var(--bg); }
.topbar {
  display: flex;
  align-items: center;
  gap: .55rem;
  flex: 0 0 auto;
  min-height: 52px;
  padding: .55rem 1.1rem;
  border-bottom: 1px solid var(--line);
}
.topbar-title { font-size: .86rem; font-weight: 600; letter-spacing: -.01em; }
.topbar-status { margin-left: auto; color: var(--muted); font-size: .78rem; }
.topbar-status[data-kind="inactive"] { color: var(--amber); }
.icon-button {
  display: none;
  align-items: center;
  justify-content: center;
  width: 34px;
  height: 34px;
  min-height: 34px;
  padding: 0;
}
.banner {
  flex: 0 0 auto;
  margin: .8rem 1.1rem 0;
  padding: .6rem .75rem;
  border: 1px solid rgba(227, 170, 75, .38);
  border-radius: 8px;
  background: var(--amber-soft);
  color: #f0c079;
  font-size: .83rem;
  font-weight: 550;
  line-height: 1.45;
}
.conversation {
  flex: 1 1 auto;
  min-height: 0;
  overflow-y: auto;
  padding: 1.5rem 1.25rem 1rem;
}
.empty { max-width: 720px; margin: min(16vh, 8rem) auto 0; }
.empty h2 {
  max-width: 24ch;
  margin: 0 0 .65rem;
  font-size: clamp(1.45rem, 3vw, 1.9rem);
  font-weight: 600;
  letter-spacing: -.02em;
  line-height: 1.2;
}
.empty p { max-width: 58ch; margin: 0; color: var(--muted); line-height: 1.6; }
.exchange {
  display: flex;
  flex-direction: column;
  gap: 1.6rem;
  max-width: 760px;
  margin: 0 auto;
}
.msg-head {
  margin: 0 0 .4rem;
  color: var(--muted);
  font-size: .74rem;
  font-weight: 650;
  letter-spacing: .03em;
}
.msg-body {
  margin: 0;
  padding: .7rem .9rem;
  border: 1px solid var(--line);
  border-radius: 12px;
  background: var(--surface);
  line-height: 1.55;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
.response {
  max-width: 72ch;
  min-height: 1.7rem;
  margin: 0;
  color: var(--text);
  line-height: 1.7;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
.exchange[data-state="pending"] .response:empty::before {
  content: "Waiting for the gateway…";
  color: var(--muted);
}
.exchange .hint { margin-top: -.5rem; }
.composer-wrap {
  flex: 0 0 auto;
  padding: .5rem 1.25rem 1rem;
  border-top: 1px solid var(--line);
  background: var(--bg);
}
.composer-inner { max-width: 760px; margin: 0 auto; }
.status { min-height: 1.35rem; margin: 0 0 .35rem; color: var(--muted); font-size: .82rem; line-height: 1.4; }
.status[data-kind="error"] { color: var(--danger); font-weight: 550; }
.status[data-kind="info"] { color: var(--muted); }
.composer {
  padding: .55rem .6rem .45rem;
  border: 1px solid var(--line-strong);
  border-radius: 12px;
  background: var(--surface);
}
.composer:focus-within { border-color: #5a5a54; }
.composer-row { display: flex; align-items: center; gap: .45rem; margin-top: .35rem; }
.composer-row button { min-height: 32px; padding: .3rem .7rem; font-size: .84rem; }
.composer-hint { margin-right: auto; color: var(--muted); font-size: .72rem; }
.foot { margin: .55rem 0 0; color: var(--muted); font-size: .72rem; line-height: 1.5; }
[hidden] { display: none !important; }
@media (max-width: 820px) {
  .app { display: flex; flex-direction: column; height: 100dvh; min-height: 100dvh; }
  .sidebar {
    display: none;
    flex: 0 0 auto;
    max-height: 68dvh;
    overflow-y: auto;
    border-right: 0;
    border-bottom: 1px solid var(--line);
  }
  .app[data-nav="open"] .sidebar { display: flex; }
  .main { flex: 1 1 auto; min-height: 0; }
  .icon-button { display: inline-flex; }
  .topbar { padding: .5rem .75rem; }
  .topbar-status { font-size: .74rem; }
  .banner { margin: .7rem .75rem 0; }
  .conversation { overflow-y: auto; padding: 1.1rem .9rem .5rem; }
  .empty { margin: 2.4rem auto 0; }
  .composer-wrap { padding: .45rem .75rem .75rem; }
  .composer-hint { display: none; }
}
@media (max-width: 380px) {
  .key-row { flex-wrap: wrap; }
  .key-row button { flex: 1 1 45%; }
  .topbar-title { font-size: .8rem; }
  .composer-wrap { padding: .4rem .55rem .65rem; }
}
"""


_DEMO_JS = """
"use strict";
(function () {
  var appEl = document.getElementById("app");
  var sidebarToggle = document.getElementById("sidebar-toggle");
  var newChatButton = document.getElementById("new-chat");
  var keyInput = document.getElementById("chat-key");
  var keyForm = document.getElementById("key-form");
  var loadKeyButton = document.getElementById("load-key");
  var forgetKeyButton = document.getElementById("forget-key");
  var promptForm = document.getElementById("prompt-form");
  var promptInput = document.getElementById("prompt");
  var sendButton = document.getElementById("send");
  var clearButton = document.getElementById("clear");
  var exchangeEl = document.getElementById("exchange");
  var emptyStateEl = document.getElementById("empty-state");
  var lastPromptEl = document.getElementById("last-prompt");
  var responseEl = document.getElementById("response");
  var statusEl = document.getElementById("status");
  var keyStateEl = document.getElementById("key-state");
  var modeEl = document.getElementById("mode-value");
  var readinessEl = document.getElementById("readiness-value");
  var guardsEl = document.getElementById("guards-value");
  var topbarGuardsEl = document.getElementById("topbar-guards");
  var banner = document.getElementById("test-banner");
  var refreshButton = document.getElementById("refresh-status");
  var chatToken = "";
  var keyAccepted = false;
  var busy = false;
  var navOpen = false;
  var epoch = 0;
  var activeController = null;
  var requestTimer = null;
  var healthEpoch = 0;
  var healthController = null;
  var healthTimer = null;
  var CHAT_TIMEOUT_MS = 90000;
  var HEALTH_TIMEOUT_MS = 10000;
  var TEST_BANNER = "Test mode: model-based injection and output checks are inactive.";
  var NO_GUARD_BANNER = "Guards are not active. Chat may be unavailable.";

  function setStatus(text, kind) {
    statusEl.textContent = text || "";
    if (kind) {
      statusEl.setAttribute("data-kind", kind);
    } else {
      statusEl.removeAttribute("data-kind");
    }
  }

  function setKeyState() {
    if (!chatToken) {
      keyStateEl.textContent = "No key loaded.";
    } else if (keyAccepted) {
      keyStateEl.textContent = "Chat key accepted in this tab.";
    } else {
      keyStateEl.textContent = "Chat key loaded for this tab.";
    }
  }

  function updateControls() {
    sendButton.disabled = busy;
    loadKeyButton.disabled = busy;
    refreshButton.disabled = false;
  }

  function setNav(open) {
    navOpen = open;
    appEl.setAttribute("data-nav", open ? "open" : "closed");
    sidebarToggle.setAttribute("aria-expanded", open ? "true" : "false");
  }

  function focusKeyField() {
    // The key field lives in the sidebar, which is hidden below the mobile
    // breakpoint; reveal it before moving focus so the recovery is reachable.
    setNav(true);
    keyInput.focus();
  }

  function showEmptyConversation() {
    lastPromptEl.textContent = "";
    responseEl.textContent = "";
    exchangeEl.hidden = true;
    emptyStateEl.hidden = false;
    exchangeEl.removeAttribute("data-state");
  }

  function stopTimer() {
    if (requestTimer !== null) {
      clearTimeout(requestTimer);
      requestTimer = null;
    }
  }

  function invalidateRequest() {
    epoch += 1;
    busy = false;
    stopTimer();
    if (activeController !== null) {
      var controller = activeController;
      activeController = null;
      try {
        controller.abort();
      } catch (error) {
        // An already-finished request has nothing left to abort.
      }
    }
    updateControls();
  }

  function finishRequest() {
    busy = false;
    stopTimer();
    activeController = null;
    updateControls();
  }

  function setHealthUnknown() {
    modeEl.textContent = "unknown";
    readinessEl.textContent = "unknown";
    guardsEl.textContent = "unknown";
    guardsEl.removeAttribute("data-kind");
    topbarGuardsEl.textContent = "Guards unknown";
    topbarGuardsEl.removeAttribute("data-kind");
  }

  function validHealthPayload(data) {
    return (
      data !== null &&
      typeof data === "object" &&
      !Array.isArray(data) &&
      typeof data.mode === "string" &&
      data.mode.length > 0 &&
      typeof data.status === "string" &&
      (data.status === "ready" || data.status === "not_ready") &&
      typeof data.guards_active === "boolean"
    );
  }

  function setHealthLabels(data, httpStatus) {
    var mode = data.mode;
    var guards = data.guards_active;
    var ready = httpStatus === 200 && data.status === "ready";
    var guardsActive = guards === true && mode !== "test";
    modeEl.textContent = mode;
    readinessEl.textContent = ready ? "ready" : "not ready";
    guardsEl.textContent = guardsActive ? "active" : "inactive";
    if (guardsActive) {
      guardsEl.removeAttribute("data-kind");
      topbarGuardsEl.textContent = "Guards active";
      topbarGuardsEl.removeAttribute("data-kind");
    } else {
      guardsEl.setAttribute("data-kind", "inactive");
      topbarGuardsEl.textContent = "Guards inactive";
      topbarGuardsEl.setAttribute("data-kind", "inactive");
    }
    if (mode === "test") {
      banner.textContent = TEST_BANNER;
      banner.hidden = false;
    } else if (!guardsActive) {
      banner.textContent = NO_GUARD_BANNER;
      banner.hidden = false;
    } else {
      banner.textContent = "";
      banner.hidden = true;
    }
  }

  function stopHealthTimer() {
    if (healthTimer !== null) {
      clearTimeout(healthTimer);
      healthTimer = null;
    }
  }

  function refreshHealth() {
    healthEpoch += 1;
    var current = healthEpoch;
    if (healthController !== null) {
      var previous = healthController;
      healthController = null;
      try {
        previous.abort();
      } catch (error) {
        // An already-finished health probe has nothing left to abort.
      }
    }
    stopHealthTimer();
    var controller = new AbortController();
    healthController = controller;
    healthTimer = setTimeout(function () {
      healthTimer = null;
      try {
        controller.abort();
      } catch (error) {
        // The probe may already be complete.
      }
    }, HEALTH_TIMEOUT_MS);

    fetch("/health/ready", {
      method: "GET",
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      signal: controller.signal
    }).then(function (response) {
      return response.json().then(
        function (data) {
          return { parsed: true, status: response.status, data: data };
        },
        function () {
          return { parsed: false, status: response.status, data: null };
        }
      );
    }).then(function (result) {
      if (current !== healthEpoch) {
        return;
      }
      stopHealthTimer();
      healthController = null;
      if (!result.parsed || !validHealthPayload(result.data)) {
        // Malformed or failed status is unknown; keep any existing warning.
        setHealthUnknown();
        return;
      }
      setHealthLabels(result.data, result.status);
    }).catch(function () {
      if (current !== healthEpoch) {
        return;
      }
      stopHealthTimer();
      healthController = null;
      setHealthUnknown();
    });
  }

  function failureMessage(status) {
    if (status === 401) {
      return "Access denied. The chat key was cleared.";
    }
    if (status === 403) {
      return "The request was blocked by the active safety policy.";
    }
    if (status === 413) {
      return "The prompt exceeds the supported input limit.";
    }
    if (status === 429) {
      return "The gateway is busy. Try again shortly.";
    }
    if (status === 503) {
      return "The gateway is not ready or could not complete the request. Try again later.";
    }
    if (status === 400) {
      return "The gateway rejected the request.";
    }
    return "The gateway returned an error.";
  }

  function clearBadKey() {
    chatToken = "";
    keyAccepted = false;
    keyInput.value = "";
    setKeyState();
    focusKeyField();
  }

  function handleFailure(status) {
    if (status === 401) {
      clearBadKey();
    }
    exchangeEl.setAttribute("data-state", "error");
    setStatus(failureMessage(status), "error");
  }

  function sendPrompt() {
    if (busy) {
      return;
    }
    var prompt = promptInput.value.trim();
    if (!chatToken) {
      setStatus("Load a chat key first.", "error");
      focusKeyField();
      return;
    }
    if (!prompt) {
      setStatus("Enter a prompt before sending.", "error");
      promptInput.focus();
      return;
    }

    busy = true;
    updateControls();
    setStatus("Sending…", "info");
    lastPromptEl.textContent = prompt;
    responseEl.textContent = "";
    emptyStateEl.hidden = true;
    exchangeEl.hidden = false;
    exchangeEl.setAttribute("data-state", "pending");
    var requestEpoch = epoch;
    var timedOut = false;
    var controller = new AbortController();
    activeController = controller;
    requestTimer = setTimeout(function () {
      requestTimer = null;
      timedOut = true;
      try {
        controller.abort();
      } catch (error) {
        // The request may already be complete.
      }
    }, CHAT_TIMEOUT_MS);

    fetch("/v1/chat/completions", {
      method: "POST",
      headers: {
        "Authorization": "Bearer " + chatToken,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model: "pilot-local",
        messages: [{ role: "user", content: prompt }]
      }),
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      signal: controller.signal
    }).then(function (response) {
      if (requestEpoch !== epoch) {
        return null;
      }
      return response.json().then(
        function (data) {
          return { response: response, data: data, invalidJson: false };
        },
        function () {
          return { response: response, data: null, invalidJson: true };
        }
      );
    }).then(function (result) {
      if (requestEpoch !== epoch || result === null) {
        return;
      }
      if (!result.response.ok) {
        handleFailure(result.response.status);
        return;
      }
      var data = result.data;
      var choice = !result.invalidJson && data && Array.isArray(data.choices) ? data.choices[0] : null;
      if (
        !choice ||
        choice.finish_reason !== "stop" ||
        !choice.message ||
        typeof choice.message.content !== "string"
      ) {
        exchangeEl.setAttribute("data-state", "error");
        setStatus("The gateway returned an incomplete or unsupported response.", "error");
        return;
      }
      responseEl.textContent = choice.message.content;
      exchangeEl.setAttribute("data-state", "done");
      keyAccepted = true;
      setKeyState();
      setStatus("Response received.", "info");
    }).catch(function (error) {
      if (requestEpoch !== epoch) {
        return;
      }
      exchangeEl.setAttribute("data-state", "error");
      if (timedOut) {
        setStatus("The request timed out after 90 seconds. Try again or reset the prompt.", "error");
      } else if (error && error.name === "AbortError") {
        setStatus("Request cancelled.", "error");
      } else {
        setStatus("The gateway could not be reached.", "error");
      }
    }).then(function () {
      if (requestEpoch !== epoch) {
        return;
      }
      finishRequest();
    });
  }

  function loadKey() {
    if (busy) {
      return;
    }
    var candidate = keyInput.value.trim();
    if (!candidate) {
      setStatus("Enter a chat key before loading it.", "error");
      focusKeyField();
      return;
    }
    chatToken = candidate;
    keyAccepted = false;
    keyInput.value = "";
    setKeyState();
    setStatus("Chat key loaded for this tab.", "info");
    setNav(false);
    promptInput.focus();
  }

  function resetConversation(message) {
    invalidateRequest();
    promptInput.value = "";
    showEmptyConversation();
    setStatus(message, "info");
    promptInput.focus();
  }

  function forgetKey() {
    invalidateRequest();
    chatToken = "";
    keyAccepted = false;
    keyInput.value = "";
    promptInput.value = "";
    showEmptyConversation();
    setKeyState();
    setStatus("Chat key forgotten. Conversation cleared.", "info");
    focusKeyField();
  }

  function pagehide() {
    healthEpoch += 1;
    stopHealthTimer();
    if (healthController !== null) {
      var controller = healthController;
      healthController = null;
      try {
        controller.abort();
      } catch (error) {
        // The probe may already be complete.
      }
    }
    invalidateRequest();
    chatToken = "";
    keyAccepted = false;
    keyInput.value = "";
    promptInput.value = "";
    showEmptyConversation();
    setKeyState();
    setStatus("");
  }

  keyForm.addEventListener("submit", function (event) {
    event.preventDefault();
    loadKey();
  });
  forgetKeyButton.addEventListener("click", forgetKey);
  promptForm.addEventListener("submit", function (event) {
    event.preventDefault();
    sendPrompt();
  });
  promptInput.addEventListener("keydown", function (event) {
    if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
      event.preventDefault();
      sendPrompt();
    }
  });
  clearButton.addEventListener("click", function () {
    resetConversation("Conversation cleared.");
  });
  newChatButton.addEventListener("click", function () {
    setNav(false);
    resetConversation("Conversation cleared.");
  });
  sidebarToggle.addEventListener("click", function () {
    setNav(!navOpen);
  });
  refreshButton.addEventListener("click", refreshHealth);
  window.addEventListener("pagehide", pagehide);

  setNav(false);
  showEmptyConversation();
  setKeyState();
  updateControls();
  refreshHealth();
}());
"""


def _csp_hash(text: str) -> str:
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return "'sha256-" + base64.b64encode(digest).decode("ascii") + "'"


_MODE_BANNER_MARKER = "<!-- MODE_BANNER -->"
_MODE_VALUE_MARKER = "<!-- MODE_VALUE -->"


def demo_html(*, mode: str, guards_active: bool) -> str:
    """Return the static demo page with server-controlled mode and banner."""
    if mode == "test":
        banner = (
            '<div id="test-banner" class="banner" role="note">'
            "Test mode: model-based injection and output checks are inactive."
            "</div>"
        )
    elif not guards_active:
        banner = (
            '<div id="test-banner" class="banner" role="note">'
            "Guards are not active. Chat may be unavailable."
            "</div>"
        )
    else:
        banner = '<div id="test-banner" class="banner" role="note" hidden></div>'
    return DEMO_HTML.replace(_MODE_BANNER_MARKER, banner, 1).replace(
        _MODE_VALUE_MARKER, html.escape(mode, quote=True), 1
    )


DEMO_HTML = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<meta name="theme-color" content="#0c0c0c">
<title>Nasi Lemak gateway demo</title>
<style>{_DEMO_CSS}</style>
</head>
<body>
<div class="app" id="app" data-nav="closed">
<aside class="sidebar" id="sidebar" aria-label="Demo controls">
<div class="brand">
<svg class="brand-mark" width="22" height="22" viewBox="0 0 22 22" fill="none" aria-hidden="true" focusable="false">
<rect x="1.5" y="1.5" width="19" height="19" rx="5" stroke="currentColor" stroke-width="1.4"/>
<path d="M6.5 11h9M11 6.5v9" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>
</svg>
<div>
<h1>Nasi Lemak</h1>
<p class="brand-sub">Gateway demo</p>
</div>
</div>
<button id="new-chat" class="new-chat" type="button">
<svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true" focusable="false">
<path d="M8 3v10M3 8h10" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>
</svg>
<span>New chat</span>
</button>
<section class="side-section" aria-labelledby="connection-heading">
<h2 id="connection-heading">Connection</h2>
<form id="key-form" novalidate>
<label for="chat-key">Chat key</label>
<input id="chat-key" name="chat-key" type="password" autocomplete="off" spellcheck="false" autocapitalize="off" maxlength="4096">
<div class="key-row">
<button id="load-key" type="submit">Load key</button>
<button id="forget-key" class="ghost" type="button">Forget</button>
</div>
</form>
<p id="key-state" class="key-state" aria-live="polite">No key loaded.</p>
<p class="hint">The key stays in this tab's memory. It is not stored, put in the address bar, or written to the page.</p>
</section>
<nav class="side-nav" aria-label="Operator">
<a href="/admin">Operator audit view</a>
</nav>
<section class="side-section" aria-label="Gateway status">
<h2>Status</h2>
<div class="status-list">
<div class="status-row"><span class="label">Mode</span><strong id="mode-value">{_MODE_VALUE_MARKER}</strong></div>
<div class="status-row"><span class="label">Readiness</span><strong id="readiness-value">checking</strong></div>
<div class="status-row"><span class="label">LLM guards</span><strong id="guards-value">checking</strong></div>
</div>
<button id="refresh-status" class="link-button" type="button">Refresh status</button>
</section>
<p class="hint">The operator audit view uses a separate operator key and never receives this chat key.</p>
</aside>
<div class="main">
<header class="topbar">
<button id="sidebar-toggle" class="icon-button" type="button" aria-expanded="false" aria-controls="sidebar" aria-label="Toggle demo controls">
<svg width="18" height="18" viewBox="0 0 18 18" fill="none" aria-hidden="true" focusable="false">
<rect x="1.75" y="2.75" width="14.5" height="12.5" rx="2.5" stroke="currentColor" stroke-width="1.3"/>
<path d="M6.5 3v12" stroke="currentColor" stroke-width="1.3"/>
</svg>
</button>
<span class="topbar-title">Customer demo</span>
<span id="topbar-guards" class="topbar-status">Guards checking</span>
</header>
{_MODE_BANNER_MARKER}
<main class="conversation" id="conversation">
<div class="empty" id="empty-state">
<h2>Ask the gateway something</h2>
<p>Each prompt is sent independently; earlier turns are not included. Load a chat key in the sidebar, then write below. Answers appear here.</p>
</div>
<div class="exchange" id="exchange" hidden>
<article class="msg msg-user">
<p class="msg-head">You</p>
<p id="last-prompt" class="msg-body"></p>
</article>
<article class="msg msg-assistant">
<p class="msg-head">Gateway</p>
<div id="response" class="response" tabindex="0" aria-live="polite" aria-label="Gateway response"></div>
</article>
<p class="hint">Only this prompt is sent — earlier turns are not included.</p>
</div>
</main>
<footer class="composer-wrap">
<div class="composer-inner">
<p id="status" class="status" role="status" aria-live="polite"></p>
<form id="prompt-form" class="composer" novalidate>
<label class="sr-only" for="prompt">Your prompt</label>
<textarea id="prompt" name="prompt" rows="2" maxlength="3800" placeholder="Message the gateway…"></textarea>
<div class="composer-row">
<span class="composer-hint">Ctrl/Command + Enter sends.</span>
<button id="clear" class="ghost" type="button">Clear</button>
<button id="send" class="primary" type="submit">Send</button>
</div>
</form>
<p class="foot">Responses come from the configured model and may be inaccurate. Use synthetic examples only.</p>
</div>
</footer>
</div>
</div>
<script>{_DEMO_JS}</script>
</body>
</html>
"""


DEMO_SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "Content-Security-Policy": (
        "default-src 'none'; "
        f"script-src {_csp_hash(_DEMO_JS)}; "
        f"style-src {_csp_hash(_DEMO_CSS)}; "
        "connect-src 'self'; "
        "img-src 'none'; "
        "font-src 'none'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "form-action 'none'; "
        "frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}
