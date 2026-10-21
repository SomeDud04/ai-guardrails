"""Static customer demo shell for the existing gateway.

The page is a thin same-origin client for ``POST /v1/chat/completions``.  The
chat key is typed by the operator, kept in a JavaScript variable only, and sent
as an ``Authorization`` header.  It is never put in a URL, storage, cookie,
console output or page text.  Prompt, response and error text are always
assigned with ``textContent``.

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
  color-scheme: light;
  --teal: #0f3d3e;
  --teal-soft: #1d5a58;
  --offwhite: #faf6ec;
  --paper: #fffdf7;
  --gold: #b98a2f;
  --ink: #1d2a2a;
  --muted: #556564;
  --line: #d9d2c0;
  --danger: #8c2f24;
  font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--offwhite);
  color: var(--ink);
  min-height: 100vh;
}
.wrap { max-width: 1180px; margin: 0 auto; padding: 1.25rem; }
.masthead { display: flex; flex-wrap: wrap; gap: 1rem; justify-content: space-between; align-items: flex-start; }
.eyebrow { margin: 0; color: var(--gold); font-size: .78rem; font-weight: 700; letter-spacing: .12em; text-transform: uppercase; }
h1 { margin: .15rem 0 .4rem; color: var(--teal); font-size: clamp(1.6rem, 3vw, 2.15rem); letter-spacing: -.01em; }
.lede { margin: 0; max-width: 46rem; color: var(--muted); line-height: 1.5; }
.audit-link { color: var(--teal); font-weight: 600; text-decoration-thickness: 2px; text-underline-offset: .2em; white-space: nowrap; }
a { color: var(--teal); }
.warning {
  margin: 1rem 0 0;
  padding: .75rem .9rem;
  border-left: 5px solid var(--danger);
  background: #f8e9e3;
  color: #5d1f18;
  font-weight: 600;
  line-height: 1.45;
}
.status-strip {
  display: flex;
  flex-wrap: wrap;
  gap: .55rem;
  align-items: center;
  margin-top: 1rem;
  padding: .65rem .75rem;
  border: 1px solid var(--line);
  border-radius: .55rem;
  background: var(--paper);
}
.chip { display: flex; gap: .4rem; align-items: baseline; padding: .2rem .55rem; border-right: 1px solid var(--line); }
.chip:last-of-type { border-right: 0; }
.chip .label { color: var(--muted); font-size: .78rem; font-weight: 700; letter-spacing: .06em; text-transform: uppercase; }
.chip strong { color: var(--teal); font-size: .95rem; }
.layout { display: grid; grid-template-columns: minmax(15rem, 21rem) minmax(0, 1fr); gap: 1rem; margin-top: 1rem; align-items: start; }
.panel { border: 1px solid var(--line); border-radius: .65rem; background: var(--paper); padding: 1rem; }
.config { position: sticky; top: 1rem; }
h2 { margin: 0 0 .55rem; color: var(--teal); font-size: 1.05rem; }
h2 + p { margin-top: 0; }
label { display: block; margin: .75rem 0 .3rem; font-weight: 700; font-size: .92rem; }
input, textarea, button { font: inherit; }
input, textarea {
  width: 100%;
  padding: .6rem .65rem;
  border: 1px solid #a9a391;
  border-radius: .4rem;
  background: #ffffff;
  color: var(--ink);
}
textarea { min-height: 10.5rem; resize: vertical; line-height: 1.5; }
button {
  padding: .55rem .9rem;
  border: 1px solid var(--teal);
  border-radius: .4rem;
  background: var(--teal);
  color: #fffdf7;
  font-weight: 650;
  cursor: pointer;
}
button.secondary { background: transparent; color: var(--teal); }
button.quiet { margin-left: auto; background: transparent; color: var(--teal); border-color: var(--line); padding: .35rem .65rem; font-size: .85rem; }
button:disabled { cursor: not-allowed; opacity: .55; }
button:focus-visible, input:focus-visible, textarea:focus-visible, pre:focus-visible, a:focus-visible {
  outline: 3px solid var(--gold);
  outline-offset: 2px;
}
.button-row { display: flex; flex-wrap: wrap; gap: .5rem; margin-top: .75rem; }
.key-state { margin: .7rem 0 0; font-weight: 650; color: var(--teal-soft); }
.hint { margin: .55rem 0 0; color: var(--muted); font-size: .86rem; line-height: 1.45; }
code { background: #efe9d9; border-radius: .25rem; padding: .05rem .3rem; }
.workspace h2 { margin-top: .2rem; }
.response {
  min-height: 12rem;
  max-height: 26rem;
  overflow: auto;
  margin: 0;
  padding: .85rem;
  border: 1px solid var(--line);
  border-radius: .5rem;
  background: #ffffff;
  color: var(--ink);
  font: inherit;
  line-height: 1.55;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
.response:empty::before { content: "The response will appear here."; color: var(--muted); font-style: italic; }
.status { min-height: 1.6rem; margin: .9rem 0 0; line-height: 1.45; }
.status[data-kind="error"] { color: var(--danger); font-weight: 650; }
.status[data-kind="info"] { color: var(--teal-soft); font-weight: 600; }
.foot { margin-top: 1.1rem; color: var(--muted); font-size: .84rem; line-height: 1.45; }
[hidden] { display: none !important; }
@media (max-width: 760px) {
  .wrap { padding: .8rem; }
  .layout { grid-template-columns: 1fr; }
  .config { position: static; }
  .chip { border-right: 0; }
}
"""


_DEMO_JS = """
"use strict";
(function () {
  var keyInput = document.getElementById("chat-key");
  var keyForm = document.getElementById("key-form");
  var loadKeyButton = document.getElementById("load-key");
  var forgetKeyButton = document.getElementById("forget-key");
  var promptForm = document.getElementById("prompt-form");
  var promptInput = document.getElementById("prompt");
  var sendButton = document.getElementById("send");
  var clearButton = document.getElementById("clear");
  var responseEl = document.getElementById("response");
  var statusEl = document.getElementById("status");
  var keyStateEl = document.getElementById("key-state");
  var modeEl = document.getElementById("mode-value");
  var readinessEl = document.getElementById("readiness-value");
  var guardsEl = document.getElementById("guards-value");
  var banner = document.getElementById("test-banner");
  var refreshButton = document.getElementById("refresh-status");
  var chatToken = "";
  var keyAccepted = false;
  var busy = false;
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
    keyInput.focus();
  }

  function handleFailure(status) {
    if (status === 401) {
      clearBadKey();
    }
    setStatus(failureMessage(status), "error");
  }

  function sendPrompt() {
    if (busy) {
      return;
    }
    var prompt = promptInput.value.trim();
    if (!chatToken) {
      setStatus("Load a chat key first.", "error");
      keyInput.focus();
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
    responseEl.textContent = "";
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
        setStatus("The gateway returned an incomplete or unsupported response.", "error");
        return;
      }
      responseEl.textContent = choice.message.content;
      keyAccepted = true;
      setKeyState();
      setStatus("Response received.", "info");
    }).catch(function (error) {
      if (requestEpoch !== epoch) {
        return;
      }
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
      keyInput.focus();
      return;
    }
    chatToken = candidate;
    keyAccepted = false;
    keyInput.value = "";
    setKeyState();
    setStatus("Chat key loaded for this tab.", "info");
    promptInput.focus();
  }

  function forgetKey() {
    invalidateRequest();
    chatToken = "";
    keyAccepted = false;
    keyInput.value = "";
    promptInput.value = "";
    responseEl.textContent = "";
    setKeyState();
    setStatus("Chat key forgotten. Prompt and response cleared.", "info");
    keyInput.focus();
  }

  function clearConversation() {
    invalidateRequest();
    promptInput.value = "";
    responseEl.textContent = "";
    setStatus("Prompt and response cleared.", "info");
    promptInput.focus();
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
    responseEl.textContent = "";
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
  clearButton.addEventListener("click", clearConversation);
  refreshButton.addEventListener("click", refreshHealth);
  window.addEventListener("pagehide", pagehide);

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
            '<p id="test-banner" class="warning" role="note">'
            "Test mode: model-based injection and output checks are inactive."
            "</p>"
        )
    elif not guards_active:
        banner = (
            '<p id="test-banner" class="warning" role="note">'
            "Guards are not active. Chat may be unavailable."
            "</p>"
        )
    else:
        banner = '<p id="test-banner" class="warning" role="note" hidden></p>'
    return DEMO_HTML.replace(_MODE_BANNER_MARKER, banner, 1).replace(
        _MODE_VALUE_MARKER, html.escape(mode, quote=True), 1
    )


DEMO_HTML = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Nasi Lemak gateway demo</title>
<style>{_DEMO_CSS}</style>
</head>
<body>
<main class="wrap">
<header class="masthead">
<div>
<p class="eyebrow">Project Nasi Lemak</p>
<h1>Gateway demo</h1>
<p class="lede">Try a prompt, inspect the response, and review policy decisions in the audit view.</p>
</div>
<a class="audit-link" href="/admin">Operator audit view</a>
</header>
{_MODE_BANNER_MARKER}
<section class="status-strip" aria-label="Gateway status">
<div class="chip"><span class="label">Mode</span><strong id="mode-value">{_MODE_VALUE_MARKER}</strong></div>
<div class="chip"><span class="label">Readiness</span><strong id="readiness-value">checking</strong></div>
<div class="chip"><span class="label">LLM guards</span><strong id="guards-value">checking</strong></div>
<button id="refresh-status" class="quiet" type="button">Refresh status</button>
</section>
<div class="layout">
<aside class="panel config" aria-labelledby="connection-heading">
<h2 id="connection-heading">Connection</h2>
<form id="key-form" novalidate>
<label for="chat-key">Chat key</label>
<input id="chat-key" name="chat-key" type="password" autocomplete="off" spellcheck="false" autocapitalize="off" maxlength="4096">
<div class="button-row">
<button id="load-key" type="submit">Load key</button>
<button id="forget-key" class="secondary" type="button">Forget key</button>
</div>
</form>
<p id="key-state" class="key-state" aria-live="polite">No key loaded.</p>
<p class="hint">The key stays in this tab's memory. It is not stored, put in the address bar, or written to the page.</p>
<p class="hint">The <a href="/admin">operator audit view</a> uses a separate operator key and never receives this chat key.</p>
</aside>
<section class="panel workspace" aria-labelledby="prompt-heading">
<h2 id="prompt-heading">Prompt</h2>
<form id="prompt-form" novalidate>
<label for="prompt">Your prompt</label>
<textarea id="prompt" name="prompt" rows="7" maxlength="3800" placeholder="Enter a synthetic customer-demo prompt."></textarea>
<p class="hint">Keyboard: Ctrl/Command + Enter sends.</p>
<div class="button-row">
<button id="send" type="submit">Send prompt</button>
<button id="clear" class="secondary" type="button">Clear</button>
</div>
</form>
<h2>Response</h2>
<pre id="response" class="response" tabindex="0" aria-live="polite" aria-label="Gateway response"></pre>
</section>
</div>
<p id="status" class="status" role="status" aria-live="polite"></p>
<p class="foot">Responses come from the configured model and may be inaccurate. Use synthetic examples only.</p>
</main>
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
