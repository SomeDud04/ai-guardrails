"""Static operator login/event-view shell.

The HTML contains no events, token or runtime configuration.  The operator token
is read from a password field, kept in a JavaScript variable only, and sent as an
``Authorization`` header to the same-origin protected API.  It is never put in a
URL, storage, cookie or page text.  Event values are always assigned through
``textContent``.

Inline CSS/JS is allowed by a hash-based Content-Security-Policy; there is no
remote resource, ``eval`` or inline event handler.
"""

from __future__ import annotations

import base64
import hashlib


_ADMIN_CSS = """
:root { color-scheme: light dark; font-family: system-ui, -apple-system, Segoe UI, sans-serif; }
* { box-sizing: border-box; }
body { margin: 0; background: Canvas; color: CanvasText; }
.wrap { max-width: 1180px; margin: 0 auto; padding: 1rem; }
h1 { font-size: 1.4rem; margin: 0 0 .35rem; }
h2 { font-size: 1.05rem; margin: 1.4rem 0 .5rem; }
p { line-height: 1.45; margin: .35rem 0; }
.panel { border: 1px solid color-mix(in srgb, CanvasText 28%, transparent); border-radius: .5rem; padding: 1rem; margin-top: 1rem; }
label { display: block; font-weight: 600; margin-bottom: .3rem; }
input, select, button { font: inherit; }
input, select { width: 100%; padding: .55rem .6rem; border: 1px solid color-mix(in srgb, CanvasText 40%, transparent); border-radius: .35rem; background: Field; color: FieldText; }
button { padding: .55rem .9rem; border: 1px solid color-mix(in srgb, CanvasText 40%, transparent); border-radius: .35rem; background: ButtonFace; color: ButtonText; cursor: pointer; }
button:disabled { cursor: not-allowed; opacity: .55; }
button:focus-visible, input:focus-visible, select:focus-visible { outline: 3px solid Highlight; outline-offset: 1px; }
.row { display: flex; flex-wrap: wrap; gap: .6rem; align-items: end; }
.row > div { flex: 1 1 12rem; }
.actions { display: flex; flex-wrap: wrap; gap: .6rem; margin-top: .8rem; }
.status { min-height: 1.5rem; margin-top: .8rem; }
.status[data-kind="error"] { color: #b00020; font-weight: 600; }
.status[data-kind="info"] { font-weight: 600; }
.meta { display: grid; grid-template-columns: max-content minmax(0, 1fr); gap: .25rem .8rem; margin: .6rem 0 0; }
.meta dt { font-weight: 600; }
.meta dd { margin: 0; overflow-wrap: anywhere; }
.table-wrap { overflow-x: auto; border: 1px solid color-mix(in srgb, CanvasText 24%, transparent); border-radius: .4rem; }
table { border-collapse: collapse; width: 100%; font-size: .9rem; }
caption { text-align: left; padding: .6rem; font-weight: 600; }
th, td { text-align: left; vertical-align: top; padding: .45rem .55rem; border-top: 1px solid color-mix(in srgb, CanvasText 20%, transparent); white-space: nowrap; }
td.wrap-cell { white-space: normal; overflow-wrap: anywhere; min-width: 12rem; }
tbody tr:nth-child(even) { background: color-mix(in srgb, CanvasText 4%, transparent); }
.foot { display: flex; flex-wrap: wrap; gap: .6rem; align-items: center; justify-content: space-between; margin-top: .7rem; }
.hint { font-size: .9rem; opacity: .85; }
[hidden] { display: none !important; }
@media (max-width: 640px) {
  .wrap { padding: .7rem; }
  .row > div { flex-basis: 100%; }
  .meta { grid-template-columns: 1fr; }
}
"""

_ADMIN_JS = """
"use strict";
(function () {
  var tokenInput = document.getElementById("operator-token");
  var loginForm = document.getElementById("login-form");
  var connectButton = document.getElementById("connect");
  var disconnectButton = document.getElementById("disconnect");
  var loginPanel = document.getElementById("login-panel");
  var viewPanel = document.getElementById("view-panel");
  var statusEl = document.getElementById("status");
  var eventsBody = document.getElementById("events-body");
  var pageInfo = document.getElementById("page-info");
  var policyVersion = document.getElementById("policy-version");
  var policyDigest = document.getElementById("policy-digest");
  var healthStatus = document.getElementById("health-status");
  var decisionFilter = document.getElementById("decision-filter");
  var eventTypeFilter = document.getElementById("event-type-filter");
  var requestIdFilter = document.getElementById("request-id-filter");
  var applyButton = document.getElementById("apply-filters");
  var exportButton = document.getElementById("export-csv");
  var previousButton = document.getElementById("previous-page");
  var nextButton = document.getElementById("next-page");
  var operatorToken = "";
  var cursorHistory = [];
  var currentCursor = null;
  var nextCursor = null;
  var busy = false;
  var sessionEpoch = 0;
  var activeController = null;

  function setStatus(text, kind) {
    statusEl.textContent = text || "";
    if (kind) {
      statusEl.setAttribute("data-kind", kind);
    } else {
      statusEl.removeAttribute("data-kind");
    }
  }

  function setMeta(policy, health) {
    var version = policy && typeof policy.version === "string" ? policy.version : "";
    var digest = policy && typeof policy.digest === "string" ? policy.digest : "";
    policyVersion.textContent = version || "unavailable";
    policyDigest.textContent = digest || "unavailable";
    healthStatus.textContent = health === "ready" ? "ready" : "not ready";
  }

  function clearTable() {
    while (eventsBody.firstChild) {
      eventsBody.removeChild(eventsBody.firstChild);
    }
    pageInfo.textContent = "";
  }

  function clearMeta() {
    policyVersion.textContent = "";
    policyDigest.textContent = "";
    healthStatus.textContent = "";
  }

  function formatTimestamp(value) {
    var seconds = Number(value);
    if (!isFinite(seconds)) {
      return "";
    }
    var date = new Date(seconds * 1000);
    if (isNaN(date.getTime())) {
      return "";
    }
    return date.toISOString();
  }

  function cell(row, value, wrap) {
    var td = document.createElement("td");
    td.textContent = value === null || value === undefined ? "" : String(value);
    if (wrap) {
      td.className = "wrap-cell";
    }
    row.appendChild(td);
  }

  function renderEvents(events) {
    clearTable();
    for (var i = 0; i < events.length; i += 1) {
      var event = events[i] || {};
      var row = document.createElement("tr");
      var decision = event.decision === null || event.decision === undefined ? "" : String(event.decision);
      cell(row, event.seq);
      cell(row, formatTimestamp(event.timestamp));
      cell(row, event.request_id, true);
      cell(row, event.event_type);
      cell(row, decision);
      cell(row, event.error_code);
      cell(row, event.policy_version);
      cell(row, event.policy_digest, true);
      cell(row, event.model);
      eventsBody.appendChild(row);
    }
    if (events.length === 0) {
      pageInfo.textContent = "No events match the current filters.";
    }
  }

  function updateNavigation() {
    previousButton.disabled = busy || cursorHistory.length === 0;
    nextButton.disabled = busy || nextCursor === null;
  }

  function updateControls() {
    updateNavigation();
    applyButton.disabled = busy;
    exportButton.disabled = busy;
    decisionFilter.disabled = busy;
    eventTypeFilter.disabled = busy;
    requestIdFilter.disabled = busy;
  }

  function readFilters() {
    return {
      decision: decisionFilter.value,
      eventType: eventTypeFilter.value,
      requestId: requestIdFilter.value.trim()
    };
  }

  function buildQuery(filters, cursor) {
    var params = new URLSearchParams();
    params.set("limit", "50");
    if (filters.decision) {
      params.set("decision", filters.decision);
    }
    if (filters.eventType) {
      params.set("event_type", filters.eventType);
    }
    if (filters.requestId) {
      params.set("request_id", filters.requestId);
    }
    if (cursor !== null) {
      params.set("after", String(cursor));
    }
    return params.toString();
  }

  function buildExportQuery(filters) {
    // An export is one complete snapshot, never the current page.  Limit and
    // cursor are deliberately omitted even when the view is on page two.
    var params = new URLSearchParams();
    if (filters.decision) {
      params.set("decision", filters.decision);
    }
    if (filters.eventType) {
      params.set("event_type", filters.eventType);
    }
    if (filters.requestId) {
      params.set("request_id", filters.requestId);
    }
    return params.toString();
  }

  function exportRowCount(response) {
    var raw = response.headers && typeof response.headers.get === "function"
      ? response.headers.get("X-Export-Row-Count")
      : null;
    if (raw === null || raw === "") {
      return null;
    }
    var count = Number(raw);
    if (!isFinite(count) || Math.floor(count) !== count || count < 0) {
      return null;
    }
    return count;
  }

  function saveExport(blob) {
    var url = URL.createObjectURL(blob);
    var anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "nasi-lemak-events-export.csv";
    anchor.rel = "noopener";
    document.body.appendChild(anchor);
    try {
      anchor.click();
    } finally {
      document.body.removeChild(anchor);
      URL.revokeObjectURL(url);
    }
  }

  function invalidateSession() {
    sessionEpoch += 1;
    busy = false;
    if (activeController !== null) {
      var controller = activeController;
      activeController = null;
      try {
        controller.abort();
      } catch (error) {
        // An already-finished request has nothing left to abort.
      }
    }
  }

  function clearViewData() {
    resetPaging();
    clearTable();
    clearMeta();
  }

  function loadPage() {
    if (!operatorToken || busy) {
      return;
    }
    busy = true;
    updateControls();
    setStatus("Loading events…", "info");
    var epoch = sessionEpoch;
    var query = buildQuery(readFilters(), currentCursor);
    var controller = new AbortController();
    activeController = controller;
    fetch("/admin/events?" + query, {
      method: "GET",
      headers: { "Authorization": "Bearer " + operatorToken },
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      signal: controller.signal
    }).then(function (response) {
      if (epoch !== sessionEpoch) {
        return null;
      }
      if (!response.ok) {
        resetPaging();
        clearTable();
        clearMeta();
        setStatus(response.status === 401 ? "Access denied. Check the operator token." : "Events are unavailable.", "error");
        return null;
      }
      return response.json().then(function (data) {
        if (epoch !== sessionEpoch) {
          return null;
        }
        return data;
      });
    }).then(function (data) {
      if (epoch !== sessionEpoch || !data) {
        return;
      }
      var events = Array.isArray(data.events) ? data.events : [];
      renderEvents(events);
      setMeta(data.policy, data.health);
      nextCursor = typeof data.next_cursor === "number" ? data.next_cursor : null;
      var count = events.length;
      if (count === 0) {
        pageInfo.textContent = "No events match the current filters.";
        setStatus("No events loaded.", "info");
      } else {
        pageInfo.textContent = count + " event" + (count === 1 ? "" : "s") + " shown; more available: " + (data.has_more === true ? "yes" : "no") + ".";
        setStatus("Events loaded.", "info");
      }
    }).catch(function (error) {
      if (epoch !== sessionEpoch) {
        return;
      }
      resetPaging();
      clearTable();
      clearMeta();
      setStatus("Events are unavailable.", "error");
    }).then(function () {
      if (epoch !== sessionEpoch) {
        return;
      }
      busy = false;
      if (activeController === controller) {
        activeController = null;
      }
      updateControls();
    });
  }

  function exportCsv() {
    if (!operatorToken || busy) {
      return;
    }
    busy = true;
    updateControls();
    setStatus("Preparing export…", "info");
    var epoch = sessionEpoch;
    var query = buildExportQuery(readFilters());
    var controller = new AbortController();
    activeController = controller;
    fetch("/admin/export.csv" + (query ? "?" + query : ""), {
      method: "GET",
      headers: { "Authorization": "Bearer " + operatorToken },
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      signal: controller.signal
    }).then(function (response) {
      if (epoch !== sessionEpoch) {
        return null;
      }
      if (!response.ok) {
        if (response.status === 413) {
          setStatus("Export is too large. Narrow the filters and try again.", "error");
        } else if (response.status === 401) {
          setStatus("Access denied. Check the operator token.", "error");
        } else if (response.status === 503) {
          setStatus("Export is unavailable.", "error");
        } else {
          setStatus("Export is unavailable.", "error");
        }
        return null;
      }
      return response.blob().then(function (blob) {
        if (epoch !== sessionEpoch) {
          return null;
        }
        return { blob: blob, rowCount: exportRowCount(response) };
      });
    }).then(function (result) {
      if (epoch !== sessionEpoch || !result) {
        return;
      }
      saveExport(result.blob);
      if (result.rowCount === null) {
        setStatus("Export prepared.", "info");
      } else {
        setStatus(
          "Export prepared: " + result.rowCount + " row" +
            (result.rowCount === 1 ? "" : "s") + ". Download requested.",
          "info"
        );
      }
    }).catch(function (error) {
      if (epoch !== sessionEpoch) {
        return;
      }
      setStatus("Export is unavailable.", "error");
    }).then(function () {
      if (epoch !== sessionEpoch) {
        return;
      }
      busy = false;
      if (activeController === controller) {
        activeController = null;
      }
      updateControls();
    });
  }

  function resetPaging() {
    cursorHistory = [];
    currentCursor = null;
    nextCursor = null;
  }

  function connect() {
    var candidate = tokenInput.value.trim();
    if (!candidate) {
      setStatus("Enter the operator token.", "error");
      return;
    }
    operatorToken = candidate;
    tokenInput.value = "";
    invalidateSession();
    resetPaging();
    loginPanel.hidden = true;
    viewPanel.hidden = false;
    disconnectButton.hidden = false;
    loadPage();
  }

  function disconnect() {
    invalidateSession();
    operatorToken = "";
    tokenInput.value = "";
    clearViewData();
    setStatus("Disconnected.", "info");
    viewPanel.hidden = true;
    loginPanel.hidden = false;
    disconnectButton.hidden = true;
    updateControls();
    tokenInput.focus();
  }

  connectButton.addEventListener("click", connect);
  loginForm.addEventListener("submit", function (event) {
    event.preventDefault();
    connect();
  });
  tokenInput.addEventListener("keydown", function (event) {
    if (event.key === "Enter") {
      event.preventDefault();
      connect();
    }
  });
  disconnectButton.addEventListener("click", disconnect);
  applyButton.addEventListener("click", function () {
    if (busy) {
      return;
    }
    resetPaging();
    loadPage();
  });
  exportButton.addEventListener("click", exportCsv);
  previousButton.addEventListener("click", function () {
    if (busy || cursorHistory.length === 0) {
      return;
    }
    currentCursor = cursorHistory.pop();
    loadPage();
  });
  nextButton.addEventListener("click", function () {
    if (busy || nextCursor === null) {
      return;
    }
    cursorHistory.push(currentCursor);
    currentCursor = nextCursor;
    loadPage();
  });
  window.addEventListener("pagehide", function () {
    invalidateSession();
    operatorToken = "";
    tokenInput.value = "";
    clearViewData();
    setStatus("");
    viewPanel.hidden = true;
    loginPanel.hidden = false;
    disconnectButton.hidden = true;
    updateControls();
  });
  updateControls();
}());
"""


def _csp_hash(text: str) -> str:
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return "'sha256-" + base64.b64encode(digest).decode("ascii") + "'"


_MODE_BANNER_MARKER = "<!-- MODE_BANNER -->"


def admin_html(*, mode: str, guards_active: bool) -> str:
    """Return the static operator HTML with a server-controlled mode banner.

    The banner is plain body text and introduces no new inline script or style,
    so the existing hash-based CSP is unchanged.
    """
    if mode == "test":
        banner = (
            '<p class="status" data-kind="error">'
            "Test mode: LLM guards are inactive. This runtime is not protected by native guard classifiers."
            "</p>"
        )
    elif not guards_active:
        banner = (
            '<p class="status" data-kind="error">'
            "Guards are not active. Chat is unavailable until guard configuration is valid."
            "</p>"
        )
    else:
        banner = ""
    return ADMIN_HTML.replace(_MODE_BANNER_MARKER, banner, 1)


ADMIN_HTML = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Nasi Lemak operator events</title>
<style>{_ADMIN_CSS}</style>
</head>
<body>
<main class="wrap">
<h1>Nasi Lemak operator events</h1>
{_MODE_BANNER_MARKER}
<p>Read-only audit events for the active application. This page contains no event data until you authenticate.</p>
<p class="hint">The operator token stays in this tab's JavaScript memory. It is not stored, put in the address bar, or kept in a cookie.</p>

<section id="login-panel" class="panel" aria-labelledby="login-heading">
<h2 id="login-heading">Connect</h2>
<form id="login-form" novalidate>
<label for="operator-token">Operator token</label>
<input id="operator-token" name="operator-token" type="password" autocomplete="off" spellcheck="false" autocapitalize="off" required>
<div class="actions">
<button id="connect" type="button">Connect</button>
</div>
</form>
</section>

<section id="view-panel" class="panel" aria-labelledby="events-heading" hidden>
<div class="actions">
<h2 id="events-heading">Events</h2>
</div>
<dl class="meta">
<dt>Active policy version</dt><dd id="policy-version"></dd>
<dt>Active policy digest</dt><dd id="policy-digest"></dd>
<dt>Health</dt><dd id="health-status"></dd>
</dl>
<div class="row">
<div>
<label for="decision-filter">Decision</label>
<select id="decision-filter">
<option value="">Any decision</option>
<option value="pending">pending</option>
<option value="allowed">allowed</option>
<option value="blocked">blocked</option>
<option value="failed">failed</option>
<option value="interrupted">interrupted</option>
</select>
</div>
<div>
<label for="event-type-filter">Event type</label>
<select id="event-type-filter">
<option value="">Any event type</option>
<option value="request_started">request_started</option>
<option value="request_completed">request_completed</option>
<option value="request_failed">request_failed</option>
<option value="request_blocked">request_blocked</option>
<option value="request_recovered">request_recovered</option>
</select>
</div>
<div>
<label for="request-id-filter">Request ID</label>
<input id="request-id-filter" type="text" maxlength="128" autocomplete="off" spellcheck="false" placeholder="req_…">
</div>
<div>
<button id="apply-filters" type="button">Apply filters</button>
</div>
</div>
<div class="actions">
<button id="export-csv" type="button">Export matching events</button>
<button id="disconnect" type="button">Disconnect</button>
</div>
<div class="table-wrap">
<table>
<caption>Audit events, oldest first. A request_started row shows the pending decision recorded by that start event; its final outcome may appear in a later event or on another page.</caption>
<thead>
<tr>
<th scope="col">Seq</th>
<th scope="col">Time (UTC)</th>
<th scope="col">Request ID</th>
<th scope="col">Event</th>
<th scope="col">Decision</th>
<th scope="col">Error code</th>
<th scope="col">Policy version</th>
<th scope="col">Policy digest</th>
<th scope="col">Model</th>
</tr>
</thead>
<tbody id="events-body"></tbody>
</table>
</div>
<div class="foot">
<p id="page-info" class="hint" aria-live="polite"></p>
<div class="actions">
<button id="previous-page" type="button" disabled>Previous</button>
<button id="next-page" type="button" disabled>Next</button>
</div>
</div>
</section>

<p id="status" class="status" role="status" aria-live="polite"></p>
</main>
<script>{_ADMIN_JS}</script>
</body>
</html>
"""


ADMIN_SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "Content-Security-Policy": (
        "default-src 'none'; "
        f"script-src {_csp_hash(_ADMIN_JS)}; "
        f"style-src {_csp_hash(_ADMIN_CSS)}; "
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
