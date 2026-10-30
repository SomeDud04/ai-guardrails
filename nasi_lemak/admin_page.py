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


_ADMIN_CSS = """:root {
  color-scheme: dark;
  --bg: #0b0b0b;
  --panel: #0f0f0e;
  --surface: #171716;
  --surface-raised: #1e1e1c;
  --surface-strong: #252523;
  --line: #2a2a27;
  --line-strong: #3b3b36;
  --text: #eeeeeb;
  --text-soft: #c9c9c2;
  --muted: #9f9f97;
  --muted-dim: #7c7c74;
  --amber: #e6b15c;
  --amber-soft: #241c0f;
  --amber-line: #584424;
  --green: #a9dfb5;
  --green-soft: #122015;
  --green-line: #2f5437;
  --danger: #ff9f92;
  --danger-soft: #241312;
  --focus: #e8e8e0;
  --radius: 10px;
  --radius-lg: 14px;
  font-family: "Segoe UI", system-ui, -apple-system, "Helvetica Neue", Arial, sans-serif;
  font-size: 16px;
}
* { box-sizing: border-box; }
html, body { min-height: 100%; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  line-height: 1.55;
  -webkit-font-smoothing: antialiased;
  text-rendering: optimizeLegibility;
}
::selection { background: #3d3d34; color: #ffffff; }
* { scrollbar-color: #3d3d38 transparent; scrollbar-width: thin; }
h1, h2, h3, p, dl, dd { margin-top: 0; }
a { color: var(--text); text-decoration-color: var(--line-strong); text-underline-offset: .18em; }
a:hover { text-decoration-color: var(--text); }
button {
  font: inherit;
  color: var(--text);
  background: transparent;
  border: 1px solid var(--line-strong);
  border-radius: 8px;
  padding: .48rem .8rem;
  min-height: 36px;
  cursor: pointer;
  transition: background-color .16s ease, border-color .16s ease, color .16s ease;
}
button:hover:not(:disabled) { background: var(--surface-raised); border-color: #4f4f48; }
button:disabled { cursor: not-allowed; opacity: .45; }
button.primary {
  background: var(--text);
  color: #121210;
  border-color: var(--text);
  font-weight: 650;
}
button.primary:hover:not(:disabled) { background: #ffffff; border-color: #ffffff; }
button.ghost { color: var(--muted); border-color: transparent; }
button.ghost:hover:not(:disabled) { color: var(--text); border-color: var(--line-strong); }
input, select { font: inherit; color: var(--text); }
input, select {
  width: 100%;
  padding: .5rem .6rem;
  border: 1px solid var(--line-strong);
  border-radius: 8px;
  background: var(--surface);
}
input::placeholder { color: #8f8f87; }
input:focus-visible, select:focus-visible, button:focus-visible, a:focus-visible, summary:focus-visible, [tabindex]:focus-visible {
  outline: 2px solid var(--focus);
  outline-offset: 2px;
}
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
  grid-template-columns: 262px minmax(0, 1fr);
  min-height: 100dvh;
}
.sidebar {
  position: sticky;
  top: 0;
  display: flex;
  flex-direction: column;
  gap: 1rem;
  height: 100dvh;
  min-height: 0;
  padding: 1.1rem .95rem;
  overflow-y: auto;
  background: var(--panel);
  border-right: 1px solid var(--line);
}
.brand { display: flex; align-items: center; gap: .65rem; padding: .1rem .15rem .2rem; }
.brand-mark { flex: 0 0 auto; color: var(--text); }
.brand h1 { margin: 0; font-size: 1rem; font-weight: 650; letter-spacing: -.015em; }
.brand-sub { margin: .05rem 0 0; color: var(--muted); font-size: .76rem; }
.side-nav { display: grid; gap: 2px; }
.side-nav a {
  display: flex;
  align-items: center;
  gap: .55rem;
  padding: .48rem .55rem;
  border: 1px solid transparent;
  border-radius: 8px;
  color: var(--muted);
  font-size: .86rem;
  text-decoration: none;
}
.side-nav a:hover { background: var(--surface); color: var(--text); }
.side-nav a[aria-current="page"] {
  background: var(--surface-raised);
  border-color: var(--line);
  color: var(--text);
  font-weight: 550;
}
.side-nav .nav-mark {
  width: 5px;
  height: 5px;
  border-radius: 50%;
  background: var(--muted-dim);
}
.side-nav a[aria-current="page"] .nav-mark { background: var(--amber); }
.side-section { border-top: 1px solid var(--line); padding-top: .9rem; }
.side-section h2 {
  margin: 0 0 .5rem;
  color: var(--muted);
  font-size: .69rem;
  font-weight: 650;
  letter-spacing: .09em;
  text-transform: uppercase;
}
.hint { margin: .5rem 0 0; color: var(--muted); font-size: .76rem; line-height: 1.55; }
.side-state {
  margin: .65rem 0 0;
  padding: .5rem .55rem;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--surface);
  color: var(--text-soft);
  font-size: .78rem;
}
.disclosure { margin-top: .7rem; border-top: 1px solid var(--line); padding-top: .65rem; }
.disclosure summary {
  color: var(--text-soft);
  font-size: .79rem;
  font-weight: 550;
  cursor: pointer;
}
.disclosure summary:hover { color: var(--text); }
.disclosure p { margin: .45rem 0 0; color: var(--muted); font-size: .76rem; line-height: 1.55; }
.sidebar > .hint { margin-top: auto; padding-top: .8rem; border-top: 1px solid var(--line); }
.main { display: flex; flex-direction: column; min-width: 0; min-height: 100dvh; background: var(--bg); }
.topbar {
  position: sticky;
  top: 0;
  z-index: 10;
  display: flex;
  align-items: center;
  gap: .7rem;
  min-height: 62px;
  padding: .6rem 1.35rem;
  border-bottom: 1px solid var(--line);
  background: var(--bg);
}
.title-group { display: flex; flex-direction: column; min-width: 0; }
.topbar-title { font-size: .88rem; font-weight: 600; letter-spacing: -.01em; line-height: 1.3; }
.topbar-sub { color: var(--muted); font-size: .74rem; line-height: 1.35; }
.topbar-tag {
  margin-left: auto;
  padding: .24rem .55rem;
  border: 1px solid var(--line-strong);
  border-radius: 999px;
  color: var(--muted);
  font-size: .73rem;
  font-weight: 550;
  white-space: nowrap;
}
.notice {
  margin: .9rem 1.35rem 0;
  padding: .72rem .9rem;
  border: 1px solid var(--amber-line);
  border-radius: var(--radius);
  background: var(--amber-soft);
  color: #f0c67f;
  font-size: .82rem;
  line-height: 1.55;
}
.notice strong { color: #ffd9a0; font-weight: 650; }
.content {
  width: 100%;
  max-width: 1340px;
  flex: 1 1 auto;
  margin: 0 auto;
  padding: 1.6rem 1.4rem 3rem;
}
.status { min-height: 1.3rem; margin: 0 0 1rem; color: var(--muted); font-size: .82rem; line-height: 1.45; }
.status[data-kind="error"] { color: var(--danger); font-weight: 550; }
.status[data-kind="info"] { color: var(--muted); }
.login-shell { max-width: 500px; margin: min(11vh, 5rem) auto 0; }
.login-panel {
  padding: 1.45rem;
  border: 1px solid var(--line);
  border-radius: var(--radius-lg);
  background: var(--panel);
}
.login-panel h1 { margin: 0 0 .45rem; font-size: 1.5rem; font-weight: 600; letter-spacing: -.02em; line-height: 1.2; }
.lead { max-width: 64ch; margin: 0; color: var(--muted); line-height: 1.62; }
.form-field { margin-top: 1.15rem; }
.form-field label { display: block; margin-bottom: .35rem; color: var(--text-soft); font-size: .81rem; font-weight: 550; }
.actions { display: flex; flex-wrap: wrap; gap: .5rem; align-items: center; margin-top: .9rem; }
.view-head {
  display: flex;
  flex-wrap: wrap;
  align-items: flex-end;
  justify-content: space-between;
  gap: .9rem;
  margin-bottom: 1rem;
}
.view-head h1 { margin: 0 0 .3rem; font-size: 1.5rem; font-weight: 600; letter-spacing: -.02em; line-height: 1.2; }
.action-row { display: flex; flex-wrap: wrap; gap: .5rem; }
.meta-block {
  margin-bottom: 1rem;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--panel);
}
.meta-block summary {
  padding: .62rem .8rem;
  color: var(--text-soft);
  font-size: .81rem;
  font-weight: 550;
  cursor: pointer;
}
.meta-block[open] summary { border-bottom: 1px solid var(--line); }
.meta {
  display: grid;
  grid-template-columns: max-content minmax(0, 1fr);
  gap: .35rem .9rem;
  margin: 0;
  padding: .8rem;
}
.meta dt { color: var(--muted); font-size: .76rem; font-weight: 550; }
.meta dd { margin: 0; overflow-wrap: anywhere; font-size: .78rem; color: var(--text-soft); }
.toolbar {
  display: grid;
  grid-template-columns: 170px 190px minmax(0, 1fr) auto;
  gap: .6rem;
  align-items: end;
  margin-bottom: .9rem;
  padding: .8rem;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--panel);
}
.field label { display: block; margin-bottom: .3rem; color: var(--muted); font-size: .73rem; font-weight: 550; }
.field select, .field input { font-size: .82rem; }
.table-tools {
  display: flex;
  justify-content: flex-end;
  margin-bottom: .5rem;
}
.table-tools button { font-size: .8rem; }
.table-wrap {
  overflow-x: auto;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--surface);
}
table {
  width: 100%;
  min-width: 0;
  border-collapse: separate;
  border-spacing: 0;
  font-size: .8rem;
}
caption {
  padding: .7rem .8rem;
  border-bottom: 1px solid var(--line);
  color: var(--muted);
  font-size: .76rem;
  line-height: 1.5;
  text-align: left;
}
th, td {
  padding: .52rem .65rem;
  border-bottom: 1px solid var(--line);
  text-align: left;
  vertical-align: top;
}
thead th {
  position: sticky;
  top: 0;
  z-index: 1;
  background: var(--surface-raised);
  color: var(--muted);
  font-size: .68rem;
  font-weight: 650;
  letter-spacing: .07em;
  text-transform: uppercase;
  white-space: nowrap;
}
tbody tr:last-child td { border-bottom: 0; }
tbody tr:hover td { background: #1a1a18; }
td { color: var(--text-soft); white-space: nowrap; }
td.wrap-cell { min-width: 12rem; white-space: normal; overflow-wrap: anywhere; }
td.dense { color: var(--muted); font-size: .75rem; }
td.mono { font-family: ui-monospace, "Cascadia Mono", Consolas, monospace; font-size: .74rem; }
.table-wrap[data-technical="off"] .col-technical { display: none; }
.table-wrap[data-technical="on"] table { min-width: 960px; }
.badge {
  display: inline-block;
  padding: .12rem .45rem;
  border: 1px solid var(--line-strong);
  border-radius: 999px;
  font-size: .7rem;
  font-weight: 600;
  line-height: 1.5;
  color: var(--muted);
}
.badge[data-decision="allowed"] { color: var(--green); border-color: var(--green-line); background: var(--green-soft); }
.badge[data-decision="blocked"] { color: var(--danger); border-color: #64322c; background: var(--danger-soft); }
.badge[data-decision="failed"], .badge[data-decision="interrupted"] { color: #e0c58e; border-color: var(--amber-line); background: var(--amber-soft); }
.badge[data-decision="pending"] { color: var(--amber); border-color: var(--amber-line); background: var(--amber-soft); }
.events-state {
  margin-top: 1rem;
  padding: 1.2rem;
  border: 1px dashed var(--line-strong);
  border-radius: var(--radius);
  background: var(--panel);
}
.events-state h2 { margin: 0 0 .35rem; font-size: 1rem; font-weight: 600; letter-spacing: -.01em; }
.events-state p { margin: 0; color: var(--muted); font-size: .83rem; line-height: 1.6; }
.events-state[data-kind="error"] { border-color: #64322c; }
.events-state[data-kind="error"] h2 { color: var(--danger); }
.events-state[data-kind="loading"] h2 { color: var(--amber); }
.page-foot {
  display: flex;
  flex-wrap: wrap;
  gap: .7rem;
  align-items: center;
  justify-content: space-between;
  margin-top: .8rem;
}
.page-info { margin: 0; color: var(--muted); font-size: .78rem; }
.guide { margin-top: 1rem; border-top: 1px solid var(--line); padding-top: .7rem; }
.guide summary { color: var(--text-soft); font-size: .79rem; font-weight: 550; cursor: pointer; }
.guide p { max-width: 80ch; margin: .45rem 0 0; color: var(--muted); font-size: .76rem; line-height: 1.55; }
[hidden] { display: none !important; }
@media (max-width: 900px) {
  .toolbar { grid-template-columns: 1fr 1fr; }
  .toolbar .field:last-of-type { grid-column: 1 / -1; }
  .toolbar .actions { grid-column: 1 / -1; margin-top: 0; }
}
@media (max-width: 820px) {
  .app { display: block; min-height: 100dvh; }
  .sidebar {
    position: static;
    display: flex;
    flex-direction: row;
    flex-wrap: wrap;
    align-items: center;
    gap: .5rem .9rem;
    height: auto;
    max-height: none;
    padding: .55rem .85rem;
    border-right: 0;
    border-bottom: 1px solid var(--line);
  }
  .side-nav { display: flex; margin-left: auto; }
  .side-section, .sidebar > .disclosure, .sidebar > .hint { display: none; }
  .main { min-height: 0; }
  .topbar { padding: .55rem .85rem; }
  .notice { margin: .7rem .85rem 0; }
  .content { padding: 1.1rem .85rem 2rem; }
  .meta { grid-template-columns: 1fr; }
  .meta dd { margin-bottom: .3rem; }
  .login-shell { margin-top: 1.5rem; }
  table { min-width: 640px; }
  .table-wrap[data-technical="on"] table { min-width: 1080px; }
}
@media (max-width: 620px) {
  .toolbar { grid-template-columns: 1fr; }
  .view-head { align-items: stretch; }
  .view-head .action-row { width: 100%; }
  .view-head .action-row button { flex: 1 1 auto; }
  .table-tools button { width: 100%; }
  .page-foot { align-items: stretch; }
  .page-foot .action-row { width: 100%; }
  .page-foot .action-row button { flex: 1 1 auto; }
  .brand-sub { display: none; }
}"""

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
  var eventsState = document.getElementById("events-state");
  var eventsStateTitle = document.getElementById("events-state-title");
  var eventsStateText = document.getElementById("events-state-text");
  var policyVersion = document.getElementById("policy-version");
  var policyDigest = document.getElementById("policy-digest");
  var effectiveLimits = document.getElementById("effective-limits");
  var limitsPanel = document.getElementById("limits-panel");
  var healthStatus = document.getElementById("health-status");
  var decisionFilter = document.getElementById("decision-filter");
  var eventTypeFilter = document.getElementById("event-type-filter");
  var requestIdFilter = document.getElementById("request-id-filter");
  var applyButton = document.getElementById("apply-filters");
  var exportButton = document.getElementById("export-csv");
  var tableWrap = document.getElementById("table-wrap");
  var technicalButton = document.getElementById("toggle-technical");
  var previousButton = document.getElementById("previous-page");
  var nextButton = document.getElementById("next-page");
  var operatorToken = "";
  var cursorHistory = [];
  var currentCursor = null;
  var nextCursor = null;
  var busy = false;
  var sessionEpoch = 0;
  var activeController = null;
  var technicalVisible = false;

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

  var LIMIT_ROWS = [
    ["context_messages", "Context messages"],
    ["context_budget", "Context budget"],
    ["default_reply_tokens", "Default reply tokens"],
    ["max_reply_tokens", "Maximum reply tokens"]
  ];

  function setLimits(limits) {
    if (!effectiveLimits || !limitsPanel) {
      return;
    }
    while (effectiveLimits.firstChild) {
      effectiveLimits.removeChild(effectiveLimits.firstChild);
    }
    if (!limits || typeof limits !== "object") {
      limitsPanel.hidden = true;
      return;
    }
    limitsPanel.hidden = false;
    for (var index = 0; index < LIMIT_ROWS.length; index += 1) {
      var field = LIMIT_ROWS[index][0];
      var entry = limits[field];
      if (!entry || typeof entry !== "object") {
        continue;
      }
      var term = document.createElement("dt");
      term.textContent = LIMIT_ROWS[index][1];
      var detail = document.createElement("dd");
      var value = typeof entry.effective === "number" ? entry.effective : "unavailable";
      var ceiling = typeof entry.ceiling === "number" ? entry.ceiling : "unavailable";
      var source = entry.source === "policy" ? "policy" : "env";
      detail.textContent = String(value) + " (env ceiling " + String(ceiling) + ", source " + source + ")";
      effectiveLimits.appendChild(term);
      effectiveLimits.appendChild(detail);
    }
  }

  function clearTable() {
    while (eventsBody.firstChild) {
      eventsBody.removeChild(eventsBody.firstChild);
    }
    pageInfo.textContent = "";
  }

  function setEventsState(kind, title, text) {
    if (kind === "ready") {
      eventsState.hidden = true;
      eventsState.removeAttribute("data-kind");
      eventsStateTitle.textContent = "";
      eventsStateText.textContent = "";
      return;
    }
    eventsState.hidden = false;
    eventsState.setAttribute("data-kind", kind);
    eventsStateTitle.textContent = title;
    eventsStateText.textContent = text;
  }

  function setTechnicalVisible(visible) {
    technicalVisible = visible === true;
    tableWrap.setAttribute("data-technical", technicalVisible ? "on" : "off");
    technicalButton.setAttribute("aria-expanded", technicalVisible ? "true" : "false");
    technicalButton.textContent = technicalVisible
      ? "Hide technical columns"
      : "Show technical columns";
  }

  function clearMeta() {
    policyVersion.textContent = "";
    policyDigest.textContent = "";
    healthStatus.textContent = "";
    setLimits(null);
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

  // Fixed column order. Technical columns keep their cells in the DOM and are
  // hidden only by the table wrapper's data-technical attribute.
  var EVENT_COLUMNS = [
    { get: function (event) { return event.seq; }, className: "dense col-technical" },
    { get: function (event) { return formatTimestamp(event.timestamp); } },
    { get: function (event) { return event.request_id; }, className: "wrap-cell mono" },
    { get: function (event) { return event.event_type; } },
    { get: function (event) { return event.decision; }, badge: true },
    { get: function (event) { return event.error_code; }, className: "dense" },
    { get: function (event) { return event.policy_version; }, className: "dense col-technical" },
    { get: function (event) { return event.policy_digest; }, className: "wrap-cell mono dense col-technical" },
    { get: function (event) { return event.model; }, className: "dense col-technical" }
  ];

  function cell(row, value, className) {
    var td = document.createElement("td");
    td.textContent = value === null || value === undefined ? "" : String(value);
    if (className) {
      td.className = className;
    }
    row.appendChild(td);
  }

  function decisionCell(row, value) {
    var td = document.createElement("td");
    var label = value === null || value === undefined || value === "" ? "—" : String(value);
    var badge = document.createElement("span");
    badge.className = "badge";
    if (value !== null && value !== undefined && value !== "") {
      badge.setAttribute("data-decision", String(value));
    }
    badge.textContent = label;
    td.appendChild(badge);
    row.appendChild(td);
  }

  function renderEvents(events) {
    clearTable();
    for (var i = 0; i < events.length; i += 1) {
      var event = events[i] || {};
      var row = document.createElement("tr");
      for (var columnIndex = 0; columnIndex < EVENT_COLUMNS.length; columnIndex += 1) {
        var column = EVENT_COLUMNS[columnIndex];
        var value = column.get(event);
        if (column.badge) {
          decisionCell(row, value);
        } else {
          cell(row, value, column.className);
        }
      }
      eventsBody.appendChild(row);
    }
    if (events.length === 0) {
      pageInfo.textContent = "No events match the current filters.";
    }
  }

  function hasFilters(filters) {
    return Boolean(filters.decision || filters.eventType || filters.requestId);
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
    setEventsState("ready", "", "");
    setTechnicalVisible(false);
  }

  function loadPage() {
    if (!operatorToken || busy) {
      return;
    }
    busy = true;
    updateControls();
    setStatus("Loading events…", "info");
    var epoch = sessionEpoch;
    var filters = readFilters();
    var query = buildQuery(filters, currentCursor);
    setEventsState("loading", "Loading events", "Reading audit metadata for this page.");
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
        if (response.status === 401) {
          setEventsState("error", "Access denied", "The operator key was not accepted. Disconnect, check the key and connect again.");
          setStatus("Access denied. Check the operator token.", "error");
        } else {
          setEventsState("error", "Events are unavailable", "The audit workspace could not load events. Try again or check the gateway status.");
          setStatus("Events are unavailable.", "error");
        }
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
      setLimits(data.limits);
      nextCursor = typeof data.next_cursor === "number" ? data.next_cursor : null;
      setEventsState("ready", "", "");
      var count = events.length;
      if (count === 0) {
        if (hasFilters(filters)) {
          pageInfo.textContent = "No events match the current filters.";
          setEventsState(
            "empty",
            "No matching events",
            "No audit events match these filters. Widen the decision, event type or request ID to see more."
          );
        } else {
          pageInfo.textContent = "No events recorded yet.";
          setEventsState(
            "empty",
            "No events yet",
            "Audit events appear here after the gateway handles requests. An empty stream is not evidence that chat is working."
          );
        }
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
      setEventsState("error", "Events are unavailable", "The audit workspace could not load events. Try again or check the gateway status.");
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
  technicalButton.addEventListener("click", function () {
    setTechnicalVisible(!technicalVisible);
  });
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
  setEventsState("ready", "", "");
  setTechnicalVisible(false);
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
            '<div class="notice" role="note">'
            "<strong>Model guard inactive.</strong> Test mode: LLM guards are inactive. "
            "This runtime is not protected by model-based guard classifiers. "
            "Deterministic policy and PII masking still run. "
            "Next step: configure the model guard adapters."
            "</div>"
        )
    elif not guards_active:
        banner = (
            '<div class="notice" role="note">'
            "<strong>Model guard not active.</strong> Guards are not active. "
            "Chat is unavailable until guard configuration is valid."
            "</div>"
        )
    else:
        banner = ""
    return ADMIN_HTML.replace(_MODE_BANNER_MARKER, banner, 1)


ADMIN_HTML = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<meta name="theme-color" content="#0b0b0b">
<title>Audit &amp; events · Nasi Lemak</title>
<style>{_ADMIN_CSS}</style>
</head>
<body>
<div class="app" data-nav="desktop">
<aside class="sidebar" aria-label="Operator navigation">
<div class="brand">
<svg class="brand-mark" width="22" height="22" viewBox="0 0 22 22" fill="none" aria-hidden="true" focusable="false">
<rect x="1.5" y="1.5" width="19" height="19" rx="5" stroke="currentColor" stroke-width="1.4"/>
<path d="M6.5 11h9M11 6.5v9" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>
</svg>
<div>
<h1>Nasi Lemak</h1>
<p class="brand-sub">Guardrail console</p>
</div>
</div>
<nav class="side-nav" aria-label="Primary">
<a href="/"><span class="nav-mark" aria-hidden="true"></span>Prompt testing</a>
<a href="/admin" aria-current="page"><span class="nav-mark" aria-hidden="true"></span>Audit &amp; events</a>
</nav>
<section class="side-section" aria-labelledby="operator-heading">
<h2 id="operator-heading">Operator access</h2>
<p class="hint">Use the operator key issued for audit access. It is separate from the application chat key and is held in this tab only.</p>
<p class="side-state">Read-only workspace. This view cannot change policy.</p>
</section>
<details class="disclosure">
<summary>What this workspace shows</summary>
<p>Event metadata recorded by the gateway. A request_started row records the pending decision at that moment; its final result can appear in a later event or on another page.</p>
</details>
<p class="hint">No tokens, prompt text or response text are displayed here.</p>
</aside>
<div class="main">
<header class="topbar">
<div class="title-group">
<span class="topbar-title">Audit &amp; events</span>
<span class="topbar-sub">Read-only operator workspace</span>
</div>
<span class="topbar-tag">Operator console</span>
</header>
{_MODE_BANNER_MARKER}
<div class="content">
<p id="status" class="status" role="status" aria-live="polite"></p>

<section id="login-panel" class="login-shell" aria-labelledby="login-heading">
<div class="login-panel">
<h1 id="login-heading">Connect to audit events</h1>
<p class="lead">Enter the operator key to read event metadata for this application. The application chat key does not work here.</p>
<form id="login-form" novalidate>
<div class="form-field">
<label for="operator-token">Operator key</label>
<input id="operator-token" name="operator-token" type="password" autocomplete="off" spellcheck="false" autocapitalize="off" required>
</div>
<div class="actions">
<button id="connect" class="primary" type="button">Connect</button>
</div>
</form>
<p class="hint">The key stays in this tab's JavaScript memory. It is not stored, put in the address bar, or kept in a cookie. Disconnecting or leaving the page clears the view.</p>
</div>
</section>

<section id="view-panel" class="workspace" aria-labelledby="events-heading" hidden>
<div class="view-head">
<div>
<h1 id="events-heading">Audit events</h1>
<p class="lead">Read-only metadata, oldest first. Use the filters to narrow the stream before exporting.</p>
</div>
<div class="action-row">
<button id="export-csv" class="primary" type="button">Export CSV</button>
<button id="disconnect" type="button" hidden>Disconnect</button>
</div>
</div>

<details class="meta-block">
<summary>Active policy &amp; health</summary>
<dl class="meta">
<dt>Policy version</dt><dd id="policy-version"></dd>
<dt>Policy digest</dt><dd id="policy-digest"></dd>
<dt>Gateway health</dt><dd id="health-status"></dd>
</dl>
</details>

<details class="meta-block" id="limits-panel" hidden>
<summary>Effective limits</summary>
<dl class="meta" id="effective-limits"></dl>
<p class="hint">Read-only. The environment (or built-in default) value is a hard ceiling; a startup policy may only tighten it.</p>
</details>

<div class="toolbar" role="group" aria-label="Filter audit events">
<div class="field">
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
<div class="field">
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
<div class="field">
<label for="request-id-filter">Request ID</label>
<input id="request-id-filter" type="text" maxlength="128" autocomplete="off" spellcheck="false" placeholder="req_…">
</div>
<div class="actions">
<button id="apply-filters" type="button">Apply filters</button>
</div>
</div>

<div class="table-tools">
<button id="toggle-technical" type="button" aria-expanded="false" aria-controls="events-table">Show technical columns</button>
</div>

<div class="table-wrap" id="table-wrap" role="region" aria-label="Audit events table" tabindex="0" data-technical="off">
<table id="events-table">
<caption>Audit events, oldest first. A request_started row shows the pending decision recorded by that start event; its final outcome may appear in a later event or on another page.</caption>
<thead>
<tr>
<th scope="col" class="col-technical">Seq</th>
<th scope="col">Time (UTC)</th>
<th scope="col">Request ID</th>
<th scope="col">Event</th>
<th scope="col">Decision</th>
<th scope="col">Error code</th>
<th scope="col" class="col-technical">Policy version</th>
<th scope="col" class="col-technical">Policy digest</th>
<th scope="col" class="col-technical">Model</th>
</tr>
</thead>
<tbody id="events-body"></tbody>
</table>
</div>

<section id="events-state" class="events-state" aria-live="polite" hidden>
<h2 id="events-state-title"></h2>
<p id="events-state-text"></p>
</section>

<details class="guide">
<summary>Event field guide</summary>
<p><strong>Decision</strong> is the value recorded on that row, not a recomputed or global verdict. <strong>Pending</strong> means the request had started. <strong>Policy version</strong> and <strong>policy digest</strong> identify the active policy snapshot. <strong>Model</strong> is the upstream label recorded by the gateway. Use <strong>Show technical columns</strong> to reveal sequence, policy and model fields. This view does not show prompt or response content.</p>
</details>

<div class="page-foot">
<p id="page-info" class="page-info" aria-live="polite"></p>
<div class="action-row">
<button id="previous-page" type="button" disabled>Previous</button>
<button id="next-page" type="button" disabled>Next</button>
</div>
</div>
</section>
</div>
</div>
</div>
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
