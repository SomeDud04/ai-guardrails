"""Static employee workspace shell for the opt-in workspace HTTP API.

The page is a same-origin client for ``/workspace/api/*``.  It contains no
application data, no secrets and no remote assets.  The browser holds only an
HttpOnly, SameSite=Strict workspace cookie scoped to ``/workspace``: the page
never receives or stores a session token.  Every rendered value is assigned
with ``textContent`` or built with DOM methods.

The page is served only when the workspace is enabled.  It reports an unready
configuration honestly, while the API remains the authority for every action.
Inline CSS/JS is covered by an independent hash-based Content-Security-Policy.
"""

from __future__ import annotations

import base64
import hashlib


_WORKSPACE_CSS = """:root {
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
  --danger: #ff9f92;
  --danger-soft: #241312;
  --focus: #e8e8e0;
  --radius: 8px;
  --radius-lg: 12px;
  --control-h: 36px;
  --space-1: .25rem;
  --space-2: .5rem;
  --space-3: .75rem;
  --space-4: 1rem;
  --space-5: 1.5rem;
  font-family: "Segoe UI", system-ui, -apple-system, "Helvetica Neue", Arial, sans-serif;
  font-size: 16px;
}
* { box-sizing: border-box; }
[hidden] { display: none !important; }
html, body { min-height: 100%; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  line-height: 1.55;
  -webkit-font-smoothing: antialiased;
  text-rendering: optimizeLegibility;
  overflow: hidden;
}
::selection { background: #3d3d34; color: #fff; }
* { scrollbar-color: #3d3d38 transparent; scrollbar-width: thin; }
h1, h2, h3, p { margin-top: 0; }
button, input, textarea, select { font: inherit; color: var(--text); }
button {
  background: transparent;
  border: 1px solid var(--line-strong);
  border-radius: var(--radius);
  padding: 0 var(--space-3);
  min-height: var(--control-h);
  cursor: pointer;
  transition: background-color .16s ease, border-color .16s ease, color .16s ease;
}
button:hover:not(:disabled) { background: var(--surface-raised); border-color: #4f4f48; }
button:disabled { cursor: not-allowed; opacity: .45; }
button.primary { background: var(--text); color: #121210; border-color: var(--text); font-weight: 650; }
button.primary:hover:not(:disabled) { background: #fff; border-color: #fff; }
button.ghost { color: var(--muted); border-color: transparent; }
button.ghost:hover:not(:disabled) { color: var(--text); border-color: var(--line-strong); }
button.danger { color: #1b0806; background: var(--danger); border-color: var(--danger); font-weight: 650; }
button.danger:hover:not(:disabled) { background: #ffb6ac; border-color: #ffb6ac; }
input, textarea, select {
  width: 100%;
  min-height: var(--control-h);
  padding: 0 var(--space-3);
  border: 1px solid var(--line-strong);
  border-radius: var(--radius);
  background: var(--surface);
}
select { padding-right: var(--space-2); }
input[type="checkbox"] { width: auto; min-height: 0; padding: 0; }
textarea {
  resize: vertical;
  min-height: 84px;
  max-height: 220px;
  padding: var(--space-2) var(--space-3);
  line-height: 1.5;
}
input::placeholder, textarea::placeholder { color: #8f8f87; }
input:focus-visible, textarea:focus-visible, select:focus-visible, button:focus-visible,
a:focus-visible, [tabindex]:focus-visible {
  outline: 2px solid var(--focus);
  outline-offset: 2px;
}
textarea:focus-visible { outline-offset: -2px; }
.sr-only {
  position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px;
  overflow: hidden; clip: rect(0, 0, 0, 0); white-space: nowrap; border: 0;
}
.app { display: grid; grid-template-columns: 264px minmax(0, 1fr); height: 100dvh; overflow: hidden; }
.sidebar {
  display: flex; flex-direction: column; min-width: 0; min-height: 0;
  background: var(--panel); border-right: 1px solid var(--line);
}
.brand { display: flex; align-items: center; gap: .75rem; padding: var(--space-4) var(--space-3) var(--space-3); border-bottom: 1px solid var(--line); }
.brand-mark { flex: none; color: var(--amber); }
.brand h1 { margin: 0; font-size: .95rem; letter-spacing: .01em; }
.brand p { margin: .125rem 0 0; color: var(--muted); font-size: .75rem; }
.side-section { padding: var(--space-3) var(--space-3) var(--space-1); }
.side-heading { margin: 0 0 var(--space-2) var(--space-1); color: var(--muted-dim); font-size: .75rem; font-weight: 650; letter-spacing: .09em; text-transform: uppercase; }
.side-nav { display: grid; gap: var(--space-1); padding: var(--space-2) var(--space-2) var(--space-1); }
.side-nav button { display: flex; align-items: center; gap: var(--space-2); width: 100%; min-height: var(--control-h); padding: 0 var(--space-2); border-color: transparent; color: var(--muted); font-size: .84rem; text-align: left; }
.side-nav button:hover:not(:disabled) { color: var(--text); }
.side-nav button[aria-selected="true"] { color: var(--text); background: var(--surface); border-color: var(--line); }
.new-chat { display: flex; align-items: center; justify-content: center; gap: var(--space-2); width: calc(100% - var(--space-4)); margin: var(--space-1) var(--space-2) var(--space-3); font-size: .82rem; }
.side-list-head { display: flex; align-items: center; justify-content: space-between; padding: 0 var(--space-3) var(--space-2); }
.side-list-head h2 { margin: 0; color: var(--muted-dim); font-size: .75rem; font-weight: 650; letter-spacing: .09em; text-transform: uppercase; }
.conversation-list { display: grid; align-content: start; gap: 2px; overflow-y: auto; padding: 0 var(--space-2) var(--space-2); min-height: 0; flex: 1 1 auto; }
.conversation-item { display: block; width: 100%; padding: var(--space-2) var(--space-3); border-color: transparent; text-align: left; }
.conversation-item:hover:not(:disabled) { border-color: var(--line); }
.conversation-item[aria-current="true"] { background: var(--surface); border-color: var(--line-strong); }
.conversation-item .item-title { display: block; color: var(--text-soft); font-size: .82rem; }
.conversation-item .item-meta { display: block; color: var(--muted-dim); font-size: .75rem; margin-top: .125rem; }
.list-state { margin: 0; padding: var(--space-1) var(--space-3) var(--space-2); color: var(--muted); font-size: .75rem; }
.list-more { margin: 0 var(--space-2) var(--space-3); font-size: .75rem; }
.side-foot { margin-top: auto; padding: var(--space-3); border-top: 1px solid var(--line); color: var(--muted-dim); font-size: .75rem; }
.main { display: flex; flex-direction: column; min-width: 0; min-height: 0; }
.topbar {
  display: flex; align-items: center; gap: var(--space-2); min-height: 56px;
  padding: var(--space-2) var(--space-4); border-bottom: 1px solid var(--line); background: var(--bg);
}
.topbar-title { flex: 0 1 auto; min-width: 0; margin: 0; color: var(--text-soft); font-size: .86rem; font-weight: 600; }
.guard-status { position: relative; flex: 0 1 auto; min-width: 0; margin: 0; color: var(--muted); font-size: .75rem; line-height: 1.35; text-align: right; }
.guard-status summary { max-width: 240px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; cursor: pointer; list-style: none; }
.guard-status summary::-webkit-details-marker { display: none; }
.guard-status summary::after {
  content: ""; display: inline-block; width: .34rem; height: .34rem; margin-left: .4rem;
  border-right: 1px solid currentColor; border-bottom: 1px solid currentColor;
  transform: rotate(45deg) translateY(-1px); vertical-align: .08em;
}
.guard-status[open] summary::after { transform: rotate(225deg) translateY(-1px); }
.guard-status[data-kind="inactive"] summary { color: var(--amber); }
.guard-detail {
  position: absolute; z-index: 30; right: 0; top: calc(100% + .45rem); width: min(340px, 80vw);
  margin: 0; padding: var(--space-2) var(--space-3); border: 1px solid var(--line-strong);
  border-radius: var(--radius); background: var(--surface-raised); color: var(--text-soft);
  font-size: .75rem; line-height: 1.45; text-align: left;
}
.guard-detail:empty { display: none; }
.identity { display: grid; flex: 0 1 auto; justify-items: end; min-width: 0; }
.identity-name { max-width: 210px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--text-soft); font-size: .78rem; }
.identity-meta { max-width: 210px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--muted-dim); font-size: .75rem; }
.icon-button { display: none; width: var(--control-h); padding: 0; place-items: center; }
.global-status { width: 100%; max-width: 960px; margin: 0 auto; padding: 0 var(--space-5); color: var(--muted); font-size: .75rem; min-height: 0; }
.global-status:not(:empty) { padding-top: var(--space-2); }
.retry-check { display: block; margin: var(--space-2) auto 0; min-height: 32px; font-size: .75rem; color: var(--text-soft); }
.app[data-private="hidden"] .sidebar,
.app[data-private="hidden"] .identity,
.app[data-private="hidden"] .topbar-title { visibility: hidden; pointer-events: none; }
.banner { margin: var(--space-3) var(--space-4) 0; padding: var(--space-2) var(--space-3); border: 1px solid var(--amber-line); border-radius: var(--radius); background: var(--amber-soft); color: var(--text-soft); font-size: .78rem; }
.banner strong { color: var(--amber); }
.content { flex: 1 1 auto; min-height: 0; display: flex; flex-direction: column; }
#workspace-view { flex: 1 1 auto; min-height: 0; display: flex; flex-direction: column; }
.auth-view { width: min(400px, calc(100% - 2rem)); margin: auto; padding: var(--space-5) 0; }
.auth-view h2 { margin-bottom: var(--space-1); font-size: 1.25rem; }
.auth-view > p { color: var(--muted); font-size: .84rem; }
.auth-view form { display: grid; gap: var(--space-2); margin: var(--space-4) 0 var(--space-3); }
.auth-view label { color: var(--text-soft); font-size: .78rem; }
.auth-view button { margin-top: var(--space-2); justify-self: start; min-width: 112px; }
.auth-status, .chat-status, .review-state { margin: 0; color: var(--muted); font-size: .78rem; min-height: 1.25em; }
.auth-status[data-kind="error"], .chat-status[data-kind="error"], .review-state[data-kind="error"] { color: var(--danger); }
.chat-status[data-kind="denied"], .review-state[data-kind="denied"] { color: var(--amber); }
.chat-status[data-kind="warning"], .global-status[data-kind="warning"] { color: var(--amber); }
.chat-status[data-kind="ok"] { color: #b9d7b2; }
.foot { color: var(--muted-dim); font-size: .75rem; }
.panel { flex: 1 1 auto; min-height: 0; display: flex; flex-direction: column; }
.chat-column {
  display: flex; flex-direction: column; flex: 1 1 auto; min-height: 0;
  width: 100%; max-width: 960px; margin: 0 auto; padding: 0 var(--space-5);
}
.conversation-head { display: flex; align-items: flex-start; gap: var(--space-2); padding: var(--space-3) 0 var(--space-2); }
.conversation-head h2 { margin: 0; font-size: 1rem; }
.chat-meta { margin: .125rem 0 0; color: var(--muted-dim); font-size: .75rem; }
.chat-actions { display: flex; gap: var(--space-1); margin-left: auto; }
.chat-actions button { font-size: .76rem; min-height: 32px; padding: 0 var(--space-2); }
.confirm { margin: 0 0 var(--space-2); padding: var(--space-3); border: 1px solid #6b332d; border-radius: var(--radius); background: var(--danger-soft); color: var(--text-soft); font-size: .78rem; }
.confirm p { margin-bottom: var(--space-2); }
.confirm button { min-height: 32px; font-size: .76rem; margin-right: var(--space-2); }
.messages { flex: 1 1 auto; min-height: 0; overflow-y: auto; padding: var(--space-2) 0 var(--space-4); display: flex; flex-direction: column; gap: var(--space-5); }
.message { width: 100%; margin: 0; }
.message-head { display: flex; align-items: baseline; gap: var(--space-2); margin-bottom: var(--space-1); color: var(--muted-dim); font-size: .75rem; }
.message-role { color: var(--text-soft); font-weight: 650; letter-spacing: .02em; }
.message-flag { color: var(--danger); font-weight: 650; }
.message-flag[data-outcome="blocked"] { color: var(--amber); }
.message-text { margin: 0; white-space: pre-wrap; overflow-wrap: anywhere; color: var(--text); font-size: .93rem; line-height: 1.62; }
.message.user .message-text { color: var(--text-soft); }
.empty-state { margin: auto; padding: var(--space-5) var(--space-3); max-width: 520px; text-align: center; color: var(--muted); font-size: .88rem; }
.empty-state strong { display: block; margin-bottom: var(--space-1); color: var(--text-soft); }
.chat-status { padding-bottom: var(--space-2); }
.composer-wrap { padding: var(--space-2) 0 var(--space-4); border-top: 1px solid var(--line); background: var(--bg); }
.composer {
  display: flex; flex-direction: column; max-width: none; margin: 0;
  padding: var(--space-2);
  border: 1px solid var(--line-strong); border-radius: var(--radius-lg);
  background: var(--surface);
  transition: border-color .16s ease, box-shadow .16s ease;
}
.composer:focus-within { border-color: #6d6757; box-shadow: 0 0 0 2px rgba(230, 177, 92, .2); }
.composer textarea {
  min-height: 68px; padding: var(--space-1) var(--space-1);
  border: 0; border-radius: 0; background: transparent;
}
.composer textarea:focus-visible { outline: none; }
.composer-row { display: flex; align-items: flex-end; justify-content: flex-end; gap: var(--space-2); margin-top: var(--space-1); }
.composer-hint { flex: 1 1 auto; min-width: 0; color: var(--muted-dim); font-size: .75rem; }
.composer-row button { min-width: 76px; min-height: 32px; align-self: flex-end; }
.privacy-disclosure { margin-top: var(--space-2); color: var(--muted-dim); font-size: .75rem; }
.privacy-disclosure summary { width: fit-content; cursor: pointer; color: var(--muted); list-style: none; }
.privacy-disclosure summary::-webkit-details-marker { display: none; }
.privacy-disclosure summary::after {
  content: ""; display: inline-block; width: .3rem; height: .3rem; margin-left: .35rem;
  border-right: 1px solid currentColor; border-bottom: 1px solid currentColor;
  transform: rotate(45deg) translateY(-1px); vertical-align: .08em;
}
.privacy-disclosure[open] summary::after { transform: rotate(225deg) translateY(-1px); }
.retention { max-width: 72ch; margin: var(--space-2) 0 0; color: var(--muted-dim); font-size: .75rem; }
.review-view { flex: 1 1 auto; min-height: 0; overflow-y: auto; padding: var(--space-4) var(--space-5) var(--space-5); }
.review-view > h2 { margin-bottom: .125rem; font-size: 1rem; }
.review-notice { max-width: 960px; color: var(--muted); font-size: .76rem; }
.review-layout { display: grid; grid-template-columns: minmax(220px, 320px) minmax(0, 1fr); gap: var(--space-4); margin-top: var(--space-3); align-items: start; max-width: 1160px; }
.review-column { border: 1px solid var(--line); border-radius: var(--radius-lg); background: var(--panel); padding: var(--space-2); min-width: 0; }
.review-column h3 { margin: var(--space-1) var(--space-1) var(--space-2); color: var(--muted-dim); font-size: .75rem; letter-spacing: .08em; text-transform: uppercase; }
.review-list { display: grid; gap: 2px; }
.review-meta { padding: var(--space-2) var(--space-3); border-bottom: 1px solid var(--line); color: var(--muted); font-size: .75rem; overflow-wrap: anywhere; }
.review-meta strong { color: var(--text-soft); }
.review-messages { padding: var(--space-3); display: flex; flex-direction: column; gap: var(--space-4); max-height: 58vh; overflow-y: auto; }
.review-empty { padding: var(--space-4) var(--space-2); color: var(--muted-dim); font-size: .8rem; }
.admin-view { flex: 1 1 auto; min-height: 0; overflow-y: auto; padding: var(--space-4) var(--space-5) var(--space-5); }
.admin-view > h2 { margin-bottom: .125rem; font-size: 1rem; }
.admin-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 300px), 1fr)); gap: var(--space-4); margin-top: var(--space-3); align-items: start; max-width: 1160px; }
.admin-card { border: 1px solid var(--line); border-radius: var(--radius-lg); background: var(--panel); padding: var(--space-4); min-width: 0; }
.admin-card h3 { margin: 0 0 var(--space-3); color: var(--text-soft); font-size: .8rem; }
.admin-form { display: grid; gap: var(--space-2); margin-bottom: var(--space-3); }
.admin-form label { color: var(--text-soft); font-size: .75rem; }
.admin-form button { justify-self: start; margin-top: var(--space-1); }
.admin-note { margin: var(--space-1) 0 var(--space-2); color: var(--muted-dim); font-size: .75rem; }
.admin-warning { margin: var(--space-1) 0 var(--space-2); padding: var(--space-2) var(--space-3); border: 1px solid var(--amber-line); border-radius: var(--radius); background: var(--amber-soft); color: var(--text-soft); font-size: .75rem; }
.admin-list { display: grid; margin-top: var(--space-2); }
.admin-row { border: 0; border-top: 1px solid var(--line); border-radius: 0; padding: var(--space-2) var(--space-1); display: grid; gap: var(--space-1); min-width: 0; overflow-wrap: anywhere; }
.admin-list > .admin-row:first-child { border-top: 0; }
.admin-row-main { color: var(--text-soft); font-size: .8rem; }
.admin-row-meta { color: var(--muted-dim); font-size: .75rem; }
.admin-row-actions { display: flex; flex-wrap: wrap; gap: var(--space-1); }
.admin-row-actions button { min-height: 30px; padding: 0 var(--space-2); font-size: .75rem; }
.admin-confirm { border: 1px solid #6b332d; border-radius: var(--radius); background: var(--danger-soft); padding: var(--space-2) var(--space-3); display: grid; gap: var(--space-2); margin-top: var(--space-1); }
.admin-confirm p { margin: 0; color: var(--text-soft); font-size: .75rem; }
.admin-confirm button { min-height: 30px; font-size: .75rem; }
.admin-reset { display: grid; gap: var(--space-2); border-top: 1px solid var(--line); padding-top: var(--space-2); margin-top: var(--space-1); }
.admin-reset label { color: var(--text-soft); font-size: .75rem; }
.admin-reset-actions { display: flex; flex-wrap: wrap; gap: var(--space-2); }
.admin-reset-actions button { min-height: 30px; font-size: .75rem; }
.admin-empty { margin: 0; padding: var(--space-2) var(--space-1); color: var(--muted-dim); font-size: .76rem; }
.admin-more { margin-top: var(--space-2); font-size: .75rem; }
.admin-card > p[role="status"] { margin: var(--space-1) 0; }
@media (max-width: 900px) {
  .review-layout { grid-template-columns: minmax(200px, 280px) minmax(0, 1fr); }
}
@media (max-width: 760px) {
  .app { grid-template-columns: minmax(0, 1fr); }
  .sidebar { position: fixed; z-index: 20; inset: 0 auto 0 0; width: min(276px, 86vw); transform: translateX(-102%); transition: transform .18s ease; box-shadow: 18px 0 40px rgba(0,0,0,.45); }
  .app[data-nav="open"] .sidebar { transform: translateX(0); }
  .icon-button { display: grid; }
  .topbar { min-height: 52px; padding: var(--space-2) var(--space-3); flex-wrap: wrap; }
  .topbar-title { flex: 1 1 auto; }
  .identity-name, .identity-meta { max-width: 140px; }
  .guard-status { order: 10; flex-basis: 100%; text-align: left; }
  .guard-detail { left: 0; right: auto; width: min(340px, calc(100vw - 1.5rem)); }
  .chat-column { padding: 0 var(--space-3); }
  .messages { padding: var(--space-2) 0 var(--space-3); gap: var(--space-4); }
  .conversation-head { padding: var(--space-2) 0 var(--space-1); }
  .composer-wrap { padding: var(--space-2) 0 var(--space-3); }
  .review-view { padding: var(--space-3); }
  .admin-view { padding: var(--space-3); }
  .admin-grid { grid-template-columns: minmax(0, 1fr); }
  .review-layout { grid-template-columns: minmax(0, 1fr); }
  .review-messages { max-height: none; }
  .global-status { padding: 0 var(--space-3); }
  .banner { margin: var(--space-2) var(--space-3) 0; }
}
@media (max-width: 380px) {
  .identity { display: none; }
  .topbar { padding: var(--space-2) var(--space-3); gap: var(--space-1); }
  .chat-column { padding: 0 var(--space-3); }
  .chat-actions button { padding: 0 var(--space-2); }
  .conversation-head h2 { font-size: .92rem; }
  .message-head { flex-wrap: wrap; }
  .composer-row { gap: var(--space-2); }
  .composer-row button { min-width: 76px; }
  .auth-view { width: calc(100% - 1.5rem); }
  .review-view, .admin-view { padding: var(--space-2) var(--space-3) var(--space-3); }
  .admin-card { padding: var(--space-3); }
  .review-column { padding: var(--space-2); }
}
"""


_WORKSPACE_JS = """
(function () {
  "use strict";

  var REQUEST_TIMEOUT_MS = 60000;
  var LIST_LIMIT = 25;
  // A safe read of /me may be answered with a transient 503 while the bounded
  // control-plane admission is full.  Retrying the read is safe; writes and the
  // login POST are never retried and the password is never resent.
  var PROFILE_CHECK_RETRY_MS = [300, 800];

  function byId(id) { return document.getElementById(id); }
  var appEl = byId("app");
  var sidebarToggle = byId("sidebar-toggle");
  var sidebar = byId("sidebar");
  var authView = byId("auth-view");
  var workspaceView = byId("workspace-view");
  var loginForm = byId("login-form");
  var loginUsername = byId("username");
  var loginPassword = byId("password");
  var loginSubmit = byId("login-submit");
  var authStatus = byId("auth-status");
  var globalStatus = byId("global-status");
  var revalidateRetry = byId("revalidate-retry");
  var guardStatus = byId("guard-status");
  var guardSummary = byId("guard-summary");
  var guardDetail = byId("guard-detail");
  var identityName = byId("identity-name");
  var identityMeta = byId("identity-meta");
  var logoutButton = byId("logout-button");
  var tabChat = byId("tab-chat");
  var tabReview = byId("tab-review");
  var topbarTitle = byId("topbar-title");
  var chatPanel = byId("chat-panel");
  var reviewPanel = byId("review-panel");
  var conversationList = byId("conversation-list");
  var listState = byId("list-state");
  var loadMoreButton = byId("load-more");
  var newChatButton = byId("new-chat");
  var chatTitle = byId("chat-title");
  var chatMeta = byId("chat-meta");
  var deleteButton = byId("delete-conversation");
  var deleteConfirm = byId("delete-confirm");
  var deleteYes = byId("delete-yes");
  var deleteNo = byId("delete-no");
  var messagesEl = byId("messages");
  var chatEmpty = byId("chat-empty");
  var chatStatus = byId("chat-status");
  var composerForm = byId("composer-form");
  var composer = byId("composer");
  var sendButton = byId("send");
  var composerHint = byId("composer-hint");
  var reviewList = byId("review-list");
  var reviewState = byId("review-state");
  var reviewLoadMore = byId("review-load-more");
  var reviewMeta = byId("review-meta");
  var reviewMessages = byId("review-messages");
  var reviewEmpty = byId("review-empty");
  var tabAdmin = byId("tab-admin");
  var adminPanel = byId("admin-panel");
  var adminStatus = byId("admin-status");
  var departmentForm = byId("department-form");
  var departmentName = byId("department-name");
  var departmentSubmit = byId("department-submit");
  var departmentList = byId("department-list");
  var departmentState = byId("department-state");
  var departmentMore = byId("department-more");
  var userForm = byId("user-form");
  var userUsername = byId("new-user-username");
  var userFullName = byId("new-user-fullname");
  var userDepartment = byId("new-user-department");
  var userRole = byId("new-user-role");
  var userPassword = byId("new-user-password");
  var userSubmit = byId("user-submit");
  var userList = byId("user-list");
  var userState = byId("user-state");
  var userMore = byId("user-more");
  var grantForm = byId("grant-form");
  var grantUser = byId("grant-user");
  var grantScope = byId("grant-scope");
  var grantDepartment = byId("grant-department");
  var grantDepartmentField = byId("grant-department-field");
  var grantGlobalField = byId("grant-global-field");
  var grantGlobalConfirm = byId("grant-global-confirm");
  var grantSubmit = byId("grant-submit");
  var grantList = byId("grant-list");
  var grantState = byId("grant-state");
  var grantMore = byId("grant-more");
  var accessList = byId("access-list");
  var accessState = byId("access-state");
  var accessMore = byId("access-more");

  var signedIn = false;
  var profile = null;
  var drafts = Object.create(null);
  var authChannel = null;
  var revalidating = false;
  var logoutBusy = false;
  var logoutUnconfirmed = false;
  var logoutExpectedUid = null;
  var revalidateSeq = 0;
  var sessionEpoch = 0;
  // Auth changes and session restores supersede any profile check that was
  // started for the previous cookie, even within the same session epoch.
  var sessionCheckSeq = 0;
  var controllers = [];
  var currentConversation = null;
  var chatSeq = 0;
  var listCursor = null;
  var listLoading = false;
  var listLoaded = false;
  var reviewCursor = null;
  var reviewLoading = false;
  var reviewLoaded = false;
  var reviewDetailSeq = 0;
  var sending = false;
  var creating = false;
  var deleting = false;
  var loginBusy = false;
  var currentView = "chat";
  var sendSeq = 0;
  var adminLoaded = false;
  var adminDepartments = [];
  var adminUsers = [];
  var departmentCursor = null;
  var userCursor = null;
  var grantCursor = null;
  var accessCursor = null;
  var departmentLoading = false;
  var userLoading = false;
  var grantLoading = false;
  var accessLoading = false;
  var creatingDepartment = false;
  var creatingUser = false;
  var granting = false;
  var resettingPassword = false;
  var adminActiveConfirm = null;
  var adminListChain = Promise.resolve();

  function isObject(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
  }

  function shortId(value) {
    return typeof value === "string" ? value.slice(0, 8) : "unknown";
  }

  function formatDate(seconds) {
    var date = new Date((typeof seconds === "number" ? seconds : 0) * 1000);
    if (isNaN(date.getTime())) { return "unknown date"; }
    try { return date.toLocaleString(); } catch (error) { return date.toISOString(); }
  }

  function setStatus(node, text, kind) {
    node.textContent = text || "";
    if (kind) { node.setAttribute("data-kind", kind); }
    else { node.removeAttribute("data-kind"); }
  }

  function clearNode(node) {
    while (node.firstChild) { node.removeChild(node.firstChild); }
  }

  function abortAll() {
    var pending = controllers;
    controllers = [];
    for (var i = 0; i < pending.length; i += 1) {
      try { pending[i].abort(); } catch (error) { /* already finished */ }
    }
  }

  function api(path, options) {
    var settings = options || {};
    var controller = new AbortController();
    // Public readiness data is independent of the private session lifecycle:
    // signing out or failing session restore must not abort the health check.
    if (!settings.independent) { controllers.push(controller); }
    var timer = setTimeout(function () {
      controller.workspaceTimedOut = true;
      try { controller.abort(); } catch (error) { /* already finished */ }
    }, REQUEST_TIMEOUT_MS);
    var headers = { "Accept": "application/json" };
    // Callers may pin the identity a request belongs to explicitly. Logout does
    // this because it clears the profile before the revoke is sent.
    var expectedUser = typeof settings.expectedUser === "string" && settings.expectedUser
      ? settings.expectedUser
      : (profile && profile.user && typeof profile.user.id === "string" ? profile.user.id : "");
    if (expectedUser) {
      headers["X-Workspace-User"] = expectedUser;
    }
    var method = settings.method || "GET";
    var init = {
      method: method,
      headers: headers,
      // The HttpOnly workspace cookie is the only browser credential.  It is
      // sent to this origin only; no token is stored or received by this page.
      credentials: "same-origin",
      cache: "no-store",
      signal: controller.signal
    };
    if (typeof settings.body === "string") {
      headers["Content-Type"] = "application/json";
      init.body = settings.body;
    } else if (method === "POST" || method === "DELETE") {
      // The cookie mutation guard requires exactly one JSON Content-Type on
      // every write.  A bodyless write therefore still sends an empty JSON
      // object instead of omitting the header (which the guard rejects).
      headers["Content-Type"] = "application/json";
      init.body = "{}";
    }
    return fetch(path, init).then(function (response) {
      return response.json().catch(function () { return null; }).then(function (data) {
        return { status: response.status, ok: response.ok, data: data };
      });
    }).catch(function (error) {
      if (controller.workspaceTimedOut) {
        return { timeout: true, status: 0, ok: false, data: null };
      }
      if (error && error.name === "AbortError") {
        return { aborted: true, status: 0, ok: false, data: null };
      }
      return { network: true, status: 0, ok: false, data: null };
    }).then(function (result) {
      clearTimeout(timer);
      var remaining = [];
      for (var i = 0; i < controllers.length; i += 1) {
        if (controllers[i] !== controller) { remaining.push(controllers[i]); }
      }
      controllers = remaining;
      return result;
    });
  }

  function serverMessage(result, fallback) {
    if (isObject(result.data) && isObject(result.data.error) &&
        typeof result.data.error.message === "string" && result.data.error.message) {
      return result.data.error.message;
    }
    return fallback;
  }

  function timeoutOrNetwork(result) {
    if (result.timeout) {
      return "The request timed out. The server may still be working; refresh before retrying.";
    }
    return "The workspace could not be reached. Check the connection and try again.";
  }

  function errorCode(result) {
    if (isObject(result.data) && isObject(result.data.error) &&
        typeof result.data.error.code === "string") {
      return result.data.error.code;
    }
    return "";
  }

  function wait(ms) {
    return new Promise(function (resolve) { setTimeout(resolve, ms); });
  }

  function authFailure(result) {
    if (result.status === 401) {
      clearSession("Your session expired. Sign in again.");
      return true;
    }
    if (result.status === 403 && errorCode(result) === "IDENTITY_CONFLICT") {
      clearSession("This browser signed in as a different account. Private data was cleared. Sign in again.");
      return true;
    }
    return false;
  }

  function resetPrivateState() {
    signedIn = false;
    profile = null;
    drafts = Object.create(null);
    logoutExpectedUid = null;
    currentConversation = null;
    sending = false;
    creating = false;
    deleting = false;
    loginBusy = false;
    logoutBusy = false;
    revalidating = false;
    listLoading = false;
    listLoaded = false;
    reviewLoading = false;
    reviewLoaded = false;
    listCursor = null;
    reviewCursor = null;
    abortAll();
    resetAdminState();
    loginSubmit.disabled = false;
    logoutButton.disabled = false;
    logoutButton.textContent = "Sign out";
    revalidateRetry.hidden = true;
    composer.value = "";
    clearNode(conversationList);
    clearNode(messagesEl);
    clearNode(reviewList);
    clearNode(reviewMessages);
    reviewMeta.textContent = "";
    reviewEmpty.textContent = "Select a conversation to review.";
    reviewEmpty.hidden = false;
    listState.textContent = "";
    chatMeta.textContent = "";
    chatTitle.textContent = "Conversation";
    identityName.textContent = "";
    identityMeta.textContent = "";
    loadMoreButton.hidden = true;
    reviewLoadMore.hidden = true;
    deleteButton.hidden = true;
    deleteConfirm.hidden = true;
    newChatButton.disabled = false;
    chatEmpty.hidden = false;
    chatEmpty.textContent = "Select a conversation or start a new one.";
    messagesEl.hidden = false;
    composer.disabled = true;
    sendButton.disabled = true;
    composerHint.textContent = "Select or create a conversation to send a message.";
    setStatus(chatStatus, "");
    setStatus(reviewState, "");
  }

  function clearSession(message) {
    sessionEpoch += 1;
    logoutUnconfirmed = false;
    resetPrivateState();
    loginUsername.value = "";
    loginPassword.value = "";
    setStatus(globalStatus, message || "Signed out.", message ? "error" : "");
    setStatus(authStatus, message || "Sign in to continue.", message ? "error" : "");
    authView.hidden = false;
    workspaceView.hidden = true;
    appEl.removeAttribute("data-private");
    logoutButton.hidden = true;
    tabReview.hidden = true;
    tabAdmin.hidden = true;
    topbarTitle.textContent = "Sign in";
    currentView = "chat";
    setViewTabs("chat");
    setSidebar(false);
    try { loginUsername.focus(); } catch (error) { /* non-fatal */ }
  }

  function announceAuthChange() {
    if (!authChannel) { return; }
    try { authChannel.postMessage({ type: "workspace-auth-changed" }); }
    catch (error) { /* another tab is not required */ }
  }

  function applyProfile(data) {
    if (!isObject(data) || !isObject(data.user) ||
        typeof data.user.id !== "string" || typeof data.user.username !== "string" ||
        typeof data.user.full_name !== "string" || !isObject(data.department) ||
        typeof data.department.name !== "string") {
      throw new Error("invalid profile");
    }
    var previous = profile;
    profile = {
      user: data.user,
      department: data.department,
      reviewScope: typeof data.review_scope === "string" ? data.review_scope : null,
      reviewDepartmentIds: Array.isArray(data.review_department_ids) ? data.review_department_ids : [],
      reviewGrants: Array.isArray(data.review_grants) ? data.review_grants : []
    };
    signedIn = true;
    // A confirmed profile is the authoritative identity; a pending login or
    // failed sign-out identity is no longer needed.
    logoutExpectedUid = null;
    var scopeChanged = !!previous && (
      previous.reviewScope !== profile.reviewScope ||
      (Array.isArray(previous.reviewDepartmentIds) ? previous.reviewDepartmentIds.join("|") : "") !==
        profile.reviewDepartmentIds.join("|")
    );
    identityName.textContent = data.user.full_name;
    identityMeta.textContent = data.department.name + " · " + data.user.username +
      (data.user.role === "admin" ? " · Administrator" : "");
    tabReview.hidden = !profile.reviewScope;
    if (scopeChanged) { clearReviewAccessState(); }
    if (!profile.reviewScope && currentView === "review") { showView("chat"); }
    var isAdmin = data.user.role === "admin";
    if (previous && previous.user && previous.user.role === "admin" && !isAdmin) {
      resetAdminState();
    }
    tabAdmin.hidden = !isAdmin;
    if (!isAdmin && currentView === "admin") { showView("chat"); }
    authView.hidden = true;
    workspaceView.hidden = false;
    appEl.removeAttribute("data-private");
    logoutButton.hidden = false;
    logoutUnconfirmed = false;
    revalidateRetry.hidden = true;
    setStatus(authStatus, "");
  }

  function loadProfile(options) {
    var settings = options || {};
    var epoch = sessionEpoch;
    var retryIn = Array.isArray(settings.retryIn) ? settings.retryIn.slice() : [];
    var expectedUid = typeof settings.expectedUid === "string" ? settings.expectedUid : "";
    function stillCurrent() {
      return epoch === sessionEpoch && (!settings.isCurrent || settings.isCurrent());
    }
    function check() {
      return api("/workspace/api/me", { auth: false }).then(function (result) {
        if (!stillCurrent()) { return false; }
        if (settings.initial && result.status === 401) {
          clearSession("");
          return false;
        }
        if (authFailure(result)) { return false; }
        if (!result.ok) {
          if (retryIn.length && result.status === 503) {
            // Bounded, delayed retry of this safe read only.  The recovery
            // button remains the final fallback when the retries are exhausted.
            return wait(retryIn.shift()).then(function () {
              if (!stillCurrent()) { return false; }
              return check();
            });
          }
          if (!settings.quiet) {
            setStatus(authStatus, serverMessage(result, timeoutOrNetwork(result)), "error");
          }
          if (settings.onFailure) { settings.onFailure(result); }
          return false;
        }
        if (!isObject(result.data) || !isObject(result.data.user) ||
            typeof result.data.user.id !== "string") {
          clearSession("The workspace returned an unexpected response. Sign in again.");
          return false;
        }
        if (expectedUid && result.data.user.id !== expectedUid) {
          // The login answer and the cookie profile must describe the same
          // account; never trust a silently switched cookie.
          clearSession("This browser signed in as a different account. Private data was cleared. Sign in again.");
          return false;
        }
        if (profile && profile.user && profile.user.id !== result.data.user.id) {
          clearSession("This browser signed in as a different account. Private data was cleared. Sign in again.");
          return false;
        }
        try { applyProfile(result.data); }
        catch (error) {
          clearSession("The workspace returned an unexpected response. Sign in again.");
          return false;
        }
        return true;
      });
    }
    return check();
  }

  function revalidate(force) {
    if (!signedIn) { return Promise.resolve(false); }
    if (revalidating && !force) { return Promise.resolve(false); }
    revalidating = true;
    var seq = ++revalidateSeq;
    var epoch = sessionEpoch;
    // Private content is withheld for the whole identity check.  Existing
    // requests keep their original epoch: a changed identity clears the session
    // and invalidates their callbacks before anything can be shown again.
    authView.hidden = true;
    workspaceView.hidden = true;
    revalidateRetry.hidden = true;
    appEl.setAttribute("data-private", "hidden");
    setStatus(globalStatus, "Confirming your session…");
    return api("/workspace/api/me").then(function (result) {
      if (seq !== revalidateSeq) { return false; }
      revalidating = false;
      if (epoch !== sessionEpoch) { return false; }
      if (authFailure(result)) { return false; }
      if (!result.ok) {
        // A transient failure does not prove an identity change, but it also
        // does not permit showing the previous identity's private content.
        workspaceView.hidden = true;
        authView.hidden = true;
        logoutButton.hidden = false;
        revalidateRetry.hidden = false;
        setStatus(
          globalStatus,
          "Private content stays hidden because your session could not be confirmed. " +
            timeoutOrNetwork(result) + " Retry the check before continuing.",
          "warning"
        );
        return false;
      }
      if (profile && profile.user && profile.user.id !== result.data.user.id) {
        clearSession("This browser signed in as a different account. Private data was cleared. Sign in again.");
        return false;
      }
      try { applyProfile(result.data); }
      catch (error) {
        clearSession("The workspace returned an unexpected response. Sign in again.");
        return false;
      }
      setStatus(globalStatus, "");
      return true;
    });
  }

  function showSessionCheckRecovery(failure) {
    // The password was accepted so a cookie exists, but no private surface may
    // be shown until /me confirms which account that cookie belongs to.  Keep
    // an honest, accessible recovery path instead of a blank hidden page.
    signedIn = false;
    workspaceView.hidden = true;
    authView.hidden = true;
    revalidateRetry.hidden = false;
    logoutButton.hidden = false;
    appEl.setAttribute("data-private", "hidden");
    topbarTitle.textContent = "Session check";
    var detail = failure
      ? serverMessage(failure, "The workspace is busy or did not answer.")
      : "The workspace did not answer.";
    setStatus(
      globalStatus,
      "Your session could not be confirmed. " + detail +
        " Private content stays hidden; retry the session check.",
      "warning"
    );
  }

  function finishLogin(result, epoch) {
    if (epoch !== sessionEpoch) { return; }
    loginBusy = false;
    loginSubmit.disabled = false;
    loginPassword.value = "";
    if (result.status === 401) {
      setStatus(authStatus, "The username or password was not accepted.", "error");
      loginUsername.focus();
      return;
    }
    if (result.status === 429) {
      setStatus(authStatus, "Too many attempts. Wait a minute and try again.", "error");
      return;
    }
    if (result.status === 403) {
      setStatus(authStatus, "Sign-in is not allowed from this connection. Open the workspace directly and try again.", "error");
      return;
    }
    if (!result.ok || !isObject(result.data) || !isObject(result.data.user)) {
      setStatus(authStatus, serverMessage(result, timeoutOrNetwork(result)), "error");
      return;
    }
    var loginUid = typeof result.data.user.id === "string" ? result.data.user.id : "";
    var failure = null;
    resetPrivateState();
    sessionEpoch += 1;
    epoch = sessionEpoch;
    logoutUnconfirmed = false;
    // resetPrivateState() dropped the pending identity, but the accepted login
    // response named the account whose server cookie now exists.  Retain that
    // non-secret id so a sign-out from the recovery screen can still revoke the
    // server session even before /me confirms who the cookie belongs to.
    logoutExpectedUid = loginUid;
    // No identity, no private surface and no "Signed in" claim until /me
    // answers for the account named by this login response.
    var checkSeq = ++sessionCheckSeq;
    authView.hidden = true;
    workspaceView.hidden = true;
    appEl.setAttribute("data-private", "hidden");
    revalidateRetry.hidden = true;
    setStatus(authStatus, "");
    setStatus(globalStatus, "Confirming your session…");
    announceAuthChange();
    loadProfile({
      quiet: true,
      expectedUid: loginUid,
      retryIn: PROFILE_CHECK_RETRY_MS,
      isCurrent: function () { return checkSeq === sessionCheckSeq; },
      onFailure: function (failedResult) { failure = failedResult; }
    }).then(function (loaded) {
      if (epoch !== sessionEpoch || checkSeq !== sessionCheckSeq) { return; }
      if (loaded && signedIn && profile) {
        topbarTitle.textContent = "Chat";
        setStatus(globalStatus, "");
        // Readiness is public but still consumes a bounded admission slot, so
        // refresh it only after the critical profile check has completed.
        loadGuardStatus();
        loadConversations(true);
        return;
      }
      showSessionCheckRecovery(failure);
    });
  }

  loginForm.addEventListener("submit", function (event) {
    event.preventDefault();
    if (loginBusy) { return; }
    var username = loginUsername.value;
    var password = loginPassword.value;
    if (!username || !password) {
      setStatus(authStatus, "Enter your username and password.", "error");
      return;
    }
    var epoch = sessionEpoch;
    loginBusy = true;
    loginSubmit.disabled = true;
    loginPassword.value = "";
    setStatus(authStatus, "Signing in…");
    api("/workspace/api/login", {
      method: "POST",
      body: JSON.stringify({ username: username, password: password, cookie: true }),
      auth: false
    }).then(function (result) { finishLogin(result, epoch); });
  });

  function logout() {
    if (logoutBusy) { return; }
    if (!signedIn && !logoutUnconfirmed && !logoutExpectedUid) {
      // No confirmed or login-named identity exists, so no server revoke can
      // be attributed honestly.  Clear only the local view.
      clearSession("Signed out.");
      return;
    }
    // Sign-out must name the account the server has to revoke.  Capture it
    // before resetPrivateState() drops the profile so a failed revoke can be
    // retried honestly without the cookie silently belonging to a peer.
    var expectedUid = profile && profile.user && typeof profile.user.id === "string"
      ? profile.user.id : logoutExpectedUid;
    sessionEpoch += 1;
    var epoch = sessionEpoch;
    // Withhold and clear every private surface as soon as sign-out starts.
    // The sign-in form appears only after the server answers, so a failed or
    // timed-out revoke is never reported as a completed sign-out.
    resetPrivateState();
    logoutExpectedUid = expectedUid;
    logoutBusy = true;
    logoutButton.disabled = true;
    logoutButton.hidden = false;
    appEl.setAttribute("data-private", "hidden");
    workspaceView.hidden = true;
    authView.hidden = true;
    currentView = "chat";
    setViewTabs("chat");
    topbarTitle.textContent = "Signing out";
    setStatus(globalStatus, "Signing out…");
    api("/workspace/api/logout", {
      method: "POST",
      body: "{}",
      auth: false,
      expectedUser: expectedUid
    }).then(function (result) {
      if (epoch !== sessionEpoch) { return; }
      logoutBusy = false;
      logoutButton.disabled = false;
      if (result.ok) {
        logoutUnconfirmed = false;
        clearSession("Signed out.");
        announceAuthChange();
        return;
      }
      if (authFailure(result)) {
        announceAuthChange();
        return;
      }
      logoutUnconfirmed = true;
      workspaceView.hidden = true;
      authView.hidden = false;
      logoutButton.hidden = false;
      logoutButton.textContent = "Retry sign-out";
      var message = "Sign-out was not confirmed. " + (result.timeout || result.network
        ? "The session may still be active; check the connection and try again."
        : serverMessage(result, "The session may still be active. Try again."));
      setStatus(authStatus, message, "error");
      setStatus(globalStatus, message, "error");
    });
  }

  logoutButton.addEventListener("click", logout);

  function setSidebar(open) {
    appEl.setAttribute("data-nav", open ? "open" : "closed");
    sidebarToggle.setAttribute("aria-expanded", open ? "true" : "false");
  }

  sidebarToggle.addEventListener("click", function () {
    setSidebar(appEl.getAttribute("data-nav") !== "open");
  });

  window.addEventListener("keydown", function (event) {
    if (event && event.key === "Escape") { setSidebar(false); }
  });

  function makeItem(title, meta, handler) {
    var button = document.createElement("button");
    button.className = "conversation-item";
    button.type = "button";
    var titleEl = document.createElement("span");
    titleEl.className = "item-title";
    titleEl.textContent = title;
    var metaEl = document.createElement("span");
    metaEl.className = "item-meta";
    metaEl.textContent = meta;
    button.appendChild(titleEl);
    button.appendChild(metaEl);
    button.addEventListener("click", handler);
    return button;
  }

  function markCurrent() {
    var buttons = conversationList.children || [];
    for (var i = 0; i < buttons.length; i += 1) {
      var child = buttons[i];
      if (currentConversation && child.getAttribute &&
          child.getAttribute("data-conversation") === currentConversation.id) {
        child.setAttribute("aria-current", "true");
      } else if (child.removeAttribute) {
        child.removeAttribute("aria-current");
      }
    }
  }

  function renderConversationList(items, reset) {
    if (reset) { clearNode(conversationList); }
    for (var i = 0; i < items.length; i += 1) {
      (function (item) {
        if (!isObject(item) || typeof item.id !== "string") { return; }
        var label = "Conversation " + shortId(item.id);
        var meta = formatDate(item.updated_at || item.created_at) + " · saved chat";
        var button = makeItem(label, meta, function () {
          openConversation(item.id);
          setSidebar(false);
        });
        button.setAttribute("data-conversation", item.id);
        conversationList.appendChild(button);
      }(items[i]));
    }
    markCurrent();
  }

  function loadConversations(reset) {
    if (!signedIn || listLoading) { return Promise.resolve(false); }
    var epoch = sessionEpoch;
    listLoading = true;
    if (reset) {
      listCursor = null;
      listLoaded = false;
      clearNode(conversationList);
      setStatus(listState, "Loading conversations…");
    } else {
      setStatus(listState, "Loading more…");
    }
    var path = "/workspace/api/conversations?limit=" + LIST_LIMIT +
      (listCursor ? "&after=" + encodeURIComponent(listCursor) : "");
    return api(path).then(function (result) {
      if (epoch !== sessionEpoch) { return false; }
      listLoading = false;
      if (authFailure(result)) { return false; }
      if (result.status === 403) { setStatus(listState, "Conversation list access was denied.", "denied"); return false; }
      if (!result.ok || !isObject(result.data) || !Array.isArray(result.data.items)) {
        setStatus(listState, serverMessage(result, timeoutOrNetwork(result)), "error");
        return false;
      }
      renderConversationList(result.data.items, reset);
      listCursor = typeof result.data.next === "string" && result.data.next ? result.data.next : null;
      loadMoreButton.hidden = !listCursor;
      listLoaded = true;
      if (reset && result.data.items.length === 0) {
        setStatus(listState, "No saved conversations yet.");
      } else {
        setStatus(listState, listCursor ? "More conversations available." : "");
      }
      return true;
    });
  }

  loadMoreButton.addEventListener("click", function () { loadConversations(false); });

  function updateComposer() {
    var ready = !!(signedIn && currentConversation);
    composer.disabled = !ready || sending;
    sendButton.disabled = !ready || sending;
    composer.setAttribute(
      "placeholder",
      ready ? "Type your message…" : "Select or create a conversation to send a message."
    );
    if (!ready) {
      composerHint.textContent = "Select or create a conversation to send a message.";
    } else if (sending) {
      composerHint.textContent = "Sending… duplicate submissions are paused.";
    } else {
      composerHint.textContent = "Ctrl/Command + Enter sends.";
    }
  }

  function renderMessages(container, messages) {
    clearNode(container);
    if (!Array.isArray(messages)) { return; }
    for (var i = 0; i < messages.length; i += 1) {
      var item = messages[i];
      if (!isObject(item) || typeof item.text !== "string") { continue; }
      var role = item.role === "assistant" ? "assistant" : "user";
      var article = document.createElement("article");
      article.className = "message " + role;
      var head = document.createElement("div");
      head.className = "message-head";
      var roleEl = document.createElement("span");
      roleEl.className = "message-role";
      roleEl.textContent = role === "assistant" ? "Assistant" : "You";
      head.appendChild(roleEl);
      var outcome = typeof item.outcome === "string" ? item.outcome : "";
      if (role === "user" && (outcome === "blocked" || outcome === "failed")) {
        var flag = document.createElement("span");
        flag.className = "message-flag";
        flag.setAttribute("data-outcome", outcome);
        flag.textContent = outcome === "blocked" ? "Blocked" : "Failed";
        head.appendChild(flag);
        if (typeof item.error_code === "string" && item.error_code) {
          var code = document.createElement("span");
          code.textContent = item.error_code;
          head.appendChild(code);
        }
      }
      var when = document.createElement("span");
      when.textContent = formatDate(item.created_at);
      head.appendChild(when);
      var body = document.createElement("p");
      body.className = "message-text";
      body.textContent = item.text;
      article.appendChild(head);
      article.appendChild(body);
      container.appendChild(article);
    }
  }

  function storeDraft(conversationId) {
    if (typeof conversationId !== "string") { return; }
    var value = composer.value;
    if (value) { drafts[conversationId] = value; }
    else { delete drafts[conversationId]; }
  }

  function restoreDraft(conversationId) {
    composer.value = typeof conversationId === "string" && drafts[conversationId]
      ? drafts[conversationId]
      : "";
  }

  function openConversation(id, options) {
    if (!signedIn || typeof id !== "string") { return Promise.resolve(false); }
    var settings = options || {};
    if (currentConversation) { storeDraft(currentConversation.id); }
    chatSeq += 1;
    var seq = chatSeq;
    var epoch = sessionEpoch;
    currentConversation = null;
    if (!settings.quiet) {
      sendSeq += 1;
      // Restore this conversation's own unsent draft; drafts are tab memory
      // only and are never sent with metadata or stored in the browser.
      restoreDraft(id);
    }
    sending = false;
    deleteConfirm.hidden = true;
    clearNode(messagesEl);
    chatEmpty.hidden = true;
    chatEmpty.textContent = "";
    deleteButton.hidden = true;
    if (!settings.quiet) { setStatus(chatStatus, "Loading conversation…"); }
    updateComposer();
    return api("/workspace/api/conversations/" + encodeURIComponent(id)).then(function (result) {
      if (seq !== chatSeq || epoch !== sessionEpoch) { return false; }
      if (authFailure(result)) { return false; }
      if (result.status === 403) {
        setStatus(chatStatus, "You do not have permission to open this conversation.", "denied");
        return false;
      }
      if (result.status === 404) {
        setStatus(chatStatus, "Conversation not found. It may already have been deleted.", "error");
        return false;
      }
      if (!result.ok || !isObject(result.data) || typeof result.data.id !== "string" ||
          !Array.isArray(result.data.messages)) {
        setStatus(chatStatus, serverMessage(result, timeoutOrNetwork(result)), "error");
        return false;
      }
      currentConversation = result.data;
      chatTitle.textContent = "Conversation";
      chatMeta.textContent = shortId(result.data.id) + " · started " +
        formatDate(result.data.created_at) + " · " + (result.data.messages.length) + " messages";
      renderMessages(messagesEl, result.data.messages);
      chatEmpty.hidden = result.data.messages.length > 0;
      chatEmpty.textContent = "No messages yet. Send the first prompt below.";
      deleteButton.hidden = false;
      markCurrent();
      updateComposer();
      if (!settings.quiet) { setStatus(chatStatus, ""); }
      try { composer.focus(); } catch (error) { /* non-fatal */ }
      return true;
    });
  }

  newChatButton.addEventListener("click", function () {
    if (!signedIn || creating) { return; }
    if (currentConversation) { storeDraft(currentConversation.id); }
    creating = true;
    newChatButton.disabled = true;
    setStatus(chatStatus, "Creating conversation…");
    var epoch = sessionEpoch;
    var startSeq = chatSeq;
    var startConversation = currentConversation ? currentConversation.id : null;
    api("/workspace/api/conversations", { method: "POST", body: "{}" }).then(function (result) {
      if (epoch !== sessionEpoch) { return; }
      creating = false;
      newChatButton.disabled = false;
      if (authFailure(result)) { return; }
      if (!result.ok || !isObject(result.data) || typeof result.data.id !== "string") {
        if (chatSeq === startSeq) {
          setStatus(chatStatus, serverMessage(result, timeoutOrNetwork(result)), "error");
        }
        return;
      }
      var stillCurrent = chatSeq === startSeq &&
        (currentConversation ? currentConversation.id : null) === startConversation;
      if (!stillCurrent) {
        loadConversations(true);
        return;
      }
      // The previous draft is already retained in memory.  Detach the old
      // conversation before clearing the composer so the empty value is not
      // mistaken for a new draft for the previous conversation.
      currentConversation = null;
      composer.value = "";
      delete drafts[result.data.id];
      loadConversations(true).then(function () {
        if (epoch !== sessionEpoch || chatSeq !== startSeq) { return; }
        openConversation(result.data.id);
      });
      setSidebar(false);
    });
  });

  function submitMessage() {
    if (!signedIn || !currentConversation || sending) { return; }
    var text = composer.value;
    if (!text || !text.trim()) {
      setStatus(chatStatus, "Enter a message before sending.", "error");
      composer.focus();
      return;
    }
    var conversationId = currentConversation.id;
    var seq = chatSeq;
    var epoch = sessionEpoch;
    var send = ++sendSeq;
    drafts[conversationId] = text;
    sending = true;
    updateComposer();
    setStatus(chatStatus, "Sending…");
    api("/workspace/api/conversations/" + encodeURIComponent(conversationId) + "/messages", {
      method: "POST",
      body: JSON.stringify({ text: text })
    }).then(function (result) {
      if (epoch !== sessionEpoch) { return; }
      if (send !== sendSeq) { return; }
      if (authFailure(result)) { return; }
      var sameConversation = currentConversation && currentConversation.id === conversationId &&
        chatSeq === seq;
      var message;
      var kind = "error";
      var keepText = false;
      if (result.timeout) {
        message = "Completion is uncertain: the request timed out and the server may still finish. Refresh this conversation before retrying; your text has been kept.";
        kind = "warning";
        keepText = true;
      } else if (result.network) {
        message = "The workspace could not be reached. Your text has been kept; refresh to check whether the turn was saved.";
        kind = "warning";
        keepText = true;
      } else if (result.status === 403) {
        message = "The message was blocked by the safety checks. The original prompt is saved with a Blocked label.";
        kind = "denied";
      } else if (result.ok) {
        message = "Answer received and saved.";
        kind = "ok";
      } else if (result.status === 409) {
        message = "This conversation is busy with another turn. Your text has been kept.";
        kind = "warning";
        keepText = true;
      } else if (result.status === 429) {
        message = "Too many requests. Your text has been kept; wait a moment and retry.";
        kind = "warning";
        keepText = true;
      } else if (result.status === 503) {
        message = "The workspace could not confirm completion. The server may still finish; refresh before retrying.";
        kind = "warning";
        keepText = true;
      } else if (result.status === 400 || result.status === 404) {
        message = serverMessage(result, "The message could not be sent.") + " Your text has been kept.";
        keepText = true;
      } else {
        message = serverMessage(result, "The message could not be sent.") +
          " The original prompt is shown from the saved conversation if it was stored.";
      }
      if (keepText) { drafts[conversationId] = text; }
      else { delete drafts[conversationId]; }
      if (!sameConversation) {
        sending = false;
        updateComposer();
        return;
      }
      if (!keepText) { composer.value = ""; }
      openConversation(conversationId, { quiet: true }).then(function (reloaded) {
        // A different send or conversation selection may have happened while
        // this quiet reload was pending. Never let the stale reload restore
        // old text, clear the composer or overwrite the new status.
        if (epoch !== sessionEpoch || send !== sendSeq || chatSeq !== seq + 1) {
          return;
        }
        sending = false;
        updateComposer();
        if (reloaded) { setStatus(chatStatus, message, kind); }
        else if (!keepText) { composer.value = text; }
      });
    });
  }

  composerForm.addEventListener("submit", function (event) {
    event.preventDefault();
    submitMessage();
  });

  composer.addEventListener("input", function () {
    if (currentConversation) { storeDraft(currentConversation.id); }
  });

  composer.addEventListener("keydown", function (event) {
    if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
      event.preventDefault();
      submitMessage();
    }
  });

  deleteButton.addEventListener("click", function () {
    deleteConfirm.hidden = false;
    deleteYes.focus();
  });

  deleteNo.addEventListener("click", function () {
    deleteConfirm.hidden = true;
    deleteButton.focus();
  });

  deleteYes.addEventListener("click", function () {
    if (!signedIn || !currentConversation || deleting) { return; }
    var id = currentConversation.id;
    var seq = chatSeq;
    var epoch = sessionEpoch;
    deleting = true;
    deleteYes.disabled = true;
    setStatus(chatStatus, "Deleting conversation…");
    api("/workspace/api/conversations/" + encodeURIComponent(id), { method: "DELETE" }).then(function (result) {
      if (epoch !== sessionEpoch) { return; }
      deleting = false;
      deleteYes.disabled = false;
      if (authFailure(result)) { return; }
      var stillCurrent = currentConversation && currentConversation.id === id && chatSeq === seq;
      deleteConfirm.hidden = true;
      if (result.status === 403) {
        if (stillCurrent) { setStatus(chatStatus, "You do not have permission to delete this conversation.", "denied"); }
        return;
      }
      if (result.status === 409) {
        if (stillCurrent) { setStatus(chatStatus, "The conversation is busy. Try deleting it again after the reply finishes.", "warning"); }
        return;
      }
      if (!result.ok) {
        if (stillCurrent) { setStatus(chatStatus, serverMessage(result, timeoutOrNetwork(result)), "error"); }
        return;
      }
      loadConversations(true);
      delete drafts[id];
      if (!stillCurrent) { return; }
      currentConversation = null;
      chatMeta.textContent = "";
      deleteButton.hidden = true;
      clearNode(messagesEl);
      chatEmpty.hidden = false;
      chatEmpty.textContent = "Conversation deleted. Start a new conversation when ready.";
      composer.value = "";
      updateComposer();
      setStatus(chatStatus, "Conversation and messages deleted.", "ok");
    });
  });

  function setViewTabs(view) {
    tabChat.setAttribute("aria-selected", view === "chat" ? "true" : "false");
    tabReview.setAttribute("aria-selected", view === "review" ? "true" : "false");
    tabAdmin.setAttribute("aria-selected", view === "admin" ? "true" : "false");
    chatPanel.hidden = view !== "chat";
    reviewPanel.hidden = view !== "review";
    adminPanel.hidden = view !== "admin";
  }

  function showView(view) {
    if (view === "review" && (!profile || !profile.reviewScope)) {
      setStatus(globalStatus, "Review access is not available for this account.", "denied");
      return;
    }
    if (view === "admin" && (!profile || !profile.user || profile.user.role !== "admin")) {
      setStatus(globalStatus, "Administrator access is not available for this account.", "denied");
      return;
    }
    currentView = view;
    setViewTabs(view);
    topbarTitle.textContent = view === "review" ? "Review" : (view === "admin" ? "Account administration" : "Chat");
    setSidebar(false);
    if (view === "review" && !reviewLoaded) { loadReviewConversations(true); }
    if (view === "chat" && !listLoaded) { loadConversations(true); }
    if (view === "admin") { loadAdminPanels(); }
  }

  tabChat.addEventListener("click", function () { showView("chat"); });
  tabReview.addEventListener("click", function () { showView("review"); });
  tabAdmin.addEventListener("click", function () { showView("admin"); });

  function renderReviewList(items, reset) {
    if (reset) { clearNode(reviewList); }
    for (var i = 0; i < items.length; i += 1) {
      (function (item) {
        if (!isObject(item) || typeof item.id !== "string") { return; }
        var owner = typeof item.owner_full_name === "string" ? item.owner_full_name : "Unknown employee";
        var department = typeof item.department_name === "string" ? item.department_name : "Unknown department";
        var button = makeItem("Conversation", owner + " · " + department + " · " +
          shortId(item.id) + " · " + formatDate(item.updated_at || item.created_at), function () {
          openReviewConversation(item.id);
        });
        button.setAttribute("data-conversation", item.id);
        reviewList.appendChild(button);
      }(items[i]));
    }
  }

  function loadReviewConversations(reset) {
    if (!signedIn || reviewLoading || !profile || !profile.reviewScope) { return Promise.resolve(false); }
    var epoch = sessionEpoch;
    reviewLoading = true;
    if (reset) {
      reviewCursor = null;
      reviewLoaded = false;
      clearNode(reviewList);
      setStatus(reviewState, "Loading authorised conversations…");
    } else {
      setStatus(reviewState, "Loading more…");
    }
    var path = "/workspace/api/review/conversations?limit=" + LIST_LIMIT +
      (reviewCursor ? "&after=" + encodeURIComponent(reviewCursor) : "");
    return api(path).then(function (result) {
      if (epoch !== sessionEpoch) { return false; }
      reviewLoading = false;
      if (authFailure(result)) { return false; }
      if (result.status === 403) {
        setStatus(reviewState, "Review permission was denied. Your grants may have changed.", "denied");
        refreshReviewAccess();
        return false;
      }
      if (!result.ok || !isObject(result.data) || !Array.isArray(result.data.items)) {
        setStatus(reviewState, serverMessage(result, timeoutOrNetwork(result)), "error");
        return false;
      }
      renderReviewList(result.data.items, reset);
      reviewCursor = typeof result.data.next === "string" && result.data.next ? result.data.next : null;
      reviewLoadMore.hidden = !reviewCursor;
      reviewLoaded = true;
      if (reset && result.data.items.length === 0) {
        setStatus(reviewState, "No conversations are in your authorised review scope.");
      } else {
        setStatus(reviewState, reviewCursor ? "More conversations available." : "");
      }
      return true;
    });
  }

  reviewLoadMore.addEventListener("click", function () { loadReviewConversations(false); });

  function clearReviewAccessState() {
    reviewLoading = false;
    reviewLoaded = false;
    reviewCursor = null;
    reviewDetailSeq += 1;
    clearNode(reviewList);
    clearNode(reviewMessages);
    reviewMeta.textContent = "";
    reviewEmpty.textContent = "Select a conversation to review.";
    reviewEmpty.hidden = false;
    reviewLoadMore.hidden = true;
    setStatus(reviewState, "");
  }

  function refreshReviewAccess() {
    var epoch = sessionEpoch;
    var previousScope = profile ? profile.reviewScope : null;
    var previousDepartments = profile && Array.isArray(profile.reviewDepartmentIds)
      ? profile.reviewDepartmentIds.join("|") : "";
    var wasReviewView = currentView === "review";
    return api("/workspace/api/me").then(function (result) {
      if (epoch !== sessionEpoch) { return; }
      if (authFailure(result)) { return; }
      if (!result.ok) { return; }
      try { applyProfile(result.data); }
      catch (error) { return; }
      var currentScope = profile.reviewScope;
      var currentDepartments = Array.isArray(profile.reviewDepartmentIds)
        ? profile.reviewDepartmentIds.join("|") : "";
      if (currentScope !== previousScope || currentDepartments !== previousDepartments) {
        clearReviewAccessState();
        if (currentScope && currentView === "review") {
          loadReviewConversations(true);
          return;
        }
      }
      if (!currentScope && wasReviewView) {
        showView("chat");
        setStatus(globalStatus, "Review access was removed. Chat remains available.", "denied");
      }
    });
  }

  function openReviewConversation(id) {
    if (!signedIn || typeof id !== "string") { return; }
    reviewDetailSeq += 1;
    var seq = reviewDetailSeq;
    var epoch = sessionEpoch;
    reviewEmpty.hidden = true;
    reviewMeta.textContent = "Loading conversation…";
    clearNode(reviewMessages);
    api("/workspace/api/review/conversations/" + encodeURIComponent(id)).then(function (result) {
      if (seq !== reviewDetailSeq || epoch !== sessionEpoch) { return; }
      if (authFailure(result)) { return; }
      if (result.status === 403) {
        reviewMeta.textContent = "Permission denied for this conversation. This access attempt was not expanded.";
        setStatus(reviewState, "Review permission was denied. Rechecking your grants.", "denied");
        refreshReviewAccess();
        return;
      }
      if (!result.ok || !isObject(result.data) || !Array.isArray(result.data.messages)) {
        reviewMeta.textContent = serverMessage(result, timeoutOrNetwork(result));
        setStatus(reviewState, "The conversation could not be opened.", "error");
        return;
      }
      var data = result.data;
      var owner = typeof data.owner_full_name === "string" ? data.owner_full_name : "Unknown employee";
      var department = typeof data.department_name === "string" ? data.department_name : "Unknown department";
      reviewMeta.textContent = "Owner: " + owner + " · Department: " + department +
        " · Conversation " + shortId(data.id) + " · started " + formatDate(data.created_at) +
        " · original content, read-only. This access is recorded in the workspace access log.";
      renderMessages(reviewMessages, data.messages);
      reviewEmpty.hidden = data.messages.length > 0;
      reviewEmpty.textContent = "This conversation has no messages.";
      setStatus(reviewState, "");
    });
  }


  function adminGuard(result, node) {
    if (authFailure(result)) { return true; }
    if (result.status === 403) {
      setStatus(node, "Administrator permission was denied by the server.", "denied");
      return true;
    }
    return false;
  }

  function appendEmpty(container, text) {
    var empty = document.createElement("p");
    empty.className = "admin-empty";
    empty.textContent = text;
    container.appendChild(empty);
  }

  function removeActiveConfirm() {
    if (adminActiveConfirm && adminActiveConfirm.parentNode) {
      adminActiveConfirm.parentNode.removeChild(adminActiveConfirm);
    }
    adminActiveConfirm = null;
  }

  function askConfirm(container, question, label, onConfirm) {
    removeActiveConfirm();
    var box = document.createElement("div");
    box.className = "admin-confirm";
    var copy = document.createElement("p");
    copy.textContent = question;
    var yes = document.createElement("button");
    yes.type = "button";
    yes.className = "danger";
    yes.textContent = label;
    var no = document.createElement("button");
    no.type = "button";
    no.className = "ghost";
    no.textContent = "Cancel";
    no.addEventListener("click", function () {
      if (box.parentNode) { box.parentNode.removeChild(box); }
      if (adminActiveConfirm === box) { adminActiveConfirm = null; }
      try { container.focus(); } catch (error) { /* non-fatal */ }
    });
    yes.addEventListener("click", function () {
      yes.disabled = true;
      no.disabled = true;
      onConfirm(box);
    });
    box.appendChild(copy);
    box.appendChild(yes);
    box.appendChild(no);
    container.appendChild(box);
    adminActiveConfirm = box;
    try { no.focus(); } catch (error) { /* non-fatal */ }
  }

  function departmentLabel(id) {
    for (var i = 0; i < adminDepartments.length; i += 1) {
      if (adminDepartments[i].id === id) { return adminDepartments[i].name; }
    }
    return typeof id === "string" && id ? "Department " + shortId(id) : "No department";
  }

  function fillSelect(select, items, placeholder, labeller) {
    var previous = select.value;
    clearNode(select);
    var first = document.createElement("option");
    first.value = "";
    first.textContent = placeholder;
    select.appendChild(first);
    var found = false;
    for (var i = 0; i < items.length; i += 1) {
      var item = items[i];
      if (!isObject(item) || typeof item.id !== "string") { continue; }
      var option = document.createElement("option");
      option.value = item.id;
      option.textContent = labeller(item);
      select.appendChild(option);
      if (item.id === previous) { found = true; }
    }
    select.value = found ? previous : "";
  }

  function syncDepartmentOptions() {
    fillSelect(userDepartment, adminDepartments, "Select a department", function (item) { return item.name; });
    fillSelect(grantDepartment, adminDepartments, "Select a department", function (item) { return item.name; });
    fillSelect(grantUser, adminUsers, "Select a reviewer", function (item) {
      return "@" + item.username + " (" + item.full_name + ")";
    });
  }

  function syncGrantForm() {
    var global = grantScope.value === "global";
    grantDepartmentField.hidden = global;
    grantDepartment.disabled = global;
    grantGlobalField.hidden = !global;
    if (!global) { grantGlobalConfirm.checked = false; }
  }

  function renderDepartments(items, reset) {
    if (reset) { clearNode(departmentList); }
    if (reset && items.length === 0) { appendEmpty(departmentList, "No departments have been created."); }
    for (var i = 0; i < items.length; i += 1) {
      var item = items[i];
      if (!isObject(item) || typeof item.id !== "string" || typeof item.name !== "string") { continue; }
      var row = document.createElement("div");
      row.className = "admin-row";
      var main = document.createElement("div");
      main.className = "admin-row-main";
      main.textContent = item.name;
      var meta = document.createElement("div");
      meta.className = "admin-row-meta";
      meta.textContent = "Created " + formatDate(item.created_at);
      row.appendChild(main);
      row.appendChild(meta);
      departmentList.appendChild(row);
    }
  }

  function openPasswordReset(row, item) {
    removeActiveConfirm();
    if (row.adminResetForm && row.adminResetForm.parentNode) {
      row.adminResetForm.parentNode.removeChild(row.adminResetForm);
    }
    var form = document.createElement("form");
    form.className = "admin-reset";
    form.setAttribute("aria-label", "Reset password for " + item.username);
    var label = document.createElement("label");
    label.textContent = "New password for @" + item.username + " (at least 12 characters)";
    var input = document.createElement("input");
    input.type = "password";
    input.className = "admin-reset-input";
    input.autocomplete = "new-password";
    input.minLength = 12;
    input.setAttribute("maxlength", "128");
    input.required = true;
    label.setAttribute("for", "reset-password-" + item.id);
    input.id = "reset-password-" + item.id;
    var actions = document.createElement("div");
    actions.className = "admin-reset-actions";
    var confirmButton = document.createElement("button");
    confirmButton.type = "submit";
    confirmButton.className = "danger";
    confirmButton.textContent = "Confirm reset";
    var cancelButton = document.createElement("button");
    cancelButton.type = "button";
    cancelButton.className = "ghost";
    cancelButton.textContent = "Cancel";
    cancelButton.addEventListener("click", function () {
      if (form.parentNode) { form.parentNode.removeChild(form); }
      row.adminResetForm = null;
      try { row.focus(); } catch (error) { /* non-fatal */ }
    });
    form.addEventListener("submit", function (event) {
      event.preventDefault();
      if (resettingPassword) { return; }
      var password = input.value;
      if (password.length < 12) {
        input.value = "";
        setStatus(adminStatus, "The new password must be at least 12 characters. Nothing was changed.", "error");
        input.focus();
        return;
      }
      input.value = "";
      resettingPassword = true;
      confirmButton.disabled = true;
      cancelButton.disabled = true;
      setStatus(adminStatus, "Resetting password…");
      var epoch = sessionEpoch;
      api("/workspace/api/admin/users/" + encodeURIComponent(item.id) + "/reset-password", {
        method: "POST",
        body: JSON.stringify({ password: password })
      }).then(function (result) {
        if (epoch !== sessionEpoch) { return; }
        resettingPassword = false;
        confirmButton.disabled = false;
        cancelButton.disabled = false;
        if (adminGuard(result, adminStatus)) { return; }
        if (!result.ok) {
          setStatus(adminStatus, serverMessage(result, timeoutOrNetwork(result)), "error");
          return;
        }
        setStatus(adminStatus, "Password reset for @" + item.username + ". Existing sign-ins for this account were revoked.", "ok");
        if (form.parentNode) { form.parentNode.removeChild(form); }
        row.adminResetForm = null;
      });
    });
    actions.appendChild(confirmButton);
    actions.appendChild(cancelButton);
    form.appendChild(label);
    form.appendChild(input);
    form.appendChild(actions);
    row.appendChild(form);
    row.adminResetForm = form;
    try { input.focus(); } catch (error) { /* non-fatal */ }
  }

  function renderUsers(items, reset) {
    if (reset) { clearNode(userList); }
    if (reset && items.length === 0) { appendEmpty(userList, "No user accounts have been created."); }
    var selfId = profile && profile.user ? profile.user.id : null;
    for (var i = 0; i < items.length; i += 1) {
      var item = items[i];
      if (!isObject(item) || typeof item.id !== "string" || typeof item.username !== "string") { continue; }
      var row = document.createElement("div");
      row.className = "admin-row";
      row.setAttribute("data-user", item.id);
      var main = document.createElement("div");
      main.className = "admin-row-main";
      main.textContent = (typeof item.full_name === "string" ? item.full_name : "Unknown name") +
        " (@" + item.username + ")";
      var meta = document.createElement("div");
      meta.className = "admin-row-meta";
      var metaText = (item.role === "admin" ? "Administrator" : "Employee") + " · " +
        departmentLabel(item.department_id) + " · " + (item.disabled ? "Disabled" : "Active");
      if (item.id === selfId) { metaText += " · This is your account"; }
      meta.textContent = metaText;
      row.appendChild(main);
      row.appendChild(meta);
      var actions = document.createElement("div");
      actions.className = "admin-row-actions";
      if (!item.disabled && item.id !== selfId) {
        var disableButton = document.createElement("button");
        disableButton.type = "button";
        disableButton.className = "danger";
        disableButton.textContent = "Disable";
        disableButton.addEventListener("click", function (target, userItem) {
          return function () {
            askConfirm(target, "Disable @" + userItem.username +
              "? Their existing sign-ins are revoked. Conversation history is kept.",
              "Confirm disable", function () {
                var epoch = sessionEpoch;
                setStatus(adminStatus, "Disabling @" + userItem.username + "…");
                api("/workspace/api/admin/users/" + encodeURIComponent(userItem.id) + "/disable", {
                  method: "POST",
                  body: "{}"
                }).then(function (result) {
                  if (epoch !== sessionEpoch) { return; }
                  if (adminGuard(result, adminStatus)) { return; }
                  if (!result.ok) {
                    setStatus(adminStatus, serverMessage(result, timeoutOrNetwork(result)), "error");
                    return;
                  }
                  setStatus(adminStatus, "Account @" + userItem.username +
                    " disabled. Existing sign-ins were revoked.", "ok");
                  queueAdminList(function () { return loadUsers(true); }).then(function (ok) {
                    if (!ok && epoch === sessionEpoch) {
                      setStatus(adminStatus, "Account disabled, but the list could not be refreshed.", "warning");
                    }
                  });
                });
              });
          };
        }(row, item));
        actions.appendChild(disableButton);
      }
      var resetButton = document.createElement("button");
      resetButton.type = "button";
      resetButton.className = "ghost";
      resetButton.textContent = "Reset password";
      resetButton.addEventListener("click", function (target, userItem) {
        return function () { openPasswordReset(target, userItem); };
      }(row, item));
      actions.appendChild(resetButton);
      row.appendChild(actions);
      userList.appendChild(row);
    }
  }

  function renderGrants(items, reset) {
    if (reset) { clearNode(grantList); }
    if (reset && items.length === 0) { appendEmpty(grantList, "No review grants exist."); }
    for (var i = 0; i < items.length; i += 1) {
      var item = items[i];
      if (!isObject(item) || typeof item.id !== "string" || typeof item.username !== "string") { continue; }
      var row = document.createElement("div");
      row.className = "admin-row";
      var main = document.createElement("div");
      main.className = "admin-row-main";
      var scopeText = item.scope === "global"
        ? "Global · all departments"
        : "Department · " + (typeof item.department_name === "string" && item.department_name
          ? item.department_name : departmentLabel(item.department_id));
      main.textContent = "@" + item.username + " · " + scopeText;
      var meta = document.createElement("div");
      meta.className = "admin-row-meta";
      meta.textContent = "Granted " + formatDate(item.created_at);
      var actions = document.createElement("div");
      actions.className = "admin-row-actions";
      var revokeButton = document.createElement("button");
      revokeButton.type = "button";
      revokeButton.className = "danger";
      revokeButton.textContent = "Revoke";
      revokeButton.addEventListener("click", function (target, grant) {
        return function () {
          askConfirm(target, "Revoke review access for @" + grant.username +
            "? This removes read access to original confidential chat text in this scope.",
            "Revoke grant", function () {
              var epoch = sessionEpoch;
              setStatus(adminStatus, "Revoking review access…");
              api("/workspace/api/admin/review-grants/" + encodeURIComponent(grant.id), {
                method: "DELETE"
              }).then(function (result) {
                if (epoch !== sessionEpoch) { return; }
                if (adminGuard(result, adminStatus)) { return; }
                if (!result.ok) {
                  setStatus(adminStatus, serverMessage(result, timeoutOrNetwork(result)), "error");
                  return;
                }
                setStatus(adminStatus, "Review access revoked for @" + grant.username + ".", "ok");
                queueAdminList(function () { return loadGrants(true); }).then(function (ok) {
                  if (!ok && epoch === sessionEpoch) {
                    setStatus(adminStatus, "Access revoked, but the grant list could not be refreshed.", "warning");
                  }
                });
                refreshReviewAccess();
              });
            });
        };
      }(row, item));
      actions.appendChild(revokeButton);
      row.appendChild(main);
      row.appendChild(meta);
      row.appendChild(actions);
      grantList.appendChild(row);
    }
  }

  function renderAccess(items, reset) {
    if (reset) { clearNode(accessList); }
    if (reset && items.length === 0) { appendEmpty(accessList, "The access log is empty."); }
    for (var i = 0; i < items.length; i += 1) {
      var item = items[i];
      if (!isObject(item) || typeof item.action !== "string") { continue; }
      var row = document.createElement("div");
      row.className = "admin-row";
      var main = document.createElement("div");
      main.className = "admin-row-main";
      main.textContent = item.action + " · actor " + shortId(item.actor_id);
      var meta = document.createElement("div");
      meta.className = "admin-row-meta";
      meta.textContent = "Department: " + departmentLabel(item.department_id) +
        " · Conversation: " + (typeof item.conversation_id === "string" && item.conversation_id
          ? shortId(item.conversation_id) : "none") +
        " · " + formatDate(item.created_at);
      row.appendChild(main);
      row.appendChild(meta);
      accessList.appendChild(row);
    }
  }

  function loadDepartments(reset) {
    if (!signedIn || departmentLoading) { return Promise.resolve(false); }
    var epoch = sessionEpoch;
    departmentLoading = true;
    if (reset) {
      departmentCursor = null;
      clearNode(departmentList);
      setStatus(departmentState, "Loading departments…");
    } else {
      setStatus(departmentState, "Loading more departments…");
    }
    var path = "/workspace/api/admin/departments?limit=" + LIST_LIMIT +
      (departmentCursor ? "&after=" + encodeURIComponent(departmentCursor) : "");
    return api(path).then(function (result) {
      if (epoch !== sessionEpoch) { return false; }
      departmentLoading = false;
      if (adminGuard(result, departmentState)) { return false; }
      if (!result.ok || !isObject(result.data) || !Array.isArray(result.data.items)) {
        setStatus(departmentState, serverMessage(result, timeoutOrNetwork(result)), "error");
        return false;
      }
      var got = [];
      for (var i = 0; i < result.data.items.length; i += 1) {
        var item = result.data.items[i];
        if (isObject(item) && typeof item.id === "string" && typeof item.name === "string") {
          got.push({ id: item.id, name: item.name, created_at: item.created_at });
        }
      }
      adminDepartments = reset ? got : adminDepartments.concat(got);
      renderDepartments(got, reset);
      departmentCursor = typeof result.data.next === "string" && result.data.next ? result.data.next : null;
      departmentMore.hidden = !departmentCursor;
      setStatus(departmentState, reset && got.length === 0
        ? "No departments have been created."
        : (departmentCursor ? "More departments available." : ""));
      syncDepartmentOptions();
      return true;
    });
  }

  function loadUsers(reset) {
    if (!signedIn || userLoading) { return Promise.resolve(false); }
    var epoch = sessionEpoch;
    userLoading = true;
    if (reset) {
      userCursor = null;
      clearNode(userList);
      setStatus(userState, "Loading user accounts…");
    } else {
      setStatus(userState, "Loading more users…");
    }
    var path = "/workspace/api/admin/users?limit=" + LIST_LIMIT +
      (userCursor ? "&after=" + encodeURIComponent(userCursor) : "");
    return api(path).then(function (result) {
      if (epoch !== sessionEpoch) { return false; }
      userLoading = false;
      if (adminGuard(result, userState)) { return false; }
      if (!result.ok || !isObject(result.data) || !Array.isArray(result.data.items)) {
        setStatus(userState, serverMessage(result, timeoutOrNetwork(result)), "error");
        return false;
      }
      var got = [];
      for (var i = 0; i < result.data.items.length; i += 1) {
        var item = result.data.items[i];
        if (isObject(item) && typeof item.id === "string" && typeof item.username === "string") {
          got.push(item);
        }
      }
      adminUsers = reset ? got : adminUsers.concat(got);
      renderUsers(got, reset);
      userCursor = typeof result.data.next === "string" && result.data.next ? result.data.next : null;
      userMore.hidden = !userCursor;
      setStatus(userState, reset && got.length === 0
        ? "No user accounts have been created."
        : (userCursor ? "More users available." : ""));
      syncDepartmentOptions();
      return true;
    });
  }

  function loadGrants(reset) {
    if (!signedIn || grantLoading) { return Promise.resolve(false); }
    var epoch = sessionEpoch;
    grantLoading = true;
    if (reset) {
      grantCursor = null;
      clearNode(grantList);
      setStatus(grantState, "Loading review grants…");
    } else {
      setStatus(grantState, "Loading more grants…");
    }
    var path = "/workspace/api/admin/review-grants?limit=" + LIST_LIMIT +
      (grantCursor ? "&after=" + encodeURIComponent(grantCursor) : "");
    return api(path).then(function (result) {
      if (epoch !== sessionEpoch) { return false; }
      grantLoading = false;
      if (adminGuard(result, grantState)) { return false; }
      if (!result.ok || !isObject(result.data) || !Array.isArray(result.data.items)) {
        setStatus(grantState, serverMessage(result, timeoutOrNetwork(result)), "error");
        return false;
      }
      var got = [];
      for (var i = 0; i < result.data.items.length; i += 1) {
        var item = result.data.items[i];
        if (isObject(item) && typeof item.id === "string") { got.push(item); }
      }
      renderGrants(got, reset);
      grantCursor = typeof result.data.next === "string" && result.data.next ? result.data.next : null;
      grantMore.hidden = !grantCursor;
      setStatus(grantState, reset && got.length === 0
        ? "No review grants exist."
        : (grantCursor ? "More grants available." : ""));
      return true;
    });
  }

  function loadAccessLog(reset) {
    if (!signedIn || accessLoading) { return Promise.resolve(false); }
    var epoch = sessionEpoch;
    accessLoading = true;
    if (reset) {
      accessCursor = null;
      clearNode(accessList);
      setStatus(accessState, "Loading access log…");
    } else {
      setStatus(accessState, "Loading more access events…");
    }
    var path = "/workspace/api/admin/access-log?limit=" + LIST_LIMIT +
      (accessCursor ? "&after=" + encodeURIComponent(accessCursor) : "");
    return api(path).then(function (result) {
      if (epoch !== sessionEpoch) { return false; }
      accessLoading = false;
      if (adminGuard(result, accessState)) { return false; }
      if (!result.ok || !isObject(result.data) || !Array.isArray(result.data.items)) {
        setStatus(accessState, serverMessage(result, timeoutOrNetwork(result)), "error");
        return false;
      }
      var got = [];
      for (var i = 0; i < result.data.items.length; i += 1) {
        var item = result.data.items[i];
        if (isObject(item) && typeof item.action === "string") { got.push(item); }
      }
      renderAccess(got, reset);
      accessCursor = typeof result.data.next === "string" && result.data.next ? result.data.next : null;
      accessMore.hidden = !accessCursor;
      setStatus(accessState, reset && got.length === 0
        ? "The access log is empty."
        : (accessCursor ? "More access events available." : ""));
      return true;
    });
  }

  function queueAdminList(loader) {
    var epoch = sessionEpoch;
    function run() {
      if (epoch !== sessionEpoch || !signedIn) { return false; }
      return loader();
    }
    var result = adminListChain.then(run, run);
    adminListChain = result.then(function () {}, function () {});
    return result;
  }

  function loadAdminPanels() {
    if (!signedIn || !profile || !profile.user || profile.user.role !== "admin") { return; }
    adminLoaded = true;
    setStatus(adminStatus, "Loading account administration data…");
    var epoch = sessionEpoch;
    Promise.all([
      queueAdminList(function () { return loadDepartments(true); }),
      queueAdminList(function () { return loadUsers(true); }),
      queueAdminList(function () { return loadGrants(true); }),
      queueAdminList(function () { return loadAccessLog(true); })
    ]).then(function (results) {
      if (epoch !== sessionEpoch) { return; }
      var allOk = true;
      for (var i = 0; i < results.length; i += 1) { if (!results[i]) { allOk = false; } }
      if (!allOk && adminStatus.getAttribute("data-kind") !== "denied") {
        setStatus(adminStatus, "Some account data could not be loaded. Check each list for details.", "warning");
      } else if (allOk) {
        setStatus(adminStatus, "");
      }
    });
  }

  function resetAdminState() {
    adminLoaded = false;
    adminDepartments = [];
    adminUsers = [];
    departmentCursor = null;
    userCursor = null;
    grantCursor = null;
    accessCursor = null;
    departmentLoading = false;
    userLoading = false;
    grantLoading = false;
    accessLoading = false;
    creatingDepartment = false;
    creatingUser = false;
    granting = false;
    resettingPassword = false;
    adminActiveConfirm = null;
    if (departmentName) { departmentName.value = ""; }
    if (userUsername) { userUsername.value = ""; }
    if (userFullName) { userFullName.value = ""; }
    if (userPassword) { userPassword.value = ""; }
    if (userRole) { userRole.value = "employee"; }
    if (grantScope) { grantScope.value = "department"; }
    if (grantGlobalConfirm) { grantGlobalConfirm.checked = false; }
    if (departmentSubmit) { departmentSubmit.disabled = false; }
    if (userSubmit) { userSubmit.disabled = false; }
    if (grantSubmit) { grantSubmit.disabled = false; }
    clearNode(departmentList);
    clearNode(userList);
    clearNode(grantList);
    clearNode(accessList);
    clearNode(userDepartment);
    clearNode(grantDepartment);
    clearNode(grantUser);
    departmentMore.hidden = true;
    userMore.hidden = true;
    grantMore.hidden = true;
    accessMore.hidden = true;
    setStatus(departmentState, "");
    setStatus(userState, "");
    setStatus(grantState, "");
    setStatus(accessState, "");
    setStatus(adminStatus, "");
    syncGrantForm();
  }

  departmentForm.addEventListener("submit", function (event) {
    event.preventDefault();
    if (!signedIn || creatingDepartment) { return; }
    var name = departmentName.value.trim();
    if (!name) {
      setStatus(adminStatus, "Enter a department name.", "error");
      departmentName.focus();
      return;
    }
    creatingDepartment = true;
    departmentSubmit.disabled = true;
    setStatus(adminStatus, "Creating department…");
    var epoch = sessionEpoch;
    api("/workspace/api/admin/departments", {
      method: "POST",
      body: JSON.stringify({ name: name })
    }).then(function (result) {
      if (epoch !== sessionEpoch) { return; }
      creatingDepartment = false;
      departmentSubmit.disabled = false;
      if (adminGuard(result, adminStatus)) { return; }
      if (!result.ok) {
        setStatus(adminStatus, serverMessage(result, timeoutOrNetwork(result)), "error");
        return;
      }
      departmentName.value = "";
      setStatus(adminStatus, "Department created.", "ok");
      queueAdminList(function () { return loadDepartments(true); }).then(function (ok) {
        if (!ok && epoch === sessionEpoch) {
          setStatus(adminStatus, "Department created, but the list could not be refreshed.", "warning");
        }
      });
    });
  });

  userForm.addEventListener("submit", function (event) {
    event.preventDefault();
    if (!signedIn || creatingUser) { return; }
    var username = userUsername.value.trim();
    var fullName = userFullName.value.trim();
    var departmentId = userDepartment.value;
    var role = userRole.value === "admin" ? "admin" : "employee";
    var password = userPassword.value;
    if (!username || !fullName || !departmentId) {
      setStatus(adminStatus, "Enter a username, full name and department.", "error");
      return;
    }
    if (password.length < 12) {
      userPassword.value = "";
      setStatus(adminStatus, "The initial password must be at least 12 characters. Nothing was created.", "error");
      userPassword.focus();
      return;
    }
    userPassword.value = "";
    creatingUser = true;
    userSubmit.disabled = true;
    setStatus(adminStatus, "Creating user account…");
    var epoch = sessionEpoch;
    api("/workspace/api/admin/users", {
      method: "POST",
      body: JSON.stringify({
        username: username,
        full_name: fullName,
        department_id: departmentId,
        role: role,
        password: password
      })
    }).then(function (result) {
      if (epoch !== sessionEpoch) { return; }
      creatingUser = false;
      userSubmit.disabled = false;
      if (adminGuard(result, adminStatus)) { return; }
      if (!result.ok) {
        setStatus(adminStatus, serverMessage(result, timeoutOrNetwork(result)), "error");
        return;
      }
      userUsername.value = "";
      userFullName.value = "";
      userPassword.value = "";
      setStatus(adminStatus, "User account created. Share the initial password separately; it is never shown again.", "ok");
      queueAdminList(function () { return loadUsers(true); }).then(function (ok) {
        if (!ok && epoch === sessionEpoch) {
          setStatus(adminStatus, "Account created, but the user list could not be refreshed.", "warning");
        }
      });
    });
  });

  grantScope.addEventListener("change", syncGrantForm);

  grantForm.addEventListener("submit", function (event) {
    event.preventDefault();
    if (!signedIn || granting) { return; }
    var userId = grantUser.value;
    var scope = grantScope.value === "global" ? "global" : "department";
    if (!userId) {
      setStatus(adminStatus, "Select a reviewer for the grant.", "error");
      return;
    }
    var payload = { user_id: userId, scope: scope };
    if (scope === "department") {
      if (!grantDepartment.value) {
        setStatus(adminStatus, "Select a department for a department-scoped grant.", "error");
        return;
      }
      payload.department_id = grantDepartment.value;
    } else if (!grantGlobalConfirm.checked) {
      setStatus(adminStatus, "A global grant requires the explicit confirmation checkbox.", "error");
      grantGlobalConfirm.focus();
      return;
    }
    grantGlobalConfirm.checked = false;
    granting = true;
    grantSubmit.disabled = true;
    setStatus(adminStatus, "Granting review access…");
    var epoch = sessionEpoch;
    api("/workspace/api/admin/review-grants", {
      method: "POST",
      body: JSON.stringify(payload)
    }).then(function (result) {
      if (epoch !== sessionEpoch) { return; }
      granting = false;
      grantSubmit.disabled = false;
      if (adminGuard(result, adminStatus)) { return; }
      if (!result.ok) {
        setStatus(adminStatus, serverMessage(result, timeoutOrNetwork(result)), "error");
        return;
      }
      setStatus(adminStatus, scope === "global"
        ? "Global review grant created. This grants access to original confidential chat text in every department."
        : "Department review grant created.", "ok");
      queueAdminList(function () { return loadGrants(true); }).then(function (ok) {
        if (!ok && epoch === sessionEpoch) {
          setStatus(adminStatus, "Grant created, but the grant list could not be refreshed.", "warning");
        }
      });
      refreshReviewAccess();
    });
  });

  departmentMore.addEventListener("click", function () {
    queueAdminList(function () { return loadDepartments(false); });
  });
  userMore.addEventListener("click", function () {
    queueAdminList(function () { return loadUsers(false); });
  });
  grantMore.addEventListener("click", function () {
    queueAdminList(function () { return loadGrants(false); });
  });
  accessMore.addEventListener("click", function () {
    queueAdminList(function () { return loadAccessLog(false); });
  });

  function setGuardStatus(label, detail, inactive) {
    guardSummary.textContent = label;
    guardDetail.textContent = detail;
    if (inactive) { guardStatus.setAttribute("data-kind", "inactive"); }
    else { guardStatus.removeAttribute("data-kind"); }
    guardStatus.open = false;
  }

  function loadGuardStatus() {
    api("/health/ready", { independent: true }).then(function (result) {
      if (!result.ok || !isObject(result.data)) {
        setGuardStatus(
          "Unavailable",
          "Guard status is unavailable — the readiness check did not succeed. " +
            "Do not rely on model guard protection.",
          true
        );
        return;
      }
      var mode = typeof result.data.mode === "string" ? result.data.mode : "unknown";
      var configured = result.data.guards_active === true;
      var ready = result.data.status === "ready" && result.data.workspace !== "not_ready";
      if (configured && ready) {
        setGuardStatus(
          "Configured",
          "Model guard is configured. Readiness: ready. Deterministic checks still apply.",
          false
        );
      } else if (configured) {
        setGuardStatus(
          "Unavailable",
          "Model guard is configured but unavailable — readiness is not ready. " +
            "Do not rely on model guard protection.",
          true
        );
      } else {
        setGuardStatus(
          "Inactive",
          "Model guard is inactive — model-based checks are not running in " + mode +
            " mode. Deterministic checks may still apply.",
          true
        );
      }
      if (result.data.workspace === "not_ready") {
        guardDetail.textContent += " Workspace readiness is not ready.";
      }
    });
  }

  function restoreSession() {
    // A restore supersedes any profile check started for an earlier cookie, so
    // a buffered reply cannot paint a stale identity after a peer change.
    var seq = ++sessionCheckSeq;
    var epoch = sessionEpoch;
    authView.hidden = true;
    workspaceView.hidden = true;
    revalidateRetry.hidden = true;
    appEl.setAttribute("data-private", "hidden");
    setStatus(globalStatus, "Checking your session…");
    loadProfile({
      initial: true,
      isCurrent: function () { return seq === sessionCheckSeq; }
    }).then(function (loaded) {
      if (seq !== sessionCheckSeq || epoch !== sessionEpoch) { return; }
      if (loaded && signedIn && profile) {
        appEl.removeAttribute("data-private");
        topbarTitle.textContent = "Chat";
        setStatus(globalStatus, "");
        loadConversations(true);
        return;
      }
      if (!signedIn) {
        authView.hidden = false;
        if (!authStatus.textContent) {
          setStatus(authStatus, "Sign in to continue.", "");
        }
        if (authStatus.getAttribute("data-kind") === "error") {
          setStatus(globalStatus, authStatus.textContent, "warning");
          revalidateRetry.hidden = false;
        }
      }
    });
  }

  revalidateRetry.addEventListener("click", function () {
    if (signedIn) { revalidate(); }
    else { restoreSession(); }
  });

  function revalidateIfSignedIn() {
    if (!signedIn) { return; }
    revalidate();
  }

  window.addEventListener("focus", revalidateIfSignedIn);
  window.addEventListener("pageshow", revalidateIfSignedIn);
  if (document.addEventListener) {
    document.addEventListener("visibilitychange", function () {
      if (!document.hidden) { revalidateIfSignedIn(); }
    });
  }
  if (typeof BroadcastChannel === "function") {
    try {
      // Only a change signal crosses tabs; no token, profile, prompt or draft
      // text is ever posted through this channel or any browser storage.
      authChannel = new BroadcastChannel("nasi_lemak_workspace_auth");
      authChannel.addEventListener("message", function (event) {
        if (!event || !isObject(event.data) || event.data.type !== "workspace-auth-changed") {
          return;
        }
        // A change announced by another tab supersedes any check already in
        // flight: its buffered /me reply answers for the pre-change cookie, so
        // it must not repaint private content.  Force a fresh check instead of
        // dropping the signal, while every surface stays withheld.
        if (signedIn) { revalidate(true); }
        else { restoreSession(); }
      });
    } catch (error) {
      authChannel = null;
    }
  }

  setViewTabs("chat");
  resetAdminState();
  authView.hidden = true;
  workspaceView.hidden = true;
  appEl.setAttribute("data-private", "hidden");
  logoutButton.hidden = true;
  deleteButton.hidden = true;
  deleteConfirm.hidden = true;
  composer.disabled = true;
  sendButton.disabled = true;
  updateComposer();
  loadGuardStatus();
  restoreSession();
}());
"""


def _csp_hash(text: str) -> str:
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return "'sha256-" + base64.b64encode(digest).decode("ascii") + "'"


_AVAILABILITY_MARKER = "<!-- AVAILABILITY -->"


WORKSPACE_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<meta name="theme-color" content="#0b0b0b">
<title>Workspace · Nasi Lemak</title>
<style>__WORKSPACE_CSS__</style>
</head>
<body>
<div class="app" id="app" data-nav="closed">
<aside class="sidebar" id="sidebar" aria-label="Workspace navigation">
<div class="brand">
<svg class="brand-mark" width="24" height="24" viewBox="0 0 24 24" fill="none" aria-hidden="true" focusable="false">
<circle cx="12" cy="12" r="9.2" stroke="currentColor" stroke-width="1.3"/>
<path d="M7.5 13.5c2.6 2.2 6.4 2.2 9 0M9 9.5h.01M15 9.5h.01" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>
</svg>
<div>
<h1>Nasi Lemak</h1>
<p>Employee workspace</p>
</div>
</div>
<div class="side-nav" role="tablist" aria-label="Workspace sections">
<button id="tab-chat" type="button" role="tab" aria-controls="chat-panel" aria-selected="true">Chat</button>
<button id="tab-review" type="button" role="tab" aria-controls="review-panel" aria-selected="false" hidden>Review</button>
<button id="tab-admin" type="button" role="tab" aria-controls="admin-panel" aria-selected="false" hidden>Admin</button>
</div>
<button id="new-chat" class="new-chat" type="button">
<svg width="15" height="15" viewBox="0 0 16 16" fill="none" aria-hidden="true" focusable="false">
<path d="M8 3v10M3 8h10" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>
</svg>
<span>New chat</span>
</button>
<div class="side-list-head"><h2>Conversations</h2></div>
<div id="conversation-list" class="conversation-list" aria-label="Your conversations"></div>
<p id="list-state" class="list-state" role="status" aria-live="polite"></p>
<button id="load-more" class="list-more" type="button" hidden>Load more</button>
<div class="side-foot">Your history is private to your account and authorised reviewers.</div>
</aside>
<main class="main">
<header class="topbar">
<button id="sidebar-toggle" class="icon-button" type="button" aria-controls="sidebar" aria-expanded="false">
<span class="sr-only">Toggle navigation</span>
<svg width="17" height="17" viewBox="0 0 18 18" fill="none" aria-hidden="true" focusable="false"><path d="M2.5 5h13M2.5 9h13M2.5 13h13" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>
</button>
<h2 id="topbar-title" class="topbar-title">Sign in</h2>
<details id="guard-status" class="guard-status">
<summary id="guard-summary" class="guard-summary">Guard status loading…</summary>
<p id="guard-detail" class="guard-detail" aria-live="polite"></p>
</details>
<div class="identity">
<span id="identity-name" class="identity-name"></span>
<span id="identity-meta" class="identity-meta"></span>
</div>
<button id="logout-button" class="ghost" type="button">Sign out</button>
</header>
<p id="global-status" class="global-status" role="status" aria-live="polite"></p>
<button id="revalidate-retry" class="retry-check" type="button" hidden>Retry session check</button>
<!-- AVAILABILITY -->
<div class="content">
<section id="auth-view" class="auth-view" aria-labelledby="login-heading">
<h2 id="login-heading">Sign in to your workspace</h2>
<p>Use the individual account provided by your administrator.</p>
<form id="login-form" novalidate>
<label for="username">Username</label>
<input id="username" name="username" type="text" autocomplete="username" autocapitalize="none" spellcheck="false" maxlength="128" required>
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="current-password" maxlength="128" required>
<button id="login-submit" class="primary" type="submit">Sign in</button>
</form>
<p id="auth-status" class="auth-status" role="status" aria-live="polite">Sign in to continue.</p>
<p class="foot">Your password is sent only to this workspace and is cleared from the form after each request. The server keeps your session in an HttpOnly cookie scoped to this workspace; this page never stores a token in browser storage or the URL.</p>
</section>
<section id="workspace-view" hidden>
<div id="chat-panel" class="panel" role="tabpanel" aria-labelledby="tab-chat">
<div class="chat-column">
<div class="conversation-head">
<div>
<h2 id="chat-title">Conversation</h2>
<p id="chat-meta" class="chat-meta"></p>
</div>
<div class="chat-actions">
<button id="delete-conversation" class="ghost" type="button" hidden>Delete</button>
</div>
</div>
<div id="delete-confirm" class="confirm" role="group" aria-label="Confirm conversation deletion" hidden>
<p>Delete this conversation and all of its messages permanently? This cannot be undone. Reviewers' recorded access metadata is kept.</p>
<button id="delete-yes" class="danger" type="button">Delete permanently</button>
<button id="delete-no" class="ghost" type="button">Cancel</button>
</div>
<div id="messages" class="messages" aria-label="Conversation messages"></div>
<div id="chat-empty" class="empty-state"><strong>No conversation selected</strong>Choose a saved conversation or start a new chat. Original prompts and delivered answers remain encrypted on the server.</div>
<p id="chat-status" class="chat-status" role="status" aria-live="polite"></p>
<div class="composer-wrap">
<form id="composer-form" class="composer" novalidate>
<label class="sr-only" for="composer">Message</label>
<textarea id="composer" maxlength="4096" rows="2" disabled placeholder="Select or create a conversation to send a message."></textarea>
<div class="composer-row">
<span id="composer-hint" class="composer-hint">Select or create a conversation to send a message.</span>
<button id="send" class="primary" type="submit" disabled>Send</button>
</div>
</form>
<details class="privacy-disclosure">
<summary>Privacy and storage</summary>
<p class="retention">Your original prompt and the delivered assistant reply are saved encrypted on the server until you delete the conversation. A blocked or failed prompt is saved with its outcome; no blocked assistant reply is stored.</p>
</details>
</div>
</div>
</div>
<div id="review-panel" class="review-view" role="tabpanel" aria-labelledby="tab-review" hidden>
<h2>Authorised review</h2>
<p class="review-notice">Read-only view of original prompts and delivered replies inside your explicit review grant. Every review list and conversation access is recorded in the workspace access log. Administrators without a grant cannot read transcripts.</p>
<div class="review-layout">
<div class="review-column">
<h3>Authorised conversations</h3>
<div id="review-list" class="review-list" aria-label="Conversations available for review"></div>
<p id="review-state" class="review-state" role="status" aria-live="polite"></p>
<button id="review-load-more" type="button" hidden>Load more</button>
</div>
<div class="review-column">
<div id="review-meta" class="review-meta"></div>
<div id="review-messages" class="review-messages" aria-label="Reviewed conversation messages"></div>
<p id="review-empty" class="review-empty">Select a conversation to review.</p>
</div>
</div>
</div>
<div id="admin-panel" class="admin-view" role="tabpanel" aria-labelledby="tab-admin" hidden>
<h2>Account administration</h2>
<p class="review-notice">Administrator tools for this workspace. The server verifies the administrator role on every request. Review grants allow reading original confidential chat text, and every access is recorded in the access log.</p>
<p id="admin-status" class="chat-status" role="status" aria-live="polite"></p>
<div class="admin-grid">
<section class="admin-card" aria-labelledby="department-heading">
<h3 id="department-heading">Departments</h3>
<form id="department-form" class="admin-form" novalidate>
<label for="department-name">Department name</label>
<input id="department-name" name="department-name" type="text" maxlength="80" autocomplete="off" required>
<button id="department-submit" class="primary" type="submit">Create department</button>
</form>
<p id="department-state" class="admin-note" role="status" aria-live="polite"></p>
<div id="department-list" class="admin-list" aria-label="Departments"></div>
<button id="department-more" class="admin-more" type="button" hidden>Load more departments</button>
</section>
<section class="admin-card" aria-labelledby="users-heading">
<h3 id="users-heading">User accounts</h3>
<form id="user-form" class="admin-form" novalidate>
<label for="new-user-username">Username</label>
<input id="new-user-username" name="new-user-username" type="text" maxlength="128" autocomplete="off" autocapitalize="none" spellcheck="false" required>
<label for="new-user-fullname">Full name</label>
<input id="new-user-fullname" name="new-user-fullname" type="text" maxlength="120" autocomplete="off" required>
<label for="new-user-department">Department</label>
<select id="new-user-department" name="new-user-department" required></select>
<label for="new-user-role">Role</label>
<select id="new-user-role" name="new-user-role">
<option value="employee">Employee</option>
<option value="admin">Administrator</option>
</select>
<label for="new-user-password">Initial password (at least 12 characters)</label>
<input id="new-user-password" name="new-user-password" type="password" minlength="12" maxlength="128" autocomplete="new-password" required>
<p class="admin-note">Share the initial password separately with the employee. It is never shown again, and there is no default or fixed credential. Password fields are cleared after every attempt.</p>
<button id="user-submit" class="primary" type="submit">Create user</button>
</form>
<p id="user-state" class="admin-note" role="status" aria-live="polite"></p>
<div id="user-list" class="admin-list" aria-label="User accounts"></div>
<button id="user-more" class="admin-more" type="button" hidden>Load more users</button>
</section>
<section class="admin-card" aria-labelledby="grants-heading">
<h3 id="grants-heading">Review access grants</h3>
<form id="grant-form" class="admin-form" novalidate>
<label for="grant-user">Reviewer</label>
<select id="grant-user" name="grant-user" required></select>
<label for="grant-scope">Scope</label>
<select id="grant-scope" name="grant-scope">
<option value="department">One department</option>
<option value="global">Global (all departments)</option>
</select>
<div id="grant-department-field">
<label for="grant-department">Department</label>
<select id="grant-department" name="grant-department"></select>
</div>
<p class="admin-warning">Access warning: a review grant lets the selected user read original confidential chat text and delivered replies in its scope. Every review access is recorded.</p>
<div id="grant-global-field" hidden>
<label for="grant-global-confirm"><input id="grant-global-confirm" type="checkbox"> I understand a global grant exposes original confidential chat text across every department.</label>
</div>
<p class="admin-note">Use Load more to see additional users and departments.</p>
<button id="grant-submit" class="primary" type="submit">Grant review access</button>
</form>
<p id="grant-state" class="admin-note" role="status" aria-live="polite"></p>
<div id="grant-list" class="admin-list" aria-label="Review access grants"></div>
<button id="grant-more" class="admin-more" type="button" hidden>Load more grants</button>
</section>
<section class="admin-card" aria-labelledby="access-heading">
<h3 id="access-heading">Access log</h3>
<p class="admin-note">Metadata only: event actor, time, action, department and conversation. Message text and session tokens are never shown here.</p>
<div id="access-list" class="admin-list" aria-label="Access log metadata"></div>
<button id="access-more" class="admin-more" type="button" hidden>Load more access events</button>
<p id="access-state" class="admin-note" role="status" aria-live="polite"></p>
</section>
</div>
</div>
</section>
</div>
</main>
</div>
<script>__WORKSPACE_JS__</script>
</body>
</html>
""".replace("__WORKSPACE_CSS__", _WORKSPACE_CSS).replace(
    "__WORKSPACE_JS__", _WORKSPACE_JS
)


WORKSPACE_SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "Content-Security-Policy": (
        "default-src 'none'; "
        f"script-src {_csp_hash(_WORKSPACE_JS)}; "
        f"style-src {_csp_hash(_WORKSPACE_CSS)}; "
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


def workspace_html(*, ready: bool) -> str:
    """Return the static page with a generic configuration notice if unready."""
    if ready:
        availability = ""
    else:
        availability = (
            '<div class="banner" role="note"><strong>Workspace unavailable.</strong> '
            "Workspace storage or the safety gateway is not configured. "
            "Sign-in stays unavailable until an operator fixes the configuration.</div>"
        )
    return WORKSPACE_HTML.replace(_AVAILABILITY_MARKER, availability, 1)
