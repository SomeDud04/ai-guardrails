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
.list-retry { margin: 0 var(--space-2) var(--space-3); font-size: .75rem; }
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
.composer-row { display: flex; align-items: flex-end; justify-content: flex-end; flex-wrap: wrap; gap: var(--space-2); margin-top: var(--space-1); }
.composer-hint { flex: 1 1 auto; min-width: 0; color: var(--muted-dim); font-size: .75rem; }
.composer-row button { min-width: 76px; min-height: 32px; align-self: flex-end; }
.reply-choice { display: flex; align-items: center; gap: var(--space-1); color: var(--muted); font-size: .75rem; white-space: nowrap; }
.reply-choice select { width: auto; min-height: 32px; padding: 0 var(--space-2); font-size: .75rem; }
.context-notice { margin: var(--space-2) 0 0; max-width: 72ch; color: var(--muted-dim); font-size: .75rem; overflow-wrap: anywhere; }
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
.admin-table-row .admin-reset { grid-column: 1 / -1; }
.admin-empty { margin: 0; padding: var(--space-2) var(--space-1); color: var(--muted-dim); font-size: .76rem; }
.admin-more { margin-top: var(--space-2); font-size: .75rem; }
.admin-card > p[role="status"] { margin: var(--space-1) 0; }
.topbar-actions { display: flex; align-items: center; gap: var(--space-2); margin-left: auto; min-width: 0; }
.alerts-bell { position: relative; display: grid; flex: none; place-items: center; width: var(--control-h); min-height: var(--control-h); padding: 0; color: var(--muted); }
.alerts-bell:hover:not(:disabled) { color: var(--text); }
.alerts-bell[data-state="unavailable"] { color: var(--danger); }
.alerts-badge {
  position: absolute; top: -5px; right: -5px; min-width: 18px; height: 18px; padding: 0 4px;
  border-radius: 9px; background: var(--amber); color: #17130b; font-size: .68rem;
  font-weight: 700; line-height: 18px; text-align: center;
}
.admin-shell { width: 100%; max-width: 1280px; margin: 0 auto; }
.admin-subtabs { display: flex; flex-wrap: wrap; gap: var(--space-1); margin: var(--space-3) 0 var(--space-2); border-bottom: 1px solid var(--line); }
.admin-subtab {
  min-height: 34px; margin-bottom: -1px; padding: 0 var(--space-3);
  border-color: transparent; border-bottom-color: transparent; border-radius: var(--radius) var(--radius) 0 0;
  color: var(--muted); font-size: .78rem;
}
.admin-subtab[aria-selected="true"] { color: var(--text); background: var(--surface); border-color: var(--line); border-bottom-color: var(--surface); }
.admin-panel-section { display: grid; gap: var(--space-3); min-width: 0; padding: var(--space-3) 0 var(--space-5); }
.admin-section-head { display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-2); }
.admin-section-head h3 { margin: 0; color: var(--text-soft); font-size: .86rem; }
.admin-toolbar { display: flex; flex-wrap: wrap; align-items: flex-end; gap: var(--space-2); min-width: 0; }
.admin-toolbar label { display: grid; gap: var(--space-1); min-width: 0; color: var(--muted); font-size: .75rem; }
.admin-toolbar input, .admin-toolbar select { min-width: 0; }
.admin-search { flex: 1 1 240px; max-width: 380px; }
.admin-search-note { margin: 0; color: var(--muted-dim); font-size: .72rem; }
.admin-table-wrap { width: 100%; max-width: 100%; overflow-x: auto; border: 1px solid var(--line); border-radius: var(--radius); background: var(--panel); }
.admin-table { display: grid; min-width: 0; max-width: 100%; overflow-x: auto; }
.admin-table-head, .admin-table-row {
  display: grid; grid-template-columns: repeat(var(--admin-cols, 4), minmax(0, 1fr));
  gap: var(--space-3); align-items: start; min-width: 620px;
  padding: var(--space-2) var(--space-3);
}
.admin-table-head { border-bottom: 1px solid var(--line); color: var(--muted-dim); font-size: .7rem; letter-spacing: .06em; text-transform: uppercase; }
.admin-table-row { border-top: 1px solid var(--line); min-height: 44px; }
.admin-table-head.cols-2, .admin-table-row.cols-2 { grid-template-columns: minmax(0, 2fr) minmax(0, 1fr); min-width: 360px; }
.admin-table-head.cols-3, .admin-table-row.cols-3 { grid-template-columns: minmax(0, 1.5fr) minmax(0, 1fr) auto; }
.admin-table-head.cols-4, .admin-table-row.cols-4 { grid-template-columns: minmax(0, 1.2fr) minmax(0, .8fr) minmax(0, 1.5fr) auto; }
.admin-table-head.cols-5, .admin-table-row.cols-5 { grid-template-columns: minmax(0, 1.1fr) minmax(0, .9fr) minmax(0, 1.2fr) minmax(0, 1fr) auto; }
.admin-table-head.cols-6, .admin-table-row.cols-6 { grid-template-columns: minmax(0, 1fr) minmax(0, .8fr) minmax(0, .9fr) minmax(0, 1.2fr) minmax(0, .8fr) auto; }
.admin-table-row:first-child { border-top: 0; }
.admin-table-row > div { min-width: 0; overflow-wrap: anywhere; color: var(--text-soft); font-size: .78rem; }
.admin-table-row .cell-muted { color: var(--muted-dim); font-size: .73rem; }
.admin-table-row .cell-actions { display: flex; flex-wrap: wrap; gap: var(--space-1); }
.admin-table-row .cell-actions button { min-height: 28px; padding: 0 var(--space-2); font-size: .72rem; }
.admin-table-empty { margin: 0; padding: var(--space-3); color: var(--muted-dim); font-size: .78rem; }
.admin-inline { display: inline-flex; align-items: center; gap: var(--space-1); color: var(--text-soft); font-size: .76rem; }
.admin-details { border: 1px solid var(--line); border-radius: var(--radius); background: var(--panel); padding: var(--space-2) var(--space-3); }
.admin-details > summary { cursor: pointer; color: var(--text-soft); font-size: .8rem; font-weight: 600; }
.admin-details[open] > summary { margin-bottom: var(--space-3); }
.policy-form { border: 1px solid var(--line); border-radius: var(--radius); background: var(--surface); padding: var(--space-3); margin: 0; }
.policy-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 220px), 1fr)); gap: var(--space-3); }
.policy-grid fieldset { min-width: 0; margin: 0; padding: var(--space-2); border: 1px solid var(--line); border-radius: var(--radius); }
.policy-grid legend { padding: 0 var(--space-1); color: var(--muted); font-size: .74rem; }
.policy-checks { display: grid; gap: var(--space-1); }
.policy-checks label { display: flex; align-items: flex-start; gap: var(--space-1); color: var(--text-soft); font-size: .76rem; }
.policy-actions { display: flex; flex-wrap: wrap; gap: var(--space-2); }
.policy-note { margin: 0; color: var(--muted-dim); font-size: .74rem; max-width: 88ch; }
.policy-history { display: grid; gap: 0; border: 1px solid var(--line); border-radius: var(--radius); overflow: hidden; }
.policy-history-row { display: grid; grid-template-columns: 70px minmax(0, 1fr) auto; gap: var(--space-3); align-items: start; padding: var(--space-2) var(--space-3); border-top: 1px solid var(--line); font-size: .77rem; }
.policy-history-row:first-child { border-top: 0; }
.policy-history-row > span, .policy-history-row > div { min-width: 0; overflow-wrap: anywhere; }
.effective-summary { border: 1px solid var(--line); border-radius: var(--radius); background: var(--panel); padding: var(--space-3); font-size: .78rem; color: var(--text-soft); }
.effective-summary p { margin: 0 0 var(--space-1); }
.effective-summary ul { margin: var(--space-1) 0 0; padding-left: 1.2rem; }
.chat-block { margin: 0 0 var(--space-2); padding: var(--space-3); border: 1px solid var(--amber-line); border-radius: var(--radius); background: var(--amber-soft); color: var(--text-soft); font-size: .8rem; overflow-wrap: anywhere; }
.chat-block h3 { margin: 0 0 var(--space-1); color: var(--amber); font-size: .86rem; }
.chat-block p { margin: 0 0 var(--space-1); }
.chat-block p:last-child { margin-bottom: 0; }
.message .chat-block { margin-top: var(--space-2); }
.policy-summary { margin: var(--space-2) 0 0; max-width: 88ch; color: var(--muted); font-size: .74rem; overflow-wrap: anywhere; }
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
  .admin-table-head, .admin-table-row { min-width: 560px; }
  .policy-history-row { grid-template-columns: 56px minmax(0, 1fr); }
  .policy-history-row > :last-child { grid-column: 1 / -1; }
  .topbar-actions { gap: var(--space-1); }
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
  .composer-row { gap: var(--space-2); align-items: stretch; }
  .composer-row button { min-width: 76px; }
  .reply-choice { flex: 1 1 100%; justify-content: space-between; }
  .reply-choice select { flex: 0 1 auto; min-width: 0; }
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
  // The conversation list is a safe idempotent read.  Only transient read
  // failures are retried, and an exhausted retry leaves an explicit control.
  var LIST_RETRY_MS = [300, 800];
  var GENERIC_CONTEXT_NOTICE = "Full saved history is kept. Older messages may be left out of a model request to fit the configured context.";

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
  var listRetry = byId("list-retry");
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
  var replyLength = byId("reply-length");
  var contextNotice = byId("context-notice");
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
  var alertsBell = byId("alerts-bell");
  var alertsBadge = byId("alerts-badge");
  var chatBlock = byId("chat-block");
  var policySummary = byId("policy-summary");
  var adminTabUsers = byId("admin-tab-users");
  var adminTabDepartments = byId("admin-tab-departments");
  var adminTabPolicies = byId("admin-tab-policies");
  var adminTabAlerts = byId("admin-tab-alerts");
  var adminTabAccess = byId("admin-tab-access");
  var adminUsersPanel = byId("admin-users-panel");
  var adminDepartmentsPanel = byId("admin-departments-panel");
  var adminPoliciesPanel = byId("admin-policies-panel");
  var adminAlertsPanel = byId("admin-alerts-panel");
  var adminAccessPanel = byId("admin-access-panel");
  var newUserToggle = byId("new-user-toggle");
  var userCancel = byId("user-cancel");
  var newDepartmentToggle = byId("new-department-toggle");
  var departmentCancel = byId("department-cancel");
  var userSearch = byId("user-search");
  var departmentSearch = byId("department-search");
  var accessSearch = byId("access-search");
  var policyNew = byId("policy-new");
  var policyRefresh = byId("policy-refresh");
  var policySearch = byId("policy-search");
  var policyMore = byId("policy-more");
  var policyForm = byId("policy-form");
  var policyName = byId("policy-name");
  var policyInputEnabled = byId("policy-input-enabled");
  var policyOutputEnabled = byId("policy-output-enabled");
  var policyInputEmail = byId("policy-input-email");
  var policyInputPhone = byId("policy-input-phone");
  var policyInputMykad = byId("policy-input-mykad");
  var policyOutputEmail = byId("policy-output-email");
  var policyOutputPhone = byId("policy-output-phone");
  var policyOutputMykad = byId("policy-output-mykad");
  var policyDisabledNote = byId("policy-disabled-note");
  var policySubmit = byId("policy-submit");
  var policyCancel = byId("policy-cancel");
  var policyState = byId("policy-state");
  var policyList = byId("policy-list");
  var policyHistory = byId("policy-history");
  var policyHistoryState = byId("policy-history-state");
  var assignmentScope = byId("assignment-scope");
  var assignmentDepartmentField = byId("assignment-department-field");
  var assignmentDepartment = byId("assignment-department");
  var assignmentUserField = byId("assignment-user-field");
  var assignmentUser = byId("assignment-user");
  var assignmentProfile = byId("assignment-profile");
  var assignmentRevision = byId("assignment-revision");
  var assignmentCurrent = byId("assignment-current");
  var assignmentForm = byId("policy-assignment-form");
  var assignmentSubmit = byId("assignment-submit");
  var assignmentClear = byId("assignment-clear");
  var assignmentState = byId("assignment-state");
  var effectiveUser = byId("effective-user");
  var effectivePreview = byId("effective-preview");
  var effectiveState = byId("effective-state");
  var effectivePolicy = byId("effective-policy");
  var alertRefresh = byId("alert-refresh");
  var alertStage = byId("alert-stage");
  var alertDepartment = byId("alert-department");
  var alertUser = byId("alert-user");
  var alertUnread = byId("alert-unread");
  var alertAck = byId("alert-ack");
  var alertSummary = byId("alert-summary");
  var alertState = byId("alert-state");
  var alertList = byId("alert-list");
  var alertMore = byId("alert-more");
  var alertDetail = byId("alert-detail");
  var accessRefresh = byId("access-refresh");

  var signedIn = false;
  var profile = null;
  var drafts = Object.create(null);
  var chatLimits = null;
  var selectedReplyTokens = null;
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
  var listResetLoading = false;
  var listPending = Promise.resolve(false);
  // Set when a mutation asks for a first-page refresh while a reset is
  // already in flight.  Exactly one follow-up runs after the older reset
  // settles, so a pre-mutation snapshot can never win.
  var listRefreshPending = false;
  // Bumped by every list attempt.  An older response or retry timer must not
  // append rows, reuse a cursor or paint a previous identity's list.
  var listAttemptSeq = 0;
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
  var adminSection = "users";
  var adminStateEpoch = 0;
  var adminDepartmentsLoaded = false;
  var adminUsersLoaded = false;
  var adminGrantsLoaded = false;
  var adminAccessLoaded = false;
  var adminAccess = [];
  var adminPoliciesLoaded = false;
  var policyProfiles = [];
  var policyProfilesLoading = false;
  var policyProfilesSeq = 0;
  var policyCursor = null;
  var policySearchText = "";
  var policyEditingId = null;
  var policyEditingRevision = null;
  var policyEditSeq = 0;
  var policyHistoryFor = null;
  var policyHistoryLoading = false;
  var policyHistorySeq = 0;
  var policySaving = false;
  var policyRollbackBusy = false;
  var assignmentVersion = null;
  var assignmentReady = false;
  var assignmentCurrentProfile = null;
  var assignmentLoadedFor = "";
  var assignmentLoadSeq = 0;
  var assignmentLoading = false;
  var assignmentSaving = false;
  var assignmentClearing = false;
  var effectiveLoading = false;
  var effectiveSeq = 0;
  var alertsLoaded = false;
  var alertsList = [];
  var alertCursor = null;
  var alertLoading = false;
  var alertListSeq = 0;
  var alertSummaryLoading = false;
  var alertSummarySeq = 0;
  var alertSummaryEpoch = 0;
  var alertRefreshTimer = null;
  var alertRefreshEpoch = 0;
  var alertActionBusy = "";
  var policySummarySeq = 0;
  // Sign-in and session restore read history and readiness first.  Policy and
  // alert summaries are queued behind those reads so a new startup cannot
  // occupy every bounded admission slot at once.
  var baselinePending = false;
  var baselineSeq = 0;
  var summariesQueued = false;
  var startupGuardPromise = null;
  var userSearchText = "";
  var departmentSearchText = "";
  var accessSearchText = "";

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

  function retriableRead(result) {
    // Only a transient read failure is safe to repeat.  Authentication,
    // permission and malformed-answer outcomes need a real user action.
    return result.network === true || result.timeout === true ||
      result.status === 502 || result.status === 503 || result.status === 504;
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
    policySummarySeq += 1;
    baselinePending = false;
    baselineSeq += 1;
    summariesQueued = false;
    startupGuardPromise = null;
    currentConversation = null;
    sending = false;
    creating = false;
    deleting = false;
    loginBusy = false;
    logoutBusy = false;
    revalidating = false;
    listLoading = false;
    listLoaded = false;
    listResetLoading = false;
    listPending = Promise.resolve(false);
    listRefreshPending = false;
    listAttemptSeq += 1;
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
    composer.removeAttribute("maxlength");
    clearNode(replyLength);
    replyLength.value = "";
    replyLength.disabled = true;
    chatLimits = null;
    selectedReplyTokens = null;
    contextNotice.textContent = GENERIC_CONTEXT_NOTICE;
    clearNode(conversationList);
    clearNode(messagesEl);
    clearNode(reviewList);
    clearNode(reviewMessages);
    reviewMeta.textContent = "";
    reviewEmpty.textContent = "Select a conversation to review.";
    reviewEmpty.hidden = false;
    listState.textContent = "";
    listRetry.hidden = true;
    chatMeta.textContent = "";
    chatTitle.textContent = "Conversation";
    identityName.textContent = "";
    identityMeta.textContent = "";
    loadMoreButton.hidden = true;
    reviewLoadMore.hidden = true;
    deleteButton.hidden = true;
    deleteConfirm.hidden = true;
    chatBlock.hidden = true;
    clearNode(chatBlock);
    policySummary.textContent = "Workspace policy summary loading…";
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
    alertsBell.hidden = true;
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

  var BLOCK_DETAILS = {
    INPUT_GUARD_BLOCK: { stage: "input", title: "Prompt blocked", reason: "The prompt did not pass the input safety check." },
    INPUT_POLICY_BLOCK: { stage: "input", title: "Prompt blocked", reason: "The prompt contains content disallowed by policy." },
    OUTPUT_GUARD_BLOCK: { stage: "output", title: "Response withheld", reason: "The response did not pass the output safety check." },
    OUTPUT_POLICY_BLOCK: { stage: "output", title: "Response withheld", reason: "The response contains content disallowed by policy." }
  };

  function safeBlock(raw, fallbackRef) {
    if (!isObject(raw)) { return null; }
    var code = raw.reason_code;
    var detail = Object.prototype.hasOwnProperty.call(BLOCK_DETAILS, code)
      ? BLOCK_DETAILS[code] : null;
    if (!detail) { return null; }
    if (typeof raw.stage === "string" && raw.stage && raw.stage !== detail.stage) { return null; }
    var ref = typeof raw.ref === "string" ? raw.ref :
      (typeof fallbackRef === "string" ? fallbackRef : "");
    if (!ref || ref.length > 128) { ref = "Unavailable"; }
    else {
      for (var i = 0; i < ref.length; i += 1) {
        if (ref.charCodeAt(i) < 32 || ref.charCodeAt(i) === 127) { ref = "Unavailable"; break; }
      }
    }
    return { title: detail.title, reason: detail.reason, stage: detail.stage, ref: ref };
  }

  function appendBlockNotice(container, block) {
    if (!block) { return; }
    var box = document.createElement("div");
    box.className = "chat-block";
    var title = document.createElement("h3");
    title.textContent = block.title;
    var reason = document.createElement("p");
    reason.textContent = block.reason;
    var reference = document.createElement("p");
    reference.textContent = "Reference ID: " + block.ref;
    box.appendChild(title);
    box.appendChild(reason);
    box.appendChild(reference);
    container.appendChild(box);
  }

  function showChatBlock(block) {
    clearNode(chatBlock);
    if (!block) { chatBlock.hidden = true; return; }
    appendBlockNotice(chatBlock, block);
    chatBlock.hidden = false;
  }

  function loadPolicySummary() {
    if (!signedIn || !profile || !profile.user) { return Promise.resolve(false); }
    var seq = ++policySummarySeq;
    var epoch = sessionEpoch;
    var uid = profile.user.id;
    var token = adminStateEpoch;
    return api("/workspace/api/policy").then(function (result) {
      if (seq !== policySummarySeq || epoch !== sessionEpoch || token !== adminStateEpoch ||
          !signedIn || !profile || !profile.user || profile.user.id !== uid) { return false; }
      if (authFailure(result)) { return false; }
      // A malformed or failed answer must never read like active protection.
      var settings = result.ok && isObject(result.data) ? policySettings(result.data) : null;
      if (!settings) {
        policySummary.textContent = "Workspace policy details could not be verified. Do not assume " +
          "model safety checks or PII masking are active; server deny rules and configured limits still apply.";
        return false;
      }
      var inputMasks = settings.input_masks;
      var outputMasks = settings.output_masks;
      var parts = [];
      parts.push(settings.input_check_enabled
        ? "Input model safety check: enabled by administrator policy."
        : "Input model safety check: DISABLED by administrator policy; the model guard does not check input content for this account.");
      parts.push(settings.output_check_enabled
        ? "Output model safety check: enabled by administrator policy."
        : "Output model safety check: DISABLED by administrator policy; the model guard does not check output content for this account.");
      // Masking runs independently of the model check toggles, so always show
      // the selected masks for both channels.
      parts.push(inputMasks.length
        ? "Selected input masking: " + inputMasks.join(", ") + "."
        : "Selected input masking: none.");
      parts.push(outputMasks.length
        ? "Selected output masking: " + outputMasks.join(", ") + "."
        : "Selected output masking: none.");
      parts.push("Masking is applied independently of the model safety checks. " +
        "Static server deny rules and configured limits still apply.");
      parts.push("Model guard runtime status is reported separately in the guard status control.");
      if (result.data.is_default === true) { parts.push("Default workspace policy applies."); }
      policySummary.textContent = parts.join(" ");
      return true;
    });
  }

  // -- policies: profiles, assignments and effective preview --------------

  function policySettings(raw) {
    if (!isObject(raw) ||
        typeof raw.input_check_enabled !== "boolean" ||
        typeof raw.output_check_enabled !== "boolean" ||
        !Array.isArray(raw.input_masks) || !Array.isArray(raw.output_masks)) {
      return null;
    }
    var allowed = { EMAIL: true, MY_PHONE: true, MYKAD: true };
    var input = [];
    var output = [];
    var i;
    for (i = 0; i < raw.input_masks.length; i += 1) {
      var inputMask = raw.input_masks[i];
      if (typeof inputMask !== "string" || !allowed[inputMask] ||
          input.indexOf(inputMask) >= 0) { return null; }
      input.push(inputMask);
    }
    for (i = 0; i < raw.output_masks.length; i += 1) {
      var outputMask = raw.output_masks[i];
      if (typeof outputMask !== "string" || !allowed[outputMask] ||
          output.indexOf(outputMask) >= 0) { return null; }
      output.push(outputMask);
    }
    return {
      input_check_enabled: raw.input_check_enabled,
      output_check_enabled: raw.output_check_enabled,
      input_masks: input,
      output_masks: output
    };
  }

  function policyProfile(raw) {
    if (!isObject(raw) || typeof raw.id !== "string" || typeof raw.name !== "string" ||
        !raw.name || typeof raw.revision !== "number" || !isFinite(raw.revision) ||
        raw.revision < 1 || Math.floor(raw.revision) !== raw.revision) {
      return null;
    }
    var settings = policySettings(raw.settings);
    if (!settings) { return null; }
    return {
      id: raw.id,
      name: raw.name,
      revision: raw.revision,
      settings: settings,
      settings_digest: typeof raw.settings_digest === "string" ? raw.settings_digest : ""
    };
  }

  function policyAssignment(raw) {
    if (!isObject(raw) || typeof raw.id !== "string" ||
        typeof raw.profile_id !== "string" ||
        typeof raw.profile_revision !== "number" ||
        typeof raw.version !== "number" ||
        raw.profile_revision < 1 || raw.version < 1 ||
        Math.floor(raw.profile_revision) !== raw.profile_revision ||
        Math.floor(raw.version) !== raw.version) {
      return null;
    }
    var settings = policySettings(raw.settings);
    if (!settings) { return null; }
    var scope = raw.scope_type;
    if (scope !== "workspace" && scope !== "department" && scope !== "user") { return null; }
    return {
      id: raw.id,
      scope_type: scope,
      scope_id: typeof raw.scope_id === "string" ? raw.scope_id : null,
      profile_id: raw.profile_id,
      profile_name: typeof raw.profile_name === "string" && raw.profile_name
        ? raw.profile_name : "Profile " + shortId(raw.profile_id),
      profile_revision: raw.profile_revision,
      version: raw.version,
      settings: settings
    };
  }

  function policyChecksText(settings) {
    return (settings.input_check_enabled ? "Input checks on" : "Input checks off") +
      " · " + (settings.output_check_enabled ? "Output checks on" : "Output checks off");
  }

  function policyMasksText(settings) {
    return "Input masks: " +
      (settings.input_masks.length ? settings.input_masks.join(", ") : "none (explicit no masking)") +
      " · Output masks: " +
      (settings.output_masks.length ? settings.output_masks.join(", ") : "none (explicit no masking)");
  }

  function policySettingsSummary(settings) {
    return policyChecksText(settings) + " · " + policyMasksText(settings);
  }

  function findPolicyProfile(id) {
    for (var i = 0; i < policyProfiles.length; i += 1) {
      if (policyProfiles[i].id === id) { return policyProfiles[i]; }
    }
    return null;
  }

  function findAdminUser(id) {
    for (var i = 0; i < adminUsers.length; i += 1) {
      if (adminUsers[i].id === id) { return adminUsers[i]; }
    }
    return null;
  }

  function policyScopeLabel(scopeType, scopeId) {
    if (scopeType === "workspace") { return "Workspace"; }
    if (scopeType === "department") {
      return "Department · " + departmentLabel(scopeId);
    }
    if (scopeType === "user") {
      var user = findAdminUser(scopeId);
      return "User · " + (user ? "@" + user.username : shortId(scopeId));
    }
    return "Unknown scope";
  }

  function ensurePolicyProfileOption(id, name, revision) {
    if (!assignmentProfile || typeof id !== "string" || !id) { return; }
    var children = assignmentProfile.children || [];
    for (var i = 0; i < children.length; i += 1) {
      if (children[i].value === id) { return; }
    }
    var option = document.createElement("option");
    option.value = id;
    option.textContent = (typeof name === "string" && name ? name : "Profile " + shortId(id)) +
      " · revision " + (typeof revision === "number" && revision >= 1 ? revision : "?");
    assignmentProfile.appendChild(option);
  }

  function syncPolicyTargetOptions() {
    if (assignmentDepartment) {
      fillSelect(assignmentDepartment, adminDepartments, "Select a department", function (item) {
        return item.name;
      });
    }
    if (assignmentUser) {
      fillSelect(assignmentUser, adminUsers, "Select a user", function (item) {
        return "@" + item.username + " (" + item.full_name + ")";
      });
    }
    if (effectiveUser) {
      fillSelect(effectiveUser, adminUsers, "Select a user", function (item) {
        return "@" + item.username + " (" + item.full_name + ")";
      });
    }
  }

  function syncPolicyProfileOptions() {
    if (!assignmentProfile) { return; }
    var selected = assignmentProfile.value;
    fillSelect(assignmentProfile, policyProfiles, "Select a profile", function (item) {
      return item.name + " · revision " + item.revision;
    });
    if (assignmentCurrentProfile) {
      ensurePolicyProfileOption(
        assignmentCurrentProfile.id,
        assignmentCurrentProfile.name,
        assignmentCurrentProfile.revision
      );
      if (selected === assignmentCurrentProfile.id) {
        assignmentProfile.value = selected;
      }
    }
  }

  function renderPolicyProfiles(items, reset) {
    if (reset) {
      clearNode(policyList);
      renderTableHead(policyList, ["Profile", "Checks", "Masks", "Actions"], 4);
    }
    var query = policySearchText.toLowerCase();
    var shown = 0;
    for (var i = 0; i < items.length; i += 1) {
      var profile = policyProfile(items[i]);
      if (!profile) { continue; }
      var haystack = (profile.name + " revision " + profile.revision + " " +
        policySettingsSummary(profile.settings)).toLowerCase();
      if (query && haystack.indexOf(query) < 0) { continue; }
      var row = document.createElement("div");
      row.className = "admin-table-row cols-4";
      row.setAttribute("data-policy", profile.id);
      var nameCell = tableCell(profile.name);
      nameCell.appendChild(tableCell(
        "Revision " + profile.revision +
        (profile.settings_digest ? " · digest " + shortId(profile.settings_digest) : ""),
        "cell-muted"
      ));
      row.appendChild(nameCell);
      row.appendChild(tableCell(policyChecksText(profile.settings)));

      var masksCell = tableCell("Input: " + (profile.settings.input_masks.length
        ? profile.settings.input_masks.join(", ") : "None (explicit no masking)"));
      masksCell.appendChild(tableCell("Output: " + (profile.settings.output_masks.length
        ? profile.settings.output_masks.join(", ") : "None (explicit no masking)"), "cell-muted"));
      row.appendChild(masksCell);

      var actions = document.createElement("div");
      actions.className = "cell-actions";
      var editButton = document.createElement("button");
      editButton.type = "button";
      editButton.className = "ghost";
      editButton.textContent = "Edit";
      editButton.addEventListener("click", function (target) {
        return function () { editPolicyProfile(target.id); };
      }(profile));
      var historyButton = document.createElement("button");
      historyButton.type = "button";
      historyButton.className = "ghost";
      historyButton.textContent = "History";
      historyButton.addEventListener("click", function (target) {
        return function () { openPolicyHistory(target); };
      }(profile));
      actions.appendChild(editButton);
      actions.appendChild(historyButton);
      row.appendChild(actions);
      policyList.appendChild(row);
      shown += 1;
    }
    if (reset && shown === 0) {
      appendEmpty(policyList, query
        ? "No loaded policy profiles match this search. Search applies only to rows loaded so far."
        : "No policy profiles exist. Create a profile and then assign it explicitly.");
    }
  }

  function loadPolicyProfiles(reset) {
    if (!currentAdmin()) { return Promise.resolve(false); }
    if (!reset && (policyProfilesLoading || !policyCursor)) {
      return Promise.resolve(false);
    }
    var epoch = sessionEpoch;
    var token = adminStateEpoch;
    var uid = profile.user.id;
    var seq = ++policyProfilesSeq;
    policyProfilesLoading = true;
    if (reset) {
      policyProfiles = [];
      policyCursor = null;
      adminPoliciesLoaded = false;
      clearNode(policyList);
      setStatus(policyState, "Loading policy profiles…");
    } else {
      setStatus(policyState, "Loading more policy profiles…");
    }
    if (policyMore) { policyMore.disabled = true; }
    var path = "/workspace/api/admin/policy/profiles?limit=" + LIST_LIMIT +
      (policyCursor ? "&after=" + encodeURIComponent(policyCursor) : "");
    return api(path).then(function (result) {
      if (seq !== policyProfilesSeq || epoch !== sessionEpoch ||
          token !== adminStateEpoch || !currentAdmin(uid)) {
        return false;
      }
      policyProfilesLoading = false;
      if (policyMore) { policyMore.disabled = false; }
      if (adminGuard(result, policyState)) { return false; }
      if (!result.ok || !isObject(result.data) || !Array.isArray(result.data.items)) {
        setStatus(policyState, serverMessage(result, timeoutOrNetwork(result)), "error");
        if (reset) {
          clearNode(policyList);
          appendEmpty(policyList, "Policy profiles could not be loaded.");
        }
        return false;
      }
      var got = [];
      for (var i = 0; i < result.data.items.length; i += 1) {
        var item = policyProfile(result.data.items[i]);
        if (item) { got.push(item); }
      }
      policyProfiles = reset ? got : policyProfiles.concat(got);
      adminPoliciesLoaded = true;
      renderPolicyProfiles(policyProfiles, true);
      policyCursor = typeof result.data.next === "string" && result.data.next
        ? result.data.next : null;
      if (policyMore) { policyMore.hidden = !policyCursor; }
      setStatus(policyState, policyProfiles.length === 0
        ? "No policy profiles exist. Create a profile and then assign it explicitly."
        : "Showing " + policyProfiles.length + " loaded profile" +
          (policyProfiles.length === 1 ? "" : "s") + "." +
          (policyCursor ? " More may be available." : ""));
      syncPolicyProfileOptions();
      return true;
    });
  }

  function syncPolicyFormNote() {
    var relaxed = !policyInputEnabled.checked || !policyOutputEnabled.checked ||
      !policyInputEmail.checked || !policyInputPhone.checked || !policyInputMykad.checked ||
      !policyOutputEmail.checked || !policyOutputPhone.checked || !policyOutputMykad.checked;
    policyDisabledNote.hidden = !relaxed;
  }

  function openPolicyForm(profile) {
    policyEditingId = profile ? profile.id : null;
    policyEditingRevision = profile ? profile.revision : null;
    policyName.value = profile ? profile.name : "";
    policyInputEnabled.checked = profile ? profile.settings.input_check_enabled : true;
    policyOutputEnabled.checked = profile ? profile.settings.output_check_enabled : true;
    policyInputEmail.checked = profile ? profile.settings.input_masks.indexOf("EMAIL") >= 0 : true;
    policyInputPhone.checked = profile ? profile.settings.input_masks.indexOf("MY_PHONE") >= 0 : true;
    policyInputMykad.checked = profile ? profile.settings.input_masks.indexOf("MYKAD") >= 0 : true;
    policyOutputEmail.checked = profile ? profile.settings.output_masks.indexOf("EMAIL") >= 0 : true;
    policyOutputPhone.checked = profile ? profile.settings.output_masks.indexOf("MY_PHONE") >= 0 : true;
    policyOutputMykad.checked = profile ? profile.settings.output_masks.indexOf("MYKAD") >= 0 : true;
    policyForm.hidden = false;
    policySubmit.disabled = false;
    policyCancel.disabled = false;
    setStatus(policyState, profile
      ? "Editing " + profile.name + " at revision " + profile.revision + "."
      : "New profile. Input and output checks and all masks are selected by default.");
    syncPolicyFormNote();
    try { policyName.focus(); } catch (error) { /* non-fatal */ }
  }

  function closePolicyForm() {
    policyEditingId = null;
    policyEditingRevision = null;
    policyForm.hidden = true;
    policyName.value = "";
  }

  function editPolicyProfile(profileId) {
    if (!currentAdmin() || typeof profileId !== "string") { return; }
    var epoch = sessionEpoch;
    var token = adminStateEpoch;
    var uid = profile.user.id;
    var seq = ++policyEditSeq;
    setStatus(policyState, "Loading the latest profile revision…");
    api("/workspace/api/admin/policy/profiles/" + encodeURIComponent(profileId)).then(function (result) {
      if (seq !== policyEditSeq || epoch !== sessionEpoch ||
          token !== adminStateEpoch || !currentAdmin(uid)) { return; }
      if (adminGuard(result, policyState)) { return; }
      if (result.status === 404) {
        setStatus(policyState, "That profile no longer exists. Refresh the list.", "error");
        return;
      }
      if (!result.ok) {
        setStatus(policyState, serverMessage(result, timeoutOrNetwork(result)), "error");
        return;
      }
      var profile = policyProfile(result.data);
      if (!profile) {
        setStatus(policyState, "The profile response was not valid. Nothing was changed.", "error");
        return;
      }
      openPolicyForm(profile);
    });
  }

  function policyConflict(node, result, message) {
    if (result.status !== 409) { return false; }
    setStatus(node, message, "error");
    return true;
  }

  function selectedPolicyMasks(emailNode, phoneNode, mykadNode) {
    var masks = [];
    if (emailNode.checked) { masks.push("EMAIL"); }
    if (phoneNode.checked) { masks.push("MY_PHONE"); }
    if (mykadNode.checked) { masks.push("MYKAD"); }
    return masks;
  }

  function savePolicyProfile(event) {
    event.preventDefault();
    if (!currentAdmin() || policySaving) { return; }
    var name = policyName.value.trim();
    if (!name) {
      setStatus(policyState, "Enter a profile name.", "error");
      try { policyName.focus(); } catch (error) { /* non-fatal */ }
      return;
    }
    var editingId = policyEditingId;
    var editingRevision = policyEditingRevision;
    var payload = {
      input_check_enabled: policyInputEnabled.checked,
      output_check_enabled: policyOutputEnabled.checked,
      input_masks: selectedPolicyMasks(policyInputEmail, policyInputPhone, policyInputMykad),
      output_masks: selectedPolicyMasks(policyOutputEmail, policyOutputPhone, policyOutputMykad)
    };
    var path = "/workspace/api/admin/policy/profiles";
    if (editingId) {
      payload.expected_revision = editingRevision;
      path += "/" + encodeURIComponent(editingId) + "/revise";
    } else {
      payload.name = name;
    }
    var epoch = sessionEpoch;
    var token = adminStateEpoch;
    var uid = profile.user.id;
    policySaving = true;
    policySubmit.disabled = true;
    policyCancel.disabled = true;
    setStatus(policyState, editingId ? "Revising profile…" : "Creating profile…");
    api(path, { method: "POST", body: JSON.stringify(payload) }).then(function (result) {
      if (epoch !== sessionEpoch || token !== adminStateEpoch || !currentAdmin(uid)) { return; }
      policySaving = false;
      policySubmit.disabled = false;
      policyCancel.disabled = false;
      if (adminGuard(result, policyState)) { return; }
      if (policyConflict(policyState, result,
          "This profile changed since it was opened. Nothing was overwritten. Reload the latest revision and review it before saving again.")) {
        queueAdminList(function () { return loadPolicyProfiles(true); });
        return;
      }
      if (!result.ok) {
        setStatus(policyState, serverMessage(result, timeoutOrNetwork(result)), "error");
        return;
      }
      var saved = policyProfile(result.data);
      closePolicyForm();
      var message = editingId
        ? "Profile revised to revision " + (saved ? saved.revision : "a new revision") +
          ". Existing assignments keep their pinned revision until explicitly reapplied."
        : "Profile created" + (saved ? " at revision " + saved.revision : "") +
          ". It is not assigned to anyone yet.";
      if (editingId && policyHistoryFor && policyHistoryFor.id === editingId) {
        loadPolicyHistory(editingId);
      }
      queueAdminList(function () { return loadPolicyProfiles(true); }).then(function (ok) {
        if (epoch === sessionEpoch && token === adminStateEpoch && currentAdmin(uid)) {
          setStatus(policyState, ok ? message
            : message + " The profile list could not be refreshed.", ok ? "ok" : "warning");
        }
      });
    });
  }

  function loadPolicyHistory(profileId) {
    if (!currentAdmin() || typeof profileId !== "string") { return Promise.resolve(false); }
    if (!policyHistoryFor || policyHistoryFor.id !== profileId) {
      var known = findPolicyProfile(profileId);
      policyHistoryFor = {
        id: profileId,
        name: known ? known.name : "Profile " + shortId(profileId),
        revision: known ? known.revision : null
      };
    }
    var contextId = policyHistoryFor.id;
    var epoch = sessionEpoch;
    var token = adminStateEpoch;
    var uid = profile.user.id;
    var seq = ++policyHistorySeq;
    policyHistoryLoading = true;
    clearNode(policyHistory);
    setStatus(policyHistoryState, "Loading revision history…");
    return api("/workspace/api/admin/policy/profiles/" + encodeURIComponent(profileId) +
      "/history?limit=50").then(function (result) {
      if (seq !== policyHistorySeq || epoch !== sessionEpoch ||
          token !== adminStateEpoch || !currentAdmin(uid) ||
          !policyHistoryFor || policyHistoryFor.id !== contextId) { return false; }
      policyHistoryLoading = false;
      if (adminGuard(result, policyHistoryState)) { return false; }
      if (!result.ok || !isObject(result.data) || !Array.isArray(result.data.items)) {
        setStatus(policyHistoryState, serverMessage(result, timeoutOrNetwork(result)), "error");
        appendEmpty(policyHistory, "Profile history could not be loaded.");
        return false;
      }
      var items = result.data.items;
      if (items.length > 0 && typeof items[0].revision === "number") {
        policyHistoryFor.revision = items[0].revision;
      }
      renderPolicyHistory(items);
      var next = typeof result.data.next === "string" && result.data.next;
      setStatus(policyHistoryState, items.length === 0
        ? "No revision history was returned for this profile."
        : "Showing " + items.length + " revision" + (items.length === 1 ? "" : "s") +
          " for " + policyHistoryFor.name + "." + (next ? " Older revisions are not shown." : "") +
          " Rollback appends a new revision; pinned assignments do not advance automatically.");
      return true;
    });
  }

  function openPolicyHistory(profile) {
    if (!profile || typeof profile.id !== "string") { return; }
    policyHistoryFor = {
      id: profile.id,
      name: profile.name,
      revision: profile.revision
    };
    loadPolicyHistory(profile.id);
  }

  function renderPolicyHistory(items) {
    clearNode(policyHistory);
    if (!items || items.length === 0) {
      appendEmpty(policyHistory, "No revisions were returned.");
      return;
    }
    var latest = policyHistoryFor && typeof policyHistoryFor.revision === "number"
      ? policyHistoryFor.revision : null;
    for (var i = 0; i < items.length; i += 1) {
      var raw = items[i];
      if (!isObject(raw) || typeof raw.revision !== "number") { continue; }
      var settings = policySettings(raw.settings);
      if (!settings) { continue; }
      var row = document.createElement("div");
      row.className = "policy-history-row";
      var revisionCell = document.createElement("span");
      revisionCell.textContent = "r" + raw.revision;
      var detail = document.createElement("div");
      var main = document.createElement("div");
      main.textContent = policyChecksText(settings);
      var masks = document.createElement("div");
      masks.textContent = policyMasksText(settings);
      detail.appendChild(main);
      detail.appendChild(masks);
      if (typeof raw.rollback_of === "number") {
        var rollbackFrom = document.createElement("div");
        rollbackFrom.className = "cell-muted";
        rollbackFrom.textContent = "Rolled back from revision " + raw.rollback_of + ".";
        detail.appendChild(rollbackFrom);
      }
      var meta = document.createElement("div");
      meta.className = "cell-muted";
      meta.textContent = "Created " + formatDate(raw.created_at) + ".";
      detail.appendChild(meta);
      var actions = document.createElement("div");
      actions.className = "cell-actions";
      if (latest !== null && raw.revision >= latest) {
        var current = document.createElement("span");
        current.className = "cell-muted";
        current.textContent = "Current revision";
        actions.appendChild(current);
      } else {
        var rollbackButton = document.createElement("button");
        rollbackButton.type = "button";
        rollbackButton.className = "ghost";
        rollbackButton.textContent = "Roll back to r" + raw.revision;
        rollbackButton.addEventListener("click", function (targetRevision) {
          return function () {
            rollbackPolicyProfile(policyHistoryFor ? policyHistoryFor.id : "", targetRevision);
          };
        }(raw.revision));
        actions.appendChild(rollbackButton);
      }
      row.appendChild(revisionCell);
      row.appendChild(detail);
      row.appendChild(actions);
      policyHistory.appendChild(row);
    }
  }

  function rollbackPolicyProfile(profileId, targetRevision) {
    if (!currentAdmin() || policyRollbackBusy || !policyHistoryFor ||
        policyHistoryFor.id !== profileId ||
        typeof policyHistoryFor.revision !== "number" ||
        typeof targetRevision !== "number") {
      return;
    }
    var expectedRevision = policyHistoryFor.revision;
    var epoch = sessionEpoch;
    var token = adminStateEpoch;
    var uid = profile.user.id;
    policyRollbackBusy = true;
    setStatus(policyHistoryState, "Rolling back to revision " + targetRevision + "…");
    api("/workspace/api/admin/policy/profiles/" + encodeURIComponent(profileId) + "/rollback", {
      method: "POST",
      body: JSON.stringify({
        target_revision: targetRevision,
        expected_revision: expectedRevision
      })
    }).then(function (result) {
      if (epoch !== sessionEpoch || token !== adminStateEpoch || !currentAdmin(uid)) { return; }
      policyRollbackBusy = false;
      if (adminGuard(result, policyHistoryState)) { return; }
      if (policyConflict(policyHistoryState, result,
          "This profile changed before the rollback. Nothing was overwritten. Reload the latest revision and history before trying again.")) {
        queueAdminList(function () { return loadPolicyProfiles(true); });
        loadPolicyHistory(profileId);
        return;
      }
      if (!result.ok) {
        setStatus(policyHistoryState, serverMessage(result, timeoutOrNetwork(result)), "error");
        return;
      }
      var saved = policyProfile(result.data);
      var message = "Rollback appended revision " + (saved ? saved.revision : "a new revision") +
        ". Old revisions remain immutable. Existing assignments keep their pinned revision until explicitly reapplied.";
      queueAdminList(function () { return loadPolicyProfiles(true); });
      loadPolicyHistory(profileId).then(function (ok) {
        if (ok && epoch === sessionEpoch && token === adminStateEpoch && currentAdmin(uid)) {
          setStatus(policyHistoryState, message, "ok");
        }
      });
    });
  }

  function syncAssignmentScope() {
    var scope = assignmentScope.value;
    var departmentScope = scope === "department";
    var userScope = scope === "user";
    assignmentDepartmentField.hidden = !departmentScope;
    assignmentDepartment.disabled = !departmentScope;
    assignmentUserField.hidden = !userScope;
    assignmentUser.disabled = !userScope;
  }

  function assignmentTarget() {
    var scope = assignmentScope.value;
    if (scope !== "workspace" && scope !== "department" && scope !== "user") { return null; }
    var scopeId = null;
    if (scope === "department") {
      scopeId = assignmentDepartment.value;
    } else if (scope === "user") {
      scopeId = assignmentUser.value;
    }
    if (scope !== "workspace" && (!scopeId || typeof scopeId !== "string")) { return null; }
    return {
      scope_type: scope,
      scope_id: scopeId,
      key: scope + ":" + (scopeId || "")
    };
  }

  function assignmentPath(target) {
    var path = "/workspace/api/admin/policy/assignments/" +
      encodeURIComponent(target.scope_type);
    if (target.scope_id) { path += "?scope_id=" + encodeURIComponent(target.scope_id); }
    return path;
  }

  function assignmentSelectionChanged() {
    assignmentLoadSeq += 1;
    assignmentLoadedFor = "";
    assignmentReady = false;
    assignmentVersion = null;
    assignmentCurrentProfile = null;
    setStatus(assignmentState, "");
    loadCurrentAssignment();
  }

  function loadCurrentAssignment() {
    if (!currentAdmin()) { return Promise.resolve(false); }
    var target = assignmentTarget();
    if (!target) {
      assignmentLoadSeq += 1;
      assignmentLoadedFor = "";
      assignmentReady = false;
      assignmentVersion = null;
      assignmentCurrentProfile = null;
      assignmentCurrent.textContent = "Choose a department or user target to check its assignment.";
      setStatus(assignmentState, "");
      return Promise.resolve(false);
    }
    var key = target.key;
    var seq = ++assignmentLoadSeq;
    var epoch = sessionEpoch;
    var token = adminStateEpoch;
    var uid = profile.user.id;
    assignmentLoadedFor = key;
    assignmentReady = false;
    assignmentVersion = null;
    assignmentCurrentProfile = null;
    assignmentLoading = true;
    assignmentCurrent.textContent = "Checking the current assignment for " +
      policyScopeLabel(target.scope_type, target.scope_id) + "…";
    setStatus(assignmentState, "");
    return api(assignmentPath(target)).then(function (result) {
      if (seq !== assignmentLoadSeq || epoch !== sessionEpoch ||
          token !== adminStateEpoch || !currentAdmin(uid)) {
        return false;
      }
      var after = assignmentTarget();
      if (assignmentLoadedFor !== key || !after || after.key !== key) { return false; }
      assignmentLoading = false;
      if (adminGuard(result, assignmentState)) { return false; }
      if (!result.ok || !isObject(result.data)) {
        assignmentCurrent.textContent = "The current assignment could not be read. Saving is blocked until it loads; nothing was changed.";
        setStatus(assignmentState, serverMessage(result, timeoutOrNetwork(result)), "error");
        return false;
      }
      var raw = result.data.assignment;
      if (raw === null || typeof raw === "undefined") {
        assignmentReady = true;
        assignmentVersion = null;
        assignmentCurrentProfile = null;
        var selected = findPolicyProfile(assignmentProfile.value);
        if (selected) { assignmentRevision.value = String(selected.revision); }
        assignmentCurrent.textContent = "No assignment at this scope. It inherits from the next less-specific scope or the default policy (both checks enabled, all masks). Saving creates an assignment pinned to the chosen revision.";
        return true;
      }
      var assignment = policyAssignment(raw);
      if (!assignment) {
        assignmentCurrent.textContent = "The current assignment response was not valid. Saving is blocked; nothing was changed.";
        setStatus(assignmentState, "The current assignment could not be validated.", "error");
        return false;
      }
      assignmentReady = true;
      assignmentVersion = assignment.version;
      assignmentCurrentProfile = {
        id: assignment.profile_id,
        name: assignment.profile_name,
        revision: assignment.profile_revision
      };
      syncPolicyProfileOptions();
      ensurePolicyProfileOption(
        assignment.profile_id, assignment.profile_name, assignment.profile_revision
      );
      assignmentProfile.value = assignment.profile_id;
      assignmentRevision.value = String(assignment.profile_revision);
      assignmentCurrent.textContent = "Current assignment: " + assignment.profile_name +
        " revision " + assignment.profile_revision + " at " +
        policyScopeLabel(assignment.scope_type, assignment.scope_id) +
        " (assignment version " + assignment.version + "). This exact revision stays pinned. " +
        "Later profile revisions do not auto-apply; choose a newer revision and save to reapply explicitly.";
      return true;
    });
  }

  function assignmentProfileChanged() {
    var profile = findPolicyProfile(assignmentProfile.value);
    if (!profile) { return; }
    assignmentRevision.value = String(profile.revision);
    if (assignmentCurrentProfile && assignmentCurrentProfile.id === profile.id &&
        assignmentCurrentProfile.revision !== profile.revision) {
      setStatus(assignmentState,
        "This form now selects the profile's current revision. Saving will reapply it explicitly; " +
        "the existing assignment stays pinned until you save.", "warning");
    }
  }

  function savePolicyAssignment(event) {
    event.preventDefault();
    if (!currentAdmin() || assignmentSaving || assignmentClearing) { return; }
    var target = assignmentTarget();
    if (!target) {
      setStatus(assignmentState, "Choose the department or user that should receive this assignment.", "error");
      return;
    }
    if (!assignmentReady || assignmentLoadedFor !== target.key) {
      setStatus(assignmentState,
        "The current assignment has not been read for this target. Wait for it to load before saving.", "error");
      return;
    }
    var profileId = assignmentProfile.value;
    if (!profileId) {
      setStatus(assignmentState, "Choose a policy profile to assign.", "error");
      return;
    }
    var rawRevision = assignmentRevision.value;
    var revision = Number(rawRevision);
    if (!rawRevision || !isFinite(revision) || revision < 1 ||
        Math.floor(revision) !== revision) {
      setStatus(assignmentState, "The pinned revision must be a whole number of at least 1.", "error");
      return;
    }
    var epoch = sessionEpoch;
    var token = adminStateEpoch;
    var uid = profile.user.id;
    assignmentSaving = true;
    assignmentSubmit.disabled = true;
    assignmentClear.disabled = true;
    setStatus(assignmentState, "Saving the pinned assignment…");
    api("/workspace/api/admin/policy/assignments", {
      method: "POST",
      body: JSON.stringify({
        scope_type: target.scope_type,
        scope_id: target.scope_id,
        profile_id: profileId,
        profile_revision: revision,
        expected_version: assignmentVersion
      })
    }).then(function (result) {
      if (epoch !== sessionEpoch || token !== adminStateEpoch || !currentAdmin(uid)) { return; }
      assignmentSaving = false;
      assignmentSubmit.disabled = false;
      assignmentClear.disabled = false;
      if (adminGuard(result, assignmentState)) { return; }
      if (policyConflict(assignmentState, result,
          "This assignment changed since it was read. Nothing was overwritten. Reload the target to review the current version.")) {
        loadCurrentAssignment();
        return;
      }
      if (!result.ok) {
        setStatus(assignmentState, serverMessage(result, timeoutOrNetwork(result)), "error");
        return;
      }
      var saved = policyAssignment(result.data);
      var message = "Assignment saved" +
        (saved ? " at version " + saved.version : "") +
        ". The selected profile revision is pinned; later profile changes do not advance it automatically.";
      loadCurrentAssignment().then(function (ok) {
        if (ok && epoch === sessionEpoch && token === adminStateEpoch &&
            currentAdmin(uid) && assignmentLoadedFor === target.key) {
          setStatus(assignmentState, message, "ok");
        }
      });
    });
  }

  function clearPolicyAssignment() {
    if (!currentAdmin() || assignmentClearing || assignmentSaving) { return; }
    var target = assignmentTarget();
    if (!target) {
      setStatus(assignmentState, "Choose the department or user whose assignment should be cleared.", "error");
      return;
    }
    if (!assignmentReady || assignmentLoadedFor !== target.key) {
      setStatus(assignmentState,
        "The current assignment has not been read for this target. Wait for it to load before clearing.", "error");
      return;
    }
    if (!assignmentCurrentProfile || assignmentVersion === null) {
      setStatus(assignmentState, "There is no assignment override at this scope to clear.", "ok");
      return;
    }
    var epoch = sessionEpoch;
    var token = adminStateEpoch;
    var uid = profile.user.id;
    assignmentClearing = true;
    assignmentSubmit.disabled = true;
    assignmentClear.disabled = true;
    setStatus(assignmentState, "Clearing the assignment override…");
    api("/workspace/api/admin/policy/assignments/" +
        encodeURIComponent(target.scope_type) + "/clear", {
      method: "POST",
      body: JSON.stringify({
        scope_id: target.scope_id,
        expected_version: assignmentVersion
      })
    }).then(function (result) {
      if (epoch !== sessionEpoch || token !== adminStateEpoch || !currentAdmin(uid)) { return; }
      assignmentClearing = false;
      assignmentSubmit.disabled = false;
      assignmentClear.disabled = false;
      if (adminGuard(result, assignmentState)) { return; }
      if (policyConflict(assignmentState, result,
          "This assignment changed since it was read. Nothing was cleared. Reload the target to review the current version.")) {
        loadCurrentAssignment();
        return;
      }
      if (!result.ok) {
        setStatus(assignmentState, serverMessage(result, timeoutOrNetwork(result)), "error");
        return;
      }
      var cleared = isObject(result.data) && result.data.cleared === true;
      var message = cleared
        ? "Assignment cleared. Users at this scope inherit the next less-specific assignment or the default policy."
        : "No override existed at this scope.";
      assignmentCurrentProfile = null;
      assignmentVersion = null;
      loadCurrentAssignment().then(function (ok) {
        if (ok && epoch === sessionEpoch && token === adminStateEpoch &&
            currentAdmin(uid) && assignmentLoadedFor === target.key) {
          setStatus(assignmentState, message, "ok");
        }
      });
    });
  }

  function renderEffectivePreview(data, selectedUserId) {
    clearNode(effectivePolicy);
    var settings = policySettings(data);
    if (!settings) {
      setStatus(effectiveState, "The effective policy response was not valid. No settings were displayed.", "error");
      return;
    }
    var user = findAdminUser(typeof data.user_id === "string" ? data.user_id : selectedUserId);
    var identity = user
      ? "@" + user.username + " (" + user.full_name + ")"
      : "User " + shortId(typeof data.user_id === "string" ? data.user_id : selectedUserId);
    var intro = document.createElement("p");
    intro.textContent = "Effective policy for " + identity + ".";
    effectivePolicy.appendChild(intro);

    var input = document.createElement("p");
    input.textContent = "Input checks: " + (settings.input_check_enabled ? "enabled" : "DISABLED") +
      " · masks: " + (settings.input_masks.length
        ? settings.input_masks.join(", ") : "none (explicit no masking)") + ".";
    effectivePolicy.appendChild(input);
    var output = document.createElement("p");
    output.textContent = "Output checks: " + (settings.output_check_enabled ? "enabled" : "DISABLED") +
      " · masks: " + (settings.output_masks.length
        ? settings.output_masks.join(", ") : "none (explicit no masking)") + ".";
    effectivePolicy.appendChild(output);

    var source = isObject(data.source) ? data.source : null;
    var winning = document.createElement("p");
    if (source && typeof source.scope_type === "string") {
      winning.textContent = "Winning scope: " +
        policyScopeLabel(source.scope_type, source.scope_id) + " · " +
        (typeof source.profile_name === "string" && source.profile_name
          ? source.profile_name : "Profile " + shortId(source.profile_id)) +
        " revision " + source.revision + ".";
    } else if (data.is_default === true) {
      winning.textContent = "Winning scope: default workspace policy. No assignment exists in the inheritance chain.";
    } else {
      winning.textContent = "Winning scope: not reported by the server.";
    }
    effectivePolicy.appendChild(winning);

    var sources = Array.isArray(data.sources) ? data.sources : [];
    if (sources.length > 0) {
      var heading = document.createElement("p");
      heading.textContent = "Inheritance sources, least to most specific:";
      effectivePolicy.appendChild(heading);
      var list = document.createElement("ul");
      for (var i = 0; i < sources.length; i += 1) {
        var item = sources[i];
        if (!isObject(item) || typeof item.scope_type !== "string") { continue; }
        var entry = document.createElement("li");
        entry.textContent = policyScopeLabel(item.scope_type, item.scope_id) +
          " · " + (typeof item.profile_name === "string" && item.profile_name
            ? item.profile_name : "Profile " + shortId(item.profile_id)) +
          " revision " + item.revision + ".";
        list.appendChild(entry);
      }
      effectivePolicy.appendChild(list);
    } else if (data.is_default === true) {
      var defaultNote = document.createElement("p");
      defaultNote.textContent = "Default inheritance: both checks enabled and all masks selected.";
      effectivePolicy.appendChild(defaultNote);
    }

    var pinned = document.createElement("p");
    pinned.textContent = "This preview uses the currently pinned revisions. Editing a profile does not change it until an assignment is explicitly reapplied.";
    effectivePolicy.appendChild(pinned);
  }

  function loadEffectivePreview() {
    if (!currentAdmin()) { return Promise.resolve(false); }
    var userId = effectiveUser.value;
    if (!userId) {
      setStatus(effectiveState, "Choose a user to preview.", "error");
      return Promise.resolve(false);
    }
    var epoch = sessionEpoch;
    var token = adminStateEpoch;
    var uid = profile.user.id;
    var seq = ++effectiveSeq;
    effectiveLoading = true;
    effectivePreview.disabled = true;
    setStatus(effectiveState, "Resolving the effective policy…");
    return api("/workspace/api/admin/policy/effective?user_id=" + encodeURIComponent(userId))
      .then(function (result) {
        if (seq !== effectiveSeq || epoch !== sessionEpoch ||
            token !== adminStateEpoch || !currentAdmin(uid)) { return false; }
        if (effectiveUser.value !== userId) {
          effectiveLoading = false;
          effectivePreview.disabled = false;
          clearNode(effectivePolicy);
          setStatus(effectiveState, "The selected user changed. Choose Preview to resolve again.");
          return false;
        }
        effectiveLoading = false;
        effectivePreview.disabled = false;
        if (adminGuard(result, effectiveState)) { return false; }
        if (result.status === 404) {
          setStatus(effectiveState, "That user is not active or no longer exists.", "error");
          return false;
        }
        if (!result.ok || !isObject(result.data)) {
          setStatus(effectiveState, serverMessage(result, timeoutOrNetwork(result)), "error");
          return false;
        }
        renderEffectivePreview(result.data, userId);
        if (effectiveState.getAttribute("data-kind") === "error") { return false; }
        setStatus(effectiveState, "");
        return true;
      });
  }

  function clearEffectivePreview() {
    effectiveSeq += 1;
    effectiveLoading = false;
    effectivePreview.disabled = false;
    clearNode(effectivePolicy);
    setStatus(effectiveState, "");
  }

  function clearAlertRefresh() {
    if (alertRefreshTimer !== null) {
      try { clearTimeout(alertRefreshTimer); } catch (error) { /* already finished */ }
      alertRefreshTimer = null;
    }
  }

  function scheduleAlertRefresh() {
    clearAlertRefresh();
    if (!signedIn || !profile || !profile.user || profile.user.role !== "admin" ||
        document.hidden) {
      return;
    }
    var epoch = sessionEpoch;
    alertRefreshEpoch = epoch;
    alertRefreshTimer = setTimeout(function () {
      alertRefreshTimer = null;
      if (epoch !== sessionEpoch || !signedIn || document.hidden ||
          !profile || !profile.user || profile.user.role !== "admin") {
        return;
      }
      loadAlertSummary().then(function (ok) {
        if (ok) { scheduleAlertRefresh(); }
      });
    }, 30000);
  }

  function loadAlertSummary() {
    if (!signedIn || !profile || !profile.user || profile.user.role !== "admin") {
      return Promise.resolve(false);
    }
    if (alertSummaryLoading) { return Promise.resolve(false); }
    var epoch = sessionEpoch;
    var token = adminStateEpoch;
    var seq = ++alertSummarySeq;
    alertSummaryLoading = true;
    return api("/workspace/api/admin/alerts/summary").then(function (result) {
      if (seq !== alertSummarySeq || epoch !== sessionEpoch || token !== adminStateEpoch) {
        return false;
      }
      alertSummaryLoading = false;
      if (!signedIn) { return false; }
      if (authFailure(result)) { return false; }
      if (!result.ok || !isObject(result.data) ||
          typeof result.data.total !== "number" ||
          typeof result.data.unread !== "number" ||
          typeof result.data.acknowledged !== "number") {
        if (result.status === 403) {
          alertsBell.hidden = true;
        } else {
          alertsBell.hidden = false;
          alertsBell.setAttribute("data-state", "unavailable");
          alertsBell.setAttribute("aria-label", "Alerts unavailable");
        }
        alertsBadge.hidden = true;
        alertSummary.textContent = "Alerts are unavailable. Alert counts are unknown; do not assume there are none.";
        clearAlertRefresh();
        return false;
      }
      var total = Math.max(0, Math.floor(result.data.total));
      var unread = Math.max(0, Math.floor(result.data.unread));
      var acknowledged = Math.max(0, Math.floor(result.data.acknowledged));
      alertsBell.hidden = false;
      alertsBell.removeAttribute("data-state");
      alertsBell.setAttribute("aria-label", "Alerts, " + unread + " unread, " + total + " total");
      alertsBadge.textContent = String(unread);
      alertsBadge.hidden = unread === 0;
      alertSummary.textContent = "Block alerts: " + total + " total, " + unread +
        " unread, " + acknowledged + " acknowledged.";
      return true;
    });
  }

  function runSummarySurfaces() {
    // One policy read, and for an administrator exactly one alert count read.
    // The alert count is not requested again from inside loadPolicySummary.
    loadPolicySummary();
    if (profile && profile.user && profile.user.role === "admin") {
      scheduleAlertRefresh();
      loadAlertSummary();
    }
  }

  function beginBaseline() {
    baselineSeq += 1;
    baselinePending = true;
    summariesQueued = false;
    return baselineSeq;
  }

  function cancelBaseline() {
    baselineSeq += 1;
    baselinePending = false;
    summariesQueued = false;
  }

  function queueSummarySurfaces() {
    if (baselinePending) {
      summariesQueued = true;
      return;
    }
    runSummarySurfaces();
  }

  function watchBaseline(reads, isCurrent, token) {
    // Wait for both the initial history read and the readiness read to settle.
    // Their own bounded retries and recovery remain untouched; only the new
    // summary reads wait.  No timer or delay is involved.
    return Promise.all(reads).then(function (results) {
      if (token !== undefined && token !== baselineSeq) {
        // A newer startup or identity reset owns the baseline now, so this
        // settled read must not clear its pending marker.
        return results;
      }
      baselinePending = false;
      if (!isCurrent()) {
        summariesQueued = false;
        return results;
      }
      if (summariesQueued) {
        summariesQueued = false;
        runSummarySurfaces();
      }
      return results;
    });
  }

  function applyProfile(data) {
    if (!isObject(data) || !isObject(data.user) ||
        typeof data.user.id !== "string" || typeof data.user.username !== "string" ||
        typeof data.user.full_name !== "string" || !isObject(data.department) ||
        typeof data.department.name !== "string") {
      throw new Error("invalid profile");
    }
    var previous = profile;
    var sameUser = !!(previous && previous.user && previous.user.id === data.user.id);
    profile = {
      user: data.user,
      department: data.department,
      reviewScope: typeof data.review_scope === "string" ? data.review_scope : null,
      reviewDepartmentIds: Array.isArray(data.review_department_ids) ? data.review_department_ids : [],
      reviewGrants: Array.isArray(data.review_grants) ? data.review_grants : []
    };
    signedIn = true;
    if (!sameUser) { selectedReplyTokens = null; }
    applyChatLimits(data.chat_limits);
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
    if (previous && previous.user && previous.user.id !== data.user.id) {
      resetAdminState();
    }
    tabAdmin.hidden = !isAdmin;
    alertsBell.hidden = !isAdmin;
    if (!isAdmin) {
      clearAlertRefresh();
      alertsBadge.hidden = true;
      alertsBadge.textContent = "0";
      alertsBell.setAttribute("aria-label", "Alerts unavailable");
      alertsBell.removeAttribute("data-state");
    }
    if (!isAdmin && currentView === "admin") { showView("chat"); }
    authView.hidden = true;
    workspaceView.hidden = false;
    appEl.removeAttribute("data-private");
    logoutButton.hidden = false;
    logoutUnconfirmed = false;
    revalidateRetry.hidden = true;
    setStatus(authStatus, "");
    queueSummarySurfaces();
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
    var baselineToken = beginBaseline();
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
        var guardPromise = loadGuardStatus();
        startupGuardPromise = guardPromise;
        var uid = profile.user.id;
        watchBaseline(
          [loadConversations(true), guardPromise],
          function () {
            return epoch === sessionEpoch && checkSeq === sessionCheckSeq &&
              signedIn && !!profile && profile.user.id === uid;
          },
          baselineToken
        );
        return;
      }
      cancelBaseline();
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
    if (!signedIn) { return Promise.resolve(false); }
    if (listLoading) {
      // A reset (login, new chat, send, delete or retry) may supersede an
      // in-flight older page, but a second reset coalesces instead of
      // spending another admission slot.  A load-more never overlaps.
      if (!reset) { return Promise.resolve(false); }
      if (listResetLoading) {
        // A mutation changed the first page while this reset was already in
        // flight.  Coalesce into one follow-up refresh once it settles.
        listRefreshPending = true;
        return listPending;
      }
    }
    var epoch = sessionEpoch;
    var attempt = ++listAttemptSeq;
    var cursor = reset ? null : listCursor;
    var retries = LIST_RETRY_MS.slice();
    listLoading = true;
    listResetLoading = !!reset;
    listRefreshPending = false;
    listRetry.hidden = true;
    if (reset) {
      listLoaded = false;
      setStatus(listState, "Loading conversations…");
    } else {
      setStatus(listState, "Loading more…");
    }
    function stillCurrent() {
      return epoch === sessionEpoch && attempt === listAttemptSeq;
    }
    function failed(result) {
      listLoading = false;
      listResetLoading = false;
      listRefreshPending = false;
      // Never rewrite a failed refresh as an empty account.  Any rows already
      // on screen stay in place and the user gets an explicit safe retry.
      setStatus(
        listState,
        serverMessage(result, timeoutOrNetwork(result)) +
          " Saved conversations may still exist. Retry the conversation list.",
        "error"
      );
      listRetry.hidden = false;
      return false;
    }
    function request() {
      var path = "/workspace/api/conversations?limit=" + LIST_LIMIT +
        (cursor ? "&after=" + encodeURIComponent(cursor) : "");
      return api(path).then(function (result) {
        if (!stillCurrent()) { return false; }
        if (authFailure(result)) { return false; }
        if (result.status === 403) {
          listLoading = false;
          listResetLoading = false;
          listRefreshPending = false;
          setStatus(listState, "Conversation list access was denied.", "denied");
          listRetry.hidden = true;
          return false;
        }
        if (!result.ok || !isObject(result.data) || !Array.isArray(result.data.items)) {
          if (retries.length && retriableRead(result)) {
            setStatus(listState, "The conversation list is temporarily unavailable. Retrying…", "warning");
            return wait(retries.shift()).then(function () {
              if (!stillCurrent()) { return false; }
              return request();
            });
          }
          return failed(result);
        }
        if (reset && listRefreshPending) {
          // A mutation asked for a new first page while this reset was in
          // flight, so this snapshot predates it.  Discard the rows/cursor and
          // spend the single follow-up on a fresh first-page read.
          listRefreshPending = false;
          listLoading = false;
          listResetLoading = false;
          listPending = loadConversations(true);
          return listPending;
        }
        listLoading = false;
        listResetLoading = false;
        listRetry.hidden = true;
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
    listPending = request();
    return listPending;
  }

  loadMoreButton.addEventListener("click", function () { loadConversations(false); });

  listRetry.addEventListener("click", function () {
    if (!signedIn || listLoading) { return; }
    loadConversations(true).then(function (loaded) {
      // A retry must not discard the current conversation or its draft.  It
      // only refreshes read-only list metadata; focus moves to the recovered
      // rows (or the create control when the account really has none).
      if (!loaded) {
        try { listRetry.focus(); } catch (error) { /* non-fatal */ }
        return;
      }
      var target = conversationList.firstChild || newChatButton;
      try { target.focus(); } catch (error) { /* non-fatal */ }
    });
  });

  function positiveInt(value) {
    return typeof value === "number" && isFinite(value) &&
      Math.floor(value) === value && value > 0 ? value : null;
  }

  function parseChatLimits(raw) {
    if (!isObject(raw)) { return null; }
    var maxReply = positiveInt(raw.max_reply_tokens);
    var defaultReply = positiveInt(raw.default_reply_tokens);
    var maxPrompt = positiveInt(raw.max_prompt_chars);
    if (maxReply === null || defaultReply === null || maxPrompt === null) { return null; }
    if (defaultReply > maxReply) { defaultReply = maxReply; }
    return {
      maxReplyTokens: maxReply,
      defaultReplyTokens: defaultReply,
      maxPromptChars: maxPrompt,
      contextMessages: positiveInt(raw.context_messages),
      contextBudget: positiveInt(raw.context_budget),
      policyTokenBudget: positiveInt(raw.policy_token_budget)
    };
  }

  function applyChatLimits(raw) {
    var next = parseChatLimits(raw);
    chatLimits = next;
    clearNode(replyLength);
    replyLength.value = "";
    if (!next) {
      selectedReplyTokens = null;
      replyLength.disabled = true;
      composer.removeAttribute("maxlength");
      return;
    }
    composer.setAttribute("maxlength", String(next.maxPromptChars));
    var current = positiveInt(selectedReplyTokens);
    if (current !== null && current > next.maxReplyTokens) { current = null; }
    selectedReplyTokens = current;
    var short = Math.min(next.defaultReplyTokens, 256);
    var values = [];
    var candidates = [short, next.defaultReplyTokens, next.maxReplyTokens];
    for (var i = 0; i < candidates.length; i += 1) {
      var value = positiveInt(candidates[i]);
      if (value !== null && value <= next.maxReplyTokens && values.indexOf(value) < 0) {
        values.push(value);
      }
    }
    if (selectedReplyTokens !== null && values.indexOf(selectedReplyTokens) < 0) {
      values.push(selectedReplyTokens);
    }
    values.sort(function (left, right) { return left - right; });
    for (var index = 0; index < values.length; index += 1) {
      var tokenValue = values[index];
      var label = tokenValue === next.defaultReplyTokens ? "Standard" :
        tokenValue === next.maxReplyTokens ? "Longer" :
        tokenValue === short ? "Short" : "Selected";
      var option = document.createElement("option");
      option.value = String(tokenValue);
      option.textContent = label + " (" + tokenValue + " tokens)";
      replyLength.appendChild(option);
    }
    if (selectedReplyTokens === null || values.indexOf(selectedReplyTokens) < 0) {
      selectedReplyTokens = next.defaultReplyTokens;
    }
    replyLength.value = String(selectedReplyTokens);
    replyLength.disabled = false;
  }

  function contextNoticeText(context) {
    if (isObject(context)) {
      var selected = positiveInt(context.selected_messages);
      var omitted = typeof context.omitted_messages === "number" &&
        isFinite(context.omitted_messages) && context.omitted_messages >= 0
        ? context.omitted_messages : null;
      if (selected !== null && omitted !== null) {
        if (omitted > 0) {
          return "Full saved history is kept. The latest model request included " +
            selected + " messages; " + omitted + " older saved " +
            (omitted === 1 ? "message was" : "messages were") +
            " not included to fit the configured context.";
        }
        return "Full saved history is kept. The latest model request included all " +
          selected + " messages.";
      }
    }
    return GENERIC_CONTEXT_NOTICE;
  }

  function updateComposer() {
    var ready = !!(signedIn && currentConversation);
    composer.disabled = !ready || sending;
    sendButton.disabled = !ready || sending;
    replyLength.disabled = !ready || sending || !chatLimits;
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
      var savedBlock = safeBlock(item.block, item.block && item.block.ref);
      if (savedBlock) { appendBlockNotice(article, savedBlock); }
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

  function enterChatView() {
    // Opening an own conversation or starting a new chat is an explicit
    // navigation action, even when the user came from Admin or Review.  It
    // must not carry that panel over and must close the mobile sidebar.
    currentView = "chat";
    setViewTabs("chat");
    topbarTitle.textContent = "Chat";
    setSidebar(false);
  }

  function openConversation(id, options) {
    if (!signedIn || typeof id !== "string") { return Promise.resolve(false); }
    var settings = options || {};
    if (!settings.quiet) { enterChatView(); }
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
    if (!settings.quiet) { contextNotice.textContent = GENERIC_CONTEXT_NOTICE; }
    deleteConfirm.hidden = true;
    if (!settings.quiet) { showChatBlock(null); }
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
    enterChatView();
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
    var replyTokens = positiveInt(Number(replyLength.value));
    if (replyTokens === null || !chatLimits || replyTokens > chatLimits.maxReplyTokens) {
      replyTokens = positiveInt(selectedReplyTokens);
    } else {
      selectedReplyTokens = replyTokens;
    }
    var body = { text: text };
    if (replyTokens !== null && chatLimits && replyTokens <= chatLimits.maxReplyTokens) {
      body.max_tokens = replyTokens;
    }
    var seq = chatSeq;
    var epoch = sessionEpoch;
    var send = ++sendSeq;
    drafts[conversationId] = text;
    sending = true;
    updateComposer();
    setStatus(chatStatus, "Sending…");
    api("/workspace/api/conversations/" + encodeURIComponent(conversationId) + "/messages", {
      method: "POST",
      body: JSON.stringify(body)
    }).then(function (result) {
      if (epoch !== sessionEpoch) { return; }
      if (send !== sendSeq) { return; }
      if (authFailure(result)) { return; }
      var sameConversation = currentConversation && currentConversation.id === conversationId &&
        chatSeq === seq;
      var message;
      var kind = "error";
      var keepText = false;
      var noticeText = GENERIC_CONTEXT_NOTICE;
      if (result.timeout) {
        message = "Completion is uncertain: the request timed out and the server may still finish. Refresh this conversation before retrying; your text has been kept.";
        kind = "warning";
        keepText = true;
      } else if (result.network) {
        message = "The workspace could not be reached. Your text has been kept; refresh to check whether the turn was saved.";
        kind = "warning";
        keepText = true;
      } else if (result.status === 403) {
        var errorBody = isObject(result.data) && isObject(result.data.error) ? result.data.error : {};
        var parsedBlock = safeBlock(
          errorBody.block,
          typeof errorBody.turn_request_id === "string" && errorBody.turn_request_id
            ? errorBody.turn_request_id
            : (isObject(errorBody.block) ? errorBody.block.ref : "")
        );
        if (parsedBlock) {
          showChatBlock(parsedBlock);
          message = parsedBlock.title + ". The original prompt is saved with a Blocked label.";
        } else {
          showChatBlock(null);
          message = "The message was blocked by the safety checks. The original prompt is saved with a Blocked label.";
        }
        kind = "denied";
      } else if (result.ok) {
        noticeText = contextNoticeText(result.data && result.data.context);
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
      } else if (result.status === 413) {
        message = "The latest message is over the configured input limit. Shorten it or ask an administrator about the workspace context budget. Your text has been kept.";
        kind = "denied";
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
        // A saved turn changes recency.  Refresh only the existing list data;
        // this is a safe read of the first page and does not touch the current
        // conversation, its draft or the message transcript.
        loadConversations(true);
        if (profile && profile.user && profile.user.role === "admin") {
          loadAlertSummary();
        }
        contextNotice.textContent = noticeText;
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

  replyLength.addEventListener("change", function () {
    var value = positiveInt(Number(replyLength.value));
    if (chatLimits && value !== null && value <= chatLimits.maxReplyTokens) {
      selectedReplyTokens = value;
    } else if (chatLimits) {
      selectedReplyTokens = chatLimits.defaultReplyTokens;
      replyLength.value = String(selectedReplyTokens);
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

  function setAdminSectionTabs(section) {
    adminTabUsers.setAttribute("aria-selected", section === "users" ? "true" : "false");
    adminTabDepartments.setAttribute("aria-selected", section === "departments" ? "true" : "false");
    adminTabPolicies.setAttribute("aria-selected", section === "policies" ? "true" : "false");
    adminTabAlerts.setAttribute("aria-selected", section === "alerts" ? "true" : "false");
    adminTabAccess.setAttribute("aria-selected", section === "access" ? "true" : "false");
    adminUsersPanel.hidden = section !== "users";
    adminDepartmentsPanel.hidden = section !== "departments";
    adminPoliciesPanel.hidden = section !== "policies";
    adminAlertsPanel.hidden = section !== "alerts";
    adminAccessPanel.hidden = section !== "access";
  }

  function showAdminSection(section) {
    if (!profile || !profile.user || profile.user.role !== "admin") {
      setStatus(globalStatus, "Administrator access is not available for this account.", "denied");
      return;
    }
    adminSection = section;
    setAdminSectionTabs(section);
    loadAdminSection(section);
  }

  function loadAdminSection(section) {
    if (!signedIn || !profile || !profile.user || profile.user.role !== "admin") { return; }
    if (section === "users") {
      // Department names are needed by the user table and the create-user form.
      if (!adminDepartmentsLoaded) {
        queueAdminList(function () {
          return adminDepartmentsLoaded ? Promise.resolve(true) : loadDepartments(true);
        });
      }
      if (!adminUsersLoaded) {
        queueAdminList(function () {
          return adminUsersLoaded ? Promise.resolve(true) : loadUsers(true);
        });
      }
      return;
    }
    if (section === "departments") {
      if (!adminDepartmentsLoaded) {
        queueAdminList(function () {
          return adminDepartmentsLoaded ? Promise.resolve(true) : loadDepartments(true);
        });
      }
      return;
    }
    if (section === "policies") {
      // Assignment targets and the effective preview use the same bounded
      // loaded admin lists as the other sections; no separate directory read.
      if (!adminDepartmentsLoaded) {
        queueAdminList(function () {
          return adminDepartmentsLoaded ? Promise.resolve(true) : loadDepartments(true);
        });
      }
      if (!adminUsersLoaded) {
        queueAdminList(function () {
          return adminUsersLoaded ? Promise.resolve(true) : loadUsers(true);
        });
      }
      queueAdminList(function () {
        return adminPoliciesLoaded ? Promise.resolve(true) : loadPolicyProfiles(true);
      }).then(function (ok) {
        if (!ok || !currentAdmin()) { return; }
        syncPolicyTargetOptions();
        syncPolicyProfileOptions();
        loadCurrentAssignment();
      });
      return;
    }
    if (section === "alerts") {
      // Filters are populated only from records this session actually loaded.
      if (!adminDepartmentsLoaded) {
        queueAdminList(function () {
          return adminDepartmentsLoaded ? Promise.resolve(true) : loadDepartments(true);
        });
      }
      if (!adminUsersLoaded) {
        queueAdminList(function () {
          return adminUsersLoaded ? Promise.resolve(true) : loadUsers(true);
        });
      }
      syncAlertFilterOptions();
      loadAlerts(true);
      return;
    }
    if (section === "access") {
      if (!adminDepartmentsLoaded) {
        queueAdminList(function () {
          return adminDepartmentsLoaded ? Promise.resolve(true) : loadDepartments(true);
        });
      }
      if (!adminUsersLoaded) {
        queueAdminList(function () {
          return adminUsersLoaded ? Promise.resolve(true) : loadUsers(true);
        });
      }
      if (!adminGrantsLoaded) {
        queueAdminList(function () {
          return adminGrantsLoaded ? Promise.resolve(true) : loadGrants(true);
        });
      }
      if (!adminAccessLoaded) {
        queueAdminList(function () {
          return adminAccessLoaded ? Promise.resolve(true) : loadAccessLog(true);
        });
      }
    }
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
    if (view === "admin") { showAdminSection(adminSection); }
  }

  tabChat.addEventListener("click", function () { showView("chat"); });
  tabReview.addEventListener("click", function () { showView("review"); });
  tabAdmin.addEventListener("click", function () { showView("admin"); });
  adminTabUsers.addEventListener("click", function () { showAdminSection("users"); });
  adminTabDepartments.addEventListener("click", function () { showAdminSection("departments"); });
  adminTabPolicies.addEventListener("click", function () { showAdminSection("policies"); });
  adminTabAlerts.addEventListener("click", function () { showAdminSection("alerts"); });
  adminTabAccess.addEventListener("click", function () { showAdminSection("access"); });
  alertsBell.addEventListener("click", function () {
    if (!profile || !profile.user || profile.user.role !== "admin") { return; }
    showView("admin");
    showAdminSection("alerts");
  });

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
    empty.className = "admin-table-empty";
    empty.textContent = text;
    container.appendChild(empty);
  }

  function renderTableHead(container, labels, cols) {
    var head = document.createElement("div");
    head.className = "admin-table-head cols-" + cols;
    for (var i = 0; i < labels.length; i += 1) {
      var cell = document.createElement("div");
      cell.textContent = labels[i];
      head.appendChild(cell);
    }
    container.appendChild(head);
  }

  function tableCell(text, className) {
    var cell = document.createElement("div");
    if (className) { cell.className = className; }
    cell.textContent = text;
    return cell;
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
    syncPolicyTargetOptions();
    syncAlertFilterOptions();
  }

  function syncAlertFilterOptions() {
    fillSelect(alertDepartment, adminDepartments, "All departments", function (item) {
      return item.name;
    });
    fillSelect(alertUser, adminUsers, "All users", function (item) {
      return "@" + item.username + " (" + item.full_name + ")";
    });
  }

  function resetAlertFilterOptions() {
    fillSelect(alertDepartment, [], "All departments", function () { return ""; });
    fillSelect(alertUser, [], "All users", function () { return ""; });
    alertStage.value = "";
    alertUnread.value = "";
    alertAck.value = "";
  }

  function currentAdmin(uid) {
    return signedIn && profile && profile.user && profile.user.role === "admin" &&
      (typeof uid !== "string" || !uid || profile.user.id === uid);
  }

  function syncGrantForm() {
    var global = grantScope.value === "global";
    grantDepartmentField.hidden = global;
    grantDepartment.disabled = global;
    grantGlobalField.hidden = !global;
    if (!global) { grantGlobalConfirm.checked = false; }
  }

  function renderDepartments(items, reset) {
    if (reset) {
      clearNode(departmentList);
      renderTableHead(departmentList, ["Department", "Created"], 2);
    }
    var query = departmentSearchText.toLowerCase();
    var shown = 0;
    for (var i = 0; i < items.length; i += 1) {
      var item = items[i];
      if (!isObject(item) || typeof item.id !== "string" || typeof item.name !== "string") { continue; }
      if (query && item.name.toLowerCase().indexOf(query) < 0) { continue; }
      var row = document.createElement("div");
      row.className = "admin-table-row cols-2";
      row.appendChild(tableCell(item.name));
      row.appendChild(tableCell("Created " + formatDate(item.created_at), "cell-muted"));
      departmentList.appendChild(row);
      shown += 1;
    }
    if (reset && shown === 0) {
      appendEmpty(departmentList, query
        ? "No loaded departments match this search. Search applies only to rows loaded so far."
        : "No departments have been created.");
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
    if (reset) {
      clearNode(userList);
      renderTableHead(userList, ["Account", "Role", "Department", "Status", "Actions"], 5);
    }
    var query = userSearchText.toLowerCase();
    var selfId = profile && profile.user ? profile.user.id : null;
    var shown = 0;
    for (var i = 0; i < items.length; i += 1) {
      var item = items[i];
      if (!isObject(item) || typeof item.id !== "string" || typeof item.username !== "string") { continue; }
      var fullName = typeof item.full_name === "string" ? item.full_name : "Unknown name";
      var department = departmentLabel(item.department_id);
      var role = item.role === "admin" ? "Administrator" : "Employee";
      var status = item.disabled ? "Disabled" : "Active";
      var haystack = (fullName + " " + item.username + " " + role + " " + department + " " + status).toLowerCase();
      if (query && haystack.indexOf(query) < 0) { continue; }
      var row = document.createElement("div");
      row.className = "admin-table-row cols-5";
      row.setAttribute("data-user", item.id);
      var account = tableCell(fullName + " · @" + item.username);
      if (item.id === selfId) { account.appendChild(tableCell("This is your account", "cell-muted")); }
      row.appendChild(account);
      row.appendChild(tableCell(role));
      row.appendChild(tableCell(department));
      row.appendChild(tableCell(status + (item.disabled ? "" : " · signed in sessions allowed"), "cell-muted"));
      var actions = document.createElement("div");
      actions.className = "cell-actions";
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
                var token = adminStateEpoch;
                setStatus(adminStatus, "Disabling @" + userItem.username + "…");
                api("/workspace/api/admin/users/" + encodeURIComponent(userItem.id) + "/disable", {
                  method: "POST",
                  body: "{}"
                }).then(function (result) {
                  if (epoch !== sessionEpoch || token !== adminStateEpoch) { return; }
                  if (adminGuard(result, adminStatus)) { return; }
                  if (!result.ok) {
                    setStatus(adminStatus, serverMessage(result, timeoutOrNetwork(result)), "error");
                    return;
                  }
                  setStatus(adminStatus, "Account @" + userItem.username +
                    " disabled. Existing sign-ins were revoked.", "ok");
                  queueAdminList(function () { return loadUsers(true); }).then(function (ok) {
                    if (!ok && epoch === sessionEpoch && token === adminStateEpoch) {
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
      shown += 1;
    }
    if (reset && shown === 0) {
      appendEmpty(userList, query
        ? "No loaded user accounts match this search. Search applies only to rows loaded so far."
        : "No user accounts have been created.");
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
    if (reset) {
      clearNode(accessList);
      renderTableHead(accessList, ["Time", "Actor", "Action", "Department", "Conversation"], 5);
    }
    var query = accessSearchText.toLowerCase();
    var shown = 0;
    for (var i = 0; i < items.length; i += 1) {
      var item = items[i];
      if (!isObject(item) || typeof item.action !== "string") { continue; }
      var actor = typeof item.actor_id === "string" && item.actor_id
        ? shortId(item.actor_id) : "unknown";
      var department = departmentLabel(item.department_id);
      var conversation = typeof item.conversation_id === "string" && item.conversation_id
        ? shortId(item.conversation_id) : "none";
      var when = formatDate(item.created_at);
      var haystack = (when + " " + actor + " " + item.action + " " + department + " " + conversation).toLowerCase();
      if (query && haystack.indexOf(query) < 0) { continue; }
      var row = document.createElement("div");
      row.className = "admin-table-row cols-5";
      row.appendChild(tableCell(when, "cell-muted"));
      row.appendChild(tableCell("Actor " + actor));
      row.appendChild(tableCell(item.action));
      row.appendChild(tableCell(department));
      row.appendChild(tableCell("Conversation " + conversation, "cell-muted"));
      accessList.appendChild(row);
      shown += 1;
    }
    if (reset && shown === 0) {
      appendEmpty(accessList, query
        ? "No loaded access events match this search. Search applies only to rows loaded so far."
        : "The access log is empty.");
    }
  }

  function loadDepartments(reset) {
    if (!signedIn || departmentLoading) { return Promise.resolve(false); }
    var epoch = sessionEpoch;
    var token = adminStateEpoch;
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
      if (epoch !== sessionEpoch || token !== adminStateEpoch) { return false; }
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
      adminDepartmentsLoaded = true;
      renderDepartments(adminDepartments, true);
      departmentCursor = typeof result.data.next === "string" && result.data.next ? result.data.next : null;
      departmentMore.hidden = !departmentCursor;
      setStatus(departmentState, adminDepartments.length === 0
        ? "No departments have been created."
        : (departmentCursor ? "More departments available." : ""));
      syncDepartmentOptions();
      return true;
    });
  }

  function loadUsers(reset) {
    if (!signedIn || userLoading) { return Promise.resolve(false); }
    var epoch = sessionEpoch;
    var token = adminStateEpoch;
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
      if (epoch !== sessionEpoch || token !== adminStateEpoch) { return false; }
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
      adminUsersLoaded = true;
      renderUsers(adminUsers, true);
      userCursor = typeof result.data.next === "string" && result.data.next ? result.data.next : null;
      userMore.hidden = !userCursor;
      setStatus(userState, adminUsers.length === 0
        ? "No user accounts have been created."
        : (userCursor ? "More users available." : ""));
      syncDepartmentOptions();
      return true;
    });
  }

  function loadGrants(reset) {
    if (!signedIn || grantLoading) { return Promise.resolve(false); }
    var epoch = sessionEpoch;
    var token = adminStateEpoch;
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
      if (epoch !== sessionEpoch || token !== adminStateEpoch) { return false; }
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
      adminGrantsLoaded = true;
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
    var token = adminStateEpoch;
    accessLoading = true;
    if (reset) {
      accessCursor = null;
      adminAccess = [];
      clearNode(accessList);
      setStatus(accessState, "Loading access log…");
    } else {
      setStatus(accessState, "Loading more access events…");
    }
    var path = "/workspace/api/admin/access-log?limit=" + LIST_LIMIT +
      (accessCursor ? "&after=" + encodeURIComponent(accessCursor) : "");
    return api(path).then(function (result) {
      if (epoch !== sessionEpoch || token !== adminStateEpoch) { return false; }
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
      adminAccess = reset ? got : adminAccess.concat(got);
      adminAccessLoaded = true;
      renderAccess(adminAccess, true);
      accessCursor = typeof result.data.next === "string" && result.data.next ? result.data.next : null;
      accessMore.hidden = !accessCursor;
      setStatus(accessState, adminAccess.length === 0
        ? "The access log is empty."
        : (accessCursor ? "More access events available." : ""));
      return true;
    });
  }

  function alertQueryPath() {
    var parts = ["limit=50"];
    if (alertStage.value) { parts.push("stage=" + encodeURIComponent(alertStage.value)); }
    if (alertDepartment.value) {
      parts.push("department_id=" + encodeURIComponent(alertDepartment.value));
    }
    if (alertUser.value) { parts.push("user_id=" + encodeURIComponent(alertUser.value)); }
    if (alertUnread.value) {
      parts.push("unread=" + encodeURIComponent(alertUnread.value));
    }
    if (alertAck.value) {
      parts.push("acknowledged=" + encodeURIComponent(alertAck.value));
    }
    if (alertCursor) { parts.push("after=" + encodeURIComponent(alertCursor)); }
    return "/workspace/api/admin/alerts?" + parts.join("&");
  }

  function alertReason(item) {
    if (typeof item.reason_text === "string" && item.reason_text) {
      return item.reason_text;
    }
    var detail = Object.prototype.hasOwnProperty.call(BLOCK_DETAILS, item.reason_code)
      ? BLOCK_DETAILS[item.reason_code] : null;
    return detail ? detail.reason : "Blocked by policy.";
  }

  function alertProfile(item) {
    var sources = Array.isArray(item.control_sources) ? item.control_sources : [];
    var source = sources.length > 0 ? sources[sources.length - 1] : null;
    var scopeType = source && typeof source.scope_type === "string" ? source.scope_type : "";
    var scope = "Workspace";
    if (scopeType === "department") {
      var department = typeof item.department_name === "string" && item.department_name
        ? item.department_name : departmentLabel(source.scope_id);
      scope = "Department · " + department;
    } else if (scopeType === "user") {
      var user = typeof item.full_name === "string" && item.full_name
        ? item.full_name
        : (typeof item.username === "string" && item.username
          ? "@" + item.username : shortId(source.scope_id));
      scope = "User · " + user;
    }
    // The visible label uses only the validated numeric source revision. The
    // full opaque control_revision stays inside Technical details.
    var revision = source && typeof source.revision === "number" &&
      source.revision >= 1 && !isNaN(source.revision)
      ? String(source.revision) : "unavailable";
    var loaded = source && typeof source.profile_id === "string"
      ? findPolicyProfile(source.profile_id) : null;
    var name = loaded && typeof loaded.name === "string" && loaded.name
      ? loaded.name
      : (typeof item.profile_name === "string" && item.profile_name
        ? item.profile_name
        : (typeof item.policy_name === "string" && item.policy_name ? item.policy_name : ""));
    var label = name || scope;
    return label + " · revision " + revision;
  }

  function alertProfileCell(item) {
    var cell = tableCell(alertProfile(item));
    var revision = typeof item.control_revision === "string" && item.control_revision
      ? item.control_revision : "unavailable";
    var digest = typeof item.control_digest === "string" && item.control_digest
      ? item.control_digest : "unavailable";
    var details = document.createElement("details");
    var summary = document.createElement("summary");
    summary.textContent = "Technical details";
    details.appendChild(summary);
    var revisionLine = document.createElement("p");
    revisionLine.textContent = "Policy revision: " + revision;
    details.appendChild(revisionLine);
    var digestLine = document.createElement("p");
    digestLine.textContent = "Control digest: " + digest;
    details.appendChild(digestLine);
    cell.appendChild(details);
    return cell;
  }

  function appendAlertRetry(container, reset) {
    var retry = document.createElement("button");
    retry.type = "button";
    retry.className = "ghost";
    retry.textContent = reset ? "Retry alerts" : "Retry loading more alerts";
    retry.addEventListener("click", function () { loadAlerts(reset); });
    container.appendChild(retry);
  }

  function disableAlertActions(buttons, disabled) {
    for (var i = 0; i < buttons.length; i += 1) {
      if (buttons[i]) { buttons[i].disabled = disabled; }
    }
  }

  function applyAlertState(item, data) {
    if (!isObject(data) || typeof data.alert_id !== "string" || data.alert_id !== item.id) {
      return;
    }
    item.read = data.read === true;
    item.read_at = typeof data.read_at === "number" ? data.read_at : null;
    item.acknowledged = data.acknowledged === true;
    item.acknowledged_at = typeof data.acknowledged_at === "number"
      ? data.acknowledged_at : null;
  }

  function runAlertAction(item, action, buttons) {
    if (!currentAdmin() || alertActionBusy || (action !== "read" && action !== "ack")) {
      return;
    }
    if (action === "read" && item.read) { return; }
    if (action === "ack" && item.acknowledged) { return; }
    var epoch = sessionEpoch;
    var token = adminStateEpoch;
    var uid = profile.user.id;
    var busyKey = item.id + ":" + action;
    alertActionBusy = busyKey;
    disableAlertActions(buttons, true);
    setStatus(alertState, action === "read" ? "Marking alert read…" : "Acknowledging alert…");
    api("/workspace/api/admin/alerts/" + encodeURIComponent(item.id) + "/" + action, {
      method: "POST",
      body: "{}"
    }).then(function (result) {
      if (epoch !== sessionEpoch || token !== adminStateEpoch || !currentAdmin(uid)) {
        return;
      }
      if (alertActionBusy === busyKey) { alertActionBusy = ""; }
      if (authFailure(result)) { return; }
      if (result.status === 403) {
        disableAlertActions(buttons, false);
        setStatus(alertState, "Administrator permission was denied by the server.", "denied");
        return;
      }
      if (!result.ok) {
        disableAlertActions(buttons, false);
        setStatus(alertState, serverMessage(result, timeoutOrNetwork(result)), "error");
        return;
      }
      applyAlertState(item, result.data);
      renderAlerts(alertsList, true);
      var message = action === "read" ? "Alert marked read." : "Alert acknowledged.";
      loadAlertSummary();
      loadAlerts(true).then(function (ok) {
        if (ok && epoch === sessionEpoch && token === adminStateEpoch && currentAdmin(uid)) {
          setStatus(alertState, message, "ok");
        }
      });
    });
  }

  function viewAlertConversation(item) {
    if (!currentAdmin() || typeof item.conversation_id !== "string" || !item.conversation_id) {
      return;
    }
    var conversationId = item.conversation_id;
    alertDetail.hidden = false;
    clearNode(alertDetail);
    if (!profile || !profile.reviewScope) {
      // The administrator can see alert metadata but has no review grant, so
      // do not ask any endpoint for original message text and do not claim the
      // conversation was opened.
      var denied = document.createElement("p");
      denied.textContent = "No review permission. Your account has no review scope, so " +
        "conversation " + shortId(conversationId) + " was not opened and its original " +
        "message text was not requested. A review grant is required before this content " +
        "can be viewed.";
      alertDetail.appendChild(denied);
      setStatus(alertState, "No review permission. The conversation was not opened.", "denied");
      return;
    }
    var note = document.createElement("p");
    note.textContent = "Conversation " + shortId(conversationId) +
      " is opened through the grant-controlled review endpoint. The server denies access without a matching review grant.";
    alertDetail.appendChild(note);
    showView("review");
    // Existing grant-controlled review loader; the Alerts page never reads
    // original message text or uses the owner conversation endpoint.
    openReviewConversation(conversationId);
  }

  function renderAlerts(items, reset) {
    if (reset) {
      clearNode(alertList);
      renderTableHead(alertList, [
        "User", "Department", "Time and state", "Stage and reason",
        "Profile and reference", "Actions"
      ], 6);
    }
    if (reset && items.length === 0) {
      appendEmpty(alertList, "No block alerts match these filters in the loaded result. This list is not a global alert count; the summary above reports totals.");
    }
    for (var i = 0; i < items.length; i += 1) {
      var item = items[i];
      if (!isObject(item) || typeof item.id !== "string") { continue; }
      var username = typeof item.username === "string" ? item.username : "unknown";
      var fullName = typeof item.full_name === "string" ? item.full_name : "Unknown employee";
      var department = typeof item.department_name === "string" && item.department_name
        ? item.department_name : departmentLabel(item.department_id);
      var row = document.createElement("div");
      row.className = "admin-table-row cols-6";
      row.setAttribute("data-alert", item.id);
      row.appendChild(tableCell(fullName + " · @" + username));
      row.appendChild(tableCell(department));
      row.appendChild(tableCell(
        formatDate(item.created_at) + " · " + (item.read ? "Read" : "Unread") +
        " · " + (item.acknowledged ? "Acknowledged" : "Not acknowledged"),
        "cell-muted"
      ));
      var stage = tableCell(item.stage === "output" ? "Output" : "Input");
      stage.appendChild(tableCell(alertReason(item), "cell-muted"));
      row.appendChild(stage);
      var profileCell = alertProfileCell(item);
      profileCell.appendChild(tableCell(
        "Reference " + (typeof item.request_id === "string" && item.request_id
          ? item.request_id : "Unavailable"),
        "cell-muted"
      ));
      row.appendChild(profileCell);
      var actions = document.createElement("div");
      actions.className = "cell-actions";
      var readButton = document.createElement("button");
      readButton.type = "button";
      readButton.className = "ghost";
      readButton.textContent = "Mark read";
      readButton.disabled = item.read === true;
      var ackButton = document.createElement("button");
      ackButton.type = "button";
      ackButton.className = "ghost";
      ackButton.textContent = "Acknowledge";
      ackButton.disabled = item.acknowledged === true;
      var viewButton = document.createElement("button");
      viewButton.type = "button";
      viewButton.className = "ghost";
      viewButton.textContent = "View conversation";
      viewButton.disabled = typeof item.conversation_id !== "string" || !item.conversation_id;
      var buttons = [readButton, ackButton, viewButton];
      readButton.addEventListener("click", function (alertItem, controls) {
        return function () { runAlertAction(alertItem, "read", controls); };
      }(item, buttons));
      ackButton.addEventListener("click", function (alertItem, controls) {
        return function () { runAlertAction(alertItem, "ack", controls); };
      }(item, buttons));
      viewButton.addEventListener("click", function (alertItem) {
        return function () { viewAlertConversation(alertItem); };
      }(item));
      actions.appendChild(readButton);
      actions.appendChild(ackButton);
      actions.appendChild(viewButton);
      row.appendChild(actions);
      alertList.appendChild(row);
    }
  }

  function loadAlerts(reset) {
    if (!currentAdmin()) { return Promise.resolve(false); }
    if (!reset && alertLoading) { return Promise.resolve(false); }
    if (alertUnread.value === "true" && alertAck.value === "true") {
      setStatus(alertState, "Unread only cannot be combined with acknowledged alerts. Choose one filter.", "error");
      return Promise.resolve(false);
    }
    var epoch = sessionEpoch;
    var token = adminStateEpoch;
    var uid = profile.user.id;
    var seq = ++alertListSeq;
    alertLoading = true;
    if (reset) {
      alertsLoaded = false;
      alertCursor = null;
      alertsList = [];
      alertMore.hidden = true;
      clearNode(alertList);
      alertDetail.hidden = true;
      clearNode(alertDetail);
      setStatus(alertState, "Loading block alerts…");
    } else {
      setStatus(alertState, "Loading more block alerts…");
      alertMore.disabled = true;
    }
    var path = alertQueryPath();
    return api(path).then(function (result) {
      if (seq !== alertListSeq || epoch !== sessionEpoch || token !== adminStateEpoch ||
          !currentAdmin(uid)) {
        return false;
      }
      alertLoading = false;
      alertMore.disabled = false;
      if (authFailure(result)) { return false; }
      if (result.status === 403) {
        setStatus(alertState, "Administrator permission was denied by the server.", "denied");
        return false;
      }
      if (!result.ok || !isObject(result.data) || !Array.isArray(result.data.items)) {
        setStatus(alertState, serverMessage(result, timeoutOrNetwork(result)), "error");
        if (reset) {
          clearNode(alertList);
          appendEmpty(alertList, "Block alerts could not be loaded.");
          appendAlertRetry(alertList, true);
        } else {
          appendAlertRetry(alertList, false);
        }
        return false;
      }
      var got = [];
      for (var i = 0; i < result.data.items.length; i += 1) {
        var item = result.data.items[i];
        if (isObject(item) && typeof item.id === "string") { got.push(item); }
      }
      alertsList = reset ? got : alertsList.concat(got);
      alertsLoaded = true;
      renderAlerts(alertsList, true);
      alertCursor = typeof result.data.next === "string" && result.data.next ? result.data.next : null;
      alertMore.hidden = !alertCursor;
      setStatus(alertState, alertsList.length === 0
        ? "No block alerts match these filters. The summary above reports overall totals."
        : "Showing " + alertsList.length + " loaded alert" +
          (alertsList.length === 1 ? "" : "s") + "." +
          (alertCursor ? " More may be available." : " No more pages in this filtered result."));
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
    adminStateEpoch += 1;
    adminLoaded = false;
    adminDepartments = [];
    adminUsers = [];
    adminAccess = [];
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
    adminDepartmentsLoaded = false;
    adminUsersLoaded = false;
    adminGrantsLoaded = false;
    adminAccessLoaded = false;
    adminPoliciesLoaded = false;
    policyProfiles = [];
    policyProfilesLoading = false;
    policyProfilesSeq += 1;
    policyCursor = null;
    policySearchText = "";
    policyEditingId = null;
    policyEditingRevision = null;
    policyEditSeq += 1;
    policyHistoryFor = null;
    policyHistoryLoading = false;
    policyHistorySeq += 1;
    policySaving = false;
    policyRollbackBusy = false;
    assignmentVersion = null;
    assignmentReady = false;
    assignmentCurrentProfile = null;
    assignmentLoadedFor = "";
    assignmentLoadSeq += 1;
    assignmentLoading = false;
    assignmentSaving = false;
    assignmentClearing = false;
    effectiveLoading = false;
    effectiveSeq += 1;
    clearAlertRefresh();
    alertRefreshEpoch += 1;
    alertsLoaded = false;
    alertsList = [];
    alertCursor = null;
    alertLoading = false;
    alertListSeq += 1;
    alertSummaryLoading = false;
    alertSummarySeq += 1;
    alertSummaryEpoch += 1;
    alertActionBusy = "";
    userSearchText = "";
    departmentSearchText = "";
    accessSearchText = "";
    if (departmentName) { departmentName.value = ""; }
    if (userUsername) { userUsername.value = ""; }
    if (userFullName) { userFullName.value = ""; }
    if (userPassword) { userPassword.value = ""; }
    if (userRole) { userRole.value = "employee"; }
    if (grantScope) { grantScope.value = "department"; }
    if (grantGlobalConfirm) { grantGlobalConfirm.checked = false; }
    if (userSearch) { userSearch.value = ""; }
    if (departmentSearch) { departmentSearch.value = ""; }
    if (accessSearch) { accessSearch.value = ""; }
    if (policySearch) { policySearch.value = ""; }
    if (policyName) { policyName.value = ""; }
    if (policySubmit) { policySubmit.disabled = false; }
    if (policyCancel) { policyCancel.disabled = false; }
    if (policyMore) { policyMore.hidden = true; policyMore.disabled = false; }
    if (assignmentScope) { assignmentScope.value = "workspace"; }
    if (assignmentRevision) { assignmentRevision.value = "1"; }
    if (assignmentSubmit) { assignmentSubmit.disabled = false; }
    if (assignmentClear) { assignmentClear.disabled = false; }
    if (effectivePreview) { effectivePreview.disabled = false; }
    if (departmentSubmit) { departmentSubmit.disabled = false; }
    if (userSubmit) { userSubmit.disabled = false; }
    if (grantSubmit) { grantSubmit.disabled = false; }
    if (userForm) { userForm.hidden = true; }
    if (departmentForm) { departmentForm.hidden = true; }
    if (policyForm) { policyForm.hidden = true; }
    if (policyDisabledNote) { policyDisabledNote.hidden = true; }
    if (newUserToggle) { newUserToggle.setAttribute("aria-expanded", "false"); }
    if (newDepartmentToggle) { newDepartmentToggle.setAttribute("aria-expanded", "false"); }
    clearNode(departmentList);
    clearNode(userList);
    clearNode(grantList);
    clearNode(accessList);
    clearNode(userDepartment);
    clearNode(grantDepartment);
    clearNode(grantUser);
    clearNode(assignmentDepartment);
    clearNode(assignmentUser);
    clearNode(assignmentProfile);
    clearNode(effectiveUser);
    clearNode(policyList);
    clearNode(policyHistory);
    clearNode(effectivePolicy);
    clearNode(alertList);
    clearNode(alertDetail);
    alertDetail.hidden = true;
    alertMore.hidden = true;
    alertMore.disabled = false;
    resetAlertFilterOptions();
    alertSummary.textContent = "Alert summary loading…";
    departmentMore.hidden = true;
    userMore.hidden = true;
    grantMore.hidden = true;
    accessMore.hidden = true;
    setStatus(departmentState, "");
    setStatus(userState, "");
    setStatus(grantState, "");
    setStatus(accessState, "");
    setStatus(adminStatus, "");
    setStatus(policyState, "");
    setStatus(policyHistoryState, "");
    setStatus(assignmentState, "");
    setStatus(effectiveState, "");
    setStatus(alertState, "");
    assignmentCurrent.textContent = "";
    effectivePolicy.textContent = "";
    syncGrantForm();
    syncAssignmentScope();
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
  alertMore.addEventListener("click", function () { loadAlerts(false); });
  alertRefresh.addEventListener("click", function () { loadAlerts(true); });
  alertStage.addEventListener("change", function () { loadAlerts(true); });
  alertDepartment.addEventListener("change", function () { loadAlerts(true); });
  alertUser.addEventListener("change", function () { loadAlerts(true); });
  alertUnread.addEventListener("change", function () { loadAlerts(true); });
  alertAck.addEventListener("change", function () { loadAlerts(true); });

  userSearch.addEventListener("input", function () {
    userSearchText = userSearch.value.trim();
    renderUsers(adminUsers, true);
  });
  departmentSearch.addEventListener("input", function () {
    departmentSearchText = departmentSearch.value.trim();
    renderDepartments(adminDepartments, true);
  });
  accessSearch.addEventListener("input", function () {
    accessSearchText = accessSearch.value.trim();
    renderAccess(adminAccess, true);
  });
  policySearch.addEventListener("input", function () {
    policySearchText = policySearch.value.trim();
    renderPolicyProfiles(policyProfiles, true);
  });
  policyMore.addEventListener("click", function () {
    queueAdminList(function () { return loadPolicyProfiles(false); });
  });
  policyRefresh.addEventListener("click", function () {
    if (!currentAdmin()) { return; }
    queueAdminList(function () { return loadPolicyProfiles(true); });
  });
  policyNew.addEventListener("click", function () {
    if (!currentAdmin()) { return; }
    openPolicyForm(null);
  });
  policyCancel.addEventListener("click", function () {
    closePolicyForm();
    setStatus(policyState, "");
  });
  policyForm.addEventListener("submit", savePolicyProfile);
  policyInputEnabled.addEventListener("change", syncPolicyFormNote);
  policyOutputEnabled.addEventListener("change", syncPolicyFormNote);
  policyInputEmail.addEventListener("change", syncPolicyFormNote);
  policyInputPhone.addEventListener("change", syncPolicyFormNote);
  policyInputMykad.addEventListener("change", syncPolicyFormNote);
  policyOutputEmail.addEventListener("change", syncPolicyFormNote);
  policyOutputPhone.addEventListener("change", syncPolicyFormNote);
  policyOutputMykad.addEventListener("change", syncPolicyFormNote);

  assignmentScope.addEventListener("change", function () {
    syncAssignmentScope();
    assignmentSelectionChanged();
  });
  assignmentDepartment.addEventListener("change", assignmentSelectionChanged);
  assignmentUser.addEventListener("change", assignmentSelectionChanged);
  assignmentProfile.addEventListener("change", assignmentProfileChanged);
  assignmentForm.addEventListener("submit", savePolicyAssignment);
  assignmentClear.addEventListener("click", clearPolicyAssignment);
  effectivePreview.addEventListener("click", loadEffectivePreview);
  effectiveUser.addEventListener("change", clearEffectivePreview);

  newUserToggle.addEventListener("click", function () {
    var open = userForm.hidden;
    userForm.hidden = !open;
    newUserToggle.setAttribute("aria-expanded", open ? "true" : "false");
    if (open) {
      if (!adminDepartmentsLoaded) {
        queueAdminList(function () { return loadDepartments(true); });
      }
      try { userUsername.focus(); } catch (error) { /* non-fatal */ }
    }
  });
  userCancel.addEventListener("click", function () {
    userForm.hidden = true;
    newUserToggle.setAttribute("aria-expanded", "false");
    userPassword.value = "";
  });
  newDepartmentToggle.addEventListener("click", function () {
    var open = departmentForm.hidden;
    departmentForm.hidden = !open;
    newDepartmentToggle.setAttribute("aria-expanded", open ? "true" : "false");
    if (open) {
      try { departmentName.focus(); } catch (error) { /* non-fatal */ }
    }
  });
  departmentCancel.addEventListener("click", function () {
    departmentForm.hidden = true;
    newDepartmentToggle.setAttribute("aria-expanded", "false");
    departmentName.value = "";
  });

  function setGuardStatus(label, detail, inactive) {
    guardSummary.textContent = label;
    guardDetail.textContent = detail;
    if (inactive) { guardStatus.setAttribute("data-kind", "inactive"); }
    else { guardStatus.removeAttribute("data-kind"); }
    guardStatus.open = false;
  }

  function loadGuardStatus() {
    return api("/health/ready", { independent: true }).then(function (result) {
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
    // Reuse the readiness read captured at boot; a later recovery check starts
    // a fresh one.  Both reads settle before the queued summaries are allowed.
    var guardPromise = startupGuardPromise;
    startupGuardPromise = null;
    if (!guardPromise) { guardPromise = loadGuardStatus(); }
    var baselineToken = beginBaseline();
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
        var uid = profile.user.id;
        watchBaseline(
          [loadConversations(true), guardPromise],
          function () {
            return seq === sessionCheckSeq && epoch === sessionEpoch &&
              signedIn && !!profile && profile.user.id === uid;
          },
          baselineToken
        );
        return;
      }
      cancelBaseline();
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
  contextNotice.textContent = GENERIC_CONTEXT_NOTICE;
  applyChatLimits(null);
  updateComposer();
  // Capture the readiness read once at startup; restoreSession adopts it so
  // queued policy and alert summaries cannot start before it settles.
  baselinePending = true;
  summariesQueued = false;
  startupGuardPromise = loadGuardStatus();
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
<button id="list-retry" class="list-retry" type="button" hidden>Retry conversations</button>
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
<div class="topbar-actions">
<button id="alerts-bell" class="alerts-bell" type="button" aria-label="Alerts" hidden>
<svg width="18" height="18" viewBox="0 0 20 20" fill="none" aria-hidden="true" focusable="false">
<path d="M10 2.6a4.1 4.1 0 0 0-4.1 4.1v2.2L4.5 11.6h11l-1.4-2.7V6.7A4.1 4.1 0 0 0 10 2.6ZM8.2 14.1a1.9 1.9 0 0 0 3.6 0" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/>
</svg>
<span id="alerts-badge" class="alerts-badge" hidden>0</span>
<span class="sr-only">Open block alerts</span>
</button>
<button id="logout-button" class="ghost" type="button">Sign out</button>
</div>
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
<div id="chat-block" class="chat-block" role="status" aria-live="polite" hidden></div>
<p id="chat-status" class="chat-status" role="status" aria-live="polite"></p>
<div class="composer-wrap">
<form id="composer-form" class="composer" novalidate>
<label class="sr-only" for="composer">Message</label>
<textarea id="composer" rows="2" disabled placeholder="Select or create a conversation to send a message."></textarea>
<div class="composer-row">
<label class="reply-choice" for="reply-length">Reply length
<select id="reply-length" disabled></select>
</label>
<span id="composer-hint" class="composer-hint">Select or create a conversation to send a message.</span>
<button id="send" class="primary" type="submit" disabled>Send</button>
</div>
<p id="context-notice" class="context-notice" role="status" aria-live="polite">Full saved history is kept. Older messages may be left out of a model request to fit the configured context.</p>
<p id="policy-summary" class="policy-summary" role="status" aria-live="polite">Workspace policy summary loading…</p>
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
<div class="admin-shell">
<h2>Account administration</h2>
<p class="review-notice">Administrator tools for this workspace. The server verifies the administrator role on every request. Review grants allow reading original confidential chat text, and every access is recorded in the access log.</p>
<div class="admin-subtabs" role="tablist" aria-label="Administration sections">
<button id="admin-tab-users" class="admin-subtab" type="button" role="tab" aria-controls="admin-users-panel" aria-selected="true">Users</button>
<button id="admin-tab-departments" class="admin-subtab" type="button" role="tab" aria-controls="admin-departments-panel" aria-selected="false">Departments</button>
<button id="admin-tab-policies" class="admin-subtab" type="button" role="tab" aria-controls="admin-policies-panel" aria-selected="false">Policies</button>
<button id="admin-tab-alerts" class="admin-subtab" type="button" role="tab" aria-controls="admin-alerts-panel" aria-selected="false">Alerts</button>
<button id="admin-tab-access" class="admin-subtab" type="button" role="tab" aria-controls="admin-access-panel" aria-selected="false">Access history</button>
</div>
<p id="admin-status" class="chat-status" role="status" aria-live="polite"></p>

<section id="admin-users-panel" class="admin-panel-section" role="tabpanel" aria-labelledby="admin-tab-users">
<div class="admin-section-head">
<h3 id="users-heading">User accounts</h3>
<button id="new-user-toggle" type="button">New user</button>
</div>
<p class="admin-note">Loaded accounts only. Use Load more to extend the list.</p>
<div class="admin-toolbar">
<label class="admin-search" for="user-search">Search users<input id="user-search" type="search" autocomplete="off" spellcheck="false"></label>
</div>
<p class="admin-search-note">Search applies only to user rows loaded so far; it is not a global account search.</p>
<form id="user-form" class="admin-form policy-form" novalidate hidden>
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
<div class="policy-actions">
<button id="user-submit" class="primary" type="submit">Create user</button>
<button id="user-cancel" class="ghost" type="button">Cancel</button>
</div>
</form>
<p id="user-state" class="admin-note" role="status" aria-live="polite"></p>
<div id="user-list" class="admin-table" aria-label="User accounts"></div>
<button id="user-more" class="admin-more" type="button" hidden>Load more users</button>
</section>

<section id="admin-departments-panel" class="admin-panel-section" role="tabpanel" aria-labelledby="admin-tab-departments" hidden>
<div class="admin-section-head">
<h3 id="department-heading">Departments</h3>
<button id="new-department-toggle" type="button">New department</button>
</div>
<p class="admin-note">Loaded departments only. Use Load more to extend the list.</p>
<div class="admin-toolbar">
<label class="admin-search" for="department-search">Search departments<input id="department-search" type="search" autocomplete="off" spellcheck="false"></label>
</div>
<p class="admin-search-note">Search applies only to department rows loaded so far; it is not a global directory search.</p>
<form id="department-form" class="admin-form policy-form" novalidate hidden>
<label for="department-name">Department name</label>
<input id="department-name" name="department-name" type="text" maxlength="80" autocomplete="off" required>
<div class="policy-actions">
<button id="department-submit" class="primary" type="submit">Create department</button>
<button id="department-cancel" class="ghost" type="button">Cancel</button>
</div>
</form>
<p id="department-state" class="admin-note" role="status" aria-live="polite"></p>
<div id="department-list" class="admin-table" aria-label="Departments"></div>
<button id="department-more" class="admin-more" type="button" hidden>Load more departments</button>
</section>

<section id="admin-policies-panel" class="admin-panel-section" role="tabpanel" aria-labelledby="admin-tab-policies" hidden>
<div class="admin-section-head">
<h3>Check profiles</h3>
<button id="policy-new" type="button">New profile</button>
<button id="policy-refresh" class="ghost" type="button">Refresh profiles</button>
</div>
<p class="policy-note">A profile records input/output classifier and masking settings. Creating a profile does not assign it to anyone; use the assignment section below.</p>
<div class="admin-toolbar">
<label class="admin-search" for="policy-search">Search profiles<input id="policy-search" type="search" autocomplete="off" spellcheck="false"></label>
</div>
<p class="admin-search-note">Search applies only to profile rows loaded so far; it is not a global profile search.</p>
<form id="policy-form" class="admin-form policy-form" novalidate hidden>
<label for="policy-name">Profile name</label>
<input id="policy-name" name="policy-name" type="text" maxlength="80" autocomplete="off" required>
<div class="policy-grid">
<fieldset>
<legend>Input checks</legend>
<div class="policy-checks">
<label for="policy-input-enabled"><input id="policy-input-enabled" type="checkbox" checked> Run input safety checks</label>
<label for="policy-input-email"><input id="policy-input-email" type="checkbox" checked> Mask EMAIL</label>
<label for="policy-input-phone"><input id="policy-input-phone" type="checkbox" checked> Mask MY_PHONE</label>
<label for="policy-input-mykad"><input id="policy-input-mykad" type="checkbox" checked> Mask MYKAD</label>
</div>
</fieldset>
<fieldset>
<legend>Output checks</legend>
<div class="policy-checks">
<label for="policy-output-enabled"><input id="policy-output-enabled" type="checkbox" checked> Run output safety checks</label>
<label for="policy-output-email"><input id="policy-output-email" type="checkbox" checked> Mask EMAIL</label>
<label for="policy-output-phone"><input id="policy-output-phone" type="checkbox" checked> Mask MY_PHONE</label>
<label for="policy-output-mykad"><input id="policy-output-mykad" type="checkbox" checked> Mask MYKAD</label>
</div>
</fieldset>
</div>
<p id="policy-disabled-note" class="admin-warning" hidden>If an input or output check is turned off, this profile does not ask the model guard to check that channel. No masking selected for a channel is an explicit relaxation and does not protect that content. Server limits and the denylist still apply, and the separate guard status shows whether the model guard runtime is active.</p>
<div class="policy-actions">
<button id="policy-submit" class="primary" type="submit">Save profile</button>
<button id="policy-cancel" class="ghost" type="button">Cancel</button>
</div>
</form>
<p id="policy-state" class="admin-note" role="status" aria-live="polite"></p>
<div id="policy-list" class="admin-table" aria-label="Policy profiles"></div>
<button id="policy-more" class="admin-more" type="button" hidden>Load more profiles</button>
<h3>Profile history</h3>
<p class="policy-note">History is immutable. Rollback appends a new revision instead of overwriting the old one.</p>
<div id="policy-history" class="policy-history" aria-label="Profile revision history"></div>
<p id="policy-history-state" class="admin-note" role="status" aria-live="polite"></p>

<h3>Policy assignment</h3>
<p class="policy-note">Assignments pin an exact profile revision. Saving reads the current assignment version first. If the profile later changes, this assignment keeps its pinned revision until you explicitly reapply a newer revision. Choose the revision explicitly; changing a profile never auto-applies to this scope.</p>
<form id="policy-assignment-form" class="admin-form policy-form" novalidate>
<div class="policy-grid">
<label for="assignment-scope">Scope<select id="assignment-scope" name="assignment-scope">
<option value="workspace">Workspace</option>
<option value="department">Department</option>
<option value="user">User</option>
</select></label>
<div id="assignment-department-field" hidden>
<label for="assignment-department">Department target<select id="assignment-department" name="assignment-department"></select></label>
</div>
<div id="assignment-user-field" hidden>
<label for="assignment-user">User target<select id="assignment-user" name="assignment-user"></select></label>
</div>
<label for="assignment-profile">Profile<select id="assignment-profile" name="assignment-profile"></select></label>
<label for="assignment-revision">Pinned profile revision<input id="assignment-revision" name="assignment-revision" type="number" min="1" step="1" value="1"></label>
</div>
<p id="assignment-current" class="policy-note">Checking the current assignment…</p>
<p class="policy-note">Clear override removes the assignment at this scope; users then inherit from the next less-specific scope or the default policy.</p>
<div class="policy-actions">
<button id="assignment-submit" class="primary" type="submit">Save assignment</button>
<button id="assignment-clear" class="ghost" type="button">Clear override</button>
</div>
</form>
<p id="assignment-state" class="admin-note" role="status" aria-live="polite"></p>

<h3>Effective policy preview</h3>
<div class="admin-toolbar">
<label for="effective-user">User<select id="effective-user" name="effective-user"></select></label>
<button id="effective-preview" type="button">Preview</button>
</div>
<p id="effective-state" class="admin-note" role="status" aria-live="polite"></p>
<div id="effective-policy" class="effective-summary" aria-label="Effective policy preview"></div>
</section>

<section id="admin-alerts-panel" class="admin-panel-section" role="tabpanel" aria-labelledby="admin-tab-alerts" hidden>
<div class="admin-section-head">
<h3 id="alerts-heading">Block alerts</h3>
<button id="alert-refresh" type="button">Refresh alerts</button>
</div>
<p class="admin-note">Saved metadata only. Viewing original text requires an existing review grant; the administrator role alone is not enough. This page never marks an alert read just because the bell was opened.</p>
<div class="admin-toolbar">
<label for="alert-stage">Stage<select id="alert-stage" name="alert-stage">
<option value="">All stages</option>
<option value="input">Input</option>
<option value="output">Output</option>
</select></label>
<label for="alert-department">Department<select id="alert-department" name="alert-department"><option value="">All departments</option></select></label>
<label for="alert-user">User<select id="alert-user" name="alert-user"><option value="">All users</option></select></label>
<label for="alert-unread">Read state<select id="alert-unread" name="alert-unread">
<option value="">All</option>
<option value="true">Unread only</option>
<option value="false">Read only</option>
</select></label>
<label for="alert-ack">Acknowledgement<select id="alert-ack" name="alert-ack">
<option value="">All</option>
<option value="true">Acknowledged</option>
<option value="false">Not acknowledged</option>
</select></label>
</div>
<p id="alert-summary" class="admin-note" role="status" aria-live="polite">Alert summary loading…</p>
<p id="alert-state" class="admin-note" role="status" aria-live="polite"></p>
<div id="alert-list" class="admin-table" aria-label="Block alerts"></div>
<button id="alert-more" class="admin-more" type="button" hidden>Load more alerts</button>
<div id="alert-detail" class="effective-summary" aria-label="Alert conversation detail" hidden></div>
</section>

<section id="admin-access-panel" class="admin-panel-section" role="tabpanel" aria-labelledby="admin-tab-access" hidden>
<div class="admin-section-head">
<h3 id="access-heading">Access history</h3>
<button id="access-refresh" class="ghost" type="button">Refresh access history</button>
</div>
<p class="admin-note">Metadata only: event actor, time, action, department and conversation. Message text and session tokens are never shown here.</p>
<div class="admin-toolbar">
<label class="admin-search" for="access-search">Search access events<input id="access-search" type="search" autocomplete="off" spellcheck="false"></label>
</div>
<p class="admin-search-note">Search applies only to access rows loaded so far; it is not a global audit search.</p>
<div id="access-list" class="admin-table" aria-label="Access log metadata"></div>
<button id="access-more" class="admin-more" type="button" hidden>Load more access events</button>
<p id="access-state" class="admin-note" role="status" aria-live="polite"></p>
<details id="grants-details" class="admin-details">
<summary>Review grants and grant management</summary>
<form id="grant-form" class="admin-form policy-form" novalidate>
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
<label for="grant-global-confirm" class="admin-inline"><input id="grant-global-confirm" type="checkbox"> I understand a global grant exposes original confidential chat text across every department.</label>
</div>
<p class="admin-note">Use Load more to see additional users and departments.</p>
<button id="grant-submit" class="primary" type="submit">Grant review access</button>
</form>
<p id="grant-state" class="admin-note" role="status" aria-live="polite"></p>
<div id="grant-list" class="admin-list" aria-label="Review access grants"></div>
<button id="grant-more" class="admin-more" type="button" hidden>Load more grants</button>
</details>
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
