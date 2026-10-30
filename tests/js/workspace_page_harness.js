"use strict";
/*
 * Behavior regression for the employee workspace page's inline JavaScript.
 *
 * Node is used only as a deterministic local JavaScript runtime. The harness
 * supplies a small DOM, fake timers, deferred fetch replies and a real
 * AbortController. It proves request shape, text-only rendering, session
 * isolation, failure refresh, reviewer routing and pagination behavior. It is
 * not a browser engine or CSP execution claim.
 *
 * Usage: node tests/js/workspace_page_harness.js <extracted-workspace-js>
 */

const fs = require("fs");
const vm = require("vm");

const scriptPath = process.argv[2];
if (!scriptPath) {
  console.error("usage: node workspace_page_harness.js <workspace-js-file>");
  process.exit(2);
}
const scriptText = fs.readFileSync(scriptPath, "utf8");

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function tick() {
  return new Promise((resolve) => setImmediate(resolve));
}

async function settle(rounds = 12) {
  for (let i = 0; i < rounds; i += 1) {
    await tick();
  }
}

function collect(root, out) {
  out = out || [];
  for (const child of root.children || []) {
    out.push(child);
    collect(child, out);
  }
  return out;
}

function findButton(root, label) {
  return collect(root).find(
    (element) => element.tagName === "BUTTON" && element.textContent.trim() === label
  );
}

function findByClass(root, className) {
  return collect(root).find((element) => String(element.className).split(" ").indexOf(className) >= 0);
}

function findDataRow(root, attribute, value) {
  return collect(root).find((element) => element.getAttribute(attribute) === value);
}

function makeElement(id) {
  const listeners = Object.create(null);
  const attributes = Object.create(null);
  let ownText = "";
  const element = {
    id,
    tagName: String(id || "div").toUpperCase(),
    value: "",
    hidden: false,
    disabled: false,
    className: "",
    type: "",
    children: [],
    focused: 0,
    appendChild(child) {
      element.children.push(child);
      return child;
    },
    removeChild(child) {
      const index = element.children.indexOf(child);
      if (index >= 0) {
        element.children.splice(index, 1);
      }
      return child;
    },
    setAttribute(name, value) {
      attributes[name] = String(value);
    },
    getAttribute(name) {
      return Object.prototype.hasOwnProperty.call(attributes, name)
        ? attributes[name]
        : null;
    },
    removeAttribute(name) {
      delete attributes[name];
    },
    addEventListener(type, handler) {
      if (!listeners[type]) {
        listeners[type] = [];
      }
      listeners[type].push(handler);
    },
    dispatch(type, extra) {
      const event = Object.assign(
        {
          type,
          defaultPrevented: false,
          preventDefault() {
            event.defaultPrevented = true;
          },
        },
        extra || {}
      );
      for (const handler of listeners[type] || []) {
        handler(event);
      }
      return event;
    },
    focus() {
      element.focused += 1;
    },
  };
  Object.defineProperty(element, "textContent", {
    get() {
      let text = ownText;
      for (const child of element.children) {
        text += child.textContent;
      }
      return text;
    },
    set(value) {
      ownText = value === null || value === undefined ? "" : String(value);
      element.children.length = 0;
    },
  });
  Object.defineProperty(element, "firstChild", {
    get() {
      return element.children.length ? element.children[0] : null;
    },
  });
  Object.defineProperty(element, "innerHTML", {
    get() {
      return "";
    },
    set() {
      throw new Error("workspace page must never assign innerHTML");
    },
  });
  return element;
}

function createApp(options) {
  const maxInflight = options && options.maxInflight ? options.maxInflight : 0;
  const elements = Object.create(null);
  const created = [];
  function elementFor(id) {
    if (!elements[id]) {
      elements[id] = makeElement(id);
    }
    return elements[id];
  }
  const documentListeners = Object.create(null);
  const document = {
    body: makeElement("body"),
    hidden: false,
    addEventListener(type, handler) {
      if (!documentListeners[type]) {
        documentListeners[type] = [];
      }
      documentListeners[type].push(handler);
    },
    dispatch(type, extra) {
      for (const handler of documentListeners[type] || []) {
        handler(Object.assign({ type }, extra || {}));
      }
    },
    getElementById(id) {
      return elementFor(id);
    },
    createElement(tag) {
      const element = makeElement(tag);
      created.push(element);
      return element;
    },
    createTextNode(text) {
      // The page appends literal separators between spans; model a DOM Text
      // node so parent textContent concatenation behaves like the browser.
      return {
        nodeType: 3,
        nodeName: "#text",
        textContent: String(text),
        children: [],
      };
    },
  };
  const windowListeners = Object.create(null);
  const location = {
    pathname: (options && options.pathname) || "/workspace",
    search: "",
    hash: "",
  };
  const historyEntries = [location.pathname];
  let historyIndex = 0;
  const historyApi = {
    get state() { return historyEntries[historyIndex]; },
    pushState(_state, _title, url) {
      if (typeof url !== "string" || !url) { return; }
      location.pathname = url;
      historyEntries.splice(historyIndex + 1);
      historyEntries.push(url);
      historyIndex = historyEntries.length - 1;
    },
    replaceState(_state, _title, url) {
      if (typeof url !== "string" || !url) { return; }
      location.pathname = url;
      historyEntries[historyIndex] = url;
    },
  };
  const window = {
    location,
    history: historyApi,
    addEventListener(type, handler) {
      if (!windowListeners[type]) {
        windowListeners[type] = [];
      }
      windowListeners[type].push(handler);
    },
    dispatch(type, extra) {
      for (const handler of windowListeners[type] || []) {
        handler(Object.assign({ type }, extra || {}));
      }
    },
  };

  const calls = [];
  function fetch(url, options) {
    const call = {
      url: String(url),
      options: options || {},
      aborted: false,
      settled: false,
    };
    const promise = new Promise((resolve, reject) => {
      call.resolve = (value) => {
        call.settled = true;
        resolve(value);
      };
      call.reject = (error) => {
        call.settled = true;
        reject(error);
      };
    });
    const signal = call.options.signal;
    if (signal) {
      signal.addEventListener("abort", () => {
        call.aborted = true;
        const error = new Error("aborted");
        error.name = "AbortError";
        call.reject(error);
      });
    }
    call.respond = (payload, status, extra) => {
      const statusCode = typeof status === "number" ? status : 200;
      call.status = statusCode;
      const extras = extra || {};
      call.resolve({
        ok: statusCode >= 200 && statusCode < 300,
        status: statusCode,
        headers: { get() { return null; } },
        json() {
          if (extras.invalidJson) {
            return Promise.reject(new SyntaxError("invalid json"));
          }
          return Promise.resolve(payload);
        },
      });
    };
    calls.push(call);
    if (maxInflight > 0 && calls.filter((item) => !item.settled).length > maxInflight) {
      // Models the control-plane admission: requests beyond the two available
      // slots are rejected immediately rather than queued by the server.
      call.respond({ error: { code: "UNAVAILABLE", message: "Busy." } }, 503);
    }
    return promise;
  }

  const timers = [];
  let timerId = 0;
  function fakeSetTimeout(fn, delay) {
    timerId += 1;
    timers.push({ id: timerId, fn, delay, cleared: false });
    return timerId;
  }
  function fakeClearTimeout(id) {
    for (const timer of timers) {
      if (timer.id === id) {
        timer.cleared = true;
      }
    }
  }

  const channelInstances = [];
  class FakeBroadcastChannel {
    constructor(name) {
      this.name = name;
      this.handlers = [];
      channelInstances.push(this);
    }
    addEventListener(type, handler) {
      if (type === "message") { this.handlers.push(handler); }
    }
    postMessage() {
      // A real BroadcastChannel never delivers a message back to its sender.
    }
  }

  const context = {
    document,
    window,
    fetch,
    AbortController,
    BroadcastChannel: FakeBroadcastChannel,
    Promise,
    Date,
    JSON,
    Math,
    encodeURIComponent,
    isNaN,
    console: { log() {}, error() {} },
    setTimeout: fakeSetTimeout,
    clearTimeout: fakeClearTimeout,
  };
  vm.createContext(context);
  // The page markup nests these summary/detail nodes inside the guard
  // <details> element; the synthetic DOM must mirror that containment.
  elementFor("guard-status").appendChild(elementFor("guard-summary"));
  elementFor("guard-status").appendChild(elementFor("guard-detail"));
  // The synthetic DOM is not an HTML parser, so mirror the static markup for
  // the retry control that has no dynamically assigned label.
  elementFor("list-retry").textContent = "Retry conversations";
  elementFor("list-retry").hidden = true;
  elementFor("load-more").hidden = true;
  vm.runInContext(scriptText, context, { filename: "workspace_page.js" });

  function callsMatching(part) {
    return calls.filter((call) => call.url.indexOf(part) >= 0);
  }
  function pendingCallsMatching(part) {
    return callsMatching(part).filter((call) => !call.settled);
  }
  function lastMatching(part) {
    const found = callsMatching(part);
    return found[found.length - 1];
  }
  function fireAllTimers() {
    for (const timer of timers.slice()) {
      if (!timer.cleared) {
        timer.cleared = true;
        timer.fn();
      }
    }
  }

  return {
    elements,
    elementFor,
    created,
    calls,
    window,
    location,
    history: historyApi,
    historyEntries,
    get historyIndex() { return historyIndex; },
    goBack() {
      if (historyIndex === 0) { return false; }
      historyIndex -= 1;
      location.pathname = historyEntries[historyIndex];
      window.dispatch("popstate", { state: null });
      return true;
    },
    goForward() {
      if (historyIndex >= historyEntries.length - 1) { return false; }
      historyIndex += 1;
      location.pathname = historyEntries[historyIndex];
      window.dispatch("popstate", { state: null });
      return true;
    },
    timers,
    callsMatching,
    pendingCallsMatching,
    lastMatching,
    broadcast(data) {
      for (const channel of channelInstances.slice()) {
        for (const handler of channel.handlers.slice()) {
          handler({ data });
        }
      }
    },
    fireAllTimers,
  };
}

const ALICE_USER = {
  id: "user-alice",
  username: "alice",
  full_name: "Alice Tan",
  department_id: "dept-accounting",
  role: "employee",
  disabled: false,
  created_at: 1700000000,
};
const PROFILE = {
  user: ALICE_USER,
  department: { id: "dept-accounting", name: "Accounting" },
  review_scope: null,
  review_department_ids: [],
  review_grants: [],
  chat_limits: {
    context_messages: 32,
    context_budget: 8192,
    default_reply_tokens: 1024,
    max_reply_tokens: 4096,
    max_prompt_chars: 8192,
    policy_token_budget: 512,
  },
};
const DEFAULT_POLICY = {
  is_default: true,
  input_check_enabled: true,
  output_check_enabled: true,
  input_masks: [],
  output_masks: [],
};
const EMPTY_ALERT_SUMMARY = { total: 0, unread: 0, acknowledged: 0 };

const BOB_PROFILE = {
  user: {
    id: "user-bob",
    username: "bob",
    full_name: "Bob Lee",
    department_id: "dept-accounting",
    role: "employee",
    disabled: false,
    created_at: 1700000000,
  },
  department: { id: "dept-accounting", name: "Accounting" },
  review_scope: null,
  review_department_ids: [],
  review_grants: [],
  chat_limits: {
    context_messages: 32,
    context_budget: 8192,
    default_reply_tokens: 1024,
    max_reply_tokens: 4096,
    max_prompt_chars: 8192,
    policy_token_budget: 512,
  },
};

function loginPayload(user) {
  return {
    expires: 1800000000,
    user: user || ALICE_USER,
  };
}

async function start(app, options) {
  const settings = options || {};
  await settle();
  const health = app.lastMatching("/health/ready");
  if (health) {
    health.respond(
      settings.health || { status: "ready", mode: "test", guards_active: false },
      settings.healthStatus || 200
    );
  }
  await settle();
  const me = app.lastMatching("/workspace/api/me");
  if (me) {
    assert(
      me.options.credentials === "same-origin",
      "the initial /me restore must use same-origin credentials"
    );
    assert(
      me.options.headers.Authorization === undefined,
      "the page must never send a bearer token"
    );
    assert(
      me.options.headers["X-Workspace-User"] === undefined,
      "the initial /me bootstrap has no expected user yet"
    );
    me.respond(
      settings.profile || {
        error: { code: "UNAUTHORIZED", message: "Authentication required." },
      },
      settings.profile ? 200 : 401
    );
  }
  await settle();
}

async function signIn(app, profile, username) {
  const login = app.elementFor("login-form");
  const name = username || "alice";
  app.elementFor("username").value = name;
  app.elementFor("password").value = "secret-password";
  login.dispatch("submit");
  const request = app.lastMatching("/workspace/api/login");
  assert(request, "login request was not issued");
  assert(
    app.elementFor("password").value === "",
    "password field must be cleared when the request starts"
  );
  const body = JSON.parse(request.options.body);
  assert(body.username === name, "username payload mismatch");
  assert(body.password === "secret-password", "password payload mismatch");
  assert(body.cookie === true, "login must opt into the HttpOnly cookie");
  assert(request.options.credentials === "same-origin", "login credentials shape is wrong");
  assert(
    request.options.headers.Authorization === undefined,
    "login must not send a stale bearer token"
  );
  request.respond(loginPayload(profile ? profile.user : ALICE_USER), 200);
  await settle();
  const me = app.lastMatching("/workspace/api/me");
  assert(me, "GET /me was not issued after login");
  assert(
    me.options.credentials === "same-origin",
    "session restore must use same-origin credentials"
  );
  assert(
    me.options.headers.Authorization === undefined,
    "session restore must not use a bearer token"
  );
  assert(
    me.options.headers["X-Workspace-User"] === undefined,
    "login bootstrap /me must not name an expected user"
  );
  me.respond(profile || PROFILE, 200);
  await settle();
  // The readiness refresh is now sequenced after the critical profile check.
  // Settle it so it cannot hold an admission slot for the rest of a scenario.
  const postLoginHealth = app.lastMatching("/health/ready");
  if (postLoginHealth && !postLoginHealth.settled) {
    postLoginHealth.respond(
      { status: "ready", mode: "test", guards_active: false },
      200
    );
    await settle();
  }
  assert(app.elementFor("workspace-view").hidden === false,
    "a confirmed profile must reveal the workspace");
}

async function settleSummarySurfaces(app, summary) {
  // The page reads its own effective policy and, for an administrator, the
  // alert count only after the initial history and readiness reads settle.
  // Both consume bounded admission slots, so settle them before a scenario
  // starts exercising admin list admission.
  const policy = app.pendingCallsMatching("/workspace/api/policy").filter(
    (call) => call.url === "/workspace/api/policy"
  ).pop();
  if (policy) {
    policy.respond(DEFAULT_POLICY, 200);
    await settle();
  }
  const alertSummary = app.pendingCallsMatching(
    "/workspace/api/admin/alerts/summary"
  ).pop();
  if (alertSummary) {
    alertSummary.respond(summary || EMPTY_ALERT_SUMMARY, 200);
    await settle();
  }
}

async function scenarioSignInAndChat() {
  assert(!/localStorage|sessionStorage|document\.cookie/.test(scriptText),
    "page script must not use browser storage or cookies");
  assert(!/Authorization|Bearer\s/.test(scriptText),
    "page script must never build a bearer credential");
  assert(!/innerHTML\s*=/.test(scriptText), "page script must not assign innerHTML");
  assert(!/console\.(log|error|warn)/.test(scriptText), "page must not log");

  const app = createApp();
  await start(app);
  assert(
    app.elementFor("guard-status").textContent.indexOf("inactive") >= 0,
    "test mode must clearly report inactive guard models"
  );

  await signIn(app);
  const list = app.lastMatching("/workspace/api/conversations?limit=25");
  assert(list, "own conversation list request missing");
  assert(list.options.credentials === "same-origin", "conversation list credentials changed");
  assert(list.options.headers.Authorization === undefined, "list must not use a bearer token");
  assert(list.options.body === undefined,
    "GET requests must not gain a synthetic JSON body");
  assert(list.options.headers["Content-Type"] === undefined,
    "GET requests must not gain a mutation Content-Type");
  assert(
    list.options.headers["X-Workspace-User"] === "user-alice",
    "authenticated requests must name the current profile"
  );
  list.respond(
    {
      items: [
        {
          id: "conv-alpha-1234",
          title: "GENERATED PROMPT TITLE MUST NOT SHOW",
          created_at: 1700000100,
          updated_at: 1700000200,
          owner_full_name: "Alice Tan",
          department_name: "Accounting",
        },
        {
          id: "conv-beta-5678",
          title: "Second generated title",
          created_at: 1700000050,
          updated_at: 1700000060,
        },
      ],
      next: "cursor-two",
    },
    200
  );
  await settle();
  assert(app.elementFor("identity-name").textContent === "Alice Tan", "identity missing");
  assert(app.elementFor("identity-meta").textContent.indexOf("Accounting") >= 0, "department missing");
  const renderedText = app.elementFor("conversation-list").children
    .map((child) => child.textContent)
    .join(" ");
  assert(
    renderedText.indexOf("GENERATED PROMPT TITLE") < 0,
    "generated conversation title must never be displayed"
  );
  assert(renderedText.indexOf("conv-alp") >= 0, "short conversation id missing");

  app.elementFor("load-more").dispatch("click");
  const next = app.lastMatching("/workspace/api/conversations?limit=25&after=cursor-two");
  assert(next, "pagination cursor was not used");
  next.respond({ items: [], next: null }, 200);
  await settle();

  const first = app.elementFor("conversation-list").children[0];
  first.dispatch("click");
  const firstDetail = app.lastMatching("/workspace/api/conversations/conv-alpha-1234");
  assert(firstDetail, "conversation detail request missing");
  firstDetail.respond(
    {
      id: "conv-alpha-1234",
      owner_id: "user-alice",
      title: "ignored",
      created_at: 1700000100,
      messages: [
        {
          id: "m1",
          role: "user",
          outcome: "allowed",
          text: "Original prompt",
          created_at: 1700000101,
        },
        {
          id: "m2",
          role: "assistant",
          outcome: "allowed",
          text: "Delivered answer",
          created_at: 1700000102,
        },
      ],
    },
    200
  );
  await settle();
  assert(!app.elementFor("composer").disabled, "composer should be enabled for a conversation");

  const second = app.elementFor("conversation-list").children[1];
  second.dispatch("click");
  const staleDetail = app.lastMatching("/workspace/api/conversations/conv-beta-5678");
  first.dispatch("click");
  const currentDetail = app.lastMatching("/workspace/api/conversations/conv-alpha-1234");
  currentDetail.respond(
    {
      id: "conv-alpha-1234",
      created_at: 1700000100,
      messages: [
        { id: "m1", role: "user", outcome: "allowed", text: "Current conversation A", created_at: 1700000101 },
      ],
    },
    200
  );
  await settle();
  staleDetail.respond(
    {
      id: "conv-beta-5678",
      created_at: 1700000050,
      messages: [
        { id: "m9", role: "assistant", outcome: "allowed", text: "STALE CONVERSATION B", created_at: 1700000060 },
      ],
    },
    200
  );
  await settle();
  const visibleMessages = app.elementFor("messages").children
    .map((child) => child.textContent)
    .join(" ");
  assert(visibleMessages.indexOf("Current conversation A") >= 0, "selected conversation did not render");
  assert(visibleMessages.indexOf("STALE CONVERSATION B") < 0, "stale reply rendered after switching");
  assert(visibleMessages.indexOf("Failed") < 0, "an allowed message must not be labelled Failed");

  const hostile = "Original <img src=x onerror=alert(1)> & </script> text";
  const composer = app.elementFor("composer");
  const reply = app.elementFor("reply-length");
  assert(reply.disabled === false, "reply length must be enabled with server limits");
  assert(
    reply.children.map((option) => option.value).join(",") === "256,1024,4096",
    "reply length choices must stay within the configured server maximum"
  );
  assert(reply.value === "1024", "the configured server default must be selected");
  assert(
    composer.getAttribute("maxlength") === "8192",
    "the textarea must use the server prompt limit"
  );
  reply.value = "4096";
  composer.value = hostile;
  app.elementFor("composer-form").dispatch("submit");
  const send = app.lastMatching("/workspace/api/conversations/conv-alpha-1234/messages");
  assert(send, "message request missing");
  const sendBody = JSON.parse(send.options.body);
  assert(sendBody.text === hostile,
    "message payload must contain exactly the original prompt text");
  assert(sendBody.max_tokens === 4096,
    "every message must carry the selected reply length");
  app.elementFor("composer-form").dispatch("submit");
  assert(
    app.callsMatching("/workspace/api/conversations/conv-alpha-1234/messages").length === 1,
    "duplicate submissions must be prevented"
  );
  send.respond(
    { error: { code: "FORBIDDEN", message: "Request did not pass safety checks.", request_id: "req-1" } },
    403
  );
  await settle();
  const reload = app.lastMatching("/workspace/api/conversations/conv-alpha-1234");
  assert(reload, "conversation must reload after a blocked result");
  reload.respond(
    {
      id: "conv-alpha-1234",
      created_at: 1700000100,
      messages: [
        {
          id: "m1",
          role: "user",
          outcome: "blocked",
          error_code: "POLICY_BLOCKED",
          text: hostile,
          created_at: 1700000101,
        },
      ],
    },
    200
  );
  await settle();
  const blockedText = app.elementFor("messages").children
    .map((child) => child.textContent)
    .join(" ");
  assert(blockedText.indexOf("Blocked") >= 0, "blocked label missing");
  assert(blockedText.indexOf(hostile) >= 0, "hostile prompt must render as text");
  assert(app.elementFor("composer").value === "", "submitted prompt should clear after a known blocked result");
  assert(
    app.elementFor("chat-status").textContent.indexOf("blocked") >= 0,
    "blocked outcome should be reported"
  );
  // A saved (including blocked) turn must refresh list recency from the
  // existing list endpoint without changing the current conversation or text.
  const recency = app.pendingCallsMatching("/workspace/api/conversations?limit=25").pop();
  assert(recency, "a saved turn must refresh the conversation list recency");
  assert(recency.options.headers["X-Workspace-User"] === "user-alice",
    "recency refresh must keep naming the current profile");
  recency.respond(
    {
      items: [
        { id: "conv-beta-5678", created_at: 1700000050, updated_at: 1700000300 },
        { id: "conv-alpha-1234", created_at: 1700000100, updated_at: 1700000200 },
      ],
      next: null,
    },
    200
  );
  await settle();
  const recencyOrder = app.elementFor("conversation-list").children.map(
    (child) => child.getAttribute("data-conversation")
  );
  assert(recencyOrder[0] === "conv-beta-5678" && recencyOrder[1] === "conv-alpha-1234",
    "the refreshed list must put the most recent conversation first without duplicates");
  assert(app.elementFor("chat-title").textContent === "Conversation",
    "recency refresh must not replace the current conversation");
  assert(
    app.elementFor("messages").children.map((child) => child.textContent).join(" ").indexOf(hostile) >= 0,
    "recency refresh must not drop the current transcript"
  );
  assert(app.elementFor("composer").value === "",
    "recency refresh must not restore a submitted prompt into the composer");

  app.elementFor("delete-conversation").dispatch("click");
  assert(
    app.callsMatching("/workspace/api/conversations/conv-alpha-1234").filter(
      (call) => call.options.method === "DELETE"
    ).length === 0,
    "delete must require explicit confirmation"
  );
  app.elementFor("delete-yes").dispatch("click");
  const deletion = app.callsMatching("/workspace/api/conversations/conv-alpha-1234").filter(
    (call) => call.options.method === "DELETE"
  )[0];
  assert(deletion, "confirmed delete did not issue DELETE");
  assert(deletion.options.body === "{}",
    "bodyless DELETE must send an empty JSON object");
  assert(deletion.options.headers["Content-Type"] === "application/json",
    "DELETE must declare a JSON Content-Type for the cookie mutation guard");
  assert(deletion.options.credentials === "same-origin", "delete credentials changed");
  assert(deletion.options.headers["X-Workspace-User"] === "user-alice",
    "delete must name the current profile");
  assert(deletion.options.headers.Authorization === undefined,
    "delete must not use bearer auth");
  deletion.respond({ status: "deleted" }, 200);
  await settle();
  const afterDelete = app.lastMatching("/workspace/api/conversations?limit=25");
  afterDelete.respond(
    {
      items: [
        { id: "conv-alpha-1234", title: "ignored", created_at: 1700000100, updated_at: 1700000200 },
        { id: "conv-beta-5678", title: "ignored", created_at: 1700000050, updated_at: 1700000060 },
      ],
      next: null,
    },
    200
  );
  await settle();

  const pendingDetail = app.lastMatching("/workspace/api/conversations/conv-beta-5678");
  app.elementFor("conversation-list").children[1].dispatch("click");
  const lateDetail = app.lastMatching("/workspace/api/conversations/conv-beta-5678");
  assert(lateDetail, "conversation opened before logout is missing");
  app.elementFor("logout-button").dispatch("click");
  const logoutCall = app.lastMatching("/workspace/api/logout");
  assert(logoutCall, "logout did not call the server first");
  assert(logoutCall.options.method === "POST", "logout must POST");
  assert(logoutCall.options.body === "{}", "bodyless logout must send a JSON body");
  assert(logoutCall.options.credentials === "same-origin", "logout credentials changed");
  assert(logoutCall.options.headers.Authorization === undefined, "logout must not use bearer auth");
  assert(logoutCall.options.headers["X-Workspace-User"] === "user-alice",
    "logout must name the identity the server has to revoke");
  assert(app.elementFor("auth-view").hidden === true,
    "local state must not claim sign-out before the server confirms");
  logoutCall.respond({ status: "ok" }, 200);
  await settle();
  assert(app.elementFor("auth-view").hidden === false, "logout must show sign-in");
  assert(app.elementFor("workspace-view").hidden === true, "logout must hide workspace");
  lateDetail.respond(
    {
      id: "conv-beta-5678",
      created_at: 1700000050,
      messages: [{ id: "late", role: "assistant", outcome: "allowed", text: "LATE AFTER LOGOUT", created_at: 1700000060 }],
    },
    200
  );
  await settle();
  assert(lateDetail.aborted || lateDetail.settled, "pending detail was handled at logout");
  assert(
    app.elementFor("messages").children.map((child) => child.textContent).join("").indexOf("LATE AFTER LOGOUT") < 0,
    "late reply must not render after logout"
  );
  assert(pendingDetail !== lateDetail, "harness sanity: a new pending request was created");
  assert(app.callsMatching("/workspace/api/admin").length === 0, "non-admin must never fetch admin endpoints");
  assert(app.elementFor("tab-admin").hidden === true, "non-admin must not see the admin tab");
  assert(
    !findButton(app.elementFor("user-list"), "Grant admin") &&
      !findButton(app.elementFor("user-list"), "Revoke admin"),
    "non-admin must not be offered administrator role actions"
  );
}

async function scenarioReviewer() {
  const app = createApp();
  await start(app);
  await signIn(app, {
    user: { ...ALICE_USER, id: "user-rev", username: "reviewer", full_name: "Rita Reviewer", role: "employee" },
    department: { id: "dept-accounting", name: "Accounting" },
    review_scope: "department",
    review_department_ids: ["dept-accounting"],
    review_grants: [{ id: "grant-1", scope: "department", department_id: "dept-accounting", department_name: "Accounting" }],
  });
  app.lastMatching("/workspace/api/conversations?limit=25").respond(
    {
      items: [
        { id: "conv-own-reviewer", created_at: 1700000001, updated_at: 1700000002 },
      ],
      next: null,
    },
    200
  );
  await settle();
  assert(app.elementFor("tab-review").hidden === false, "review tab must appear only with a review scope");
  app.elementFor("tab-review").dispatch("click");
  const reviewList = app.lastMatching("/workspace/api/review/conversations?limit=25");
  assert(reviewList, "review list must use the review endpoint");
  reviewList.respond(
    {
      items: [
        {
          id: "conv-review-1",
          owner_full_name: "Alice Tan",
          department_name: "Accounting",
          created_at: 1700000100,
          updated_at: 1700000200,
        },
      ],
      next: null,
    },
    200
  );
  await settle();
  const reviewText = app.elementFor("review-list").textContent;
  assert(reviewText.indexOf("Alice Tan") >= 0, "reviewer owner reference missing");
  assert(reviewText.indexOf("Accounting") >= 0, "reviewer department reference missing");
  app.elementFor("review-list").children[0].dispatch("click");
  const detail = app.lastMatching("/workspace/api/review/conversations/conv-review-1");
  assert(detail, "review detail must use the review endpoint");
  assert(
    app.callsMatching("/workspace/api/conversations/conv-review-1").filter(
      (call) => call.url.indexOf("/review/") < 0
    ).length === 0,
    "reviewer must not use the own-conversation route"
  );
  detail.respond(
    {
      id: "conv-review-1",
      owner_full_name: "Alice Tan",
      department_name: "Accounting",
      created_at: 1700000100,
      messages: [{ id: "r1", role: "user", outcome: "blocked", text: "Reviewed prompt", created_at: 1700000101 }],
    },
    200
  );
  await settle();
  assert(
    app.elementFor("review-meta").textContent.indexOf("Owner: Alice Tan") >= 0,
    "review owner reference missing from detail"
  );
  assert(app.elementFor("composer").disabled === true, "reviewer must not have an enabled composer");
  assert(app.elementFor("review-messages").children.length === 1, "review messages missing");
  assert(app.elementFor("review-panel").hidden === false && app.elementFor("chat-panel").hidden === true,
    "selecting a review conversation must stay in Review");

  // Selecting the reviewer's own saved conversation is an explicit chat
  // navigation and must leave Review; the mobile sidebar closes as well.
  app.elementFor("conversation-list").children[0].dispatch("click");
  const ownDetail = app.lastMatching("/workspace/api/conversations/conv-own-reviewer");
  assert(ownDetail, "own conversation detail request missing from Review");
  assert(app.elementFor("chat-panel").hidden === false && app.elementFor("review-panel").hidden === true,
    "opening an own conversation from Review must show Chat");
  assert(app.elementFor("app").getAttribute("data-nav") === "closed",
    "opening an own conversation must close the mobile sidebar");
  ownDetail.respond(
    {
      id: "conv-own-reviewer",
      created_at: 1700000001,
      messages: [{ id: "own1", role: "assistant", outcome: "allowed", text: "Own answer", created_at: 1700000003 }],
    },
    200
  );
  await settle();
  assert(!app.elementFor("composer").disabled, "own conversation must enable the composer");

  // New chat from Review must also switch to Chat immediately, even before
  // the server answers, and must close the mobile sidebar.
  app.elementFor("tab-review").dispatch("click");
  assert(app.elementFor("review-panel").hidden === false, "review tab must reopen Review");
  app.elementFor("sidebar-toggle").dispatch("click");
  assert(app.elementFor("app").getAttribute("data-nav") === "open", "sidebar setup failed");
  app.elementFor("new-chat").dispatch("click");
  assert(app.elementFor("chat-panel").hidden === false && app.elementFor("review-panel").hidden === true,
    "New chat from Review must show Chat before the create answer");
  assert(app.elementFor("app").getAttribute("data-nav") === "closed",
    "New chat must close the mobile sidebar");
  const createFromReview = app.callsMatching("/workspace/api/conversations").filter(
    (call) => call.options.method === "POST"
  ).pop();
  assert(createFromReview, "New chat from Review did not POST");
  createFromReview.respond({ id: "conv-new-reviewer", created_at: 1700000009 }, 201);
  await settle();
  app.lastMatching("/workspace/api/conversations?limit=25").respond(
    {
      items: [
        { id: "conv-new-reviewer", created_at: 1700000009, updated_at: 1700000009 },
        { id: "conv-own-reviewer", created_at: 1700000001, updated_at: 1700000002 },
      ],
      next: null,
    },
    200
  );
  await settle();
  const newDetail = app.lastMatching("/workspace/api/conversations/conv-new-reviewer");
  assert(newDetail, "New chat from Review must open the created conversation");
  newDetail.respond(
    { id: "conv-new-reviewer", created_at: 1700000009, messages: [] },
    200
  );
  await settle();
  assert(app.elementFor("chat-panel").hidden === false, "New chat from Review must remain in Chat");
  assert(app.elementFor("composer").focused >= 1, "opening the created conversation must focus its composer");
}

async function scenarioReviewRevoked() {
  const app = createApp();
  await start(app);
  await signIn(app, {
    user: { ...ALICE_USER, id: "user-rev2", username: "reviewer2", full_name: "Rita Reviewer" },
    department: { id: "dept-accounting", name: "Accounting" },
    review_scope: "department",
    review_department_ids: ["dept-accounting"],
    review_grants: [],
  });
  app.lastMatching("/workspace/api/conversations?limit=25").respond({ items: [], next: null }, 200);
  await settle();
  app.elementFor("tab-review").dispatch("click");
  const listed = app.lastMatching("/workspace/api/review/conversations?limit=25");
  listed.respond(
    {
      items: [
        {
          id: "conv-revoked",
          owner_full_name: "Alice Tan",
          department_name: "Accounting",
          created_at: 1700000100,
          updated_at: 1700000200,
        },
      ],
      next: null,
    },
    200
  );
  await settle();
  assert(app.elementFor("review-list").children.length === 1, "review list must load before revocation");
  app.elementFor("review-list").children[0].dispatch("click");
  const denied = app.lastMatching("/workspace/api/review/conversations/conv-revoked");
  denied.respond({ error: { code: "FORBIDDEN", message: "Permission denied." } }, 403);
  await settle();
  const refresh = app.lastMatching("/workspace/api/me");
  assert(refresh, "review denial must re-fetch /me");
  refresh.respond(
    {
      user: { ...ALICE_USER, id: "user-rev2", username: "reviewer2", full_name: "Rita Reviewer" },
      department: { id: "dept-accounting", name: "Accounting" },
      review_scope: null,
      review_department_ids: [],
      review_grants: [],
    },
    200
  );
  await settle();
  assert(app.elementFor("tab-review").hidden === true, "revoked review tab must hide after /me");
  assert(app.elementFor("auth-view").hidden === true, "review denial must not log the user out");
  assert(app.elementFor("review-panel").hidden === true, "revoked review panel must hide");
  assert(app.elementFor("chat-panel").hidden === false, "review revocation must return to chat");
  assert(app.elementFor("review-list").children.length === 0, "revoked review list must clear");
  assert(app.elementFor("review-messages").children.length === 0, "revoked review detail must clear");
  assert(app.elementFor("review-meta").textContent === "", "revoked review metadata must clear");
}

async function scenarioExpiredSession() {
  const app = createApp();
  await start(app);
  await signIn(app);
  app.lastMatching("/workspace/api/conversations?limit=25").respond(
    { error: { code: "UNAUTHORIZED", message: "Authentication required." } },
    401
  );
  await settle();
  assert(app.elementFor("auth-view").hidden === false, "401 must return to sign-in");
  assert(app.elementFor("workspace-view").hidden === true, "401 must hide workspace content");
}


async function scenarioComposerIsolation() {
  const app = createApp();
  await start(app);
  await signIn(app);
  app.lastMatching("/workspace/api/conversations?limit=25").respond(
    {
      items: [
        { id: "conv-a", created_at: 1700000001, updated_at: 1700000002 },
        { id: "conv-b", created_at: 1700000003, updated_at: 1700000004 },
      ],
      next: null,
    },
    200
  );
  await settle();
  app.elementFor("conversation-list").children[0].dispatch("click");
  app.lastMatching("/workspace/api/conversations/conv-a").respond(
    {
      id: "conv-a",
      created_at: 1700000001,
      messages: [{ id: "a1", role: "user", outcome: "allowed", text: "A prompt", created_at: 1700000002 }],
    },
    200
  );
  await settle();
  app.elementFor("composer").value = "unsent draft in A";
  assert(
    String(app.elementFor("composer").getAttribute("placeholder")).indexOf("Select") < 0,
    "a ready composer must not still ask the user to select a conversation"
  );
  app.elementFor("composer-form").dispatch("submit");
  const sendA = app.lastMatching("/workspace/api/conversations/conv-a/messages");
  assert(sendA, "message request for A missing");
  app.elementFor("conversation-list").children[1].dispatch("click");
  app.lastMatching("/workspace/api/conversations/conv-b").respond(
    {
      id: "conv-b",
      created_at: 1700000003,
      messages: [{ id: "b1", role: "assistant", outcome: "allowed", text: "B transcript", created_at: 1700000004 }],
    },
    200
  );
  await settle();
  app.elementFor("composer").value = "draft only in B";
  sendA.respond({ status: "allowed" }, 200);
  await settle();
  assert(app.elementFor("composer").value === "draft only in B", "stale A reply must not clear B draft");
  const rendered = app.elementFor("messages").children.map((child) => child.textContent).join(" ");
  assert(rendered.indexOf("B transcript") >= 0, "B transcript missing");
  assert(rendered.indexOf("A prompt") < 0, "stale A content must not render in B");
  assert(app.elementFor("chat-status").textContent.indexOf("Answer received") < 0,
    "stale A status must not appear in B");
  const detailGets = app.callsMatching("/workspace/api/conversations/conv-a").filter(
    (call) => (!call.options.method || call.options.method === "GET") && call.url.endsWith("/conv-a")
  );
  assert(detailGets.length === 1, "stale A reply must not reload or replace B");

  app.elementFor("new-chat").dispatch("click");
  const create = app.calls.filter(
    (call) => call.url.endsWith("/workspace/api/conversations") && call.options.method === "POST"
  ).pop();
  assert(create, "new conversation request missing");
  app.elementFor("conversation-list").children[0].dispatch("click");
  app.lastMatching("/workspace/api/conversations/conv-a").respond(
    {
      id: "conv-a",
      created_at: 1700000001,
      messages: [{ id: "a1", role: "user", outcome: "allowed", text: "A again", created_at: 1700000002 }],
    },
    200
  );
  await settle();
  app.elementFor("composer").value = "keep this draft";
  create.respond({ id: "conv-new", created_at: 1700000009 }, 201);
  await settle();
  const listRefresh = app.lastMatching("/workspace/api/conversations?limit=25");
  if (listRefresh && !listRefresh.settled) {
    listRefresh.respond(
      {
        items: [
          { id: "conv-a", created_at: 1700000001, updated_at: 1700000002 },
          { id: "conv-b", created_at: 1700000003, updated_at: 1700000004 },
        ],
        next: null,
      },
      200
    );
    await settle();
  }
  assert(app.callsMatching("/workspace/api/conversations/conv-new").length === 0,
    "delayed create must not switch the conversation");
  assert(app.elementFor("composer").value === "keep this draft", "delayed create must not clear the current draft");

  app.elementFor("delete-conversation").dispatch("click");
  app.elementFor("delete-yes").dispatch("click");
  const deletion = app.calls.filter(
    (call) => call.url.endsWith("/workspace/api/conversations/conv-a") && call.options.method === "DELETE"
  ).pop();
  assert(deletion, "delete request missing");
  app.elementFor("conversation-list").children[1].dispatch("click");
  app.lastMatching("/workspace/api/conversations/conv-b").respond(
    {
      id: "conv-b",
      created_at: 1700000003,
      messages: [{ id: "b2", role: "assistant", outcome: "allowed", text: "B stays", created_at: 1700000005 }],
    },
    200
  );
  await settle();
  app.elementFor("composer").value = "B draft stays";
  deletion.respond({ status: "deleted" }, 200);
  await settle();
  const afterDeleteList = app.lastMatching("/workspace/api/conversations?limit=25");
  if (afterDeleteList && !afterDeleteList.settled) {
    afterDeleteList.respond(
      {
        items: [
          { id: "conv-b", created_at: 1700000003, updated_at: 1700000004 },
          { id: "conv-a", created_at: 1700000001, updated_at: 1700000002 },
        ],
        next: null,
      },
      200
    );
    await settle();
  }
  assert(app.elementFor("composer").value === "B draft stays", "delayed delete must not clear B draft");
  const afterDeleteText = app.elementFor("messages").children.map((child) => child.textContent).join(" ");
  assert(afterDeleteText.indexOf("B stays") >= 0, "delayed delete must not clear the current conversation");
  assert(app.elementFor("delete-confirm").hidden === true, "delete confirmation must close");
}

async function scenarioStaleQuietReloadKeepsCurrentDraft() {
  const app = createApp();
  await start(app);
  await signIn(app);
  app.lastMatching("/workspace/api/conversations?limit=25").respond(
    {
      items: [
        { id: "conv-a", created_at: 1700000001, updated_at: 1700000002 },
        { id: "conv-b", created_at: 1700000003, updated_at: 1700000004 },
      ],
      next: null,
    },
    200
  );
  await settle();
  app.elementFor("conversation-list").children[0].dispatch("click");
  app.lastMatching("/workspace/api/conversations/conv-a").respond(
    {
      id: "conv-a",
      created_at: 1700000001,
      messages: [{ id: "a1", role: "user", outcome: "allowed", text: "A prompt", created_at: 1700000002 }],
    },
    200
  );
  await settle();

  app.elementFor("composer").value = "send this to A";
  app.elementFor("composer-form").dispatch("submit");
  const sendA = app.lastMatching("/workspace/api/conversations/conv-a/messages");
  assert(sendA, "message request for A missing");
  sendA.respond({ status: "allowed" }, 200);
  await settle();

  const pendingReloads = app.pendingCallsMatching("/workspace/api/conversations/conv-a").filter(
    (call) => (!call.options.method || call.options.method === "GET") && call.url.endsWith("/conv-a")
  );
  assert(pendingReloads.length === 1, "post-send quiet reload for A missing");
  const reloadA = pendingReloads[0];

  app.elementFor("conversation-list").children[1].dispatch("click");
  app.lastMatching("/workspace/api/conversations/conv-b").respond(
    {
      id: "conv-b",
      created_at: 1700000003,
      messages: [{ id: "b1", role: "assistant", outcome: "allowed", text: "B transcript", created_at: 1700000004 }],
    },
    200
  );
  await settle();
  app.elementFor("composer").value = "draft B must survive";
  reloadA.respond(
    {
      id: "conv-a",
      created_at: 1700000001,
      messages: [{ id: "a2", role: "assistant", outcome: "allowed", text: "stale A answer", created_at: 1700000005 }],
    },
    200
  );
  await settle();

  assert(app.elementFor("composer").value === "draft B must survive",
    "a stale quiet reload must not restore the old A text over the B draft");
  const rendered = app.elementFor("messages").children.map((child) => child.textContent).join(" ");
  assert(rendered.indexOf("B transcript") >= 0, "current B transcript missing");
  assert(rendered.indexOf("stale A answer") < 0, "stale A reload must not replace B content");
  assert(app.elementFor("chat-status").textContent.indexOf("Answer received") < 0,
    "a stale quiet reload must not overwrite the current status");
}

async function scenarioGuardReadiness() {
  const app = createApp();
  await start(app, {
    health: { status: "not_ready", mode: "enforce", guards_active: true, workspace: "not_ready" },
    healthStatus: 503,
  });
  const text = app.elementFor("guard-status").textContent;
  assert(text.indexOf("unavailable") >= 0 || text.indexOf("not ready") >= 0,
    "unready health must be reported as unavailable");
  assert(text.indexOf("active") < 0, "unready health must not claim active protection");
  assert(app.elementFor("guard-status").getAttribute("data-kind") === "inactive",
    "unready health must be marked inactive");
}

async function scenarioStaleLogin() {
  const app = createApp();
  await start(app);
  app.elementFor("username").value = "alice";
  app.elementFor("password").value = "first-password";
  app.elementFor("login-form").dispatch("submit");
  const first = app.lastMatching("/workspace/api/login");
  assert(first, "first login request missing");
  app.elementFor("logout-button").dispatch("click");
  app.elementFor("username").value = "bob";
  app.elementFor("password").value = "second-password";
  const meCount = app.callsMatching("/workspace/api/me").length;
  first.respond(loginPayload(), 200);
  await settle();
  assert(app.elementFor("password").value === "second-password",
    "stale login must not clear the newer password");
  assert(app.elementFor("username").value === "bob", "stale login must not overwrite the newer username");
  assert(app.callsMatching("/workspace/api/me").length === meCount,
    "stale login must not start a new authenticated session");
}

async function scenarioAdmin() {
  const app = createApp({ maxInflight: 2 });
  await start(app);
  const adminProfile = {
    user: { ...ALICE_USER, id: "user-admin", username: "admin", full_name: "Ada Admin", role: "admin" },
    department: { id: "dept-accounting", name: "Accounting" },
    review_scope: null,
    review_department_ids: [],
    review_grants: [],
  };
  await signIn(app, adminProfile);
  app.lastMatching("/workspace/api/conversations?limit=25").respond({ items: [], next: null }, 200);
  await settle();
  await settleSummarySurfaces(app);
  assert(app.elementFor("tab-admin").hidden === false, "admin tab must appear for an admin role");
  const adminReadsBeforeOpen = app.callsMatching("/workspace/api/admin");
  assert(
    adminReadsBeforeOpen.length === 1 &&
      adminReadsBeforeOpen[0].url === "/workspace/api/admin/alerts/summary",
    "only the alert summary may be fetched before the admin view opens"
  );
  assert(
    app.callsMatching("/workspace/api/admin/users").length === 0 &&
      app.callsMatching("/workspace/api/admin/departments").length === 0 &&
      app.callsMatching("/workspace/api/admin/review-grants").length === 0 &&
      app.callsMatching("/workspace/api/admin/access-log").length === 0,
    "admin data must not be fetched before the admin view opens"
  );

  app.elementFor("tab-admin").dispatch("click");
  await settle();
  const departments = app.lastMatching("/workspace/api/admin/departments?limit=25");
  assert(departments, "all admin list requests must be bounded");
  assert(app.pendingCallsMatching("/workspace/api/admin").length <= 2,
    "admin list loading must respect the two-slot admission");
  assert(departments.options.headers.Authorization === undefined,
    "admin requests must not carry a bearer token");
  assert(departments.options.credentials === "same-origin",
    "admin requests must use same-origin cookie credentials");
  assert(departments.options.headers["X-Workspace-User"] === "user-admin",
    "admin requests must name the current profile");
  departments.respond(
    {
      items: [
        { id: "dept-accounting", name: "Accounting", created_at: 1700000000 },
        { id: "dept-hr", name: "Human Resources", created_at: 1700000001 },
      ],
      next: "dept-cursor",
    },
    200
  );
  await settle();
  const users = app.lastMatching("/workspace/api/admin/users?limit=25");
  assert(users, "the user list request must follow the department list");
  users.respond(
    {
      items: [
        { id: "user-admin", username: "admin", full_name: "Ada Admin", department_id: "dept-accounting", role: "admin", disabled: false, created_at: 1700000002 },
        { id: "user-alice", username: "alice", full_name: "Alice Tan", department_id: "dept-accounting", role: "employee", disabled: false, created_at: 1700000001 },
      ],
      next: "user-cursor",
    },
    200
  );
  await settle();
  app.elementFor("admin-tab-access").dispatch("click");
  await settle();
  const grants = app.lastMatching("/workspace/api/admin/review-grants?limit=25");
  assert(grants, "the grant list request must follow the user list");
  grants.respond(
    {
      items: [
        { id: "grant-1", user_id: "user-alice", username: "alice", scope: "department", department_id: "dept-accounting", department_name: "Accounting", created_by: "user-admin", created_at: 1700000003 },
      ],
      next: "grant-cursor",
    },
    200
  );
  await settle();
  const access = app.lastMatching("/workspace/api/admin/access-log?limit=25");
  assert(access, "the access log request must follow the grant list");
  access.respond(
    {
      items: [
        {
          id: "log-1", actor_id: "user-admin", actor_full_name: "Ada Admin",
          actor_username: "admin", actor_role: "admin", actor_deleted: false,
          action: "reviewer.read_conversation", conversation_id: "conv-1",
          department_id: "dept-accounting", department_name: "Accounting",
          conversation_created_at: 1700000000, conversation_updated_at: 1700000004,
          conversation_deleted: false, created_at: 1700000004,
        },
        {
          id: "log-2", actor_id: "user-gone", actor_full_name: null,
          actor_username: null, actor_role: null, actor_deleted: true,
          action: "owner.delete_conversation", conversation_id: "conv-gone",
          department_id: null, department_name: null,
          conversation_created_at: null, conversation_updated_at: null,
          conversation_deleted: true, created_at: 1700000002,
        },
      ],
      next: "access-cursor",
    },
    200
  );
  await settle();
  assert(app.callsMatching("/workspace/api/admin").some((call) => call.status === 503) === false,
    "sequential admin loading must not exhaust control admission");
  assert(app.elementFor("department-list").textContent.indexOf("Human Resources") >= 0,
    "department list did not render");
  assert(app.elementFor("user-list").textContent.indexOf("Ada Admin") >= 0, "user list did not render");
  assert(app.elementFor("grant-list").textContent.indexOf("@alice") >= 0, "grant list did not render");
  const accessText = app.elementFor("access-list").textContent;
  assert(
    accessText.indexOf("Read a conversation for review") >= 0 &&
      accessText.indexOf("Ada Admin") >= 0 &&
      accessText.indexOf("@admin") >= 0 &&
      accessText.indexOf("Administrator") >= 0 &&
      accessText.indexOf("Accounting") >= 0 &&
      accessText.indexOf("Deleted own conversation") >= 0 &&
      accessText.indexOf("Deleted user") >= 0 &&
      accessText.indexOf("Deleted conversation") >= 0,
    "access log must show human actor, action, department and conversation names"
  );
  assert(accessText.indexOf("reviewer.read_conversation") < 0 &&
    accessText.indexOf("owner.delete_conversation") < 0,
    "machine action names must not be the primary display text");
  assert(accessText.indexOf("prompt") < 0, "access log must not contain message text");
  const accessRows = collect(app.elementFor("access-list")).filter(
    (element) => String(element.className).indexOf("admin-table-row") >= 0
  );
  assert(accessRows.length === 2, "access log rows missing");
  const accessRow = accessRows[0];
  assert(
    accessRow.children.map((cell) => cell.getAttribute("data-label")).join(",") ===
      "Time,Actor,Action,Department,Conversation",
    "access rows must keep labelled cells for the narrow stacked layout"
  );
  const accessActionCell = accessRow.children[2];
  assert(accessActionCell.textContent === "Read a conversation for review",
    "the action must use its plain-language label");
  assert(accessActionCell.getAttribute("title") === "reviewer.read_conversation",
    "the original machine action must stay available as a title");
  const accessDepartmentCell = accessRows[1].children[3];
  assert(accessDepartmentCell.textContent.trim() === "—",
    "an unscoped department must render as an em dash");
  assert(accessDepartmentCell.getAttribute("title") === "Not department-scoped",
    "an unscoped department must explain itself in a tooltip");
  const accessConversationCell = accessRow.children[4];
  const accessConversationText = collect(accessConversationCell).find(
    (element) => element.getAttribute("title") === "Conversation ID conv-1"
  );
  assert(accessConversationText,
    "the full conversation identifier must stay available as a title");
  assert(String(accessConversationText.className).indexOf("cell-truncate") >= 0,
    "the conversation identifier must use the non-wrapping cell style");
  assert(collect(accessConversationCell).some(
    (element) => element.tagName === "BUTTON" && element.textContent === "Copy"
  ), "the full conversation identifier must be copyable");
  const adminDisableButtons = collect(app.elementFor("user-list")).filter(
    (element) => element.tagName === "BUTTON" && element.textContent.trim() === "Disable"
  );
  assert(adminDisableButtons.length === 1, "the current admin must not be offered self-disable");

  let aliceRow = findDataRow(app.elementFor("user-list"), "data-user", "user-alice");
  assert(aliceRow, "the employee row was not rendered");
  assert(
    aliceRow.children.map((cell) => cell.getAttribute("data-label")).join(",") ===
      "Account,Role,Department,Status,Actions",
    "user rows must keep labelled cells for the narrow stacked layout"
  );
  assert(aliceRow.children[4].getAttribute("data-label") === "Actions",
    "the action group must stay associated with the user row");
  assert(findButton(aliceRow, "Grant admin"), "an employee must be offered Grant admin");
  let selfRow = findDataRow(app.elementFor("user-list"), "data-user", "user-admin");
  assert(findButton(selfRow, "Revoke admin"), "an administrator must be offered Revoke admin");
  findButton(aliceRow, "Grant admin").dispatch("click");
  const cancelRoleBox = findByClass(aliceRow, "admin-confirm");
  assert(cancelRoleBox, "a role change must open an inline confirmation");
  const cancelRoleText = cancelRoleBox.textContent;
  assert(
    cancelRoleText.indexOf("Alice Tan") >= 0 &&
      cancelRoleText.indexOf("@alice") >= 0 &&
      cancelRoleText.indexOf("Administrator") >= 0,
    "the role confirmation must name the selected full name, username and intended role"
  );
  assert(
    findButton(cancelRoleBox, "Cancel").focused > 0,
    "a role confirmation must focus the safe action"
  );
  findButton(cancelRoleBox, "Cancel").dispatch("click");
  assert(
    app.callsMatching("/workspace/api/admin/users/user-alice/role").length === 0,
    "cancelling a role change must not send a request"
  );

  findButton(aliceRow, "Grant admin").dispatch("click");
  findButton(aliceRow, "Confirm grant").dispatch("click");
  const grantRole = app.lastMatching("/workspace/api/admin/users/user-alice/role");
  assert(grantRole && grantRole.options.method === "POST", "confirmed grant was not sent");
  assert(JSON.parse(grantRole.options.body).role === "admin", "grant payload mismatch");
  assert(grantRole.options.credentials === "same-origin", "role changes must use same-origin cookies");
  assert(grantRole.options.headers["Content-Type"] === "application/json",
    "role changes must declare a JSON Content-Type");
  assert(grantRole.options.headers["X-Workspace-User"] === "user-admin",
    "role changes must name the current profile");
  grantRole.respond(
    { id: "user-alice", username: "alice", full_name: "Alice Tan", department_id: "dept-accounting", role: "admin", disabled: false, created_at: 1700000001 },
    200
  );
  await settle();
  const grantRoleRefresh = app.lastMatching("/workspace/api/admin/users?limit=25");
  assert(grantRoleRefresh && !grantRoleRefresh.settled,
    "a successful role change must refresh the user list");
  grantRoleRefresh.respond(
    {
      items: [
        { id: "user-admin", username: "admin", full_name: "Ada Admin", department_id: "dept-accounting", role: "admin", disabled: false, created_at: 1700000002 },
        { id: "user-alice", username: "alice", full_name: "Alice Tan", department_id: "dept-accounting", role: "admin", disabled: false, created_at: 1700000001 },
      ],
      next: "user-cursor",
    },
    200
  );
  await settle();
  assert(app.elementFor("admin-status").textContent.indexOf("granted") >= 0,
    "a successful grant must be reported");
  aliceRow = findDataRow(app.elementFor("user-list"), "data-user", "user-alice");
  assert(findButton(aliceRow, "Revoke admin"), "the refreshed administrator row must offer Revoke admin");

  findButton(aliceRow, "Revoke admin").dispatch("click");
  const revokeRoleBox = findByClass(aliceRow, "admin-confirm");
  assert(revokeRoleBox && revokeRoleBox.textContent.indexOf("Employee") >= 0,
    "revoking admin must state the intended employee role");
  findButton(revokeRoleBox, "Confirm revoke").dispatch("click");
  const revokeRole = app.lastMatching("/workspace/api/admin/users/user-alice/role");
  assert(JSON.parse(revokeRole.options.body).role === "employee", "revoke payload mismatch");
  revokeRole.respond(
    { id: "user-alice", username: "alice", full_name: "Alice Tan", department_id: "dept-accounting", role: "employee", disabled: false, created_at: 1700000001 },
    200
  );
  await settle();
  app.lastMatching("/workspace/api/admin/users?limit=25").respond(
    {
      items: [
        { id: "user-admin", username: "admin", full_name: "Ada Admin", department_id: "dept-accounting", role: "admin", disabled: false, created_at: 1700000002 },
        { id: "user-alice", username: "alice", full_name: "Alice Tan", department_id: "dept-accounting", role: "employee", disabled: false, created_at: 1700000001 },
      ],
      next: "user-cursor",
    },
    200
  );
  await settle();
  assert(app.elementFor("admin-status").textContent.indexOf("revoked") >= 0,
    "a successful revoke must be reported");

  const meCallsBeforeConflict = app.callsMatching("/workspace/api/me").length;
  selfRow = findDataRow(app.elementFor("user-list"), "data-user", "user-admin");
  findButton(selfRow, "Revoke admin").dispatch("click");
  findButton(selfRow, "Confirm revoke").dispatch("click");
  const lastAdmin = app.lastMatching("/workspace/api/admin/users/user-admin/role");
  assert(JSON.parse(lastAdmin.options.body).role === "employee", "self-revoke payload mismatch");
  lastAdmin.respond(
    { error: { code: "CONFLICT", message: "The resource is busy." } },
    409
  );
  await settle();
  assert(
    app.elementFor("admin-status").textContent.indexOf("at least one administrator") >= 0,
    "a 409 last-admin refusal must be visible"
  );
  assert(app.elementFor("admin-status").getAttribute("data-kind") === "error",
    "a refused role change must be reported as an error");
  assert(app.callsMatching("/workspace/api/me").length === meCallsBeforeConflict,
    "a refused role change must not refresh the profile");

  app.elementFor("department-more").dispatch("click");
  await settle();
  const departmentMoreCall = app.lastMatching("/workspace/api/admin/departments?limit=25&after=dept-cursor");
  assert(departmentMoreCall, "department pagination request missing");
  departmentMoreCall.respond(
    { items: [{ id: "dept-it", name: "IT", created_at: 1700000005 }], next: null }, 200
  );
  await settle();
  app.elementFor("user-more").dispatch("click");
  await settle();
  const userMoreCall = app.lastMatching("/workspace/api/admin/users?limit=25&after=user-cursor");
  assert(userMoreCall, "user pagination request missing");
  userMoreCall.respond(
    { items: [], next: "user-page-2" }, 200
  );
  await settle();
  app.elementFor("grant-more").dispatch("click");
  await settle();
  const grantMoreCall = app.lastMatching("/workspace/api/admin/review-grants?limit=25&after=grant-cursor");
  assert(grantMoreCall, "grant pagination request missing");
  grantMoreCall.respond(
    { items: [], next: "grant-page-2" }, 200
  );
  await settle();
  app.elementFor("access-more").dispatch("click");
  await settle();
  const accessMoreCall = app.lastMatching("/workspace/api/admin/access-log?limit=25&after=access-cursor");
  assert(accessMoreCall, "access log pagination request missing");
  accessMoreCall.respond(
    { items: [], next: null }, 200
  );
  await settle();
  assert(app.pendingCallsMatching("/workspace/api/admin").length === 0,
    "admin pagination must settle without exceeding admission");
  assert(app.elementFor("department-list").textContent.indexOf("IT") >= 0, "department pagination failed");

  app.elementFor("department-name").value = "Finance";
  app.elementFor("department-form").dispatch("submit");
  const createDepartment = app.lastMatching("/workspace/api/admin/departments");
  assert(createDepartment.options.method === "POST", "department creation must POST");
  assert(JSON.parse(createDepartment.options.body).name === "Finance", "department payload mismatch");
  createDepartment.respond({ id: "dept-fin", name: "Finance", created_at: 1700000006 }, 201);
  await settle();
  const departmentRefresh = app.lastMatching("/workspace/api/admin/departments?limit=25");
  departmentRefresh.respond(
    { items: [{ id: "dept-fin", name: "Finance", created_at: 1700000006 }], next: null }, 200
  );
  await settle();

  app.elementFor("new-user-username").value = "new.person";
  app.elementFor("new-user-fullname").value = "New Person";
  app.elementFor("new-user-department").value = "dept-fin";
  app.elementFor("new-user-role").value = "employee";
  app.elementFor("new-user-password").value = "short";
  app.elementFor("user-form").dispatch("submit");
  assert(
    app.calls.filter(
      (call) => call.url === "/workspace/api/admin/users" && call.options.method === "POST"
    ).length === 0,
    "a password shorter than 12 characters must be rejected client-side"
  );
  app.elementFor("new-user-password").value = "long-enough-password";
  app.elementFor("user-form").dispatch("submit");
  const createUser = app.lastMatching("/workspace/api/admin/users");
  assert(createUser.options.method === "POST", "user creation must POST");
  const userPayload = JSON.parse(createUser.options.body);
  assert(userPayload.username === "new.person" && userPayload.role === "employee",
    "user payload mismatch");
  assert(userPayload.password === "long-enough-password", "user password missing from payload");
  assert(app.elementFor("new-user-password").value === "", "password must be cleared after the attempt");
  createUser.respond(
    { id: "user-new", username: "new.person", full_name: "New Person", department_id: "dept-fin", role: "employee", disabled: false, created_at: 1700000007 },
    201
  );
  await settle();
  app.lastMatching("/workspace/api/admin/users?limit=25").respond(
    {
      items: [
        { id: "user-admin", username: "admin", full_name: "Ada Admin", department_id: "dept-accounting", role: "admin", disabled: false, created_at: 1700000002 },
        { id: "user-alice", username: "alice", full_name: "Alice Tan", department_id: "dept-accounting", role: "employee", disabled: false, created_at: 1700000001 },
        { id: "user-new", username: "new.person", full_name: "New Person", department_id: "dept-fin", role: "employee", disabled: false, created_at: 1700000007 },
      ],
      next: "user-page-2",
    },
    200
  );
  await settle();

  assert(/original confidential chat text/.test(scriptText),
    "grant form must warn about original confidential chat text");
  app.elementFor("grant-user").value = "user-alice";
  app.elementFor("grant-scope").value = "global";
  app.elementFor("grant-scope").dispatch("change");
  assert(app.elementFor("grant-department-field").hidden === true,
    "global grants must hide the department selector");
  app.elementFor("grant-form").dispatch("submit");
  assert(
    app.callsMatching("/workspace/api/admin/review-grants").filter(
      (call) => call.options.method === "POST"
    ).length === 0,
    "a global grant without explicit confirmation must not be sent"
  );
  app.elementFor("grant-global-confirm").checked = true;
  app.elementFor("grant-form").dispatch("submit");
  const createGrant = app.calls.filter(
    (call) => call.url.endsWith("/workspace/api/admin/review-grants") && call.options.method === "POST"
  ).pop();
  assert(createGrant, "confirmed global grant was not sent");
  const grantPayload = JSON.parse(createGrant.options.body);
  assert(grantPayload.scope === "global" && !("department_id" in grantPayload),
    "global grant payload must not include a department");
  assert(app.elementFor("grant-global-confirm").checked === false,
    "global confirmation must reset after the attempt");
  createGrant.respond({ id: "grant-new", scope: "global" }, 201);
  await settle();
  app.lastMatching("/workspace/api/admin/review-grants?limit=25").respond(
    {
      items: [
        { id: "grant-new", user_id: "user-alice", username: "alice", scope: "global", department_name: null, created_at: 1700000008 },
      ],
      next: "grant-page-2",
    },
    200
  );
  const meAfterGrant = app.lastMatching("/workspace/api/me");
  assert(meAfterGrant, "grant creation must refresh the profile");
  meAfterGrant.respond(
    {
      ...adminProfile,
      review_scope: "global",
      review_grants: [{ id: "grant-new", scope: "global", department_id: null, department_name: null }],
    },
    200
  );
  await settle();
  await settleSummarySurfaces(app);
  assert(app.elementFor("admin-panel").hidden === false, "admin self-grant must keep the admin view visible");
  assert(app.elementFor("tab-review").hidden === false, "admin self-grant must expose the review tab");

  findButton(app.elementFor("grant-list"), "Revoke").dispatch("click");
  findButton(app.elementFor("grant-list"), "Cancel").dispatch("click");
  assert(
    app.callsMatching("/workspace/api/admin/review-grants/grant-new").filter(
      (call) => call.options.method === "DELETE"
    ).length === 0,
    "cancelled revoke must not send a request"
  );
  findButton(app.elementFor("grant-list"), "Revoke").dispatch("click");
  findButton(app.elementFor("grant-list"), "Revoke grant").dispatch("click");
  const revoke = app.callsMatching("/workspace/api/admin/review-grants/grant-new").filter(
    (call) => call.options.method === "DELETE"
  ).pop();
  assert(revoke, "confirmed revoke was not sent");
  assert(revoke.options.body === "{}",
    "bodyless grant revoke must send an empty JSON object");
  assert(revoke.options.headers["Content-Type"] === "application/json",
    "grant revoke must declare a JSON Content-Type for the cookie mutation guard");
  assert(revoke.options.credentials === "same-origin", "grant revoke credentials changed");
  assert(revoke.options.headers["X-Workspace-User"] === "user-admin",
    "grant revoke must name the current profile");
  assert(revoke.options.headers.Authorization === undefined,
    "grant revoke must not use bearer auth");
  revoke.respond({ status: "revoked" }, 200);
  await settle();
  app.lastMatching("/workspace/api/admin/review-grants?limit=25").respond(
    { items: [], next: "grant-page-9" }, 200
  );
  app.lastMatching("/workspace/api/me").respond(adminProfile, 200);
  await settle();
  await settleSummarySurfaces(app);
  assert(app.elementFor("admin-panel").hidden === false, "revoked admin self-grant must keep the admin view visible");
  assert(app.elementFor("tab-review").hidden === true, "revoked admin self-grant must hide the review tab");
  assert(app.elementFor("review-panel").hidden === true, "revoked admin self-grant must keep review hidden");

  findButton(app.elementFor("user-list"), "Disable").dispatch("click");
  findButton(app.elementFor("user-list"), "Cancel").dispatch("click");
  assert(app.callsMatching("/workspace/api/admin/users/user-alice/disable").length === 0,
    "cancelled disable must not send a request");
  findButton(app.elementFor("user-list"), "Disable").dispatch("click");
  findButton(app.elementFor("user-list"), "Confirm disable").dispatch("click");
  const disable = app.lastMatching("/workspace/api/admin/users/user-alice/disable");
  assert(disable && disable.options.method === "POST", "confirmed disable was not sent");
  disable.respond({ status: "disabled" }, 200);
  await settle();
  app.lastMatching("/workspace/api/admin/users?limit=25").respond(
    {
      items: [
        { id: "user-alice", username: "alice", full_name: "Alice Tan", department_id: "dept-accounting", role: "employee", disabled: true, created_at: 1700000001 },
      ],
      next: "user-page-2",
    },
    200
  );
  await settle();
  assert(
    !findButton(app.elementFor("user-list"), "Grant admin") &&
      !findButton(app.elementFor("user-list"), "Revoke admin"),
    "a disabled user must not be offered a role change"
  );

  findButton(app.elementFor("user-list"), "Reset password").dispatch("click");
  const resetInput = findByClass(app.elementFor("user-list"), "admin-reset-input");
  const resetForm = findByClass(app.elementFor("user-list"), "admin-reset");
  assert(resetInput && resetInput.type === "password" && resetForm, "reset password form missing");
  resetInput.value = "short";
  resetForm.dispatch("submit");
  assert(app.callsMatching("/workspace/api/admin/users/user-alice/reset-password").length === 0,
    "short reset password must not be sent");
  resetInput.value = "long-enough-password";
  resetForm.dispatch("submit");
  const resetPost = app.lastMatching("/workspace/api/admin/users/user-alice/reset-password");
  assert(resetPost, "confirmed reset was not sent");
  assert(JSON.parse(resetPost.options.body).password === "long-enough-password",
    "reset payload mismatch");
  assert(resetInput.value === "", "reset password input must be cleared after the attempt");
  resetPost.respond({ status: "reset" }, 200);
  await settle();
  assert(app.elementFor("admin-status").textContent.indexOf("revoked") >= 0,
    "reset success must state that existing sign-ins were revoked");

  app.elementFor("user-more").dispatch("click");
  await settle();
  const deniedUsers = app.lastMatching("/workspace/api/admin/users?limit=25&after=user-page-2");
  assert(deniedUsers, "user pagination request missing");
  deniedUsers.respond(
    { error: { code: "FORBIDDEN", message: "Permission denied." } }, 403
  );
  await settle();
  assert(app.elementFor("user-state").textContent.indexOf("denied") >= 0,
    "a 403 must be reported as permission denial");
  assert(app.elementFor("auth-view").hidden === true, "a 403 must not sign the admin out");

  app.elementFor("grant-more").dispatch("click");
  await settle();
  const staleGrant = app.lastMatching("/workspace/api/admin/review-grants?limit=25&after=grant-page-9");
  assert(staleGrant, "grant pagination request missing");
  app.elementFor("access-more").dispatch("click");
  const accessCallsBefore = app.callsMatching("/workspace/api/admin/access-log").length;
  app.elementFor("logout-button").dispatch("click");
  staleGrant.respond(
    {
      items: [{ id: "grant-stale", username: "stale-admin", scope: "global", created_at: 1700000099 }],
      next: null,
    },
    200
  );
  await settle();
  assert(app.callsMatching("/workspace/api/admin/access-log").length === accessCallsBefore,
    "a stale session epoch must not launch the queued admin list fetch");
  assert(app.elementFor("grant-list").textContent.indexOf("stale-admin") < 0,
    "stale admin reply must not render after logout");
  assert(app.elementFor("admin-panel").hidden === true, "logout must hide the admin panel");
  assert(app.elementFor("department-name").value === "", "logout must destroy admin form fields");
  assert(app.elementFor("new-user-password").value === "", "logout must destroy password fields");
  assert(app.elementFor("workspace-view").hidden === true, "logout must hide the workspace");
}

async function scenarioAdminEnableAndDelete() {
  const app = createApp({ maxInflight: 2 });
  await start(app);
  const adminProfile = {
    user: { ...ALICE_USER, id: "user-admin", username: "admin", full_name: "Ada Admin", role: "admin" },
    department: { id: "dept-accounting", name: "Accounting" },
    review_scope: null,
    review_department_ids: [],
    review_grants: [],
  };
  const adminRow = {
    id: "user-admin", username: "admin", full_name: "Ada Admin",
    department_id: "dept-accounting", role: "admin", disabled: false, created_at: 1700000002,
  };
  const disabledAlice = {
    id: "user-alice", username: "alice", full_name: "Alice Tan",
    department_id: "dept-accounting", role: "employee", disabled: true, created_at: 1700000001,
  };
  const activeAlice = { ...disabledAlice, disabled: false };
  await signIn(app, adminProfile);
  app.lastMatching("/workspace/api/conversations?limit=25").respond({ items: [], next: null }, 200);
  await settle();
  await settleSummarySurfaces(app);

  app.elementFor("tab-admin").dispatch("click");
  await settle();
  app.lastMatching("/workspace/api/admin/departments?limit=25").respond(
    { items: [{ id: "dept-accounting", name: "Accounting", created_at: 1700000000 }], next: null },
    200
  );
  await settle();
  app.lastMatching("/workspace/api/admin/users?limit=25").respond(
    { items: [adminRow, disabledAlice], next: null },
    200
  );
  await settle();

  const selfRow = findDataRow(app.elementFor("user-list"), "data-user", "user-admin");
  assert(selfRow && !findButton(selfRow, "Delete"),
    "an administrator must not be offered self-delete");
  assert(!findButton(selfRow, "Disable"), "an administrator must not be offered self-disable");

  let aliceRow = findDataRow(app.elementFor("user-list"), "data-user", "user-alice");
  assert(aliceRow, "the disabled account row was not rendered");
  assert(findButton(aliceRow, "Enable"),
    "a disabled account must offer Enable instead of only password reset");
  assert(findButton(aliceRow, "Reset password"),
    "a disabled account must still offer Reset password");
  assert(findButton(aliceRow, "Delete"),
    "an ordinary target account must offer Delete");
  assert(!findButton(aliceRow, "Disable"), "a disabled account must not offer Disable");
  assert(!findButton(aliceRow, "Grant admin") && !findButton(aliceRow, "Revoke admin"),
    "a disabled account must not offer a role change");

  findButton(aliceRow, "Enable").dispatch("click");
  let enableBox = findByClass(aliceRow, "admin-confirm");
  assert(enableBox, "Enable must open an inline confirmation");
  assert(enableBox.getAttribute("role") === "group", "the enable confirmation must be an accessible group");
  assert(String(enableBox.getAttribute("aria-label")).indexOf("@alice") >= 0,
    "the enable confirmation must name the target in its accessible label");
  assert(enableBox.textContent.indexOf("existing sign-ins stay revoked") >= 0,
    "the enable confirmation must state that previous sessions stay revoked");
  findButton(enableBox, "Cancel").dispatch("click");
  assert(app.callsMatching("/workspace/api/admin/users/user-alice/enable").length === 0,
    "cancelled enable must not send a request");

  findButton(aliceRow, "Enable").dispatch("click");
  findButton(findByClass(aliceRow, "admin-confirm"), "Confirm enable").dispatch("click");
  let enableCall = app.lastMatching("/workspace/api/admin/users/user-alice/enable");
  assert(enableCall && enableCall.options.method === "POST", "confirmed enable was not sent");
  assert(enableCall.options.body === "{}", "enable must send an empty JSON object");
  assert(enableCall.options.headers["Content-Type"] === "application/json",
    "enable must declare a JSON Content-Type");
  assert(enableCall.options.credentials === "same-origin", "enable must use same-origin cookies");
  assert(enableCall.options.headers["X-Workspace-User"] === "user-admin",
    "enable must name the current profile");
  enableCall.respond({ error: { code: "CONFLICT", message: "user is already active" } }, 409);
  await settle();
  assert(app.elementFor("admin-status").textContent.indexOf("already active") >= 0,
    "a 409 enable refusal must be visible");
  assert(app.elementFor("admin-status").getAttribute("data-kind") === "error",
    "a refused enable must be reported as an error");
  assert(findButton(aliceRow, "Enable"), "a refused enable must leave the account disabled");

  findButton(aliceRow, "Enable").dispatch("click");
  findButton(findByClass(aliceRow, "admin-confirm"), "Confirm enable").dispatch("click");
  enableCall = app.lastMatching("/workspace/api/admin/users/user-alice/enable");
  enableCall.respond(activeAlice, 200);
  await settle();
  const enableRefresh = app.lastMatching("/workspace/api/admin/users?limit=25");
  assert(enableRefresh && !enableRefresh.settled,
    "a successful enable must refresh the user list");
  enableRefresh.respond({ items: [adminRow, activeAlice], next: null }, 200);
  await settle();
  assert(app.elementFor("admin-status").textContent.indexOf("enabled") >= 0,
    "a successful enable must be reported");
  aliceRow = findDataRow(app.elementFor("user-list"), "data-user", "user-alice");
  assert(aliceRow && findButton(aliceRow, "Disable") && !findButton(aliceRow, "Enable"),
    "the refreshed row must be active and offer Disable");
  assert(findButton(aliceRow, "Grant admin"), "the refreshed row must offer a role change again");
  assert(findButton(aliceRow, "Delete"), "the refreshed row must still offer Delete");

  findButton(aliceRow, "Delete").dispatch("click");
  let deleteBox = findByClass(aliceRow, "admin-confirm");
  assert(deleteBox, "Delete must open an inline typed confirmation");
  assert(deleteBox.getAttribute("role") === "group",
    "the delete confirmation must be an accessible group");
  assert(String(deleteBox.getAttribute("aria-label")).indexOf("Delete Alice Tan") >= 0 &&
    String(deleteBox.getAttribute("aria-label")).indexOf("@alice") >= 0,
    "the delete confirmation must name the account in its accessible label");
  const deleteText = deleteBox.textContent;
  assert(deleteText.indexOf("permanently erases") >= 0 &&
    deleteText.indexOf("saved conversations") >= 0 &&
    deleteText.indexOf("cannot be undone") >= 0,
    "the delete confirmation must show the erasure consequence");
  assert(deleteText.indexOf("alice") >= 0, "the delete confirmation must name the exact username");
  const consequence = findByClass(deleteBox, "admin-confirm-consequence");
  let deleteInput = findByClass(deleteBox, "admin-confirm-input");
  assert(consequence && deleteInput, "the typed delete confirmation is missing its parts");
  assert(deleteInput.getAttribute("aria-describedby") === consequence.id,
    "the typed input must be described by the erasure consequence");
  assert(String(deleteInput.getAttribute("aria-label")).indexOf("alice") >= 0,
    "the typed input must have an accessible label naming the username");
  const confirmDelete = findButton(deleteBox, "Confirm delete");
  assert(confirmDelete.disabled === true,
    "delete must stay disabled until the exact username is typed");

  deleteInput.value = "alica";
  deleteInput.dispatch("input");
  assert(confirmDelete.disabled === true, "a mismatched username must keep delete disabled");
  confirmDelete.dispatch("click");
  assert(app.callsMatching("/workspace/api/admin/users/user-alice/delete").length === 0,
    "a mismatched typed confirmation must not send a delete request");

  deleteInput.value = "alice";
  deleteInput.dispatch("input");
  assert(confirmDelete.disabled === false, "the exact username must enable delete");

  confirmDelete.dispatch("click");
  let deleteCall = app.lastMatching("/workspace/api/admin/users/user-alice/delete");
  assert(deleteCall && deleteCall.options.method === "POST", "confirmed delete was not sent");
  assert(JSON.parse(deleteCall.options.body).confirm_username === "alice",
    "the delete request must repeat the exact username");
  assert(deleteCall.options.headers["Content-Type"] === "application/json",
    "delete must declare a JSON Content-Type");
  assert(deleteCall.options.credentials === "same-origin", "delete must use same-origin cookies");
  deleteCall.respond(
    { error: { code: "CONFLICT", message: "account has an active conversation turn" } },
    409
  );
  await settle();
  assert(app.elementFor("admin-status").textContent.indexOf("Deletion was refused") >= 0,
    "a 409 delete refusal must be visible");
  assert(app.elementFor("admin-status").getAttribute("data-kind") === "error",
    "a refused delete must be reported as an error");
  assert(findDataRow(app.elementFor("user-list"), "data-user", "user-alice"),
    "a refused delete must leave the row in place");

  aliceRow = findDataRow(app.elementFor("user-list"), "data-user", "user-alice");
  findButton(aliceRow, "Delete").dispatch("click");
  deleteBox = findByClass(aliceRow, "admin-confirm");
  deleteInput = findByClass(deleteBox, "admin-confirm-input");
  deleteInput.value = "alice";
  deleteInput.dispatch("input");
  findButton(deleteBox, "Confirm delete").dispatch("click");
  deleteCall = app.lastMatching("/workspace/api/admin/users/user-alice/delete");
  deleteCall.respond(
    { status: "deleted", deleted_conversations: 2, deleted_messages: 5 },
    200
  );
  await settle();
  const deleteRefresh = app.lastMatching("/workspace/api/admin/users?limit=25");
  assert(deleteRefresh && !deleteRefresh.settled,
    "a successful delete must refresh the user list");
  deleteRefresh.respond({ items: [adminRow], next: null }, 200);
  await settle();
  const deleteStatus = app.elementFor("admin-status").textContent;
  assert(deleteStatus.indexOf("deleted") >= 0 &&
    deleteStatus.indexOf("2 conversation") >= 0 &&
    deleteStatus.indexOf("5 message") >= 0,
    "a successful delete must report the erasure counts");
  assert(!findDataRow(app.elementFor("user-list"), "data-user", "user-alice"),
    "a successful delete must remove the row after refresh");
  const finalSelfRow = findDataRow(app.elementFor("user-list"), "data-user", "user-admin");
  assert(finalSelfRow && !findButton(finalSelfRow, "Delete"),
    "the refreshed list must never offer self-delete");
}

async function scenarioAdminOwnRoleChange() {
  const app = createApp({ maxInflight: 2 });
  await start(app);
  const adminProfile = {
    user: { ...ALICE_USER, id: "user-admin", username: "admin", full_name: "Ada Admin", role: "admin" },
    department: { id: "dept-accounting", name: "Accounting" },
    review_scope: null,
    review_department_ids: [],
    review_grants: [],
  };
  const adminRow = {
    id: "user-admin", username: "admin", full_name: "Ada Admin",
    department_id: "dept-accounting", role: "admin", disabled: false, created_at: 1700000002,
  };
  const secondAdmin = {
    id: "user-alice", username: "alice", full_name: "Alice Tan",
    department_id: "dept-accounting", role: "admin", disabled: false, created_at: 1700000001,
  };
  await signIn(app, adminProfile);
  app.lastMatching("/workspace/api/conversations?limit=25").respond({ items: [], next: null }, 200);
  await settle();
  await settleSummarySurfaces(app);
  app.elementFor("tab-admin").dispatch("click");
  await settle();
  app.lastMatching("/workspace/api/admin/departments?limit=25").respond(
    { items: [{ id: "dept-accounting", name: "Accounting", created_at: 1700000000 }], next: null },
    200
  );
  await settle();
  app.lastMatching("/workspace/api/admin/users?limit=25").respond(
    { items: [adminRow, secondAdmin], next: null },
    200
  );
  await settle();

  const selfRow = findDataRow(app.elementFor("user-list"), "data-user", "user-admin");
  findButton(selfRow, "Revoke admin").dispatch("click");
  findButton(selfRow, "Confirm revoke").dispatch("click");
  const request = app.lastMatching("/workspace/api/admin/users/user-admin/role");
  assert(request && JSON.parse(request.options.body).role === "employee",
    "own role change payload mismatch");
  request.respond({ ...adminRow, role: "employee" }, 200);
  await settle();
  const profileRefresh = app.lastMatching("/workspace/api/me");
  assert(profileRefresh && !profileRefresh.settled,
    "an own role change must refresh the current profile");
  profileRefresh.respond(
    { ...adminProfile, user: { ...adminProfile.user, role: "employee" } },
    200
  );
  await settle();
  assert(app.elementFor("tab-admin").hidden === true,
    "an own demotion must hide the admin tab");
  assert(app.elementFor("admin-panel").hidden === true,
    "an own demotion must leave the admin view");
  assert(app.elementFor("global-status").textContent.indexOf("no longer available") >= 0,
    "an own demotion must explain that admin tools are gone");
}

async function scenarioPolicyPostalMask() {
  const app = createApp();
  await start(app);
  const adminProfile = {
    user: { ...ALICE_USER, id: "user-admin", username: "admin", full_name: "Ada Admin", role: "admin" },
    department: { id: "dept-accounting", name: "Accounting" },
    review_scope: null,
    review_department_ids: [],
    review_grants: [],
  };
  const aliceRow = {
    id: "user-alice", username: "alice", full_name: "Alice Tan",
    department_id: "dept-accounting", role: "employee", disabled: false, created_at: 1700000001,
  };
  // A profile saved before POSTAL_ADDRESS existed. Editing it must not select
  // postal masking on the administrator's behalf.
  const legacyProfile = {
    id: "profile-legacy",
    name: "Legacy masks",
    revision: 1,
    settings: {
      input_check_enabled: true,
      output_check_enabled: true,
      input_masks: ["EMAIL"],
      output_masks: ["EMAIL", "MY_PHONE"],
    },
    settings_digest: "c".repeat(64),
  };
  await signIn(app, adminProfile);
  app.lastMatching("/workspace/api/conversations?limit=25").respond({ items: [], next: null }, 200);
  await settle();
  await settleSummarySurfaces(app);

  app.elementFor("tab-admin").dispatch("click");
  await settle();
  app.lastMatching("/workspace/api/admin/departments?limit=25").respond(
    { items: [{ id: "dept-accounting", name: "Accounting", created_at: 1700000000 }], next: null },
    200
  );
  await settle();
  app.lastMatching("/workspace/api/admin/users?limit=25").respond(
    { items: [aliceRow], next: null },
    200
  );
  await settle();
  app.elementFor("admin-tab-policies").dispatch("click");
  await settle();
  app.lastMatching("/workspace/api/admin/policy/profiles?limit=25").respond(
    { items: [legacyProfile], next: null },
    200
  );
  await settle();
  const assignment = app.lastMatching("/workspace/api/admin/policy/assignments/workspace");
  assert(assignment, "the policies tab must read the current workspace assignment");
  assignment.respond({ assignment: null }, 200);
  await settle();

  app.elementFor("policy-new").dispatch("click");
  for (const id of [
    "policy-input-email", "policy-input-phone", "policy-input-mykad", "policy-input-postal",
    "policy-output-email", "policy-output-phone", "policy-output-mykad", "policy-output-postal",
  ]) {
    assert(app.elementFor(id).checked === true,
      "a new profile must select every mask by default, including " + id);
  }
  app.elementFor("policy-name").value = "Postal output only";
  app.elementFor("policy-input-postal").checked = false;
  app.elementFor("policy-form").dispatch("submit");
  const create = app.lastMatching("/workspace/api/admin/policy/profiles");
  assert(create && create.options.method === "POST", "profile creation must POST");
  const payload = JSON.parse(create.options.body);
  assert(payload.input_masks.indexOf("POSTAL_ADDRESS") < 0,
    "an unchecked postal mask must stay off on input");
  assert(payload.input_masks.indexOf("EMAIL") >= 0,
    "the other selected input masks must still be saved");
  assert(payload.output_masks.indexOf("POSTAL_ADDRESS") >= 0,
    "postal masking must be independently selectable on output");
  const savedProfile = {
    id: "profile-postal-output",
    name: "Postal output only",
    revision: 1,
    settings: {
      input_check_enabled: true,
      output_check_enabled: true,
      input_masks: ["EMAIL", "MY_PHONE", "MYKAD"],
      output_masks: ["EMAIL", "MY_PHONE", "MYKAD", "POSTAL_ADDRESS"],
    },
    settings_digest: "d".repeat(64),
  };
  create.respond(savedProfile, 201);
  await settle();
  const listRefresh = app.lastMatching("/workspace/api/admin/policy/profiles?limit=25");
  assert(listRefresh, "a saved profile must refresh the list");
  listRefresh.respond({ items: [savedProfile, legacyProfile], next: null }, 200);
  await settle();
  const listText = app.elementFor("policy-list").textContent;
  assert(listText.indexOf("Postal output only") >= 0, "the saved profile must be listed");
  const savedRow = findDataRow(app.elementFor("policy-list"), "data-policy", "profile-postal-output");
  assert(savedRow && savedRow.textContent.indexOf("POSTAL_ADDRESS") >= 0,
    "the profile list must show the postal mask honestly on output");
  const masksCellText = savedRow.children[2].textContent;
  assert(masksCellText.indexOf("Input: EMAIL, MY_PHONE, MYKAD") >= 0 &&
    masksCellText.indexOf("Output: EMAIL, MY_PHONE, MYKAD, POSTAL_ADDRESS") >= 0,
    "the profile list must show postal masking only on the output channel");

  const legacyRow = findDataRow(app.elementFor("policy-list"), "data-policy", "profile-legacy");
  findButton(legacyRow, "Edit").dispatch("click");
  const legacyGet = app.lastMatching("/workspace/api/admin/policy/profiles/profile-legacy");
  assert(legacyGet, "editing must read the latest stored revision");
  legacyGet.respond(legacyProfile, 200);
  await settle();
  assert(app.elementFor("policy-input-postal").checked === false &&
    app.elementFor("policy-output-postal").checked === false,
    "an existing profile that omits POSTAL_ADDRESS must not silently gain it in the editor");
  assert(app.elementFor("policy-input-email").checked === true &&
    app.elementFor("policy-output-phone").checked === true,
    "the editor must still reflect the masks the stored profile selected");
  app.elementFor("policy-form").dispatch("submit");
  const revise = app.lastMatching("/workspace/api/admin/policy/profiles/profile-legacy/revise");
  assert(revise, "saving an edited profile must revise it");
  const revisePayload = JSON.parse(revise.options.body);
  assert(revisePayload.expected_revision === 1, "the pinned revision must be sent");
  assert(revisePayload.input_masks.indexOf("POSTAL_ADDRESS") < 0 &&
    revisePayload.output_masks.indexOf("POSTAL_ADDRESS") < 0,
    "saving an untouched legacy profile must not add postal masking");
  revise.respond({ ...legacyProfile, revision: 2 }, 200);
  await settle();
  app.lastMatching("/workspace/api/admin/policy/profiles?limit=25").respond(
    { items: [savedProfile, { ...legacyProfile, revision: 2 }], next: null }, 200
  );
  await settle();

  app.elementFor("effective-user").value = "user-alice";
  app.elementFor("effective-preview").dispatch("click");
  const effective = app.lastMatching("/workspace/api/admin/policy/effective?user_id=user-alice");
  assert(effective, "the effective preview request is missing");
  effective.respond(
    {
      user_id: "user-alice",
      department_id: "dept-accounting",
      input_check_enabled: true,
      output_check_enabled: true,
      input_masks: ["EMAIL"],
      output_masks: ["POSTAL_ADDRESS"],
      revision: "profile:profile-postal-output:1",
      settings_digest: "d".repeat(64),
      source: {
        scope_type: "user",
        scope_id: "user-alice",
        profile_id: "profile-postal-output",
        profile_name: "Postal output only",
        revision: 1,
      },
      sources: [
        {
          scope_type: "user",
          scope_id: "user-alice",
          profile_id: "profile-postal-output",
          profile_name: "Postal output only",
          revision: 1,
        },
      ],
      is_default: false,
    },
    200
  );
  await settle();
  const preview = app.elementFor("effective-policy");
  const outputBlock = collect(preview).find(
    (element) => String(element.className).split(" ").indexOf("effective-block") >= 0 &&
      element.getAttribute("data-stage") === "output"
  );
  const inputBlock = collect(preview).find(
    (element) => String(element.className).split(" ").indexOf("effective-block") >= 0 &&
      element.getAttribute("data-stage") === "input"
  );
  assert(outputBlock && collect(outputBlock).some(
    (element) => element.textContent === "POSTAL_ADDRESS" &&
      String(element.className).split(" ").indexOf("is-mask") >= 0
  ), "the effective preview must show postal masking on output");
  assert(inputBlock && inputBlock.textContent.indexOf("POSTAL_ADDRESS") < 0,
    "the effective preview must not show postal masking on an input channel that omits it");
}

async function scenarioEffectivePolicyPreview() {
  const app = createApp();
  await start(app);
  const adminProfile = {
    user: { ...ALICE_USER, id: "user-admin", username: "admin", full_name: "Ada Admin", role: "admin" },
    department: { id: "dept-accounting", name: "Accounting" },
    review_scope: null,
    review_department_ids: [],
    review_grants: [],
  };
  const adminRow = {
    id: "user-admin", username: "admin", full_name: "Ada Admin",
    department_id: "dept-accounting", role: "admin", disabled: false, created_at: 1700000002,
  };
  const aliceRow = {
    id: "user-alice", username: "alice", full_name: "Alice Tan",
    department_id: "dept-accounting", role: "employee", disabled: false, created_at: 1700000001,
  };
  const openProfile = {
    id: "profile-input-open",
    name: "No input PII masking",
    revision: 1,
    settings: {
      input_check_enabled: true,
      output_check_enabled: true,
      input_masks: [],
      output_masks: ["EMAIL"],
    },
    settings_digest: "a".repeat(64),
  };
  await signIn(app, adminProfile);
  app.lastMatching("/workspace/api/conversations?limit=25").respond({ items: [], next: null }, 200);
  await settle();
  await settleSummarySurfaces(app);

  app.elementFor("tab-admin").dispatch("click");
  await settle();
  app.lastMatching("/workspace/api/admin/departments?limit=25").respond(
    { items: [{ id: "dept-accounting", name: "Accounting", created_at: 1700000000 }], next: null },
    200
  );
  await settle();
  app.lastMatching("/workspace/api/admin/users?limit=25").respond(
    { items: [adminRow, aliceRow], next: null },
    200
  );
  await settle();
  app.elementFor("admin-tab-policies").dispatch("click");
  await settle();
  app.lastMatching("/workspace/api/admin/policy/profiles?limit=25").respond(
    { items: [openProfile], next: null },
    200
  );
  await settle();
  const assignment = app.lastMatching("/workspace/api/admin/policy/assignments/workspace");
  assert(assignment, "the policies tab must read the current workspace assignment");
  assignment.respond({ assignment: null }, 200);
  await settle();

  app.elementFor("effective-user").value = "user-alice";
  app.elementFor("effective-preview").dispatch("click");
  const single = app.lastMatching("/workspace/api/admin/policy/effective?user_id=user-alice");
  assert(single, "the effective preview request is missing");
  single.respond(
    {
      user_id: "user-alice",
      department_id: "dept-accounting",
      input_check_enabled: true,
      output_check_enabled: true,
      input_masks: [],
      output_masks: ["EMAIL"],
      revision: "profile:profile-input-open:1",
      settings_digest: "a".repeat(64),
      source: {
        scope_type: "user",
        scope_id: "user-alice",
        profile_id: "profile-input-open",
        profile_name: "No input PII masking",
        revision: 1,
      },
      sources: [
        {
          scope_type: "user",
          scope_id: "user-alice",
          profile_id: "profile-input-open",
          profile_name: "No input PII masking",
          revision: 1,
        },
      ],
      is_default: false,
    },
    200
  );
  await settle();

  const preview = app.elementFor("effective-policy");
  const singleText = preview.textContent;
  assert(singleText.indexOf("explicit no masking") < 0,
    "an empty mask list must be a neutral chip, not a warning-like phrase");
  assert(singleText.indexOf("Winning scope") < 0 && singleText.indexOf("Inheritance sources") < 0,
    "the preview must replace scope and inheritance jargon");
  assert(singleText.indexOf("Input checks / masks") >= 0 &&
    singleText.indexOf("Output checks / masks") >= 0,
    "input and output must be separate labelled blocks");
  const blocks = collect(preview).filter(
    (element) => String(element.className).split(" ").indexOf("effective-block") >= 0
  );
  assert(blocks.length === 2, "the preview must render exactly two channel blocks");
  const inputBlock = blocks.find((element) => element.getAttribute("data-stage") === "input");
  const outputBlock = blocks.find((element) => element.getAttribute("data-stage") === "output");
  assert(inputBlock && inputBlock.textContent.indexOf("Masks: None") >= 0,
    "the no-masking input block must show a plain None chip");
  const noneChip = collect(inputBlock).find(
    (element) => String(element.className).split(" ").indexOf("is-none") >= 0 &&
      element.textContent === "None"
  );
  assert(noneChip, "None must be rendered as its own neutral chip");
  assert(outputBlock && outputBlock.textContent.indexOf("EMAIL") >= 0,
    "the output block must list its masks explicitly");
  assert(!collect(outputBlock).some(
    (element) => String(element.className).split(" ").indexOf("is-none") >= 0
  ), "a masked channel must not also show a None chip");
  assert(singleText.indexOf("User · @alice") >= 0 &&
    singleText.indexOf("No input PII masking") >= 0 &&
    singleText.indexOf("revision 1") >= 0,
    "the preview must name the winning scope, human profile name and revision");
  assert(singleText.indexOf("profile-input-open") < 0,
    "an internal profile identifier must not be presented as a human label");
  assert(singleText.indexOf("re-apply the assignment") >= 0,
    "the preview must state the re-apply action instead of pinning jargon");
  assert(!collect(preview).some(
    (element) => String(element.className).split(" ").indexOf("effective-chain") >= 0
  ), "a single source must not render an inheritance chain");

  app.elementFor("effective-preview").dispatch("click");
  const multi = app.lastMatching("/workspace/api/admin/policy/effective?user_id=user-alice");
  assert(multi && multi !== single, "a second preview request is missing");
  multi.respond(
    {
      user_id: "user-alice",
      department_id: "dept-accounting",
      input_check_enabled: false,
      output_check_enabled: true,
      input_masks: ["EMAIL"],
      output_masks: ["EMAIL", "MYKAD"],
      revision: "profile:profile-user:3",
      settings_digest: "b".repeat(64),
      source: {
        scope_type: "user",
        scope_id: "user-alice",
        profile_id: "profile-user",
        profile_name: "No input PII masking",
        revision: 3,
      },
      sources: [
        {
          scope_type: "workspace",
          scope_id: "workspace",
          profile_id: "profile-workspace",
          profile_name: "Baseline",
          revision: 1,
        },
        {
          scope_type: "department",
          scope_id: "dept-accounting",
          profile_id: "profile-department",
          profile_name: "Accounting policy",
          revision: 2,
        },
        {
          scope_type: "user",
          scope_id: "user-alice",
          profile_id: "profile-user",
          profile_name: "No input PII masking",
          revision: 3,
        },
      ],
      is_default: false,
    },
    200
  );
  await settle();

  const multiText = preview.textContent;
  const chainItems = collect(preview).filter(
    (element) => String(element.className).split(" ").indexOf("effective-chain-item") >= 0
  );
  assert(chainItems.length === 3, "a multi-scope preview must render the full scope chain");
  assert(chainItems[0].textContent.indexOf("Organisation") >= 0 &&
    chainItems[0].textContent.indexOf("Baseline") >= 0 &&
    chainItems[1].textContent.indexOf("Department · Accounting") >= 0 &&
    chainItems[1].textContent.indexOf("superseded") >= 0 &&
    chainItems[2].textContent.indexOf("User · @alice") >= 0 &&
    chainItems[2].textContent.indexOf("Winner") >= 0,
    "the chain must order scopes, label non-winners superseded and mark the winner");
  assert(chainItems[2].className.indexOf("is-winner") >= 0,
    "the winning chain item must carry the winner style");
  assert(multiText.indexOf("dept-accounting") < 0 && multiText.indexOf("user-alice") < 0,
    "scope identifiers must not be shown as human labels");
  assert(multiText.indexOf("overrides the Department · Accounting assignment") >= 0,
    "the preview must name the less-specific assignment that was overridden");
  assert(multiText.indexOf("no values are combined") >= 0,
    "the preview must state honestly that settings are not merged field by field");
  const multiInput = collect(preview).find(
    (element) => String(element.className).split(" ").indexOf("effective-block") >= 0 &&
      element.getAttribute("data-stage") === "input"
  );
  assert(multiInput && multiInput.textContent.indexOf("Checks off") >= 0,
    "a disabled channel must show an explicit off state");
  assert(collect(multiInput).some(
    (element) => String(element.className).split(" ").indexOf("is-disabled") >= 0
  ), "an off channel must use the disabled state chip");
}

async function scenarioAlertProfileFallbackAndAcknowledgement() {
  const app = createApp();
  await start(app);
  const adminProfile = {
    user: { ...ALICE_USER, id: "user-admin", username: "admin", full_name: "Ada Admin", role: "admin" },
    department: { id: "dept-accounting", name: "Accounting" },
    review_scope: null,
    review_department_ids: [],
    review_grants: [],
  };
  await signIn(app, adminProfile);
  app.lastMatching("/workspace/api/conversations?limit=25").respond({ items: [], next: null }, 200);
  await settle();
  const oldestUnreadAt = 1700000200;
  await settleSummarySurfaces(app, {
    total: 12,
    unread: 3,
    acknowledged: 9,
    input: 8,
    output: 4,
    oldest_unread_at: oldestUnreadAt,
  });
  assert(app.elementFor("alerts-bell").getAttribute("aria-label").indexOf("3 unread") >= 0,
    "the bell must report the summary unread count");
  assert(app.elementFor("alert-summary").textContent.indexOf("12 total") >= 0,
    "the summary must report the total alert count");
  assert(app.elementFor("alert-summary").textContent.indexOf("3 unread") >= 0,
    "the summary must report the unread count");
  assert(app.elementFor("alert-summary").textContent.indexOf("8Input alerts") >= 0,
    "the summary must report the input-stage count");
  assert(app.elementFor("alert-summary").textContent.indexOf("4Output alerts") >= 0,
    "the summary must report the output-stage count");
  const oldestCell = app.elementFor("alert-summary").children.find((cell) => {
    const label = findByClass(cell, "alert-summary-label");
    return label && label.textContent.indexOf("Oldest unread") === 0;
  });
  assert(oldestCell, "the summary must keep an oldest-unread cell");
  const oldestValue = findByClass(oldestCell, "alert-summary-value").textContent;
  assert(oldestValue && oldestValue !== "None" && oldestValue !== "Not reported",
    "a reported oldest unread time must render its date");
  assert(findByClass(oldestCell, "alert-summary-label").textContent.indexOf("ago") > 0,
    "the oldest-unread label must report the age");


  const alertId = "alert:one";
  const conversationId = "conv-secret-alert";
  const fullDigest = "sha256:9f2c-full-control-digest";
  const alertItem = {
    id: alertId,
    request_id: "req-alert-1",
    user_id: "user-alice",
    username: "alice",
    full_name: "Alice Tan",
    department_id: "dept-accounting",
    department_name: "Accounting",
    conversation_id: conversationId,
    message_id: "msg-alert-1",
    stage: "input",
    reason_code: "PROMPT_SECRET",
    reason_text: "Prompt contained a secret.",
    control_revision: "profile:unloaded-profile:7",
    control_digest: fullDigest,
    control_sources: [
      {
        scope_type: "department",
        scope_id: "dept-accounting",
        profile_id: "profile-not-loaded",
        revision: 7,
      },
    ],
    created_at: 1700000300,
    read: false,
    read_at: null,
    acknowledged: false,
    acknowledged_at: null,
  };
  const userScopeAlert = {
    ...alertItem,
    id: "alert:user-scope",
    request_id: "req-alert-2",
    stage: "output",
    control_revision: "profile:unloaded-profile:1",
    control_digest: "sha256:user-full-control-digest",
    control_sources: [
      {
        scope_type: "user",
        scope_id: "user-alice",
        profile_id: "profile-not-loaded",
        revision: 1,
      },
    ],
  };
  const workspaceScopeAlert = {
    ...alertItem,
    id: "alert:workspace-scope",
    request_id: "req-alert-3",
    control_revision: "profile:unloaded-profile:1",
    control_digest: "sha256:workspace-full-control-digest",
    control_sources: [
      {
        scope_type: "workspace",
        scope_id: "workspace-main",
        profile_id: "profile-not-loaded",
        revision: 1,
      },
    ],
  };
  const defaultPolicyAlert = {
    ...alertItem,
    id: "alert:default-policy",
    request_id: "req-alert-4",
    control_revision: "",
    control_digest: "",
    control_sources: [],
  };
  // Ten loaded rows plus the scoped alerts above: the list must render every
  // row it received rather than truncating at the old page size.
  const extraAlerts = [];
  for (let i = 0; i < 9; i += 1) {
    extraAlerts.push({
      ...alertItem,
      id: "alert:extra-" + i,
      request_id: "req-extra-" + i,
      stage: i % 2 === 0 ? "output" : "input",
    });
  }
  const allAlerts = [
    alertItem, userScopeAlert, workspaceScopeAlert, defaultPolicyAlert, ...extraAlerts
  ];

  app.elementFor("alerts-bell").dispatch("click");
  await settle();
  const departments = app.lastMatching("/workspace/api/admin/departments?limit=25");
  assert(departments, "opening the bell must load the department filter options");
  const alerts = app.lastMatching("/workspace/api/admin/alerts?limit=50");
  assert(alerts, "opening the bell must request the alert list");
  assert(!app.lastMatching("/workspace/api/admin/users?limit=25"),
    "the user filter list must wait for the department list");
  assert(alerts.options.credentials === "same-origin", "alert reads must use cookie credentials");
  assert(alerts.options.headers.Authorization === undefined, "alert reads must not use bearer auth");
  assert(alerts.options.headers["X-Workspace-User"] === "user-admin",
    "alert reads must name the current profile");
  // The alert list is answered before either filter list, so the concise
  // label must not depend on department or user lookups completing.
  alerts.respond(
    { items: allAlerts, next: null },
    200
  );
  await settle();

  function alertRow(id) {
    return app.elementFor("alert-list").children.find(
      (child) => child.getAttribute("data-alert") === id
    );
  }

  function conciseProfileText(row) {
    const cell = row.children[4];
    const details = cell.children.find((child) => child.tagName === "DETAILS");
    assert(details, "alert profile must expose technical details");
    return cell.textContent.replace(details.textContent, "");
  }

  const rendered = alertRow(alertId);
  assert(rendered, "a valid input alert must render without a ReferenceError");
  const rowText = rendered.textContent;
  assert(rowText.indexOf("Prompt contained a secret.") >= 0, "alert reason missing");
  assert(rowText.indexOf("Reference req-alert-1") >= 0, "alert request reference missing");
  assert(rowText.indexOf("Unread") >= 0 && rowText.indexOf("Not acknowledged") >= 0,
    "opening the bell must leave the alert unread and unacknowledged");
  assert(rowText.indexOf("Department · Accounting · revision 7") >= 0,
    "an unloaded control profile must fall back to concise scope and revision");
  const profileCell = rendered.children[4];
  const details = profileCell.children.find((child) => child.tagName === "DETAILS");
  assert(details, "alert profile must expose technical details");
  const referenceText = collect(profileCell).find(
    (element) => String(element.className).indexOf("cell-truncate") >= 0
  );
  assert(referenceText && referenceText.getAttribute("title") === "Reference req-alert-1",
    "the full request reference must stay available as a title");
  assert(rendered.children[5].getAttribute("data-label") === "Actions",
    "the alert action group must stay associated with the alert row");
  const profileSummary = conciseProfileText(rendered);
  assert(profileSummary.indexOf("Department · Accounting · revision 7") >= 0,
    "the concise profile summary must carry scope and revision");
  assert(details.textContent.indexOf(fullDigest) >= 0,
    "technical details must keep the full control digest");
  assert(details.textContent.indexOf("profile:unloaded-profile:7") >= 0,
    "technical details must keep the full control revision");
  assert(profileSummary.indexOf(fullDigest) < 0,
    "the full control digest must live only in technical details");
  assert(profileSummary.indexOf(alertItem.control_revision) < 0,
    "the full control revision must live only in technical details");
  assert(conciseProfileText(alertRow(userScopeAlert.id)).indexOf(
    "User · Alice Tan · revision 1") >= 0,
    "a user-scope alert must use the alert's own name, not an unloaded filter lookup");
  assert(conciseProfileText(alertRow(workspaceScopeAlert.id)).indexOf(
    "Workspace · revision 1") >= 0,
    "a workspace-scope alert must use the concise workspace label");
  assert(findButton(rendered, "Mark read").disabled === false,
    "opening the bell must not disable the manual read action");
  assert(
    app.callsMatching("/workspace/api/admin/alerts/").filter(
      (call) => call.options.method === "POST"
    ).length === 0,
    "opening the bell must not mark any alert read"
  );

  const loadedRows = app.elementFor("alert-list").children.filter(
    (child) => child.getAttribute("data-alert")
  );
  assert(loadedRows.length === allAlerts.length,
    "the alert list must render every loaded row, including ten or more alerts");
  assert(loadedRows[loadedRows.length - 1].getAttribute("data-alert") ===
    extraAlerts[extraAlerts.length - 1].id,
    "the alert list must render the final row of a long page");

  const inputBadge = findByClass(rendered, "alert-stage-badge");
  assert(inputBadge && inputBadge.textContent === "Input",
    "an input alert must carry an Input stage badge");
  assert(String(inputBadge.className).indexOf("is-output") < 0,
    "an input alert must not carry the output badge style");
  const outputRow = alertRow(userScopeAlert.id);
  const outputBadge = findByClass(outputRow, "alert-stage-badge");
  assert(outputBadge && outputBadge.textContent === "Output",
    "an output alert must carry an Output stage badge");
  assert(String(outputBadge.className).indexOf("is-output") >= 0,
    "an output alert must carry the output badge style");

  const copyReference = findButton(rendered, "Copy");
  assert(copyReference &&
    copyReference.getAttribute("aria-label") === "Copy reference req-alert-1",
    "the reference copy action must name the full request reference");
  assert(copyReference.title === "Copy reference",
    "the reference copy action must explain itself on hover");

  const defaultRow = alertRow(defaultPolicyAlert.id);
  assert(defaultRow, "an alert with no assignment lineage must still render");
  assert(conciseProfileText(defaultRow).indexOf("Default policy") === 0,
    "an alert with no assignment lineage must name the built-in default policy");
  const defaultDetails = defaultRow.children[4].children.find(
    (child) => child.tagName === "DETAILS"
  );
  assert(defaultDetails.textContent.indexOf("Policy revision: unavailable") >= 0,
    "the default policy must not invent a revision");

  departments.respond(
    {
      items: [{ id: "dept-accounting", name: "Accounting", created_at: 1700000000 }],
      next: null,
    },
    200
  );
  await settle();

  const users = app.lastMatching("/workspace/api/admin/users?limit=25");
  assert(users, "the alert user filter must load after the department list");
  users.respond(
    {
      items: [
        { id: "user-alice", username: "alice", full_name: "Alice Tan", department_id: "dept-accounting", role: "employee", disabled: false, created_at: 1700000001 },
      ],
      next: null,
    },
    200
  );
  await settle();

  findButton(rendered, "Acknowledge").dispatch("click");
  const ackPath = "/workspace/api/admin/alerts/" + encodeURIComponent(alertId) + "/ack";
  const ack = app.lastMatching(ackPath);
  assert(ack, "Acknowledge must POST to the encoded alert id");
  assert(ack.options.method === "POST", "Acknowledge must use POST");
  assert(ack.options.body === "{}", "Acknowledge must send an empty JSON object");
  assert(ack.options.headers["Content-Type"] === "application/json",
    "Acknowledge must declare a JSON Content-Type");
  assert(ack.options.credentials === "same-origin", "Acknowledge credentials changed");
  assert(ack.options.headers["X-Workspace-User"] === "user-admin",
    "Acknowledge must name the current profile");
  assert(ack.options.headers.Authorization === undefined,
    "Acknowledge must not use bearer auth");
  ack.respond(
    {
      alert_id: alertId,
      read: true,
      read_at: 1700000400,
      acknowledged: true,
      acknowledged_at: 1700000400,
    },
    200
  );
  await settle();

  const summaryRefresh = app.pendingCallsMatching("/workspace/api/admin/alerts/summary").pop();
  assert(summaryRefresh, "Acknowledge must refresh the alert summary");
  summaryRefresh.respond({ total: 1, unread: 0, acknowledged: 1 }, 200);
  await settle();
  const listRefresh = app.pendingCallsMatching("/workspace/api/admin/alerts?limit=50").pop();
  assert(listRefresh, "Acknowledge must refresh the alert list");
  listRefresh.respond(
    {
      items: [
        {
          ...alertItem,
          read: true,
          read_at: 1700000400,
          acknowledged: true,
          acknowledged_at: 1700000400,
        },
      ],
      next: null,
    },
    200
  );
  await settle();

  assert(app.elementFor("alert-summary").textContent.indexOf("0 unread") >= 0,
    "acknowledging must decrease the unread alert count");
  assert(app.elementFor("alerts-bell").getAttribute("aria-label").indexOf("0 unread") >= 0,
    "the bell must report the decreased unread count");
  const acknowledged = alertRow(alertId);
  assert(acknowledged, "the acknowledged alert must stay rendered after refresh");
  assert(acknowledged.textContent.indexOf("Acknowledged") >= 0,
    "the acknowledged state must render");
  assert(!findButton(acknowledged, "Acknowledge"),
    "an acknowledged alert must not render an inapplicable Acknowledge action");
  assert(!findButton(acknowledged, "Mark read"),
    "a read alert must not render an inapplicable Mark read action");
  assert(findButton(acknowledged, "View conversation"),
    "an acknowledged alert must keep the conversation action");
  assert(app.elementFor("alert-state").textContent.indexOf("Alert acknowledged.") >= 0,
    "acknowledgement success must be reported");

  const reviewCallsBefore = app.callsMatching("/workspace/api/review").length;
  const conversationCallsBefore = app.callsMatching(conversationId).length;
  findButton(acknowledged, "View conversation").dispatch("click");
  await settle();
  assert(app.elementFor("alert-detail").hidden === false,
    "View conversation must show the explicit denial panel");
  const denial = app.elementFor("alert-detail").textContent;
  assert(denial.indexOf("No review permission") >= 0,
    "an admin without review scope must see an explicit denial");
  assert(denial.indexOf(conversationId.slice(0, 8)) >= 0,
    "the denial must name the alert's conversation");
  assert(app.elementFor("alert-state").textContent.indexOf("No review permission") >= 0,
    "the denial must be reported in the alert status");
  assert(app.callsMatching("/workspace/api/review").length === reviewCallsBefore,
    "the denial must not request review content");
  assert(app.callsMatching(conversationId).length === conversationCallsBefore,
    "the denial must not request conversation content");

  app.elementFor("alert-stage").value = "output";
  app.elementFor("alert-unread").value = "false";
  app.elementFor("alert-ack").value = "false";
  app.elementFor("alert-stage").dispatch("change");
  await settle();
  const filtered = app.lastMatching("/workspace/api/admin/alerts?limit=50");
  assert(filtered &&
    filtered.url ===
      "/workspace/api/admin/alerts?limit=50&stage=output&unread=false&acknowledged=false",
    "the stage and state filters must be sent as encoded query parameters");
  filtered.respond({ items: [], next: null }, 200);
  await settle();
  assert(app.elementFor("alert-state").textContent.indexOf(
    "No block alerts match these filters") >= 0,
    "an empty filtered list must say that no alerts matched rather than that none exist");
}

async function scenarioMarkAllAlertsRead() {
  const app = createApp();
  await start(app);
  const adminProfile = {
    user: { ...ALICE_USER, id: "user-admin", username: "admin", full_name: "Ada Admin", role: "admin" },
    department: { id: "dept-accounting", name: "Accounting" },
    review_scope: null,
    review_department_ids: [],
    review_grants: [],
  };
  await signIn(app, adminProfile);
  app.lastMatching("/workspace/api/conversations?limit=25").respond({ items: [], next: null }, 200);
  await settle();
  await settleSummarySurfaces(app, {
    total: 4,
    unread: 2,
    acknowledged: 2,
    input: 3,
    output: 1,
  });

  const markAll = app.elementFor("alert-mark-all");
  assert(markAll.hidden === false,
    "an administrator with unread alerts must see Mark all read");
  assert(markAll.disabled === false,
    "Mark all read must be enabled with unread alerts and no request in flight");
  assert(markAll.getAttribute("aria-label") === "Mark all alerts read",
    "the bulk action must have an accessible label");

  // Open the alert panel, then select filters that the refresh after a
  // successful bulk action must preserve.
  app.elementFor("alerts-bell").dispatch("click");
  await settle();
  const departments = app.lastMatching("/workspace/api/admin/departments?limit=25");
  assert(departments, "opening the alerts panel must load filter options");
  departments.respond(
    {
      items: [{ id: "dept-accounting", name: "Accounting", created_at: 1700000000 }],
      next: null,
    },
    200
  );
  await settle();
  const users = app.lastMatching("/workspace/api/admin/users?limit=25");
  assert(users, "the alert user filter must load after departments");
  users.respond(
    {
      items: [
        { id: "user-alice", username: "alice", full_name: "Alice Tan", department_id: "dept-accounting", role: "employee", disabled: false, created_at: 1700000001 },
      ],
      next: null,
    },
    200
  );
  const initialList = app.lastMatching("/workspace/api/admin/alerts?limit=50");
  assert(initialList, "opening the alerts panel must load the list");
  initialList.respond({ items: [], next: null }, 200);
  await settle();

  app.elementFor("alert-stage").value = "output";
  app.elementFor("alert-unread").value = "true";
  app.elementFor("alert-stage").dispatch("change");
  await settle();
  const filtered = app.lastMatching("/workspace/api/admin/alerts?limit=50");
  assert(filtered &&
    filtered.url === "/workspace/api/admin/alerts?limit=50&stage=output&unread=true",
    "the fixture must be reading a filtered alert list");
  filtered.respond({ items: [], next: null }, 200);
  await settle();

  markAll.dispatch("click");
  const failed = app.lastMatching("/workspace/api/admin/alerts/read-all");
  assert(failed, "Mark all read must POST to the read-all endpoint");
  assert(failed.options.method === "POST", "Mark all read must use POST");
  assert(failed.options.body === "{}", "Mark all read must send an empty JSON body");
  assert(failed.options.headers["Content-Type"] === "application/json",
    "Mark all read must declare a JSON Content-Type");
  assert(failed.options.credentials === "same-origin",
    "Mark all read must use same-origin cookie credentials");
  assert(failed.options.headers["X-Workspace-User"] === "user-admin",
    "Mark all read must name the current profile");
  assert(failed.options.headers.Authorization === undefined,
    "Mark all read must not use bearer auth");
  assert(markAll.disabled === true && markAll.hidden === false,
    "the bulk action must stay visible but disabled while the request is in flight");
  failed.respond(
    { error: { code: "UNAVAILABLE", message: "The workspace is busy." } },
    503
  );
  await settle();
  assert(markAll.disabled === false && markAll.hidden === false,
    "a failed bulk action must re-enable the control for a retry");
  assert(app.elementFor("alert-state").textContent.indexOf("The workspace is busy.") >= 0,
    "a failed bulk action must show the server message");
  assert(app.elementFor("alert-state").getAttribute("data-kind") === "error",
    "a failed bulk action must be reported as an error");
  assert(app.callsMatching("/workspace/api/admin/alerts/read-all").length === 1,
    "a failed bulk action must not be repeated automatically");

  markAll.dispatch("click");
  const readAll = app.lastMatching("/workspace/api/admin/alerts/read-all");
  assert(readAll && readAll !== failed, "the retry must issue a new read-all request");
  readAll.respond({ status: "read", marked_read: 2, total: 4 }, 200);
  await settle();

  const summaryRefresh = app.pendingCallsMatching("/workspace/api/admin/alerts/summary").pop();
  assert(summaryRefresh, "a successful bulk action must refresh the summary");
  const listRefresh = app.pendingCallsMatching("/workspace/api/admin/alerts?limit=50").pop();
  assert(listRefresh, "a successful bulk action must refresh the filtered list");
  assert(
    listRefresh.url === "/workspace/api/admin/alerts?limit=50&stage=output&unread=true",
    "the post-read refresh must keep the selected filters"
  );
  summaryRefresh.respond(
    { total: 4, unread: 0, acknowledged: 4, input: 3, output: 1 },
    200
  );
  listRefresh.respond({ items: [], next: null }, 200);
  await settle();

  assert(app.elementFor("alert-summary").textContent.indexOf("0 unread") >= 0,
    "the refreshed summary must report zero unread");
  assert(app.elementFor("alert-state").textContent.indexOf("Marked 2 alerts read.") >= 0,
    "a successful bulk action must report how many alerts were marked");
  assert(app.elementFor("alert-state").getAttribute("data-kind") === "ok",
    "a successful bulk action must be reported as success");
  assert(markAll.hidden === true && markAll.disabled === false,
    "zero unread must hide the bulk action after the refresh");
  assert(app.elementFor("alerts-bell").getAttribute("aria-label").indexOf("0 unread") >= 0,
    "the bell must reflect the refreshed unread count");

  // An employee never receives the administrator bulk action or its endpoint.
  const employeeApp = createApp();
  await start(employeeApp);
  await signIn(employeeApp);
  employeeApp.lastMatching("/workspace/api/conversations?limit=25").respond(
    { items: [], next: null },
    200
  );
  await settle();
  const employeeMarkAll = employeeApp.elementFor("alert-mark-all");
  assert(employeeMarkAll.hidden === true,
    "an employee must never be shown the administrator bulk action");
  employeeMarkAll.dispatch("click");
  await settle();
  assert(employeeApp.callsMatching("/workspace/api/admin/alerts/read-all").length === 0,
    "an employee must not be able to post the bulk read action");
  assert(employeeApp.callsMatching("/workspace/api/admin").length === 0,
    "an employee must not fetch any administrator endpoint");
}

async function scenarioOwnNavigationFromAdmin() {
  const app = createApp();
  await start(app);
  const adminProfile = {
    user: { ...ALICE_USER, id: "user-admin", username: "admin", full_name: "Ada Admin", role: "admin" },
    department: { id: "dept-accounting", name: "Accounting" },
    review_scope: null,
    review_department_ids: [],
    review_grants: [],
  };
  await signIn(app, adminProfile);
  app.lastMatching("/workspace/api/conversations?limit=25").respond(
    {
      items: [
        { id: "conv-own-admin", created_at: 1700000001, updated_at: 1700000002 },
        { id: "conv-other-admin", created_at: 1700000003, updated_at: 1700000004 },
      ],
      next: null,
    },
    200
  );
  await settle();

  app.elementFor("tab-admin").dispatch("click");
  await settle();
  assert(app.elementFor("admin-panel").hidden === false, "admin view must open for an admin");
  app.elementFor("sidebar-toggle").dispatch("click");
  app.elementFor("new-chat").dispatch("click");
  assert(app.elementFor("chat-panel").hidden === false && app.elementFor("admin-panel").hidden === true,
    "New chat from Admin must switch to Chat before the create answer");
  assert(app.elementFor("app").getAttribute("data-nav") === "closed",
    "New chat from Admin must close the mobile sidebar");
  const create = app.callsMatching("/workspace/api/conversations").filter(
    (call) => call.options.method === "POST"
  ).pop();
  assert(create, "New chat from Admin did not POST");
  create.respond({ id: "conv-new-admin", created_at: 1700000009 }, 201);
  await settle();
  app.lastMatching("/workspace/api/conversations?limit=25").respond(
    {
      items: [
        { id: "conv-new-admin", created_at: 1700000009, updated_at: 1700000009 },
        { id: "conv-own-admin", created_at: 1700000001, updated_at: 1700000002 },
        { id: "conv-other-admin", created_at: 1700000003, updated_at: 1700000004 },
      ],
      next: null,
    },
    200
  );
  await settle();
  app.lastMatching("/workspace/api/conversations/conv-new-admin").respond(
    { id: "conv-new-admin", created_at: 1700000009, messages: [] },
    200
  );
  await settle();
  assert(app.elementFor("chat-panel").hidden === false && app.elementFor("admin-panel").hidden === true,
    "created conversation from Admin must stay in Chat");
  assert(app.elementFor("composer").focused >= 1, "opening the created conversation must focus its composer");

  app.elementFor("tab-admin").dispatch("click");
  await settle();
  assert(app.elementFor("admin-panel").hidden === false, "admin view must reopen");
  const own = app.elementFor("conversation-list").children.find(
    (child) => child.getAttribute("data-conversation") === "conv-own-admin"
  );
  assert(own, "own conversation missing from the sidebar");
  own.dispatch("click");
  assert(app.elementFor("chat-panel").hidden === false && app.elementFor("admin-panel").hidden === true,
    "selecting an own conversation must switch from Admin to Chat");
  const ownDetail = app.lastMatching("/workspace/api/conversations/conv-own-admin");
  assert(ownDetail, "own conversation detail request missing from Admin");
  ownDetail.respond(
    {
      id: "conv-own-admin",
      created_at: 1700000001,
      messages: [{ id: "a1", role: "assistant", outcome: "allowed", text: "Admin own answer", created_at: 1700000002 }],
    },
    200
  );
  await settle();
  assert(app.elementFor("messages").textContent.indexOf("Admin own answer") >= 0,
    "own conversation did not render after leaving Admin");

  // A failed selection still switches to Chat so its meaningful error is not
  // hidden behind the Admin panel.
  app.elementFor("tab-admin").dispatch("click");
  await settle();
  const denied = app.elementFor("conversation-list").children.find(
    (child) => child.getAttribute("data-conversation") === "conv-other-admin"
  );
  assert(denied, "second own conversation missing from the sidebar");
  denied.dispatch("click");
  assert(app.elementFor("chat-panel").hidden === false && app.elementFor("admin-panel").hidden === true,
    "a failed own selection must still leave Admin");
  app.lastMatching("/workspace/api/conversations/conv-other-admin").respond(
    { error: { code: "FORBIDDEN", message: "Permission denied." } },
    403
  );
  await settle();
  assert(app.elementFor("chat-status").textContent.indexOf("permission") >= 0,
    "own-conversation denial must stay visible in Chat");
}

async function scenarioConversationListRetryAndPreservation() {
  const app = createApp();
  await start(app);
  await signIn(app);

  const first = app.lastMatching("/workspace/api/conversations?limit=25");
  assert(first && !first.settled, "initial conversation list request missing");
  first.respond(
    { error: { code: "UNAVAILABLE", message: "Required workspace control is unavailable." } },
    503
  );
  await settle();
  assert(app.elementFor("list-retry").hidden === true,
    "bounded retries must finish before the retry control appears");
  assert(app.elementFor("list-state").getAttribute("data-kind") === "warning",
    "a retrying list must be reported as transient");
  assert(app.elementFor("list-state").textContent.indexOf("No saved conversations") < 0,
    "a transient failure must not look like empty history");

  app.fireAllTimers();
  await settle();
  const second = app.lastMatching("/workspace/api/conversations?limit=25");
  assert(second && second !== first && !second.settled, "bounded list retry missing");
  second.respond({ error: { code: "UNAVAILABLE", message: "Busy." } }, 503);
  await settle();
  app.fireAllTimers();
  await settle();
  const third = app.lastMatching("/workspace/api/conversations?limit=25");
  assert(third && third !== second && !third.settled, "second bounded list retry missing");
  third.respond({ error: { code: "UNAVAILABLE", message: "Busy." } }, 503);
  await settle();

  assert(app.elementFor("list-retry").hidden === false,
    "exhausted list retries must offer an explicit retry");
  assert(app.elementFor("list-retry").textContent.trim() === "Retry conversations",
    "the retry control must be labelled for assistive technology");
  assert(app.elementFor("list-state").textContent.indexOf("Saved conversations may still exist") >= 0,
    "exhausted retries must explain that history may still exist");
  assert(app.callsMatching("/workspace/api/conversations?limit=25").length === 3,
    "list retries must be bounded");

  app.elementFor("list-retry").dispatch("click");
  const recovered = app.lastMatching("/workspace/api/conversations?limit=25");
  assert(recovered && recovered !== third && !recovered.settled,
    "Retry conversations must issue a fresh safe read");
  recovered.respond(
    {
      items: [{ id: "conv-a", created_at: 1700000001, updated_at: 1700000002 }],
      next: "page-2",
    },
    200
  );
  await settle();
  assert(app.elementFor("list-retry").hidden === true, "a successful retry must hide the control");
  assert(app.elementFor("conversation-list").children.length === 1,
    "a successful retry must render the recovered list once");
  assert(app.elementFor("conversation-list").children[0].focused >= 1,
    "a successful retry must restore focus to the recovered list");

  app.elementFor("conversation-list").children[0].dispatch("click");
  app.lastMatching("/workspace/api/conversations/conv-a").respond(
    {
      id: "conv-a",
      created_at: 1700000001,
      messages: [{ id: "a1", role: "user", outcome: "allowed", text: "Preserved transcript", created_at: 1700000002 }],
    },
    200
  );
  await settle();
  app.elementFor("composer").value = "draft survives a list failure";

  app.elementFor("load-more").dispatch("click");
  const pageFirst = app.lastMatching("/workspace/api/conversations?limit=25&after=page-2");
  assert(pageFirst && !pageFirst.settled, "load-more request missing");
  pageFirst.respond({ error: { code: "UNAVAILABLE", message: "Busy." } }, 503);
  await settle();
  app.fireAllTimers();
  await settle();
  const pageSecond = app.lastMatching("/workspace/api/conversations?limit=25&after=page-2");
  assert(pageSecond && pageSecond !== pageFirst && !pageSecond.settled,
    "load-more retry missing");
  pageSecond.respond({ error: { code: "UNAVAILABLE", message: "Busy." } }, 503);
  await settle();
  app.fireAllTimers();
  await settle();
  const pageThird = app.lastMatching("/workspace/api/conversations?limit=25&after=page-2");
  assert(pageThird && pageThird !== pageSecond && !pageThird.settled,
    "second load-more retry missing");
  pageThird.respond({ error: { code: "UNAVAILABLE", message: "Busy." } }, 503);
  await settle();
  assert(app.elementFor("list-retry").hidden === false,
    "a failed page must offer the explicit retry");
  assert(app.elementFor("composer").value === "draft survives a list failure",
    "a failed list refresh must not clear the current draft");
  assert(
    app.elementFor("messages").textContent.indexOf("Preserved transcript") >= 0,
    "a failed list refresh must not clear the current conversation"
  );

  app.elementFor("list-retry").dispatch("click");
  const retryPage = app.lastMatching("/workspace/api/conversations?limit=25");
  assert(retryPage && retryPage !== pageThird && !retryPage.settled,
    "list retry after a failed page missing");
  retryPage.respond(
    {
      items: [{ id: "conv-a", created_at: 1700000001, updated_at: 1700000002 }],
      next: null,
    },
    200
  );
  await settle();
  assert(app.elementFor("composer").value === "draft survives a list failure",
    "a successful list retry must preserve the draft");
  assert(app.elementFor("chat-title").textContent === "Conversation",
    "a successful list retry must preserve the current conversation");
  assert(app.elementFor("conversation-list").children.length === 1,
    "a retried reset must not duplicate rows");

  const deniedApp = createApp();
  await start(deniedApp);
  await signIn(deniedApp);
  deniedApp.lastMatching("/workspace/api/conversations?limit=25").respond(
    { error: { code: "FORBIDDEN", message: "Permission denied." } },
    403
  );
  await settle();
  assert(deniedApp.callsMatching("/workspace/api/conversations?limit=25").length === 1,
    "403 must not be retried");
  assert(deniedApp.elementFor("list-retry").hidden === true,
    "permission denial must not offer a blind retry");
  assert(deniedApp.elementFor("list-state").getAttribute("data-kind") === "denied",
    "403 must be reported as permission denial");

  const malformedApp = createApp();
  await start(malformedApp);
  await signIn(malformedApp);
  malformedApp.lastMatching("/workspace/api/conversations?limit=25").respond(
    { items: "not-an-array" },
    200
  );
  await settle();
  assert(malformedApp.callsMatching("/workspace/api/conversations?limit=25").length === 1,
    "malformed list data must not be retried");
  assert(malformedApp.elementFor("list-state").getAttribute("data-kind") === "error",
    "malformed list data must be reported honestly");
  assert(malformedApp.elementFor("list-state").textContent.indexOf("No saved conversations") < 0,
    "malformed list data must not look like empty history");
}

async function scenarioListAttemptCannotOutliveIdentityChange() {
  const app = createApp();
  await start(app);
  await signIn(app);
  const oldList = app.lastMatching("/workspace/api/conversations?limit=25");
  assert(oldList && !oldList.settled, "initial list request missing");
  oldList.respond({ error: { code: "UNAVAILABLE", message: "Busy." } }, 503);
  await settle();
  const before = app.callsMatching("/workspace/api/conversations?limit=25").length;

  app.broadcast({ type: "workspace-auth-changed" });
  await settle();
  const check = app.lastMatching("/workspace/api/me");
  assert(check && !check.settled, "peer auth change must revalidate the session");
  check.respond(BOB_PROFILE, 200);
  await settle();
  assert(app.elementFor("auth-view").hidden === false,
    "a changed cookie identity must not keep the previous workspace visible");
  assert(app.elementFor("identity-name").textContent === "",
    "the previous identity must be cleared");
  assert(app.elementFor("list-retry").hidden === true,
    "the previous account's list retry must be cleared");

  // The old bounded retry timer must not launch a list request with the old
  // attempt (or the new account's cookie) after the identity changed.
  app.fireAllTimers();
  await settle();
  assert(app.callsMatching("/workspace/api/conversations?limit=25").length === before,
    "a stale list retry must not outlive the identity change");

  await signIn(app, BOB_PROFILE, "bob");
  const bobList = app.lastMatching("/workspace/api/conversations?limit=25");
  assert(bobList && !bobList.settled, "new-account list request missing");
  assert(bobList.options.headers["X-Workspace-User"] === "user-bob",
    "new-account list must name the new profile");
  bobList.respond(
    {
      items: [{ id: "conv-bob", created_at: 1700000001, updated_at: 1700000002 }],
      next: null,
    },
    200
  );
  await settle();
  assert(app.elementFor("identity-name").textContent === "Bob Lee",
    "the new identity must be shown");
  assert(app.elementFor("conversation-list").textContent.indexOf("conv-bob") >= 0,
    "the new account's history must render");
}

async function scenarioPendingListRefreshKeepsNewChat() {
  const app = createApp();
  await start(app);
  await signIn(app);

  const stale = app.lastMatching("/workspace/api/conversations?limit=25");
  assert(stale && !stale.settled, "initial list request must still be pending");

  // Commit a new chat while the initial reset is in flight.
  app.elementFor("new-chat").dispatch("click");
  const create = app.lastMatching("/workspace/api/conversations");
  assert(create && !create.settled && create.options.method === "POST",
    "new chat request missing");
  create.respond({ id: "conv-new", created_at: 1700000100 }, 201);
  await settle();
  assert(app.callsMatching("/workspace/api/conversations?limit=25").length === 1,
    "a reset requested during a pending reset must coalesce, not overlap");

  // The old snapshot predates the new conversation.
  stale.respond(
    {
      items: [{ id: "conv-old", created_at: 1700000001, updated_at: 1700000002 }],
      next: "stale-page-2",
    },
    200
  );
  await settle();
  assert(app.elementFor("conversation-list").children.length === 0,
    "a stale pre-mutation snapshot must not repaint rows");
  assert(app.elementFor("load-more").hidden === true,
    "a stale pre-mutation cursor must not be repainted");

  const fresh = app.lastMatching("/workspace/api/conversations?limit=25");
  assert(fresh && fresh !== stale && !fresh.settled,
    "a mutation during a pending reset must trigger one fresh first-page read");
  assert(fresh.url.indexOf("after=") < 0, "the follow-up refresh must start at page one");
  assert(app.callsMatching("/workspace/api/conversations?limit=25").length === 2,
    "the follow-up refresh must be bounded to one request");

  fresh.respond(
    {
      items: [{ id: "conv-new", created_at: 1700000100, updated_at: 1700000100 }],
      next: null,
    },
    200
  );
  await settle();
  assert(app.elementFor("conversation-list").children.length === 1,
    "the fresh refresh must render the new conversation exactly once");
  assert(
    app.elementFor("conversation-list").children[0].getAttribute("data-conversation") === "conv-new",
    "the fresh refresh must reflect the mutation, not the withheld snapshot"
  );
  assert(app.elementFor("load-more").hidden === true,
    "the stale cursor must not survive the follow-up refresh");
}

async function scenarioInitialRestoreWithholdsSurfaces() {
  const app = createApp();
  await settle();
  assert(app.elementFor("auth-view").hidden === true,
    "the sign-in form must not flash before the initial session check answers");
  assert(app.elementFor("workspace-view").hidden === true,
    "private workspace content must stay hidden during the initial check");
  const me = app.lastMatching("/workspace/api/me");
  assert(me && !me.settled, "initial session check missing");
  me.respond({ error: { code: "UNAUTHORIZED", message: "Authentication required." } }, 401);
  await settle();
  assert(app.elementFor("auth-view").hidden === false,
    "a completed initial check must reveal sign-in");
  assert(app.elementFor("workspace-view").hidden === true,
    "a signed-out initial check must keep private content hidden");
}

async function scenarioDraftSurvivesListNavigation() {
  const app = createApp();
  await start(app);
  await signIn(app);
  app.lastMatching("/workspace/api/conversations?limit=25").respond(
    {
      items: [
        { id: "conv-a", created_at: 1700000001, updated_at: 1700000002 },
        { id: "conv-b", created_at: 1700000003, updated_at: 1700000004 },
      ],
      next: null,
    },
    200
  );
  await settle();
  app.elementFor("conversation-list").children[0].dispatch("click");
  app.lastMatching("/workspace/api/conversations/conv-a").respond(
    { id: "conv-a", created_at: 1700000001, messages: [] },
    200
  );
  await settle();
  app.elementFor("composer").value = "draft in A";

  app.elementFor("conversation-list").children[1].dispatch("click");
  app.lastMatching("/workspace/api/conversations/conv-b").respond(
    { id: "conv-b", created_at: 1700000003, messages: [] },
    200
  );
  await settle();
  app.elementFor("composer").value = "draft in B";

  app.elementFor("conversation-list").children[0].dispatch("click");
  app.lastMatching("/workspace/api/conversations/conv-a").respond(
    { id: "conv-a", created_at: 1700000001, messages: [] },
    200
  );
  await settle();
  assert(app.elementFor("composer").value === "draft in A",
    "returning to A must restore A's in-memory draft");

  app.elementFor("conversation-list").children[1].dispatch("click");
  app.lastMatching("/workspace/api/conversations/conv-b").respond(
    { id: "conv-b", created_at: 1700000003, messages: [] },
    200
  );
  await settle();
  assert(app.elementFor("composer").value === "draft in B",
    "B to A to B navigation must restore B's draft, not clear it");
}

async function scenarioChatEmptyCtaAndBusy() {
  const app = createApp();
  await start(app);
  await signIn(app);
  app.lastMatching("/workspace/api/conversations?limit=25").respond(
    { items: [], next: null },
    200
  );
  await settle();
  assert(app.elementFor("chat-empty").hidden === false,
    "an account with no conversations must show the empty state");
  assert(app.elementFor("chat-empty-title").textContent === "No conversation selected",
    "the empty state must explain that no conversation is selected");
  assert(app.elementFor("empty-cta").hidden === false,
    "the empty state must offer a start control");
  assert(app.elementFor("empty-new-chat").disabled === false,
    "the empty start control must be enabled");

  app.elementFor("empty-new-chat").dispatch("click");
  const create = app.lastMatching("/workspace/api/conversations");
  assert(create && create.options.method === "POST" && !create.settled,
    "the empty CTA must start a new conversation");
  assert(app.elementFor("empty-new-chat").disabled === true &&
    app.elementFor("new-chat").disabled === true,
    "both new-chat controls must pause while the create request is pending");
  assert(app.elementFor("chat-status").getAttribute("data-kind") === "pending",
    "starting a chat must be reported as pending");
  app.elementFor("empty-new-chat").dispatch("click");
  assert(
    app.callsMatching("/workspace/api/conversations").filter(
      (call) => call.options.method === "POST"
    ).length === 1,
    "the empty CTA must not start a second conversation while one is pending"
  );

  create.respond({ id: "conv-new-empty", created_at: 1700000100 }, 201);
  await settle();
  const createdList = app.lastMatching("/workspace/api/conversations?limit=25");
  assert(createdList && !createdList.settled,
    "a created chat must refresh the conversation list before opening");
  assert(app.elementFor("empty-new-chat").disabled === false,
    "the empty start control must recover after the create answer");
  createdList.respond(
    {
      items: [{ id: "conv-new-empty", created_at: 1700000100, updated_at: 1700000100 }],
      next: null,
    },
    200
  );
  await settle();
  const detail = app.lastMatching("/workspace/api/conversations/conv-new-empty");
  assert(detail && !detail.settled, "the created chat detail request missing");
  assert(app.elementFor("messages").getAttribute("aria-busy") === "true",
    "a pending conversation load must mark the transcript busy");
  assert(app.elementFor("chat-empty").hidden === true && app.elementFor("empty-cta").hidden === true,
    "the empty state must stay hidden while the new chat loads");
  assert(app.elementFor("chat-status").getAttribute("data-kind") === "pending",
    "loading the new chat must remain visibly pending");
  detail.respond({ id: "conv-new-empty", created_at: 1700000100, messages: [] }, 200);
  await settle();
  assert(app.elementFor("messages").getAttribute("aria-busy") === null,
    "a settled conversation load must clear aria-busy");
  assert(app.elementFor("chat-empty").hidden === false,
    "an empty new chat must show the empty state");
  assert(app.elementFor("chat-empty-title").textContent === "No messages yet" &&
    app.elementFor("chat-empty-text").textContent === "Send the first prompt below.",
    "an empty new chat must invite the first prompt");
  assert(app.elementFor("empty-cta").hidden === true,
    "the start control must not remain inside an opened empty chat");
  assert(app.elementFor("composer").disabled === false &&
    app.elementFor("delete-conversation").hidden === false,
    "an opened empty chat must enable its composer and delete control");
}

async function scenarioChatGatewayFailureKeepsDraft() {
  const app = createApp();
  await start(app);
  await signIn(app);
  app.lastMatching("/workspace/api/conversations?limit=25").respond(
    {
      items: [{ id: "conv-draft", created_at: 1700000001, updated_at: 1700000002 }],
      next: null,
    },
    200
  );
  await settle();
  app.elementFor("conversation-list").children[0].dispatch("click");
  app.lastMatching("/workspace/api/conversations/conv-draft").respond(
    {
      id: "conv-draft",
      created_at: 1700000001,
      messages: [{ id: "m1", role: "assistant", outcome: "allowed", text: "Previous answer", created_at: 1700000002 }],
    },
    200
  );
  await settle();

  const draft = "keep this draft through the gateway failure";
  const composer = app.elementFor("composer");
  composer.value = draft;
  const keyEvent = composer.dispatch("keydown", { key: "Enter", ctrlKey: true });
  assert(keyEvent.defaultPrevented, "Ctrl+Enter must suppress the textarea default");
  const send = app.lastMatching("/workspace/api/conversations/conv-draft/messages");
  assert(send && send.options.method === "POST", "Ctrl+Enter must send the message");
  assert(JSON.parse(send.options.body).text === draft, "Ctrl+Enter payload mismatch");
  assert(app.elementFor("messages").getAttribute("aria-busy") === "true",
    "a pending turn must mark the transcript busy");
  composer.dispatch("keydown", { key: "Enter" });
  assert(app.callsMatching("/workspace/api/conversations/conv-draft/messages").length === 1,
    "a plain Enter must not submit while a turn is pending");

  send.respond({ error: { code: "UNAVAILABLE", message: "Busy." } }, 503);
  await settle();
  const reload = app.lastMatching("/workspace/api/conversations/conv-draft");
  assert(reload && reload !== send && !reload.settled,
    "a gateway failure must reload the conversation once");
  reload.respond(
    {
      id: "conv-draft",
      created_at: 1700000001,
      messages: [{ id: "m1", role: "assistant", outcome: "allowed", text: "Previous answer", created_at: 1700000002 }],
    },
    200
  );
  await settle();
  assert(app.elementFor("composer").value === draft,
    "a 503 must preserve the unsent draft");
  assert(app.elementFor("chat-status").getAttribute("data-kind") === "warning",
    "an unconfirmed gateway result must be reported as a warning");
  const statusText = app.elementFor("chat-status").textContent;
  assert(statusText.indexOf("Your text has been kept") >= 0 &&
    statusText.indexOf("no automatic retry") >= 0,
    "a 503 must explain the kept draft and the absence of an automatic retry");
  assert(app.elementFor("messages").getAttribute("aria-busy") === null,
    "the turn and its reload must clear aria-busy");
  const recency = app.lastMatching("/workspace/api/conversations?limit=25");
  if (recency && !recency.settled) {
    recency.respond(
      {
        items: [{ id: "conv-draft", created_at: 1700000001, updated_at: 1700000002 }],
        next: null,
      },
      200
    );
    await settle();
  }
  app.fireAllTimers();
  await settle();
  assert(app.callsMatching("/workspace/api/conversations/conv-draft/messages").length === 1,
    "a 503 must never auto-retry the turn write");
}

async function scenarioChatBlockNoticeDeduplicated() {
  const app = createApp();
  await start(app);
  await signIn(app);
  app.lastMatching("/workspace/api/conversations?limit=25").respond(
    {
      items: [{ id: "conv-block", created_at: 1700000001, updated_at: 1700000002 }],
      next: null,
    },
    200
  );
  await settle();
  app.elementFor("conversation-list").children[0].dispatch("click");
  app.lastMatching("/workspace/api/conversations/conv-block").respond(
    {
      id: "conv-block",
      created_at: 1700000001,
      messages: [{ id: "m1", role: "assistant", outcome: "allowed", text: "Ready", created_at: 1700000002 }],
    },
    200
  );
  await settle();

  const prompt = "blocked prompt text";
  const savedBlock = {
    stage: "input",
    reason_code: "INPUT_POLICY_BLOCK",
    title: "Prompt blocked",
    reason: "The prompt contains content disallowed by policy.",
    ref: "block-ref-1",
  };
  app.elementFor("composer").value = prompt;
  app.elementFor("composer-form").dispatch("submit");
  const send = app.lastMatching("/workspace/api/conversations/conv-block/messages");
  send.respond(
    {
      error: {
        code: "FORBIDDEN",
        message: "Prompt blocked",
        block: savedBlock,
        request_id: "block-ref-1",
        turn_request_id: "block-ref-1",
      },
    },
    403
  );
  await settle();
  const reload = app.lastMatching("/workspace/api/conversations/conv-block");
  assert(reload && reload !== send && !reload.settled,
    "a block must reload the saved transcript");
  reload.respond(
    {
      id: "conv-block",
      created_at: 1700000001,
      messages: [
        {
          id: "m2",
          role: "user",
          outcome: "blocked",
          error_code: "POLICY_BLOCK",
          text: prompt,
          created_at: 1700000003,
          block: savedBlock,
        },
      ],
    },
    200
  );
  await settle();
  const messagesText = app.elementFor("messages").textContent;
  assert(messagesText.indexOf("Prompt blocked") >= 0 &&
    messagesText.indexOf("The prompt contains content disallowed by policy.") >= 0,
    "the saved transcript must state the block reason");
  assert(messagesText.indexOf("Reference ID: block-ref-1") >= 0,
    "the saved transcript must state the block reference");
  assert(messagesText.split("block-ref-1").length - 1 === 1,
    "the block reference must be rendered exactly once");
  assert(app.elementFor("chat-block").hidden === true &&
    app.elementFor("chat-block").textContent === "",
    "the global block notice must not duplicate the saved notice");
  assert(app.elementFor("composer").value === "",
    "a known blocked prompt must clear after the saved transcript reloads");
  assert(app.elementFor("chat-status").textContent.indexOf("Prompt blocked") >= 0,
    "the block outcome must remain visible in status");
  const recency = app.lastMatching("/workspace/api/conversations?limit=25");
  if (recency && !recency.settled) {
    recency.respond(
      {
        items: [{ id: "conv-block", created_at: 1700000001, updated_at: 1700000003 }],
        next: null,
      },
      200
    );
    await settle();
  }
}

async function scenarioChatGuardrailDetails() {
  const app = createApp();
  await start(app);
  await signIn(app);
  app.lastMatching("/workspace/api/conversations?limit=25").respond(
    {
      items: [{ id: "conv-guard", created_at: 1700000001, updated_at: 1700000002 }],
      next: null,
    },
    200
  );
  await settle();
  app.elementFor("conversation-list").children[0].dispatch("click");
  app.lastMatching("/workspace/api/conversations/conv-guard").respond(
    { id: "conv-guard", created_at: 1700000001, messages: [] },
    200
  );
  await settle();

  async function reloadWith(messages) {
    await settle();
    app.lastMatching("/workspace/api/conversations/conv-guard").respond(
      { id: "conv-guard", created_at: 1700000001, messages: messages },
      200
    );
    await settle();
    const recency = app.lastMatching("/workspace/api/conversations?limit=25");
    if (recency && !recency.settled) {
      recency.respond(
        {
          items: [{ id: "conv-guard", created_at: 1700000001, updated_at: 1700000003 }],
          next: null,
        },
        200
      );
      await settle();
    }
  }

  app.elementFor("composer").value = "My email is ali@example.com";
  app.elementFor("composer-form").dispatch("submit");
  app.lastMatching("/workspace/api/conversations/conv-guard/messages").respond(
    {
      id: "req-allow",
      conversation_id: "conv-guard",
      role: "assistant",
      content: "Hello",
      context: {},
      guardrail: {
        input_check: "safe",
        output_check: "safe",
        input_pii_masked: true,
        output_pii_masked: false,
        latency_ms: 17786,
      },
    },
    200
  );
  const allowed = [
    { id: "m1", role: "user", outcome: "allowed", request_id: "req-allow",
      text: "My email is ali@example.com", created_at: 1700000002 },
    { id: "m2", role: "assistant", outcome: "allowed", request_id: "req-allow",
      text: "Hello", created_at: 1700000003 },
  ];
  await reloadWith(allowed);
  let shown = app.elementFor("messages").textContent;
  assert(shown.indexOf("Input: Safe") >= 0 && shown.indexOf("Output: Safe") >= 0,
    "an allowed turn must show both guard checks after the transcript reloads");
  assert(shown.indexOf("PII masked in prompt") >= 0,
    "a masked prompt must be stated");
  assert(shown.indexOf("17.8 s") >= 0, "the server latency must be shown in seconds");
  assert(shown.split("Input: Safe").length - 1 === 1,
    "the panel belongs to the assistant message only, once");

  app.elementFor("composer").value = "blocked prompt";
  app.elementFor("composer-form").dispatch("submit");
  app.lastMatching("/workspace/api/conversations/conv-guard/messages").respond(
    {
      error: {
        code: "FORBIDDEN",
        message: "Prompt blocked",
        block: {
          stage: "input",
          reason_code: "INPUT_GUARD_BLOCK",
          title: "Prompt blocked",
          ref: "req-block",
        },
        request_id: "req-block",
        turn_request_id: "req-block",
        guardrail: {
          input_check: "blocked",
          output_check: "not_run",
          input_pii_masked: false,
          output_pii_masked: false,
          latency_ms: 6400,
        },
      },
    },
    403
  );
  await reloadWith(allowed.concat([
    { id: "m3", role: "user", outcome: "blocked", error_code: "POLICY_BLOCK",
      request_id: "req-block", text: "blocked prompt", created_at: 1700000004 },
  ]));
  shown = app.elementFor("messages").textContent;
  assert(shown.indexOf("Input: Blocked") >= 0 && shown.indexOf("Output: Not run") >= 0,
    "a blocked turn must not read as if the output check passed");
  assert(shown.indexOf("Input: Safe") >= 0,
    "the earlier turn keeps its own details after the next reload");

  // A malformed summary is dropped, never shown as a passed check.
  app.elementFor("composer").value = "second";
  app.elementFor("composer-form").dispatch("submit");
  app.lastMatching("/workspace/api/conversations/conv-guard/messages").respond(
    {
      id: "req-bad",
      conversation_id: "conv-guard",
      role: "assistant",
      content: "Fine",
      context: {},
      guardrail: { input_check: "<b>unknown</b>", output_check: "safe",
        input_pii_masked: false, output_pii_masked: false },
    },
    200
  );
  await reloadWith([
    { id: "m4", role: "assistant", outcome: "allowed", request_id: "req-bad",
      text: "Fine", created_at: 1700000005 },
  ]);
  shown = app.elementFor("messages").textContent;
  assert(shown.indexOf("Input:") < 0 && shown.indexOf("unknown") < 0,
    "an unrecognized guardrail summary must not render");
}

async function scenarioChatMobileCloseAndDeletedEmptyState() {
  const app = createApp();
  await start(app);
  await signIn(app);
  app.lastMatching("/workspace/api/conversations?limit=25").respond(
    {
      items: [{ id: "conv-delete", created_at: 1700000001, updated_at: 1700000002 }],
      next: null,
    },
    200
  );
  await settle();
  app.elementFor("conversation-list").children[0].dispatch("click");
  app.lastMatching("/workspace/api/conversations/conv-delete").respond(
    {
      id: "conv-delete",
      created_at: 1700000001,
      messages: [{ id: "m1", role: "assistant", outcome: "allowed", text: "Delete me", created_at: 1700000002 }],
    },
    200
  );
  await settle();

  app.elementFor("sidebar-toggle").dispatch("click");
  assert(app.elementFor("app").getAttribute("data-nav") === "open" &&
    app.elementFor("sidebar-toggle").getAttribute("aria-expanded") === "true",
    "the mobile sidebar toggle must open the navigation");
  app.elementFor("sidebar-close").dispatch("click");
  assert(app.elementFor("app").getAttribute("data-nav") === "closed" &&
    app.elementFor("sidebar-toggle").getAttribute("aria-expanded") === "false",
    "the mobile close control must close the navigation");
  assert(app.elementFor("sidebar-toggle").focused >= 1,
    "closing the mobile navigation must restore focus to its toggle");
  app.elementFor("sidebar-toggle").dispatch("click");
  assert(app.elementFor("app").getAttribute("data-nav") === "open",
    "the sidebar must reopen before the Escape check");
  app.window.dispatch("keydown", { key: "Escape" });
  assert(app.elementFor("app").getAttribute("data-nav") === "closed" &&
    app.elementFor("sidebar-toggle").getAttribute("aria-expanded") === "false",
    "Escape must close the mobile sidebar");

  app.elementFor("delete-conversation").dispatch("click");
  assert(app.elementFor("delete-confirm").hidden === false,
    "delete must open an explicit confirmation");
  app.elementFor("delete-yes").dispatch("click");
  const deletion = app.callsMatching("/workspace/api/conversations/conv-delete").filter(
    (call) => call.options.method === "DELETE"
  ).pop();
  assert(deletion, "confirmed delete did not issue DELETE");
  deletion.respond({ status: "deleted" }, 200);
  await settle();
  const emptyList = app.lastMatching("/workspace/api/conversations?limit=25");
  assert(emptyList && !emptyList.settled,
    "a deleted conversation must refresh the conversation list");
  emptyList.respond({ items: [], next: null }, 200);
  await settle();
  assert(app.elementFor("chat-empty").hidden === false,
    "a deleted conversation must show the empty state");
  assert(app.elementFor("chat-empty-title").textContent === "Conversation deleted",
    "the deleted empty state must confirm the deletion");
  assert(app.elementFor("chat-empty-text").textContent === "Start a new conversation when ready.",
    "the deleted empty state must point at the next safe action");
  assert(app.elementFor("empty-cta").hidden === false,
    "the deleted empty state must offer a new chat");
  assert(app.elementFor("empty-new-chat").focused >= 1,
    "deletion should move focus to the new chat CTA");
  assert(app.elementFor("composer").disabled === true &&
    app.elementFor("composer").value === "",
    "deletion must disable and clear the composer");
  assert(app.elementFor("messages").children.length === 0 &&
    app.elementFor("messages").getAttribute("aria-busy") === null,
    "deletion must clear the transcript and its busy state");
  assert(app.elementFor("delete-conversation").hidden === true,
    "deletion must hide the delete control");
  assert(app.elementFor("chat-status").textContent.indexOf("deleted") >= 0,
    "deletion must be reported in status");
}

async function scenarioRevalidationHidesPrivateState() {
  const app = createApp();
  await start(app);
  await signIn(app);
  app.lastMatching("/workspace/api/conversations?limit=25").respond(
    { items: [{ id: "conv-a", created_at: 1700000001, updated_at: 1700000002 }], next: null },
    200
  );
  await settle();
  app.elementFor("conversation-list").children[0].dispatch("click");
  app.lastMatching("/workspace/api/conversations/conv-a").respond(
    {
      id: "conv-a",
      created_at: 1700000001,
      messages: [{ id: "a1", role: "assistant", outcome: "allowed", text: "private A", created_at: 1700000002 }],
    },
    200
  );
  await settle();
  app.elementFor("composer").value = "draft in A";

  app.window.dispatch("focus");
  const check = app.lastMatching("/workspace/api/me");
  assert(check && !check.settled, "focus revalidation request missing");
  assert(app.elementFor("workspace-view").hidden === true,
    "private surfaces must hide while identity is checked");
  assert(app.elementFor("auth-view").hidden === true,
    "revalidation must not show the sign-in form before the result");
  assert(app.elementFor("app").getAttribute("data-private") === "hidden",
    "the sidebar and identity must be withheld during revalidation");
  assert(app.elementFor("composer").value === "draft in A",
    "same-identity drafts stay in tab memory while hidden");

  check.respond(PROFILE, 200);
  await settle();
  assert(app.elementFor("workspace-view").hidden === false,
    "a confirmed identity must restore the workspace");
  assert(app.elementFor("app").getAttribute("data-private") === null,
    "a confirmed identity must restore the sidebar");
  assert(app.elementFor("composer").value === "draft in A",
    "a confirmed identity must restore its own draft");

  app.window.dispatch("focus");
  const offline = app.lastMatching("/workspace/api/me");
  assert(offline && !offline.settled, "second revalidation request missing");
  offline.reject(new Error("offline"));
  await settle();
  assert(app.elementFor("workspace-view").hidden === true,
    "a failed revalidation must keep private content hidden");
  assert(app.elementFor("auth-view").hidden === true,
    "a failed revalidation must not claim the user is signed out");
  assert(app.elementFor("revalidate-retry").hidden === false,
    "a failed revalidation must offer a retry");
  assert(app.elementFor("global-status").textContent.indexOf("could not be confirmed") >= 0,
    "a failed revalidation must explain the hidden state");

  app.elementFor("revalidate-retry").dispatch("click");
  const retry = app.lastMatching("/workspace/api/me");
  assert(retry && !retry.settled, "retry revalidation request missing");
  retry.respond({
    user: { ...ALICE_USER, id: "user-bob", username: "bob", full_name: "Bob Lee" },
    department: { id: "dept-accounting", name: "Accounting" },
    review_scope: null,
    review_department_ids: [],
    review_grants: [],
  }, 200);
  await settle();
  assert(app.elementFor("workspace-view").hidden === true,
    "a changed cookie identity must not paint the old workspace");
  assert(app.elementFor("auth-view").hidden === false,
    "a changed cookie identity must require sign-in");
  assert(app.elementFor("conversation-list").children.length === 0,
    "a changed cookie identity must clear private lists");
  assert(app.elementFor("composer").value === "",
    "a changed cookie identity must clear drafts");
}

async function scenarioLoginProfile503IsRecoverable() {
  const app = createApp();
  await start(app);
  app.elementFor("username").value = "alice";
  app.elementFor("password").value = "secret-password";
  app.elementFor("login-form").dispatch("submit");
  const loginRequest = app.lastMatching("/workspace/api/login");
  assert(loginRequest, "login request missing");
  loginRequest.respond(loginPayload(), 200);
  await settle();

  // The cookie exists, but nothing private may be shown and no sign-in claim
  // may be made until /me confirms the account.
  assert(app.elementFor("auth-view").hidden === true,
    "sign-in must stay hidden while the cookie profile is unconfirmed");
  assert(app.elementFor("workspace-view").hidden === true,
    "private content must stay hidden while the cookie profile is unconfirmed");
  assert(app.elementFor("app").getAttribute("data-private") === "hidden",
    "the sidebar must stay withheld while the cookie profile is unconfirmed");
  assert(app.elementFor("global-status").textContent.indexOf("Signed in") < 0,
    "a successful password POST must not claim a confirmed session");
  assert(app.elementFor("identity-name").textContent === "",
    "no identity may be painted before /me confirms it");

  const first = app.lastMatching("/workspace/api/me");
  assert(first && !first.settled, "critical profile check missing after login");
  first.respond({ error: { code: "UNAVAILABLE", message: "Busy." } }, 503);
  await settle();
  assert(app.elementFor("workspace-view").hidden === true,
    "a busy profile check must not reveal private content");
  assert(app.elementFor("revalidate-retry").hidden === true,
    "the retries must finish before the recovery control appears");

  app.fireAllTimers();
  await settle();
  const second = app.lastMatching("/workspace/api/me");
  assert(second && second !== first && !second.settled, "bounded profile retry missing");
  second.respond({ error: { code: "UNAVAILABLE", message: "Busy." } }, 503);
  await settle();
  app.fireAllTimers();
  await settle();
  const third = app.lastMatching("/workspace/api/me");
  assert(third && third !== second && !third.settled, "second bounded profile retry missing");
  third.respond({ error: { code: "UNAVAILABLE", message: "Busy." } }, 503);
  await settle();

  assert(app.elementFor("workspace-view").hidden === true,
    "exhausted profile retries must keep private content hidden");
  assert(app.elementFor("auth-view").hidden === true,
    "exhausted profile retries must not claim the user is signed out");
  assert(app.elementFor("revalidate-retry").hidden === false,
    "exhausted profile retries must offer an accessible retry");
  assert(app.elementFor("global-status").getAttribute("data-kind") === "warning",
    "the hidden state must be explained honestly");
  assert(app.elementFor("global-status").textContent.indexOf("could not be confirmed") >= 0,
    "the recovery text must state that the session is unconfirmed");
  assert(app.elementFor("global-status").textContent.indexOf("Signed in") < 0,
    "an unconfirmed session must never be reported as signed in");

  app.elementFor("revalidate-retry").dispatch("click");
  const retry = app.lastMatching("/workspace/api/me");
  assert(retry && !retry.settled && retry !== third, "retry session check request missing");
  retry.respond(PROFILE, 200);
  await settle();
  assert(app.elementFor("workspace-view").hidden === false,
    "a confirmed identity must reveal the workspace");
  assert(app.elementFor("auth-view").hidden === true,
    "a confirmed identity must keep sign-in hidden");
  assert(app.elementFor("identity-name").textContent === "Alice Tan",
    "the confirmed account must be painted");
  assert(app.elementFor("app").getAttribute("data-private") === null,
    "a confirmed identity must restore the sidebar");
  assert(app.elementFor("revalidate-retry").hidden === true,
    "the recovery control must hide after confirmation");
}

async function scenarioLoginRecoverySignOutRevokesPendingIdentity() {
  const app = createApp();
  await start(app);
  app.elementFor("username").value = "alice";
  app.elementFor("password").value = "secret-password";
  app.elementFor("login-form").dispatch("submit");
  app.lastMatching("/workspace/api/login").respond(loginPayload(), 200);
  await settle();

  // The password POST succeeded, but every bounded /me check is unavailable.
  const first = app.lastMatching("/workspace/api/me");
  assert(first && !first.settled, "critical profile check missing after login");
  first.respond({ error: { code: "UNAVAILABLE", message: "Busy." } }, 503);
  await settle();
  app.fireAllTimers();
  await settle();
  const second = app.lastMatching("/workspace/api/me");
  assert(second && second !== first && !second.settled, "bounded profile retry missing");
  second.respond({ error: { code: "UNAVAILABLE", message: "Busy." } }, 503);
  await settle();
  app.fireAllTimers();
  await settle();
  const third = app.lastMatching("/workspace/api/me");
  assert(third && third !== second && !third.settled, "second bounded profile retry missing");
  third.respond({ error: { code: "UNAVAILABLE", message: "Busy." } }, 503);
  await settle();

  assert(app.elementFor("revalidate-retry").hidden === false,
    "exhausted profile retries must offer a session check retry");
  assert(app.elementFor("logout-button").hidden === false,
    "the recovery screen must offer sign-out");
  assert(app.elementFor("workspace-view").hidden === true,
    "private content must stay hidden during recovery");
  assert(app.elementFor("global-status").textContent.indexOf("Signed in") < 0,
    "an unconfirmed login must not claim a confirmed session");

  // A cookie exists for the account named by the accepted login POST, so
  // recovery sign-out must revoke it rather than merely clearing the view.
  app.elementFor("logout-button").dispatch("click");
  const revoke = app.lastMatching("/workspace/api/logout");
  assert(revoke && !revoke.settled,
    "sign-out during recovery must call the server");
  assert(revoke.options.method === "POST", "recovery sign-out must POST");
  assert(typeof revoke.options.body === "string" &&
    revoke.options.body.indexOf("{}") >= 0, "recovery sign-out must send a JSON body");
  assert(revoke.options.headers["X-Workspace-User"] === "user-alice",
    "recovery sign-out must name the login identity");
  assert(revoke.options.credentials === "same-origin",
    "recovery sign-out must use same-origin credentials");
  assert(revoke.options.headers.Authorization === undefined,
    "recovery sign-out must not use bearer auth");
  assert(app.elementFor("workspace-view").hidden === true,
    "pending sign-out must keep private content hidden");
  assert(app.elementFor("app").getAttribute("data-private") === "hidden",
    "pending sign-out must withhold the sidebar");
  assert(app.elementFor("auth-view").hidden === true,
    "sign-in must stay hidden until the server confirms sign-out");
  assert(app.elementFor("global-status").textContent.indexOf("Signed out") < 0,
    "sign-out must not be claimed before the server answers");

  revoke.respond({ error: { code: "UNAVAILABLE", message: "Could not revoke." } }, 503);
  await settle();
  assert(app.elementFor("logout-button").textContent === "Retry sign-out",
    "a failed recovery revoke must offer an honest retry");
  assert(app.elementFor("global-status").textContent.indexOf("Signed out") < 0,
    "a failed recovery revoke must not claim success");

  const before = app.callsMatching("/workspace/api/logout").length;
  app.elementFor("logout-button").dispatch("click");
  const retry = app.lastMatching("/workspace/api/logout");
  assert(app.callsMatching("/workspace/api/logout").length === before + 1,
    "the retry must issue a new server revoke");
  assert(retry && !retry.settled && retry !== revoke, "recovery revoke retry missing");
  assert(retry.options.headers["X-Workspace-User"] === "user-alice",
    "a retry must keep the pending login identity");
  retry.respond({ status: "ok" }, 200);
  await settle();
  assert(app.elementFor("workspace-view").hidden === true,
    "a confirmed sign-out must keep the workspace hidden");
  assert(app.elementFor("auth-view").hidden === false,
    "a confirmed sign-out must reveal sign-in");
  assert(app.elementFor("logout-button").hidden === true,
    "a confirmed sign-out must remove the retry control");
  assert(app.elementFor("global-status").textContent.indexOf("Signed out") >= 0,
    "a confirmed sign-out may claim completion");
}

async function scenarioQueuedAuthChangeCannotRevealLoginProfile() {
  const app = createApp();
  await start(app);
  app.elementFor("username").value = "alice";
  app.elementFor("password").value = "secret-password";
  app.elementFor("login-form").dispatch("submit");
  app.lastMatching("/workspace/api/login").respond(loginPayload(), 200);
  await settle();
  const stale = app.lastMatching("/workspace/api/me");
  assert(stale && !stale.settled, "login profile check missing");

  // A peer change arrives while the login profile check is still queued.
  app.broadcast({ type: "workspace-auth-changed" });
  await settle();
  const fresh = app.lastMatching("/workspace/api/me");
  assert(fresh && fresh !== stale, "a peer change must start a fresh cookie check");

  stale.respond(PROFILE, 200);
  await settle();
  assert(app.elementFor("workspace-view").hidden === true,
    "a queued pre-change login reply must not reveal private content");
  assert(app.elementFor("auth-view").hidden === true,
    "the sign-in form must wait for the fresh cookie check");

  fresh.respond(PROFILE, 200);
  await settle();
  assert(app.elementFor("workspace-view").hidden === false,
    "the fresh cookie check must reveal the confirmed account");
  assert(app.elementFor("identity-name").textContent === "Alice Tan",
    "the fresh check must paint the correct identity");
}

async function scenarioLogoutFailureIsRetryable() {
  const app = createApp();
  await start(app);
  await signIn(app);
  app.lastMatching("/workspace/api/conversations?limit=25").respond({ items: [], next: null }, 200);
  await settle();
  app.elementFor("logout-button").dispatch("click");
  const first = app.lastMatching("/workspace/api/logout");
  assert(first, "logout request missing");
  assert(first.options.headers["X-Workspace-User"] === "user-alice",
    "the first revoke must name the signed-in identity");
  first.respond({ error: { code: "UNAVAILABLE", message: "Could not revoke." } }, 503);
  await settle();
  assert(app.elementFor("workspace-view").hidden === true,
    "a failed sign-out must leave private content hidden");
  assert(app.elementFor("auth-view").hidden === false,
    "a failed sign-out may offer sign-in again");
  assert(app.elementFor("logout-button").hidden === false,
    "a failed sign-out must keep a usable retry control");
  assert(app.elementFor("logout-button").textContent === "Retry sign-out",
    "the retry control must be labelled honestly");
  assert(app.elementFor("global-status").textContent.indexOf("not confirmed") >= 0,
    "a failed sign-out must not claim success");
  assert(app.elementFor("global-status").textContent.indexOf("Signed out") < 0,
    "a failed sign-out must not claim completion");

  const before = app.callsMatching("/workspace/api/logout").length;
  app.elementFor("logout-button").dispatch("click");
  const retry = app.lastMatching("/workspace/api/logout");
  assert(app.callsMatching("/workspace/api/logout").length === before + 1,
    "the retry control must issue a new revoke");
  assert(retry && !retry.settled, "retry revoke missing");
  assert(retry.options.headers["X-Workspace-User"] === "user-alice",
    "a retry after the profile was cleared must still name the revoked identity");
  retry.respond({ status: "ok" }, 200);
  await settle();
  assert(app.elementFor("workspace-view").hidden === true,
    "a completed retry must hide the workspace");
  assert(app.elementFor("auth-view").hidden === false,
    "a completed retry must show sign-in");
  assert(app.elementFor("logout-button").hidden === true,
    "a completed retry must remove the retry control");
  assert(app.elementFor("global-status").textContent.indexOf("Signed out") >= 0,
    "a completed retry may claim success");
}

async function scenarioAuthChangeRejectsStaleProfile() {
  const app = createApp();
  await start(app);
  await signIn(app);
  app.lastMatching("/workspace/api/conversations?limit=25").respond(
    { items: [{ id: "conv-a", created_at: 1700000001, updated_at: 1700000002 }], next: null },
    200
  );
  await settle();
  app.elementFor("conversation-list").children[0].dispatch("click");
  app.lastMatching("/workspace/api/conversations/conv-a").respond(
    {
      id: "conv-a",
      created_at: 1700000001,
      messages: [{ id: "a1", role: "assistant", outcome: "allowed", text: "private A", created_at: 1700000002 }],
    },
    200
  );
  await settle();
  app.elementFor("composer").value = "same identity draft";

  // A focus check is already in flight when a peer announces an auth change.
  app.window.dispatch("focus");
  const stale = app.lastMatching("/workspace/api/me");
  assert(stale && !stale.settled, "focus revalidation request missing");
  app.broadcast({ type: "workspace-auth-changed" });
  await settle();
  assert(app.elementFor("workspace-view").hidden === true,
    "an auth change must withhold private content");
  assert(app.elementFor("app").getAttribute("data-private") === "hidden",
    "an auth change must not leave private content exposed");
  const fresh = app.lastMatching("/workspace/api/me");
  assert(fresh !== stale && !fresh.settled,
    "an auth change must bootstrap a fresh cookie identity check");

  // The pre-change reply for the old cookie must be discarded.
  stale.respond(PROFILE, 200);
  await settle();
  assert(app.elementFor("workspace-view").hidden === true,
    "a buffered pre-change /me reply must not repaint private content");
  assert(app.elementFor("auth-view").hidden === true,
    "the sign-in form must wait for the fresh identity check");

  // Confirming the same identity restores the tab's own draft.
  fresh.respond(PROFILE, 200);
  await settle();
  assert(app.elementFor("workspace-view").hidden === false,
    "a confirmed identity must restore the workspace");
  assert(app.elementFor("composer").value === "same identity draft",
    "same-identity drafts must survive an auth change");

  // A later change to a different identity must clear the old private state.
  app.window.dispatch("focus");
  const secondStale = app.lastMatching("/workspace/api/me");
  assert(secondStale && !secondStale.settled, "second revalidation request missing");
  app.broadcast({ type: "workspace-auth-changed" });
  await settle();
  const changed = app.lastMatching("/workspace/api/me");
  assert(changed !== secondStale && !changed.settled,
    "the second auth change must bootstrap another identity check");
  secondStale.respond(PROFILE, 200);
  await settle();
  assert(app.elementFor("workspace-view").hidden === true,
    "a stale same-identity reply must not repaint after a peer change");
  changed.respond({
    user: { ...ALICE_USER, id: "user-bob", username: "bob", full_name: "Bob Lee" },
    department: { id: "dept-accounting", name: "Accounting" },
    review_scope: null,
    review_department_ids: [],
    review_grants: [],
  }, 200);
  await settle();
  assert(app.elementFor("workspace-view").hidden === true,
    "a changed cookie identity must not paint the old workspace");
  assert(app.elementFor("auth-view").hidden === false,
    "a changed cookie identity must require sign-in");
  assert(app.elementFor("conversation-list").children.length === 0,
    "a changed cookie identity must clear private lists");
  assert(app.elementFor("composer").value === "",
    "a changed cookie identity must clear drafts");
}

async function scenarioReplyLengthContextNoticeAndIdentityReset() {
  const app = createApp();
  await start(app);
  const configured = {
    ...PROFILE,
    chat_limits: {
      ...PROFILE.chat_limits,
      default_reply_tokens: 700,
      max_reply_tokens: 2048,
    },
  };
  await signIn(app, configured);
  const list = app.lastMatching("/workspace/api/conversations?limit=25");
  list.respond(
    {
      items: [
        { id: "conv-limit-a", created_at: 1700000100, updated_at: 1700000100 },
        { id: "conv-limit-b", created_at: 1700000050, updated_at: 1700000050 },
      ],
      next: null,
    },
    200
  );
  await settle();
  app.elementFor("conversation-list").children[0].dispatch("click");
  app.lastMatching("/workspace/api/conversations/conv-limit-a").respond(
    { id: "conv-limit-a", created_at: 1700000100, messages: [] },
    200
  );
  await settle();

  const reply = app.elementFor("reply-length");
  assert(reply.disabled === false, "configured reply control must be enabled");
  assert(
    reply.children.map((option) => option.value).join(",") === "256,700,2048",
    "unusual configured default and maximum must appear exactly"
  );
  assert(reply.value === "700", "the configured server default must be selected");
  assert(
    app.elementFor("composer").getAttribute("maxlength") === "8192",
    "the textarea must follow max_prompt_chars rather than a hardcoded value"
  );

  reply.value = "2048";
  app.elementFor("composer").value = "how much history?";
  app.elementFor("composer-form").dispatch("submit");
  const send = app.lastMatching("/workspace/api/conversations/conv-limit-a/messages");
  assert(reply.children[0].textContent.indexOf("Short") === 0,
    "the smallest reply option must be labelled Short");
  assert(reply.children[1].textContent === "Standard (700 tokens)",
    "the configured server default must be labelled Standard (700 tokens)");
  assert(reply.children[2].textContent === "Longer (2048 tokens)",
    "the server maximum must be labelled Longer (2048 tokens)");
  assert(JSON.parse(send.options.body).max_tokens === 2048,
    "the selected maximum must be posted");
  send.respond(
    {
      content: "answer",
      conversation_id: "conv-limit-a",
      role: "assistant",
      context: { selected_messages: 5, omitted_messages: 7 },
    },
    200
  );
  await settle();
  app.lastMatching("/workspace/api/conversations/conv-limit-a").respond(
    {
      id: "conv-limit-a",
      created_at: 1700000100,
      messages: [
        { id: "a1", role: "user", outcome: "allowed", text: "how much history?", created_at: 1700000101 },
        { id: "a2", role: "assistant", outcome: "allowed", text: "answer", created_at: 1700000102 },
      ],
    },
    200
  );
  await settle();
  assert(
    app.elementFor("context-notice").textContent.indexOf("7 older") >= 0,
    "successful turn must report how many older messages were omitted"
  );

  // Same-user revalidation keeps a still-valid explicit choice even when the
  // server's maximum grows.
  app.window.dispatch("focus");
  const check = app.lastMatching("/workspace/api/me");
  check.respond(
    {
      ...configured,
      chat_limits: { ...configured.chat_limits, max_reply_tokens: 4096 },
    },
    200
  );
  await settle();
  assert(reply.value === "2048",
    "same-user revalidation must preserve a valid reply choice");

  // A delayed reply for the old chat must not paint the new chat notice or
  // clear the new chat's draft.
  app.elementFor("composer").value = "second question";
  app.elementFor("composer-form").dispatch("submit");
  const staleSend = app.lastMatching("/workspace/api/conversations/conv-limit-a/messages");
  app.elementFor("conversation-list").children[1].dispatch("click");
  app.lastMatching("/workspace/api/conversations/conv-limit-b").respond(
    { id: "conv-limit-b", created_at: 1700000050, messages: [] },
    200
  );
  await settle();
  app.elementFor("composer").value = "draft B stays";
  app.elementFor("composer").dispatch("input");
  staleSend.respond(
    { content: "late answer", context: { selected_messages: 9, omitted_messages: 99 } },
    200
  );
  await settle();
  assert(
    app.elementFor("context-notice").textContent.indexOf("99") < 0,
    "a stale reply must not paint the current chat context notice"
  );
  assert(app.elementFor("composer").value === "draft B stays",
    "a stale reply must not clear the current chat draft");

  // Identity changes reset the reply choice and the precise context notice.
  app.window.dispatch("focus");
  app.lastMatching("/workspace/api/me").respond(BOB_PROFILE, 200);
  await settle();
  assert(app.elementFor("reply-length").disabled === true,
    "identity change must disable the previous reply control");
  assert(app.elementFor("reply-length").value === "",
    "identity change must clear the previous reply choice");
  assert(
    app.elementFor("context-notice").textContent.indexOf("7 older") < 0,
    "identity change must clear the previous precise context count"
  );
}

async function scenarioViewUrlsAndHistory() {
  // The legacy entry stays a chat entry and becomes canonical after /me.
  const legacy = createApp();
  await start(legacy);
  await signIn(legacy, PROFILE);
  assert(legacy.location.pathname === "/workspace/chat",
    "the legacy /workspace entry must canonicalise to the chat view");
  assert(legacy.elementFor("chat-panel").hidden === false, "legacy entry must show Chat");

  // A bookmark for Review is applied only after /me confirms a reviewer.
  const reviewer = {
    user: { ...ALICE_USER, id: "user-rev-url", username: "reviewer", full_name: "Rita Reviewer", role: "employee" },
    department: { id: "dept-accounting", name: "Accounting" },
    review_scope: "department",
    review_department_ids: ["dept-accounting"],
    review_grants: [],
  };
  const review = createApp({ pathname: "/workspace/review/" });
  await start(review, { profile: reviewer });
  assert(review.location.pathname === "/workspace/review",
    "a direct review URL must canonicalise without the trailing slash");
  assert(review.elementFor("review-panel").hidden === false &&
    review.elementFor("chat-panel").hidden === true,
    "a direct review URL must open Review");
  assert(review.callsMatching("/workspace/api/review/conversations").length === 1,
    "a direct review URL must load the authorised review list");
  assert(review.callsMatching("/workspace/api/admin").length === 0,
    "a review URL must not trigger admin reads");
  const reviewList = review.lastMatching("/workspace/api/review/conversations?limit=25");
  reviewList.respond({ items: [], next: null }, 200);
  await settle();
  const ownList = review.lastMatching("/workspace/api/conversations?limit=25");
  ownList.respond({ items: [], next: null }, 200);
  await settle();

  // Tab navigation records history; Back/Forward changes the view without
  // adding entries.
  const entriesBefore = review.historyEntries.length;
  review.elementFor("tab-chat").dispatch("click");
  assert(review.location.pathname === "/workspace/chat", "chat tab must update the URL");
  assert(review.elementFor("chat-panel").hidden === false, "chat tab must show Chat");
  review.elementFor("tab-review").dispatch("click");
  assert(review.location.pathname === "/workspace/review", "review tab must update the URL");
  assert(review.elementFor("review-panel").hidden === false, "review tab must show Review");
  const entriesAfter = review.historyEntries.length;
  assert(entriesAfter === entriesBefore + 2, "tab navigation must push exactly one entry each");
  const indexBeforeBack = review.historyIndex;
  assert(review.goBack(), "history back fixture must have an entry");
  await settle();
  assert(review.location.pathname === "/workspace/chat", "Back must restore the chat URL");
  assert(review.elementFor("chat-panel").hidden === false, "Back must show Chat");
  assert(review.historyEntries.length === entriesAfter, "Back must not add history entries");
  assert(review.historyIndex === indexBeforeBack - 1, "Back must move one entry");
  assert(review.goBack(), "history back fixture must have an earlier entry");
  await settle();
  assert(review.location.pathname === "/workspace/review", "second Back must restore Review");
  assert(review.elementFor("review-panel").hidden === false, "second Back must show Review");
  assert(review.historyEntries.length === entriesAfter, "Back must never append entries");
  assert(review.goForward(), "history forward fixture must have an entry");
  await settle();
  assert(review.location.pathname === "/workspace/chat", "Forward must restore the chat URL");
  assert(review.elementFor("chat-panel").hidden === false, "Forward must show Chat");

  // Starting a chat and selecting a conversation keep the canonical chat URL.
  review.elementFor("new-chat").dispatch("click");
  await settle();
  const create = review.callsMatching("/workspace/api/conversations").filter(
    (call) => call.options.method === "POST"
  ).pop();
  assert(create, "a new chat must still POST");
  create.respond({ id: "conv-url-new", created_at: 1700000400 }, 201);
  await settle();
  const newList = review.lastMatching("/workspace/api/conversations?limit=25");
  newList.respond({
    items: [{ id: "conv-url-new", created_at: 1700000400, updated_at: 1700000400 }],
    next: null,
  }, 200);
  await settle();
  const newDetail = review.lastMatching("/workspace/api/conversations/conv-url-new");
  newDetail.respond({ id: "conv-url-new", created_at: 1700000400, messages: [] }, 200);
  await settle();
  assert(review.location.pathname === "/workspace/chat",
    "new chat and conversation selection must stay on the chat URL");
  assert(review.historyEntries.length >= entriesAfter,
    "chat navigation must not remove existing history");

  // An unauthorised bookmark falls back to Chat without issuing admin reads.
  const denied = createApp({ pathname: "/workspace/admin" });
  await start(denied, { profile: PROFILE });
  assert(denied.location.pathname === "/workspace/chat",
    "an unauthorised admin URL must canonicalise to chat");
  assert(denied.elementFor("chat-panel").hidden === false &&
    denied.elementFor("admin-panel").hidden === true,
    "an unauthorised admin URL must show Chat only");
  assert(denied.callsMatching("/workspace/api/admin").length === 0,
    "an unauthorised admin URL must not issue protected admin reads");

  // A permitted admin bookmark opens Admin and its own reads.
  const admin = {
    user: { ...ALICE_USER, id: "user-admin-url", username: "admin", full_name: "Ada Admin", role: "admin" },
    department: { id: "dept-accounting", name: "Accounting" },
    review_scope: null,
    review_department_ids: [],
    review_grants: [],
  };
  const adminApp = createApp({ pathname: "/workspace/admin" });
  await start(adminApp, { profile: admin });
  assert(adminApp.location.pathname === "/workspace/admin",
    "a permitted admin URL must stay on the admin view");
  assert(adminApp.elementFor("admin-panel").hidden === false &&
    adminApp.elementFor("chat-panel").hidden === true,
    "a permitted admin URL must open Admin");
  assert(adminApp.callsMatching("/workspace/api/admin/departments").length >= 1,
    "a permitted admin URL must load the admin lists");

  // A direct route reached before sign-in is applied after login, and losing
  // review permission replaces the URL with chat.
  const login = createApp({ pathname: "/workspace/review" });
  await start(login);
  assert(login.location.pathname === "/workspace/review",
    "the requested URL must be preserved until sign-in is confirmed");
  await signIn(login, reviewer);
  assert(login.location.pathname === "/workspace/review",
    "login must open the requested review view");
  assert(login.elementFor("review-panel").hidden === false, "login must show Review");
  const loginReviewList = login.lastMatching("/workspace/api/review/conversations?limit=25");
  loginReviewList.respond({ items: [], next: null }, 200);
  await settle();
  const loginOwnList = login.lastMatching("/workspace/api/conversations?limit=25");
  loginOwnList.respond({ items: [], next: null }, 200);
  await settle();
  login.window.dispatch("focus");
  login.lastMatching("/workspace/api/me").respond(
    { ...reviewer, review_scope: null, review_department_ids: [], review_grants: [] },
    200
  );
  await settle();
  assert(login.location.pathname === "/workspace/chat",
    "losing review permission must canonicalise the URL to chat");
  assert(login.elementFor("chat-panel").hidden === false &&
    login.elementFor("review-panel").hidden === true,
    "losing review permission must show Chat");
}

async function main() {
  await scenarioInitialRestoreWithholdsSurfaces();
  await scenarioSignInAndChat();
  await scenarioReplyLengthContextNoticeAndIdentityReset();
  await scenarioReviewer();
  await scenarioReviewRevoked();
  await scenarioExpiredSession();
  await scenarioComposerIsolation();
  await scenarioDraftSurvivesListNavigation();
  await scenarioStaleQuietReloadKeepsCurrentDraft();
  await scenarioChatEmptyCtaAndBusy();
  await scenarioChatGatewayFailureKeepsDraft();
  await scenarioChatBlockNoticeDeduplicated();
  await scenarioChatMobileCloseAndDeletedEmptyState();
  await scenarioRevalidationHidesPrivateState();
  await scenarioAuthChangeRejectsStaleProfile();
  await scenarioGuardReadiness();
  await scenarioStaleLogin();
  await scenarioLoginProfile503IsRecoverable();
  await scenarioLoginRecoverySignOutRevokesPendingIdentity();
  await scenarioQueuedAuthChangeCannotRevealLoginProfile();
  await scenarioLogoutFailureIsRetryable();
  await scenarioAdmin();
  await scenarioAdminEnableAndDelete();
  await scenarioAdminOwnRoleChange();
  await scenarioEffectivePolicyPreview();
  await scenarioPolicyPostalMask();
  await scenarioChatGuardrailDetails();
  await scenarioAlertProfileFallbackAndAcknowledgement();
  await scenarioMarkAllAlertsRead();
  await scenarioOwnNavigationFromAdmin();
  await scenarioViewUrlsAndHistory();
  await scenarioConversationListRetryAndPreservation();
  await scenarioListAttemptCannotOutliveIdentityChange();
  await scenarioPendingListRefreshKeepsNewChat();
  console.log("workspace page: all scenarios passed");
}

main().catch((error) => {
  console.error(error.stack || String(error));
  process.exit(1);
});
