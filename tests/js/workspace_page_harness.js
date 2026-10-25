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
  };
  const windowListeners = Object.create(null);
  const window = {
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

async function signIn(app, profile) {
  const login = app.elementFor("login-form");
  app.elementFor("username").value = "alice";
  app.elementFor("password").value = "secret-password";
  login.dispatch("submit");
  const request = app.lastMatching("/workspace/api/login");
  assert(request, "login request was not issued");
  assert(
    app.elementFor("password").value === "",
    "password field must be cleared when the request starts"
  );
  const body = JSON.parse(request.options.body);
  assert(body.username === "alice", "username payload mismatch");
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
  composer.value = hostile;
  app.elementFor("composer-form").dispatch("submit");
  const send = app.lastMatching("/workspace/api/conversations/conv-alpha-1234/messages");
  assert(send, "message request missing");
  assert(
    send.options.body === JSON.stringify({ text: hostile }),
    "message payload must contain exactly the original prompt text"
  );
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
  app.lastMatching("/workspace/api/conversations?limit=25").respond({ items: [], next: null }, 200);
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
  assert(app.elementFor("tab-admin").hidden === false, "admin tab must appear for an admin role");
  assert(app.callsMatching("/workspace/api/admin").length === 0,
    "admin data must not be fetched before the admin view opens");

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
        { id: "log-1", actor_id: "user-admin", action: "review.read", conversation_id: "conv-1", department_id: "dept-accounting", created_at: 1700000004 },
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
  assert(accessText.indexOf("review.read") >= 0 && accessText.indexOf("conv-1") >= 0,
    "access log metadata missing");
  assert(accessText.indexOf("prompt") < 0, "access log must not contain message text");
  const adminDisableButtons = collect(app.elementFor("user-list")).filter(
    (element) => element.tagName === "BUTTON" && element.textContent.trim() === "Disable"
  );
  assert(adminDisableButtons.length === 1, "the current admin must not be offered self-disable");

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
    app.callsMatching("/workspace/api/admin/users").filter(
      (call) => call.options.method === "POST"
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

async function main() {
  await scenarioInitialRestoreWithholdsSurfaces();
  await scenarioSignInAndChat();
  await scenarioReviewer();
  await scenarioReviewRevoked();
  await scenarioExpiredSession();
  await scenarioComposerIsolation();
  await scenarioDraftSurvivesListNavigation();
  await scenarioStaleQuietReloadKeepsCurrentDraft();
  await scenarioRevalidationHidesPrivateState();
  await scenarioAuthChangeRejectsStaleProfile();
  await scenarioGuardReadiness();
  await scenarioStaleLogin();
  await scenarioLoginProfile503IsRecoverable();
  await scenarioLoginRecoverySignOutRevokesPendingIdentity();
  await scenarioQueuedAuthChangeCannotRevealLoginProfile();
  await scenarioLogoutFailureIsRetryable();
  await scenarioAdmin();
  console.log("workspace page: all scenarios passed");
}

main().catch((error) => {
  console.error(error.stack || String(error));
  process.exit(1);
});
