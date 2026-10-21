"use strict";
/*
 * Behavior regression for the inline customer-demo script.
 *
 * Node.js is used as a deterministic local JavaScript runtime; this is not a
 * browser or CSP execution claim. The harness supplies a tiny DOM, a fake clock,
 * deferred fetch replies and a real AbortController, then exercises the same
 * origin request shape, plain-text rendering, status handling and stale replies.
 *
 * Usage: node tests/js/demo_page_harness.js <extracted-demo-js-file>
 */

const fs = require("fs");
const vm = require("vm");

const scriptPath = process.argv[2];
if (!scriptPath) {
  console.error("usage: node demo_page_harness.js <demo-js-file>");
  process.exit(2);
}
const scriptText = fs.readFileSync(scriptPath, "utf8");
const realSetTimeout = setTimeout;
const realClearTimeout = clearTimeout;

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function makeElement(id) {
  const listeners = Object.create(null);
  const element = {
    id: id,
    textContent: "",
    value: "",
    hidden: false,
    disabled: false,
    tagName: id,
    children: [],
    appendChild(child) {
      element.children.push(child);
      return child;
    },
    setAttribute(name, value) {
      element[name] = value;
    },
    removeAttribute(name) {
      delete element[name];
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
          type: type,
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
      element.focused = (element.focused || 0) + 1;
    },
  };
  Object.defineProperty(element, "innerHTML", {
    get() {
      return "";
    },
    set() {
      throw new Error("demo page must never assign innerHTML");
    },
  });
  return element;
}

function createApp() {
  const ids = [
    "chat-key",
    "key-form",
    "load-key",
    "forget-key",
    "prompt",
    "prompt-form",
    "send",
    "clear",
    "response",
    "status",
    "key-state",
    "mode-value",
    "readiness-value",
    "guards-value",
    "test-banner",
    "refresh-status",
  ];
  const elements = Object.create(null);
  for (const id of ids) {
    elements[id] = makeElement(id);
  }
  const created = [];
  const document = {
    body: makeElement("body"),
    getElementById(id) {
      return elements[id] || null;
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
    dispatch(type) {
      for (const handler of windowListeners[type] || []) {
        handler({ type: type });
      }
    },
  };

  const calls = [];
  function fetch(url, options) {
    const call = { url: url, options: options || {}, aborted: false };
    if (call.options.signal) {
      call.options.signal.addEventListener("abort", function () {
        call.aborted = true;
      });
    }
    const promise = new Promise(function (resolve, reject) {
      call.resolve = resolve;
      call.reject = reject;
    });
    call.respond = function (payload, status, extra) {
      const extras = extra || {};
      const statusCode = typeof status === "number" ? status : 200;
      call.resolve({
        ok: statusCode >= 200 && statusCode < 300,
        status: statusCode,
        headers: { get() { return null; } },
        json: function () {
          if (extras.invalidJson) {
            return Promise.reject(new SyntaxError("invalid json"));
          }
          return Promise.resolve(payload);
        },
      });
    };
    calls.push(call);
    return promise;
  }

  const timers = [];
  let timerId = 0;
  function fakeSetTimeout(fn, delay) {
    timerId += 1;
    timers.push({ id: timerId, fn: fn, delay: delay, cleared: false });
    return timerId;
  }
  function fakeClearTimeout(id) {
    for (const timer of timers) {
      if (timer.id === id) {
        timer.cleared = true;
      }
    }
  }

  const context = {
    document: document,
    window: window,
    fetch: fetch,
    AbortController: AbortController,
    console: console,
    setTimeout: fakeSetTimeout,
    clearTimeout: fakeClearTimeout,
  };
  vm.createContext(context);
  vm.runInContext(scriptText, context, { filename: "demo_page.js" });
  return {
    elements: elements,
    window: window,
    calls: calls,
    created: created,
    timers: timers,
    fireTimers() {
      for (const timer of timers.slice()) {
        if (!timer.cleared) {
          timer.cleared = true;
          timer.fn();
        }
      }
    },
  };
}

function flush() {
  return new Promise(function (resolve) {
    realSetTimeout(resolve, 0);
  });
}

function abortError() {
  const error = new Error("aborted");
  error.name = "AbortError";
  return error;
}

function completion(content) {
  return {
    choices: [{ finish_reason: "stop", message: { role: "assistant", content: content } }],
  };
}

function loadKey(app, key) {
  app.elements["chat-key"].value = key;
  app.elements["key-form"].dispatch("submit");
}

async function readyApp(mode, guardsActive) {
  const app = createApp();
  assert(app.calls.length === 1, "page probes readiness on load");
  assert(app.calls[0].url === "/health/ready", "readiness probe uses the public health path");
  assert(app.calls[0].options.method === "GET", "readiness probe is a GET");
  assert(app.calls[0].options.credentials === "same-origin", "readiness probe is same-origin");
  app.calls[0].respond({
    status: "ready",
    mode: mode || "test",
    guards_active: guardsActive === true,
  });
  await flush();
  return app;
}

async function healthLabelsAndTestModeAreVisible() {
  const app = await readyApp("test", false);
  assert(app.elements["mode-value"].textContent === "test", "actual mode is shown");
  assert(app.elements["readiness-value"].textContent === "ready", "readiness is shown");
  assert(app.elements["guards-value"].textContent === "inactive", "inactive guards are shown");
  assert(app.elements["test-banner"].hidden === false, "test-mode banner is visible");
  assert(
    app.elements["test-banner"].textContent.indexOf(
      "model-based injection and output checks are inactive"
    ) >= 0,
    "test mode states that model-based checks are inactive"
  );
  assert(
    scriptText.indexOf("localStorage") < 0 &&
      scriptText.indexOf("sessionStorage") < 0 &&
      scriptText.indexOf("document.cookie") < 0 &&
      scriptText.indexOf("console.") < 0,
    "script has no storage, cookie or console sink"
  );
}

async function unreadyHealthIsReportedTruthfully() {
  const app = createApp();
  app.calls[0].respond({ status: "not_ready", mode: "guarded", guards_active: false }, 503);
  await flush();
  assert(app.elements["readiness-value"].textContent === "not ready", "503 readiness is not ready");
  assert(app.elements["guards-value"].textContent === "inactive", "guards stay reported inactive");
  assert(app.elements["test-banner"].hidden === false, "unguarded deployment warning is visible");
  assert(
    app.elements["test-banner"].textContent.indexOf("Guards are not active") >= 0,
    "warning does not claim guard protection"
  );

  const broken = createApp();
  broken.calls[0].respond(null, 502, { invalidJson: true });
  await flush();
  assert(broken.elements["mode-value"].textContent === "unknown", "non-JSON mode is unknown");
  assert(broken.elements["readiness-value"].textContent === "unknown", "non-JSON readiness is unknown");
  assert(broken.elements["guards-value"].textContent === "unknown", "unknown guards are not claimed active");
}

async function healthRefreshIsBoundedAndOrdered() {
  const app = await readyApp("test", false);
  const before = app.calls.length;
  app.elements["refresh-status"].dispatch("click");
  const first = app.calls[before];
  assert(first.url === "/health/ready", "refresh uses the public health path");
  assert(first.options.signal, "refresh carries an abort signal");
  app.elements["refresh-status"].dispatch("click");
  assert(first.aborted === true, "a newer refresh aborts the previous one");
  const second = app.calls[before + 1];
  second.respond({ status: "ready", mode: "guarded", guards_active: true });
  await flush();
  assert(app.elements["mode-value"].textContent === "guarded", "current health mode is applied");
  assert(app.elements["readiness-value"].textContent === "ready", "current readiness is applied");
  assert(app.elements["guards-value"].textContent === "active", "current active guards are applied");
  assert(app.elements["test-banner"].hidden === true, "valid active status clears the stale warning");

  first.respond({ status: "not_ready", mode: "test", guards_active: false }, 503);
  await flush();
  assert(app.elements["mode-value"].textContent === "guarded", "late older reply cannot overwrite mode");
  assert(app.elements["readiness-value"].textContent === "ready", "late older reply cannot overwrite readiness");
  assert(app.elements["guards-value"].textContent === "active", "late older reply cannot overwrite guards");
}

async function healthTimeoutIsUnknownAndKeepsWarning() {
  const app = await readyApp("test", false);
  const before = app.calls.length;
  app.elements["refresh-status"].dispatch("click");
  const probe = app.calls[before];
  const pending = app.timers.filter(function (timer) {
    return !timer.cleared;
  });
  assert(pending.length === 1, "health refresh arms exactly one deadline");
  assert(pending[0].delay === 10000, "health deadline is 10 seconds");
  app.fireTimers();
  assert(probe.aborted === true, "health deadline aborts the fetch");
  probe.reject(abortError());
  await flush();
  assert(app.elements["mode-value"].textContent === "unknown", "timed-out mode is unknown");
  assert(app.elements["readiness-value"].textContent === "unknown", "timed-out readiness is unknown");
  assert(app.elements["guards-value"].textContent === "unknown", "timed-out guards are unknown");
  assert(
    app.elements["test-banner"].hidden === false &&
      app.elements["test-banner"].textContent.indexOf("model-based") >= 0,
    "timed-out refresh keeps the existing test-mode warning"
  );
}

async function malformedAndInconsistentHealthNeverClaimProtection() {
  const malformed = await readyApp("test", false);
  const malformedCall = malformed.calls.length;
  malformed.elements["refresh-status"].dispatch("click");
  malformed.calls[malformedCall].respond({}, 200);
  await flush();
  assert(malformed.elements["mode-value"].textContent === "unknown", "malformed mode is unknown");
  assert(malformed.elements["readiness-value"].textContent === "unknown", "malformed readiness is unknown");
  assert(malformed.elements["guards-value"].textContent === "unknown", "malformed guards are unknown");
  assert(
    malformed.elements["test-banner"].hidden === false &&
      malformed.elements["test-banner"].textContent.indexOf("model-based") >= 0,
    "malformed health cannot hide the test-mode warning"
  );

  const errorHtml = await readyApp("test", false);
  const errorCall = errorHtml.calls.length;
  errorHtml.elements["refresh-status"].dispatch("click");
  errorHtml.calls[errorCall].respond(null, 502, { invalidJson: true });
  await flush();
  assert(errorHtml.elements["guards-value"].textContent === "unknown", "error HTML guards are unknown");
  assert(
    errorHtml.elements["test-banner"].hidden === false &&
      errorHtml.elements["test-banner"].textContent.indexOf("model-based") >= 0,
    "error HTML cannot hide the test-mode warning"
  );

  const inconsistent = await readyApp("test", true);
  assert(
    inconsistent.elements["guards-value"].textContent === "inactive",
    "test mode plus guards_active=true never claims active guards"
  );
  assert(
    inconsistent.elements["test-banner"].hidden === false &&
      inconsistent.elements["test-banner"].textContent.indexOf("model-based") >= 0,
    "inconsistent status still shows the test-mode warning"
  );
}

async function pagehideAbortsHealthRefresh() {
  const app = await readyApp("test", false);
  const before = app.calls.length;
  app.elements["refresh-status"].dispatch("click");
  const probe = app.calls[before];
  app.window.dispatch("pagehide");
  assert(probe.aborted === true, "pagehide aborts a pending health refresh");
  probe.respond({ status: "ready", mode: "guarded", guards_active: true });
  await flush();
  assert(app.elements["mode-value"].textContent === "test", "pagehide late health cannot overwrite mode");
  assert(app.elements["guards-value"].textContent === "inactive", "pagehide late health cannot claim active guards");
  assert(app.elements["test-banner"].hidden === false, "pagehide late health cannot hide the warning");
}

async function keyLoadClearsInputAndClaimsNoAuthentication() {
  const app = await readyApp();
  loadKey(app, "  demo-chat-key  ");
  assert(app.elements["chat-key"].value === "", "password field is cleared after load");
  assert(app.calls.length === 1, "loading a key sends no chat request");
  assert(
    app.elements["key-state"].textContent === "Chat key loaded for this tab.",
    "loaded key uses the neutral tab-local state"
  );
  assert(
    app.elements["status"].textContent === "Chat key loaded for this tab.",
    "status repeats the neutral loaded state"
  );
  assert(
    app.elements["key-state"].textContent.indexOf("verified") < 0 &&
      app.elements["status"].textContent.indexOf("verified") < 0,
    "no verification claim is made before chat"
  );
}

async function requestIsStrictSameOriginPayload() {
  const app = await readyApp();
  loadKey(app, "demo-chat-key");
  app.elements["prompt"].value = "Hello synthetic customer demo";
  app.elements["prompt-form"].dispatch("submit");
  assert(app.calls.length === 2, "one submit starts exactly one chat request");
  const call = app.calls[1];
  assert(call.url === "/v1/chat/completions", "chat path is fixed with no query string");
  assert(call.url.indexOf("demo-chat-key") < 0, "key never appears in the URL");
  assert(call.options.method === "POST", "chat uses POST");
  assert(call.options.credentials === "same-origin", "chat is same-origin");
  assert(call.options.cache === "no-store", "chat is not cached");
  assert(call.options.redirect === "error", "chat does not follow redirects");
  assert(call.options.headers["Authorization"] === "Bearer demo-chat-key", "bearer header carries the key");
  assert(call.options.headers["Content-Type"] === "application/json", "chat declares JSON");
  const body = JSON.parse(call.options.body);
  assert(
    JSON.stringify(body) ===
      JSON.stringify({
        model: "pilot-local",
        messages: [{ role: "user", content: "Hello synthetic customer demo" }],
      }),
    "body contains only the fixed model and one user message"
  );
  assert(call.options.body.indexOf("demo-chat-key") < 0, "key never appears in the body");

  app.elements["prompt-form"].dispatch("submit");
  assert(app.calls.length === 2, "duplicate submit while in flight is ignored");
  assert(app.elements["send"].disabled === true, "send is disabled while in flight");

  call.respond({
    choices: [
      {
        finish_reason: "stop",
        message: { role: "assistant", content: "Synthetic answer" },
      },
    ],
  });
  await flush();
  assert(app.elements["response"].textContent === "Synthetic answer", "response text is shown");
  assert(app.elements["status"].textContent === "Response received.", "success status is truthful");
  assert(
    app.elements["key-state"].textContent === "Chat key accepted in this tab.",
    "successful chat updates the key state without a broader claim"
  );
  assert(app.elements["send"].disabled === false, "send unlocks after success");
}

async function responseAndErrorStringsStayPlainText() {
  const app = await readyApp("test", false);
  loadKey(app, "demo-chat-key");
  app.elements["prompt"].value = "Render markup as text";
  app.elements["prompt-form"].dispatch("submit");
  const payload = '<img src=x onerror="window.pwned=1"><script>bad()</script>';
  app.calls[1].respond({
    choices: [{ finish_reason: "stop", message: { role: "assistant", content: payload } }],
  });
  await flush();
  assert(app.elements["response"].textContent === payload, "response is rendered as plain text");
  assert(app.created.length === 0, "page creates no HTML elements from model output");
  assert(
    app.elements["test-banner"].textContent.indexOf(
      "model-based injection and output checks are inactive"
    ) >= 0,
    "successful chat does not remove the test-mode warning"
  );

  const broken = await readyApp();
  loadKey(broken, "demo-chat-key");
  broken.elements["prompt"].value = "Incomplete";
  broken.elements["prompt-form"].dispatch("submit");
  broken.calls[1].respond({ choices: [{ message: { content: "partial" } }] });
  await flush();
  assert(broken.elements["response"].textContent === "", "missing finish_reason is not rendered");
  assert(
    broken.elements["status"].textContent.indexOf("incomplete") >= 0,
    "incomplete completion is reported as unsupported"
  );
}

async function unauthorizedClearsBadKey() {
  const app = await readyApp();
  loadKey(app, "bad-key");
  app.elements["prompt"].value = "Hello";
  app.elements["prompt-form"].dispatch("submit");
  app.calls[1].respond({ error: { code: "UNAUTHORIZED" } }, 401);
  await flush();
  assert(app.elements["chat-key"].value === "", "401 clears the key input");
  assert(app.elements["key-state"].textContent === "No key loaded.", "401 clears in-memory key state");
  assert(
    app.elements["status"].textContent.indexOf("chat key was cleared") >= 0,
    "401 explains that the key was cleared"
  );
  const before = app.calls.length;
  app.elements["prompt-form"].dispatch("submit");
  assert(app.calls.length === before, "cleared key cannot send another request");
}

async function blockedAndUnavailableAreHandledWithoutRawErrors() {
  const blocked = await readyApp();
  loadKey(blocked, "good-key");
  blocked.elements["prompt"].value = "Blocked example";
  blocked.elements["prompt-form"].dispatch("submit");
  blocked.calls[1].respond({ error: { code: "POLICY_BLOCK", message: "raw upstream text" } }, 403);
  await flush();
  assert(
    blocked.elements["status"].textContent === "The request was blocked by the active safety policy.",
    "403 maps to a policy-block message"
  );
  assert(blocked.elements["status"].textContent.indexOf("raw upstream text") < 0, "403 hides raw error text");
  assert(
    blocked.elements["key-state"].textContent === "Chat key loaded for this tab.",
    "403 keeps the key"
  );
  assert(blocked.elements["response"].textContent === "", "403 renders no response");

  const unavailable = await readyApp();
  loadKey(unavailable, "good-key");
  unavailable.elements["prompt"].value = "Unavailable example";
  unavailable.elements["prompt-form"].dispatch("submit");
  unavailable.calls[1].respond({ error: { code: "UNAVAILABLE" } }, 503);
  await flush();
  assert(
    unavailable.elements["status"].textContent.indexOf("not ready") >= 0,
    "503 reports an unready or unavailable gateway"
  );
  assert(unavailable.elements["send"].disabled === false, "503 unlocks send");

  const proxy = await readyApp();
  loadKey(proxy, "good-key");
  proxy.elements["prompt"].value = "Proxy failure example";
  proxy.elements["prompt-form"].dispatch("submit");
  proxy.calls[1].respond(null, 502, { invalidJson: true });
  await flush();
  assert(proxy.elements["status"].textContent === "The gateway returned an error.", "non-JSON failure is generic");
  assert(proxy.elements["send"].disabled === false, "non-JSON failure unlocks send");
}

async function emptyInputsNeverDispatch() {
  const noKey = await readyApp();
  noKey.elements["prompt"].value = "Hello";
  noKey.elements["prompt-form"].dispatch("submit");
  assert(noKey.calls.length === 1, "missing key sends nothing");
  assert(noKey.elements["status"].textContent === "Load a chat key first.", "missing key is explained");

  loadKey(noKey, "demo-chat-key");
  noKey.elements["prompt"].value = "   ";
  noKey.elements["prompt-form"].dispatch("submit");
  assert(noKey.calls.length === 1, "empty prompt sends nothing");
  assert(
    noKey.elements["status"].textContent === "Enter a prompt before sending.",
    "empty prompt is explained"
  );
}

async function forgetAndClearInvalidateLateReplies() {
  const forgotten = await readyApp();
  loadKey(forgotten, "demo-chat-key");
  forgotten.elements["prompt"].value = "First prompt";
  forgotten.elements["prompt-form"].dispatch("submit");
  forgotten.calls[1].respond(completion("Visible answer"));
  await flush();
  assert(
    forgotten.elements["response"].textContent === "Visible answer",
    "a displayed response exists before forget"
  );
  forgotten.elements["prompt"].value = "Late reply";
  forgotten.elements["prompt-form"].dispatch("submit");
  forgotten.elements["forget-key"].dispatch("click");
  assert(forgotten.calls[2].aborted === true, "forget aborts the in-flight request");
  assert(forgotten.elements["prompt"].value === "", "forget clears an existing prompt");
  assert(forgotten.elements["response"].textContent === "", "forget clears an existing response");
  assert(forgotten.elements["key-state"].textContent === "No key loaded.", "forget clears key state");
  forgotten.calls[2].respond(completion("should not appear"));
  await flush();
  assert(forgotten.elements["response"].textContent === "", "late reply cannot repopulate after forget");
  assert(
    forgotten.elements["status"].textContent === "Chat key forgotten. Prompt and response cleared.",
    "forget status survives"
  );
  assert(forgotten.elements["send"].disabled === false, "forget unlocks send");

  const cleared = await readyApp();
  loadKey(cleared, "demo-chat-key");
  cleared.elements["prompt"].value = "Clear me";
  cleared.elements["prompt-form"].dispatch("submit");
  cleared.elements["clear"].dispatch("click");
  assert(cleared.calls[1].aborted === true, "clear aborts the in-flight request");
  cleared.calls[1].respond({
    choices: [{ finish_reason: "stop", message: { role: "assistant", content: "stale answer" } }],
  });
  await flush();
  assert(cleared.elements["prompt"].value === "", "clear empties the prompt");
  assert(cleared.elements["response"].textContent === "", "stale reply stays cleared");
  assert(cleared.elements["status"].textContent === "Prompt and response cleared.", "clear status survives");
}

async function pagehideClearsSensitiveState() {
  const app = await readyApp();
  loadKey(app, "demo-chat-key");
  app.elements["prompt"].value = "Pagehide example";
  app.elements["prompt-form"].dispatch("submit");
  app.window.dispatch("pagehide");
  assert(app.calls[1].aborted === true, "pagehide aborts the in-flight request");
  assert(app.elements["chat-key"].value === "", "pagehide clears the key field");
  assert(app.elements["key-state"].textContent === "No key loaded.", "pagehide clears key state");
  assert(app.elements["prompt"].value === "", "pagehide clears the prompt");
  app.calls[1].respond({
    choices: [{ finish_reason: "stop", message: { role: "assistant", content: "stale" } }],
  });
  await flush();
  assert(app.elements["response"].textContent === "", "pagehide late reply cannot render");
  assert(app.elements["status"].textContent === "", "pagehide late reply cannot set status");
}

async function finiteTimeoutAbortsAndUnlocks() {
  const app = await readyApp();
  loadKey(app, "demo-chat-key");
  app.elements["prompt"].value = "Timeout example";
  app.elements["prompt-form"].dispatch("submit");
  const pending = app.timers.filter(function (timer) {
    return !timer.cleared;
  });
  assert(pending.length === 1, "one UI deadline timer is armed");
  assert(pending[0].delay === 90000, "UI deadline is 90 seconds");
  app.fireTimers();
  assert(app.calls[1].aborted === true, "deadline aborts the fetch");
  app.calls[1].reject(abortError());
  await flush();
  assert(
    app.elements["status"].textContent.indexOf("timed out after 90 seconds") >= 0,
    "timeout is reported truthfully"
  );
  assert(app.elements["send"].disabled === false, "timeout unlocks send");
}

async function main() {
  const scenarios = [
    ["health labels and test mode", healthLabelsAndTestModeAreVisible],
    ["unready health is truthful", unreadyHealthIsReportedTruthfully],
    ["health refresh is bounded and ordered", healthRefreshIsBoundedAndOrdered],
    ["health timeout keeps the warning", healthTimeoutIsUnknownAndKeepsWarning],
    ["malformed or inconsistent health claims nothing", malformedAndInconsistentHealthNeverClaimProtection],
    ["pagehide aborts health refresh", pagehideAbortsHealthRefresh],
    ["key load clears input and claims no auth", keyLoadClearsInputAndClaimsNoAuthentication],
    ["strict same-origin payload", requestIsStrictSameOriginPayload],
    ["plain-text response rendering", responseAndErrorStringsStayPlainText],
    ["401 clears the bad key", unauthorizedClearsBadKey],
    ["403 and 503 handling", blockedAndUnavailableAreHandledWithoutRawErrors],
    ["empty inputs never dispatch", emptyInputsNeverDispatch],
    ["forget and clear invalidate replies", forgetAndClearInvalidateLateReplies],
    ["pagehide clears sensitive state", pagehideClearsSensitiveState],
    ["finite timeout aborts", finiteTimeoutAbortsAndUnlocks],
  ];
  for (const [name, scenario] of scenarios) {
    await scenario();
    console.log("ok - " + name);
  }
  console.log("demo_page_harness: all scenarios passed");
}

main().catch(function (error) {
  console.error("demo_page_harness failed: " + (error && error.stack ? error.stack : error));
  process.exitCode = 1;
});
