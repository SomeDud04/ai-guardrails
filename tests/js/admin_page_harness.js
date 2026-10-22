"use strict";
/*
 * Behavior regression for the inline operator-shell script.
 *
 * Node.js is used as a deterministic local JavaScript runtime; this is not a
 * browser or CSP execution claim. The harness supplies a tiny DOM, deferred
 * fetch replies and a real AbortController, then exercises stale/disconnected
 * replies and paging/filter locking.
 *
 * Usage: node tests/js/admin_page_harness.js <extracted-admin-js-file>
 */

const fs = require("fs");
const vm = require("vm");

const scriptPath = process.argv[2];
if (!scriptPath) {
  console.error("usage: node admin_page_harness.js <admin-js-file>");
  process.exit(2);
}
const scriptText = fs.readFileSync(scriptPath, "utf8");

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
    className: "",
    children: [],
    appendChild(child) {
      element.children.push(child);
      return child;
    },
    removeChild(child) {
      const index = element.children.indexOf(child);
      assert(index >= 0, "removeChild target is present");
      element.children.splice(index, 1);
      return child;
    },
    get firstChild() {
      return element.children.length ? element.children[0] : null;
    },
    setAttribute(name, value) {
      element[name] = value;
    },
    removeAttribute(name) {
      delete element[name];
    },
    click() {
      element.clicked = (element.clicked || 0) + 1;
    },
    focus() {},
    addEventListener(type, handler) {
      if (!listeners[type]) {
        listeners[type] = [];
      }
      listeners[type].push(handler);
    },
    dispatch(type, extra) {
      const event = Object.assign(
        {
          preventDefault() {
            event.defaultPrevented = true;
          },
        },
        extra || {}
      );
      const handlers = listeners[type] || [];
      for (const handler of handlers) {
        handler(event);
      }
      return event;
    },
  };
  return element;
}

function createApp() {
  const ids = [
    "operator-token",
    "login-form",
    "connect",
    "disconnect",
    "login-panel",
    "view-panel",
    "status",
    "events-body",
    "page-info",
    "events-state",
    "events-state-title",
    "events-state-text",
    "policy-version",
    "policy-digest",
    "health-status",
    "decision-filter",
    "event-type-filter",
    "request-id-filter",
    "apply-filters",
    "export-csv",
    "table-wrap",
    "toggle-technical",
    "previous-page",
    "next-page",
  ];
  const elements = Object.create(null);
  for (const id of ids) {
    elements[id] = makeElement(id);
  }
  const body = makeElement("body");
  const created = [];

  const document = {
    body: body,
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
      const handlers = windowListeners[type] || [];
      for (const handler of handlers) {
        handler({ type: type });
      }
    },
  };

  const calls = [];
  const objectUrls = [];
  const revokedUrls = [];
  const URLMock = {
    createObjectURL(blob) {
      objectUrls.push(blob);
      return "blob:admin-page-test-" + objectUrls.length;
    },
    revokeObjectURL(url) {
      revokedUrls.push(url);
    },
  };
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
    call.respond = function (payload, status, ok, extra) {
      const extras = extra || {};
      const headerValues = extras.headers || {};
      const statusCode = typeof status === "number" ? status : 200;
      const isOk = typeof ok === "boolean" ? ok : statusCode >= 200 && statusCode < 300;
      call.resolve({
        ok: isOk,
        status: statusCode,
        headers: {
          get(name) {
            const key = String(name).toLowerCase();
            for (const stored of Object.keys(headerValues)) {
              if (stored.toLowerCase() === key) {
                return headerValues[stored];
              }
            }
            return null;
          },
        },
        json: function () {
          return Promise.resolve(payload);
        },
        blob: function () {
          const text = typeof extras.blobText === "string" ? extras.blobText : "";
          return Promise.resolve(new Blob([text], { type: "text/csv" }));
        },
      });
    };
    calls.push(call);
    return promise;
  }

  const context = {
    document: document,
    window: window,
    fetch: fetch,
    AbortController: AbortController,
    URLSearchParams: URLSearchParams,
    URL: URLMock,
    Blob: Blob,
    console: console,
    setTimeout: setTimeout,
    clearTimeout: clearTimeout,
  };
  vm.createContext(context);
  vm.runInContext(scriptText, context, { filename: "admin_page.js" });
  return {
    elements: elements,
    window: window,
    calls: calls,
    created: created,
    body: body,
    objectUrls: objectUrls,
    revokedUrls: revokedUrls,
  };
}

function flush() {
  return new Promise(function (resolve) {
    setTimeout(resolve, 0);
  });
}

function rows(app) {
  return app.elements["events-body"].children.map(function (row) {
    return row.children.map(function (cell) {
      return cell.textContent;
    });
  });
}

function event(seq, requestId, decision) {
  return {
    seq: seq,
    timestamp: 1700000000 + seq,
    request_id: requestId,
    event_type: "request_started",
    decision: decision || "pending",
    error_code: null,
    policy_version: "v-test",
    policy_digest: "d".repeat(64),
    model: "pilot-local",
  };
}

function payload(events, options) {
  const extras = options || {};
  return {
    events: events,
    has_more: extras.has_more === true,
    next_cursor: typeof extras.next_cursor === "number" ? extras.next_cursor : null,
    policy: { version: extras.version || "v-test", digest: "d".repeat(64) },
    health: "ready",
  };
}

function connect(app, token) {
  app.elements["operator-token"].value = token;
  app.elements["login-form"].dispatch("submit");
}

async function staleSuccessAfterDisconnect() {
  const app = createApp();
  connect(app, "secret-one");
  assert(app.calls.length === 1, "connect starts one event request");
  assert(
    app.calls[0].url === "/admin/events?limit=50",
    "request uses the captured default filters"
  );
  assert(
    app.elements["decision-filter"].disabled &&
      app.elements["apply-filters"].disabled &&
      app.elements["next-page"].disabled,
    "filters and navigation lock while a page is loading"
  );
  assert(app.elements["events-state"].hidden === false, "loading state is visible while a page loads");
  assert(
    app.elements["events-state-title"].textContent === "Loading events",
    "loading state names the current task"
  );

  app.elements["disconnect"].dispatch("click");
  assert(app.calls[0].aborted === true, "disconnect aborts the in-flight request");
  assert(app.elements["operator-token"].value === "", "token is cleared on disconnect");
  assert(app.elements["status"].textContent === "Disconnected.", "disconnect status");

  app.calls[0].respond(payload([event(1, "req_stale")]));
  await flush();
  assert(rows(app).length === 0, "stale success must not repopulate a disconnected view");
  assert(app.elements["policy-version"].textContent === "", "stale metadata stays cleared");
  assert(app.elements["page-info"].textContent === "", "stale page info stays cleared");
  assert(app.elements["events-state"].hidden === true, "stale success cannot reveal an empty state");
  assert(app.elements["status"].textContent === "Disconnected.", "stale success cannot replace status");
  assert(app.elements["view-panel"].hidden === true, "view stays hidden");
}

async function laterSessionSurvivesOlderReply() {
  const app = createApp();
  connect(app, "secret-one");
  app.elements["disconnect"].dispatch("click");
  connect(app, "secret-two");
  assert(app.calls.length === 2, "second connection starts its own request");

  app.calls[1].respond(payload([event(9, "req_second")]));
  await flush();
  assert(rows(app).length === 1, "second session renders its page");
  assert(rows(app)[0][2] === "req_second", "second session row is visible");
  assert(app.elements["status"].textContent === "Events loaded.", "second session status");

  app.calls[0].respond(payload([event(1, "req_first")]));
  await flush();
  assert(rows(app).length === 1, "older reply cannot overwrite the later session");
  assert(rows(app)[0][2] === "req_second", "later session row survives");
}

async function pagehideClearsAndCannotRepopulate() {
  const app = createApp();
  connect(app, "secret-pagehide");
  app.window.dispatch("pagehide");
  assert(app.calls[0].aborted === true, "pagehide aborts the in-flight request");
  assert(app.elements["operator-token"].value === "", "pagehide clears the token input");
  assert(app.elements["view-panel"].hidden === true, "pagehide hides the event view");

  app.calls[0].respond(payload([event(1, "req_pagehide")]));
  await flush();
  assert(rows(app).length === 0, "pagehide stale reply cannot render rows");
  assert(app.elements["status"].textContent === "", "pagehide stale reply cannot set status");
}

async function abortRejectionDoesNotBecomeAnError() {
  const app = createApp();
  connect(app, "secret-abort");
  app.elements["disconnect"].dispatch("click");
  const aborted = new Error("aborted");
  aborted.name = "AbortError";
  app.calls[0].reject(aborted);
  await flush();
  assert(app.elements["status"].textContent === "Disconnected.", "abort is not a visible error");
  assert(app.elements["apply-filters"].disabled === false, "busy resets after abort");
}

async function filtersAreCapturedAndUnlockAfterSuccess() {
  const app = createApp();
  connect(app, "secret-filters");
  app.elements["decision-filter"].value = "blocked";
  app.elements["request-id-filter"].value = "req_later";
  assert(
    app.calls[0].url === "/admin/events?limit=50",
    "in-flight request keeps the filters captured at request start"
  );

  app.calls[0].respond(payload([event(1, "req_page")], { has_more: true, next_cursor: 7 }));
  await flush();
  assert(app.elements["decision-filter"].disabled === false, "filters unlock after success");
  assert(app.elements["apply-filters"].disabled === false, "apply unlocks after success");
  assert(app.elements["next-page"].disabled === false, "next unlocks when a cursor exists");

  app.elements["apply-filters"].dispatch("click");
  assert(app.calls.length === 2, "apply starts a new request");
  assert(
    app.calls[1].url === "/admin/events?limit=50&decision=blocked&request_id=req_later",
    "new request uses current filters and resets paging"
  );
  app.calls[1].respond(payload([]));
  await flush();
  assert(app.elements["status"].textContent === "No events loaded.", "empty result status");
  assert(
    app.elements["page-info"].textContent === "No events match the current filters.",
    "empty result explanation"
  );
  assert(app.elements["events-state"].hidden === false, "filtered empty result shows a state");
  assert(
    app.elements["events-state-title"].textContent === "No matching events",
    "filtered empty state names the cause"
  );
  assert(
    app.elements["events-state-text"].textContent.indexOf("Widen") >= 0,
    "filtered empty state explains recovery"
  );
}

async function emptyStreamTeachesTheWorkspace() {
  const app = createApp();
  connect(app, "secret-empty");
  app.calls[0].respond(payload([]));
  await flush();
  assert(app.elements["status"].textContent === "No events loaded.", "empty stream status");
  assert(app.elements["page-info"].textContent === "No events recorded yet.", "empty stream page info");
  assert(app.elements["events-state"].hidden === false, "empty stream shows a state");
  assert(
    app.elements["events-state-title"].textContent === "No events yet",
    "empty stream state avoids claiming activity"
  );
  assert(
    app.elements["events-state-text"].textContent.indexOf("after the gateway handles requests") >= 0,
    "empty stream explains when events appear"
  );
  assert(app.elements["apply-filters"].disabled === false, "empty stream unlocks filters");
}

async function currentFailureClearsAndUnlocks() {
  const app = createApp();
  connect(app, "secret-failure");
  app.calls[0].respond({}, 503, false);
  await flush();
  assert(app.elements["status"].textContent === "Events are unavailable.", "failure status");
  assert(app.elements["status"]["data-kind"] === "error", "failure is marked as an error");
  assert(rows(app).length === 0, "failure clears rows");
  assert(app.elements["apply-filters"].disabled === false, "busy resets after failure");
}

async function exportUsesFiltersWithoutPageCursor() {
  const app = createApp();
  connect(app, "secret-export");
  app.calls[0].respond(payload([event(1, "req_page_one")], { has_more: true, next_cursor: 7 }));
  await flush();

  app.elements["next-page"].dispatch("click");
  assert(app.calls.length === 2, "next page starts a second event request");
  app.calls[1].respond(payload([event(7, "req_page_two")]));
  await flush();

  app.elements["decision-filter"].value = "blocked";
  app.elements["event-type-filter"].value = "request_blocked";
  app.elements["request-id-filter"].value = "req_export";
  app.elements["export-csv"].dispatch("click");
  assert(app.calls.length === 3, "export starts one export request");
  assert(
    app.calls[2].url ===
      "/admin/export.csv?decision=blocked&event_type=request_blocked&request_id=req_export",
    "export uses current filters and omits page limit/cursor"
  );
  assert(
    app.elements["export-csv"].disabled &&
      app.elements["decision-filter"].disabled &&
      app.elements["next-page"].disabled,
    "export locks filters, navigation and itself while busy"
  );

  app.calls[2].respond(null, 200, true, {
    headers: { "X-Export-Row-Count": "126" },
    blobText: "seq,request_id\r\n1,req_export\r\n",
  });
  await flush();
  assert(app.objectUrls.length === 1, "successful export creates one blob URL");
  assert(app.revokedUrls.length === 1, "blob URL is revoked after download");
  assert(app.revokedUrls[0] === "blob:admin-page-test-1", "revocation targets the created URL");
  const anchors = app.created.filter(function (element) {
    return element.id === "a" || element.tagName === "a";
  });
  assert(anchors.length === 1, "export creates one download anchor");
  assert(anchors[0].download === "nasi-lemak-events-export.csv", "fixed download filename");
  assert(anchors[0].clicked === 1, "anchor click starts the download");
  assert(anchors[0].removed !== true && app.body.children.length === 0, "anchor is removed");
  assert(
    app.elements["status"].textContent === "Export prepared: 126 rows. Download requested.",
    "trusted row count is shown"
  );
  assert(
    app.elements["status"].textContent.indexOf("seq,request_id") < 0,
    "CSV content is not written into the page"
  );
  assert(app.elements["export-csv"].disabled === false, "export unlocks after success");
  assert(app.elements["decision-filter"].disabled === false, "filters unlock after success");
}

async function exportFailureShowsMessageAndNeverDownloads() {
  const app = createApp();
  connect(app, "secret-export-failure");
  app.calls[0].respond(payload([event(1, "req_page")]));
  await flush();

  const cases = [
    [413, "Export is too large. Narrow the filters and try again."],
    [401, "Access denied. Check the operator token."],
    [503, "Export is unavailable."],
  ];
  for (const [status, message] of cases) {
    const before = app.calls.length;
    app.elements["export-csv"].dispatch("click");
    assert(app.calls.length === before + 1, "each export attempt starts one request");
    app.calls[app.calls.length - 1].respond({}, status, false);
    await flush();
    assert(app.elements["status"].textContent === message, "mapped failure message for " + status);
    assert(app.elements["status"]["data-kind"] === "error", "export failure is an error");
    assert(app.objectUrls.length === 0, "failed export creates no blob URL");
    assert(app.revokedUrls.length === 0, "failed export revokes nothing");
    assert(
      app.created.filter(function (element) {
        return element.id === "a" || element.tagName === "a";
      }).length === 0,
      "failed export creates no download anchor"
    );
    assert(app.elements["export-csv"].disabled === false, "export unlocks after failure");
    assert(app.elements["apply-filters"].disabled === false, "filters unlock after failure");
  }
}

async function exportStaleCompletionCannotDownload() {
  const disconnected = createApp();
  connect(disconnected, "secret-export-disconnect");
  disconnected.calls[0].respond(payload([event(1, "req_page")]));
  await flush();
  disconnected.elements["export-csv"].dispatch("click");
  disconnected.elements["disconnect"].dispatch("click");
  assert(disconnected.calls[1].aborted === true, "disconnect aborts an export");
  disconnected.calls[1].respond(null, 200, true, {
    headers: { "X-Export-Row-Count": "1" },
    blobText: "seq\r\n1\r\n",
  });
  await flush();
  assert(disconnected.objectUrls.length === 0, "stale export after disconnect downloads nothing");
  assert(disconnected.elements["status"].textContent === "Disconnected.", "disconnect status stays");
  assert(disconnected.elements["export-csv"].disabled === false, "disconnect leaves controls unlocked");

  const pagehidden = createApp();
  connect(pagehidden, "secret-export-pagehide");
  pagehidden.calls[0].respond(payload([event(1, "req_page")]));
  await flush();
  pagehidden.elements["export-csv"].dispatch("click");
  pagehidden.window.dispatch("pagehide");
  assert(pagehidden.calls[1].aborted === true, "pagehide aborts an export");
  pagehidden.calls[1].respond(null, 200, true, {
    headers: { "X-Export-Row-Count": "1" },
    blobText: "seq\r\n1\r\n",
  });
  await flush();
  assert(pagehidden.objectUrls.length === 0, "stale export after pagehide downloads nothing");
  assert(pagehidden.elements["status"].textContent === "", "pagehide status stays empty");
}

async function technicalColumnsToggleAndReset() {
  const app = createApp();
  connect(app, "secret-columns");
  app.calls[0].respond(payload([event(1, "req_columns")]));
  await flush();

  assert(rows(app).length === 1, "event row renders");
  assert(rows(app)[0].length === 9, "every metadata cell stays in the DOM");
  assert(rows(app)[0][0] === "1", "sequence metadata is retained");
  assert(rows(app)[0][6] === "v-test", "policy version metadata is retained");
  assert(rows(app)[0][7] === "d".repeat(64), "policy digest metadata is retained");
  assert(rows(app)[0][8] === "pilot-local", "model metadata is retained");

  assert(
    app.elements["table-wrap"]["data-technical"] === "off",
    "technical columns start hidden"
  );
  assert(
    app.elements["toggle-technical"]["aria-expanded"] === "false",
    "toggle starts collapsed"
  );
  assert(
    app.elements["toggle-technical"].textContent === "Show technical columns",
    "toggle names the reveal action"
  );

  app.elements["toggle-technical"].dispatch("click");
  assert(
    app.elements["table-wrap"]["data-technical"] === "on",
    "toggle reveals technical columns"
  );
  assert(
    app.elements["toggle-technical"]["aria-expanded"] === "true",
    "toggle reports the expanded state"
  );
  assert(
    app.elements["toggle-technical"].textContent === "Hide technical columns",
    "toggle names the hide action"
  );

  app.elements["disconnect"].dispatch("click");
  assert(
    app.elements["table-wrap"]["data-technical"] === "off",
    "disconnect resets the technical view"
  );
  assert(
    app.elements["toggle-technical"]["aria-expanded"] === "false",
    "disconnect collapses the toggle state"
  );
  assert(
    app.elements["toggle-technical"].textContent === "Show technical columns",
    "disconnect restores the reveal label"
  );
}

async function lateExportCannotCrossSessions() {
  const app = createApp();
  connect(app, "secret-export-first");
  app.calls[0].respond(payload([event(1, "req_first")]));
  await flush();
  app.elements["export-csv"].dispatch("click");
  assert(app.calls.length === 2, "first session starts an export");

  app.elements["disconnect"].dispatch("click");
  connect(app, "secret-export-second");
  assert(app.calls.length === 3, "second session starts its own page request");

  app.calls[1].respond(null, 200, true, {
    headers: { "X-Export-Row-Count": "1" },
    blobText: "seq\r\n1\r\n",
  });
  await flush();
  assert(app.objectUrls.length === 0, "late export reply cannot download in a newer session");
  assert(app.elements["view-panel"].hidden === false, "new session view stays visible");

  app.calls[2].respond(payload([event(9, "req_second")]));
  await flush();
  assert(rows(app).length === 1 && rows(app)[0][2] === "req_second", "new session page renders");
  assert(app.elements["status"].textContent === "Events loaded.", "new session status survives");
  assert(app.elements["export-csv"].disabled === false, "new session export control unlocks");
}

async function main() {
  const scenarios = [
    ["stale success after disconnect", staleSuccessAfterDisconnect],
    ["later session survives older reply", laterSessionSurvivesOlderReply],
    ["pagehide clears and cannot repopulate", pagehideClearsAndCannotRepopulate],
    ["abort rejection is silent", abortRejectionDoesNotBecomeAnError],
    ["filters captured and controls unlock", filtersAreCapturedAndUnlockAfterSuccess],
    ["empty stream teaches the workspace", emptyStreamTeachesTheWorkspace],
    ["current failure clears and unlocks", currentFailureClearsAndUnlocks],
    ["export uses filters without page cursor", exportUsesFiltersWithoutPageCursor],
    ["export failure never downloads", exportFailureShowsMessageAndNeverDownloads],
    ["stale export cannot download", exportStaleCompletionCannotDownload],
    ["technical columns toggle and reset", technicalColumnsToggleAndReset],
    ["late export cannot cross sessions", lateExportCannotCrossSessions],
  ];
  for (const [name, scenario] of scenarios) {
    await scenario();
    console.log("ok - " + name);
  }
  console.log("admin_page_harness: all scenarios passed");
}

main().catch(function (error) {
  console.error("admin_page_harness failed: " + (error && error.stack ? error.stack : error));
  process.exitCode = 1;
});
