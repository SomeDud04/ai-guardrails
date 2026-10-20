---
name: dual-harness
description: Coordinate development tasks between Codex planning and review and an OpenCode Go implementation worker. Use for implementation, fixes, and refactoring in this project from either desktop harness.
---

# Codex + OpenCode Go

Run the same subscription-backed workflow from either harness. OpenCode Go implements;
Codex can plan and independently review, or the initiating Codex chat can inspect and
review the worker's actual results directly. The initiating chat reports the outcome.
This skill is portable at `.agents/skills/dual-harness` and discoverable by both
harnesses. OpenCode defaults to the `codex-coordinator` primary profile in this
project; its source-edit permissions are restricted to bridge request files. Use a new
session to pick up that default. Existing sessions keep their selected profile.

## Entry or assigned stage

- If the current assignment contains `DUAL_HARNESS_STAGE=...` or the environment
  sets `DUAL_HARNESS_STAGE`, execute that assigned stage directly. Never invoke
  this workflow recursively. Read the assignment to determine the stage's role.
- For a normal user development request, use the bridge below automatically.
- Answer explanations, status questions, and requests for planning only directly;
  do not start an implementation pipeline for those. Respect a user's explicit
  request to work with one harness only.

## Choose the delegation path

**Codex desktop chat (caller review).** Write one concise task file containing the
relevant context, the plan, and acceptance criteria. Then run the bridge with that
same file as both task and brief:

```powershell
$taskPython = 'C:\Users\user\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
& $taskPython .agents/skills/dual-harness/scripts/bridge.py run --project . `
  --task-file .orchestration/request-<unique-id>.md `
  --plan-file .orchestration/request-<unique-id>.md `
  --review-mode caller --task-class routine
```

Use `--task-class complex` only for genuinely difficult work. No second Codex
planner or reviewer is needed on this path: `--plan-file` skips Codex planning and
`--review-mode caller` skips Codex review. The result is `awaiting_review`, a
completed implementation handoff, not approval. Wait for it, then inspect the actual
changed files, change report, and validation evidence in the initiating Codex chat
before reporting completion. The bridge does not auto-repair or mark these changes
approved in caller mode.

**OpenCode default coordinator (independent Codex review).** Prepare the task and
brief, then pass the brief with `--plan-file` and keep `--review-mode codex`:

```powershell
& $taskPython .agents/skills/dual-harness/scripts/bridge.py run --project . `
  --task-file .orchestration/request-<unique-id>.md `
  --plan-file .orchestration/request-<unique-id>.md `
  --review-mode codex --task-class routine
```

The same file may serve as both task and brief. One independent Codex review remains
mandatory on this path. The coordinator stays lightweight; it routes work and reports
the actual result rather than implementing source changes itself.

**Legacy planning.** Omitting `--plan-file` in `codex` mode retains standalone Codex
planning followed by review. An empty supplied brief is rejected rather than silently
falling back.

## Run a development task

1. Preserve the user's task, constraints, relevant conversation decisions, plan, and
   acceptance criteria in one concise `.orchestration/request-<unique-id>.md` file.
   Do not include credentials or an entire chat transcript. Create the folder if needed.
2. Run the bridge command from the project root. Select `--task-class` explicitly.
   Do not infer complexity from keywords and do not use another model to classify the
   request.
3. Keep the call running and wait for the result. Prefer bounded long waits on the
   existing shell session, up to 60 seconds per tool wait in Codex. Use additional
   turns only for a meaningful state change, a failure, required input, or the final
   result. Do not add timers that prompt either model, model-driven status polling,
   heartbeat inference, monitoring agents, parallel implementations, or repeated log
   rereading.
4. Read the returned job's `result.json`, worker report, and change report. In caller
   mode, inspect the actual changed files and rerun relevant checks where possible
   before reporting completion. In codex mode, read the independent review.
   `approved` means the Codex review accepted the changes; it does not mean deployed or
   human-approved. `awaiting_review` is a handoff awaiting caller inspection.
   `needs_attention` and `failed` are incomplete work, not success.

## Models and usage

Worker settings are in `settings.json`. Routine work defaults to
`opencode-go/deepseek-v4.1-flash`; `--task-class complex` selects the configured
`opencode-go/kimi-k2.7-code`. Both are validated as explicit Go-provider models.
Escalate to the complex model only through explicit task classification or a reviewed
repair decision; never silently switch providers, enable balance fallback, or change
authentication.

A worker naturally makes multiple internal model/tool turns while coding; those turns
use Go quota. An idle OpenCode app or browser, or a coordinating process simply
waiting, does not itself run new model inference. The parent's generated progress
messages and reviews still use its model usage. These choices conserve calls; they do
not promise mathematically optimal token usage.

## Runtime behavior

The bridge finds the CLI bundled with OpenCode Desktop, uses its saved Console
authentication with an explicit `opencode-go/` model, and reuses Codex CLI's saved
ChatGPT sign-in. It never extracts or transfers tokens.

Planning and review use Codex's read-only sandbox. Implementation uses OpenCode's
normal permissions; OpenCode is not contained by the Codex sandbox. Do not bypass
permissions or add `--auto`. A permissions/authentication failure needs an accurate
report and the appropriate supported authorization, not a weaker permission mode.
Worker context stays focused on the task and relevant paths, and the final report is
concise (about 300 words maximum).

## Show the actual worker

The user wants to watch the actual OpenCode session whenever it works. Each job
creates a named `Codex worker | <job-id>` chat on the same local service as
OpenCode Desktop. The bridge prints its live URL and automatically opens that
actual OpenCode web view. Repair rounds reuse the same worker chat. Keep the live
view available while waiting; do not substitute a synthetic progress dashboard.
The same named chat is available in the desktop app's recent sessions.

On first use in a browser, run `bridge.py connect-browser --project .` to open a
one-time local pairing link. This uses the supported local pairing flow; never
export saved tokens, disable authentication, or enable remote service access.
The initiating agent can also open the printed live URL in the in-app browser.
The URL and session ID are saved in the job's `opencode-session.json`. A browser
launch request is not proof that the view loaded; verify the real session is
visible when establishing or repairing this setup.

## Bounds and diagnosis

One bridge job holds a workspace lock. Two repair rounds are allowed after the
initial implementation in `codex` mode. Caller mode performs one implementation round
and returns `awaiting_review`; the caller decides whether to request a scoped repair
run. Stage logs and file hashes/diffs live in `.orchestration`. Existing non-Git and
uncommitted files are part of the baseline. The lock coordinates bridge jobs, not
independent edits made manually or in another chat.

Run `bridge.py doctor --project .` for local executable/configuration discovery.
It does not prove subscription access or a successful model call. For installation,
verification, recovery and limitations, read [the setup notes](references/setup.md).
