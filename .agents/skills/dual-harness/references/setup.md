# Setup, use and recovery

This project uses the shared `.agents/skills/dual-harness` skill, root `AGENTS.md`
routing, `.opencode/agents/bridge-worker.md`, and the default `codex-coordinator`
primary profile in `.opencode/opencode.jsonc`. No additional subscription,
API key, MCP package, or separate OpenCode installation is required on this machine.
OpenCode Desktop 2.0.32 bundles the worker executable. Codex CLI is
0.163.0-alpha.10.2. These versions were inspected on 2026-10-19.

## Use

Start a new chat against this project in either desktop app after setup. OpenCode
new chats use `codex-coordinator`; existing chats keep their selected profile.
Select that profile or start a new chat to enable routing there. Ordinary
implementation/fix/refactor requests are routed by `AGENTS.md`. In Codex you can
also explicitly invoke `$dual-harness`; in OpenCode mention `@dual-harness`.
Automatic routing is agent guidance, not unconditional interception of every
prompt. Existing conversations may retain older instructions. This setup is
project-scoped; unrelated projects do not inherit its routing.

### Two delegation paths

**Codex desktop chat, caller review.** Write one concise task file containing the
relevant context, plan, and acceptance criteria. Pass that same file as both task
and brief, select the explicit task class, and request caller review:

```powershell
& $taskPython .agents/skills/dual-harness/scripts/bridge.py run --project . `
  --task-file .orchestration/request-<unique-id>.md `
  --plan-file .orchestration/request-<unique-id>.md `
  --review-mode caller --task-class routine
```

`--plan-file` skips the Codex planning call; `--review-mode caller` skips the Codex
review call. The job returns `awaiting_review` after implementation and change-report
creation. That is a completed handoff, not approval: inspect the actual changed files
and rerun relevant tests in the initiating Codex chat before reporting completion.
Caller mode performs no automatic repair. No second Codex planner or reviewer is
needed on this path.

**OpenCode default coordinator, independent Codex review.** Prepare the brief and
keep Codex review mandatory:

```powershell
& $taskPython .agents/skills/dual-harness/scripts/bridge.py run --project . `
  --task-file .orchestration/request-<unique-id>.md `
  --plan-file .orchestration/request-<unique-id>.md `
  --review-mode codex --task-class routine
```

The coordinator should stay lightweight: route the work and report the actual
result. Omitting `--plan-file` in `codex` mode retains standalone Codex planning as
a legacy default. An empty supplied brief is rejected; it does not silently fall back.

### Models and classification

Routine work defaults to `opencode-go/deepseek-v4.1-flash`; genuinely difficult work
uses the configured `complex_worker_model`, `opencode-go/kimi-k2.7-code`. Both are
validated as explicit Go-provider models. Select the class explicitly on the command
line; do not infer complexity from keywords or use another model to classify the
request. Escalate to the complex model only through explicit task classification or a
reviewed repair decision. Do not silently switch providers, enable balance fallback,
or change authentication. To use a different Go model, verify its identifier with
`opencode models`, then update `worker_model` or `complex_worker_model` in the skill's
`settings.json`. Codex uses its configured model. Both harnesses retain their own
saved authentication. No token export is used.

The project OpenCode config sets its default model to
`opencode-go/deepseek-v4.1-flash` while retaining the `codex-coordinator` default
agent. New OpenCode chats pick it up; existing chats keep their selected model.

### Live worker session

Each job creates a named worker session on the existing shared desktop service.
The bridge opens its actual OpenCode web UI automatically and prints its live URL.
Repairs reuse that chat. The same named chat appears in OpenCode Desktop's recent
sessions. Run `bridge.py connect-browser --project .` once to pair the default
browser through a short-lived local link. If the browser session expires, repeat
that command. No server password is exported and remote access is not enabled.
On timeout, the bridge interrupts only its worker through the session API and
checks the shared service's active-session list before releasing the lock. If
termination cannot be confirmed, a blocking recovery lock remains. Killing only
the waiting CLI would not stop a shared-service worker.

## Verification

Use Python 3.11 or later. This machine has a working interpreter at
`C:/Users/user/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe`.

- Run `scripts/bridge.py doctor --project <project>` from the skill folder to
  discover local executables, worker definitions, and configured routine/complex
  models. This does not prove authentication, available quota or model access.
- Run `python -m unittest discover -s tests -v` from the project root for the
  existing project tests and bridge contracts, including supplied-plan and
  caller-review behavior. The managed Windows shell can require approved execution
  outside its sandbox to use Python temporary folders.
- Live smoke evidence is recorded under `.orchestration/smoke/.orchestration`.
  Contract tests alone do not prove live model access or routing from a fresh
  desktop conversation. Do not run additional paid model tests merely to verify
  routing or documentation changes; mock external harness calls in contract tests.

## Waiting and usage

The bridge keeps `subprocess.communicate`'s blocking wait. Prefer bounded long waits
on the existing shell session, up to 60 seconds per tool wait in Codex. Use additional
turns only for a meaningful state change, a failure, required input, or the final
result. Do not add timers that prompt either model, model-driven status polling,
heartbeat inference, monitoring agents, parallel implementations, or repeated log
rereading.

A worker naturally makes multiple internal model/tool turns while coding; those turns
use Go quota. An idle OpenCode app or browser, or a coordinating process simply
waiting, does not itself run new model inference. The parent's generated progress
messages and reviews still use its model usage. These choices conserve calls; they do
not promise mathematically optimal token usage.

## Failure and concurrency

`failed` means a provider, process, parser, permission or stability check failed.
`needs_attention` means findings remained after the repair limit. Neither means
completion. `approved` means the independent Codex review accepted the change;
it is not deployment or human approval. `awaiting_review` means caller mode finished
implementation and produced a report; it is a handoff, not approval, and the caller
must inspect the actual changes and tests. No automatic rollback occurs; inspect
changes before retrying because the worker may already have edited files.

A stage times out after 15 minutes; at most two repair rounds follow the first
implementation in `codex` mode. Caller mode performs one implementation round and
returns `awaiting_review`; a caller that wants changes should start a new scoped run
with explicit classification. If a lock remains after abnormal termination, read
`.orchestration/active.lock`, verify the recorded PID and worker processes, and
remove only that lock once work has stopped. Never clear it just to retry.

The lock coordinates bridge jobs only. Avoid manual edits to the same workspace
during a run. Planning and review use Codex's read-only sandbox. OpenCode uses
its own normal permissions, not the Codex OS sandbox. Do not bypass denied
operations through another harness. A review may be unable to rerun tests that
write files; state that limit and inspect the worker's validation evidence.

Snapshots cover existing source files, including non-Git and uncommitted work.
They exclude caches, `.orchestration`, environment files, private-key formats and
databases. Large/binary changes are listed without a text diff. Snapshots are
review evidence, not complete backups or a security boundary. Review actual
changed files too. Request files and logs can contain project context and should
not contain secrets. The folder is excluded by `.gitignore`.

To disable automatic routing, remove the routing paragraphs from root `AGENTS.md`
and remove `default_agent` from `.opencode/opencode.jsonc`.
The skill and worker can remain available for explicit use. No global application
configuration needs restoring.

## Official references

- [OpenCode V2 CLI](https://opencode.ai/v2/docs/cli/)
- [OpenCode V2 shared skill discovery](https://opencode.ai/v2/docs/skills/)
- [OpenCode V2 project instructions](https://opencode.ai/v2/docs/instructions/)
- [OpenCode V2 agents](https://opencode.ai/v2/docs/agents/)
- [Codex automation and saved authentication](https://learn.chatgpt.com/docs/non-interactive-mode)
- [Codex skills](https://learn.chatgpt.com/docs/build-skills)
