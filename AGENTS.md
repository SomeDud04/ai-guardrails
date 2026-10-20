# Project agent instructions

For user requests to implement, fix, or refactor this project, automatically read
and follow `.agents/skills/dual-harness/SKILL.md`. OpenCode Go implements. Carry
relevant conversation constraints into one concise task file containing the context,
plan, and acceptance criteria. Do not require the user to repeat a delegation
instruction.

From a Codex desktop chat, run the bridge with `--plan-file SAME_TASK_FILE`,
`--review-mode caller`, and an explicit `--task-class` (`routine` by default;
`complex` only for genuinely difficult work). Wait for `awaiting_review`, then
inspect the actual changed files and tests in the initiating chat before reporting
completion. No second Codex planner or reviewer is needed on that path. From
OpenCode's default `codex-coordinator`, pass the prepared brief with `--plan-file`
and use `--review-mode codex`, so one independent Codex review remains mandatory.
The coordinator stays lightweight.

After a completed development slice passes verification and caller review, read and
follow `.agents/skills/push-completed-work/SKILL.md` before the final completion
response. Commit and push the reviewed slice to this repository's existing origin
unless the user cancels or explicitly says not to push. Worker stages never commit
or push.

Loading the skill alone is not delegation: run the bridge and inspect or obtain its
final review before reporting the task complete. `awaiting_review` is a completed
handoff, not approval. The initiating assistant must not edit source itself. Writing
the task file and bridge job records is part of the routing. Wait on the existing
shell session with bounded long waits (up to 60 seconds per tool wait in Codex);
use additional turns only for meaningful state changes, failure, required input, or
the final result. Do not add polling, heartbeat inference, monitoring agents,
timers, parallel implementations, or repeated log rereading. The worker's internal
model/tool turns use Go quota; an idle browser or a waiting coordinator does not run
new inference.

An assignment marked `DUAL_HARNESS_STAGE` is already a delegated stage: perform
that assignment directly and never start another bridge, harness, or subagent.
Explanations, status questions, and planning-only requests can be answered directly.
A direct user request for a single harness overrides the automatic workflow.

This is a synthetic in-process gateway foundation. Preserve the distinction
between local demo/test evidence and production outcomes. See `README.md` for
the existing scope and verification commands. Do not send real infrastructure
requests merely to test the orchestration integration.
