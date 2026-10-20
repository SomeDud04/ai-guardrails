---
name: push-completed-work
description: Commit and push a verified development slice to this repository's existing origin. Use when a reviewed implementation slice completes, or when the user asks to commit or push completed work.
---

# Push completed work

The user has given standing authorization for normal commits and pushes to this
repository's existing `origin`. Routine pushes need no repeated confirmation.
This authorization is repository-scoped; it grants nothing for other repositories.

A worker or implementer stage must not commit or push. The initiating coordinator
performs these steps only after it has reviewed the actual worker diff and verified
the slice.

## Completion gate

Treat a slice as complete only when all of the following are true:

- The acceptance criteria are met.
- The appropriate checks have been run and passed, or skipped checks are recorded.
- The actual worker changes were inspected by the reviewer. A bridge state such as
  `awaiting_review` is a handoff, not approval.

Do not commit partial work. If the gate is not met, stop and report what is missing.

## Commit and push

1. Confirm scope and stop conditions.
   - User cancellation or an explicit no-push instruction overrides the standing
     preference.
   - If there are no relevant changes, fetch and verify the current upstream state
     instead of creating an empty commit.

2. Verify the remote and branch.
   - Run `git remote -v` and confirm `origin` is the expected repository:
     `https://github.com/SomeDud04/ai-guardrails.git`.
   - Run `git branch --show-current` and `git status -sb` to identify the current
     branch and its upstream.
   - Follow the current branch. Never switch branches, force push, rewrite history,
     or change the remote to make a push succeed.

3. Stage explicitly by path.
   - Add only files that belong to the reviewed slice:
     `git add -- <path> [<path> ...]`.
   - Do not use `git add -A`, `git add .`, or any stage-all form.
   - Run `git diff --cached` and inspect the whole staged diff. Exclude credentials,
     secrets, generated or local artifacts, unrelated existing work, and anything
     outside the reviewed slice.

4. Commit.
   - Write a concise message describing the completed slice.
   - If author identity is not configured for the repository, reuse the author
     convention from existing commits with repository-local configuration or a
     one-off `git -c user.name=... -c user.email=... commit`. Do not change global
     Git identity.

5. Push normally.
   - Push the current branch to its existing upstream with a normal push. Do not force.
   - After pushing, verify that the remote branch SHA equals the local commit:
     `git ls-remote origin refs/heads/<branch>` and `git rev-parse HEAD`.
   - Report the commit SHA, the commit link, and any checks skipped or limitations.

6. Handle failure accurately.
   - On non-fast-forward, authentication, permission, or network failure, keep the
     local commit intact.
   - Report that the push is pending with the exact error. Never bypass permissions,
     alter history, or claim a push succeeded when it did not.
