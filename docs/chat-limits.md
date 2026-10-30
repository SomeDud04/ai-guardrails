# Chat context and reply limits

This page documents the non-secret bounds shared by `POST /v1/chat/completions`
and `/workspace`. They are configuration only: they do not prove a provider's
model window, guard quality or available throughput.

## Settings

| Variable | Default | Allowed | Unit |
|---|---|---|---|
| `NASI_LEMAK_CHAT_CONTEXT_MESSAGES` | 32 | 1..32 | messages (current prompt included) |
| `NASI_LEMAK_CHAT_CONTEXT_BUDGET` | 8192 | 1..32768 | conservative serialized UTF-8 units |
| `NASI_LEMAK_CHAT_DEFAULT_REPLY_TOKENS` | 1024 | 1..max reply | requested provider tokens |
| `NASI_LEMAK_CHAT_MAX_REPLY_TOKENS` | 4096 | 1..8192 | requested provider tokens |

`NASI_LEMAK_CHAT_CONTEXT_BUDGET` counts the complete serialized conversation,
including `role: content` framing. It is not a tokenizer count and not a
provider model-window claim. The gateway, guards and workspace validate values
at startup; an explicitly invalid value leaves the app live but not ready rather
than silently substituting a different limit. All four settings are optional: an
omitted or blank value keeps its application default. If
`NASI_LEMAK_CHAT_MAX_REPLY_TOKENS` is explicitly lowered and the default reply
value is omitted or blank, the reply default is clamped down to that maximum
rather than failing; an explicitly set default above the maximum is invalid.
These are gateway bounds, not claims about a provider's context window.

Pilot note: the CPU output scan takes roughly 10 s for a short reply and about
31 s for a ~1,000-token reply, so the pilot recommends
`NASI_LEMAK_CHAT_DEFAULT_REPLY_TOKENS=384` together with the concise-generation
instruction in `NASI_LEMAK_GENERATION_SYSTEM_PROMPT`. Both are optional; the
code defaults remain 1024 and no prompt.

## Precedence: env ceiling, then policy

The environment values (or their built-in defaults) are hard ceilings. The
optional top-level `limits` mapping in the startup policy may contain any subset
of `context_messages`, `context_budget`, `default_reply_tokens` and
`max_reply_tokens`; the effective value is `min(env value, policy value)` per
field. A policy value above the ceiling is clamped rather than rejected. A
malformed policy value (non-integer, boolean, zero/negative, unknown key or a
policy `default_reply_tokens` above its own `max_reply_tokens`) is a policy
error, so the server stays live but not ready. When `limits` is absent the
policy digest is unchanged; when present it is included canonically.

The same effective limits are used by `/v1`, `/chat` and `/workspace` turns.
Any later workspace profile layer, when configured, applies after this shared
tightening step and cannot widen it. `/admin` shows the effective value, the env
ceiling and the winning source (`env` or `policy`) read-only.

The context budget and the operator policy `token_budget` both apply separately.
They are not reduced to a numeric minimum because they use different units:
`token_budget` is the adapter/tokenizer counter budget (default 512, ceiling
32768), while `context_budget` is the conservative UTF-8 serialization budget.

## Rolling context, not full saved history

The workspace still persists the full conversation. For each reply it validates
and decrypts the stored history through `read_context`, then selects the most
recent complete user/assistant pairs that fit the message and byte limits. The
latest prompt is always included and is never truncated; an oversized latest
prompt fails with `413`. The response reports `selected_messages`,
`omitted_messages`, `context_budget` and `policy_token_budget`.

Because all stored history is validated and decrypted to build that selection,
SQL and decryption work still scales with saved history. This is not a bounded
query or an unlimited-capacity claim. The model receives only the selected
window and may not remember omitted older details.

The reply selector offers the configured default, a shorter and a longer
reviewed value. The server still validates every requested `max_tokens` against
`NASI_LEMAK_CHAT_MAX_REPLY_TOKENS`; the selector is not an authorization bypass.
The latest oversized prompt/context returns `413`. If a required guard path is
unavailable, chat returns the existing generic `503`; limits never bypass a
guard.

## Guard windows

The Groq input guard is chunked into sequential windows of at most 480
conservative units including framing, with a 64-UTF-8-byte overlap, a maximum of
128 segments and a 32768 sum-of-window-units cap before any HTTP request. It
also uses a 30 s deadline, request cancellation and the remaining timeout. Every
window must be valid for the guard result to allow. Cloudflare output input is
bounded to 32 messages and 64 KiB encoded input.

More segments mean more provider requests, quota use and latency; chunking is
not a detection or throughput guarantee. Cross-window semantic attack efficacy
is unverified, and the overlapping lexical fixture is not live quality proof.
Native and custom guards keep their own coverage, message and response caps;
Groq chunking does not activate for them, so configure lower context/reply
bounds if their limits are smaller.

Each stored user prompt and assistant response is limited to 65536 characters.
That is a per-message bound, not a conversation total: full conversation
history is retained until an operator manually deletes it. Ciphertext format is
unchanged, so this feature needs no database migration.

## Deployment update

Preserve the existing keys, database volume, policy files and guard mode. Do not
rerun `install.sh` and do not use `docker compose down -v`. Create the chat-limits
env file only if it does not exist, then edit the non-secret values:

```bash
test -e .secrets/compose.chat-limits.env || \
  cp docs/compose.chat-limits.env.example .secrets/compose.chat-limits.env
chmod 600 .secrets/compose.chat-limits.env
${EDITOR:-nano} .secrets/compose.chat-limits.env
```

The base `compose.yaml` declares the four names as bare pass-through entries
with no hardcoded default; the mode, API, workspace and demo overlays inherit
them. Do not deploy or validate with `compose.yaml` alone: it has no configured
guard mode or policy, so the gateway can remain unready. Always keep the base
file together with the exact existing mode env file and overlay, and always
place `--env-file .secrets/compose.chat-limits.env` **after** every existing env
file in the matching preflight, build and up commands.

API guarded mode:

```bash
python3 scripts/check_hosted_setup.py \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.hosted-guards.env \
  --env-file .secrets/compose.chat-limits.env \
  -f compose.yaml -f compose.api.yaml

sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.hosted-guards.env \
  --env-file .secrets/compose.chat-limits.env \
  -f compose.yaml -f compose.api.yaml build gateway

sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.hosted-guards.env \
  --env-file .secrets/compose.chat-limits.env \
  -f compose.yaml -f compose.api.yaml \
  up -d --no-deps --force-recreate gateway
```

API plus workspace:

```bash
python3 scripts/check_hosted_setup.py \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.hosted-guards.env \
  --env-file .secrets/compose.workspace.env \
  --env-file .secrets/compose.chat-limits.env \
  -f compose.yaml -f compose.api.yaml -f compose.workspace.yaml

sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.hosted-guards.env \
  --env-file .secrets/compose.workspace.env \
  --env-file .secrets/compose.chat-limits.env \
  -f compose.yaml -f compose.api.yaml -f compose.workspace.yaml build gateway

sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.hosted-guards.env \
  --env-file .secrets/compose.workspace.env \
  --env-file .secrets/compose.chat-limits.env \
  -f compose.yaml -f compose.api.yaml -f compose.workspace.yaml \
  up -d --no-deps --force-recreate gateway
```

Full base plus API, workspace and demo ingress:

```bash
python3 scripts/check_hosted_setup.py \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.hosted-guards.env \
  --env-file .secrets/compose.workspace.env \
  --env-file .secrets/compose.demo.env \
  --env-file .secrets/compose.chat-limits.env \
  -f compose.yaml -f compose.api.yaml -f compose.workspace.yaml -f compose.demo.yaml

sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.hosted-guards.env \
  --env-file .secrets/compose.workspace.env \
  --env-file .secrets/compose.demo.env \
  --env-file .secrets/compose.chat-limits.env \
  -f compose.yaml -f compose.api.yaml -f compose.workspace.yaml -f compose.demo.yaml \
  build gateway nginx

sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.hosted-guards.env \
  --env-file .secrets/compose.workspace.env \
  --env-file .secrets/compose.demo.env \
  --env-file .secrets/compose.chat-limits.env \
  -f compose.yaml -f compose.api.yaml -f compose.workspace.yaml -f compose.demo.yaml \
  up -d --no-deps --force-recreate gateway
```

Test or pilot deployments use their existing mode env file and overlay instead
of the hosted API pair; keep `--env-file .secrets/compose.chat-limits.env` last.
After recreate, confirm all four non-secret values reached the container without
printing any secret:

```bash
sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.hosted-guards.env \
  --env-file .secrets/compose.chat-limits.env \
  -f compose.yaml -f compose.api.yaml exec -T gateway \
  printenv NASI_LEMAK_CHAT_CONTEXT_MESSAGES \
    NASI_LEMAK_CHAT_CONTEXT_BUDGET \
    NASI_LEMAK_CHAT_DEFAULT_REPLY_TOKENS \
    NASI_LEMAK_CHAT_MAX_REPLY_TOKENS
```

## Raising the hosted policy budget

Existing policy files are never overwritten. Older policies may still say 256.
For larger Groq context, copy the approved file, keep every other actual
approved field unchanged (`app_id`, `model`, `deny_phrases` and anything else
present), assign a new reviewed `version`, and change only the budget line:

```yaml
token_budget: 8192
```

Never replace a working policy with placeholder values; substituting
placeholders for real approved fields previously caused downtime. Point the
policy mount at the new file and recreate the gateway. This is an
explicit reviewed budget change, not an automatic consequence of raising the
chat context limits. Notifications, SSO and an admin policy editor are out of
scope.
