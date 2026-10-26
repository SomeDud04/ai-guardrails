# Hosted guard setup (Groq input, Cloudflare output)

Status: **manual, opt-in example only.** The hosted adapters are implemented and
tested against synthetic loopback fixtures. No real Groq or Cloudflare request,
key or account was used in this workspace, so live API compatibility, accuracy,
quota, latency and data-flow approval remain pending. The configured guard
models are inactive until the environment, key files, restart and a later
verification are completed. A ready health response proves composition, not
guard quality.

Current `install.sh` JSON **v1 still writes the old custom `/classify` input
contract and the Qwen3Guard output adapter**. It has no hosted-provider wizard.
Do not claim that `--guard-backend api` activates this hosted pair. Use the
manual Compose example below, or keep the existing installer flow unchanged.

## 1. Preserve the existing deployment

Use the existing checkout and deployment files. Pull reviewed code only:

```bash
cd /path/to/existing/ai-guardrails
git pull --ff-only
```

Do not run `install.sh` merely to update code. Do not run `docker compose down
-v`: it removes the PostgreSQL audit/workspace volume. Keep the existing
`.secrets/compose.env`, operator policy, database volume and key files. This
slice changes no installer, auth, workspace or storage behaviour.

When moving from an existing test environment, preserve its generation URL,
model and auth mode, any custom `GATEWAY_PORT`, and the same generation secret
mechanism (key file or env-file value). Do not assume those values live in
`.secrets/compose.env`: copy the non-secret values into the one env file you
actually use, or keep the existing env file that already supplies them. Keep
one appropriate env-file chain for the deployment mode; do not keep
`compose.test.yaml` or combine it with `compose.api.yaml`. Generation auth mode
and its secret source must remain unchanged.

## 2. Create the two dedicated key files safely

Prompt Guard and Llama Guard need separate bearer key files. Neither is the
generation/chat key. Run this in bash: the guard refuses to overwrite either
existing file **before any key is prompted for**, so an existing key is never
truncated or replaced. The `umask 077` keeps new files private from creation,
and `noclobber` makes creation exclusive even if another process races the
pre-check. Keys are read with `read -r -s` and are never echoed, placed in shell
history or passed as a command argument. The `EXIT` trap clears both variables
on every path.

```bash
set -euo pipefail

install -d -m 0700 .secrets

for key_file in .secrets/input_guard_key .secrets/output_guard_key; do
  if [ -e "$key_file" ] || [ -L "$key_file" ]; then
    printf 'Refusing to overwrite existing %s. Preserve it or move it aside yourself.\n' "$key_file" >&2
    exit 1
  fi
done

trap 'unset INPUT_KEY OUTPUT_KEY' EXIT
umask 077

read -rsp 'Groq API key: ' INPUT_KEY; printf '\n'
( set -o noclobber; printf '%s' "$INPUT_KEY" > .secrets/input_guard_key )
unset INPUT_KEY

read -rsp 'Cloudflare API token: ' OUTPUT_KEY; printf '\n'
( set -o noclobber; printf '%s' "$OUTPUT_KEY" > .secrets/output_guard_key )
unset OUTPUT_KEY

sudo chown 10001:10001 .secrets/input_guard_key .secrets/output_guard_key
sudo chmod 0400 .secrets/input_guard_key .secrets/output_guard_key
```

Accepted metadata follows the existing documented pattern: owner UID/GID
`10001` with mode `0400`/`0600`, or runtime group `10001` with mode `0440`/`0640`.
The container runs as the non-root UID `10001`; owner `10001` with mode `0400`
matches the existing runtime. Never use `chmod a+r`, do not `chmod` the whole
`.secrets` directory broadly, never pass a key on a command line, and never
paste a key into Git, chat or an env file.

If the deployment already has guard key files, the snippet above stops and
leaves them untouched. Preserve them and only verify that they are readable by
UID `10001`. A missing or unreadable file leaves the app unready; there is no
fallback to another key.

## 3. Configure the nonsecret hosted env file

Copy the example, open it in a plain editor, and replace every absolute path and
the Cloudflare account placeholder yourself:

```bash
cp docs/compose.hosted-guards.env.example .secrets/compose.hosted-guards.env
nano .secrets/compose.hosted-guards.env
```

Replace every `/ABSOLUTE/...` value with its real absolute path. In
`NASI_LEMAK_OUTPUT_GUARD_URL`, replace the literal token `ACCOUNT_ID` inside
`accounts/ACCOUNT_ID/ai/v1` with the real Cloudflare account identifier. Do not
try to substitute the real identifier with a pattern that matches the real value
instead of the placeholder, and do not save the real identifier in this repository,
the example file or chat. Keep the key files separate from this env file.

After saving, do not grep the env file to check the placeholders: a matching
line would print the whole configuration line. Use the field-only read-only
preflight in section 6 instead. It inspects the resolved configuration, reports
an unresolved placeholder by field path and never prints a configured value.
Re-run it after editing this file and continue only after `Preflight OK`.

The example contains the required pair:

```text
NASI_LEMAK_INPUT_GUARD_PROVIDER=groq-prompt-guard
NASI_LEMAK_OUTPUT_GUARD_PROVIDER=cloudflare-llama-guard
NASI_LEMAK_INPUT_GUARD_MODEL=meta-llama/llama-prompt-guard-2-86m
NASI_LEMAK_OUTPUT_GUARD_MODEL=@cf/meta/llama-guard-3-8b
NASI_LEMAK_INPUT_GUARD_URL=https://api.groq.com/openai/v1
NASI_LEMAK_OUTPUT_GUARD_URL=https://api.cloudflare.com/client/v4/accounts/ACCOUNT_ID/ai/v1
```

Both selectors must be present together. Omitting both keeps the old custom
input contract and Qwen3Guard output; setting only one, an explicitly empty or
whitespace-only value, or any unknown value leaves the app unready before any
key file or HTTP call. Both hosted providers require `AUTH=bearer`; `none` is
rejected for this pair. The input threshold is explicit and uncalibrated; the
example uses `0.5`.

## 4. Respect the complete-input size limit

The Groq adapter sends the **complete serialized accepted conversation** as one
user message, including every role, every turn and the `role: content` framing.
That complete serialized text must fit the conservative 480-byte UTF-8 budget
before any Groq request. This is a byte budget, not 480 user characters, not a
token count and not a chunking allowance. Longer single prompts, or a
multi-turn conversation whose accumulated serialized turns exceed the budget,
fail closed with no HTTP request. The adapter does not tokenize, truncate or
split input; a long-context design needs separate approval.

## 5. Data flow and approval status

The existing pipeline order is unchanged:

- **Groq input guard** currently receives the original accepted conversation
  context, serialized with roles, **before PII masking**.
- **Generation** receives the PII-masked prompt context.
- **Cloudflare output guard** receives the masked prompt context plus the
  buffered raw generation output, **before final output masking**.

Use synthetic content only until external data flow to both providers is
explicitly approved. The guard models must not receive real employee or
customer content merely because the deployment starts successfully.

## 6. Preflight, rebuild and recreate the gateway with the correct overlays

Run the read-only preflight **before** any rebuild or recreate. It invokes only
`docker compose ... config --format json` with exactly the env files and overlays
you are about to deploy, in the same order, then checks the resolved local bind
sources and file-based secrets. It never builds, starts, stops or removes a
container, never reads secret file contents, never contacts a provider and never
prints the rendered configuration or child stderr. If your Docker socket requires
`sudo`, prefix the preflight command with `sudo` as well.

Without the workspace or demo ingress:

```bash
python3 scripts/check_hosted_setup.py \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.hosted-guards.env \
  -f compose.yaml -f compose.api.yaml
```

With the existing workspace overlay and nginx demo ingress:

```bash
python3 scripts/check_hosted_setup.py \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.hosted-guards.env \
  --env-file .secrets/compose.workspace.env \
  --env-file .secrets/compose.demo.env \
  -f compose.yaml -f compose.api.yaml -f compose.workspace.yaml -f compose.demo.yaml
```

Continue only after it prints `Preflight OK`. `--force-recreate` alone does **not**
build newly pulled code, so build and recreate explicitly. The full commands are
deliberately repeated rather than kept in a hidden `BASE` array: a shell array
does not survive a new shell or tmux pane, and an empty array silently turns the
intended command into a different one. If you do use an array, define it in the
same shell and fail when it is unset or empty.

Before running the build/up pair that deploys the new code, record the
deployment time and keep it with the image ID for section 7:

```bash
deployed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
```

Without the workspace or demo ingress:

```bash
sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.hosted-guards.env \
  -f compose.yaml -f compose.api.yaml \
  build gateway

sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.hosted-guards.env \
  -f compose.yaml -f compose.api.yaml \
  up -d --no-deps --force-recreate gateway
```

With the existing workspace overlay and nginx demo ingress:

```bash
sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.hosted-guards.env \
  --env-file .secrets/compose.workspace.env \
  --env-file .secrets/compose.demo.env \
  -f compose.yaml -f compose.api.yaml -f compose.workspace.yaml -f compose.demo.yaml \
  build gateway nginx

sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.hosted-guards.env \
  --env-file .secrets/compose.workspace.env \
  --env-file .secrets/compose.demo.env \
  -f compose.yaml -f compose.api.yaml -f compose.workspace.yaml -f compose.demo.yaml \
  up -d --no-deps --force-recreate gateway nginx
```

`compose.api.yaml` replaces the old test/pilot mode overlay; it is never combined
with `compose.test.yaml` or `compose.pilot.yaml`. Follow the existing layout: base
+ API mode + workspace (if enabled) + demo/nginx ingress (if enabled). The
existing nginx service already forwards the gateway routes; no new nginx
configuration is introduced here. Add `-f compose.api-ca.yaml` only when both
approved endpoints use a private CA, and preserve the existing workspace secrets,
the database volume and the operator policy.

A failed `up --force-recreate` can stop the existing container before the new one
starts. Do not debug on the stopped stack. Restore the last known-good env/overlay
set, rerun the read-only preflight, then build and recreate with that same set.
Never use `docker compose down -v`: it removes the database volume and the saved
workspace content. Use `stop`/`start` for maintenance. For later reviewed code
updates, repeat the same preflight/build/up sequence; `up -d` alone reuses the
existing image.

### Temporary local User-Agent patch when pulling upstream

Earlier deployments carried a one-line local patch adding
`User-Agent: nasi-lemak-gateway/0.1` to `nasi_lemak/generation.py`. Reviewed code
now sends the same value from the shared transport. Before pulling, inspect both
the working-tree and index state for that file:

```bash
git status --short
git diff -- nasi_lemak/generation.py
git diff --cached -- nasi_lemak/generation.py
```

A conflicting local modification makes `git pull --ff-only` refuse. That aborted
pull does not create a merge-conflict state, so there are no conflict markers to
edit. Instead, make a unique backup directory outside the repository, keeping
the full file and its diff against HEAD:

```bash
backup_root="$HOME/ai-guardrails-local-patches"
backup_dir="$backup_root/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$backup_root"
mkdir "$backup_dir"
cp -p nasi_lemak/generation.py "$backup_dir/generation.py.bak"
git diff HEAD -- nasi_lemak/generation.py > "$backup_dir/generation-vs-HEAD.patch"
```

Restore and pull **only when all of the following are true**:

- `git diff --cached --quiet -- nasi_lemak/generation.py` succeeds, so the index
  holds no staged change to that file;
- `git status --short --untracked-files=no` lists exactly
  ` M nasi_lemak/generation.py` and no other tracked modification;
- the unstaged diff is exactly the sole one-line User-Agent addition and changes
  nothing else in the file.

If another modification or any staged change exists, stop. Keep those changes,
do not restore, stash, reset or discard them, and reconcile them with the
operator first. Never restore, reset or revert any other path or history.

When the conditions above hold, restore only that file's working-tree content
from HEAD, verify it is clean, then fast-forward:

```bash
git restore --worktree --source=HEAD -- nasi_lemak/generation.py
git status --short -- nasi_lemak/generation.py
git diff --quiet HEAD -- nasi_lemak/generation.py
git pull --ff-only
```

`git restore --worktree` rewrites only the named working-tree file; it does not
change the index, other files or history. Even with a clean local file, the pull
is not guaranteed to succeed: `--ff-only` either advances to the upstream commit
or exits without changing local commits or the working tree. If it fails, stop
and inspect the message; do not delete untracked files, stash, reset or resolve
nonexistent merge conflicts.

After the pull, inspect `nasi_lemak/generation.py`. If upstream now sends the
identical User-Agent from the shared transport, keep the backup until you have
confirmed there are no other local edits, then discard it as your own cleanup.
If upstream did not land the fix, reapply the documented one-line change from
the backup. Check the patch first with
`git apply --check "$backup_dir/generation-vs-HEAD.patch"`; use `git apply` only
if that check succeeds, otherwise add the line manually. Keep the backup until
the next reviewed release.

## 7. Verify configuration, then verify live behaviour separately

Readiness and configuration checks are not quality evidence. First confirm that
the running container is the image you just built; a `200` from an old container
left running is not deployment evidence:

```bash
sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.hosted-guards.env \
  -f compose.yaml -f compose.api.yaml ps gateway

# Record the actual built image ID, not just the tag.
sudo docker image inspect nasi-lemak-gateway:0.1.0 --format '{{.Id}}'

# Repeat with the exact workspace/demo env/overlay set from section 6 when used.
container_id="$(sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.hosted-guards.env \
  -f compose.yaml -f compose.api.yaml ps -q gateway)"
sudo docker inspect \
  --format '{{.Image}} {{.Created}} {{.State.StartedAt}}' \
  "$container_id"
```

A build may reuse the cache, so do not rely on a newly appearing tag or on the
image's own `.Created` timestamp. Compare the running container's `.Image` value
with the actual image ID recorded after `build`; they must match exactly. Compare
the container's `.Created` and `.State.StartedAt` with the `${deployed_at}` value
recorded in section 6; both must be at or after that deployment time. A `200`
response alone, or an old image-created timestamp, is not deployment evidence.
Then check readiness through the configured `GATEWAY_PORT`:

```bash
# Use the configured GATEWAY_PORT, not a hardcoded 8000.
readiness_port="$(sed -n 's/^GATEWAY_PORT=//p' .secrets/compose.env | tail -n 1)"
curl -fsS "http://127.0.0.1:${readiness_port:-8000}/health/ready"
```

If `GATEWAY_PORT` is defined in a different env file, read it from there. A
custom port is never satisfied by the default `8000` URL.

`{"status":"ready","guards_active":true}` means the configured guarded
composition started. It does **not** contact either provider at startup and
does not prove endpoint reachability, the numeric Prompt Guard response shape,
the Cloudflare model echo, threshold calibration, quota or data handling.

### Reasoning-only blank content

If the generation provider returns empty or whitespace `content` while also
returning a hidden `reasoning_content` field, the transport rejects it with the
generic `generation endpoint returned no text content`. It never reads, returns
or logs `reasoning_content`, and it does not retry or silently increase the token
budget. Use an adequate generation budget (this gateway accepts a request
`max_tokens` of at most 256) and a provider model that returns ordinary assistant
content. A budget consumed entirely by hidden reasoning can leave no visible
answer even though the provider call succeeded.

Before sending any real content, confirm the provider data-flow approval and
use synthetic inputs only. The following remain explicit **pending live
acceptance**:

- Groq must return one chat completion whose `model` is exactly
  `meta-llama/llama-prompt-guard-2-86m`, whose assistant content is a single
  finite probability in `[0, 1]`, and whose `usage.prompt_tokens` is a positive
  integer below 512.
- Cloudflare must return one completed non-streaming Llama Guard completion that
  echoes exactly `@cf/meta/llama-guard-3-8b`, with only canonical `safe` or
  `unsafe` plus S1..S14 categories.
- Each hosted request is one attempt with TLS verification, no redirect, no
  proxy, the configured timeout/response-size bound, no retry and no fallback.
  Errors are generic and carry no URL, key, prompt or verdict.

The model-ID check verifies that the provider reported the requested
identifier; it is not cryptographic proof that the expected model weights
served the request. Groq's numeric-score compatibility and Cloudflare's model
echo remain pending live confirmation.

Until those checks are performed and accepted by the operator, treat the
hosted guard models as configured but not live-verified.

## Official sources

- Groq Prompt Guard 2 86M model page:
  <https://console.groq.com/docs/model/meta-llama/llama-prompt-guard-2-86m>
- Cloudflare Workers AI OpenAI compatibility:
  <https://developers.cloudflare.com/workers-ai/configuration/open-ai-compatibility/>
- Cloudflare Llama Guard 3 8B model:
  <https://developers.cloudflare.com/workers-ai/models/llama-guard-3-8b/>
- Meta Llama Guard 3 8B safety taxonomy:
  <https://huggingface.co/meta-llama/Llama-Guard-3-8B>
