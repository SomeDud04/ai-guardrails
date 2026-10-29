# Local-guards switch runbook (Qwen3Guard-Gen on the guardrail VM)

Scope: switch the **existing deployment** at `192.168.90.41` from the hosted API
guard lane (Groq Prompt Guard + Cloudflare Llama Guard, configured through
`compose.api.yaml` and `.secrets/compose.hosted-guards.env`) to the local
`Qwen3Guard-Gen-0.6B` bundle already present at
`/models/qwen3guard-gen-0.6b`.

This runbook is configuration and operator procedure only. Nothing here was
built, started, or measured in the development workspace: Docker is absent
there and no model was downloaded or executed. **No model weights are
downloaded at image build or container start; the guard Python packages (torch
from the CPU wheel index, transformers, jinja2) are downloaded during the image
build only.** The Qwen and Meta model bundles must already be complete on the
host. **A pass proves composition and startup, not detection quality.** Latency,
memory, false-positive/negative rates and multilingual coverage remain a
separate benchmark activity; no number is claimed by the switch.

The adapter itself (`nasi_lemak/qwen3_local.py`, backend selector
`NASI_LEMAK_GUARD_BACKEND=qwen3guard-local`) is implemented and covered by
synthetic tests. It loads from a local directory only (`local_files_only=True`,
`trust_remote_code=False`, safetensors only), validates the artifact structure
before and after loading, and fails closed with the generic 503 on any error.
No hosted guard is contacted, and no allow fallback exists.

## 1. Facts about the deployed checkout (verified 2026-10-29)

The deployed `main` was `1b0aa43`. The working tree contains **untracked
operator files that matter**:

| Path | State | Action |
| --- | --- | --- |
| `compose.thinking.yaml` | untracked, **REQUIRED by the running stack** | keep it; it stays in the `-f` set |
| `policy.guarded.yaml` | untracked, approved policy | keep it; `PILOT_POLICY_FILE` points at it |
| `docs/guard-benchmark-20261028.md` | untracked copy, now also tracked upstream | archive before pull |
| `scripts/bench_guard_models.py` | untracked copy, now also tracked upstream | archive before pull |
| `tests/test_bench_guard_models.py` | untracked copy, now also tracked upstream | archive before pull |

The three untracked copies have the same content as the versions that are now
tracked, so `git pull --ff-only` would refuse to overwrite them. Move them to a
scratch directory first; they are not needed and the tracked copies replace
them.

**Never run `git clean -x`.** It would delete `.secrets`, `compose.thinking.yaml`
and the approved policy. **Preserve `.secrets`**: do not delete, overwrite or
recreate it. The only permitted edits are the two explicit operator edits in
section 3 (the D14 generation settings in `.secrets/compose.env` and the local
paths in `.secrets/compose.pilot.env`); every other file in `.secrets` stays
exactly as it is.

## 2. Pull the reviewed switch

```bash
cd /path/to/ai-guardrails          # the deployed checkout
git status --short                 # confirm only the expected untracked entries
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$HOME/vm-scratch/$STAMP"
mv docs/guard-benchmark-20261028.md \
   scripts/bench_guard_models.py \
   tests/test_bench_guard_models.py \
   "$HOME/vm-scratch/$STAMP/"
git pull --ff-only
git rev-parse HEAD                 # record the deployed SHA
```

`compose.thinking.yaml` and `policy.guarded.yaml` stay where they are. If
`git status` shows any other untracked file that now collides with a tracked
path, archive it the same way rather than deleting it.

The pull must include this slice (Dockerfile CPU torch, `jinja2` in the guards
extra, the generation-key pass-through, the local-guard pilot overlay and this
runbook).

## 3. Prepare the local-guard env files

This section is the complete list of operator configuration edits. Nothing else
in `.secrets` changes.

The base env file `.secrets/compose.env` keeps the audit/application secret
paths and also carries the D14 generation settings. Because the bearer key lives
here, treat this file as a secret: never echo it, copy it to chat or Git, or
print it later.

```bash
NASI_LEMAK_GENERATION_URL=https://ua73nd90j.flexinfra.com.my/v1
NASI_LEMAK_GENERATION_MODEL=qwen3.8-27b
NASI_LEMAK_GENERATION_AUTH=bearer
NASI_LEMAK_GENERATION_API_KEY=<the bearer key, on this VM only>
```

Remove `NASI_LEMAK_GENERATION_ALLOW_INSECURE_HTTP` and any `AUTH=none` line: the
new URL is HTTPS and certificate verification stays on. Do not echo the key,
put it in shell history, chat or Git, or print the container environment later.
The base `compose.yaml` forwards the key as a bare pass-through; it is never
authored in a tracked file.

Edit `.secrets/compose.pilot.env` (copy `docs/compose.pilot.env.example` only if
the file is absent; never overwrite an existing operator file blindly):

```bash
PILOT_POLICY_FILE=<existing absolute path to policy.guarded.yaml>
PILOT_PROMPT_GUARD_MODEL_DIR=<existing approved prompt-guard-2 host path>
PILOT_LLAMA_GUARD_MODEL_DIR=<existing approved llama-guard-3 host path>
PILOT_QWEN_GUARD_MODEL_DIR=/models/qwen3guard-gen-0.6b
PILOT_QWEN_GUARD_MODEL_CONTAINER_DIR=/models/qwen3guard-gen-0.6b
OPERATOR_KEY_DIGEST_FILE=<existing absolute path to .secrets/operator_key_digest>
OPERATOR_AUDIT_DSN_FILE=<existing absolute path to .secrets/operator_audit_dsn>
```

The pilot overlay **extends** the already-approved Meta pilot: keep the existing
`PILOT_PROMPT_GUARD_MODEL_DIR` and `PILOT_LLAMA_GUARD_MODEL_DIR` operator paths
and the Meta threshold/context settings. They remain required even though Qwen
performs the active scans. Use the paths already approved on this VM; do not
invent a new Meta model path.

All paths are mandatory interpolation values; Compose aborts if any is unset or
missing, instead of creating an empty directory. The Qwen host directory and its
container directory are also mandatory, and the overlay uses the same
`PILOT_QWEN_GUARD_MODEL_CONTAINER_DIR` interpolation for
`NASI_LEMAK_QWEN3GUARD_MODEL_DIR` and the read-only mount target so they cannot
disagree. The overlay sets guarded mode, `NASI_LEMAK_ALLOW_UNGUARDED_TEST=false`,
and `NASI_LEMAK_GUARD_BACKEND=qwen3guard-local` itself. Optional tunables
(`NASI_LEMAK_QWEN3GUARD_INPUT_THRESHOLD`, `..._OUTPUT_THRESHOLD`, `..._WORKERS`,
`..._THREADS`, `..._LONG_INPUT`) are bare pass-throughs: omit them to keep the
validated defaults; on the 4-vCPU box that is 2 workers x 2 threads. Thresholds
are a categorical severity floor in `0.0..0.5`, not a calibrated probability.

The local-guard vertical must contain **no** `NASI_LEMAK_INPUT_GUARD_*` or
`NASI_LEMAK_OUTPUT_GUARD_*` entry, no `*_API_KEY_FILE` guard secret and no
`compose.api-ca.yaml`. Hosted entries must be absent, not empty: an empty URL
would still be a half-configured hosted lane, and the local backend never falls
back to it. The untracked `compose.auth.yaml` overlay is no longer needed once
the base `compose.yaml` forwards `NASI_LEMAK_GENERATION_API_KEY`; drop it from
the command set (archive it, do not delete the key file).

## 4. The update command (paste-ready)

Run from the deployed checkout. This is the existing-deployment form: base +
local-guard overlay + workspace + demo ingress + the operator's thinking
overlay, with every env file the stack uses. It deliberately **retires**
`compose.api.yaml`, `compose.api-ca.yaml`, `.secrets/compose.hosted-guards.env`
and `compose.auth.yaml` in favour of `compose.pilot.yaml`.

```bash
sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.pilot.env \
  --env-file .secrets/compose.workspace.env \
  --env-file .secrets/compose.demo.env \
  --env-file .secrets/compose.chat-limits.env \
  -f compose.yaml \
  -f compose.pilot.yaml \
  -f compose.workspace.yaml \
  -f compose.demo.yaml \
  -f compose.thinking.yaml \
  config >/dev/null
```

If this stack has never used `.secrets/compose.chat-limits.env`, omit that one
`--env-file` line; if `compose.thinking.yaml` reads its own env file, add it in
the same position. Do not add `compose.api.yaml` "as well": the two verticals
must never merge.

Then build and recreate only the two services, leaving the database, its
volume and all secrets untouched:

```bash
sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.pilot.env \
  --env-file .secrets/compose.workspace.env \
  --env-file .secrets/compose.demo.env \
  --env-file .secrets/compose.chat-limits.env \
  -f compose.yaml \
  -f compose.pilot.yaml \
  -f compose.workspace.yaml \
  -f compose.demo.yaml \
  -f compose.thinking.yaml \
  up -d --no-deps --build gateway nginx
```

`--build` is required: the guards image target changes and the Dockerfile now
installs the CPU-only torch wheel first. The first start loads the model; the
pilot healthcheck allows a 10-minute start period and `/health/ready` may
return 503 until loading and policy activation finish.

## 5. Verification ladder (in order)

Define the same command prefix once in the current shell, then run the steps
below in order. It is the exact section 4 block; it must be redefined in a new
shell or tmux pane rather than assumed to persist.

```bash
dc() {
  sudo docker compose \
    --env-file .secrets/compose.env \
    --env-file .secrets/compose.pilot.env \
    --env-file .secrets/compose.workspace.env \
    --env-file .secrets/compose.demo.env \
    --env-file .secrets/compose.chat-limits.env \
    -f compose.yaml \
    -f compose.pilot.yaml \
    -f compose.workspace.yaml \
    -f compose.demo.yaml \
    -f compose.thinking.yaml \
    "$@"
}
```

(Omit the chat-limits line if this stack does not use that env file.)

1. **Containers.**

   ```bash
   dc ps
   ```

   Expect `gateway` (image `nasi-lemak-gateway:0.1.0-pilot`), `nginx` and `db`,
   and **all three must report healthy**. `db` and `nginx` must be healthy; the
   gateway is healthy only when `/health/ready` returns 200. If any service is
   not healthy, stop here and inspect its logs before continuing.

2. **Readiness.**

   ```bash
   curl -fsS http://127.0.0.1:8000/health/ready
   ```

   A 503 is the honest fail-closed result until policy **and** guards are
   configured and loaded. When ready, expect HTTP 200 with `"mode":"guarded"`
   and `"guards_active":true`. Configuration readiness is not classifier
   accuracy, warmup proof or a detection result.

3. **Container settings (no secret values printed).**

   ```bash
   dc exec -T gateway sh -c '
     env | grep -E "^NASI_LEMAK_(MODE|ALLOW_UNGUARDED_TEST|GUARD_BACKEND|QWEN3GUARD_[A-Z_]+|GENERATION_(URL|MODEL|AUTH))=" | sort
     env | grep -E "^HF_|^TRANSFORMERS_" | sort
     env | grep -E "^NASI_LEMAK_(INPUT|OUTPUT)_GUARD_" || echo "no hosted guard entries"
     test -n "$NASI_LEMAK_GENERATION_API_KEY" && echo "generation key present"
   '
   ```

   Required: `NASI_LEMAK_GUARD_BACKEND=qwen3guard-local`; **no**
   `NASI_LEMAK_INPUT_GUARD_*`/`NASI_LEMAK_OUTPUT_GUARD_*` and no hosted guard
   URL/hostname; generation URL/model/auth are the D14 values; the bearer key is
   present (never print its value).

4. **Model mount.**

   ```bash
   dc exec -T gateway sh -c '
     ls -la /models
     ls /models/qwen3guard-gen-0.6b | head
     test -r /models/qwen3guard-gen-0.6b/config.json && echo "config readable"
   '
   sudo docker inspect --format \
     '{{range .Mounts}}{{.Destination}} RW={{.RW}}{{"\n"}}{{end}}' \
     "$(dc ps -q gateway)" | grep -F '/models/qwen3guard-gen-0.6b RW=false'
   ```

   The directory must be visible and readable by UID 10001. Read-only is checked
   through Docker's own mount metadata (`RW=false`), not by attempting a write:
   a permission denial alone would not prove the mount is read-only. The final
   `grep` must match; no output means the mount is missing or writable.

5. **One real request through the demo ingress.** Open
   `http://<DEMO_BIND_IP>:8080/`, load the application chat key and send one
   benign prompt. Confirm the answer is released and the page shows
   `Model guard active`. Then:

   ```bash
   dc logs --tail=200 gateway nginx \
     | grep -Ei 'groq|cloudflare|api\.groq|guardrail' && echo "REVIEW: hosted name found"
   dc logs --tail=200 gateway | grep -Ei 'prompt|reply|authorization|bearer' \
     && echo "REVIEW: possible raw content in logs"
   ```

   The first grep must find no hosted-guard hostname. The second is a manual
   review: the application must not log raw prompt/reply text or credentials.
   Guards stay fail-closed: a guard error or timeout must produce the generic
   503 and release nothing, exactly as on every other lane. A pass here proves
   composition, startup and one successful end-to-end request; it does not
   prove detection quality.

## 6. Admin and demo copy after the switch

`/` and `/admin` render from `/health/ready`'s `mode` and `guards_active` only;
they do not know or name the backend. In guarded-local mode:

- `mode=guarded`, `guards_active=true` → no warning banner, and the demo topbar
  shows `Model guard active`.
- The test-mode banner appears only when `mode=test`; the unguarded banner
  appears only when guards are not active. Neither wording claims a hosted
  provider.
- The "What is checked today?" disclosure now says model-based checks run when
  the gateway is in guarded mode with configured adapters, and repeats that the
  page cannot show per-request verdicts, confidence or accuracy. No page text
  claims hosted or test-mode guards for this deployment.

Nothing in the UI is evidence of detection quality; it reflects readiness and
mode only.

## 7. Rollback

Restore the previous `-f`/env set (base + `compose.api.yaml` + the hosted-guard
env file + workspace + demo + thinking) and recreate the same two services:

```bash
sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.hosted-guards.env \
  --env-file .secrets/compose.workspace.env \
  --env-file .secrets/compose.demo.env \
  --env-file .secrets/compose.chat-limits.env \
  -f compose.yaml \
  -f compose.api.yaml \
  -f compose.workspace.yaml \
  -f compose.demo.yaml \
  -f compose.thinking.yaml \
  up -d --no-deps --build gateway nginx
```

This restores the hosted-guard lane with the previously reviewed image target.
The bearer generation key is already forwarded by the new base `compose.yaml`,
so the temporary `compose.auth.yaml` overlay is not needed here; if the whole
checkout is also rolled back to the pre-switch commit, add that overlay back
exactly as it was. **Never run `docker compose down -v`**: it removes the audit
database volume. Do not delete `.secrets`, the model directory or the archived
copies.

## 8. Testing interfaces

The blueprint's CLI testing surface is a **convenience shim** at
`POST /chat`. It accepts exactly one JSON key and then dispatches the same
internal chat-completions request through `Gateway.handle`:

```bash
curl -i http://<guardrail-vm>:8080/chat \
  -H 'Authorization: Bearer YOUR_TOKEN' \
  -H 'Content-type: application/json' \
  -d '{"prompt": "..."}'
```

It uses the same single bearer check, the same bounded body read and the same
bounded admission semaphore as `POST /v1/chat/completions`. Audit writes stay
inside the gateway, so a `/chat` request produces the same initial/terminal audit
rows as `/v1` (including a blocked request). There is no second pipeline, no
alternate masking step and no weaker failure mode.

### `/chat` contract

Request body: `{"prompt": "<non-empty string>"}`. Missing, extra or non-string
top-level keys return `400`. The existing chat context/reply limits apply
unchanged.

| Field | When | Meaning |
| --- | --- | --- |
| `decision` | always | `ALLOW` or `BLOCK` |
| `sanitized_prompt` | `ALLOW`, or `BLOCK` after masking ran | The masked user text exactly as this request passed it to generation; absent for an input-stage block because masking never ran |
| `input_safety_label` | `ALLOW` and `BLOCK` | Coarse mapping of the request's validated input verdict: `safe` (allow), `blocked` (block) or `unknown` (no verdict) |
| `output_safety_label` | `ALLOW` only | Coarse mapping of the request's validated output verdict: `safe`, `blocked` or `unknown`; omitted from every block body |
| `response` | `ALLOW` | Sanitized assistant text released by the pipeline |
| `reason` | `BLOCK` | Fixed client-safe block message; no guard verdict or raw model text |
| `category` | `BLOCK` when produced | Pipeline reason code, e.g. `INPUT_GUARD_BLOCK`, `OUTPUT_GUARD_BLOCK` |

Status codes are the existing ones: `200` allow; `400` invalid shape or JSON;
`401` missing, wrong or duplicate bearer; `403` blocked (`POLICY_BLOCK`);
`413` input limit (`INPUT_LIMIT`); `503` guard/control failure, an exhausted
admission slot or a read/dispatch deadline (`UNAVAILABLE`).

These values are **request-local, in-memory metadata only**. They are produced by
the same dispatch that serves the request and are not audit columns: the existing
initial/terminal audit rows are unchanged and contain no guard label, sanitized
text, timer or latency field. `/chat` does not re-run guards, re-mask text, read
model state or time the dispatch.

The pipeline exposes only the validated input `allow`/`block` verdict and the
validated output `safe` boolean. A raw categorical classifier severity (for
example Qwen's Safe/Unsafe/Controversial) has already been discarded by the
adapters, so the coarse `safe`/`blocked` mapping above is the honest maximum and
`unknown` is used when a stage did not run (for example a policy-only block or a
disabled output check). There is no elapsed-time measurement in the gateway or
audit path, so no `latency_ms` field is fabricated: it is not part of this
contract.

### CLI test script

`scripts/test_gateway.py` is standard-library only. `--base-url` is mandatory
and there is deliberately no default localhost. The token comes only from
`--token` or `TEST_GATEWAY_TOKEN`; it is never stored or printed.

```bash
# All three blueprint builds: normal, PII and injection.
python scripts/test_gateway.py --base-url http://<guardrail-vm>:8080

# PII case: expects 200/ALLOW and a sanitized_prompt with masked values.
python scripts/test_gateway.py --base-url http://<guardrail-vm>:8080 --case pii

# Injection case: expects 403/BLOCK with a fixed reason and a category.
python scripts/test_gateway.py --base-url http://<guardrail-vm>:8080 --case injection
```

The script prints the parsed result JSON for every response, honours
`--timeout`, and exits `0` only when every expected outcome was observed
(the injection case is successful when it is blocked). A connection error,
timeout, non-JSON body, unexpected status or unexpected decision exits `2`
(fail closed).

### `/chat` versus `/v1/chat/completions`

`/chat` is the blueprint's convenience surface for manual CLI checks.
`POST /v1/chat/completions` remains the real OpenAI-compatible integration
surface (model alias, message turns, optional reply budget). Both accept one
bearer credential, are bounded by the same body/read limits, share one
`gateway.handle` pipeline and compete for the same admission lane. The `/v1`
request and response schema is exactly unchanged. There is no latent difference
in enforcement, masking, audit content or failure handling; only the extended
`/chat` response view differs, and that view adds request-local metadata without
altering the audit rows.

## 9. What this switch does not prove

- No guard model was executed in the development workspace; all transport and
  wiring tests use inference doubles.
- No image was built and no Compose stack resolved there; the command set above
  is authored configuration, not a recorded deployment result.
- Detection quality, false-positive/negative rates, multilingual coverage and
  the 500 ms p95 budget remain unmeasured. The benchmark report
  (`docs/guard-benchmark-20261028.md`) and the operator's VM measurement are
  separate evidence.
- The frozen corpus, `MANIFEST.sha256`, `evals/**` and the timeline spreadsheet
  are untouched by this slice.
