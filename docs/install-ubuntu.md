# Installing on Ubuntu 24.04 (amd64)

This guide covers the existing interactive installer for an **already installed**
Ubuntu 24.04 amd64 VM. It does not install or replace the operating system.

> **Status:** this guide was written on a Windows development machine. The
> installer, Compose stack and guard overlay have **not** been executed on
> Ubuntu, Docker or native guard checkpoints in this workspace. Treat the steps
> as reviewed instructions pending VM acceptance, not as deployment evidence.

## Fresh install or existing deployment?

Decide which path applies before running any mutating command:

- **Fresh install:** the repository and Compose stack are not on this VM yet.
  Continue with sections 1-3. Section 3 is the only path that runs `install.sh`.
- **Existing deployment:** a checkout and stack already run on this VM, and you
  are updating the application code (including a UI-only change). **Do not
  rerun `install.sh`**: a rerun rewrites the operator-owned policy and
  configuration. Pull the reviewed commit in the existing checkout and rebuild
  the image instead:
  ```bash
  cd /path/to/existing/ai-guardrails   # the checkout already running on this VM
  git pull --ff-only
  ```
  For a test-mode stack with the optional nginx ingress already configured, use
  the exact repeat-update command in
  [docs/demo-access.md](demo-access.md#updating-an-existing-deployment):
  ```bash
  sudo docker compose \
    --env-file .secrets/compose.env \
    --env-file .secrets/compose.test.env \
    --env-file .secrets/compose.demo.env \
    -f compose.yaml -f compose.test.yaml -f compose.demo.yaml \
    up -d --no-deps --build gateway nginx
  ```
  If the stack is loopback-only, run the same `up -d --no-deps --build gateway`
  pattern with only the two env files and two Compose files from section 5.
  Neither path recreates the database, truncates `.secrets`, or changes policy.

The UI is part of the application package copied into the image, so no
installer flag, migration helper or extra mutation step is needed for this
change. The installer itself is unchanged. Existing deployments keep their
current mode, policy, guard configuration, authentication and secrets.

## Prerequisites

- Ubuntu 24.04 amd64 with an existing OS installation.
- `python3` and `git`.
- A sudo-capable account (the mutating installer requires root).
- Outbound HTTPS access to GitHub, Ubuntu/Docker package sources (the installer
  provisions Docker Engine and the Compose plugin if they are missing) and the
  container registry used for `postgres:16.4-bookworm`.
- A TTY. **Mutating installs always prompt**, even when every flag is supplied;
  piping input or running without a terminal fails by design.

## 1. Clone the private repository

Use your normal Git credentials over HTTPS; do not embed a token in the URL or
in shell history:

```bash
git clone https://github.com/SomeDud04/ai-guardrails.git
cd ai-guardrails
```

## 2. Inspect before changing anything

These commands are read-only: they do not read root-only secret files, write
configuration or start services.

```bash
bash install.sh --check
bash install.sh --plan
```

`--plan` prints the planned mode, port, generation URL/model and the credential
and env-file paths it would use. It does not contact the model endpoint. For the
API guard backend it also validates the strict config and the key/CA file
metadata without reading key contents. Neither command changes file ownership or
permissions and neither starts a service.

## 3. Run the installer as root

```bash
sudo bash install.sh
```

The prompts are interactive:

1. **Mode:** choose `1` for **test**.
2. **Generation URL:** enter the exact base URL the provider specifies,
   including any required prefix (often `/v1`). A candidate for this pilot is
   `http://82haf69n.flexinfra.com.my/v1`, but it has **not** been verified as
   working. The installer preflight does not test upstream connectivity; VM
   acceptance must verify an authenticated chat request.
3. **Generation model ID:** enter the exact model ID the endpoint accepts. The
   display label "Qwen3.8 27B FP8" is **not guaranteed** to be the API model ID;
   confirm it with the provider.
4. **Plain HTTP:** because the URL is `http://`, the installer asks you to type
   `yes` to acknowledge insecure transport. Only do this for the acknowledged
   test.
5. **Test-mode acknowledgement:** type `yes` to confirm guards are inactive.
6. **Final confirmation:** review the preview and type `yes` to proceed.

There is no authentication prompt. The fixed default is **no auth**
(`--generation-auth none`). Bearer-token provisioning is **not supported** by
the installer; it does not create or mount an upstream API secret.

A non-interactive invocation is rejected even with all flags. Use `--check` or
`--plan` for automation instead.

### What test mode does and does not do

Test mode uses the real generation client with a conservative **byte** budget,
which is not a real tokenizer count. It still enforces application/operator
authentication, PII masking, deny phrases and audit logging. The native attack
and output guard classifiers are **inactive**, so no native guard artifacts are
needed. This is not a compliance or production configuration and must not be
presented as guarded inference.

## 4. Open the admin view safely

The gateway publishes only on loopback:

```text
http://127.0.0.1:8000/admin
```

From a remote workstation, forward the port instead of exposing it:

```bash
ssh -L 8000:127.0.0.1:8000 user@VM
```

Then browse `http://localhost:8000/admin`. Do not change the Compose port
mapping to a public interface and do not add a public bind.

For an optional explicit trusted-LAN demo entry (`http://VM_LAN_IP:8080/`) with
no TLS, see [docs/demo-access.md](demo-access.md). That overlay is separate from
the installer: do **not** rerun the installer to add it, because a rerun rewrites
the existing policy. The default stays loopback-only.

The installer writes plaintext key files at `.secrets/chat_key` and
`.secrets/operator_key` (state directory mode `0700`, key files `0600`). Never
print, copy to chat, or commit these values. For `/admin`, the operator opens
the key file through a secure local editor or approved secret manager and
enters the operator key into the login form. Do not weaken file or directory
permissions to make access easier.

## 5. Day-to-day Compose commands

Runtime Compose commands need root because the env and secret files are
root-owned. Always pass **both** env files and the base file plus exactly one
overlay, in this order. If you opted into the demo ingress from section 4, that
path additionally needs `.secrets/compose.demo.env` and
`-f compose.demo.yaml`; the exact commands are in
[docs/demo-access.md](demo-access.md).

Test mode:

```bash
sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.test.env \
  -f compose.yaml -f compose.test.yaml ps

sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.test.env \
  -f compose.yaml -f compose.test.yaml logs -f gateway

sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.test.env \
  -f compose.yaml -f compose.test.yaml stop

sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.test.env \
  -f compose.yaml -f compose.test.yaml start
```

Guarded mode uses the same pattern with the pilot files:

```bash
sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.pilot.env \
  -f compose.yaml -f compose.pilot.yaml ps

sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.pilot.env \
  -f compose.yaml -f compose.pilot.yaml logs -f gateway

sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.pilot.env \
  -f compose.yaml -f compose.pilot.yaml stop

sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.pilot.env \
  -f compose.yaml -f compose.pilot.yaml start
```

The explicit API guard overlay (section 6) uses its own env file and files. Add
`-f compose.api-ca.yaml` only when the approved endpoints use the private CA:

```bash
sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.api.env \
  -f compose.yaml -f compose.api.yaml ps

sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.api.env \
  -f compose.yaml -f compose.api.yaml logs -f gateway
```

Use `stop`/`start` (or `up -d`) for maintenance. **Do not run `down -v`**: it
deletes the audit database volume. Even plain `down` is unnecessary unless you
intend to recreate containers.

## 6. Optional API guard backend (explicit opt-in)

The API guard backend is an **optional** alternative to the local guard
checkpoints. It is selected only by supplying **both** `--guard-backend api` and
`--guard-api-config ABSOLUTE_PATH` (with `--mode guarded`). There is no
environment auto-detection and no silent switch away from the existing local
mode: a run that omits these flags uses the documented defaults (`--mode test`
selects test mode; `--mode guarded` selects the local guard backend), not the
previously configured API backend. Only a normal code pull plus a mode-matching
Compose rebuild and run preserves the configured mode. An invalid, unreadable or
missing config aborts before any file is written or service started. API mode imports no local guard ML stack and does not read
Prompt Guard or Llama Guard model directories.

### Strict version 1 config

The config is a non-secret, bounded JSON file. Unknown or duplicate keys are
rejected. This example uses documentation-only `.invalid` hosts; replace them
with approved endpoints:

```json
{
  "version": 1,
  "input": {
    "url": "https://input-guard.example.invalid/v1",
    "model": "meta-llama/Llama-Prompt-Guard-2-86M",
    "auth": "bearer",
    "threshold": 0.5,
    "api_key_file": "/etc/nasi-lemak/keys/input_guard_key",
    "timeout": 10,
    "max_response_bytes": 8192
  },
  "output": {
    "url": "https://output-guard.example.invalid/v1",
    "model": "Qwen/Qwen3Guard-Gen-4B",
    "auth": "none",
    "max_response_bytes": 8192
  },
  "ca_file": "/etc/nasi-lemak/private-ca.pem"
}
```

- `version` must be the integer `1`. `input` and `output` are required.
- `auth` is exactly `none` or `bearer`. `bearer` requires `api_key_file`;
  `none` rejects it. There is no inline key field and no fallback to the
  generation/chat credential.
- `threshold` is required on `input` only and must be in `[0, 1]`.
- Optional `timeout` is `1..600` seconds and optional `max_response_bytes` is
  `1024..4194304` bytes (the same minimum as the generation client).
- `api_key_file` and `ca_file` must be absolute, regular, non-symlink,
  non-empty files. `--check`, `--plan` and install inspect metadata only: they
  never read key contents and never change operator ownership or permissions.

### Endpoint contracts

- **Input:** the endpoint must implement the gateway-owned
  `nasi-lemak-input-classifier-v1` `POST /classify` contract documented in
  [docs/guard-api-integration.md](guard-api-integration.md). A stock
  OpenAI-compatible or prompt-classification API does not provide this shape; a
  compatible provider-side wrapper is required. **No such serving wrapper is
  included in this repository.**
- **Output:** Qwen3Guard through an OpenAI-style **chat-completions** endpoint
  only, with the documented `Safety` / `Categories` / `Refusal` verdict text.
- Unknown or unverified APIs remain pending; synthetic loopback tests are not
  evidence of endpoint compatibility, quality or safety acceptance.

### Key ownership and permissions

Bearer key files are secrets. Make each one readable by the container runtime
UID/GID `10001` without exposing it to other users. This is safe guidance; the
installer never applies it for you:

```bash
# Create the file and put the token in it with an approved editor or secret
# manager, then:
sudo chown 10001:10001 /etc/nasi-lemak/keys/input_guard_key
sudo chmod 0400 /etc/nasi-lemak/keys/input_guard_key
```

Copy the token into the file with an approved editor or secret manager instead
of putting it in shell history. Accepted metadata is owner `10001` with mode
`0400`/`0600`, or runtime group `10001` with mode `0440`/`0640`. Group/world
write, world read, symlinks and empty files are refused. The error message tells
you how to fix ownership or mode; it never suggests `chmod a+r`. A private CA
file is non-secret and may be world-readable.

### Read-only validation and activation

Validate before changing anything:

```bash
sudo bash install.sh --mode guarded --policy-file /etc/nasi-lemak/policy.yaml \
  --guard-backend api \
  --guard-api-config /etc/nasi-lemak/guard-api.json --check
sudo bash install.sh --mode guarded --policy-file /etc/nasi-lemak/policy.yaml \
  --guard-backend api \
  --guard-api-config /etc/nasi-lemak/guard-api.json --plan
```

Both are read-only. Activation is still an interactive mutating run with the
same explicit flags plus the required generation URL/model; the installer asks
for confirmation and writes only after validation:

```bash
sudo bash install.sh \
  --mode guarded \
  --policy-file /etc/nasi-lemak/policy.yaml \
  --guard-backend api \
  --guard-api-config /etc/nasi-lemak/guard-api.json \
  --generation-url https://generation.example.invalid/v1 \
  --generation-model YOUR_CONFIRMED_MODEL_ID \
  --generation-auth none
```

The readiness response `{"status":"ready","guards_active":true}` proves only
that the configured guarded composition started. It does **not** contact the
guard endpoints at startup and does not prove endpoint reachability, model
quality, latency or data-flow approval. No model, guard endpoint, VM or Docker
stack has been executed in this workspace.

For an existing deployment, update the code with `git pull --ff-only` in the
current checkout and rebuild the gateway using the matching Compose command
above. That keeps the existing `.secrets/` files, operator policy and the
database volume, and does not require rerunning the mutating installer. Do not
run `down -v`.

## 7. Rerunning and guard activation

Rerun `install.sh` only to change deployment configuration, not to pick up a
normal application or UI update; use "Fresh install or existing deployment?"
above for the latter. The installer reuses the generated manifest, `.secrets`
keys and the named database volume. A rerun still requires the upstream URL and
exact model ID to be supplied again; saved generation values are not used as
defaults.

To activate the **local** guard overlay, rerun interactively with absolute paths
to operator-provided artifacts. This is an explicit configuration change, never
an automatic upgrade, and it does not replace the previous mode unless the
requested mode passes readiness. For the API backend use section 6 instead.

```bash
sudo bash install.sh \
  --mode guarded \
  --generation-url http://82haf69n.flexinfra.com.my/v1 \
  --generation-model YOUR_CONFIRMED_MODEL_ID \
  --generation-auth none \
  --allow-insecure-http \
  --policy-file /absolute/path/policy.yaml \
  --prompt-guard-dir /absolute/path/prompt-guard-2 \
  --llama-guard-dir /absolute/path/llama-guard-3
```

The run is still interactive. The Prompt Guard 2 and Llama Guard 3 checkpoints
are Meta models that the operator must obtain and license independently; the
installer and images do not download weights and no arbitrary plugin support is
implied. The same generation URL and existing keys are reused.

A normal `git pull --ff-only` followed by a mode-matching rebuild keeps
`.secrets/`, the operator policy and the database volume. It does not require a
mutating installer run, and `down -v` must not be used.

## 8. If an install or upgrade fails

A failed run restores the previous installer-owned configuration and leaves
the last confirmed mode marker unchanged. It does **not** automatically roll
back containers that were already started and provides no automatic fallback
to an earlier mode.

Inspect the actual state instead of assuming rollback. This query uses the
Compose project label and does not require the installer env files, which may be
missing after a fresh failure or a guarded-only install:

```bash
sudo docker ps -a --filter label=com.docker.compose.project=nasi-lemak
```

After confirming which configuration files were restored, use the matching
previous-mode Compose commands from section 5 for further inspection or
recovery. If needed, explicitly rerun the previously approved mode with the
commands in section 6 (or the test-mode install) and confirm readiness.

## 9. Pending VM acceptance

Before treating this as verified, run on the actual VM:

- fresh install with `--check`, `--plan` and an interactive test-mode install;
- rerun to confirm manifest, keys and database volume reuse;
- an authenticated chat request through the configured endpoint;
- audit event/CSV export from the operator view;
- reboot and confirm the stack returns;
- a guarded-mode upgrade once licensed local guard artifacts are available.

There is no measured hardware sizing claim in this guide; size the VM against
your own measured workload.
