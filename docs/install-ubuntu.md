# Installing on Ubuntu 24.04 (amd64)

This guide covers the existing interactive installer for an **already installed**
Ubuntu 24.04 amd64 VM. It does not install or replace the operating system.

> **Status:** this guide was written on a Windows development machine. The
> installer, Compose stack and guard overlay have **not** been executed on
> Ubuntu, Docker or native guard checkpoints in this workspace. Treat the steps
> as reviewed instructions pending VM acceptance, not as deployment evidence.

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
and env-file paths it would use. It does not contact the model endpoint.

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

The installer writes plaintext key files at `.secrets/chat_key` and
`.secrets/operator_key` (state directory mode `0700`, key files `0600`). Never
print, copy to chat, or commit these values. For `/admin`, the operator opens
the key file through a secure local editor or approved secret manager and
enters the operator key into the login form. Do not weaken file or directory
permissions to make access easier.

## 5. Day-to-day Compose commands

Runtime Compose commands need root because the env and secret files are
root-owned. Always pass **both** env files and the base file plus exactly one
overlay, in this order.

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

Use `stop`/`start` (or `up -d`) for maintenance. **Do not run `down -v`**: it
deletes the audit database volume. Even plain `down` is unnecessary unless you
intend to recreate containers.

## 6. Rerunning and guard activation

The installer reuses the generated manifest, `.secrets` keys and the named
database volume. A rerun still requires the upstream URL and exact model ID to
be supplied again; saved generation values are not used as defaults.

To activate the guard overlay, rerun interactively with absolute paths to
operator-provided artifacts:

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

## 7. If an install or upgrade fails

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

## 8. Pending VM acceptance

Before treating this as verified, run on the actual VM:

- fresh install with `--check`, `--plan` and an interactive test-mode install;
- rerun to confirm manifest, keys and database volume reuse;
- an authenticated chat request through the configured endpoint;
- audit event/CSV export from the operator view;
- reboot and confirm the stack returns;
- a guarded-mode upgrade once licensed local guard artifacts are available.

There is no measured hardware sizing claim in this guide; size the VM against
your own measured workload.
