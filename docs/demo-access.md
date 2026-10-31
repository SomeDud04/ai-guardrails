# Optional LAN demo ingress (`compose.demo.yaml`)

This optional overlay adds a small nginx reverse proxy in front of the existing
gateway so a Windows workstation on the same trusted LAN or VPN can open the
customer demo page at `http://VM_LAN_IP:8080/`. It is **plain HTTP** for a
trusted LAN/VPN demonstration only. It adds no TLS, authentication, static
frontend, path prefix or CORS. Untrusted or internet paths need a reviewed TLS
ingress, or SSH, instead.

> **Status:** the gateway-served browser UI (`GET /`) and the Compose/nginx
> files are covered only by caller-local synthetic tests. Docker and nginx have
> not been executed on this Windows workspace, and no real VM, provider API,
> `apt` or Docker request was made. Actual nginx startup and the Windows-to-VM
> path are **pending VM acceptance**. The base stack stays localhost-only
> unless this overlay is explicitly used with an explicit `DEMO_BIND_IP`.

The customer VM is already deployed in test mode and the installer is **not**
rerun here: rerunning it would rewrite the existing policy and configuration.
Test mode means the native guard classifiers are inactive. The customer demo
must continue to show that warning, and upstream generation uses the
provider's HTTP API; guard adapters for that API are not implemented yet.
Existing bearer authentication is preserved unchanged.

## Updating an existing deployment

Use this page in two different situations:

- **UI-only update where nginx is already configured.** Do not rerun the
  installer and do not recreate `.secrets/compose.demo.env`. Use the checkout
  path already running on the VM, pull the reviewed commit, then rebuild only
  the two changed services with the existing env files:
  ```bash
  cd /path/to/existing/ai-guardrails   # the checkout already running on this VM
  git pull --ff-only

  sudo docker compose \
    --env-file .secrets/compose.env \
    --env-file .secrets/compose.test.env \
    --env-file .secrets/compose.demo.env \
    -f compose.yaml -f compose.test.yaml -f compose.demo.yaml \
    up -d --no-deps --build gateway nginx
  ```
  The database must already be running and healthy; verify it with the `ps db`
  command in section 4 first. `--no-deps` keeps `db` out of the operation.
- **First-time ingress setup, including an older deployment that only has the
  loopback gateway.** Follow the full setup below, starting at section 1. An
  older deployment without ingress has no `.secrets/compose.demo.env` yet, so
  section 2's one-time creation step is required.

A UI-only update does not change the existing policy, secrets, database volume,
authentication or guard configuration. The installer is not involved: the
image is built from the pulled checkout, which already packages the page module.

## What the ingress does

- Browser request: `http://VM_LAN_IP:8080/<path>?<query>`.
- nginx forwards the complete original URI and query string to the gateway's
  container address `gateway:8000`. The path is not rewritten.
- `Authorization` headers pass through unchanged, and the client's original
  `Host` header is forwarded verbatim (including an explicit `:8080` port).
  No client-supplied forwarding (`X-Forwarded-For`, `Forwarded`) metadata is
  trusted or generated, and no CORS headers are added. `/` still serves the
  gateway's demo shell, and `/admin` still requires the operator key.
- Upstream response headers (including CSP, `X-Content-Type-Options` and frame
  headers) pass through. Errors are not intercepted, responses are not cached,
  and nothing is retried, so a POST is never replayed.
- nginx joins only the default bridge network. It has no database-network
  attachment and mounts no secrets. The gateway keeps its existing
  `127.0.0.1:8000` host publication and PostgreSQL stays unpublished.
- Docker's embedded resolver (`127.0.0.11`, short TTL) plus variable-based
  `proxy_pass` re-resolves `gateway` at request time, so rebuilding the gateway
  container with a new address does not leave a stale upstream IP.
- nginx logs nothing per request (`access_log off`) and sends only critical
  errors to stderr. Request bodies, URIs and `Authorization` values are not
  routinely logged. The image tag `nginx:stable-alpine` is a mutable
  convenience tag, not a digest pin.

The proxy body limit is 64 KiB, matching the gateway's default maximum body.
Request buffering is enabled so slow clients cannot hold an application worker.
Proxy waits are 5 s connect, 90 s read and 90 s send; the application's default
chat deadline is 60 s. If an operator customises the gateway chat deadline above
90 s, increase `proxy_read_timeout` and `proxy_send_timeout` in
`deploy/nginx-demo.conf` to cover it before starting.

## Prerequisites

- The existing stack is running in test mode from an existing checkout.
- `.secrets/compose.env` and `.secrets/compose.test.env` already exist (use
  `.secrets/compose.pilot.env` instead only if that mode is already configured).
- The Windows workstation and VM are on the same trusted LAN or VPN.
- You can edit root-owned files under `.secrets` on the VM.

## 1. Update the existing checkout (do not rerun the installer)

This section applies to a **first-time ingress setup**, including an existing
loopback-only deployment. If nginx is already configured, use the shorter
repeat-update command in "Updating an existing deployment" instead.

```bash
cd /path/to/existing/ai-guardrails   # replace with this VM's actual checkout path
git pull --ff-only
```

Replace `/path/to/existing/ai-guardrails` with the absolute path of the
checkout that is already deployed on this VM. Do not assume `~/ai-guardrails`:
the operator may be logged in as `root` while the checkout lives under a
different user's home directory, or elsewhere on disk. Confirm it with
`docker compose ls` / `docker inspect` on the running containers, then run the
remaining commands from that directory.

The installer must not be rerun for this slice. Pulling the reviewed commit
does not change the existing policy, secrets or database volume.

## 2. Create the git-ignored ingress env file (one time only)

This section is only for a deployment that does not have the ingress env file
yet. **If `.secrets/compose.demo.env` already exists, do not run the creation
command below**: `install` with `/dev/null` empties the existing file and would
destroy the configured `DEMO_BIND_IP`. Check first and, if it exists, skip to
section 3. Edit it only when the bind address deliberately changes:

```bash
sudo test -f .secrets/compose.demo.env && echo "already present - do not recreate"
```

For a new configuration, create `.secrets/compose.demo.env` as root, mode
`0600`, with exactly these two lines
(replace `VM_LAN_IP` with this VM's actual LAN or VPN address; do not commit it):

```dotenv
DEMO_BIND_IP=VM_LAN_IP
DEMO_PORT=8080
```

`DEMO_BIND_IP` is mandatory: Compose aborts if it is missing. There is no
`0.0.0.0` or wildcard default. `DEMO_PORT` defaults to `8080` and maps to the
unprivileged container port `8080`.

```bash
sudo install -m 0600 /dev/null .secrets/compose.demo.env
sudoedit .secrets/compose.demo.env
```

## 3. Validate the merged configuration and nginx syntax

Always pass **all three** env files and **all three** Compose files, in this
order. Do not print secret values or paste command output containing them into
chat.

```bash
sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.test.env \
  --env-file .secrets/compose.demo.env \
  -f compose.yaml -f compose.test.yaml -f compose.demo.yaml config >/dev/null

sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.test.env \
  --env-file .secrets/compose.demo.env \
  -f compose.yaml -f compose.test.yaml -f compose.demo.yaml \
  run --rm --no-deps --entrypoint nginx nginx -t
```

The `--entrypoint nginx` override is required because the service's normal
entrypoint already includes `-g "daemon off;"`; without it, `-t` would be
appended after that directive. This command tests the mounted full nginx
configuration without starting the long-running proxy. It needs the existing
gateway deployment but does not recreate it.

## 4. Start only the gateway (if needed) and nginx

The existing database must **already** be running and healthy. This step is a
prerequisite check, not something the command below creates or repairs:

```bash
sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.test.env \
  --env-file .secrets/compose.demo.env \
  -f compose.yaml -f compose.test.yaml -f compose.demo.yaml ps db
```

Then build and (re)create only the gateway and nginx. `--no-deps` is required:
without it Compose may start or recreate `db` as a dependency, which this
demo-slice command must not do.

```bash
sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.test.env \
  --env-file .secrets/compose.demo.env \
  -f compose.yaml -f compose.test.yaml -f compose.demo.yaml \
  up -d --no-deps --build gateway nginx

sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.test.env \
  --env-file .secrets/compose.demo.env \
  -f compose.yaml -f compose.test.yaml -f compose.demo.yaml ps
```

`up -d --no-deps --build gateway nginx` names only `gateway` and `nginx`, so it
builds/recreates those two services and leaves the database container, its
volume and the secrets untouched. Because dependencies are skipped, the command
does **not** wait for or manage the database: if `db` is stopped or unhealthy,
fix that first with the normal stack procedure, then rerun this step. Build
output and logs may mention file paths, but never copy key contents into chat.

## 5. Check from the VM, then from Windows

`DEMO_BIND_IP` publishes the ingress **only** on that concrete VM LAN/VPN
address; `127.0.0.1:8080` is not published and a loopback request to port 8080
will fail on such a bind. Replace `VM_LAN_IP` below with the configured
`DEMO_BIND_IP` value.

```bash
curl -fsS http://VM_LAN_IP:8080/health/live
sudo ss -lntp | grep ':8080'
```

Separately, the gateway's own backend publication stays on loopback and is a
different check from the ingress:

```bash
curl -fsS http://127.0.0.1:8000/health/live   # gateway directly, not nginx
```

`/health/live` is only a liveness probe. It does not claim guard activation,
model availability or business readiness. The healthcheck assumes the official
Alpine image ships its usual BusyBox `wget`; that expectation is not runtime
tested here and should be confirmed on the VM.

On Windows PowerShell (replace `VM_LAN_IP` with the same `DEMO_BIND_IP` value):

```powershell
Test-NetConnection VM_LAN_IP -Port 8080
Start-Process "http://VM_LAN_IP:8080/"
```

The demo page asks for the **chat key** manually. Use a separate operator key
for `/admin` only. Never put either key in a URL/query token, a screenshot, a
chat message or shell history. The page sends the chat key as an
`Authorization` header and keeps it in a JavaScript variable.

## If Windows still times out

Work through the path in order; do not disable firewalls to "test" it.

1. **VM address:** `ip -4 addr` on the VM. An address such as a container/NAT
   address is not reachable from Windows. If the hypervisor uses NAT instead of
   bridged networking, configure a host port-forward for TCP 8080 or switch the
   adapter to a bridged/private-LAN network.
2. **Bind address:** `sudo ss -lntp | grep ':8080'` must show the VM LAN address,
   not only `127.0.0.1`. Confirm `DEMO_BIND_IP` in
   `.secrets/compose.demo.env` and recreate nginx after editing it.
3. **Container state:** `... ps` and `... logs nginx`. A gateway start failure
   also makes the proxy's `/health/live` probe fail; check gateway liveness
   separately on the VM loopback.
4. **Firewall ownership:** restrict TCP 8080 at the VM firewall, the hypervisor
   firewall and any network firewall to the specific Windows `ADMIN_IP` (for
   example a `ufw` rule sourced from `ADMIN_IP`). The operator owns those rules.
   UFW by itself does **not** protect Docker-published ports: Docker programs
   its own forwarding path. Use the `DOCKER-USER` chain and the
   hypervisor/network firewall for Docker traffic, and keep all other sources
   denied. Never disable a firewall or publish `0.0.0.0` to make the demo work.

The already-working alternative remains SSH, which needs no ingress:

```bash
ssh -L 8000:127.0.0.1:8000 user@VM
```

Then browse `http://localhost:8000/` (demo) and `http://localhost:8000/admin`
(operator key) locally. Use this before exposing LAN ingress if it meets the
demo need.

## Rollback

Remove **only** the optional nginx service, using all three files so the project
and gateway configuration are unchanged:

```bash
sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.test.env \
  --env-file .secrets/compose.demo.env \
  -f compose.yaml -f compose.test.yaml -f compose.demo.yaml stop nginx
```

Use `rm -sf nginx` instead of `stop nginx` to remove the stopped container.
Leave the gateway, database, `nasi_lemark_db` volume and `.secrets` files alone.
Never run `docker compose down -v`: it deletes the audit database volume. Do not
run even plain `down` as part of this demo rollback.

## Optional HTTPS

Plain HTTP lets anyone watching the LAN read chat keys, login sessions and
prompts. Turn this on before any real data goes through port 8080. It is off
until you add the overlay.

1. Put a certificate and key on the VM outside the repository. For a trusted LAN
   a self-signed pair is enough, and browsers will warn until you trust it:

   ```bash
   sudo install -d -m 0755 /etc/nasi-lemak/tls
   sudo openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
     -keyout /etc/nasi-lemak/tls/key.pem -out /etc/nasi-lemak/tls/cert.pem \
     -subj "/CN=VM_LAN_IP" -addext "subjectAltName=IP:VM_LAN_IP"
   sudo chown 101:101 /etc/nasi-lemak/tls/key.pem
   sudo chmod 0400 /etc/nasi-lemak/tls/key.pem
   ```

2. Create `.secrets/compose.demo-tls.env` with these two lines:

   ```text
   DEMO_TLS_CERT_FILE=/etc/nasi-lemak/tls/cert.pem
   DEMO_TLS_KEY_FILE=/etc/nasi-lemak/tls/key.pem
   ```

3. Add `--env-file .secrets/compose.demo-tls.env` and `-f compose.demo-tls.yaml`
   after the demo entries in your Compose chain, then recreate `gateway` and
   `nginx`. The installer adds them on a rerun when that env file exists.

Port 8080 then accepts HTTPS only, so clients use `https://VM_LAN_IP:8080`. A
self-signed certificate must be trusted by `nasi-chat` and `curl` too. The
gateway stays reachable over plain HTTP on the VM's own `127.0.0.1:8000`.

## Known limits

- The customer demo guards remain inactive in test mode, the existing warning
  stays visible, and the previously reported long-prompt `503` is a separate,
  unresolved issue.
- This ingress is not TLS and is not approved for untrusted networks.
- Local tests prove file structure only. Actual nginx startup, Windows packet
  reachability and firewall behaviour require VM acceptance.
