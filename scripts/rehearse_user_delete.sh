#!/usr/bin/env bash
# Rehearse deleting a user with the runtime account on a throwaway copy of the
# live database, because SQLite tests cannot exercise PostgreSQL grants.
#
# Run as root on the VM after building the new image.  The live gateway and
# database keep running: this only reads a pg_dump of the live database, then
# works in a separate PostgreSQL container that it removes on exit, including
# after a failure.  Prints REHEARSAL-OK when every check passes.

set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE=nasi-lemak-gateway:0.1.0-pilot
PASSWORD=rehearsal-only
umask 077
WORK=$(mktemp -d /tmp/nl-rehearsal.XXXX)

cleanup() {
    docker rm -f nl-rehearsal-db >/dev/null 2>&1 || true
    docker network rm nl-rehearsal >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

sql() {
    docker exec -i nl-rehearsal-db psql -q -tA -U nasi_lemak_admin -d nasi_lemak -v ON_ERROR_STOP=1 "$@"
}

docker network create nl-rehearsal >/dev/null
docker run -d --name nl-rehearsal-db --network nl-rehearsal --network-alias db \
    -e POSTGRES_USER=nasi_lemak_admin -e POSTGRES_PASSWORD="$PASSWORD" \
    -e POSTGRES_DB=nasi_lemak postgres:16.4-bookworm >/dev/null
until docker exec -e PGPASSWORD="$PASSWORD" nl-rehearsal-db \
    psql -h 127.0.0.1 -U nasi_lemak_admin -d nasi_lemak -c 'SELECT 1' >/dev/null 2>&1; do
    sleep 2
done

nl-compose exec -T db sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' > "$WORK/live.dump"
test -s "$WORK/live.dump"
docker exec -i nl-rehearsal-db pg_restore -U nasi_lemak_admin -d nasi_lemak \
    --no-owner --no-privileges --exit-on-error < "$WORK/live.dump"
rm -f "$WORK/live.dump"

sql < nasi_lemak/workspace_roles.sql >/dev/null
sql -c "CREATE ROLE nl_rehearsal_runtime LOGIN PASSWORD '$PASSWORD' IN ROLE nasi_lemak_workspace"

mkdir "$WORK/workspace"
cp .secrets/workspace/workspace_key "$WORK/workspace/workspace_key"
echo "postgresql://nl_rehearsal_runtime:$PASSWORD@db:5432/nasi_lemak" > "$WORK/workspace/workspace_dsn"
chown -R 10001:10001 "$WORK/workspace"
chmod 0700 "$WORK/workspace"
chmod 0400 "$WORK/workspace"/*

ADMIN_ID=$(sql -c "SELECT id FROM ws_users WHERE role = 'admin' AND disabled = 0 ORDER BY created_at LIMIT 1")
DEPARTMENT_ID=$(sql -c "SELECT id FROM ws_departments ORDER BY created_at LIMIT 1")
test -n "$ADMIN_ID"
test -n "$DEPARTMENT_ID"

python_step() {
    docker run --rm -i --network nl-rehearsal --user 10001:10001 --cap-drop ALL \
        -e ADMIN_ID="$ADMIN_ID" -e DEPARTMENT_ID="$DEPARTMENT_ID" -e PHASE="$1" \
        -v "$WORK/workspace:/secrets:ro" --entrypoint python "$IMAGE" -
}

USER_ID=$(python_step create <<'PY'
import os

from nasi_lemak import workspace_cli as cli

key = cli._read_secret_file("/secrets/workspace_key", label="key")
dsn = cli._read_secret_file("/secrets/workspace_dsn", label="DSN")
store = cli._open_store(dsn, key, migrate=False, store_factory=None)
user = store.create_user(
    os.environ["ADMIN_ID"],
    "rehearsal.delete",
    "Rehearsal-Only-2026!",
    "Rehearsal Delete",
    os.environ["DEPARTMENT_ID"],
    "employee",
)
store.create_conversation(user["id"])
store.authenticate("rehearsal.delete", "Rehearsal-Only-2026!")
store.close()
print(user["id"])
PY
)

# An alert about this account, written as an administrator because the runtime
# path needs a real blocked turn.  The delete must remove it through the foreign key.
sql -c "INSERT INTO ws_block_alerts(id, request_id, user_id, department_id, stage, reason_code, reason_text, control_revision, control_digest, control_sources, created_at)
        VALUES ('rehearsal-alert', 'req_rehearsal', '$USER_ID', '$DEPARTMENT_ID', 'input', 'INPUT_GUARD_BLOCK', 'Rehearsal', 'server-default', repeat('a', 64), '[]', 1)"
sql -c "INSERT INTO ws_alert_state(alert_id, admin_id, read_at) VALUES ('rehearsal-alert', '$ADMIN_ID', 1)"

other_alerts=$(sql -c "SELECT COUNT(*) FROM ws_block_alerts WHERE id <> 'rehearsal-alert'")

if docker exec -e PGPASSWORD="$PASSWORD" nl-rehearsal-db \
    psql -h 127.0.0.1 -U nl_rehearsal_runtime -d nasi_lemak \
    -c "DELETE FROM ws_block_alerts WHERE id = 'rehearsal-alert'" >/dev/null 2>&1; then
    echo "the runtime account must not be able to delete alerts directly" >&2
    exit 1
fi
echo "runtime account: cannot delete alerts directly"

USER_ID="$USER_ID" python_step delete <<PY
import os

from nasi_lemak import workspace_cli as cli

key = cli._read_secret_file("/secrets/workspace_key", label="key")
dsn = cli._read_secret_file("/secrets/workspace_dsn", label="DSN")
store = cli._open_store(dsn, key, migrate=False, store_factory=None)
result = store.delete_user(os.environ["ADMIN_ID"], "$USER_ID", "rehearsal.delete")
assert result["status"] == "deleted", result
assert result["deleted_conversations"] == 1, result
store.close()
print("runtime account: deleted the user")
PY

test "$(sql -c "SELECT COUNT(*) FROM ws_users WHERE id = '$USER_ID'")" = 0
test "$(sql -c "SELECT COUNT(*) FROM ws_sessions WHERE user_id = '$USER_ID'")" = 0
test "$(sql -c "SELECT COUNT(*) FROM ws_block_alerts WHERE id = 'rehearsal-alert'")" = 0
test "$(sql -c "SELECT COUNT(*) FROM ws_alert_state WHERE alert_id = 'rehearsal-alert'")" = 0
test "$(sql -c "SELECT COUNT(*) FROM ws_block_alerts")" = "$other_alerts"
test "$(sql -c "SELECT COUNT(*) FROM ws_access_log WHERE action = 'admin.delete_user:$USER_ID'")" = 1
echo "account, sessions and its alert are gone; other alerts kept; deletion is in the access log"

echo REHEARSAL-OK
