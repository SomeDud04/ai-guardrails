#!/usr/bin/env bash
# Rehearse the schema 5 upgrade on a throwaway copy of the live database.
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

before_version=$(sql -c 'SELECT MAX(version) FROM ws_schema_migrations')
before_users=$(sql -c 'SELECT COUNT(*) FROM ws_users')
echo "copied the live database: schema $before_version, $before_users accounts"
test "$before_version" = 4

mkdir "$WORK/workspace"
cp .secrets/workspace/workspace_key "$WORK/workspace/workspace_key"
echo "postgresql://nasi_lemak_admin:$PASSWORD@db:5432/nasi_lemak" > "$WORK/workspace/migration_dsn"
echo "postgresql://nl_rehearsal_runtime:$PASSWORD@db:5432/nasi_lemak" > "$WORK/workspace/workspace_dsn"
chown -R 10001:10001 "$WORK/workspace"
chmod 0700 "$WORK/workspace"
chmod 0400 "$WORK/workspace"/*

run() {
    docker run --rm -i --network nl-rehearsal --user 10001:10001 --cap-drop ALL \
        -e ADMIN_ID="${ADMIN_ID:-}" -v "$WORK/workspace:/secrets:ro" \
        --entrypoint python "$IMAGE" "$@"
}

run -m nasi_lemak.workspace_cli init --dsn-file /secrets/migration_dsn --key-file /secrets/workspace_key
sql < nasi_lemak/workspace_roles.sql >/dev/null
sql -c "CREATE ROLE nl_rehearsal_runtime LOGIN PASSWORD '$PASSWORD' IN ROLE nasi_lemak_workspace"

after_version=$(sql -c 'SELECT MAX(version) FROM ws_schema_migrations')
after_users=$(sql -c 'SELECT COUNT(*) FROM ws_users')
echo "after the migration: schema $after_version, $after_users accounts"
test "$after_version" = 5
test "$after_users" = "$before_users"

ADMIN_ID=$(sql -c "SELECT id FROM ws_users WHERE role = 'admin' AND disabled = 0 ORDER BY created_at LIMIT 1")
test -n "$ADMIN_ID"
export ADMIN_ID

run - <<'PY'
import hashlib
import os

from nasi_lemak import workspace_cli as cli

admin = os.environ["ADMIN_ID"]
key = cli._read_secret_file("/secrets/workspace_key", label="key")
dsn = cli._read_secret_file("/secrets/workspace_dsn", label="DSN")
store = cli._open_store(dsn, key, migrate=False, store_factory=None)
created = store.create_api_key(admin, "Rehearsal key")
digest = hashlib.sha256(created["key"].encode()).hexdigest()
key_id = created["item"]["id"]
assert store.resolve_api_key(digest) == {"id": key_id, "name": "Rehearsal key"}
store.record_api_key_use(key_id, "req_rehearsal")
listed = next(i for i in store.list_api_keys(admin)["items"] if i["id"] == key_id)
assert listed["requests"] == 1 and listed["last_used_at"] is not None
store.revoke_api_key(admin, key_id)
assert store.resolve_api_key(digest) is None
store.close()
print("runtime account: generate, resolve, record, list and revoke all worked")
PY

if docker exec -e PGPASSWORD="$PASSWORD" nl-rehearsal-db \
    psql -h 127.0.0.1 -U nl_rehearsal_runtime -d nasi_lemak \
    -c "DELETE FROM ws_api_key_uses" >/dev/null 2>&1; then
    echo "the runtime account must not be able to erase usage rows" >&2
    exit 1
fi
echo "runtime account: cannot erase usage rows"

echo REHEARSAL-OK
