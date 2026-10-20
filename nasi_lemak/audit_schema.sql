-- Bootstrap schema for the Nasi Lemak audit log (PostgreSQL).
--
-- Run this file with admin credentials during provisioning.  The runtime writer
-- role holds INSERT on ``events`` and USAGE on its sequence only; it does not
-- read, update or delete events and does not write the legacy ``owners`` table.
-- See audit_roles.sql for the example grants.

CREATE TABLE IF NOT EXISTS events (
    seq BIGSERIAL PRIMARY KEY,
    request_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    timestamp DOUBLE PRECISION NOT NULL,
    app_id TEXT NOT NULL,
    model TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    decision TEXT NOT NULL,
    error_code TEXT
);

CREATE TABLE IF NOT EXISTS owners (
    request_id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL
);

-- Recovery queries look for started events without a terminal event.  An index
-- on the two most-queried columns keeps the offline reconciliation bounded.
CREATE INDEX IF NOT EXISTS idx_events_request_type ON events(request_id, event_type);

-- The authenticated operator reader scopes every page to the trusted app
-- identity and pages forward by sequence, so this covering order is bounded.
CREATE INDEX IF NOT EXISTS idx_events_app_seq ON events(app_id, seq);

-- Append-only metadata for prepared CSV exports.  The writer inserts one row
-- before the CSV is released; the complete CSV, tokens and raw content are never
-- stored.  ``export_id`` is the public identifier and ``id`` only provides the
-- sequence used by the restricted writer role.
CREATE TABLE IF NOT EXISTS export_audits (
    id BIGSERIAL PRIMARY KEY,
    export_id TEXT NOT NULL UNIQUE,
    app_id TEXT NOT NULL,
    created_at DOUBLE PRECISION NOT NULL,
    filters TEXT NOT NULL,
    row_count INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    upper_seq BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_export_audits_app_created
    ON export_audits(app_id, created_at);
