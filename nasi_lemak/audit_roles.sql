-- PostgreSQL audit role provisioning (run once by a bootstrap administrator).
--
-- Requires nasi_lemak/audit_schema.sql to have been applied to the target
-- database.  This file defines NOLOGIN group roles only and contains no
-- passwords.  The operator creates LOGIN roles separately with credentials from
-- a secret manager and grants membership, for example:
--
--   CREATE ROLE nasi_lemak_gateway LOGIN;
--   -- Set its credential through the operator's secret-management procedure.
--   GRANT nasi_lemak_audit_writer TO nasi_lemak_gateway;
--
-- Runtime writer: append events and export-audit metadata only (INSERT).  It
-- cannot SELECT, UPDATE or DELETE audit rows.  Read and offline recovery use
-- separate roles.
-- Reader: SELECT events for dashboards/read-only tooling.  Export-audit viewing
-- is deferred, so the reader deliberately has no SELECT on ``export_audits``.
-- Recovery: SELECT and INSERT events for explicit offline reconciliation.
--
-- The legacy ``owners`` table in audit_schema.sql is not used by the PostgreSQL
-- runtime; no privileges below are granted on it.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nasi_lemak_audit_writer') THEN
        CREATE ROLE nasi_lemak_audit_writer NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nasi_lemak_audit_reader') THEN
        CREATE ROLE nasi_lemak_audit_reader NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nasi_lemak_audit_recovery') THEN
        CREATE ROLE nasi_lemak_audit_recovery NOLOGIN;
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public
    TO nasi_lemak_audit_writer, nasi_lemak_audit_reader, nasi_lemak_audit_recovery;

-- Re-running provisioning must not leave broader privileges from an earlier
-- grant.  The legacy owners table is not used by the PostgreSQL runtime.
REVOKE ALL PRIVILEGES ON TABLE public.events
    FROM nasi_lemak_audit_writer, nasi_lemak_audit_reader, nasi_lemak_audit_recovery;
REVOKE ALL PRIVILEGES ON TABLE public.owners
    FROM nasi_lemak_audit_writer, nasi_lemak_audit_reader, nasi_lemak_audit_recovery;
REVOKE ALL PRIVILEGES ON TABLE public.export_audits
    FROM nasi_lemak_audit_writer, nasi_lemak_audit_reader, nasi_lemak_audit_recovery;

GRANT INSERT ON TABLE public.events TO nasi_lemak_audit_writer;
GRANT SELECT ON TABLE public.events TO nasi_lemak_audit_reader;
GRANT SELECT, INSERT ON TABLE public.events TO nasi_lemak_audit_recovery;

-- Prepared-export metadata is append-only for the writer.  Readers and the
-- offline recovery role intentionally receive no export-audit privilege.
GRANT INSERT ON TABLE public.export_audits TO nasi_lemak_audit_writer;

-- BIGSERIAL columns use a sequence, so INSERT also needs USAGE on it.  Resolve
-- the sequence name at provision time so this remains correct after schema
-- qualification or a sequence rename.
DO $$
DECLARE
    event_seq text;
BEGIN
    event_seq := pg_get_serial_sequence('public.events', 'seq');
    IF event_seq IS NOT NULL THEN
        EXECUTE format(
            'REVOKE ALL PRIVILEGES ON SEQUENCE %s FROM nasi_lemak_audit_writer, '
            'nasi_lemak_audit_reader, nasi_lemak_audit_recovery',
            event_seq
        );
        EXECUTE format(
            'GRANT USAGE ON SEQUENCE %s TO nasi_lemak_audit_writer, '
            'nasi_lemak_audit_recovery',
            event_seq
        );
    END IF;
END
$$;

-- The export-audit table's BIGSERIAL identity needs USAGE for INSERT, but no
-- role receives SELECT/UPDATE/DELETE on the table itself.
DO $$
DECLARE
    export_seq text;
BEGIN
    export_seq := pg_get_serial_sequence('public.export_audits', 'id');
    IF export_seq IS NOT NULL THEN
        EXECUTE format(
            'REVOKE ALL PRIVILEGES ON SEQUENCE %s FROM nasi_lemak_audit_writer, '
            'nasi_lemak_audit_reader, nasi_lemak_audit_recovery',
            export_seq
        );
        EXECUTE format(
            'GRANT USAGE ON SEQUENCE %s TO nasi_lemak_audit_writer',
            export_seq
        );
    END IF;
END
$$;
