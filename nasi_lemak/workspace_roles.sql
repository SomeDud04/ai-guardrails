-- PostgreSQL privileges for the opt-in employee-workspace runtime.
--
-- Run once, as a PostgreSQL administrator, AFTER `workspace_cli init` has
-- created the schema and BEFORE the restricted runtime account is used.  This
-- file defines one fixed NOLOGIN group role and grants only explicit privileges
-- on the fixed `ws_*` tables.  It contains no password and creates no LOGIN
-- role.
--
-- The operator then creates a fresh dedicated LOGIN account, grants membership
-- in `nasi_lemak_workspace`, sets its credential interactively with psql
-- `\password`, and writes that account's DSN to a root/10001-readable runtime
-- DSN file.  The migration credential must remain separate from this runtime
-- group.
--
-- Re-running is safe: grants are re-applied and each table is reset to exactly
-- the listed privileges.  An existing group with elevated attributes or any
-- foreign role membership fails rather than being silently broadened.

DO $$
DECLARE
    workspace_role oid;
BEGIN
    SELECT oid INTO workspace_role
    FROM pg_roles
    WHERE rolname = 'nasi_lemak_workspace';

    IF workspace_role IS NULL THEN
        CREATE ROLE nasi_lemak_workspace NOLOGIN;
        SELECT oid INTO workspace_role
        FROM pg_roles
        WHERE rolname = 'nasi_lemak_workspace';
    ELSE
        IF EXISTS (
            SELECT 1 FROM pg_roles
            WHERE oid = workspace_role
              AND (
                  rolcanlogin
                  OR rolsuper
                  OR rolcreaterole
                  OR rolcreatedb
                  OR rolreplication
                  OR rolbypassrls
              )
        ) THEN
            RAISE EXCEPTION
                'nasi_lemak_workspace has elevated attributes';
        END IF;
        IF EXISTS (
            SELECT 1 FROM pg_auth_members
            WHERE member = workspace_role
        ) THEN
            RAISE EXCEPTION
                'nasi_lemak_workspace has foreign role membership';
        END IF;
    END IF;
END
$$;

-- The runtime may resolve the schema but must not create objects in it.
GRANT USAGE ON SCHEMA public TO nasi_lemak_workspace;
REVOKE CREATE ON SCHEMA public FROM nasi_lemak_workspace;

-- Reset each fixed table to its explicit privilege set.  This removes any
-- broader grant left by an earlier revision without touching other roles.
REVOKE ALL PRIVILEGES ON TABLE
    public.ws_schema_migrations,
    public.ws_meta,
    public.ws_departments,
    public.ws_users,
    public.ws_sessions,
    public.ws_review_grants,
    public.ws_conversations,
    public.ws_messages,
    public.ws_access_log,
    public.ws_policy_profiles,
    public.ws_policy_profile_revisions,
    public.ws_policy_assignments,
    public.ws_policy_audit,
    public.ws_block_alerts,
    public.ws_alert_state
FROM nasi_lemak_workspace;

-- Migration metadata is read-only to the runtime.
GRANT SELECT ON TABLE public.ws_schema_migrations TO nasi_lemak_workspace;
GRANT SELECT ON TABLE public.ws_meta TO nasi_lemak_workspace;

-- Append-only access audit; the runtime cannot rewrite or erase it.
GRANT SELECT, INSERT ON TABLE public.ws_access_log TO nasi_lemak_workspace;

-- Explicit data privileges used by the WorkspaceStore operations.
GRANT SELECT, INSERT ON TABLE public.ws_departments TO nasi_lemak_workspace;
GRANT SELECT, INSERT, UPDATE ON TABLE public.ws_users TO nasi_lemak_workspace;
GRANT SELECT, INSERT, UPDATE ON TABLE public.ws_sessions TO nasi_lemak_workspace;
GRANT SELECT, INSERT, DELETE ON TABLE public.ws_review_grants TO nasi_lemak_workspace;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.ws_conversations TO nasi_lemak_workspace;
GRANT SELECT, INSERT, DELETE ON TABLE public.ws_messages TO nasi_lemak_workspace;

-- Policy administration.  Profiles may change only their optimistic-concurrency
-- version/timestamp; revision rows are append-only and cannot be rewritten or
-- erased.  The policy audit trail is likewise append-only.  Assignments are the
-- one mutable scope mapping (set, update revision, or clear).
GRANT SELECT, INSERT, UPDATE ON TABLE public.ws_policy_profiles TO nasi_lemak_workspace;
GRANT SELECT, INSERT ON TABLE public.ws_policy_profile_revisions TO nasi_lemak_workspace;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.ws_policy_assignments TO nasi_lemak_workspace;
GRANT SELECT, INSERT ON TABLE public.ws_policy_audit TO nasi_lemak_workspace;

-- Block alerts are the immutable metadata record of a failed turn.  The runtime
-- may append and read them but cannot rewrite or erase alert history.  Only the
-- per-administrator read/acknowledgement state is mutable.
GRANT SELECT, INSERT ON TABLE public.ws_block_alerts TO nasi_lemak_workspace;
GRANT SELECT, INSERT, UPDATE ON TABLE public.ws_alert_state TO nasi_lemak_workspace;
