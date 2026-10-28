-- Herculean read-only role: the complete grant list.
--
-- Herculean reads the system catalogs (pg_catalog), which PUBLIC can already
-- read, so the base role is LOGIN and CONNECT. Two additions below:
--   * pg_cron's cron.job (only when pg_cron is installed), to see purge jobs;
--   * optional, commented-out column grants, only for `scan --sample`.
-- Without --sample the role needs, and is granted, no privilege on a user table.
--
-- Run with psql, supplying the three variables:
--   psql -v role=herculean_reader -v password='...' -v database=mydb -f read-only-role.sql
CREATE ROLE :"role" LOGIN PASSWORD :'password';
GRANT CONNECT ON DATABASE :"database" TO :"role";
-- Role settings apply at every server login, so read-only holds even behind a
-- transaction-mode pooler that drops session SETs (Herculean also sets it per session).
-- For a role that already exists, run only this statement (CREATE ROLE would fail).
ALTER ROLE :"role" SET default_transaction_read_only = on;

-- Only when pg_cron is installed: read its job table so scheduled purge jobs
-- count as deletion paths. Skipped automatically when cron.job does not exist.
-- pg_cron enables row-level security on cron.job (policy: username = CURRENT_USER),
-- so this role sees only its own jobs. To see other roles' purge jobs, the
-- cron.job owner must grant visibility (e.g. an extra SELECT policy for this
-- role) or the role needs BYPASSRLS. Without it the report carries the note
-- "scheduled_jobs_unreadable" and purge jobs it cannot see are not counted.
SELECT format('GRANT USAGE ON SCHEMA cron TO %I; GRANT SELECT ON cron.job TO %I', :'role', :'role')
WHERE to_regclass('cron.job') IS NOT NULL \gexec

-- OPTIONAL, when pg_cron keeps its jobs in a database other than `postgres`
-- (cron.database_name): pg_cron hides that setting from non-superusers.
-- WARNING: this built-in role shows the reader every server setting, including
-- ones that can hold credentials (primary_conninfo, archive_command,
-- restore_command). Leave it off unless pg_cron lives outside `postgres`.
--   GRANT pg_read_all_settings TO herculean_reader;
-- Then, connected to the cron database (here crondb):
--   GRANT CONNECT ON DATABASE crondb TO herculean_reader;
--   GRANT USAGE ON SCHEMA cron TO herculean_reader;
--   GRANT SELECT ON cron.job TO herculean_reader;

-- OPTIONAL, only for `herculean scan --sample`: sampling reads up to 100 values
-- of each text column the name rules leave ambiguous, one column at a time.
-- Grant SELECT on exactly those columns, nothing wider, e.g.:
--   GRANT SELECT (reach, memo) ON public.leads TO herculean_reader;
-- Values are checked in-process and dropped; only counts are reported.
