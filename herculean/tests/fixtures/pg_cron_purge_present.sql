-- Soft-deleted personal data purged by a scheduled pg_cron job.
-- pg_cron is stubbed: its schema and cron.job table with the extension's real columns.
CREATE SCHEMA cron;
CREATE TABLE cron.job (
    jobid    bigint PRIMARY KEY,
    schedule text NOT NULL,
    command  text NOT NULL,
    nodename text NOT NULL DEFAULT 'localhost',
    nodeport int NOT NULL DEFAULT 5432,
    database text NOT NULL DEFAULT current_database(),
    username text NOT NULL DEFAULT current_user,
    active   boolean NOT NULL DEFAULT true,
    jobname  text
);
CREATE TABLE customers (
    id         bigserial PRIMARY KEY,
    email      text NOT NULL,
    deleted_at timestamptz
);
INSERT INTO cron.job (jobid, schedule, command, jobname) VALUES
    (1, '0 3 * * *', 'DELETE FROM public.customers WHERE deleted_at < now() - interval ''30 days''', 'purge-customers');
