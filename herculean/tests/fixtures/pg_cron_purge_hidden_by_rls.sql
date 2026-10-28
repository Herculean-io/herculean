-- pg_cron's real row-level security on cron.job: each role sees only its own jobs.
-- The purge job belongs to another role, so a reader cannot see it.
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
ALTER TABLE cron.job ENABLE ROW LEVEL SECURITY;
CREATE POLICY cron_job_policy ON cron.job USING (username = CURRENT_USER);
CREATE TABLE customers (
    id         bigserial PRIMARY KEY,
    email      text NOT NULL,
    deleted_at timestamptz
);
INSERT INTO cron.job (jobid, schedule, command, username, jobname) VALUES
    (1, '0 3 * * *', 'DELETE FROM public.customers WHERE deleted_at < now() - interval ''30 days''', 'postgres', 'purge-customers');
