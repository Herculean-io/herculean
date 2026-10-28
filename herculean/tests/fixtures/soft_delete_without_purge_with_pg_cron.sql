-- Personal data soft-deleted via deleted_at, with no purge job, on a database with pg_cron.
-- pg_cron is stubbed: its cron.job table with the extension's real columns, and
-- cron.schedule(job_name, schedule, command), which records a job as pg_cron does.
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
CREATE FUNCTION cron.schedule(job_name text, schedule text, command text) RETURNS bigint
LANGUAGE sql AS $$
    INSERT INTO cron.job (jobid, schedule, command, jobname)
    VALUES ((SELECT coalesce(max(jobid), 0) + 1 FROM cron.job), $2, $3, $1)
    RETURNING jobid
$$;
CREATE TABLE customers (
    id         bigserial PRIMARY KEY,
    email      text NOT NULL,
    deleted_at timestamptz
);
INSERT INTO customers (email, deleted_at) VALUES ('ophelia.wrenfold@rowvalue.test', now());
