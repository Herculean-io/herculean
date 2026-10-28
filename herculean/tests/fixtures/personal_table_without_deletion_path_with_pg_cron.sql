-- One table of personal data with no deletion path, plus one non-personal table, on a
-- database with pg_cron (stubbed as in soft_delete_without_purge_with_pg_cron.sql).
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
    full_name  text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO customers (email, full_name) VALUES
    ('zelda.quixote@rowvalue.test', 'Zelda Quixote'),
    ('barnaby.fizzwick@rowvalue.test', 'Barnaby Fizzwick');

CREATE TABLE products (
    id    bigserial PRIMARY KEY,
    sku   text NOT NULL,
    price numeric(10, 2) NOT NULL
);
INSERT INTO products (sku, price) VALUES ('SKU-XYZZY-9931', 12.34);
