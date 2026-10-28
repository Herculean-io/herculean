-- The live schema is exactly what the migrations (repos/migration_live_schema_match) define.
CREATE ROLE drift_app;
CREATE TABLE accounts (
    id   bigserial PRIMARY KEY,
    plan text NOT NULL
);
CREATE TABLE customers (
    id         bigserial PRIMARY KEY,
    email      text NOT NULL,
    account_id bigint NOT NULL REFERENCES accounts (id) ON DELETE CASCADE
);
GRANT SELECT, UPDATE ON customers TO drift_app;
