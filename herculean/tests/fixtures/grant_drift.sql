-- Grant drift against the migrations tests/drift.rs writes (grant_drift_scan):
-- readonly reads every table in public, as `GRANT ... ON ALL TABLES IN SCHEMA`
-- leaves it, and customers is owned by app_owner. Roles are cluster-wide, so a
-- second database from this fixture reuses them.
DO $$ BEGIN CREATE ROLE readonly; EXCEPTION WHEN duplicate_object OR unique_violation THEN END $$;
DO $$ BEGIN CREATE ROLE app_owner; EXCEPTION WHEN duplicate_object OR unique_violation THEN END $$;
DO $$ BEGIN CREATE ROLE reporting; EXCEPTION WHEN duplicate_object OR unique_violation THEN END $$;
CREATE TABLE accounts (
    id   bigserial PRIMARY KEY,
    plan text NOT NULL
);
CREATE TABLE customers (
    id         bigserial PRIMARY KEY,
    email      text NOT NULL,
    account_id bigint NOT NULL REFERENCES accounts (id) ON DELETE CASCADE
);
ALTER TABLE customers OWNER TO app_owner;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonly;
