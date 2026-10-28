-- A migration / live schema mismatch: someone added customers.phone by hand
-- in production; the migrations (repos/migration_live_schema_mismatch) never did.
CREATE TABLE accounts (
    id   bigserial PRIMARY KEY,
    plan text NOT NULL
);
CREATE TABLE customers (
    id         bigserial PRIMARY KEY,
    email      text NOT NULL,
    phone      text,
    account_id bigint NOT NULL REFERENCES accounts (id) ON DELETE CASCADE
);
