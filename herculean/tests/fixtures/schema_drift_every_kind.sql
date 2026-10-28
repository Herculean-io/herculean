-- Every kind of drift against repos/schema_drift_every_kind: leads exists only
-- live, contacts and customers.full_name only in the migrations, customers'
-- account FK is SET NULL live but CASCADE in the migrations, and the
-- migrations' grant to drift_app was never applied.
CREATE TABLE accounts (
    id   bigserial PRIMARY KEY,
    plan text NOT NULL
);
CREATE TABLE customers (
    id         bigserial PRIMARY KEY,
    email      text NOT NULL,
    account_id bigint REFERENCES accounts (id) ON DELETE SET NULL
);
CREATE TABLE leads (
    id         bigserial PRIMARY KEY,
    email      text NOT NULL,
    account_id bigint NOT NULL REFERENCES accounts (id) ON DELETE CASCADE
);
