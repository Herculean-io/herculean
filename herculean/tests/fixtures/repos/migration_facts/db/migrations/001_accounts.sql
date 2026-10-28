CREATE SCHEMA billing;

CREATE TABLE accounts (
    id   bigserial PRIMARY KEY,
    plan text NOT NULL
);

-- Removed with its account: ON DELETE CASCADE is a deletion path.
CREATE TABLE customers (
    id         bigserial PRIMARY KEY,
    account_id bigint NOT NULL REFERENCES accounts (id) ON DELETE CASCADE
);

-- Soft-deleted, and its account reference blocks deletion.
CREATE TABLE billing.contacts (
    id         bigserial PRIMARY KEY,
    phone      text,
    deleted_at timestamptz,
    account_id bigint NOT NULL,
    FOREIGN KEY (account_id) REFERENCES accounts (id)
);
