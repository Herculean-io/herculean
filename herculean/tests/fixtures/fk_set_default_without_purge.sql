-- Same as fk_set_null_without_purge, with ON DELETE SET DEFAULT.
CREATE TABLE accounts (
    id   bigserial PRIMARY KEY,
    plan text NOT NULL
);
CREATE TABLE customers (
    id         bigserial PRIMARY KEY,
    email      text NOT NULL,
    account_id bigint NOT NULL DEFAULT 0 REFERENCES accounts (id) ON DELETE SET DEFAULT
);
