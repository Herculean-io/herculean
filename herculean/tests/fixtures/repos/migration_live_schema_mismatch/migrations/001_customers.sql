CREATE TABLE accounts (
    id   bigserial PRIMARY KEY,
    plan text NOT NULL
);

CREATE TABLE customers (
    id         bigserial PRIMARY KEY,
    email      text NOT NULL,
    account_id bigint NOT NULL REFERENCES accounts (id) ON DELETE CASCADE
);
