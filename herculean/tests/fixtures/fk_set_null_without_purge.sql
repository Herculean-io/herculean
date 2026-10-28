-- Personal data whose foreign key is ON DELETE SET NULL: deleting the parent keeps the row, so no deletion path.
CREATE TABLE accounts (
    id   bigserial PRIMARY KEY,
    plan text NOT NULL
);
CREATE TABLE customers (
    id         bigserial PRIMARY KEY,
    email      text NOT NULL,
    account_id bigint REFERENCES accounts (id) ON DELETE SET NULL
);
