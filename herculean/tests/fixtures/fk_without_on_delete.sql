-- Personal data whose foreign key to its parent has no ON DELETE handling (NO ACTION).
CREATE TABLE accounts (
    id   bigserial PRIMARY KEY,
    plan text NOT NULL
);
CREATE TABLE customers (
    id         bigserial PRIMARY KEY,
    email      text NOT NULL,
    account_id bigint NOT NULL REFERENCES accounts (id)
);
