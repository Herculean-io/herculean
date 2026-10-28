CREATE TABLE accounts (
    id   bigserial PRIMARY KEY,
    plan text NOT NULL
);

CREATE TABLE customers (
    id         bigserial PRIMARY KEY,
    email      text NOT NULL,
    account_id bigint NOT NULL
);

CREATE TABLE contacts (
    id         bigserial PRIMARY KEY,
    phone      text,
    account_id bigint
);
