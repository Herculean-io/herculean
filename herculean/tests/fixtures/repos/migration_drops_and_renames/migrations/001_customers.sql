CREATE TABLE accounts (
    id   bigserial PRIMARY KEY,
    plan text NOT NULL
);

CREATE TABLE customers (
    id         bigserial PRIMARY KEY,
    mail       text NOT NULL,
    phone      text,
    account_id bigint NOT NULL REFERENCES accounts (id)
);

CREATE TABLE temp_imports (
    id    bigserial PRIMARY KEY,
    email text
);
