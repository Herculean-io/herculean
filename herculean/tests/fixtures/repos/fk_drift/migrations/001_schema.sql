CREATE TABLE accounts (
    id          bigserial PRIMARY KEY,
    code        text UNIQUE,
    legacy_code text UNIQUE
);

CREATE TABLE customers (
    id         bigserial PRIMARY KEY,
    email      text NOT NULL,
    account_id bigint REFERENCES accounts (id) ON DELETE CASCADE
);

CREATE TABLE leads (
    id         bigserial PRIMARY KEY,
    email      text NOT NULL,
    account_id bigint
);

CREATE TABLE contacts (
    id           bigserial PRIMARY KEY,
    email        text NOT NULL,
    account_code text REFERENCES accounts (code) ON DELETE CASCADE
);
