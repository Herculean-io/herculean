CREATE TABLE accounts (
    id   bigserial PRIMARY KEY,
    plan text NOT NULL
);

CREATE TABLE customers (
    id         bigserial PRIMARY KEY,
    email      text NOT NULL,
    full_name  text NOT NULL,
    account_id bigint
);

CREATE TABLE contacts (
    id         bigserial PRIMARY KEY,
    phone      text,
    account_id bigint NOT NULL REFERENCES accounts (id) ON DELETE CASCADE
);

GRANT SELECT ON customers TO drift_app;
