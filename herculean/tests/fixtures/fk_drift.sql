-- Foreign-key drift against repos/fk_drift: customers' reviewed CASCADE FK was
-- dropped live, leads gained an FK the migrations never added, and contacts'
-- FK references accounts.legacy_code live but accounts.code in the migrations.
CREATE TABLE accounts (
    id          bigserial PRIMARY KEY,
    code        text UNIQUE,
    legacy_code text UNIQUE
);
CREATE TABLE customers (
    id         bigserial PRIMARY KEY,
    email      text NOT NULL,
    account_id bigint
);
CREATE TABLE leads (
    id         bigserial PRIMARY KEY,
    email      text NOT NULL,
    account_id bigint REFERENCES accounts (id) ON DELETE CASCADE
);
CREATE TABLE contacts (
    id           bigserial PRIMARY KEY,
    email        text NOT NULL,
    account_code text REFERENCES accounts (legacy_code) ON DELETE CASCADE
);
