-- Cascading drops take the foreign keys that reference the dropped table or column.
CREATE TABLE accounts (id bigint PRIMARY KEY);
CREATE TABLE customers (
    id         bigint PRIMARY KEY,
    email      text,
    account_id bigint REFERENCES accounts ON DELETE CASCADE
);
DROP TABLE accounts CASCADE;

CREATE TABLE orgs (id bigint PRIMARY KEY, code text UNIQUE);
CREATE TABLE members (
    id       bigint PRIMARY KEY,
    email    text,
    org_code text REFERENCES orgs (code) ON DELETE CASCADE
);
ALTER TABLE orgs DROP COLUMN code CASCADE;
