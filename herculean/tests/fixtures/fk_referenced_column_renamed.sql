-- The referenced column is renamed after the foreign key names it.
CREATE TABLE accounts (id bigint PRIMARY KEY);
CREATE TABLE customers (
    id         bigint PRIMARY KEY,
    email      text,
    account_id bigint REFERENCES accounts (id)
);
ALTER TABLE accounts RENAME COLUMN id TO account_key;
