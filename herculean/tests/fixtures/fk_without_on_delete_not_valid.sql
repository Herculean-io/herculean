-- Personal data whose foreign key was added NOT VALID (existing rows unchecked)
-- and has no ON DELETE handling: a fix must keep it NOT VALID.
CREATE TABLE accounts (
    id   bigserial PRIMARY KEY,
    plan text NOT NULL
);
CREATE TABLE customers (
    id         bigserial PRIMARY KEY,
    email      text NOT NULL,
    account_id bigint
);
INSERT INTO customers (email, account_id) VALUES ('quill.marrowby@rowvalue.test', 42);
ALTER TABLE customers ADD CONSTRAINT customers_account_fk
    FOREIGN KEY (account_id) REFERENCES accounts (id) NOT VALID;
