-- Personal data whose deferrable foreign key (MATCH FULL, ON UPDATE CASCADE,
-- INITIALLY DEFERRED) has no ON DELETE handling: a fix must keep the rest of the key.
CREATE TABLE accounts (
    id   bigserial PRIMARY KEY,
    plan text NOT NULL
);
CREATE TABLE customers (
    id         bigserial PRIMARY KEY,
    email      text NOT NULL,
    account_id bigint,
    CONSTRAINT customers_account_fk FOREIGN KEY (account_id) REFERENCES accounts (id)
        MATCH FULL ON UPDATE CASCADE DEFERRABLE INITIALLY DEFERRED
);
