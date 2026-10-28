-- A logical-replication publication that ships a personal-data table elsewhere.
-- ON DELETE CASCADE gives customers a deletion path, isolating the flow.
CREATE TABLE accounts (
    id   bigserial PRIMARY KEY,
    plan text NOT NULL
);
CREATE TABLE customers (
    id         bigserial PRIMARY KEY,
    email      text NOT NULL,
    account_id bigint NOT NULL REFERENCES accounts (id) ON DELETE CASCADE
);
CREATE PUBLICATION customer_feed FOR TABLE customers, accounts;
