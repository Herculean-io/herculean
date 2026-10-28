-- Every role may read a personal-data table: SELECT granted to PUBLIC.
-- ON DELETE CASCADE gives customers a deletion path, isolating the grant.
CREATE TABLE accounts (
    id   bigserial PRIMARY KEY,
    plan text NOT NULL
);
CREATE TABLE customers (
    id         bigserial PRIMARY KEY,
    email      text NOT NULL,
    account_id bigint NOT NULL REFERENCES accounts (id) ON DELETE CASCADE
);
GRANT SELECT ON customers TO PUBLIC;
