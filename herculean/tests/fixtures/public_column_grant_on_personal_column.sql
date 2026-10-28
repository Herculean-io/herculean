-- Every role may read one personal column: SELECT (email) granted to PUBLIC,
-- with no table-level grant. ON DELETE CASCADE gives customers a deletion path.
CREATE TABLE accounts (
    id   bigserial PRIMARY KEY,
    plan text NOT NULL
);
CREATE TABLE customers (
    id         bigserial PRIMARY KEY,
    email      text NOT NULL,
    phone      text NOT NULL,
    account_id bigint NOT NULL REFERENCES accounts (id) ON DELETE CASCADE
);
GRANT SELECT (email, phone) ON customers TO PUBLIC;
