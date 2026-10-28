-- PUBLIC may read a column that is not personal data: nothing to report.
CREATE TABLE accounts (
    id   bigserial PRIMARY KEY,
    plan text NOT NULL
);
CREATE TABLE customers (
    id         bigserial PRIMARY KEY,
    email      text NOT NULL,
    nickname   text,
    account_id bigint NOT NULL REFERENCES accounts (id) ON DELETE CASCADE
);
GRANT SELECT (nickname) ON customers TO PUBLIC;
