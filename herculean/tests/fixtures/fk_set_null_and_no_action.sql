-- One foreign key with no ON DELETE handling and one SET NULL: only the first is a gap.
CREATE TABLE accounts (
    id   bigserial PRIMARY KEY,
    plan text NOT NULL
);
CREATE TABLE customers (
    id         bigserial PRIMARY KEY,
    email      text NOT NULL,
    account_id bigint NOT NULL REFERENCES accounts (id),
    referrer_id bigint REFERENCES accounts (id) ON DELETE SET NULL
);
