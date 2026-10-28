CREATE TABLE accounts (
    id   bigserial PRIMARY KEY,
    plan text NOT NULL
);

CREATE TABLE contacts (
    id    bigserial PRIMARY KEY,
    reach text
);
COMMENT ON COLUMN contacts.reach IS 'customer email';
