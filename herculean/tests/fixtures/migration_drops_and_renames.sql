-- The live schema after every migration in repos/migration_drops_and_renames
-- ran, including its drops and renames.
CREATE TABLE accounts (
    id   bigserial PRIMARY KEY,
    plan text NOT NULL
);
CREATE TABLE clients (
    id         bigserial PRIMARY KEY,
    email      text NOT NULL,
    account_id bigint NOT NULL REFERENCES accounts (id) ON DELETE CASCADE
);
