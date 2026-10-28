-- A table of personal data and nothing that ever deletes its rows.
-- Herculean reports it as a deletion_path finding (severity high).
CREATE TABLE customers (
    id         bigserial PRIMARY KEY,
    email      text NOT NULL,
    full_name  text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
