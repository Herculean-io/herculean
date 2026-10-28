-- A table of personal data. src/erase.py deletes its rows on request,
-- so Herculean finds a deletion path and reports no finding.
CREATE TABLE customers (
    id         bigserial PRIMARY KEY,
    email      text NOT NULL,
    full_name  text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
