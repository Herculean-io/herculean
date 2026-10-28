-- A multi-tenant personal-data table (org_id) without row-level security:
-- nothing stops one tenant's queries from reading another's members.
CREATE TABLE orgs (
    id   bigserial PRIMARY KEY,
    plan text NOT NULL
);
CREATE TABLE members (
    id     bigserial PRIMARY KEY,
    email  text NOT NULL,
    org_id bigint NOT NULL REFERENCES orgs (id) ON DELETE CASCADE
);
