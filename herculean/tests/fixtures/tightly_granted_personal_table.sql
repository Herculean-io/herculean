-- A multi-tenant personal-data table done right: row-level security on,
-- SELECT granted to one application role only, nothing to PUBLIC.
CREATE ROLE tenant_app;
CREATE TABLE orgs (
    id   bigserial PRIMARY KEY,
    plan text NOT NULL
);
CREATE TABLE members (
    id        bigserial PRIMARY KEY,
    email     text NOT NULL,
    tenant_id bigint NOT NULL REFERENCES orgs (id) ON DELETE CASCADE
);
ALTER TABLE members ENABLE ROW LEVEL SECURITY;
CREATE POLICY members_by_tenant ON members
    USING (tenant_id = current_setting('app.tenant_id')::bigint);
GRANT SELECT ON members TO tenant_app;
