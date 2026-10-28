-- Broad role grants: any privilege on a personal-data table granted to a group
-- role (a role with at least one member), other than the table owner.
-- * support_team has a member: its SELECT on customers is broad.
-- * crm_owners owns customers and has a member: the owner is not reported.
-- * web_app is a login role without members (an app role): not reported.
-- * support_team on accounts: not a personal-data table, not reported.
-- ON DELETE CASCADE gives customers a deletion path, isolating the grants.
CREATE ROLE support_team;
CREATE ROLE support_agent LOGIN;
GRANT support_team TO support_agent;
CREATE ROLE crm_owners;
CREATE ROLE crm_admin LOGIN;
GRANT crm_owners TO crm_admin;
CREATE ROLE web_app LOGIN;
CREATE TABLE accounts (
    id   bigserial PRIMARY KEY,
    plan text NOT NULL
);
CREATE TABLE customers (
    id         bigserial PRIMARY KEY,
    email      text NOT NULL,
    account_id bigint NOT NULL REFERENCES accounts (id) ON DELETE CASCADE
);
ALTER TABLE customers OWNER TO crm_owners;
GRANT SELECT ON customers TO support_team;
GRANT SELECT, INSERT, UPDATE, DELETE ON customers TO web_app;
GRANT SELECT ON accounts TO support_team;
