-- Cluster-wide roles with broad access to every personal-data table:
-- a superuser, an RLS-bypass role, and a role that reads all data through
-- a group role (transitive membership in pg_read_all_data).
CREATE ROLE ops_admin SUPERUSER;
CREATE ROLE etl_loader BYPASSRLS;
CREATE ROLE bi_readers;
GRANT pg_read_all_data TO bi_readers;
CREATE ROLE analyst LOGIN;
GRANT bi_readers TO analyst;
