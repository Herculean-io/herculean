-- Managed-service roles. Provider-owned roles (internal superusers, RLS
-- bypassers, the admin group roles themselves) are notes; members of a
-- provider admin role are the customer's admins and a finding.
CREATE ROLE rds_superuser NOLOGIN;
CREATE ROLE rdsadmin SUPERUSER;
CREATE ROLE app_admin LOGIN;
GRANT rds_superuser TO app_admin;
CREATE ROLE cloudsqlsuperuser NOLOGIN;
CREATE ROLE cloudsqladmin SUPERUSER;
CREATE ROLE gcp_admin LOGIN;
GRANT cloudsqlsuperuser TO gcp_admin;
CREATE ROLE neon_superuser NOLOGIN BYPASSRLS;
GRANT pg_read_all_data TO neon_superuser;
CREATE ROLE neon_owner LOGIN;
GRANT neon_superuser TO neon_owner;
CREATE ROLE supabase_admin SUPERUSER;
CREATE ROLE service_role NOLOGIN BYPASSRLS;
CREATE ROLE supabase_etl_admin BYPASSRLS;
