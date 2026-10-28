-- A postgres_fdw foreign table onto another database's contacts. Catalog only:
-- the server host does not resolve and the table is never queried.
CREATE EXTENSION postgres_fdw;
CREATE SERVER crm_remote FOREIGN DATA WRAPPER postgres_fdw
    OPTIONS (host 'unused.invalid', dbname 'crm');
CREATE FOREIGN TABLE crm_contacts (
    id    bigint,
    email text,
    plan  text
) SERVER crm_remote OPTIONS (schema_name 'public', table_name 'contacts');
