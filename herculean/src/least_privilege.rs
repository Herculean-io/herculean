//! Least-privilege check: roles and grants broader than personal data needs.
//! Catalog reads only (pg_roles, pg_auth_members, pg_class, pg_attribute).

use crate::steps::RESTRICT;
use crate::{Finding, Store};
use std::collections::BTreeSet;

/// The customer's admin roles on managed services: not superusers, but their
/// members can grant themselves anything.
const PROVIDER_ADMIN_ROLES: &[&str] = &[
    "rds_superuser",
    "cloudsqlsuperuser",
    "alloydbsuperuser",
    "azure_pg_admin",
    "neon_superuser",
    "yb_superuser",
];

/// Roles the provider owns and the customer cannot change: internal
/// superusers and RLS-bypass service roles. Notes, not findings.
const PROVIDER_MANAGED_ROLES: &[&str] = &[
    "rdsadmin",
    "cloudsqladmin",
    "supabase_admin",
    "service_role",
    "supabase_etl_admin",
];

/// Cluster-wide roles with broad access: superuser, member of a provider
/// admin role (other than itself), RLS bypass, or (transitive) member of
/// pg_read_all_data or pg_write_all_data. Skips the bootstrap superuser (oid
/// 10, cannot be removed) and predefined `pg_` roles (pg_read_all_data is a
/// member of itself). Admin roles are looked up in pg_roles first:
/// pg_has_role errors on a role name that does not exist.
fn roles_sql() -> String {
    let admins: Vec<String> = PROVIDER_ADMIN_ROLES
        .iter()
        .map(|r| format!("'{r}'"))
        .collect();
    format!(
        "SELECT * FROM (SELECT r.rolname::text, r.rolsuper, r.rolbypassrls, \
           EXISTS (SELECT 1 FROM pg_catalog.pg_roles a \
             WHERE a.rolname IN ({}) AND a.oid <> r.oid \
               AND pg_catalog.pg_has_role(r.oid, a.oid, 'MEMBER')) AS admin, \
           pg_catalog.pg_has_role(r.oid, 'pg_read_all_data', 'MEMBER') \
             OR pg_catalog.pg_has_role(r.oid, 'pg_write_all_data', 'MEMBER') AS read_all \
         FROM pg_catalog.pg_roles r \
         WHERE r.oid <> 10 AND r.rolname NOT LIKE 'pg\\_%') roles \
         WHERE rolsuper OR rolbypassrls OR admin OR read_all \
         ORDER BY 1",
        admins.join(", ")
    )
}

/// A role the provider owns: the constant lists, plus `postgres` and
/// `yugabyte` on YugabyteDB (elsewhere a role named `postgres` is the
/// customer's own admin).
fn provider_managed(role: &str, yugabyte: bool) -> bool {
    PROVIDER_MANAGED_ROLES.contains(&role)
        || PROVIDER_ADMIN_ROLES.contains(&role)
        || (yugabyte && ["postgres", "yugabyte"].contains(&role))
}

/// Tables with any privilege granted to PUBLIC (aclexplode grantee 0).
const PUBLIC_GRANTS_SQL: &str = "SELECT DISTINCT n.nspname, c.relname \
     FROM pg_catalog.pg_class c \
     JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
     CROSS JOIN LATERAL pg_catalog.aclexplode(c.relacl) acl \
     WHERE acl.grantee = 0";

/// Broad role grants: any table privilege granted to a group role (one with
/// at least one member in pg_auth_members), other than the table owner.
/// PUBLIC (grantee 0) has no members and stays its own finding.
const GROUP_ROLE_GRANTS_SQL: &str = "SELECT DISTINCT n.nspname, c.relname, \
       pg_catalog.pg_get_userbyid(acl.grantee)::text \
     FROM pg_catalog.pg_class c \
     JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
     CROSS JOIN LATERAL pg_catalog.aclexplode(c.relacl) acl \
     WHERE acl.grantee <> c.relowner \
       AND EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.roleid = acl.grantee)";

/// Columns with SELECT granted to PUBLIC (pg_attribute.attacl, grantee 0): a
/// column-level grant is not in the table's relacl.
const PUBLIC_COLUMN_GRANTS_SQL: &str = "SELECT n.nspname, c.relname, a.attname \
     FROM pg_catalog.pg_attribute a \
     JOIN pg_catalog.pg_class c ON c.oid = a.attrelid \
     JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
     CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl \
     WHERE a.attnum > 0 AND NOT a.attisdropped \
       AND acl.grantee = 0 AND acl.privilege_type = 'SELECT'";

/// Tenant-scoping columns. `account_id` is left out: it is as often an
/// ordinary foreign key.
const TENANT_COLUMNS: &[&str] = &["tenant_id", "org_id", "organization_id", "workspace_id"];

/// Tables without row-level security that have a tenant-scoping column.
fn missing_rls_sql() -> String {
    let names: Vec<String> = TENANT_COLUMNS.iter().map(|c| format!("'{c}'")).collect();
    format!(
        "SELECT DISTINCT n.nspname, c.relname \
         FROM pg_catalog.pg_class c \
         JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
         JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid \
         WHERE NOT c.relrowsecurity AND a.attnum > 0 AND NOT a.attisdropped \
           AND a.attname IN ({})",
        names.join(", ")
    )
}

/// Least-privilege findings: every privileged role, and every personal-data
/// table in `stores` granted to PUBLIC (whole, or one personal column of it)
/// or to a group role, or missing RLS. Provider-owned roles come back as
/// notes instead.
pub fn findings(
    client: &mut crate::Catalog,
    stores: &[Store],
    system_id: &str,
    yugabyte: bool,
) -> Result<(Vec<Finding>, Vec<String>), postgres::Error> {
    let personal: BTreeSet<String> = stores
        .iter()
        .map(|s| format!("{}.{}", s.schema, s.table))
        .collect();
    let mut findings = Vec::new();
    let mut notes = Vec::new();
    for row in client.query(&roles_sql())? {
        let role: &str = row.get(0);
        let kind = match (row.get(1), row.get(3), row.get(2)) {
            (true, _, _) => "superuser_role",
            (false, true, _) => "provider_admin_role",
            (false, false, true) => "bypassrls_role",
            (false, false, false) => "read_all_data_role",
        };
        if provider_managed(role, yugabyte) {
            notes.push(if role == "service_role" {
                "provider_managed_role: service_role; anyone with the service key \
                 bypasses RLS, so keep the key out of clients"
                    .to_string()
            } else {
                format!("provider_managed_role: {role}")
            });
            continue;
        }
        findings.push(Finding::treatment(
            "least_privilege",
            kind,
            &format!("role:{role}"),
            RESTRICT,
            system_id,
            &format!("pg_roles:{role}"),
        ));
    }
    for (kind, sql, evidence) in [
        (
            "public_grant",
            PUBLIC_GRANTS_SQL.to_string(),
            "pg_class.relacl",
        ),
        ("missing_rls", missing_rls_sql(), "pg_class.relrowsecurity"),
    ] {
        for row in client.query(&sql)? {
            let table = format!("{}.{}", row.get::<_, &str>(0), row.get::<_, &str>(1));
            if personal.contains(&table) {
                findings.push(Finding::treatment(
                    "least_privilege",
                    kind,
                    &table,
                    RESTRICT,
                    system_id,
                    &format!("{evidence}:{table}"),
                ));
            }
        }
    }
    for row in client.query(GROUP_ROLE_GRANTS_SQL)? {
        let table = format!("{}.{}", row.get::<_, &str>(0), row.get::<_, &str>(1));
        if personal.contains(&table) {
            let role: &str = row.get(2);
            findings.push(Finding::treatment(
                "least_privilege",
                "group_role_grant",
                &table,
                RESTRICT,
                system_id,
                &format!("pg_class.relacl:{table}:{role}"),
            ));
        }
    }
    let personal_columns: BTreeSet<String> = stores
        .iter()
        .flat_map(|s| {
            s.columns
                .iter()
                .map(move |c| format!("{}.{}.{}", s.schema, s.table, c.name))
        })
        .collect();
    for row in client.query(PUBLIC_COLUMN_GRANTS_SQL)? {
        let column = format!(
            "{}.{}.{}",
            row.get::<_, &str>(0),
            row.get::<_, &str>(1),
            row.get::<_, &str>(2)
        );
        if personal_columns.contains(&column) {
            let table = format!("{}.{}", row.get::<_, &str>(0), row.get::<_, &str>(1));
            findings.push(Finding::treatment(
                "least_privilege",
                "public_grant",
                &table,
                RESTRICT,
                system_id,
                &format!("pg_attribute.attacl:{column}"),
            ));
        }
    }
    Ok((findings, notes))
}

#[cfg(test)]
mod tests {
    use super::provider_managed;

    #[test]
    fn postgres_and_yugabyte_are_provider_roles_only_on_yugabytedb() {
        let (pg, yb) = (false, true);
        assert!(!provider_managed("postgres", pg));
        assert!(!provider_managed("yugabyte", pg));
        assert!(provider_managed("postgres", yb));
        assert!(provider_managed("yugabyte", yb));
        assert!(provider_managed("rdsadmin", pg));
        assert!(!provider_managed("app_admin", yb));
    }
}
