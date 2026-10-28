//! Managed-service roles. Roles are cluster-global, so this gets its own
//! test binary (its own cluster) with exactly one test.

mod common;

use common::{fixture_db, no_repo, scan, stdout_json, steps, RESTRICT};
use serde_json::{json, Value};

fn admin_finding(system: &str, role: &str) -> Value {
    let resource = format!("role:{role}");
    let evidence = format!("pg_roles:{role}");
    json!({
        "check": "least_privilege",
        "kind": "provider_admin_role",
        "resource_id": resource,
        "steps": steps(system, &resource, &evidence, RESTRICT)
    })
}

#[test]
fn provider_admin_members_are_findings_and_provider_owned_roles_are_notes() {
    let db = fixture_db("provider_roles");
    let report: Value = stdout_json(&scan(Some(&db.url)));
    assert_eq!(
        report,
        json!({
            "data_map": { "stores": [] },
            "findings": [
                admin_finding(&db.name, "app_admin"),
                admin_finding(&db.name, "gcp_admin"),
                admin_finding(&db.name, "neon_owner"),
            ],
            "notes": [
                "provider_managed_role: cloudsqladmin",
                "provider_managed_role: neon_superuser",
                "provider_managed_role: rdsadmin",
                "provider_managed_role: service_role; anyone with the service key bypasses RLS, so keep the key out of clients",
                "provider_managed_role: supabase_admin",
                "provider_managed_role: supabase_etl_admin",
            ],
            "skipped_checks": no_repo()
        })
    );
}
