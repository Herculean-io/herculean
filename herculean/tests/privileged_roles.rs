//! Role-level least-privilege situations. Roles are cluster-global, so they
//! get their own test binary (its own cluster) and exactly one test: a role
//! created here would otherwise appear in every other test's report.
mod common;

use common::{fixture_db, no_repo, scan, stdout_json, steps, RESTRICT};
use serde_json::{json, Value};

fn restrict_finding(system: &str, kind: &str, role: &str) -> Value {
    let resource = format!("role:{role}");
    let evidence = format!("pg_roles:{role}");
    json!({
        "check": "least_privilege",
        "kind": kind,
        "resource_id": resource,
        "steps": steps(system, &resource, &evidence, RESTRICT)
    })
}

/// The bootstrap superuser (`postgres`, oid 10) cannot be removed and is not
/// reported; the harness's reader role is unprivileged and is not reported.
#[test]
fn superuser_rls_bypass_and_read_all_data_roles_are_excess_access() {
    let db = fixture_db("privileged_roles");
    let report: Value = stdout_json(&scan(Some(&db.url)));
    assert_eq!(
        report,
        json!({
            "data_map": { "stores": [] },
            "findings": [
                restrict_finding(&db.name, "read_all_data_role", "analyst"),
                restrict_finding(&db.name, "read_all_data_role", "bi_readers"),
                restrict_finding(&db.name, "bypassrls_role", "etl_loader"),
                restrict_finding(&db.name, "superuser_role", "ops_admin"),
            ],
            "skipped_checks": no_repo()
        })
    );
}
