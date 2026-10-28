//! Table-level least-privilege situations. Role-level ones (cluster-global)
//! live in `privileged_roles.rs`, their own test binary and cluster.
mod common;

use common::{cascade_path, email_store, fixture_db, no_repo, scan, stdout_json, steps, RESTRICT};
use serde_json::json;

#[test]
fn public_grant_on_a_personal_table_is_excess_access() {
    let db = fixture_db("public_grant_on_personal_table");
    let report = stdout_json(&scan(Some(&db.url)));
    assert_eq!(
        report,
        json!({
            "data_map": {
                "stores": [email_store("customers")],
                "deletion_paths": [cascade_path("customers", "account_id")]
            },
            "findings": [{
                "check": "least_privilege",
                "kind": "public_grant",
                "resource_id": "public.customers",
                "steps": steps(&db.name, "public.customers", "pg_class.relacl:public.customers", RESTRICT)
            }],
            "skipped_checks": no_repo()
        })
    );
}

/// "Broad" = any privilege on a personal-data table granted to a group role
/// (one with members), other than the table owner. The owner (a group role
/// here) and a member-less app login role are not reported.
#[test]
fn group_role_grant_on_a_personal_table_is_excess_access() {
    let db = fixture_db("group_role_grant_on_personal_table");
    let report = stdout_json(&scan(Some(&db.url)));
    assert_eq!(
        report,
        json!({
            "data_map": {
                "stores": [email_store("customers")],
                "deletion_paths": [cascade_path("customers", "account_id")]
            },
            "findings": [{
                "check": "least_privilege",
                "kind": "group_role_grant",
                "resource_id": "public.customers",
                "steps": steps(&db.name, "public.customers", "pg_class.relacl:public.customers:support_team", RESTRICT)
            }],
            "skipped_checks": no_repo()
        })
    );
}

fn contact_column(name: &str) -> serde_json::Value {
    json!({ "name": name, "category": "contact", "source": "column_name", "confidence": "high" })
}

#[test]
fn public_column_grant_on_personal_columns_is_excess_access() {
    let db = fixture_db("public_column_grant_on_personal_column");
    let report = stdout_json(&scan(Some(&db.url)));
    assert_eq!(
        report["findings"],
        json!([
            {
                "check": "least_privilege",
                "kind": "public_grant",
                "resource_id": "public.customers",
                "steps": steps(&db.name, "public.customers", "pg_attribute.attacl:public.customers.email", RESTRICT)
            },
            {
                "check": "least_privilege",
                "kind": "public_grant",
                "resource_id": "public.customers",
                "steps": steps(&db.name, "public.customers", "pg_attribute.attacl:public.customers.phone", RESTRICT)
            }
        ])
    );
    assert_eq!(
        report["data_map"]["stores"][0]["columns"],
        json!([contact_column("email"), contact_column("phone")])
    );
}

#[test]
fn public_column_grant_on_a_non_personal_column_is_not_a_finding() {
    let db = fixture_db("public_column_grant_on_other_column");
    let report = stdout_json(&scan(Some(&db.url)));
    assert_eq!(report["findings"], json!([]));
}

#[test]
fn multi_tenant_personal_table_without_rls_is_excess_access() {
    let db = fixture_db("personal_table_without_rls");
    let report = stdout_json(&scan(Some(&db.url)));
    assert_eq!(
        report,
        json!({
            "data_map": {
                "stores": [email_store("members")],
                "deletion_paths": [cascade_path("members", "org_id")]
            },
            "findings": [{
                "check": "least_privilege",
                "kind": "missing_rls",
                "resource_id": "public.members",
                "steps": steps(&db.name, "public.members", "pg_class.relrowsecurity:public.members", RESTRICT)
            }],
            "skipped_checks": no_repo()
        })
    );
}

#[test]
fn tightly_granted_personal_table_is_not_a_finding() {
    let db = fixture_db("tightly_granted_personal_table");
    let report = stdout_json(&scan(Some(&db.url)));
    assert_eq!(
        report,
        json!({
            "data_map": {
                "stores": [email_store("members")],
                "deletion_paths": [cascade_path("members", "tenant_id")]
            },
            "findings": [],
            "skipped_checks": no_repo()
        })
    );
}
