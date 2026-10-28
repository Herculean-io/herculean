//! Repo-to-live drift: a repo and a database together.
mod common;

use common::{admin_sql, fixture_db, scan_with, stdout_json, steps, TempDir, DELETE, RECONCILE};
use serde_json::{json, Value};

/// `herculean scan --repo fixtures/repos/<situation>` against the `<situation>` fixture database.
fn scan_pair(situation: &str) -> (String, Value) {
    let db = fixture_db(situation);
    let repo = format!(
        "{}/tests/fixtures/repos/{situation}",
        env!("CARGO_MANIFEST_DIR")
    );
    let report = stdout_json(&scan_with(Some(&db.url), &["--repo", &repo]));
    (db.name, report)
}

fn drift(system: &str, kind: &str, resource: &str, evidence: &str) -> Value {
    json!({
        "check": "drift",
        "kind": kind,
        "resource_id": resource,
        "steps": steps(system, resource, evidence, RECONCILE)
    })
}

#[test]
fn extra_personal_column_live_is_drift() {
    let (db, report) = scan_pair("migration_live_schema_mismatch");
    assert_eq!(
        report["findings"],
        json!([drift(
            &db,
            "extra_live_column",
            "public.customers.phone",
            "pg_attribute:public.customers.phone"
        )])
    );
}

#[test]
fn matching_repo_and_database_have_no_drift() {
    let (_, report) = scan_pair("migration_live_schema_match");
    assert_eq!(report["findings"], json!([]));
    assert!(report.get("skipped_checks").is_none());
}

#[test]
fn every_drift_kind_is_reported() {
    let (db, report) = scan_pair("schema_drift_every_kind");
    let file = "file:migrations/001_schema.sql";
    assert_eq!(
        report["findings"],
        json!([
            // The live SET NULL key is no deletion path (the migrations' CASCADE would be).
            {
                "check": "deletion_path",
                "kind": "no_deletion_path",
                "resource_id": "public.customers",
                "steps": steps(&db, "public.customers", "pg_class:public.customers", DELETE)
            },
            drift(
                &db,
                "missing_live_table",
                "public.contacts",
                &format!("{file}:13")
            ),
            drift(
                &db,
                "grant_mismatch",
                "public.customers",
                "pg_class.relacl:public.customers"
            ),
            drift(
                &db,
                "on_delete_mismatch",
                "public.customers",
                "pg_constraint:public.customers.customers_account_id_fkey"
            ),
            drift(
                &db,
                "missing_live_column",
                "public.customers.full_name",
                &format!("{file}:9")
            ),
            drift(
                &db,
                "extra_live_table",
                "public.leads",
                "pg_class:public.leads"
            ),
        ])
    );
}

#[test]
fn drift_runs_are_byte_identical() {
    let db = fixture_db("schema_drift_every_kind");
    let repo = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/repos/schema_drift_every_kind"
    );
    let first = scan_with(Some(&db.url), &["--repo", repo]);
    let second = scan_with(Some(&db.url), &["--repo", repo]);
    assert!(first.status.success());
    assert_eq!(first.stdout, second.stdout);
}

#[test]
fn drops_and_renames_in_later_migrations_leave_no_drift() {
    let (_, report) = scan_pair("migration_drops_and_renames");
    assert_eq!(report["findings"], json!([]));
}

#[test]
fn repo_only_run_applies_drops_and_renames() {
    let repo = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/repos/migration_drops_and_renames"
    );
    let report = stdout_json(&scan_with(None, &["--repo", repo]));
    assert_eq!(report["findings"], json!([]));
    assert_eq!(
        report["data_map"]["stores"],
        json!([{ "schema": "public", "table": "clients", "columns": [
            { "name": "email", "category": "contact", "source": "column_name", "confidence": "high" }
        ]}])
    );
    assert_eq!(
        report["data_map"]["deletion_paths"],
        json!([{ "table": "public.clients", "kind": "on_delete",
                 "evidence_id": "file:migrations/002_reshape.sql:8" }])
    );
}

/// The `drift` findings on `table` in the `fk_drift` pair.
fn fk_drift_on(table: &str) -> (String, Value) {
    let (db, report) = scan_pair("fk_drift");
    let on_table: Vec<Value> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["check"] == "drift" && f["resource_id"] == table)
        .cloned()
        .collect();
    (db, Value::from(on_table))
}

#[test]
fn reviewed_cascade_fk_absent_live_is_drift() {
    let (db, findings) = fk_drift_on("public.customers");
    assert_eq!(
        findings,
        json!([drift(
            &db,
            "missing_live_fk",
            "public.customers",
            "file:migrations/001_schema.sql:10"
        )])
    );
}

#[test]
fn live_only_fk_is_drift() {
    let (db, findings) = fk_drift_on("public.leads");
    assert_eq!(
        findings,
        json!([drift(
            &db,
            "extra_live_fk",
            "public.leads",
            "pg_constraint:public.leads.leads_account_id_fkey"
        )])
    );
}

#[test]
fn fk_referencing_another_column_live_is_drift() {
    let (db, findings) = fk_drift_on("public.contacts");
    assert_eq!(
        findings,
        json!([
            drift(
                &db,
                "extra_live_fk",
                "public.contacts",
                "pg_constraint:public.contacts.contacts_account_code_fkey"
            ),
            drift(
                &db,
                "missing_live_fk",
                "public.contacts",
                "file:migrations/001_schema.sql:22"
            ),
        ])
    );
}

#[test]
fn repo_table_personal_only_by_comment_missing_live_is_drift() {
    let (db, report) = scan_pair("comment_only_personal_table");
    assert_eq!(
        report["findings"],
        json!([drift(
            &db,
            "missing_live_table",
            "public.contacts",
            "file:migrations/001_schema.sql:6"
        )])
    );
}

#[test]
fn personal_false_override_removes_a_comment_classified_table_from_drift() {
    let db = fixture_db("comment_only_personal_table");
    let repo = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/repos/comment_only_personal_table"
    );
    let tmp = TempDir::new();
    let map = tmp.0.join("data-map.yaml");
    std::fs::write(
        &map,
        "overrides:\n  - column: public.contacts.reach\n    personal: false\n",
    )
    .unwrap();
    let report = stdout_json(&scan_with(
        Some(&db.url),
        &["--repo", repo, "--data-map", map.to_str().unwrap()],
    ));
    assert_eq!(report["findings"], json!([]));
    assert_eq!(report["data_map"]["stores"], json!([]));
}

/// The tables of the `grant_drift` fixture, as a migration creates them.
const GRANT_DRIFT_TABLES: &str = "
CREATE TABLE accounts (id bigserial PRIMARY KEY, plan text NOT NULL);
CREATE TABLE customers (
    id         bigserial PRIMARY KEY,
    email      text NOT NULL,
    account_id bigint NOT NULL REFERENCES accounts (id) ON DELETE CASCADE
);
";

/// Scans the `grant_drift` database, after running `live` there as the superuser,
/// against a repo whose one migration is `migration`; `{reader}` in either is
/// Herculean's reader role.
fn grant_drift_scan(migration: &str, live: &str) -> (String, Value) {
    let db = fixture_db("grant_drift");
    if !live.is_empty() {
        admin_sql(&db.name, &live.replace("{reader}", &db.reader));
    }
    let repo = TempDir::new();
    std::fs::create_dir(repo.0.join("migrations")).unwrap();
    std::fs::write(
        repo.0.join("migrations/001_schema.sql"),
        migration.replace("{reader}", &db.reader),
    )
    .unwrap();
    let report = stdout_json(&scan_with(
        Some(&db.url),
        &["--repo", repo.0.to_str().unwrap()],
    ));
    (db.name, report)
}

#[test]
fn schema_wide_grant_matching_live_is_no_drift() {
    let migration =
        format!("{GRANT_DRIFT_TABLES}GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonly;");
    let (_, report) = grant_drift_scan(&migration, "");
    assert_eq!(report["findings"], json!([]));
}

#[test]
fn schema_wide_grant_before_a_table_exists_does_not_cover_it() {
    let migration =
        format!("GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonly;{GRANT_DRIFT_TABLES}");
    let (db, report) = grant_drift_scan(&migration, "");
    assert_eq!(
        report["findings"],
        json!([drift(
            &db,
            "grant_mismatch",
            "public.customers",
            "pg_class.relacl:public.customers"
        )])
    );
}

#[test]
fn grants_to_the_owner_and_the_reader_are_not_drift() {
    let migration = format!(
        "{GRANT_DRIFT_TABLES}GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonly;
         GRANT ALL ON customers TO app_owner;
         GRANT SELECT ON customers TO {{reader}};"
    );
    let (_, report) = grant_drift_scan(&migration, "GRANT SELECT ON customers TO {reader}");
    assert_eq!(report["findings"], json!([]));
}

#[test]
fn extra_live_grant_to_another_role_is_drift() {
    let migration =
        format!("{GRANT_DRIFT_TABLES}GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonly;");
    let (db, report) = grant_drift_scan(&migration, "GRANT SELECT ON customers TO reporting");
    assert_eq!(
        report["findings"],
        json!([drift(
            &db,
            "grant_mismatch",
            "public.customers",
            "pg_class.relacl:public.customers"
        )])
    );
}

#[test]
fn default_privilege_grantees_are_left_out_with_a_note() {
    let migration = format!(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO reporting;
         ALTER DEFAULT PRIVILEGES FOR ROLE app_owner GRANT USAGE ON SEQUENCES TO readonly;
         ALTER DEFAULT PRIVILEGES REVOKE ALL ON TABLES FROM PUBLIC;
         {GRANT_DRIFT_TABLES}GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonly;"
    );
    let (_, report) = grant_drift_scan(&migration, "GRANT SELECT ON customers TO reporting");
    assert_eq!(report["findings"], json!([]));
    // Only granted table defaults name a grantee: readonly and PUBLIC are still compared.
    for live in [
        "GRANT UPDATE ON customers TO readonly",
        "GRANT SELECT ON customers TO PUBLIC",
    ] {
        let (db, report) = grant_drift_scan(&migration, live);
        let drift_findings: Vec<&Value> = report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| f["check"] == "drift")
            .collect();
        assert_eq!(
            json!(drift_findings),
            json!([drift(
                &db,
                "grant_mismatch",
                "public.customers",
                "pg_class.relacl:public.customers"
            )]),
            "{live}"
        );
    }
    assert_eq!(
        report["notes"],
        json!([
            "default_privileges_not_compared: the migrations set default table privileges \
             for reporting; Herculean does not model ALTER DEFAULT PRIVILEGES, so drift \
             compares no table grants to those roles, in the migrations or live"
        ])
    );
}
