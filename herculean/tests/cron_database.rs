//! pg_cron keeps its jobs in one database per cluster (`cron.database_name`,
//! default `postgres`); `cron.job.database` names where each job runs.
mod common;

use common::{
    admin_sql, email_store, fixture_db, no_repo, pg_cron_db, scan, stdout_json, steps, Db, TempDir,
    DELETE,
};
use serde_json::{json, Value};
use std::process::Command;

const PURGE: &str = "DELETE FROM public.customers WHERE deleted_at < now() - interval ''30 days''";

/// The open soft-delete finding on `public.customers`.
fn soft_delete_finding(db: &Db) -> Value {
    json!({
        "check": "deletion_path",
        "kind": "soft_delete_without_purge",
        "resource_id": "public.customers",
        "steps": steps(&db.name, "public.customers", "pg_attribute:public.customers.deleted_at", DELETE)
    })
}

/// The `herculean report` stdout line for criterion `id`.
fn report_line(db: &Db, id: &str) -> String {
    let tmp = TempDir::new();
    let out = Command::new(env!("CARGO_BIN_EXE_herculean"))
        .args(["report", "--out"])
        .arg(tmp.0.join("out"))
        .env("HERCULEAN_DATABASE_URL", &db.url)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    stdout
        .lines()
        .find(|l| l.starts_with(&format!("{id} ")))
        .unwrap_or_else(|| panic!("no {id} line: {stdout}"))
        .to_string()
}

#[test]
fn a_job_scheduled_for_another_database_is_ignored() {
    let db = fixture_db("pg_cron_purge_present");
    admin_sql(&db.name, "UPDATE cron.job SET database = 'other'");
    let report = stdout_json(&scan(Some(&db.url)));
    assert_eq!(
        report,
        json!({
            "data_map": { "stores": [email_store("customers")] },
            "findings": [soft_delete_finding(&db)],
            "skipped_checks": no_repo()
        })
    );
}

#[test]
fn a_cron_database_the_reader_cannot_open_is_noted_and_the_criterion_partly_runs() {
    let db = fixture_db("soft_delete_without_purge");
    admin_sql(
        "postgres",
        &format!(
            "ALTER ROLE {} SET cron.database_name = 'no_such_db'",
            db.reader
        ),
    );
    let report = stdout_json(&scan(Some(&db.url)));
    assert_eq!(
        report,
        json!({
            "data_map": { "stores": [email_store("customers")] },
            "findings": [{
                "check": "data_map",
                "kind": "incomplete_input",
                "resource_id": "cron.job",
                "steps": []
            }, soft_delete_finding(&db)],
            "notes": ["scheduled_jobs_elsewhere: pg_cron keeps jobs in another database \
                       (no_such_db); grant the reader access there"],
            "skipped_checks": no_repo()
        })
    );
    let line = report_line(&db, "C1.2");
    assert!(line.contains(": partly run,"), "{line}");
}

// Real pg_cron from here: `cron.database_name` is superuser-only, so a reader
// without pg_read_all_settings gets SQLSTATE 42501 asking for it.

/// Schedules the purge job in `cron_database` for `db`, owned by its reader,
/// and grants the reader what read-only-role.sql grants where cron.job lives.
/// Tests share the cron database and concurrent GRANTs on schema cron fail
/// with "tuple concurrently updated", so the batch (one implicit transaction)
/// holds an advisory lock.
fn schedule_purge(db: &Db, cron_database: &str) {
    db.admin(
        cron_database,
        &format!(
            "SELECT pg_advisory_xact_lock(1); \
             SELECT cron.schedule_in_database('purge_{name}', '0 3 * * *', '{PURGE}', \
                 '{name}', '{reader}'); \
             GRANT USAGE ON SCHEMA cron TO {reader}; GRANT SELECT ON cron.job TO {reader}",
            name = db.name,
            reader = db.reader
        ),
    );
}

/// The deletion paths and the deletion_path findings of `report`.
fn deletion(report: &Value) -> (Vec<String>, Vec<Value>) {
    let paths = report["data_map"]["deletion_paths"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|p| p["evidence_id"].as_str().unwrap().to_string())
        .collect();
    let findings = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["check"] == "deletion_path")
        .cloned()
        .collect();
    (paths, findings)
}

#[test]
fn without_the_settings_grant_the_job_in_postgres_is_found() {
    let db = pg_cron_db("postgres", "soft_delete_without_purge");
    schedule_purge(&db, "postgres");
    // Another database's purge job of a same-named table.
    db.admin(
        "postgres",
        &format!("SELECT cron.schedule_in_database('other_{0}', '0 3 * * *', '{PURGE}', 'postgres', '{1}')", db.name, db.reader),
    );
    let (paths, findings) = deletion(&stdout_json(&scan(Some(&db.url))));
    assert_eq!(paths.len(), 1, "{paths:?}");
    assert!(paths[0].starts_with("cron.job:"), "{paths:?}");
    assert_eq!(findings, Vec::<Value>::new());
}

#[test]
fn a_non_default_cron_database_without_the_settings_grant_is_noted() {
    let db = pg_cron_db("crondb", "soft_delete_without_purge");
    schedule_purge(&db, "crondb");
    let report = stdout_json(&scan(Some(&db.url)));
    assert_eq!(
        report["notes"],
        json!([
            "scheduled_jobs_elsewhere: pg_cron keeps jobs in another database \
                (unknown); grant the reader access there"
        ])
    );
    assert_eq!(deletion(&report).1, vec![soft_delete_finding(&db)]);
    let line = report_line(&db, "C1.2");
    assert!(line.contains(": partly run,"), "{line}");
}

#[test]
fn with_the_settings_grant_the_named_cron_database_is_used() {
    let db = pg_cron_db("crondb", "soft_delete_without_purge");
    schedule_purge(&db, "crondb");
    db.admin(
        "postgres",
        &format!("GRANT pg_read_all_settings TO {}", db.reader),
    );
    let (paths, findings) = deletion(&stdout_json(&scan(Some(&db.url))));
    assert_eq!(paths.len(), 1, "{paths:?}");
    assert!(paths[0].starts_with("cron.job:"), "{paths:?}");
    assert_eq!(findings, Vec::<Value>::new());
}

/// Both cron.job notes (hidden by RLS, then unreadable) are one incomplete-input finding.
#[test]
fn a_cron_database_without_the_cron_grants_is_one_incomplete_input() {
    let db = pg_cron_db("crondb", "soft_delete_without_purge");
    db.admin(
        "postgres",
        &format!("GRANT pg_read_all_settings TO {}", db.reader),
    );
    let report = stdout_json(&scan(Some(&db.url)));
    assert_eq!(report["notes"].as_array().unwrap().len(), 2, "{report}");
    let incomplete: Vec<&Value> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["kind"] == "incomplete_input")
        .collect();
    assert_eq!(
        incomplete,
        [&json!({
            "check": "data_map",
            "kind": "incomplete_input",
            "resource_id": "cron.job",
            "steps": []
        })]
    );
}
