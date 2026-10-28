mod common;

use common::{
    admin_sql, email_store, fixture_db, logged_statements, no_repo, scan, scan_with, stdout_json,
    steps, TempDir, DELETE,
};
use serde_json::json;

#[test]
fn soft_delete_without_purge_is_a_finding() {
    let db = fixture_db("soft_delete_without_purge");
    let report = stdout_json(&scan(Some(&db.url)));
    assert_eq!(
        report,
        json!({
            "data_map": { "stores": [email_store("customers")] },
            "findings": [{
                "check": "deletion_path",
                "kind": "soft_delete_without_purge",
                "resource_id": "public.customers",
                "steps": steps(&db.name, "public.customers", "pg_attribute:public.customers.deleted_at", DELETE)
            }],
            "skipped_checks": no_repo()
        })
    );
}

#[test]
fn foreign_key_without_on_delete_is_a_finding() {
    let db = fixture_db("fk_without_on_delete");
    let report = stdout_json(&scan(Some(&db.url)));
    assert_eq!(
        report,
        json!({
            "data_map": { "stores": [email_store("customers")] },
            "findings": [{
                "check": "deletion_path",
                "kind": "fk_without_on_delete",
                "resource_id": "public.customers",
                "steps": steps(&db.name, "public.customers",
                    "pg_constraint:public.customers.customers_account_id_fkey", DELETE)
            }],
            "skipped_checks": no_repo()
        })
    );
}

#[test]
fn on_delete_cascade_is_a_deletion_path() {
    let db = fixture_db("on_delete_cascade_present");
    let report = stdout_json(&scan(Some(&db.url)));
    assert_eq!(
        report,
        json!({
            "data_map": {
                "stores": [email_store("customers")],
                "deletion_paths": [{
                    "table": "public.customers",
                    "kind": "on_delete",
                    "evidence_id": "pg_constraint:public.customers.customers_account_id_fkey"
                }]
            },
            "findings": [],
            "skipped_checks": no_repo()
        })
    );
}

/// SET NULL / SET DEFAULT keep the personal row when the parent goes: no path, and no
/// `fk_without_on_delete` either (the key does have ON DELETE handling).
#[test]
fn set_null_and_set_default_foreign_keys_are_not_deletion_paths() {
    for fixture in ["fk_set_null_without_purge", "fk_set_default_without_purge"] {
        let db = fixture_db(fixture);
        let report = stdout_json(&scan(Some(&db.url)));
        assert_eq!(
            report,
            json!({
                "data_map": { "stores": [email_store("customers")] },
                "findings": [{
                    "check": "deletion_path",
                    "kind": "no_deletion_path",
                    "resource_id": "public.customers",
                    "steps": steps(&db.name, "public.customers", "pg_class:public.customers", DELETE)
                }],
                "skipped_checks": no_repo()
            }),
            "{fixture}"
        );
    }
}

#[test]
fn pg_cron_purge_job_is_a_deletion_path() {
    let db = fixture_db("pg_cron_purge_present");
    let report = stdout_json(&scan(Some(&db.url)));
    assert_eq!(
        report,
        json!({
            "data_map": {
                "stores": [email_store("customers")],
                "deletion_paths": [{
                    "table": "public.customers",
                    "kind": "scheduled_job",
                    "evidence_id": "cron.job:1"
                }]
            },
            "findings": [],
            "skipped_checks": no_repo()
        })
    );
}

#[test]
fn data_map_override_wins_over_detection_and_survives_a_rerun() {
    let db = fixture_db("data_map_override");
    let detected = stdout_json(&scan(Some(&db.url)));
    let stores: Vec<&str> = detected["data_map"]["stores"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["table"].as_str().unwrap())
        .collect();
    assert_eq!(
        stores,
        ["customers", "vendors"],
        "detection without overrides"
    );

    let map = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/data_map_override.yaml"
    );
    let first = scan_with(Some(&db.url), &["--data-map", map]);
    let report = stdout_json(&first);
    assert_eq!(
        report,
        json!({
            "data_map": { "stores": [{
                "schema": "public",
                "table": "customers",
                "columns": [
                    { "name": "email", "category": "contact", "source": "column_name", "confidence": "high" },
                    { "name": "notes", "category": "free_text", "source": "override", "confidence": "confirmed" }
                ]
            }]},
            "findings": [{
                "check": "deletion_path",
                "kind": "no_deletion_path",
                "resource_id": "public.customers",
                "steps": steps(&db.name, "public.customers", "pg_class:public.customers", DELETE)
            }],
            "skipped_checks": no_repo()
        })
    );
    let second = scan_with(Some(&db.url), &["--data-map", map]);
    assert_eq!(first.stdout, second.stdout);
}

#[test]
fn malformed_data_map_fails_without_scanning() {
    let db = fixture_db("data_map_override");
    let dir = TempDir::new();
    let bad = dir.0.join("data-map.yaml");
    std::fs::write(
        &bad,
        "overrides:\n  - column: public.customers.notes\n    categroy: x\n",
    )
    .unwrap();
    let out = scan_with(Some(&db.url), &["--data-map", bad.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("data map"));
}

const SAMPLE_FIXTURE: &str = "sampled_contact_column";
const SAMPLE_VALUES: &[&str] = &[
    "known.one",
    "rowvalue.test",
    "quentin.marlowe",
    "samplevalue.test",
    "7946",
    "call back",
    "prefers mornings",
];

/// Reader statements that name the fixture's user table.
fn statements_on_leads(db: &common::Db) -> Vec<String> {
    logged_statements(&db.reader, &db.name)
        .into_iter()
        .filter(|s| s.contains("leads"))
        .collect()
}

#[test]
fn sampling_is_off_by_default() {
    let db = fixture_db(SAMPLE_FIXTURE);
    let report = stdout_json(&scan(Some(&db.url)));
    assert_eq!(report["data_map"].get("samples"), None);
    assert_eq!(statements_on_leads(&db), Vec::<String>::new());
}

#[test]
fn sampling_reads_only_ambiguous_columns_and_keeps_only_counts() {
    let db = fixture_db(SAMPLE_FIXTURE);
    admin_sql(
        &db.name,
        &format!("GRANT SELECT (reach, memo) ON leads TO {}", db.reader),
    );
    let out = scan_with(Some(&db.url), &["--sample"]);
    let report = stdout_json(&out);
    assert_eq!(
        report,
        json!({
            "data_map": {
                "stores": [{
                    "schema": "public",
                    "table": "leads",
                    "columns": [
                        { "name": "email", "category": "contact", "source": "column_name", "confidence": "high" },
                        { "name": "reach", "category": "contact", "source": "sample", "confidence": "medium" }
                    ]
                }],
                "samples": [
                    { "column": "public.leads.memo", "sampled": 2, "matches": { "email": 0, "phone": 0 } },
                    { "column": "public.leads.reach", "sampled": 3, "matches": { "email": 2, "phone": 1 } }
                ]
            },
            "findings": [{
                "check": "deletion_path",
                "kind": "no_deletion_path",
                "resource_id": "public.leads",
                "steps": steps(&db.name, "public.leads", "pg_class:public.leads", DELETE)
            }],
            "skipped_checks": no_repo()
        })
    );

    let mut touched = statements_on_leads(&db);
    touched.sort();
    assert_eq!(
        touched.len(),
        2,
        "one read per sampled column: {touched:#?}"
    );
    assert!(touched[0].ends_with(r#"SELECT "memo"::text FROM "public"."leads" LIMIT 100"#));
    assert!(touched[1].ends_with(r#"SELECT "reach"::text FROM "public"."leads" LIMIT 100"#));

    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    for value in SAMPLE_VALUES {
        assert!(!all.contains(value), "row value {value:?} leaked");
    }
}

#[test]
fn sampling_skips_columns_a_comment_already_classifies() {
    let db = fixture_db(SAMPLE_FIXTURE);
    admin_sql(
        &db.name,
        &format!(
            "COMMENT ON COLUMN leads.reach IS 'customer email'; \
             GRANT SELECT (reach, memo) ON leads TO {}",
            db.reader
        ),
    );
    let report = stdout_json(&scan_with(Some(&db.url), &["--sample"]));
    assert_eq!(
        report["data_map"],
        json!({
            "stores": [{
                "schema": "public",
                "table": "leads",
                "columns": [
                    { "name": "email", "category": "contact", "source": "column_name", "confidence": "high" },
                    { "name": "reach", "category": "contact", "source": "comment", "confidence": "medium" }
                ]
            }],
            "samples": [
                { "column": "public.leads.memo", "sampled": 2, "matches": { "email": 0, "phone": 0 } }
            ]
        })
    );
    let touched = statements_on_leads(&db);
    assert!(
        !touched.iter().any(|s| s.contains("\"reach\"")),
        "comment-classified column was read: {touched:#?}"
    );
}

#[test]
fn partitioned_table_is_reported_once_by_its_parent() {
    let db = fixture_db("partitioned_personal_table");
    let report = stdout_json(&scan(Some(&db.url)));
    assert_eq!(
        report,
        json!({
            "data_map": { "stores": [email_store("customers")] },
            "findings": [{
                "check": "deletion_path",
                "kind": "no_deletion_path",
                "resource_id": "public.customers",
                "steps": steps(&db.name, "public.customers", "pg_class:public.customers", DELETE)
            }],
            "skipped_checks": no_repo()
        })
    );
}

#[test]
fn sampling_does_not_mistake_dates_ids_ips_or_decimals_for_phones() {
    let db = fixture_db("sampled_lookalike_columns");
    admin_sql(
        &db.name,
        &format!(
            "GRANT SELECT (happened, ref_code, host, amount) ON events TO {}",
            db.reader
        ),
    );
    let report = stdout_json(&scan_with(Some(&db.url), &["--sample"]));
    let none = json!({ "email": 0, "phone": 0 });
    assert_eq!(
        report,
        json!({
            "data_map": {
                "stores": [],
                "samples": [
                    { "column": "public.events.amount", "sampled": 3, "matches": none },
                    { "column": "public.events.happened", "sampled": 3, "matches": none },
                    { "column": "public.events.host", "sampled": 3, "matches": none },
                    { "column": "public.events.ref_code", "sampled": 3, "matches": none }
                ]
            },
            "findings": [],
            "skipped_checks": no_repo()
        })
    );
}

#[test]
fn unreadable_sample_column_is_skipped_and_the_scan_continues() {
    let db = fixture_db(SAMPLE_FIXTURE);
    admin_sql(
        &db.name,
        &format!("GRANT SELECT (reach) ON leads TO {}", db.reader),
    );
    let report = stdout_json(&scan_with(Some(&db.url), &["--sample"]));
    assert_eq!(
        report["data_map"]["samples"],
        json!([
            { "column": "public.leads.memo", "skipped": "SQLSTATE 42501", "sampled": 0,
              "matches": { "email": 0, "phone": 0 } },
            { "column": "public.leads.reach", "sampled": 3, "matches": { "email": 2, "phone": 1 } }
        ])
    );
    assert_eq!(
        report["data_map"]["stores"][0]["columns"],
        json!([
            { "name": "email", "category": "contact", "source": "column_name", "confidence": "high" },
            { "name": "reach", "category": "contact", "source": "sample", "confidence": "medium" }
        ])
    );
}

#[test]
fn cron_jobs_hidden_by_row_level_security_are_noted() {
    let db = fixture_db("pg_cron_purge_hidden_by_rls");
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
            }, {
                "check": "deletion_path",
                "kind": "soft_delete_without_purge",
                "resource_id": "public.customers",
                "steps": steps(&db.name, "public.customers", "pg_attribute:public.customers.deleted_at", DELETE)
            }],
            "notes": ["scheduled_jobs_unreadable: cron.job is protected by row-level security; scheduled purge jobs owned by other roles were not seen"],
            "skipped_checks": no_repo()
        })
    );
}

#[test]
fn name_rules_classify_the_column_names_real_schemas_use() {
    let db = fixture_db("column_name_tokens");
    let by_name = |name: &str, category: &str| json!({ "name": name, "category": category, "source": "column_name", "confidence": "high" });
    let by_comment = |name: &str| json!({ "name": name, "category": "health", "source": "comment", "confidence": "medium" });
    let report = stdout_json(&scan(Some(&db.url)));
    // `records` (file_name, fileName, product_name, email boolean, phone boolean,
    // email_verified_at timestamptz, phone_grace interval, order_condition, allergy,
    // zipper, conditions "Current condition of the patient") classifies nothing,
    // so it is no store.
    assert_eq!(
        report["data_map"]["stores"],
        json!([{ "schema": "public", "table": "patients", "columns": [
            by_comment("allergies"),
            by_name("birth_date", "identity"),
            by_name("birthdate", "identity"),
            by_name("birthday", "identity"),
            by_comment("chart"),
            by_name("diagnosis", "health"),
            by_name("dob", "identity"),
            by_name("firstName", "identity"),
            by_comment("history"),
            by_name("icd10_code", "health"),
            by_name("insurance_member_id", "health"),
            by_name("last_lab_result", "health"),
            by_name("medical_record_number", "health"),
            by_name("medication", "health"),
            by_name("mrn", "health"),
            by_comment("notes"),
            by_name("phone2", "contact"),
            by_name("phoneNumber", "contact"),
            by_name("postal_code", "contact"),
            by_name("postcode", "contact"),
            by_comment("pregnant"),
            by_name("prescription", "health"),
            by_name("ssn", "identity"),
            by_comment("status"),
            by_name("user_email", "contact"),
            by_name("zip", "contact"),
            by_name("zipcode", "contact")
        ]}])
    );
    assert_eq!(
        report["findings"],
        json!([{
            "check": "deletion_path",
            "kind": "no_deletion_path",
            "resource_id": "public.patients",
            "steps": steps(&db.name, "public.patients", "pg_class:public.patients", DELETE)
        }])
    );

    let map = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/column_name_tokens.yaml"
    );
    let report = stdout_json(&scan_with(Some(&db.url), &["--data-map", map]));
    let columns = report["data_map"]["stores"][0]["columns"]
        .as_array()
        .unwrap();
    assert!(
        !columns.iter().any(|c| c["name"] == "user_email"),
        "personal: false override wins over the token rule"
    );
    assert!(columns.contains(&json!({
        "name": "diagnosis", "category": "free_text", "source": "override", "confidence": "confirmed"
    })));
}
