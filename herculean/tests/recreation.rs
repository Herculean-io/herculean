mod common;

use common::{cascade_path, email_store, fixture_db, no_repo, scan, stdout_json, steps, DISABLE};
use serde_json::{json, Value};

#[test]
fn publication_with_a_personal_table_is_an_active_data_flow() {
    let db = fixture_db("publication_with_personal_table");
    let report = stdout_json(&scan(Some(&db.url)));
    assert_eq!(
        report,
        json!({
            "data_map": {
                "stores": [email_store("customers")],
                "deletion_paths": [cascade_path("customers", "account_id")],
                "flows": [{
                    "kind": "publication",
                    "object": "publication:customer_feed",
                    "table": "public.customers",
                    "evidence_id": "pg_publication:customer_feed"
                }]
            },
            "findings": [{
                "check": "recreation_risk",
                "kind": "publication",
                "resource_id": "publication:customer_feed",
                "table": "public.customers",
                "steps": steps(&db.name, "publication:customer_feed", "pg_publication:customer_feed", DISABLE)
            }],
            "skipped_checks": no_repo()
        })
    );
}

#[test]
fn publication_excluding_every_personal_table_is_not_a_finding() {
    let db = fixture_db("publication_without_personal_tables");
    let report = stdout_json(&scan(Some(&db.url)));
    assert_eq!(
        report,
        json!({
            "data_map": {
                "stores": [email_store("customers")],
                "deletion_paths": [cascade_path("customers", "account_id")]
            },
            "findings": [],
            "skipped_checks": no_repo()
        })
    );
}

#[test]
fn trigger_copying_into_a_history_table_is_an_active_data_flow() {
    let db = fixture_db("copy_trigger_into_history");
    let report = stdout_json(&scan(Some(&db.url)));
    let trigger = "trigger:public.customers.customers_audit";
    assert_eq!(
        report,
        json!({
            "data_map": {
                "stores": [email_store("customers"), email_store("customers_history")],
                "deletion_paths": [cascade_path("customers", "account_id"), cascade_path("customers_history", "account_id")],
                "flows": [{
                    "kind": "copy_trigger",
                    "object": trigger,
                    "table": "public.customers",
                    "target": "public.customers_history",
                    "evidence_id": "pg_trigger:public.customers.customers_audit"
                }]
            },
            "findings": [{
                "check": "recreation_risk",
                "kind": "copy_trigger",
                "resource_id": trigger,
                "table": "public.customers",
                "steps": steps(&db.name, trigger, "pg_trigger:public.customers.customers_audit", DISABLE)
            }],
            "skipped_checks": no_repo()
        })
    );
}

#[test]
fn foreign_table_with_personal_columns_is_an_active_data_flow() {
    let db = fixture_db("foreign_table_with_personal_columns");
    let report = stdout_json(&scan(Some(&db.url)));
    let object = "foreign_table:public.crm_contacts";
    assert_eq!(
        report,
        json!({
            "data_map": {
                "stores": [],
                "flows": [{
                    "kind": "foreign_table",
                    "object": object,
                    "table": "public.crm_contacts",
                    "target": "crm_remote",
                    "evidence_id": "pg_foreign_table:public.crm_contacts"
                }]
            },
            "findings": [{
                "check": "recreation_risk",
                "kind": "foreign_table",
                "resource_id": object,
                "table": "public.crm_contacts",
                "steps": steps(&db.name, object, "pg_foreign_table:public.crm_contacts", DISABLE)
            }],
            "skipped_checks": no_repo()
        })
    );
}

#[test]
fn cross_database_link_extensions_are_noted_as_not_analysed() {
    let db = fixture_db("cross_database_links");
    let report = stdout_json(&scan(Some(&db.url)));
    assert_eq!(
        report["notes"],
        json!([
            "cross_database_link: dblink extension is installed; calls through it are not analysed",
            "cross_database_link: postgres_fdw extension is installed; calls through it are not analysed"
        ])
    );
    let incomplete: Vec<&Value> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["check"] == "data_map")
        .collect();
    assert_eq!(
        incomplete,
        [
            &json!({ "check": "data_map", "kind": "incomplete_input", "resource_id": "dblink", "steps": [] }),
            &json!({ "check": "data_map", "kind": "incomplete_input", "resource_id": "postgres_fdw", "steps": [] })
        ]
    );
    // postgres_fdw with a foreign table on personal data is a finding instead: no note.
    let db = fixture_db("foreign_table_with_personal_columns");
    assert_eq!(stdout_json(&scan(Some(&db.url))).get("notes"), None);
}

#[test]
fn managed_service_export_channels_are_flows_and_notes() {
    let db = fixture_db("managed_export_channels");
    let report = stdout_json(&scan(Some(&db.url)));
    let crm = "trigger:public.customers.customers_crm";
    let webhook = "trigger:public.customers.customers_webhook";
    // plans_crm calls the same webhook, but plans holds no personal data.
    assert_eq!(
        report["data_map"]["flows"],
        json!([{
            "kind": "export_trigger",
            "object": crm,
            "table": "public.customers",
            "target": "http_",
            "evidence_id": "pg_trigger:public.customers.customers_crm"
        }, {
            "kind": "export_trigger",
            "object": webhook,
            "table": "public.customers",
            "target": "supabase_functions",
            "evidence_id": "pg_trigger:public.customers.customers_webhook"
        }])
    );
    let recreation: Vec<&Value> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["check"] == "recreation_risk")
        .collect();
    assert_eq!(
        recreation,
        [
            &json!({
                "check": "recreation_risk",
                "kind": "export_trigger",
                "resource_id": crm,
                "table": "public.customers",
                "steps": steps(&db.name, crm, "pg_trigger:public.customers.customers_crm", DISABLE)
            }),
            &json!({
                "check": "recreation_risk",
                "kind": "export_trigger",
                "resource_id": webhook,
                "table": "public.customers",
                "steps": steps(&db.name, webhook, "pg_trigger:public.customers.customers_webhook", DISABLE)
            })
        ]
    );
    assert_eq!(
        report["notes"],
        json!([
            "export_channel: aws_s3 extension is installed; it can copy personal data out of the database, and calls through it are not analysed"
        ])
    );
    // An installed extension is a channel that exists, not unread input, so it
    // must not fail `--fail-on` the way data_map/incomplete_input does.
    assert!(
        !report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["kind"] == "incomplete_input"),
        "{report:#}"
    );
}
