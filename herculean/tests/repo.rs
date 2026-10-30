mod common;

use common::{email_store, fixture_db, scan, scan_with, stdout_json, steps, TempDir, DELETE};
use serde_json::{json, Value};
use std::net::TcpListener;
use std::process::{Command, Output};

fn repo(situation: &str) -> String {
    format!(
        "{}/tests/fixtures/repos/{situation}",
        env!("CARGO_MANIFEST_DIR")
    )
}

/// `herculean scan --repo <situation> <args>` with no connection string.
fn scan_repo(situation: &str, args: &[&str]) -> Output {
    scan_with(None, &[&["--repo", &repo(situation)], args].concat())
}

fn skipped_checks() -> Value {
    json!([
        { "check": "recreation_risk", "reason": "no database connection" },
        { "check": "least_privilege", "reason": "no database connection" },
        { "check": "drift", "reason": "no database connection" }
    ])
}

/// Findings with the source-specific `system_id` and `evidence_id` blanked.
fn without_source(findings: &Value) -> Value {
    let mut findings = findings.clone();
    for finding in findings.as_array_mut().unwrap() {
        for step in finding["steps"].as_array_mut().unwrap() {
            step["system_id"] = json!("");
            step["evidence_id"] = json!("");
        }
    }
    findings
}

#[test]
fn repo_only_set_null_foreign_key_is_not_a_deletion_path() {
    let db = fixture_db("fk_set_null_without_purge");
    let live = stdout_json(&scan(Some(&db.url)));
    let report = stdout_json(&scan_repo("fk_set_null_without_purge", &[]));
    assert_eq!(
        without_source(&report["findings"]),
        without_source(&live["findings"])
    );
    assert_eq!(report["data_map"], live["data_map"]);
    assert_eq!(report["findings"][0]["kind"], "no_deletion_path");
}

#[test]
fn repo_only_deletion_finding_matches_the_live_run() {
    let db = fixture_db("personal_table_without_deletion_path");
    let live = stdout_json(&scan(Some(&db.url)));
    let report = stdout_json(&scan_repo("no_deletion_path", &[]));
    assert_eq!(
        without_source(&report["findings"]),
        without_source(&live["findings"])
    );
    assert_eq!(report["data_map"], live["data_map"]);
    assert_eq!(
        report,
        json!({
            "data_map": { "stores": [{
                "schema": "public",
                "table": "customers",
                "columns": [
                    { "name": "email", "category": "contact", "source": "column_name", "confidence": "high" },
                    { "name": "full_name", "category": "identity", "source": "column_name", "confidence": "high" }
                ]
            }]},
            "findings": [{
                "check": "deletion_path",
                "kind": "no_deletion_path",
                "resource_id": "public.customers",
                "steps": steps("repo", "public.customers", "file:migrations/001_customers.sql:2", DELETE)
            }],
            "skipped_checks": skipped_checks()
        })
    );
}

#[test]
fn code_that_deletes_the_rows_is_a_deletion_path() {
    let report = stdout_json(&scan_repo("code_deletes_rows", &[]));
    assert_eq!(report["findings"], json!([]));
    assert_eq!(
        report["data_map"]["deletion_paths"],
        json!([{ "table": "public.customers", "kind": "code", "evidence_id": "file:src/purge.py:5" }])
    );
    assert_eq!(report["skipped_checks"], skipped_checks());
}

/// Finding kinds and deletion paths of a repo-only scan of `files` plus a
/// `customers` table in `migrations/001.sql`.
fn deletion_result(files: &[(&str, &str)]) -> (Vec<String>, Value) {
    let mut files = files.to_vec();
    files.push(("migrations/001.sql", CREATE_CUSTOMERS));
    let tmp = repo_with(&files);
    let report = stdout_json(&scan_with(None, &["--repo", tmp.0.to_str().unwrap()]));
    let kinds = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["kind"].as_str().unwrap().to_string())
        .collect();
    (kinds, report["data_map"]["deletion_paths"].clone())
}

#[test]
fn deletes_in_docs_comments_or_always_false_are_not_deletion_paths() {
    for (path, text) in [
        ("README.md", "Example only:\nDELETE FROM customers;\n"),
        ("docs/purge.txt", "DELETE FROM customers;\n"),
        ("src/app.py", "# DELETE FROM customers\n"),
        ("src/app.ts", "  // DELETE FROM customers WHERE id = $1\n"),
        ("src/app.sql", "-- DELETE FROM customers;\n"),
        (
            "src/app.go",
            "db.Exec(\"DELETE FROM customers WHERE false\")\n",
        ),
        (
            "src/app.rb",
            "db.exec('DELETE FROM customers WHERE 1 = 0')\n",
        ),
    ] {
        let (kinds, paths) = deletion_result(&[(path, text)]);
        assert_eq!(kinds, ["no_deletion_path"], "{path}");
        assert_eq!(paths, Value::Null, "{path}");
    }
}

/// Review repros: deletes that do run, or comment filters that must not drop code.
#[test]
fn deletes_that_run_are_deletion_paths() {
    for (path, text) in [
        (
            "src/app.go",
            "db.Exec(\"DELETE FROM customers WHERE 1 > 0\")\n",
        ),
        (
            "src/app.go",
            "db.Exec(\"DELETE FROM customers WHERE 1 <> 0\")\n",
        ),
        (
            "src/app.go",
            "db.Exec(\"DELETE FROM customers WHERE false OR id = $1\")\n",
        ),
        (
            "src/app.go",
            "db.Exec(\"DELETE FROM customers WHERE 1=0 OR id = $1\")\n",
        ),
        (
            "src/app.c",
            "#define Q \"DELETE FROM customers WHERE id = ?\"\n",
        ),
        (
            "src/app.go",
            "*p = exec(\"DELETE FROM customers WHERE id = $1\")\n",
        ),
    ] {
        let (kinds, paths) = deletion_result(&[(path, text)]);
        assert_eq!(kinds, Vec::<String>::new(), "{text}");
        assert_eq!(paths[0]["evidence_id"], format!("file:{path}:1"), "{text}");
    }
}

/// Each delete is credited to its own line, never to the line above it.
#[test]
fn a_delete_is_credited_only_to_its_own_line() {
    for text in [
        "db.Exec(\"DELETE FROM customers WHERE false\")\ndb.Exec(\"DELETE FROM customers WHERE id = $1\")\n",
        "items.delete(x)\ndb.Exec(\"DELETE FROM customers WHERE id = $1\")\n",
    ] {
        let (_, paths) = deletion_result(&[("src/app.go", text)]);
        assert_eq!(
            paths,
            json!([{ "table": "public.customers", "kind": "code", "evidence_id": "file:src/app.go:2" }]),
            "{text}"
        );
    }
    for text in [
        "obj.delete(x)\n// DELETE FROM customers\n",
        "q.delete()\nfrom customers import x\n",
    ] {
        let (kinds, _) = deletion_result(&[("src/app.ts", text)]);
        assert_eq!(kinds, ["no_deletion_path"], "{text}");
    }
}

#[test]
fn delete_from_only_and_multi_line_deletes_are_deletion_paths() {
    for text in [
        "db.query(\"DELETE FROM ONLY customers WHERE id = $1\")\n",
        "db.query(`\n  DELETE FROM\n    customers\n  WHERE id = $1`)\n",
    ] {
        let (kinds, paths) = deletion_result(&[("src/app.ts", text)]);
        assert_eq!(kinds, Vec::<String>::new(), "{text}");
        let line = text.lines().position(|l| l.contains("DELETE")).unwrap() + 1;
        assert_eq!(
            paths,
            json!([{ "table": "public.customers", "kind": "code", "evidence_id": format!("file:src/app.ts:{line}") }]),
            "{text}"
        );
    }
}

#[test]
fn a_cascade_from_the_table_itself_is_not_a_deletion_path() {
    let report = migrations_report(&[(
        "001.sql",
        "CREATE TABLE customers (id int PRIMARY KEY, email text,\n\
         parent_id int REFERENCES customers (id) ON DELETE CASCADE);\n",
    )]);
    assert_eq!(report["data_map"]["deletion_paths"], Value::Null);
    assert_eq!(report["findings"][0]["kind"], "no_deletion_path");
}

#[test]
fn a_foreign_key_without_on_delete_does_not_hide_no_deletion_path() {
    let report = migrations_report(&[(
        "001.sql",
        "CREATE TABLE accounts (id int PRIMARY KEY);\n\
         CREATE TABLE customers (id int, email text, account_id int REFERENCES accounts (id));\n",
    )]);
    let kinds: Vec<&str> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["fk_without_on_delete", "no_deletion_path"]);
}

#[test]
fn migration_facts_give_the_live_deletion_rules() {
    let report = stdout_json(&scan_repo("migration_facts", &[]));
    let file = "file:db/migrations/001_accounts.sql";
    assert_eq!(
        report,
        json!({
            "data_map": {
                "stores": [
                    { "schema": "billing", "table": "contacts", "columns": [
                        { "name": "phone", "category": "contact", "source": "column_name", "confidence": "high" }
                    ]},
                    { "schema": "public", "table": "customers", "columns": [
                        { "name": "email", "category": "contact", "source": "column_name", "confidence": "high" }
                    ]}
                ],
                "deletion_paths": [
                    { "table": "public.customers", "kind": "on_delete", "evidence_id": format!("{file}:11") }
                ]
            },
            "findings": [
                {
                    "check": "deletion_path",
                    "kind": "fk_without_on_delete",
                    "resource_id": "billing.contacts",
                    "steps": steps("repo", "billing.contacts", &format!("{file}:20"), DELETE)
                },
                {
                    "check": "deletion_path",
                    "kind": "soft_delete_without_purge",
                    "resource_id": "billing.contacts",
                    "steps": steps("repo", "billing.contacts", &format!("{file}:18"), DELETE)
                }
            ],
            "skipped_checks": skipped_checks()
        })
    );
}

#[test]
fn data_map_overrides_apply_to_a_repo_only_run() {
    let map = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/data_map_override.yaml"
    );
    let report = stdout_json(&scan_repo("no_deletion_path", &["--data-map", map]));
    assert_eq!(
        report["data_map"]["stores"],
        json!([{ "schema": "public", "table": "customers", "columns": [
            { "name": "email", "category": "contact", "source": "column_name", "confidence": "high" }
        ]}])
    );
}

#[test]
fn unparsable_statement_is_skipped_with_a_note_naming_the_file() {
    let out = scan_repo("unparsable_statement", &[]);
    let report = stdout_json(&out);
    let tables: Vec<&str> = report["data_map"]["stores"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["table"].as_str().unwrap())
        .collect();
    assert_eq!(tables, ["contacts", "customers"]);
    assert_eq!(
        report["notes"],
        json!(["unparsed_sql: migrations/001_customers.sql: a statement could not be parsed and was skipped"])
    );
    let incomplete: Vec<&Value> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["check"] == "data_map")
        .collect();
    assert_eq!(
        incomplete,
        [&json!({
            "check": "data_map",
            "kind": "incomplete_input",
            "resource_id": "migrations/001_customers.sql",
            "steps": []
        })]
    );
    assert!(!String::from_utf8_lossy(&out.stdout).contains("NOT SQL"));
}

#[test]
fn a_live_scan_without_a_repo_lists_drift_as_skipped() {
    let db = fixture_db("personal_table_without_deletion_path");
    let report = stdout_json(&scan_with(Some(&db.url), &[]));
    assert_eq!(
        report["skipped_checks"],
        json!([{ "check": "drift", "reason": "no repo given" }])
    );
}

#[test]
fn repo_only_run_attempts_no_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    let out = Command::new(env!("CARGO_BIN_EXE_herculean"))
        .args(["scan", "--repo", &repo("no_deletion_path")])
        .env_remove("HERCULEAN_DATABASE_URL")
        .env("PGHOST", "127.0.0.1")
        .env("PGPORT", &port)
        .output()
        .unwrap();
    stdout_json(&out);
    let accepted = listener.accept();
    assert!(
        matches!(&accepted, Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
        "repo-only scan connected: {accepted:?}"
    );
}

#[test]
fn neither_repo_nor_database_names_both_inputs() {
    let out = scan(None);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("HERCULEAN_DATABASE_URL"), "{stderr}");
    assert!(stderr.contains("--repo"), "{stderr}");
}

#[test]
fn sampling_needs_a_database() {
    let out = scan_repo("no_deletion_path", &["--sample"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--sample"));
}

#[test]
fn live_scan_with_repo_adds_code_deletion_paths() {
    let db = fixture_db("personal_table_without_deletion_path");
    let report = stdout_json(&scan_with(
        Some(&db.url),
        &["--repo", &repo("code_deletes_rows")],
    ));
    assert_eq!(report["findings"], json!([]));
    assert_eq!(
        report["data_map"]["deletion_paths"],
        json!([{ "table": "public.customers", "kind": "code", "evidence_id": "file:src/purge.py:5" }])
    );
    assert!(report.get("skipped_checks").is_none());
}

#[test]
fn two_repo_runs_give_byte_identical_reports() {
    let first = scan_repo("migration_facts", &[]);
    let second = scan_repo("migration_facts", &[]);
    assert!(first.status.success());
    assert_eq!(first.stdout, second.stdout);
}

#[test]
fn foreign_keys_added_by_alter_table_are_deletion_paths() {
    let report = stdout_json(&scan_repo("fk_added_by_alter", &[]));
    let file = "file:migrations/002_account_fks.sql";
    assert_eq!(report["findings"], json!([]));
    assert_eq!(
        report["data_map"]["deletion_paths"],
        json!([
            { "table": "public.contacts", "kind": "on_delete", "evidence_id": format!("{file}:7") },
            { "table": "public.customers", "kind": "on_delete", "evidence_id": format!("{file}:4") }
        ])
    );
}

#[test]
fn a_column_added_again_is_listed_once() {
    let report = stdout_json(&scan_repo("repeated_add_column", &[]));
    assert_eq!(
        report["data_map"]["stores"],
        json!([{ "schema": "public", "table": "customers", "columns": [
            { "name": "email", "category": "contact", "source": "column_name", "confidence": "high" },
            { "name": "phone", "category": "contact", "source": "column_name", "confidence": "high" }
        ]}])
    );
}

/// `herculean scan --repo <dir>`, killed (and failed) if it runs over 20 seconds.
fn scan_dir_with_deadline(dir: &std::path::Path) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_herculean"))
        .arg("scan")
        .arg("--repo")
        .arg(dir)
        .env_remove("HERCULEAN_DATABASE_URL")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while child.try_wait().unwrap().is_none() {
        if std::time::Instant::now() > deadline {
            child.kill().unwrap();
            panic!("scan hung");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    child.wait_with_output().unwrap()
}

fn store_tables(report: &Value) -> Vec<String> {
    report["data_map"]["stores"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["table"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn symlinks_fifos_and_oversized_files_are_not_read() {
    let tmp = TempDir::new();
    let (outside, repo) = (tmp.0.join("outside"), tmp.0.join("repo"));
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::create_dir_all(repo.join("migrations")).unwrap();
    std::fs::write(
        repo.join("migrations/001_customers.sql"),
        "CREATE TABLE customers (id int, email text);\n",
    )
    .unwrap();
    std::fs::write(
        outside.join("secret.sql"),
        "CREATE TABLE linked_people (id int, email text);\n",
    )
    .unwrap();
    std::os::unix::fs::symlink(
        outside.join("secret.sql"),
        repo.join("migrations/002_link.sql"),
    )
    .unwrap();
    std::os::unix::fs::symlink(&outside, repo.join("linked_dir")).unwrap();
    let fifo = repo.join("migrations/003_pipe.sql");
    assert!(Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    let big = format!(
        "CREATE TABLE big_people (id int, email text);\n{}",
        "-- padding\n".repeat(110_000)
    );
    std::fs::write(repo.join("migrations/004_big.sql"), big).unwrap();

    let out = scan_dir_with_deadline(&repo);
    let report = stdout_json(&out);
    assert_eq!(store_tables(&report), ["customers"]);
    assert_eq!(
        report["notes"],
        json!(["skipped_large_file: migrations/004_big.sql is over 1 MiB and was not read"])
    );
}

#[test]
fn a_committed_data_map_in_the_repo_is_used_by_default() {
    let report = stdout_json(&scan_repo("committed_data_map", &[]));
    assert_eq!(report["data_map"]["stores"], json!([]));
    assert_eq!(report["findings"], json!([]));

    let tmp = TempDir::new();
    let out = Command::new(env!("CARGO_BIN_EXE_herculean"))
        .args(["report", "--repo", &repo("committed_data_map"), "--out"])
        .arg(tmp.0.join("out"))
        .env_remove("HERCULEAN_DATABASE_URL")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let written: Value =
        serde_json::from_str(&std::fs::read_to_string(tmp.0.join("out/report.json")).unwrap())
            .unwrap();
    assert_eq!(written["data_map"]["stores"], json!([]));

    // An explicit --data-map still replaces it.
    let empty = tmp.0.join("empty.yaml");
    std::fs::write(&empty, "overrides: []\n").unwrap();
    let report = stdout_json(&scan_repo(
        "committed_data_map",
        &["--data-map", empty.to_str().unwrap()],
    ));
    assert_eq!(report["data_map"]["stores"][0]["table"], "orders");
}

const OVERRIDES: &str = "overrides:
  # contacts.phone is a desk extension, not personal
  - column: public.contacts.phone
    personal: false
";

#[test]
fn write_data_map_writes_the_detected_map_and_keeps_the_overrides() {
    let tmp = TempDir::new();
    let migrations = tmp.0.join("migrations");
    std::fs::create_dir_all(&migrations).unwrap();
    for f in ["001_tables.sql", "002_account_fks.sql"] {
        std::fs::copy(
            format!("{}/migrations/{f}", repo("fk_added_by_alter")),
            migrations.join(f),
        )
        .unwrap();
    }
    let map = tmp.0.join("data-map.yaml");
    std::fs::write(&map, OVERRIDES).unwrap();
    let write = || {
        let out = scan_with(
            None,
            &["--repo", tmp.0.to_str().unwrap(), "--write-data-map"],
        );
        stdout_json(&out);
        std::fs::read_to_string(&map).unwrap()
    };
    let first = write();
    assert_eq!(
        first,
        format!(
            "# Generated by `herculean scan --write-data-map`, except `overrides`:
# edit only that section; its entries win over detection.
stores:
- schema: public
  table: customers
  columns:
  - name: email
    category: contact
    source: column_name
    confidence: high
flows: []
deletion_paths:
- table: public.customers
  kind: on_delete
  evidence_id: file:migrations/002_account_fks.sql:4
{OVERRIDES}"
        )
    );
    // Re-running reads the generated sections back and changes nothing.
    assert_eq!(write(), first);
}

#[test]
fn write_data_map_needs_a_repo_or_a_data_map_path() {
    let out = scan_with(None, &["--write-data-map"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).starts_with("usage:"));
}

/// `scan --repo <dir> --write-data-map`.
fn write_data_map_in(dir: &std::path::Path) -> Output {
    scan_with(None, &["--repo", dir.to_str().unwrap(), "--write-data-map"])
}

#[test]
fn write_data_map_refuses_to_replace_a_map_it_skipped() {
    let tmp = repo_with(&[
        ("repo/migrations/001.sql", CREATE_CUSTOMERS),
        ("outside.yaml", OVERRIDES),
    ]);
    let repo = tmp.0.join("repo");
    let map = repo.join("data-map.yaml");
    let big = format!("{OVERRIDES}{}", "# padding\n".repeat(110_000));
    for symlink in [true, false] {
        let _ = std::fs::remove_file(&map);
        if symlink {
            std::os::unix::fs::symlink(tmp.0.join("outside.yaml"), &map).unwrap();
        } else {
            std::fs::write(&map, &big).unwrap();
        }
        let before = (std::fs::read_link(&map).ok(), std::fs::read(&map).unwrap());
        let out = write_data_map_in(&repo);
        assert_eq!(out.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&out.stderr).contains("data-map.yaml"));
        let after = (std::fs::read_link(&map).ok(), std::fs::read(&map).unwrap());
        assert_eq!(after, before);
    }
    assert_eq!(
        std::fs::read_to_string(tmp.0.join("outside.yaml")).unwrap(),
        OVERRIDES
    );
}

const EMAIL_NOT_PERSONAL: &str = "  - column: public.customers.email\n    personal: false\n";

#[test]
fn write_data_map_keeps_overrides_under_a_quoted_key() {
    for key in ["\"overrides\":", "'overrides':"] {
        let map_text = format!("{key}\n{EMAIL_NOT_PERSONAL}");
        let tmp = repo_with(&[
            ("migrations/001.sql", CREATE_CUSTOMERS),
            ("data-map.yaml", &map_text),
        ]);
        let before = stdout_json(&scan_with(None, &["--repo", tmp.0.to_str().unwrap()]));
        assert_eq!(before["findings"], json!([]));
        assert_eq!(write_data_map_in(&tmp.0).status.code(), Some(0));
        let written = std::fs::read_to_string(tmp.0.join("data-map.yaml")).unwrap();
        assert!(written.ends_with(&map_text), "{written}");
        let after = stdout_json(&scan_with(None, &["--repo", tmp.0.to_str().unwrap()]));
        assert_eq!(after["findings"], before["findings"]);
    }
}

#[test]
fn write_data_map_refuses_when_the_overrides_would_not_survive() {
    // A flow-style map parses, but the line scanner cannot lift its overrides out.
    let map_text = "{overrides: [{column: public.customers.email, personal: false}]}\n";
    let tmp = repo_with(&[
        ("migrations/001.sql", CREATE_CUSTOMERS),
        ("data-map.yaml", map_text),
    ]);
    let out = write_data_map_in(&tmp.0);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("overrides"));
    assert_eq!(
        std::fs::read_to_string(tmp.0.join("data-map.yaml")).unwrap(),
        map_text
    );
}

#[test]
fn column_comments_classify_live_and_in_migrations_below_names_and_overrides() {
    let expected = || {
        json!([{ "schema": "public", "table": "members", "columns": [
            { "name": "born", "category": "identity", "source": "comment", "confidence": "medium" },
            { "name": "contact_handle", "category": "contact", "source": "comment", "confidence": "medium" },
            { "name": "full_name", "category": "identity", "source": "column_name", "confidence": "high" },
            { "name": "tax_ref", "category": "personal", "source": "comment", "confidence": "medium" }
        ]}])
    };
    let db = fixture_db("column_comments");
    let live = stdout_json(&scan(Some(&db.url)));
    assert_eq!(live["data_map"]["stores"], expected());

    let tmp = TempDir::new();
    std::fs::create_dir_all(tmp.0.join("migrations")).unwrap();
    std::fs::copy(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/column_comments.sql"
        ),
        tmp.0.join("migrations/001.sql"),
    )
    .unwrap();
    let repo_dir = tmp.0.to_str().unwrap();
    let from_repo = stdout_json(&scan_with(None, &["--repo", repo_dir]));
    assert_eq!(from_repo["data_map"]["stores"], expected());

    // An override wins over a comment.
    std::fs::write(
        tmp.0.join("data-map.yaml"),
        "overrides:\n  - column: public.members.tax_ref\n    personal: false\n",
    )
    .unwrap();
    let overridden = stdout_json(&scan_with(None, &["--repo", repo_dir]));
    let columns: Vec<&str> = overridden["data_map"]["stores"][0]["columns"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert_eq!(columns, ["born", "contact_handle", "full_name"]);
}

/// A scratch repo holding `files` (path relative to the repo, text).
fn repo_with(files: &[(&str, &str)]) -> TempDir {
    let tmp = TempDir::new();
    for (path, text) in files {
        let path = tmp.0.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }
    tmp
}

const CREATE_CUSTOMERS: &str = "CREATE TABLE customers (id int, email text);\n";
const DROP_CUSTOMERS: &str = "DROP TABLE customers;\n";

#[test]
fn sql_outside_the_migrations_dir_is_not_applied_but_its_deletes_still_count() {
    let tmp = repo_with(&[
        ("migrations/001.sql", CREATE_CUSTOMERS),
        (
            "test/999_teardown.sql",
            "DELETE FROM customers;\nDROP TABLE customers;\n",
        ),
    ]);
    let dir = tmp.0.to_str().unwrap();
    for args in [&[][..], &["--migrations-dir", "migrations"][..]] {
        let report = stdout_json(&scan_with(None, &[&["--repo", dir], args].concat()));
        assert_eq!(
            report["data_map"]["stores"],
            json!([email_store("customers")])
        );
        assert_eq!(
            report["data_map"]["deletion_paths"],
            json!([{ "table": "public.customers", "kind": "code", "evidence_id": "file:test/999_teardown.sql:1" }])
        );
        assert_eq!(report.get("notes"), None);
    }

    let out = Command::new(env!("CARGO_BIN_EXE_herculean"))
        .args([
            "report",
            "--repo",
            dir,
            "--migrations-dir",
            "migrations",
            "--out",
        ])
        .arg(tmp.0.join("out"))
        .env_remove("HERCULEAN_DATABASE_URL")
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let written: Value =
        serde_json::from_str(&std::fs::read_to_string(tmp.0.join("out/report.json")).unwrap())
            .unwrap();
    assert_eq!(
        written["data_map"]["stores"],
        json!([email_store("customers")])
    );
}

#[test]
fn down_migrations_are_not_applied() {
    for dir in ["migrations", "db/migrations", "supabase/migrations", "sql"] {
        let tmp = repo_with(&[
            (&format!("{dir}/001_customers.sql"), CREATE_CUSTOMERS),
            (&format!("{dir}/001_customers.down.sql"), DROP_CUSTOMERS),
            (&format!("{dir}/002_x/down.sql"), DROP_CUSTOMERS),
        ]);
        let report = stdout_json(&scan_with(None, &["--repo", tmp.0.to_str().unwrap()]));
        assert_eq!(
            report["data_map"]["stores"],
            json!([email_store("customers")]),
            "{dir}"
        );
    }
}

#[test]
fn with_no_migrations_dir_every_sql_file_is_applied_with_a_note() {
    let tmp = repo_with(&[
        ("schema/001.sql", CREATE_CUSTOMERS),
        ("test/teardown.sql", DROP_CUSTOMERS),
    ]);
    let dir = tmp.0.to_str().unwrap();
    let report = stdout_json(&scan_with(None, &["--repo", dir]));
    assert_eq!(report["data_map"]["stores"], json!([]));
    assert_eq!(
        report["notes"],
        json!(["no_migrations_dir: none of migrations/, db/migrations/, supabase/migrations/ exists \
                (pass --migrations-dir), so every *.sql file except down migrations was read as a migration"])
    );
    // The note says which files were read, not that any went unread: it fails no CI.
    assert_eq!(report["findings"], json!([]));
    let out = Command::new(env!("CARGO_BIN_EXE_herculean"))
        .args(["report", "--repo", dir, "--fail-on", "high", "--out"])
        .arg(tmp.0.join("out"))
        .env_remove("HERCULEAN_DATABASE_URL")
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let report = stdout_json(&scan_with(
        None,
        &["--repo", dir, "--migrations-dir", "schema/"],
    ));
    assert_eq!(
        report["data_map"]["stores"],
        json!([email_store("customers")])
    );
    assert_eq!(report.get("notes"), None);
}

/// `repo_with` the files under `migrations/`, scanned repo-only.
fn migrations_report(files: &[(&str, &str)]) -> Value {
    let files: Vec<(String, &str)> = files
        .iter()
        .map(|(n, t)| (format!("migrations/{n}"), *t))
        .collect();
    let files: Vec<(&str, &str)> = files.iter().map(|(n, t)| (n.as_str(), *t)).collect();
    let tmp = repo_with(&files);
    stdout_json(&scan_with(None, &["--repo", tmp.0.to_str().unwrap()]))
}

/// `schema.table` of each store in the data map.
fn store_names(report: &Value) -> Vec<String> {
    let stores = report["data_map"]["stores"].as_array().unwrap();
    stores
        .iter()
        .map(|s| {
            format!(
                "{}.{}",
                s["schema"].as_str().unwrap(),
                s["table"].as_str().unwrap()
            )
        })
        .collect()
}

#[test]
fn set_search_path_decides_the_schema_of_unqualified_tables() {
    for set in [
        "SET search_path TO tenant;",
        "SET search_path = tenant, public;",
        "SET LOCAL search_path TO \"tenant\";",
        "SET SESSION search_path TO tenant;",
    ] {
        let sql = format!(
            "CREATE SCHEMA tenant;\n{set}\nCREATE TABLE users (email text);\n\
             CREATE TABLE public.audit (email text);\n"
        );
        let report = migrations_report(&[("001.sql", &sql)]);
        assert_eq!(
            store_names(&report),
            ["public.audit", "tenant.users"],
            "{set}"
        );
        assert_eq!(report.get("notes"), None, "{set}");
    }
}

#[test]
fn the_search_path_resets_at_the_end_of_each_migration_file() {
    let report = migrations_report(&[
        (
            "001.sql",
            "SET search_path TO tenant;\nCREATE TABLE users (email text);\n",
        ),
        ("002.sql", "CREATE TABLE accounts (email text);\n"),
    ]);
    assert_eq!(store_names(&report), ["public.accounts", "tenant.users"]);
}

#[test]
fn the_search_path_applies_to_alter_drop_comment_and_references() {
    let report = migrations_report(&[(
        "001.sql",
        "SET search_path TO tenant;\n\
         CREATE TABLE users (id int primary key, email text, tax_ref text);\n\
         ALTER TABLE users ADD COLUMN full_name text;\n\
         COMMENT ON COLUMN users.tax_ref IS 'Contains PII';\n\
         CREATE TABLE gone (email text);\n\
         DROP TABLE gone;\n",
    )]);
    let stores = report["data_map"]["stores"].as_array().unwrap();
    // ALTER added full_name, COMMENT made tax_ref personal, DROP removed tenant.gone.
    assert_eq!(store_names(&report), ["tenant.users"]);
    let columns: Vec<&str> = stores[0]["columns"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert_eq!(columns, ["email", "full_name", "tax_ref"]);
}

#[test]
fn the_search_path_applies_to_references() {
    let tmp = repo_with(&[(
        "migrations/001.sql",
        "SET search_path TO tenant;\n\
         CREATE TABLE users (id bigint PRIMARY KEY);\n\
         CREATE TABLE orders (id bigint, email text, user_id bigint REFERENCES users (id));\n",
    )]);
    let out = Command::new(env!("CARGO_BIN_EXE_herculean"))
        .args([
            "fix",
            "--finding",
            "deletion_path/fk_without_on_delete/tenant.orders",
        ])
        .args(["--repo", tmp.0.to_str().unwrap()])
        .env("HERCULEAN_NOW", "2026-10-26T12:34:56Z")
        .env_remove("HERCULEAN_DATABASE_URL")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let sql =
        std::fs::read_to_string(tmp.0.join(
            "migrations/20261026123456_herculean_fix_fk_without_on_delete__tenant.orders.sql",
        ))
        .unwrap();
    assert!(
        sql.contains("REFERENCES \"tenant\".\"users\" (\"id\")"),
        "{sql}"
    );
}

#[test]
fn an_unsupported_search_path_form_is_noted_and_keeps_the_current_path() {
    for set in [
        "SET search_path TO \"$user\", public;",
        "SET search_path TO current_schema();",
        "SET search_path TO 'tenant';",
        "SELECT set_config('search_path', 'tenant', false);",
    ] {
        let sql = format!("{set}\nCREATE TABLE users (email text);\n");
        let report = migrations_report(&[("001.sql", &sql)]);
        assert_eq!(store_names(&report), ["public.users"], "{set}");
        let notes = report["notes"].as_array().unwrap();
        assert_eq!(notes.len(), 1, "{set}");
        assert!(
            notes[0]
                .as_str()
                .unwrap()
                .starts_with("search_path_ignored: migrations/001.sql: "),
            "{set}: {notes:?}"
        );
    }
    // An earlier supported path stays in force.
    let report = migrations_report(&[(
        "001.sql",
        "SET search_path TO tenant;\nSET search_path TO \"$user\";\nCREATE TABLE users (email text);\n",
    )]);
    assert_eq!(store_names(&report), ["tenant.users"]);
    assert_eq!(report["notes"].as_array().unwrap().len(), 1);
}

#[test]
fn a_pg_dump_empty_search_path_is_supported_and_not_incomplete() {
    let report = migrations_report(&[(
        "001.sql",
        "SELECT pg_catalog.set_config('search_path', '', false);\nCREATE TABLE public.users (email text);\n",
    )]);
    assert_eq!(store_names(&report), ["public.users"]);
    assert_eq!(report.get("notes"), None);
    assert!(!report.to_string().contains("incomplete_input"), "{report}");
}

#[test]
fn resetting_the_search_path_goes_back_to_public() {
    for reset in [
        "RESET search_path;",
        "RESET ALL;",
        "SET search_path TO DEFAULT;",
        "SET LOCAL search_path TO DEFAULT;",
    ] {
        let sql =
            format!("SET search_path TO tenant;\n{reset}\nCREATE TABLE users (email text);\n");
        let report = migrations_report(&[("001.sql", &sql)]);
        assert_eq!(store_names(&report), ["public.users"], "{reset}");
        assert_eq!(report.get("notes"), None, "{reset}");
    }
    // Resetting some other setting leaves the path alone.
    let report = migrations_report(&[(
        "001.sql",
        "SET search_path TO tenant;\nRESET statement_timeout;\nCREATE TABLE users (email text);\n",
    )]);
    assert_eq!(store_names(&report), ["tenant.users"]);
}

#[test]
fn a_missing_or_outside_migrations_dir_is_an_error() {
    let tmp = repo_with(&[("migrations/001.sql", CREATE_CUSTOMERS)]);
    let dir = tmp.0.to_str().unwrap();
    for (migrations_dir, error) in [
        (
            "db/migrations",
            "migrations dir db/migrations is not a directory in the repo",
        ),
        (
            "../migrations",
            "migrations dir ../migrations is outside the repo",
        ),
        ("/tmp", "migrations dir /tmp is outside the repo"),
    ] {
        let out = scan_with(None, &["--repo", dir, "--migrations-dir", migrations_dir]);
        assert_eq!(out.status.code(), Some(1));
        assert_eq!(
            String::from_utf8_lossy(&out.stderr),
            format!("herculean: cannot read repo {dir}: {error}\n")
        );
    }
}

/// Like Postgres, `DROP TABLE … CASCADE` and `DROP COLUMN … CASCADE` take the
/// foreign keys that reference what they drop, and with them the ON DELETE paths.
#[test]
fn cascading_drops_take_the_foreign_keys_that_reference_them() {
    let fixture = "fk_targets_dropped_with_cascade";
    let db = fixture_db(fixture);
    let live = stdout_json(&scan(Some(&db.url)));
    let sql = std::fs::read_to_string(format!(
        "{}/tests/fixtures/{fixture}.sql",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let report = migrations_report(&[("001.sql", &sql)]);
    let found: Vec<(&Value, &Value)> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| (&f["kind"], &f["resource_id"]))
        .collect();
    assert_eq!(
        found,
        [
            (&json!("no_deletion_path"), &json!("public.customers")),
            (&json!("no_deletion_path"), &json!("public.members")),
        ]
    );
    assert_eq!(report["data_map"].get("deletion_paths"), None, "{report:#}");
    assert_eq!(
        without_source(&report["findings"]),
        without_source(&live["findings"])
    );
    assert_eq!(report["data_map"], live["data_map"]);
}

#[test]
fn repo_only_name_rules_and_column_types_match_the_live_run() {
    let db = fixture_db("column_name_tokens");
    let live = stdout_json(&scan(Some(&db.url)));
    let report = stdout_json(&scan_repo("column_name_tokens", &[]));
    assert_eq!(report["data_map"], live["data_map"]);
    assert_eq!(
        without_source(&report["findings"]),
        without_source(&live["findings"])
    );
}

/// A column's type follows `ALTER COLUMN … TYPE` and a drop-then-re-add, as the
/// live catalog would show it: `email boolean` → `text` classifies, `phone text`
/// → `boolean` no longer does.
#[test]
fn a_column_type_change_moves_it_into_or_out_of_the_name_rules() {
    let report = migrations_report(&[(
        "001.sql",
        "CREATE TABLE users (email boolean, phone text, ssn boolean);\n\
         ALTER TABLE users ALTER COLUMN email TYPE text USING email::text;\n\
         ALTER TABLE users ALTER COLUMN phone SET DATA TYPE boolean USING phone::boolean;\n\
         ALTER TABLE users DROP COLUMN ssn;\n\
         ALTER TABLE users ADD COLUMN ssn text;\n",
    )]);
    let columns: Vec<&str> = report["data_map"]["stores"][0]["columns"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert_eq!(columns, ["email", "ssn"], "{report:#}");
}
