mod common;

use common::{admin_sql, all_files, fixture_db, TempDir, PASSWORD};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const FIXTURE: &str = "personal_table_without_deletion_path";
const NOW: &str = "2026-10-26T12:34:56Z";

/// Runs `herculean report --out <tmp>/out <args>` against `url`, with a fixed clock.
fn report(url: &str, tmp: &TempDir, args: &[&str]) -> (Output, PathBuf) {
    let out_dir = tmp.0.join("out");
    (report_to(url, &tmp.0, &out_dir, args), out_dir)
}

/// Runs `herculean report --out <out_dir> <args>` from `cwd`.
fn report_to(url: &str, cwd: &Path, out_dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_herculean"))
        .current_dir(cwd)
        .arg("report")
        .arg("--out")
        .arg(out_dir)
        .args(args)
        .env("HERCULEAN_DATABASE_URL", url)
        .env("HERCULEAN_NOW", NOW)
        .output()
        .expect("run herculean")
}

fn read_json(path: &Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn report_counts_a_set_null_foreign_key_as_an_open_finding() {
    let db = fixture_db("fk_set_null_without_purge");
    let tmp = TempDir::new();
    let (out, dir) = report(&db.url, &tmp, &[]);
    assert_eq!(out.status.code(), Some(0));
    let evidence = read_json(&dir.join("evidence/C1.2.json"));
    let item = evidence["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["check"] == "deletion_path")
        .unwrap();
    assert_eq!(item["result"], "findings_open");
    assert_eq!(item["findings"].as_array().unwrap().len(), 1);
}

#[test]
fn report_lists_the_findings_criterion_with_a_fully_stamped_evidence_item() {
    let db = fixture_db(FIXTURE);
    let tmp = TempDir::new();
    let (out, dir) = report(&db.url, &tmp, &[]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let readiness = std::fs::read_to_string(dir.join("readiness.md")).unwrap();
    assert!(readiness.contains("C1.2"), "{readiness}");
    assert!(readiness.contains("deletion_path"), "{readiness}");

    let evidence = read_json(&dir.join("evidence/C1.2.json"));
    assert_eq!(evidence["criterion"], "C1.2");
    assert_eq!(evidence["verify_before_release"], true);
    let items = evidence["items"].as_array().unwrap();
    let item = items
        .iter()
        .find(|i| i["check"] == "deletion_path")
        .expect("deletion_path item");
    assert_eq!(item["criterion"], "C1.2");
    assert_eq!(item["result"], "findings_open");
    assert_eq!(item["timestamp"], NOW);
    assert_eq!(item["herculean_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(item["envelope_version"], 1);
    assert_eq!(item["notes"], json!([]));
    assert_eq!(
        item["skipped_checks"],
        json!([{ "check": "drift", "reason": "no repo given" }])
    );
    // No --repo: no commit to name. The catalog and the data map are digested.
    assert_eq!(item["provenance"]["repo_head"], Value::Null);
    for hash in [
        &item["sha256"],
        &item["provenance"]["catalog_sha256"],
        &item["provenance"]["data_map_sha256"],
    ] {
        let hash = hash.as_str().unwrap();
        assert!(
            hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()),
            "{hash}"
        );
    }
    let findings = item["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["resource_id"], "public.customers");
    assert_eq!(findings[0]["kind"], "no_deletion_path");

    // The check with no findings mapped to C1.2 says so, without "pass" wording.
    let recreation = items
        .iter()
        .find(|i| i["check"] == "recreation_risk")
        .unwrap();
    assert_eq!(recreation["result"], "no_findings");
    assert_eq!(recreation["findings"], json!([]));

    // drift needs --repo, so a live-only run did not run it.
    let drift = read_json(&dir.join("evidence/CC8.1.json"));
    assert_eq!(drift["items"][0]["check"], "drift");
    assert_eq!(drift["items"][0]["result"], "not_run");

    // report.json is the scan report, unchanged.
    let scan = read_json(&dir.join("report.json"));
    assert_eq!(scan["findings"][0]["check"], "deletion_path");
}

#[test]
fn evidence_pack_holds_no_row_data_and_no_connection_string() {
    let db = fixture_db(FIXTURE);
    let tmp = TempDir::new();
    let (out, dir) = report(&db.url, &tmp, &[]);
    assert_eq!(out.status.code(), Some(0));
    let mut outputs = all_files(&dir);
    outputs.push(("stdout".into(), String::from_utf8_lossy(&out.stdout).into()));
    outputs.push(("stderr".into(), String::from_utf8_lossy(&out.stderr).into()));
    assert!(outputs.len() > 3, "{outputs:?}");
    // Row values from the fixture, the password, and the connection string itself.
    let forbidden = [
        "Zelda",
        "Barnaby",
        "rowvalue.test",
        "SKU-XYZZY-9931",
        PASSWORD,
        db.url.as_str(),
        "password=",
    ];
    for (path, text) in &outputs {
        for word in forbidden {
            assert!(!text.contains(word), "{} contains {word}", path.display());
        }
    }
}

#[test]
fn outputs_say_audit_ready_evidence_never_compliant_or_passed() {
    let db = fixture_db(FIXTURE);
    let tmp = TempDir::new();
    let (out, dir) = report(&db.url, &tmp, &[]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let readiness = std::fs::read_to_string(dir.join("readiness.md")).unwrap();
    assert!(stdout.contains("audit-ready evidence"), "{stdout}");
    assert!(readiness.contains("audit-ready evidence"), "{readiness}");
    assert!(
        readiness.contains(
            "A broad role grant is any privilege on a personal-data table granted to a group role \
             (a role with at least one member), other than the table owner."
        ),
        "{readiness}"
    );
    assert!(
        readiness.contains(
            "Column-level grants are reported only when `SELECT` is granted to `PUBLIC`."
        ),
        "{readiness}"
    );
    let mut outputs = all_files(&dir);
    outputs.push(("stdout".into(), stdout));
    for (path, text) in &outputs {
        let lower = text.to_lowercase();
        for word in ["compliant", "passed"] {
            assert!(!lower.contains(word), "{} says {word}", path.display());
        }
    }
}

/// The default mapping with `deletion_path` lowered to medium severity.
const LOWERED_SEVERITY_MAPPING: &str = "
criteria:
  - { id: C1.2, title: Disposal of confidential information, verify_before_release: true }
checks:
  deletion_path: { severity: medium, criteria: [C1.2] }
";

#[test]
fn exit_code_is_two_only_when_a_finding_meets_the_fail_on_severity() {
    let db = fixture_db(FIXTURE);
    let tmp = TempDir::new();
    let mapping = tmp.0.join("mapping.yaml");
    std::fs::write(&mapping, LOWERED_SEVERITY_MAPPING).unwrap();
    let mapping = mapping.to_str().unwrap();

    // deletion_path is high in the default mapping.
    assert_eq!(
        report(&db.url, &tmp, &["--fail-on", "high"])
            .0
            .status
            .code(),
        Some(2)
    );
    assert_eq!(
        report(&db.url, &tmp, &["--fail-on", "low"]).0.status.code(),
        Some(2)
    );
    // Without --fail-on, findings never fail the run.
    assert_eq!(report(&db.url, &tmp, &[]).0.status.code(), Some(0));
    // Threshold above the finding's (lowered) severity: zero; at it: two.
    let above = ["--mapping", mapping, "--fail-on", "high"];
    assert_eq!(report(&db.url, &tmp, &above).0.status.code(), Some(0));
    let at = ["--mapping", mapping, "--fail-on", "medium"];
    assert_eq!(report(&db.url, &tmp, &at).0.status.code(), Some(2));
    // A bad threshold is a usage error, not a finding.
    assert_eq!(
        report(&db.url, &tmp, &["--fail-on", "urgent"])
            .0
            .status
            .code(),
        Some(1)
    );
}

#[test]
fn changing_the_mapping_file_changes_the_report() {
    let db = fixture_db(FIXTURE);
    let tmp = TempDir::new();
    let mapping = tmp.0.join("mapping.yaml");
    std::fs::write(
        &mapping,
        "
criteria:
  - { id: CC7.9, title: A criterion only this mapping has, verify_before_release: true }
checks:
  deletion_path: { severity: high, criteria: [CC7.9] }
",
    )
    .unwrap();
    let (out, dir) = report(&db.url, &tmp, &["--mapping", mapping.to_str().unwrap()]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let readiness = std::fs::read_to_string(dir.join("readiness.md")).unwrap();
    assert!(
        readiness.contains("CC7.9 A criterion only this mapping has"),
        "{readiness}"
    );
    assert!(!readiness.contains("C1.2"), "{readiness}");
    assert!(!dir.join("evidence/C1.2.json").exists());
    let evidence = read_json(&dir.join("evidence/CC7.9.json"));
    assert_eq!(evidence["items"][0]["check"], "deletion_path");
    assert_eq!(evidence["items"][0]["result"], "findings_open");
}

/// A mapping link can name the finding kinds it carries: other kinds of the
/// same check stay out of that criterion's evidence.
#[test]
fn a_mapping_link_can_carry_only_some_finding_kinds() {
    let db = fixture_db(FIXTURE);
    let tmp = TempDir::new();
    let mapping = tmp.0.join("mapping.yaml");
    std::fs::write(
        &mapping,
        "
criteria:
  - { id: X.1, title: Every deletion finding, verify_before_release: true }
  - { id: X.2, title: Soft deletes only, verify_before_release: true }
checks:
  deletion_path:
    severity: high
    criteria: [X.1, { id: X.2, kinds: [soft_delete_without_purge] }]
",
    )
    .unwrap();
    let (out, dir) = report(&db.url, &tmp, &["--mapping", mapping.to_str().unwrap()]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let all = read_json(&dir.join("evidence/X.1.json"));
    assert_eq!(all["items"][0]["result"], "findings_open");
    assert_eq!(all["items"][0]["findings"][0]["kind"], "no_deletion_path");
    let some = read_json(&dir.join("evidence/X.2.json"));
    assert_eq!(some["items"][0]["result"], "no_findings");
    assert_eq!(some["items"][0]["findings"], json!([]));

    std::fs::write(
        &mapping,
        "
criteria:
  - { id: X.1, title: T, verify_before_release: true }
checks:
  deletion_path: { severity: high, criteria: [{ id: X.1, kinds: [] }] }
",
    )
    .unwrap();
    let (out, _) = report(&db.url, &tmp, &["--mapping", mapping.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("empty kinds"));

    // A mistyped kind would make the criterion read clean: it is an error.
    for (links, error) in [
        (
            "[{ id: X.1, kinds: [no_deletion_paht] }]",
            "no finding kind no_deletion_paht",
        ),
        (
            "[{ id: X.1, kind: [no_deletion_path] }]",
            "{ id: <criterion>, kinds: [<finding kind>, ...] }",
        ),
        (
            "[X.1, { id: X.1, kinds: [no_deletion_path] }]",
            "maps to X.1 twice",
        ),
    ] {
        std::fs::write(
            &mapping,
            format!(
                "criteria:\n  - {{ id: X.1, title: T, verify_before_release: true }}\n\
                 checks:\n  deletion_path: {{ severity: high, criteria: {links} }}\n"
            ),
        )
        .unwrap();
        let (out, _) = report(&db.url, &tmp, &["--mapping", mapping.to_str().unwrap()]);
        assert_eq!(out.status.code(), Some(1), "{links}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains(error), "{links}: {stderr}");
    }
}

/// The shipped mapping sends recreation_risk to CC6.1 only for flows that
/// leave the database (points of access by outside entities), and uses the
/// TSC's own framing for the CC7.1 title.
#[test]
fn shipped_mapping_sends_only_outbound_flows_to_cc6_1() {
    let mapping =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/soc2-mapping.yaml")).unwrap();
    assert!(
        mapping.contains(
            "{ id: CC6.1, kinds: [subscription, foreign_table, export_trigger, supabase_functions] }"
        ),
        "{mapping}"
    );
    assert!(
        mapping
            .contains("title: Monitoring for configuration changes that introduce vulnerabilities"),
        "{mapping}"
    );
}

/// The shipped mapping sends only drift's grant mismatches to CC6.3.
#[test]
fn shipped_mapping_sends_only_grant_drift_to_cc6_3() {
    let mapping =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/soc2-mapping.yaml")).unwrap();
    assert!(
        mapping.contains("{ id: CC6.3, kinds: [grant_mismatch] }"),
        "{mapping}"
    );
}

#[test]
fn timestamp_defaults_to_the_utc_clock_in_rfc3339() {
    let db = fixture_db(FIXTURE);
    let tmp = TempDir::new();
    let dir = tmp.0.join("out");
    let out = Command::new(env!("CARGO_BIN_EXE_herculean"))
        .args(["report", "--out"])
        .arg(&dir)
        .env("HERCULEAN_DATABASE_URL", &db.url)
        .env_remove("HERCULEAN_NOW")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let today = Command::new("date")
        .args(["-u", "+%Y-%m-%dT"])
        .output()
        .unwrap();
    let today = String::from_utf8_lossy(&today.stdout).trim().to_string();
    let evidence = read_json(&dir.join("evidence/C1.2.json"));
    let ts = evidence["items"][0]["timestamp"].as_str().unwrap();
    assert!(
        ts.starts_with(&today) && ts.ends_with('Z') && ts.len() == 20,
        "{ts}"
    );
}

#[test]
fn a_symlinked_report_file_is_replaced_never_followed() {
    let db = fixture_db(FIXTURE);
    let tmp = TempDir::new();
    let target = tmp.0.join("bashrc");
    std::fs::write(&target, "original\n").unwrap();
    let out_dir = tmp.0.join("out");
    std::fs::create_dir_all(out_dir.join("evidence")).unwrap();
    for name in ["report.json", "readiness.md", "evidence/C1.2.json"] {
        std::os::unix::fs::symlink(&target, out_dir.join(name)).unwrap();
    }
    let (out, dir) = report(&db.url, &tmp, &[]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "original\n");
    for name in ["report.json", "readiness.md", "evidence/C1.2.json"] {
        let meta = std::fs::symlink_metadata(dir.join(name)).unwrap();
        assert!(meta.file_type().is_file(), "{name} is still a symlink");
    }
}

#[test]
fn a_symlinked_out_or_evidence_dir_is_refused() {
    let db = fixture_db(FIXTURE);
    let tmp = TempDir::new();
    let elsewhere = tmp.0.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::fs::create_dir_all(tmp.0.join("out")).unwrap();
    std::os::unix::fs::symlink(&elsewhere, tmp.0.join("out/evidence")).unwrap();
    let (out, _) = report(&db.url, &tmp, &[]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("symlink"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);

    let tmp = TempDir::new();
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, tmp.0.join("out")).unwrap();
    let (out, _) = report(&db.url, &tmp, &[]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
}

#[test]
fn a_symlinked_ancestor_of_out_is_refused_and_nothing_outside_is_touched() {
    let db = fixture_db(FIXTURE);
    let tmp = TempDir::new();
    let evidence = tmp.0.join("outside/x/evidence");
    std::fs::create_dir_all(&evidence).unwrap();
    std::fs::create_dir_all(tmp.0.join("repo")).unwrap();
    std::fs::write(evidence.join("keep.json"), "keep\n").unwrap();
    std::fs::write(evidence.join("C1.2.json"), "old\n").unwrap();
    std::os::unix::fs::symlink("../outside", tmp.0.join("repo/reports")).unwrap();
    let before = all_files(&tmp.0.join("outside"));

    // Relative and absolute spellings of the same out dir.
    for out_dir in [tmp.0.join("repo/reports/x"), "repo/reports/x".into()] {
        let out = report_to(&db.url, &tmp.0, &out_dir, &[]);
        assert_eq!(out.status.code(), Some(1), "{}", out_dir.display());
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("symlink"),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(all_files(&tmp.0.join("outside")), before);
    }
}

#[test]
fn an_unrelated_json_file_in_the_evidence_dir_survives_a_rerun() {
    let db = fixture_db(FIXTURE);
    let tmp = TempDir::new();
    let (out, dir) = report(&db.url, &tmp, &[]);
    assert_eq!(out.status.code(), Some(0));
    std::fs::write(dir.join("evidence/keep.json"), "keep\n").unwrap();
    let (out, dir) = report(&db.url, &tmp, &[]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        std::fs::read_to_string(dir.join("evidence/keep.json")).unwrap(),
        "keep\n"
    );
}

#[test]
fn a_rerun_with_another_mapping_leaves_only_its_criteria_files() {
    let db = fixture_db(FIXTURE);
    let tmp = TempDir::new();
    let (out, dir) = report(&db.url, &tmp, &[]);
    assert_eq!(out.status.code(), Some(0));
    assert!(dir.join("evidence/C1.2.json").exists());
    let mapping = tmp.0.join("mapping.yaml");
    std::fs::write(&mapping, LOWERED_SEVERITY_MAPPING).unwrap();
    let (out, dir) = report(&db.url, &tmp, &["--mapping", mapping.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0));
    let mut names: Vec<String> = std::fs::read_dir(dir.join("evidence"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, ["C1.2.json"]);
}

#[test]
fn a_criterion_id_that_is_not_a_plain_file_name_is_refused() {
    let db = fixture_db(FIXTURE);
    let tmp = TempDir::new();
    for id in ["../x", "..", ".", "a/b", "C 1"] {
        let mapping = tmp.0.join("mapping.yaml");
        std::fs::write(
            &mapping,
            format!(
                "criteria:\n  - {{ id: '{id}', title: T, verify_before_release: true }}\n\
                 checks:\n  deletion_path: {{ severity: high, criteria: ['{id}'] }}\n"
            ),
        )
        .unwrap();
        let (out, _) = report(&db.url, &tmp, &["--mapping", mapping.to_str().unwrap()]);
        assert_eq!(out.status.code(), Some(1), "{id}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("criterion id"),
            "{id}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    assert!(!tmp.0.join("x.json").exists());
}

const UNPARSED_NOTE: &str =
    "unparsed_sql: migrations/001_customers.sql: a statement could not be parsed and was skipped";

/// `herculean report --out <tmp>/<name> --repo <situation> <args>`, no database;
/// an absolute `situation` is used as is.
fn repo_report(situation: &str, tmp: &TempDir, name: &str, args: &[&str]) -> (Output, PathBuf) {
    let out_dir = tmp.0.join(name);
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/repos");
    let repo = fixtures.join(situation);
    let out = Command::new(env!("CARGO_BIN_EXE_herculean"))
        .args(["report", "--out"])
        .arg(&out_dir)
        .arg("--repo")
        .arg(repo)
        .args(args)
        .env_remove("HERCULEAN_DATABASE_URL")
        .env("HERCULEAN_NOW", NOW)
        .output()
        .expect("run herculean");
    (out, out_dir)
}

#[test]
fn an_unparsed_migration_shows_in_readiness_evidence_and_stdout() {
    let tmp = TempDir::new();
    let (out, dir) = repo_report("unparsable_statement", &tmp, "out", &[]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(UNPARSED_NOTE), "{stdout}");
    let readiness = std::fs::read_to_string(dir.join("readiness.md")).unwrap();
    assert!(readiness.contains(UNPARSED_NOTE), "{readiness}");
    // The incomplete input is a data_map finding, so it lands in C1.1's evidence.
    let evidence = read_json(&dir.join("evidence/C1.1.json"));
    assert_eq!(evidence["notes"], json!([UNPARSED_NOTE]));
    let item = &evidence["items"][0];
    assert_eq!(item["check"], "data_map");
    assert_eq!(item["result"], "findings_open");
    assert_eq!(
        item["findings"],
        json!([{
            "check": "data_map",
            "kind": "incomplete_input",
            "resource_id": "migrations/001_customers.sql",
            "steps": []
        }])
    );
}

/// A repo whose one migration, `<dir>/001.sql`, gets two notes:
/// `search_path_ignored`, then `unparsed_sql`.
fn two_note_repo(tmp: &TempDir, dir: &str) -> PathBuf {
    let repo = tmp.0.join("repo");
    std::fs::create_dir_all(repo.join(dir)).unwrap();
    std::fs::write(
        repo.join(dir).join("001.sql"),
        "SET search_path TO 'tenant';\nCREATE TABLE users (email text);\nTHIS IS NOT SQL AT ALL;\n",
    )
    .unwrap();
    repo
}

/// One source can carry several notes (one `incomplete_input` finding): all of
/// them are unread input, none an informational note.
#[test]
fn every_note_on_one_unread_source_is_unread_input() {
    let tmp = TempDir::new();
    let repo = two_note_repo(&tmp, "migrations");
    let (out, dir) = repo_report(repo.to_str().unwrap(), &tmp, "out", &[]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let evidence = read_json(&dir.join("evidence/C1.1.json"));
    let notes: Vec<&str> = evidence["notes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_str().unwrap())
        .collect();
    assert_eq!(notes.len(), 2, "{notes:?}");
    assert!(
        notes[0].starts_with("search_path_ignored: migrations/001.sql: "),
        "{notes:?}"
    );
    assert!(
        notes[1].starts_with("unparsed_sql: migrations/001.sql: "),
        "{notes:?}"
    );
    let readiness = std::fs::read_to_string(dir.join("readiness.md")).unwrap();
    assert!(!readiness.contains("\n## Notes\n"), "{readiness}");
}

/// Live path too; `sql/` is no default migrations dir, so an informational
/// `no_migrations_dir` note follows the unread ones and must stay informational.
#[test]
fn every_note_on_one_unread_source_is_unread_input_on_a_live_scan_too() {
    let db = fixture_db(FIXTURE);
    let tmp = TempDir::new();
    let repo = two_note_repo(&tmp, "sql");
    let (out, dir) = report(&db.url, &tmp, &["--repo", repo.to_str().unwrap()]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let evidence = read_json(&dir.join("evidence/C1.1.json"));
    let notes: Vec<&str> = evidence["notes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_str().unwrap())
        .collect();
    assert_eq!(notes.len(), 2, "{notes:?}");
    assert!(
        notes[0].starts_with("search_path_ignored: sql/001.sql: "),
        "{notes:?}"
    );
    assert!(
        notes[1].starts_with("unparsed_sql: sql/001.sql: "),
        "{notes:?}"
    );
    let readiness = std::fs::read_to_string(dir.join("readiness.md")).unwrap();
    let info = readiness.split("\n## Notes\n").nth(1).unwrap_or_default();
    assert!(info.starts_with("\n- no_migrations_dir: "), "{readiness}");
    assert!(!info.contains("sql/001.sql"), "{readiness}");
}

#[test]
fn incomplete_input_fails_at_every_threshold_but_only_with_fail_on() {
    // A repo whose only problem is a statement Herculean cannot parse.
    let tmp = TempDir::new();
    std::fs::create_dir_all(tmp.0.join("repo/migrations")).unwrap();
    std::fs::write(tmp.0.join("repo/migrations/001.sql"), "THIS IS NOT SQL;\n").unwrap();
    let repo = tmp.0.join("repo");
    for (level, code) in [("low", 2), ("medium", 2), ("high", 2)] {
        let (out, _) = repo_report(repo.to_str().unwrap(), &tmp, "out", &["--fail-on", level]);
        assert_eq!(out.status.code(), Some(code), "--fail-on {level}");
    }
    let (out, _) = repo_report(repo.to_str().unwrap(), &tmp, "out", &[]);
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn a_repo_only_report_says_not_run_instead_of_zero_findings() {
    let tmp = TempDir::new();
    let (out, _) = repo_report("unparsable_statement", &tmp, "out", &[]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = |id: &str| {
        stdout
            .lines()
            .find(|l| l.starts_with(&format!("{id} ")))
            .unwrap_or_else(|| panic!("no {id} line: {stdout}"))
            .to_string()
    };
    for id in ["CC6.3", "CC7.1", "CC8.1"] {
        assert!(line(id).contains(": not run,"), "{}", line(id));
    }
    // deletion_path ran, recreation_risk did not.
    assert!(line("C1.2").contains(": partly run,"), "{}", line("C1.2"));
    // data_map ran, least_privilege and recreation_risk did not.
    assert!(line("CC6.1").contains(": partly run,"), "{}", line("CC6.1"));
    assert!(
        line("C1.1").contains(": 1 open finding(s),"),
        "{}",
        line("C1.1")
    );
    assert!(!stdout.contains("0 open finding(s)"), "{stdout}");
}

#[test]
fn two_repo_only_reports_are_byte_identical() {
    let tmp = TempDir::new();
    let (first, a) = repo_report("unparsable_statement", &tmp, "a", &[]);
    let (second, b) = repo_report("unparsable_statement", &tmp, "b", &[]);
    assert_eq!(all_files(&a), all_files(&b));
    let strip = |out: &Output, dir: &Path| {
        String::from_utf8_lossy(&out.stdout).replace(&dir.display().to_string(), "<out>")
    };
    assert_eq!(strip(&first, &a), strip(&second, &b));
}

#[test]
fn an_unparsed_migration_makes_criteria_whose_checks_ran_partly_run() {
    // Every check runs (live database and a repo), but a migration statement
    // was skipped, so no criterion but data_map's may claim a full count.
    let db = fixture_db("on_delete_cascade_present");
    let tmp = TempDir::new();
    let repo =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/repos/unparsable_statement");
    let (out, _) = report(&db.url, &tmp, &["--repo", repo.to_str().unwrap()]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = |id: &str| {
        stdout
            .lines()
            .find(|l| l.starts_with(&format!("{id} ")))
            .unwrap_or_else(|| panic!("no {id} line: {stdout}"))
            .to_string()
    };
    for id in ["C1.2", "CC6.1", "CC6.3", "CC8.1"] {
        assert!(line(id).contains(": partly run,"), "{}", line(id));
    }
    assert!(
        line("C1.1").contains(" open finding(s),"),
        "{}",
        line("C1.1")
    );
}

/// The fenced `sh` block in `readiness.md`: the documented verify step.
fn verify_step(dir: &Path) -> String {
    let readiness = std::fs::read_to_string(dir.join("readiness.md")).unwrap();
    let start = readiness
        .find("```sh\n")
        .expect("a sh block in readiness.md")
        + 6;
    let len = readiness[start..].find("```").unwrap();
    readiness[start..start + len].to_string()
}

/// Runs the documented verify step in the pack directory: whether it succeeds.
fn verifies(dir: &Path, step: &str) -> bool {
    let out = Command::new("/bin/sh")
        .args(["-c", step])
        .current_dir(dir)
        .output()
        .unwrap();
    out.status.success()
}

#[test]
fn readiness_says_tamper_evidence_needs_the_pack_kept_outside_the_repo() {
    let tmp = TempDir::new();
    let (_, dir) = repo_report("unparsable_statement", &tmp, "out", &[]);
    let readiness = std::fs::read_to_string(dir.join("readiness.md")).unwrap();
    assert!(
        readiness.contains("store or sign this pack outside the repository"),
        "{readiness}"
    );
}

/// A note quotes repo names: a file name cannot forge a readiness heading or
/// an extra stdout line (stdout reaches an agent through MCP).
#[test]
fn a_file_name_with_a_newline_cannot_forge_report_lines() {
    let tmp = TempDir::new();
    std::fs::create_dir_all(tmp.0.join("repo/migrations")).unwrap();
    std::fs::write(
        tmp.0
            .join("repo/migrations/002\n## CC6.1 Logical access: no findings\n.sql"),
        "THIS IS NOT SQL;\n",
    )
    .unwrap();
    let repo = tmp.0.join("repo");
    let (out, dir) = repo_report(repo.to_str().unwrap(), &tmp, "out", &[]);
    assert_eq!(out.status.code(), Some(0));
    let forged = |text: &str| {
        text.lines()
            .any(|l| l.starts_with("## CC6.1 Logical access: no"))
    };
    let readiness = std::fs::read_to_string(dir.join("readiness.md")).unwrap();
    assert!(!forged(&readiness), "{readiness}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!forged(&stdout), "{stdout}");
    assert!(
        stdout.contains("note: unparsed_sql: <unprintable name>: "),
        "{stdout}"
    );
}

/// After `herculean fix` is applied, its migration line is only an
/// informational note: every check ran on fully read input, so each criterion
/// gives a count, not "partly run".
#[test]
fn an_applied_fix_leaves_every_criterion_with_a_count() {
    let fixture = "soft_delete_without_purge_with_pg_cron";
    let db = fixture_db(fixture);
    let tmp = TempDir::new();
    let repo = tmp.0.join("repo");
    std::fs::create_dir_all(repo.join("migrations")).unwrap();
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("tests/fixtures/{fixture}.sql")),
        repo.join("migrations/001_schema.sql"),
    )
    .unwrap();
    let fix = Command::new(env!("CARGO_BIN_EXE_herculean"))
        .args(["fix", "--finding"])
        .arg("deletion_path/soft_delete_without_purge/public.customers")
        .arg("--repo")
        .arg(&repo)
        .args(["--retention-days", "30"])
        .env("HERCULEAN_DATABASE_URL", &db.url)
        .env("HERCULEAN_NOW", NOW)
        .output()
        .unwrap();
    assert!(
        fix.status.success(),
        "{}",
        String::from_utf8_lossy(&fix.stderr)
    );
    let path: Value = serde_json::from_slice(&fix.stdout).unwrap();
    common::admin_sql(
        &db.name,
        &std::fs::read_to_string(repo.join(path["path"].as_str().unwrap())).unwrap(),
    );
    let (out, dir) = report(&db.url, &tmp, &["--repo", repo.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("note: migration_deleter_not_counted: "),
        "{stdout}"
    );
    let criteria: Vec<&str> = stdout.lines().filter(|l| l.contains("evidence/")).collect();
    assert!(!criteria.is_empty(), "{stdout}");
    for line in criteria {
        assert!(line.contains(" open finding(s), "), "{line}");
    }
    let readiness = std::fs::read_to_string(dir.join("readiness.md")).unwrap();
    assert!(!readiness.contains("Input not fully read"), "{readiness}");
    assert!(!readiness.contains("partly run"), "{readiness}");
    assert!(
        readiness.contains("migration_deleter_not_counted: "),
        "{readiness}"
    );
}

#[test]
fn editing_any_evidence_field_fails_the_documented_verify_step() {
    let db = fixture_db(FIXTURE);
    let tmp = TempDir::new();
    let (out, dir) = report(&db.url, &tmp, &[]);
    assert_eq!(out.status.code(), Some(0));
    let step = verify_step(&dir);
    assert!(verifies(&dir, &step), "fresh pack does not verify:\n{step}");

    let path = dir.join("evidence/C1.2.json");
    let original = std::fs::read_to_string(&path).unwrap();
    // (JSON pointer into the item, new value)
    let edits = [
        ("/result", json!("no_findings")),
        ("/timestamp", json!("2020-01-01T00:00:00Z")),
        ("/herculean_version", json!("9.9.9")),
        ("/findings", json!([])),
        ("/notes", json!(["edited"])),
        ("/skipped_checks", json!([])),
        ("/provenance/catalog_sha256", json!("0".repeat(64))),
        ("/envelope_version", json!(2)),
    ];
    for (what, value) in edits {
        let mut evidence: Value = serde_json::from_str(&original).unwrap();
        let item = evidence["items"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|i| i["check"] == "deletion_path")
            .unwrap();
        *item.pointer_mut(what).unwrap() = value;
        std::fs::write(&path, serde_json::to_string_pretty(&evidence).unwrap()).unwrap();
        assert!(!verifies(&dir, &step), "editing {what} still verifies");
    }
    std::fs::write(&path, &original).unwrap();
    assert!(verifies(&dir, &step));

    // The items name the data map's digest, so report.json's data map is bound too.
    let report_path = dir.join("report.json");
    let mut scan = read_json(&report_path);
    scan["data_map"]["stores"] = json!([]);
    std::fs::write(&report_path, scan.to_string()).unwrap();
    assert!(
        !verifies(&dir, &step),
        "editing the data map still verifies"
    );
}

#[test]
fn a_corrupt_emptied_or_missing_evidence_file_fails_the_documented_verify_step() {
    let db = fixture_db(FIXTURE);
    let tmp = TempDir::new();
    let (out, dir) = report(&db.url, &tmp, &[]);
    assert_eq!(out.status.code(), Some(0));
    let step = verify_step(&dir);
    let path = dir.join("evidence/C1.2.json");
    let original = std::fs::read_to_string(&path).unwrap();
    for corrupt in ["not json", "{}", r#"{"items": []}"#, r#"{"items": null}"#] {
        std::fs::write(&path, corrupt).unwrap();
        assert!(!verifies(&dir, &step), "{corrupt} still verifies");
    }
    std::fs::write(&path, &original).unwrap();
    assert!(verifies(&dir, &step));

    std::fs::remove_dir_all(dir.join("evidence")).unwrap();
    std::fs::create_dir(dir.join("evidence")).unwrap();
    assert!(
        !verifies(&dir, &step),
        "an empty evidence dir still verifies"
    );
}

/// The step carries the expected evidence files: dropping a file, or an item
/// from one, fails it even though every remaining item still hashes right.
#[test]
fn a_deleted_evidence_file_or_item_fails_the_documented_verify_step() {
    let tmp = TempDir::new();
    let (out, dir) = repo_report("unparsable_statement", &tmp, "out", &[]);
    assert_eq!(out.status.code(), Some(0));
    let step = verify_step(&dir);
    assert!(verifies(&dir, &step), "untouched pack does not verify");

    let path = dir.join("evidence/C1.2.json");
    let original = std::fs::read_to_string(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    assert!(
        !verifies(&dir, &step),
        "a deleted evidence file still verifies"
    );

    let mut evidence: serde_json::Value = serde_json::from_str(&original).unwrap();
    let items = evidence["items"].as_array_mut().unwrap();
    assert!(items.len() > 1, "C1.2 needs several items: {original}");
    items.pop();
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&evidence).unwrap() + "\n",
    )
    .unwrap();
    assert!(
        !verifies(&dir, &step),
        "a dropped evidence item still verifies"
    );

    std::fs::write(&path, &original).unwrap();
    assert!(verifies(&dir, &step));
}

#[test]
fn a_criterion_no_check_maps_to_is_refused() {
    let db = fixture_db(FIXTURE);
    let tmp = TempDir::new();
    let mapping = tmp.0.join("mapping.yaml");
    std::fs::write(
        &mapping,
        "criteria:\n  - { id: C1, title: T, verify_before_release: true }\n\
         \x20 - { id: C2, title: T, verify_before_release: true }\n\
         checks:\n  deletion_path: { severity: high, criteria: [C1] }\n",
    )
    .unwrap();
    let (out, _) = report(&db.url, &tmp, &["--mapping", mapping.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("criterion C2 has no check"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn not_run_and_no_findings_on_the_same_data_map_hash_differently() {
    let db = fixture_db("migration_live_schema_match");
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/repos/migration_live_schema_match");
    let tmp = TempDir::new();
    let drift_item = |name: &str, args: &[&str]| {
        let dir = tmp.0.join(name);
        let out = report_to(&db.url, &tmp.0, &dir, args);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        read_json(&dir.join("evidence/CC8.1.json"))["items"][0].clone()
    };
    let not_run = drift_item("live", &[]);
    let no_findings = drift_item("with_repo", &["--repo", repo.to_str().unwrap()]);
    assert_eq!(not_run["result"], "not_run");
    assert_eq!(no_findings["result"], "no_findings");
    assert_eq!(
        not_run["provenance"]["data_map_sha256"],
        no_findings["provenance"]["data_map_sha256"]
    );
    assert_ne!(not_run["sha256"], no_findings["sha256"]);
}

#[test]
fn the_catalog_digest_follows_the_catalog_never_row_values_or_command_text() {
    let db = fixture_db("pg_cron_purge_present");
    admin_sql(
        &db.name,
        "INSERT INTO customers (email) VALUES ('zelda@rowvalue.test')",
    );
    let tmp = TempDir::new();
    let run = |name: &str| {
        let dir = tmp.0.join(name);
        let out = report_to(&db.url, &tmp.0, &dir, &["--sample"]);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let item = &read_json(&dir.join("evidence/C1.2.json"))["items"][0];
        let digest = item["provenance"]["catalog_sha256"]
            .as_str()
            .unwrap()
            .to_string();
        (dir, digest)
    };
    let (first_dir, first) = run("first");
    // Row values are sampled but never digested.
    admin_sql(
        &db.name,
        "UPDATE customers SET email = 'barnaby@rowvalue.test'",
    );
    let (_, after_update) = run("after_update");
    assert_eq!(first, after_update);
    // Command text (a job's, a trigger function's) is left out: it may hold secrets.
    admin_sql(
        &db.name,
        "UPDATE cron.job SET command = 'DELETE FROM public.customers WHERE deleted_at < now()'",
    );
    assert_eq!(first, run("after_cron_edit").1);
    admin_sql(
        &db.name,
        "CREATE FUNCTION f() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END'; \
         CREATE TRIGGER t BEFORE INSERT ON customers FOR EACH ROW EXECUTE FUNCTION f()",
    );
    let (_, before_edit) = run("before_edit");
    admin_sql(
        &db.name,
        "CREATE OR REPLACE FUNCTION f() RETURNS trigger LANGUAGE plpgsql \
         AS 'BEGIN /* key=s3cr3t */ RETURN NEW; END'",
    );
    let (_, after_edit) = run("after_edit");
    assert_eq!(before_edit, after_edit);
    assert_ne!(first, before_edit, "a new trigger is a catalog change");
    admin_sql(&db.name, "ALTER TABLE customers ADD COLUMN nickname text");
    let (_, after_alter) = run("after_alter");
    assert_ne!(first, after_alter);

    for (path, text) in all_files(&first_dir) {
        for word in [
            "DELETE FROM",
            "interval",
            "zelda",
            "barnaby",
            "rowvalue.test",
        ] {
            assert!(!text.contains(word), "{} contains {word}", path.display());
        }
    }
}

#[test]
fn a_repo_report_names_the_repo_head_commit() {
    let tmp = TempDir::new();
    let repo = tmp.0.join("repo");
    std::fs::create_dir_all(repo.join("migrations")).unwrap();
    std::fs::write(
        repo.join("migrations/001.sql"),
        "CREATE TABLE customers (email text NOT NULL);\n",
    )
    .unwrap();
    let head = |name: &str| {
        let (out, dir) = repo_report(repo.to_str().unwrap(), &tmp, name, &[]);
        assert_eq!(out.status.code(), Some(0));
        let item = read_json(&dir.join("evidence/C1.2.json"))["items"][0].clone();
        assert_eq!(item["provenance"]["catalog_sha256"], Value::Null);
        item["provenance"]["repo_head"].clone()
    };
    // Not a git repository: no commit to name.
    assert_eq!(head("before_git"), Value::Null);
    let git = |args: &[&str]| {
        let out = Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(["-c", "user.name=t", "-c", "user.email=t@example.test"])
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    };
    git(&["init", "-q"]);
    git(&["add", "."]);
    git(&["commit", "-q", "-m", "schema"]);
    assert_eq!(head("after_commit"), json!(git(&["rev-parse", "HEAD"])));
}

/// `HERCULEAN_NOW` pins the clock for tests; a release build ignores it.
/// CI also runs this test with `--release`.
#[test]
fn herculean_now_pins_the_clock_only_in_debug_builds() {
    let tmp = TempDir::new();
    let (out, dir) = repo_report("unparsable_statement", &tmp, "out", &[]);
    assert_eq!(out.status.code(), Some(0));
    let evidence = read_json(&dir.join("evidence/C1.1.json"));
    let ts = evidence["items"][0]["timestamp"].as_str().unwrap();
    assert_eq!(ts == NOW, cfg!(debug_assertions), "{ts}");
}

/// readiness.md and the evidence files say "not run" / "partly run" as
/// stdout does, instead of a bare 0.
#[test]
fn readiness_and_evidence_mark_checks_not_run_or_partly_run() {
    let tmp = TempDir::new();
    let (_, dir) = repo_report("unparsable_statement", &tmp, "out", &[]);
    let readiness = std::fs::read_to_string(dir.join("readiness.md")).unwrap();
    let section = |id: &str| {
        let start = readiness.find(&format!("\n## {id} ")).unwrap();
        let rest = &readiness[start + 1..];
        rest[..rest[1..].find("\n## ").map_or(rest.len(), |e| e + 1)].to_string()
    };
    let cc71 = section("CC7.1");
    assert!(cc71.contains("\nStatus: not run\n"), "{cc71}");
    assert!(cc71.contains("| least_privilege | not_run | - |"), "{cc71}");
    assert!(cc71.contains("| drift | not_run | - |"), "{cc71}");
    let c12 = section("C1.2");
    assert!(c12.contains("\nStatus: partly run\n"), "{c12}");
    assert!(
        c12.contains("| deletion_path | no_findings (partly run) | 0 |")
            || c12.contains("| deletion_path | findings_open (partly run) |"),
        "{c12}"
    );
    assert!(c12.contains("| recreation_risk | not_run | - |"), "{c12}");
    assert!(section("C1.1").contains("\nStatus: 1 open finding(s)\n"));
    assert_eq!(
        read_json(&dir.join("evidence/CC7.1.json"))["status"],
        "not run"
    );
    assert_eq!(
        read_json(&dir.join("evidence/C1.2.json"))["status"],
        "partly run"
    );
}

/// The verify banner names every criterion not yet verified against the
/// AICPA TSC, and is gone once a qualified human has verified them all.
#[test]
fn the_verify_banner_names_unverified_criteria_until_all_are_verified() {
    let tmp = TempDir::new();
    let mapping = tmp.0.join("mapping.yaml");
    let run = |b_unverified: bool| {
        std::fs::write(
            &mapping,
            format!(
                "criteria:\n  - {{ id: A1, title: Verified, verify_before_release: false }}\n\
                 \x20 - {{ id: B2, title: Pending, verify_before_release: {b_unverified} }}\n\
                 checks:\n  data_map: {{ severity: low, criteria: [A1] }}\n\
                 \x20 deletion_path: {{ severity: high, criteria: [B2] }}\n"
            ),
        )
        .unwrap();
        let args = ["--mapping", mapping.to_str().unwrap()];
        let (out, dir) = repo_report("unparsable_statement", &tmp, "out", &args);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        std::fs::read_to_string(dir.join("readiness.md")).unwrap()
    };

    let one_pending = run(true);
    assert!(
        one_pending.contains(
            "Criterion IDs, titles and the checks mapped to each must be verified against the \
             AICPA Trust Services Criteria before release. Not yet verified: B2.\n"
        ),
        "{one_pending}"
    );
    assert!(
        one_pending.contains("\n## B2 Pending (verify against the AICPA TSC before release)\n"),
        "{one_pending}"
    );
    assert!(one_pending.contains("\n## A1 Verified\n"), "{one_pending}");

    // Neither the banner nor any heading's note is left.
    let all_verified = run(false);
    assert!(!all_verified.contains("AICPA"), "{all_verified}");
    assert!(all_verified.contains("\n## B2 Pending\n"), "{all_verified}");
}

/// Secure disposal of personal information (P4.3) gets its evidence from both
/// disposal checks, like disposal of confidential information (C1.2).
#[test]
fn the_shipped_mapping_maps_p4_3_to_both_disposal_checks() {
    let tmp = TempDir::new();
    let (out, dir) = repo_report("unparsable_statement", &tmp, "out", &[]);
    assert_eq!(out.status.code(), Some(0));
    let evidence = read_json(&dir.join("evidence/P4.3.json"));
    assert_eq!(evidence["criterion"], "P4.3");
    let checks: Vec<&Value> = evidence["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| &i["check"])
        .collect();
    assert_eq!(checks, ["deletion_path", "recreation_risk"]);
}

/// `report.json` has always been written with sorted keys (through a
/// `serde_json::Value`); typing the report must not reorder them.
#[test]
fn report_json_keeps_its_sorted_key_order() {
    let tmp = TempDir::new();
    let (out, dir) = repo_report("column_name_tokens", &tmp, "out", &[]);
    assert_eq!(out.status.code(), Some(0));
    let text = std::fs::read_to_string(dir.join("report.json")).unwrap();
    let sorted: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(text, serde_json::to_string_pretty(&sorted).unwrap() + "\n");
}

/// readiness.md says which mapping produced it: a custom `--mapping` can clear
/// the verify banner, so the pack must show it was not the shipped mapping.
#[test]
fn readiness_names_the_mapping_it_was_written_with() {
    let tmp = TempDir::new();
    let (out, dir) = repo_report("unparsable_statement", &tmp, "builtin", &[]);
    assert_eq!(out.status.code(), Some(0));
    let readiness = std::fs::read_to_string(dir.join("readiness.md")).unwrap();
    assert!(
        readiness.contains("\nSOC 2 mapping: built-in (sha256 "),
        "{readiness}"
    );

    let mapping = tmp.0.join("mapping.yaml");
    std::fs::write(
        &mapping,
        "criteria:\n  - { id: X1, title: Verified elsewhere, verify_before_release: false }\n\
         checks:\n  data_map: { severity: low, criteria: [X1] }\n  \
         deletion_path: { severity: high, criteria: [X1] }\n",
    )
    .unwrap();
    let (out, dir) = repo_report(
        "unparsable_statement",
        &tmp,
        "custom",
        &["--mapping", mapping.to_str().unwrap()],
    );
    assert_eq!(out.status.code(), Some(0));
    let readiness = std::fs::read_to_string(dir.join("readiness.md")).unwrap();
    assert!(
        readiness.contains("\nSOC 2 mapping: custom file, sha256 ")
            && readiness.contains("; not the mapping shipped with this release.\n"),
        "{readiness}"
    );
    assert!(!readiness.contains("built-in"), "{readiness}");
}
