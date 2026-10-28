mod common;

use common::{
    fixture_db, logged_statements, no_repo, postgres_url, scan, server_cert, stdout_json,
    unrelated_cert, TempDir, PASSWORD,
};
use serde_json::json;

const FIXTURE: &str = "personal_table_without_deletion_path";

#[test]
fn personal_table_without_deletion_path_yields_one_delete_finding() {
    let db = fixture_db(FIXTURE);
    let report = stdout_json(&scan(Some(&db.url)));
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
                "steps": [
                    { "step_no": 1, "phase": "FINDING", "system_id": db.name, "resource_id": "public.customers",
                      "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": "pg_class:public.customers" },
                    { "step_no": 2, "phase": "REMEDIATION", "system_id": db.name, "resource_id": "public.customers",
                      "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": "" },
                    { "step_no": 3, "phase": "VERIFICATION", "system_id": db.name, "resource_id": "public.customers",
                      "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": "" }
                ]
            }],
            "skipped_checks": no_repo()
        })
    );
}

#[test]
fn read_only_role_from_published_grant_list_is_enough() {
    // fixture_db grants the reader exactly read-only-role.sql, after revoking PUBLIC's CONNECT/TEMP.
    let db = fixture_db(FIXTURE);
    let report = stdout_json(&scan(Some(&db.url)));
    assert_eq!(report["findings"].as_array().unwrap().len(), 1);
}

#[test]
fn scan_never_queries_user_tables() {
    let db = fixture_db(FIXTURE);
    stdout_json(&scan(Some(&db.url)));
    let statements = logged_statements(&db.reader, &db.name);
    assert!(
        statements.iter().any(|s| s.contains("pg_catalog")),
        "expected the reader's catalog queries in the statement log, got {statements:#?}"
    );
    for s in &statements {
        assert!(
            !s.contains("customers") && !s.contains("products"),
            "reader statement touched a user table: {s}"
        );
    }
}

#[test]
fn no_row_value_appears_in_output() {
    let db = fixture_db(FIXTURE);
    let out = scan(Some(&db.url));
    stdout_json(&out);
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    for value in [
        "zelda",
        "Zelda Quixote",
        "rowvalue.test",
        "Barnaby",
        "SKU-XYZZY-9931",
        "12.34",
    ] {
        assert!(!all.contains(value), "row value {value:?} leaked");
    }
}

#[test]
fn connection_string_never_appears_in_output() {
    let db = fixture_db(FIXTURE);
    let ok = scan(Some(&db.url));
    assert!(ok.status.success());
    let wrong_password = "Wrong-Pw-Kx9-should-not-echo";
    let bad_url = db.url.replace(PASSWORD, wrong_password);
    let failed = scan(Some(&bad_url));
    assert!(!failed.status.success(), "wrong password must fail");
    for out in [&ok, &failed] {
        let all = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        for secret in [PASSWORD, wrong_password, &db.url, &bad_url] {
            assert!(!all.contains(secret), "secret leaked in {all:?}");
        }
    }
}

#[test]
fn missing_connection_env_var_names_the_variable() {
    let out = scan(None);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("HERCULEAN_DATABASE_URL"));
}

#[test]
fn two_runs_give_byte_identical_reports() {
    let db = fixture_db(FIXTURE);
    let first = scan(Some(&db.url));
    let second = scan(Some(&db.url));
    assert!(first.status.success());
    assert!(!first.stdout.is_empty());
    assert_eq!(first.stdout, second.stdout);
}

/// Whether the server logged the reader's (last) connection to `db` as TLS.
fn connected_with_tls(db: &common::Db) -> bool {
    logged_statements(&db.reader, &db.name)
        .iter()
        .rev()
        .find(|e| e.contains("connection authorized"))
        .expect("connection logged")
        .contains("SSL enabled")
}

#[test]
fn sslmode_is_honoured_like_libpq() {
    // The default (prefer) and require encrypt; neither verifies the certificate.
    for mode in ["", " sslmode=prefer", " sslmode=require"] {
        let db = fixture_db(FIXTURE);
        let out = scan(Some(&format!("{}{mode}", db.tcp_url)));
        assert_eq!(
            out.status.code(),
            Some(0),
            "{mode}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(connected_with_tls(&db), "{mode}: not encrypted");
    }
    let db = fixture_db(FIXTURE);
    let out = scan(Some(&format!("{} sslmode=disable", db.tcp_url)));
    assert_eq!(out.status.code(), Some(0));
    assert!(!connected_with_tls(&db));
    // Over the unix socket the server offers no TLS: prefer falls back, require fails.
    assert_eq!(scan(Some(&db.url)).status.code(), Some(0));
}

#[test]
fn a_tls_requirement_that_cannot_be_met_fails_with_a_static_message() {
    let db = fixture_db(FIXTURE);
    // No TLS on the unix socket; a self-signed certificate is not in the verified roots.
    for url in [
        format!("{} sslmode=require", db.url),
        format!("{} sslmode=verify-full", db.tcp_url),
        postgres_url(&db, "sslmode=verify-full"),
    ] {
        let out = scan(Some(&url));
        assert_eq!(out.status.code(), Some(1), "{url}");
        assert_eq!(
            String::from_utf8_lossy(&out.stderr),
            "herculean: connecting to the database failed\n"
        );
        assert!(out.stdout.is_empty());
    }
}

#[test]
fn verify_modes_check_the_server_certificate_against_sslrootcert() {
    // A path with a space: quoted in key=value form, percent-encoded in a URL.
    let dir = TempDir::new();
    let ca = dir.0.join("ca dir").join("root.pem");
    std::fs::create_dir_all(ca.parent().unwrap()).unwrap();
    std::fs::copy(server_cert(), &ca).unwrap();
    let ca = ca.display().to_string();
    for mode in ["verify-full", "verify-ca", "require"] {
        let db = fixture_db(FIXTURE);
        for url in [
            format!("{} sslmode={mode} sslrootcert='{ca}'", db.tcp_url),
            postgres_url(
                &db,
                &format!("sslrootcert={}&sslmode={mode}", ca.replace(' ', "%20")),
            ),
        ] {
            let out = scan(Some(&url));
            assert_eq!(
                out.status.code(),
                Some(0),
                "{url}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert!(connected_with_tls(&db), "{url}: not encrypted");
        }
    }
}

#[test]
fn verify_ca_skips_the_hostname_check_and_verify_full_does_not() {
    let db = fixture_db(FIXTURE);
    // Connects to 127.0.0.1 but expects a name the certificate does not carry.
    let url = db
        .tcp_url
        .replace("host=127.0.0.1", "host=db.invalid hostaddr=127.0.0.1");
    let ca = server_cert().display().to_string();
    let out = scan(Some(&format!("{url} sslmode=verify-ca sslrootcert={ca}")));
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = scan(Some(&format!("{url} sslmode=verify-full sslrootcert={ca}")));
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "herculean: connecting to the database failed\n"
    );
}

#[test]
fn a_root_that_did_not_sign_the_server_certificate_is_rejected() {
    let dir = TempDir::new();
    let other = dir.0.join("other.pem");
    unrelated_cert(&other);
    let db = fixture_db(FIXTURE);
    // require with sslrootcert verifies the chain, as libpq does.
    for mode in ["verify-full", "verify-ca", "require"] {
        let out = scan(Some(&format!(
            "{} sslmode={mode} sslrootcert={}",
            db.tcp_url,
            other.display()
        )));
        assert_eq!(out.status.code(), Some(1), "{mode}");
        assert_eq!(
            String::from_utf8_lossy(&out.stderr),
            "herculean: connecting to the database failed\n"
        );
    }
}

#[test]
fn a_missing_sslrootcert_file_fails_with_a_static_message() {
    let db = fixture_db(FIXTURE);
    let missing = "/nonexistent-herculean/root.pem";
    for url in [
        format!("{} sslmode=verify-full sslrootcert={missing}", db.tcp_url),
        postgres_url(&db, &format!("sslmode=verify-ca&sslrootcert={missing}")),
    ] {
        let out = scan(Some(&url));
        assert_eq!(out.status.code(), Some(1), "{url}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(stderr, "herculean: cannot read the sslrootcert file\n");
        assert!(out.stdout.is_empty());
    }
}

/// A listener on 127.0.0.1 that refuses TLS (answers the SSLRequest with `N`);
/// its handle yields whether a client then sent a startup message in plaintext.
fn tls_refusing_listener() -> (u16, std::thread::JoinHandle<bool>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let handle = std::thread::spawn(move || {
        // A client that never connects would make the plaintext check vacuous.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut conn = loop {
            match listener.accept() {
                Ok((conn, _)) => break conn,
                Err(_) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(20))
                }
                Err(e) => panic!("no client connected: {e}"),
            }
        };
        conn.set_nonblocking(false).unwrap();
        conn.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        let mut request = [0u8; 8];
        conn.read_exact(&mut request).unwrap();
        assert_eq!(request, [0, 0, 0, 8, 4, 210, 22, 47], "not an SSLRequest");
        conn.write_all(b"N").unwrap();
        conn.read(&mut [0u8; 64]).unwrap_or(0) > 0
    });
    (port, handle)
}

#[test]
fn require_is_never_weakened_however_the_url_spells_it() {
    for url in [
        // tokio-postgres decodes the key: sslmode=require.
        "postgres://u:p@127.0.0.1:{port}/db?ssl%6Dode=require".to_string(),
        // An `@` in the query, no credentials.
        "postgres://h/db?sslmode=require&application_name=a@127.0.0.1:{port}".to_string(),
        // No path: the query starts right after the port, and an `@` in it is not a credential.
        "postgres://u:p@127.0.0.1:{port}?sslmode=require&application_name=svc@prod".to_string(),
        "postgres://u:p@127.0.0.1:{port}?sslmode=require&application_name=a@b?sslmode=disable"
            .to_string(),
        // tokio-postgres reads credentials up to the first `@`, so it sees a second
        // sslmode=require that the split (which stops at the query) takes for a value:
        // only the floor keeps the first, `disable`, from winning.
        "postgres://h?sslmode=disable&application_name=a@127.0.0.1:{port}/db?sslmode=require"
            .to_string(),
        "POSTGRESQL://u:p@127.0.0.1:{port}/db?sslmode=require".to_string(),
    ] {
        let (port, plaintext) = tls_refusing_listener();
        let url = url.replace("{port}", &port.to_string());
        let out = scan(Some(&url));
        assert_eq!(out.status.code(), Some(1), "{url}");
        assert!(
            !plaintext.join().unwrap(),
            "{url}: startup sent in plaintext"
        );
    }
}

#[test]
fn a_pathless_url_with_an_at_in_the_query_still_verifies_the_server() {
    let db = fixture_db(FIXTURE);
    let ca = server_cert().display().to_string();
    // No path, so the database comes from `dbname`; the `@` is in the query.
    let url = postgres_url(
        &db,
        &format!("application_name=a@b&sslmode=verify-full&sslrootcert={ca}"),
    )
    .replace(&format!("/{}?", db.name), &format!("?dbname={}&", db.name));
    assert!(!url.contains("/?") && url.contains("?dbname="), "{url}");
    let out = scan(Some(&url));
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(connected_with_tls(&db));
}

#[test]
fn a_key_value_password_with_quotes_spaces_and_escapes_round_trips() {
    let db = fixture_db(FIXTURE);
    common::admin_sql(
        &db.name,
        &format!("ALTER ROLE {} PASSWORD 'a b''c\\d=e'", db.reader),
    );
    let url = db
        .url
        .replace(&format!("password={PASSWORD}"), "password='a b\\'c\\\\d=e'");
    let out = scan(Some(&url));
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn verify_full_accepts_a_dns_name_in_the_certificate() {
    let db = fixture_db(FIXTURE);
    let url = db.tcp_url.replace("host=127.0.0.1", "host=localhost");
    let ca = server_cert().display().to_string();
    let out = scan(Some(&format!("{url} sslmode=verify-full sslrootcert={ca}")));
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(connected_with_tls(&db));
}

#[test]
fn the_session_is_made_read_only_before_any_query() {
    let db = fixture_db(FIXTURE);
    stdout_json(&scan(Some(&db.url)));
    let statements: Vec<String> = logged_statements(&db.reader, &db.name)
        .into_iter()
        .filter(|s| s.contains("LOG:  statement: ") || s.contains("LOG:  execute "))
        .collect();
    assert!(
        statements[0].ends_with("LOG:  statement: SET default_transaction_read_only = on"),
        "{statements:#?}"
    );
}

/// The digest covers catalog rows; version() changes on a patch upgrade, so it
/// is read on its own and never as part of a catalog query.
#[test]
fn the_server_version_is_never_read_with_the_catalog() {
    let db = fixture_db(FIXTURE);
    stdout_json(&scan(Some(&db.url)));
    for s in logged_statements(&db.reader, &db.name) {
        assert!(
            !(s.contains("version()") && s.contains("FROM pg_catalog.")),
            "{s}"
        );
    }
}

#[test]
fn the_reader_role_is_read_only_at_every_login_so_poolers_cannot_drop_it() {
    let db = fixture_db(FIXTURE);
    let mut client = postgres::Client::connect(&db.url, postgres::NoTls).unwrap();
    let row = client
        .query_one("SHOW default_transaction_read_only", &[])
        .unwrap();
    assert_eq!(row.get::<_, &str>(0), "on");
}

#[test]
fn the_supabase_transaction_pooler_is_refused_before_connecting() {
    let out = scan(Some(
        "postgres://u:p@aws-0-us-east-1.pooler.supabase.com:6543/postgres",
    ));
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr).trim(),
        "herculean: Supabase transaction pooler (port 6543) drops session settings; \
         use the session pooler on port 5432"
    );
}
