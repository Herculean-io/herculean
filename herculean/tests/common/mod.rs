//! Test harness: one disposable Postgres cluster per test process, one database per test.
#![allow(dead_code)] // each test binary uses a different subset of helpers

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;

pub const PASSWORD: &str = "Pw-Hq7Zt-distinctive-secret";

pub struct Cluster {
    /// Holds the unix socket and the statement log; the data dir lives inside it.
    pub dir: PathBuf,
    bin: PathBuf,
    as_postgres_user: bool,
    /// The server port: its unix socket's name, and TCP (TLS) on 127.0.0.1.
    port: u16,
}

pub struct Db {
    pub name: String,
    pub reader: String,
    /// Over the unix socket (no TLS there).
    pub url: String,
    /// Over TCP to 127.0.0.1, where the server offers TLS with a self-signed certificate.
    pub tcp_url: String,
    cluster: &'static Cluster,
}

impl Db {
    /// Runs `sql` on database `db` of this database's cluster, as the superuser.
    pub fn admin(&self, db: &str, sql: &str) {
        run(self.cluster.psql(db).args(["-c", sql]));
    }
}

fn cluster() -> &'static Cluster {
    static CLUSTER: OnceLock<Cluster> = OnceLock::new();
    CLUSTER.get_or_init(|| Cluster::start("main", ""))
}

/// A cluster with pg_cron preloaded, keeping its jobs in `cron_database`
/// ("postgres", its default, or "crondb"). Needs pg_cron built for `bin_dir()`.
fn cron_cluster(cron_database: &'static str) -> &'static Cluster {
    static CLUSTERS: [OnceLock<Cluster>; 2] = [OnceLock::new(), OnceLock::new()];
    CLUSTERS[(cron_database != "postgres") as usize].get_or_init(|| {
        let c = Cluster::start(
            cron_database,
            &format!(
                "shared_preload_libraries = 'pg_cron'\ncron.database_name = '{cron_database}'\n"
            ),
        );
        if cron_database != "postgres" {
            run(c
                .psql("postgres")
                .args(["-c", &format!("CREATE DATABASE {cron_database}")]));
        }
        run(c
            .psql(cron_database)
            .args(["-c", "CREATE EXTENSION pg_cron"]));
        c
    })
}

fn run(cmd: &mut Command) -> Output {
    let out = cmd.output().expect("spawn");
    assert!(
        out.status.success(),
        "{cmd:?} failed:\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn bin_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("HERCULEAN_PG_BIN") {
        return dir.into();
    }
    if let Ok(out) = Command::new("pg_config").arg("--bindir").output() {
        let dir = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim());
        if dir.join("initdb").exists() {
            return dir;
        }
    }
    "/usr/lib/postgresql/16/bin".into()
}

impl Cluster {
    /// `tag` names the cluster's temp dir; `conf` is appended to postgresql.conf.
    fn start(tag: &str, conf_extra: &str) -> Cluster {
        let dir = std::env::temp_dir().join(format!("herculean-pg-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // initdb/postgres refuse to run as root; run them as the `postgres` OS user then.
        let uid = run(Command::new("id").arg("-u")).stdout;
        let as_postgres_user = String::from_utf8_lossy(&uid).trim() == "0";
        if as_postgres_user {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        }
        // ponytail: a free port picked then released; a race with another process is retried by nobody.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let cluster = Cluster {
            dir,
            bin: bin_dir(),
            as_postgres_user,
            port,
        };
        let data = cluster.dir.join("data");
        run(cluster
            .pg("initdb")
            .args(["-U", "postgres", "-A", "trust", "-D"])
            .arg(&data));
        run(cluster
            .as_owner("openssl".into())
            .args([
                "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            ])
            .args(["-subj", "/CN=localhost", "-addext"])
            .args(["subjectAltName=DNS:localhost,IP:127.0.0.1", "-addext"])
            // A leaf, not a CA: webpki refuses a CA certificate as the server's.
            .args(["basicConstraints=critical,CA:FALSE", "-keyout"])
            .arg(data.join("server.key"))
            .arg("-out")
            .arg(data.join("server.crt")));
        std::fs::write(
            data.join("pg_hba.conf"),
            "local all postgres trust\nlocal all all scram-sha-256\n\
             host all all 127.0.0.1/32 scram-sha-256\n",
        )
        .unwrap();
        let mut conf = std::fs::read_to_string(data.join("postgresql.conf")).unwrap();
        conf.push_str(&format!(
            "\nlisten_addresses = '127.0.0.1'\nport = {port}\nunix_socket_directories = '{}'\n\
             ssl = on\nlog_connections = on\nlog_statement = 'all'\nlog_line_prefix = '@@%u@%d@@ '\n\
             {conf_extra}",
            cluster.dir.display()
        ));
        std::fs::write(data.join("postgresql.conf"), conf).unwrap();
        run(cluster
            .pg("pg_ctl")
            .args(["-w", "-D"])
            .arg(&data)
            .arg("-l")
            .arg(cluster.log_path())
            .arg("start"));
        cluster.stop_when_process_exits(&data);
        cluster
    }

    /// A static's Drop never runs, so a detached watchdog stops the server
    /// and removes the temp dir once this test process is gone. It has its own
    /// process group, so Ctrl-C on `cargo test` does not kill it too.
    #[allow(clippy::zombie_processes)] // the watchdog must outlive this process
    fn stop_when_process_exits(&self, data: &Path) {
        use std::os::unix::process::CommandExt;
        // POSIX wait: `tail --pid` is GNU-only and BSD tail exits at once.
        // Paths go in as arguments, never as script text.
        let mut watchdog = Command::new("sh");
        watchdog
            .args([
                "-c",
                r#"pid=$1 dir=$2; shift 2
while kill -0 "$pid" 2>/dev/null; do sleep 1; done; "$@"; rm -rf "$dir""#,
            ])
            .arg("sh")
            .arg(std::process::id().to_string())
            .arg(&self.dir);
        if self.as_postgres_user {
            watchdog.args(["runuser", "-u", "postgres", "--"]);
        }
        watchdog
            .arg(self.bin.join("pg_ctl"))
            .arg("-D")
            .arg(data)
            .args(["-m", "immediate", "stop"])
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn watchdog");
    }

    fn pg(&self, tool: &str) -> Command {
        self.as_owner(self.bin.join(tool))
    }

    /// `path` as the data directory's owner.
    fn as_owner(&self, path: PathBuf) -> Command {
        if self.as_postgres_user {
            let mut cmd = Command::new("runuser");
            cmd.args(["-u", "postgres", "--"]).arg(path);
            cmd
        } else {
            Command::new(path)
        }
    }

    fn log_path(&self) -> PathBuf {
        self.dir.join("postgres.log")
    }

    fn psql(&self, db: &str) -> Command {
        let mut cmd = Command::new(self.bin.join("psql"));
        cmd.arg("-h").arg(&self.dir).args([
            "-p",
            &self.port.to_string(),
            "-U",
            "postgres",
            "-X",
            "-q",
            "-v",
            "ON_ERROR_STOP=1",
            "-d",
            db,
        ]);
        cmd
    }
}

/// Creates a fresh database from `tests/fixtures/<fixture>.sql` and a reader role
/// built from the published grant list and nothing else.
pub fn fixture_db(fixture: &str) -> Db {
    fixture_db_in(cluster(), fixture)
}

/// Like `fixture_db`, on a cluster where pg_cron keeps its jobs in `cron_database`.
pub fn pg_cron_db(cron_database: &'static str, fixture: &str) -> Db {
    fixture_db_in(cron_cluster(cron_database), fixture)
}

fn fixture_db_in(c: &'static Cluster, fixture: &str) -> Db {
    static N: AtomicUsize = AtomicUsize::new(0);
    let name = format!("{fixture}_{}", N.fetch_add(1, Ordering::SeqCst));
    let reader = format!("reader_{name}");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    run(c
        .psql("postgres")
        .args(["-c", &format!("CREATE DATABASE {name}")]));
    run(c.psql("postgres").args([
        "-c",
        &format!("REVOKE CONNECT, TEMPORARY ON DATABASE {name} FROM PUBLIC"),
    ]));
    run(c
        .psql(&name)
        .arg("-f")
        .arg(root.join(format!("tests/fixtures/{fixture}.sql"))));
    run(c
        .psql(&name)
        .args(["-v", &format!("role={reader}")])
        .args(["-v", &format!("password={PASSWORD}")])
        .args(["-v", &format!("database={name}")])
        .arg("-f")
        .arg(root.join("read-only-role.sql")));
    let url = format!(
        "host={} port={} dbname={name} user={reader} password={PASSWORD}",
        c.dir.display(),
        c.port
    );
    let tcp_url = format!(
        "host=127.0.0.1 port={} dbname={name} user={reader} password={PASSWORD}",
        c.port
    );
    Db {
        name,
        reader,
        url,
        tcp_url,
        cluster: c,
    }
}

/// The cluster's self-signed server certificate (PEM; SANs localhost and 127.0.0.1).
pub fn server_cert() -> PathBuf {
    cluster().dir.join("data/server.crt")
}

/// Writes a self-signed certificate that did not sign the server's to `path` (PEM).
pub fn unrelated_cert(path: &Path) {
    let key = path.with_extension("key");
    run(Command::new("openssl")
        .args([
            "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        ])
        .args(["-subj", "/CN=localhost", "-addext"])
        .args(["subjectAltName=DNS:localhost,IP:127.0.0.1", "-keyout"])
        .arg(key)
        .arg("-out")
        .arg(path));
}

/// Runs `sql` on `db` as the superuser (e.g. an explicit grant a test needs).
pub fn admin_sql(db: &str, sql: &str) {
    run(cluster().psql(db).args(["-c", sql]));
}

/// Runs `herculean scan` with the given connection string.
pub fn scan(url: Option<&str>) -> Output {
    scan_with(url, &[])
}

/// Runs `herculean scan <args>` with the given connection string.
pub fn scan_with(url: Option<&str>, args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_herculean"));
    cmd.arg("scan")
        .args(args)
        .env_remove("HERCULEAN_DATABASE_URL");
    if let Some(url) = url {
        cmd.env("HERCULEAN_DATABASE_URL", url);
    }
    cmd.output().expect("run herculean")
}

/// Statements the server logged for `user` on `db`. A log entry starts with the
/// `@@user@db@@` prefix; continuation lines of multi-line statements follow it.
pub fn logged_statements(user: &str, db: &str) -> Vec<String> {
    let log = std::fs::read_to_string(cluster().log_path()).unwrap();
    let mut entries: Vec<String> = Vec::new();
    for line in log.lines() {
        if line.starts_with("@@") || entries.is_empty() {
            entries.push(line.to_string());
        } else {
            let last = entries.last_mut().unwrap();
            last.push('\n');
            last.push_str(line);
        }
    }
    let prefix = format!("@@{user}@{db}@@ ");
    entries
        .into_iter()
        .filter(|e| e.starts_with(&prefix))
        .collect()
}

/// A scratch directory removed when the test ends.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new() -> TempDir {
        static N: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "herculean-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Every file under `dir`, relative to it, as text, sorted.
pub fn all_files(dir: &Path) -> Vec<(PathBuf, String)> {
    fn walk(root: &Path, dir: &Path, files: &mut Vec<(PathBuf, String)>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(root, &path, files);
            } else {
                let text = std::fs::read_to_string(&path).unwrap();
                files.push((path.strip_prefix(root).unwrap().to_path_buf(), text));
            }
        }
    }
    let mut files = Vec::new();
    walk(dir, dir, &mut files);
    files.sort();
    files
}

/// The JSON a successful command (scan, fix, hook) printed.
pub fn stdout_json(out: &Output) -> serde_json::Value {
    assert!(
        out.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("stdout is JSON")
}

/// `db` as a `postgres://` URL over TCP to 127.0.0.1, with `query` appended.
pub fn postgres_url(db: &Db, query: &str) -> String {
    let port = db.tcp_url.split("port=").nth(1).unwrap().split(' ').next();
    let (reader, name) = (&db.reader, &db.name);
    format!(
        "postgres://{reader}:{PASSWORD}@127.0.0.1:{}/{name}?{query}",
        port.unwrap()
    )
}

/// `skipped_checks` of a live scan without `--repo`.
pub fn no_repo() -> serde_json::Value {
    serde_json::json!([{ "check": "drift", "reason": "no repo given" }])
}

/// A `public.<table>` store whose one personal column is `email`, by name.
pub fn email_store(table: &str) -> serde_json::Value {
    serde_json::json!({ "schema": "public", "table": table, "columns": [
        { "name": "email", "category": "contact", "source": "column_name", "confidence": "high" }
    ]})
}

/// The ON DELETE deletion path of `public.<table>`'s default-named foreign key on `fk_column`.
pub fn cascade_path(table: &str, fk_column: &str) -> serde_json::Value {
    serde_json::json!({
        "table": format!("public.{table}"),
        "kind": "on_delete",
        "evidence_id": format!("pg_constraint:public.{table}.{table}_{fk_column}_fkey")
    })
}

pub type Treatment = [(&'static str, &'static str); 3];
/// The solver's DELETE treatment (operation, state) per phase.
pub const DELETE: Treatment = [
    ("REPORT_REMAINING_RECORD", "PRESENT"),
    ("DELETE_RECORD", "ABSENT"),
    ("VERIFY_RECORD_ABSENT", "ABSENT"),
];
pub const DISABLE: Treatment = [
    ("REPORT_ACTIVE_DATA_FLOW", "ACTIVE"),
    ("DISABLE_DATA_FLOW", "DISABLED"),
    ("VERIFY_DATA_FLOW_DISABLED", "DISABLED"),
];
pub const RESTRICT: Treatment = [
    ("REPORT_EXCESS_ACCESS", "ACTIVE"),
    ("RESTRICT_ACCESS", "RESTRICTED"),
    ("VERIFY_ACCESS_RESTRICTED", "RESTRICTED"),
];
pub const RECONCILE: Treatment = [
    ("REPORT_SCHEMA_DRIFT", "PRESENT"),
    ("RECONCILE_SCHEMA", "RECONCILED"),
    ("VERIFY_SCHEMA_RECONCILED", "RECONCILED"),
];

/// A finding's three steps: FINDING citing `evidence`, then REMEDIATION and VERIFICATION.
pub fn steps(system: &str, resource: &str, evidence: &str, ops: Treatment) -> serde_json::Value {
    let phases = ["FINDING", "REMEDIATION", "VERIFICATION"];
    let evidence = [evidence, "", ""];
    let steps: Vec<serde_json::Value> = (0..3)
        .map(|i| {
            serde_json::json!({ "step_no": i + 1, "phase": phases[i], "system_id": system,
                "resource_id": resource, "operation": ops[i].0, "state": ops[i].1,
                "evidence_id": evidence[i] })
        })
        .collect();
    serde_json::Value::Array(steps)
}
