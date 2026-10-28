mod common;

use common::{all_files, fixture_db, TempDir, PASSWORD};
use serde_json::{json, Value};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

const FIXTURE: &str = "personal_table_without_deletion_path";
const NOW: &str = "2026-10-26T12:34:56Z";

fn herculean(url: &str, cwd: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_herculean"));
    cmd.current_dir(cwd)
        .env("HERCULEAN_DATABASE_URL", url)
        .env("HERCULEAN_NOW", NOW);
    cmd
}

/// Runs `herculean mcp`, sends `messages` one per line, closes stdin and
/// returns the raw process output.
fn session(url: &str, cwd: &Path, messages: &[Value]) -> Output {
    let mut child = herculean(url, cwd)
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run herculean mcp");
    let mut stdin = child.stdin.take().unwrap();
    for m in messages {
        writeln!(stdin, "{m}").unwrap();
    }
    drop(stdin);
    child.wait_with_output().unwrap()
}

/// An initialize handshake followed by `requests`; returns every response line.
fn call(url: &str, cwd: &Path, requests: &[Value]) -> Vec<Value> {
    let mut messages = vec![
        json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "test", "version": "0"}}}),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    ];
    messages.extend_from_slice(requests);
    let out = session(url, cwd, &messages);
    assert!(out.status.success(), "{out:?}");
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn tool_call(id: u64, name: &str, arguments: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
           "params": {"name": name, "arguments": arguments}})
}

/// The single text content item of a tools/call result.
fn text(response: &Value) -> &str {
    let content = response["result"]["content"].as_array().unwrap();
    assert_eq!(content.len(), 1, "{response}");
    assert_eq!(content[0]["type"], "text");
    content[0]["text"].as_str().unwrap()
}

#[test]
fn initialize_and_list_announce_the_scan_and_report_tools() {
    let tmp = TempDir::new();
    let responses = call(
        "unused",
        &tmp.0,
        &[json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})],
    );
    assert_eq!(responses.len(), 2, "the notification gets no reply");
    assert_eq!(
        responses[0],
        json!({"jsonrpc": "2.0", "id": 0, "result": {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "herculean", "version": env!("CARGO_PKG_VERSION")}}})
    );
    let tools = responses[1]["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["scan", "report"]);
    for tool in tools {
        assert!(tool["description"].as_str().unwrap().contains("check"));
        let schema = &tool["inputSchema"];
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["additionalProperties"], false);
    }
    let props = |i: usize| {
        let mut keys: Vec<String> = tools[i]["inputSchema"]["properties"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        keys.sort();
        keys
    };
    assert_eq!(props(0), ["data_map", "repo", "sample"]);
    assert_eq!(props(1), ["data_map", "fail_on", "mapping", "out", "repo"]);
    assert_eq!(tools[1]["inputSchema"]["required"], json!(["out"]));
}

#[test]
fn scan_tool_returns_exactly_what_the_cli_prints() {
    let db = fixture_db(FIXTURE);
    let tmp = TempDir::new();
    let cli = herculean(&db.url, &tmp.0).arg("scan").output().unwrap();
    assert!(cli.status.success());
    let responses = call(&db.url, &tmp.0, &[tool_call(1, "scan", json!({}))]);
    assert_eq!(responses[1]["id"], 1);
    assert_eq!(responses[1]["result"]["isError"], false);
    assert_eq!(text(&responses[1]), String::from_utf8(cli.stdout).unwrap());
}

#[test]
fn report_tool_writes_the_same_files_and_summary_as_the_cli() {
    let db = fixture_db(FIXTURE);
    let (cli_dir, mcp_dir) = (TempDir::new(), TempDir::new());
    let cli = herculean(&db.url, &cli_dir.0)
        .args(["report", "--out", "out", "--fail-on", "low"])
        .output()
        .unwrap();
    assert_eq!(cli.status.code(), Some(2), "a finding meets the threshold");
    let responses = call(
        &db.url,
        &mcp_dir.0,
        &[tool_call(
            1,
            "report",
            json!({"out": "out", "fail_on": "low"}),
        )],
    );
    assert_eq!(
        responses[1]["result"]["isError"], false,
        "a met threshold is a result, not a tool error"
    );
    let summary = String::from_utf8(cli.stdout).unwrap();
    assert_eq!(text(&responses[1]), format!("{summary}exit code: 2\n"));
    let files = all_files(&cli_dir.0.join("out"));
    let names: Vec<_> = files.iter().map(|(p, _)| p.to_str().unwrap()).collect();
    assert!(names.contains(&"readiness.md") && names.contains(&"report.json"));
    assert!(names.iter().any(|n| n.starts_with("evidence/")));
    assert_eq!(all_files(&mcp_dir.0.join("out")), files);
}

#[test]
fn the_connection_string_never_reaches_tool_arguments_or_output() {
    let db = fixture_db(FIXTURE);
    let tmp = TempDir::new();
    let wrong = "Wrong-Pw-distinctive-9Xq";
    let bad_url = db.url.replace(PASSWORD, wrong);
    let requests = [
        tool_call(1, "scan", json!({"database_url": db.url})),
        tool_call(2, "scan", json!({})),
        json!({"jsonrpc": "2.0", "id": 3, "method": "ping"}),
        json!({"jsonrpc": "2.0", "id": 4, "method": "resources/list"}),
    ];
    for (url, secret) in [(&db.url, PASSWORD), (&bad_url, wrong)] {
        let mut messages = vec![json!({"jsonrpc": "2.0", "id": 0, "method": "initialize",
                                        "params": {}})];
        messages.extend_from_slice(&requests);
        let out = session(url, &tmp.0, &messages);
        let (stdout, stderr) = (
            String::from_utf8(out.stdout).unwrap(),
            String::from_utf8(out.stderr).unwrap(),
        );
        assert!(!stdout.contains(secret) && !stderr.contains(secret));
        assert!(!stdout.contains("host=") && !stderr.contains("host="));
        let r: Vec<Value> = stdout
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(r[1]["result"]["isError"], true, "unknown argument refused");
        assert_eq!(text(&r[1]), "herculean: unknown argument database_url");
        assert_eq!(r[3], json!({"jsonrpc": "2.0", "id": 3, "result": {}}));
        assert_eq!(r[4]["error"]["code"], -32601);
        if secret == wrong {
            assert_eq!(r[2]["result"]["isError"], true);
            assert_eq!(
                text(&r[2]),
                "herculean: connecting to the database failed (SQLSTATE 28P01)"
            );
        } else {
            assert_eq!(r[2]["result"]["isError"], false);
        }
    }
}

#[test]
fn scan_tool_with_data_map_and_repo_matches_the_cli() {
    let db = fixture_db("data_map_override");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let (map, repo) = (
        "tests/fixtures/data_map_override.yaml",
        "tests/fixtures/repos/no_deletion_path",
    );
    let cli = herculean(&db.url, root)
        .args(["scan", "--data-map", map, "--repo", repo])
        .output()
        .unwrap();
    assert!(cli.status.success(), "{cli:?}");
    let responses = call(
        &db.url,
        root,
        &[tool_call(1, "scan", json!({"data_map": map, "repo": repo}))],
    );
    assert_eq!(responses[1]["result"]["isError"], false, "{}", responses[1]);
    assert_eq!(text(&responses[1]), String::from_utf8(cli.stdout).unwrap());
}

#[test]
fn path_arguments_must_stay_inside_the_working_directory() {
    let tmp = TempDir::new();
    let outside = TempDir::new();
    std::fs::write(outside.0.join("map.yaml"), "overrides: []\n").unwrap();
    std::os::unix::fs::symlink(&outside.0, tmp.0.join("link")).unwrap();
    std::fs::write(tmp.0.join("map.yaml"), "overrides: []\n").unwrap();
    let absolute = outside.0.join("map.yaml");
    let cases = [
        (
            "scan",
            json!({"data_map": absolute.to_str().unwrap()}),
            "data_map",
        ),
        ("scan", json!({"data_map": "../map.yaml"}), "data_map"),
        ("scan", json!({"data_map": "sub/../map.yaml"}), "data_map"),
        ("scan", json!({"data_map": "link/map.yaml"}), "data_map"),
        ("scan", json!({"repo": "link"}), "repo"),
        ("report", json!({"out": "link/out"}), "out"),
        ("report", json!({"out": "/tmp/herculean-out"}), "out"),
        (
            "report",
            json!({"out": "o", "mapping": "../m.yaml"}),
            "mapping",
        ),
    ];
    let requests: Vec<Value> = cases
        .iter()
        .enumerate()
        .map(|(i, (tool, args, _))| tool_call(i as u64 + 1, tool, args.clone()))
        .collect();
    let responses = call("unused", &tmp.0, &requests);
    for (i, (_, args, name)) in cases.iter().enumerate() {
        let r = &responses[i + 1];
        assert_eq!(r["result"]["isError"], true, "{args}: {r}");
        assert_eq!(
            text(r),
            format!("herculean: {name} must be a relative path inside the working directory"),
            "{args}"
        );
    }
    assert!(!outside.0.join("out").exists() && !Path::new("/tmp/herculean-out").exists());
}

#[test]
fn unparsable_data_map_and_mapping_are_reported_without_their_contents() {
    let db = fixture_db(FIXTURE);
    let tmp = TempDir::new();
    let secret = "zz_secret_field_9Kq";
    std::fs::write(tmp.0.join("bad.yaml"), format!("{secret}: 1\n")).unwrap();
    let responses = call(
        &db.url,
        &tmp.0,
        &[
            tool_call(1, "scan", json!({"data_map": "bad.yaml"})),
            tool_call(2, "report", json!({"out": "out", "mapping": "bad.yaml"})),
        ],
    );
    assert_eq!(
        text(&responses[1]),
        "herculean: cannot read or parse data_map"
    );
    assert_eq!(
        text(&responses[2]),
        "herculean: cannot read or parse mapping"
    );
    for r in &responses[1..] {
        assert_eq!(r["result"]["isError"], true);
    }
}
