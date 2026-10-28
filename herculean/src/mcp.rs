//! `herculean mcp`: a stdio MCP server (newline-delimited JSON-RPC 2.0) whose
//! tools turn their arguments into `herculean scan` / `herculean report`
//! arguments and call the same `run` the CLI uses. No logic of its own; the
//! database comes only from this process's `HERCULEAN_DATABASE_URL`.

use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::path::{Component, Path};

const NO_CHECK_TOOL: &str = "There is no separate check tool: scan runs every check.";

fn tools() -> Value {
    let path = |what: &str| json!({"type": "string", "description": what});
    let repo = path("Repo to read migrations and code from (runs the drift check).");
    let data_map = path("data-map.yaml with personal-data overrides.");
    json!([
        {
            "name": "scan",
            "description": format!(
                "Maps personal data in the Postgres database named by the server's \
                 HERCULEAN_DATABASE_URL (and/or a repo) and runs every check; returns the JSON \
                 report `herculean scan` prints. {NO_CHECK_TOOL}"),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "repo": repo,
                    "data_map": data_map,
                    "sample": {"type": "boolean",
                               "description": "Opt in to sampling column values."},
                },
                "additionalProperties": false,
            },
        },
        {
            "name": "report",
            "description": format!(
                "Runs the scan and every check, writes the SOC 2 readiness summary, evidence \
                 pack and report.json into `out` (as `herculean report`), and returns its \
                 summary plus the exit code the CLI would give. {NO_CHECK_TOOL}"),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "out": path("Directory to write readiness.md, evidence/ and report.json to."),
                    "repo": repo,
                    "data_map": data_map,
                    "mapping": path("SOC 2 mapping file (default: built-in)."),
                    "fail_on": {"type": "string", "enum": ["low", "medium", "high"],
                                "description": "Severity at which the exit code becomes 2."},
                },
                "required": ["out"],
                "additionalProperties": false,
            },
        },
    ])
}

/// The CLI arguments for a tool call, or an error naming the bad argument
/// (never its value).
fn cli_args(tool: &str, arguments: &Value) -> Result<Vec<String>, String> {
    let empty = serde_json::Map::new();
    let arguments = match arguments {
        Value::Null => &empty,
        Value::Object(map) => map,
        _ => return Err("herculean: arguments must be an object".into()),
    };
    let mut args = vec![tool.to_string()];
    for (name, value) in arguments {
        let flag = match (tool, name.as_str()) {
            (_, "repo" | "data_map") | ("report", "out" | "mapping" | "fail_on") => {
                format!("--{}", name.replace('_', "-"))
            }
            ("scan", "sample") => {
                match value {
                    Value::Bool(true) => args.push("--sample".into()),
                    Value::Bool(false) => {}
                    _ => return Err("herculean: sample must be a boolean".into()),
                }
                continue;
            }
            _ => return Err(format!("herculean: unknown argument {name}")),
        };
        let Value::String(value) = value else {
            return Err(format!("herculean: {name} must be a string"));
        };
        if name != "fail_on" && !inside_cwd(Path::new(value)) {
            return Err(format!(
                "herculean: {name} must be a relative path inside the working directory"
            ));
        }
        args.extend([flag, value.clone()]);
    }
    if tool == "report" && !arguments.contains_key("out") {
        return Err("herculean: out is required".into());
    }
    Ok(args)
}

/// `rel` stays under `root` (a canonical path): no absolute part, no `..`, and
/// its nearest existing ancestor resolves, symlinks followed, inside `root`.
pub(crate) fn inside(root: &Path, rel: &Path) -> bool {
    let plain = rel
        .components()
        .all(|c| matches!(c, Component::Normal(_) | Component::CurDir));
    let existing = root
        .join(rel)
        .ancestors()
        .find_map(|a| a.canonicalize().ok());
    plain && existing.is_some_and(|e| e.starts_with(root))
}

/// An agent picks these paths, so they must stay under the server's cwd (the
/// path itself must resolve for an input).
fn inside_cwd(path: &Path) -> bool {
    std::env::current_dir()
        .and_then(|d| d.canonicalize())
        .is_ok_and(|cwd| inside(&cwd, path))
}

fn call_tool(params: &Value) -> Result<Value, (i64, String)> {
    let tool = params["name"].as_str().unwrap_or_default();
    if !matches!(tool, "scan" | "report") {
        return Err((-32602, format!("unknown tool {tool}")));
    }
    let (text, is_error) = match cli_args(tool, &params["arguments"]).and_then(|a| crate::run(&a)) {
        Ok((stdout, _)) if tool == "scan" => (stdout, false),
        Ok((stdout, code)) => (format!("{stdout}exit code: {code}\n"), false),
        // These can quote the file (e.g. an unknown field); never echo it.
        Err(m) if m.starts_with(crate::DATA_MAP_ERROR) => {
            ("herculean: cannot read or parse data_map".into(), true)
        }
        Err(m) if m.starts_with(crate::MAPPING_ERROR) => {
            ("herculean: cannot read or parse mapping".into(), true)
        }
        Err(message) => (message, true),
    };
    Ok(json!({"content": [{"type": "text", "text": text}], "isError": is_error}))
}

fn handle(method: &str, params: &Value) -> Result<Value, (i64, String)> {
    match method {
        "initialize" => Ok(json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "herculean", "version": env!("CARGO_PKG_VERSION")},
        })),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({"tools": tools()})),
        "tools/call" => call_tool(params),
        _ => Err((-32601, format!("method not found: {method}"))),
    }
}

/// Serves requests from stdin until it closes.
pub fn serve() {
    let mut stdout = std::io::stdout().lock();
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Value>(&line) {
            Err(_) => json!({"jsonrpc": "2.0", "id": null,
                             "error": {"code": -32700, "message": "parse error"}}),
            // A notification (no id) gets no reply.
            Ok(msg) if msg.get("id").is_none() => continue,
            Ok(msg) => {
                let method = msg["method"].as_str().unwrap_or_default();
                match handle(method, &msg["params"]) {
                    Ok(result) => json!({"jsonrpc": "2.0", "id": msg["id"], "result": result}),
                    Err((code, message)) => json!({"jsonrpc": "2.0", "id": msg["id"],
                        "error": {"code": code, "message": message}}),
                }
            }
        };
        // The client is gone once stdout is closed: stop quietly.
        if writeln!(stdout, "{response}")
            .and_then(|_| stdout.flush())
            .is_err()
        {
            break;
        }
    }
}
