//! The Claude Code plugin under `plugin/` and the root marketplace manifest.
//! Shells out to the `claude` CLI (on PATH here; CI installs it).
mod common;

use common::{all_files, fixture_db, TempDir};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .into()
}

fn plugin_dir() -> PathBuf {
    repo_root().join("plugin")
}

fn ok(out: Output) -> String {
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "{text}");
    text
}

/// `claude <args>` with its config in `home` only.
fn claude(home: &Path, args: &[&str]) -> Output {
    Command::new("claude")
        .args(args)
        .env("HOME", home)
        .env("CLAUDE_CONFIG_DIR", home.join(".claude"))
        .current_dir(home)
        .output()
        .expect("run claude")
}

/// The shell commands a command file tells Claude to run: the lines of its
/// fenced code blocks.
fn fenced_commands(markdown: &str) -> Vec<String> {
    let mut commands = Vec::new();
    let mut in_fence = false;
    for line in markdown.lines() {
        if line.starts_with("```") {
            in_fence = !in_fence;
        } else if in_fence && !line.trim().is_empty() {
            commands.push(line.trim().to_string());
        }
    }
    commands
}

fn command_file(name: &str) -> String {
    std::fs::read_to_string(plugin_dir().join(format!("commands/{name}.md"))).unwrap()
}

/// Runs a command as written, with the built binary standing in for `herculean` on PATH.
fn run_as_written(command: &str, cwd: &Path, url: &str) -> Output {
    let args: Vec<&str> = command.split_whitespace().collect();
    assert_eq!(args[0], "herculean");
    Command::new(env!("CARGO_BIN_EXE_herculean"))
        .args(&args[1..])
        .current_dir(cwd)
        .env("HERCULEAN_DATABASE_URL", url)
        .output()
        .expect("run herculean")
}

#[test]
fn plugin_and_marketplace_manifests_validate() {
    let home = TempDir::new();
    for path in [plugin_dir(), repo_root()] {
        ok(claude(
            &home.0,
            &["plugin", "validate", "--strict", path.to_str().unwrap()],
        ));
    }
}

#[test]
fn plugin_installs_from_this_repo() {
    let home = TempDir::new();
    let root = repo_root();
    ok(claude(
        &home.0,
        &["plugin", "marketplace", "add", root.to_str().unwrap()],
    ));
    ok(claude(
        &home.0,
        &["plugin", "install", "herculean@herculean"],
    ));
    let list: Value =
        serde_json::from_str(&ok(claude(&home.0, &["plugin", "list", "--json"]))).unwrap();
    assert!(
        list.as_array()
            .unwrap()
            .iter()
            .any(|p| p["id"] == "herculean@herculean"),
        "{list}"
    );
}

#[test]
fn scan_command_runs_the_cli_and_gets_the_scan_report() {
    let db = fixture_db("personal_table_without_deletion_path");
    let commands = fenced_commands(&command_file("scan"));
    assert_eq!(commands, ["herculean scan --repo ."]);
    let cwd = TempDir::new();
    let out = run_as_written(&commands[0], &cwd.0, &db.url);
    let report: Value = serde_json::from_str(&ok(out)).unwrap();
    assert_eq!(report["findings"][0]["check"], "deletion_path");
    assert_eq!(report["findings"][0]["resource_id"], "public.customers");
}

#[test]
fn readiness_command_runs_the_cli_and_writes_the_readiness_summary() {
    let db = fixture_db("personal_table_without_deletion_path");
    let markdown = command_file("readiness");
    let commands = fenced_commands(&markdown);
    assert_eq!(commands, ["herculean report --out .herculean --repo ."]);
    assert!(markdown.contains(".herculean/readiness.md"));
    let cwd = TempDir::new();
    ok(run_as_written(&commands[0], &cwd.0, &db.url));
    let readiness = std::fs::read_to_string(cwd.0.join(".herculean/readiness.md")).unwrap();
    assert!(readiness.starts_with("# SOC 2 readiness summary"));
}

#[test]
fn fix_command_runs_the_cli_and_writes_one_migration() {
    let db = fixture_db("soft_delete_without_purge");
    let markdown = command_file("fix");
    let commands = fenced_commands(&markdown);
    assert_eq!(
        commands[0],
        "herculean fix --finding '$ARGUMENTS' --repo . --retention-days <days>"
    );
    // The user, not a default, picks the retention period.
    assert!(
        markdown.contains("ask the user how many days"),
        "{markdown}"
    );
    let cwd = TempDir::new();
    // The fix goes into the repo's own migrations dir.
    std::fs::create_dir_all(cwd.0.join("supabase/migrations")).unwrap();
    // The shell strips the single quotes around the selector.
    let command = commands[0]
        .replace(
            "'$ARGUMENTS'",
            "deletion_path/soft_delete_without_purge/public.customers",
        )
        .replace("<days>", "30");
    let printed: Value =
        serde_json::from_str(&ok(run_as_written(&command, &cwd.0, &db.url))).unwrap();
    let written = printed["path"].as_str().unwrap();
    assert!(
        written.starts_with("supabase/migrations/")
            && written.ends_with("_herculean_fix_soft_delete_without_purge__public.customers.sql"),
        "{written}"
    );
    assert_eq!(
        printed["branch"],
        "herculean/fix-soft_delete_without_purge-public-customers"
    );
    assert!(std::fs::read_to_string(cwd.0.join(written))
        .unwrap()
        .contains("\"deleted_at\" < now() - interval '30 days'"));
}

#[test]
fn plugin_holds_no_check_logic_and_only_runs_herculean() {
    let dir = plugin_dir();
    let names: Vec<String> = all_files(&dir)
        .iter()
        .map(|(p, _)| p.display().to_string())
        .collect();
    assert_eq!(
        names,
        [
            ".claude-plugin/plugin.json",
            ".mcp.json",
            "commands/fix.md",
            "commands/readiness.md",
            "commands/scan.md",
            "hooks/hooks.json",
        ]
    );
    for name in ["scan", "readiness"] {
        let markdown = command_file(name);
        assert!(markdown.contains("\nallowed-tools: Bash(herculean:*)\n"));
        assert_eq!(markdown.matches("Bash(").count(), 1, "{name}");
        assert!(!markdown.contains("!`"), "{name}: no inline shell");
        for command in fenced_commands(&markdown) {
            assert!(command.starts_with("herculean "), "{name}: {command}");
        }
    }
    // The fix command also commits, pushes and opens the PR, with narrow
    // permissions, and passes git/gh only the values `herculean fix` printed.
    let markdown = command_file("fix");
    assert!(markdown.contains(
        "\nallowed-tools: Bash(herculean fix:*), Bash(git switch -c herculean/fix-:*), \
         Bash(git add migrations/:*), Bash(git add db/migrations/:*), \
         Bash(git add supabase/migrations/:*), Bash(git commit -m:*), \
         Bash(git push -u origin herculean/fix-:*), Bash(gh pr create:*)\n"
    ));
    assert_eq!(markdown.matches("Bash(").count(), 8);
    assert!(!markdown.contains("!`"), "fix: no inline shell");
    assert_eq!(
        fenced_commands(&markdown),
        [
            "herculean fix --finding '$ARGUMENTS' --repo . --retention-days <days>",
            "git switch -c <branch>",
            "git add <path>",
            "git commit -m '<commit_message>' -- <path>",
            "git push -u origin <branch>",
            "gh pr create --head <branch> --title '<commit_message>' --body '<pr_body>'",
        ]
    );
    let hooks: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("hooks/hooks.json")).unwrap())
            .unwrap();
    let hook_commands: Vec<&Value> = hooks["hooks"]
        .as_object()
        .unwrap()
        .values()
        .flat_map(|matchers| matchers.as_array().unwrap())
        .flat_map(|m| m["hooks"].as_array().unwrap())
        .map(|h| &h["command"])
        .collect();
    // The hook does nothing when herculean is not installed; otherwise it is `herculean hook` (tests/release.rs).
    assert_eq!(
        hook_commands,
        ["command -v herculean >/dev/null 2>&1 || { cat >/dev/null; exit 0; }; exec herculean hook"]
    );
    let mcp: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join(".mcp.json")).unwrap()).unwrap();
    assert_eq!(
        mcp,
        serde_json::json!({"mcpServers": {"herculean": {"command": "herculean", "args": ["mcp"]}}}),
        "the MCP server is `herculean mcp`, with no connection string in the config"
    );
    assert_eq!(
        hooks["hooks"]["PostToolUse"][0]["matcher"],
        "Write|Edit|MultiEdit"
    );
}
