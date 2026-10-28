//! What a released binary and the plugin's hook promise: `--version`, and a hook that stays quiet
//! when the binary is not installed. Also what a release ships: the archive release.yml packs, and
//! the Action installing it from a release tag. Those run the workflow's and the Action's own
//! step scripts, as a runner would.
mod common;

use common::TempDir;
use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

#[test]
fn version_flag_prints_the_crate_version() {
    let out = Command::new(env!("CARGO_BIN_EXE_herculean"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        format!("herculean {}\n", env!("CARGO_PKG_VERSION"))
    );
}

/// The plugin's hook command, exactly as `plugin/hooks/hooks.json` declares it.
fn hook_command() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../plugin/hooks/hooks.json");
    let hooks: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    hooks["hooks"]["PostToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap()
        .to_string()
}

/// Runs the hook command the way Claude Code does (`sh -c`), with `path` as PATH and `stdin` as the payload.
fn run_hook(path: &str, stdin: &str) -> Output {
    let mut child = Command::new("/bin/sh")
        .args(["-c", &hook_command()])
        .env_clear()
        .env("PATH", path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn payload() -> String {
    let repo = format!(
        "{}/tests/fixtures/repos/hook_drift",
        env!("CARGO_MANIFEST_DIR")
    );
    json!({
        "hook_event_name": "PostToolUse",
        "cwd": repo,
        "tool_name": "Write",
        "tool_input": { "file_path": format!("{repo}/migrations/002_add_order_phone.sql") }
    })
    .to_string()
}

#[test]
fn hook_is_silent_when_herculean_is_not_installed() {
    // A PATH with the shell's own tools but no herculean binary.
    let out = run_hook("/usr/bin:/bin", &payload());
    assert!(out.status.success(), "{out:?}");
    assert!(out.stdout.is_empty(), "{out:?}");
    assert!(out.stderr.is_empty(), "{out:?}");
}

#[test]
fn hook_runs_herculean_hook_when_installed() {
    let bin_dir = Path::new(env!("CARGO_BIN_EXE_herculean"))
        .parent()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let out = run_hook(&format!("{bin_dir}:/usr/bin:/bin"), &payload());
    assert!(out.status.success(), "{out:?}");
    let warning: Value = serde_json::from_slice(&out.stdout).expect("the hook's JSON warning");
    assert_eq!(
        warning["hookSpecificOutput"]["hookEventName"],
        "PostToolUse"
    );
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .into()
}

fn ok(out: Output) -> String {
    assert!(out.status.success(), "{out:?}");
    String::from_utf8(out.stdout).unwrap()
}

fn yaml(path: &str) -> serde_norway::Value {
    serde_norway::from_str(&fs::read_to_string(repo_root().join(path)).unwrap()).unwrap()
}

/// The step called `name` among a job's or a composite action's `steps`.
fn step<'a>(steps: &'a serde_norway::Value, name: &str) -> &'a serde_norway::Value {
    steps
        .as_sequence()
        .unwrap()
        .iter()
        .find(|s| s["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("no step named {name:?}"))
}

/// Runs a step's script the way a runner does (`bash -eo pipefail`), in `dir`, with only `env`.
fn run_script(script: &str, dir: &Path, env: &[(&str, String)]) -> Output {
    assert!(
        !script.contains("${{"),
        "an expression the test does not expand:\n{script}"
    );
    Command::new("/bin/bash")
        .args(["--noprofile", "--norc", "-eo", "pipefail", "-c", script])
        .current_dir(dir)
        .env_clear()
        .envs(env.iter().map(|(k, v)| (k, v)))
        .output()
        .unwrap()
}

/// The release target `install.sh` picks on this machine.
fn host_target() -> String {
    let os = if cfg!(target_os = "macos") {
        "apple-darwin"
    } else {
        "unknown-linux-gnu"
    };
    format!("{}-{os}", std::env::consts::ARCH)
}

/// Runs release.yml's Package and Checksums steps for this machine's target, on a checkout under
/// `work` holding `binary` as the built herculean. Returns the `dist` directory: what a GitHub
/// Release publishes.
fn release_dist(work: &Path, binary: &Path) -> PathBuf {
    let target = host_target();
    let built = work.join(format!("herculean/target/{target}/release"));
    fs::create_dir_all(&built).unwrap();
    fs::copy(binary, built.join("herculean")).unwrap();
    for file in ["LICENSE", "README.md", "herculean/read-only-role.sql"] {
        fs::copy(repo_root().join(file), work.join(file)).unwrap();
    }
    let release = yaml(".github/workflows/release.yml");
    let package = step(&release["jobs"]["build"]["steps"], "Package")["run"]
        .as_str()
        .unwrap()
        .replace("${{ matrix.target }}", &target)
        .replace("${{ runner.os }}", "Linux");
    ok(run_script(
        &package,
        work,
        &[("PATH", "/usr/bin:/bin".into())],
    ));
    let dist = work.join("dist");
    let checksums = step(&release["jobs"]["publish"]["steps"], "Checksums")["run"]
        .as_str()
        .unwrap();
    let path = "/usr/bin:/bin:/usr/sbin:/sbin".into(); // macOS keeps sha256sum in /sbin
    ok(run_script(checksums, &dist, &[("PATH", path)]));
    dist
}

#[test]
fn release_archive_holds_the_read_only_role_sql_and_sha256sums_covers_it() {
    let work = TempDir::new();
    let dist = release_dist(&work.0, Path::new(env!("CARGO_BIN_EXE_herculean")));
    let name = format!("herculean-{}", host_target());
    let listing = ok(Command::new("tar")
        .arg("-tzf")
        .arg(dist.join(format!("{name}.tar.gz")))
        .output()
        .unwrap());
    for file in ["herculean", "read-only-role.sql", "LICENSE", "README.md"] {
        let entry = format!("{name}/{file}");
        assert!(listing.lines().any(|l| l == entry), "{entry}:\n{listing}");
    }
    let sums = fs::read_to_string(dist.join("SHA256SUMS")).unwrap();
    assert!(
        sums.lines()
            .any(|l| l.ends_with(&format!("  {name}.tar.gz"))),
        "{sums}"
    );
}

#[test]
fn release_gate_passes_only_when_the_named_mapping_test_ran_and_passed() {
    let release = yaml(".github/workflows/release.yml");
    // One ubuntu job that every build leg waits for, not a step on each leg.
    let job = &release["jobs"]["mapping-gate"];
    assert!(job["strategy"].is_null(), "{job:?}");
    assert_eq!(job["runs-on"].as_str(), Some("ubuntu-latest"));
    assert_eq!(
        release["jobs"]["build"]["needs"].as_str(),
        Some("mapping-gate")
    );
    let gate = step(&job["steps"], "The shipped SOC 2 mapping is verified")["run"]
        .as_str()
        .unwrap();
    let work = TempDir::new();
    // A cargo that records its arguments and prints `cargo-output`, as `cargo test` would.
    let cargo = work.0.join("cargo");
    fs::write(
        &cargo,
        "#!/bin/sh\necho \"$*\" > cargo-args\ncat cargo-output\n",
    )
    .unwrap();
    fs::set_permissions(&cargo, fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!("{}:/usr/bin:/bin", work.0.display());
    for (output, passes) in [
        ("running 1 test\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.00s\n", true),
        // The test was renamed or moved: the filter matches nothing and cargo still exits 0.
        ("running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.00s\n", false),
    ] {
        fs::write(work.0.join("cargo-output"), output).unwrap();
        let out = run_script(gate, &work.0, &[("PATH", path.clone())]);
        assert_eq!(out.status.success(), passes, "{output}{out:?}");
    }
    let args = fs::read_to_string(work.0.join("cargo-args")).unwrap();
    assert!(
        args.contains("--exact soc2::tests::shipped_mapping_has_no_unverified_entries"),
        "{args}"
    );
}

/// A runner for action.yml's steps: the action checked out at the repo root, RUNNER_TEMP,
/// GITHUB_PATH and GITHUB_OUTPUT under `dir`, and a `cargo` that only records its arguments.
struct ActionRunner {
    dir: PathBuf,
    action_ref: String,
    /// `github.action_repository`: the repo the workflow's `uses:` names.
    action_repository: String,
    /// HERCULEAN_DOWNLOAD_URL in the job's environment: where install.sh finds the release.
    download_url: String,
}

impl ActionRunner {
    fn new(dir: &Path, action_ref: &str, release: &Path) -> ActionRunner {
        let bin = dir.join("fake-cargo");
        fs::create_dir_all(&bin).unwrap();
        fs::create_dir_all(dir.join("runner-temp")).unwrap();
        let cargo = bin.join("cargo");
        let log = dir.join("cargo.log");
        fs::write(
            &cargo,
            format!("#!/bin/sh\necho \"$*\" >> '{}'\n", log.display()),
        )
        .unwrap();
        fs::set_permissions(&cargo, fs::Permissions::from_mode(0o755)).unwrap();
        ActionRunner {
            dir: dir.into(),
            action_ref: action_ref.into(),
            action_repository: "Herculean-io/herculean".into(),
            download_url: format!("file://{}", release.display()),
        }
    }

    fn runner_temp(&self) -> String {
        self.dir.join("runner-temp").display().to_string()
    }

    /// What the fake `cargo` was asked to do, one call per line.
    fn cargo_calls(&self) -> String {
        fs::read_to_string(self.dir.join("cargo.log")).unwrap_or_default()
    }

    fn github_path(&self) -> String {
        fs::read_to_string(self.dir.join("github_path")).unwrap_or_default()
    }

    fn github_output(&self) -> String {
        fs::read_to_string(self.dir.join("github_output")).unwrap_or_default()
    }

    /// Runs the step called `name`, its `env:` expressions expanded from `inputs` (the Action's
    /// `with:`, defaults applied) and the action ref. PATH holds what earlier steps added to
    /// GITHUB_PATH (newest first), then the fake cargo and the system tools.
    fn run(&self, name: &str, inputs: &[(&str, &str)]) -> Output {
        let action = yaml("action.yml");
        let step = step(&action["runs"]["steps"], name);
        let mut path: Vec<String> = self.github_path().lines().rev().map(String::from).collect();
        path.push(self.dir.join("fake-cargo").display().to_string());
        path.push("/usr/bin:/bin".into());
        let mut env = vec![
            ("RUNNER_TEMP", self.runner_temp()),
            (
                "GITHUB_PATH",
                self.dir.join("github_path").display().to_string(),
            ),
            (
                "GITHUB_OUTPUT",
                self.dir.join("github_output").display().to_string(),
            ),
            ("GITHUB_ACTION_PATH", repo_root().display().to_string()),
            ("HOME", self.dir.display().to_string()),
            ("HERCULEAN_DOWNLOAD_URL", self.download_url.clone()),
            ("PATH", path.join(":")),
        ];
        for (key, value) in step["env"].as_mapping().into_iter().flatten() {
            let expr = value.as_str().unwrap();
            let value = if expr == "${{ github.action_ref }}" {
                self.action_ref.clone()
            } else if expr == "${{ github.action_repository }}" {
                self.action_repository.clone()
            } else {
                let input = expr
                    .strip_prefix("${{ inputs.")
                    .and_then(|e| e.strip_suffix(" }}"))
                    .unwrap_or_else(|| panic!("unexpected expression {expr}"));
                let given = inputs.iter().find(|(k, _)| *k == input).map(|(_, v)| *v);
                given
                    .or(action["inputs"][input]["default"].as_str())
                    .unwrap()
                    .to_string()
            };
            env.push((key.as_str().unwrap(), value));
        }
        run_script(step["run"].as_str().unwrap(), &repo_root(), &env)
    }
}

#[test]
fn action_on_a_release_tag_installs_the_checksummed_binary_without_building() {
    let work = TempDir::new();
    let release = release_dist(
        &work.0.join("checkout"),
        Path::new(env!("CARGO_BIN_EXE_herculean")),
    );
    let tag = format!("v{}", env!("CARGO_PKG_VERSION"));
    let runner = ActionRunner::new(&work.0, &tag, &release);

    ok(runner.run("Install herculean", &[]));
    assert_eq!(runner.cargo_calls(), "", "the Action built herculean");
    let bin = format!("{}/herculean/bin", runner.runner_temp());
    assert_eq!(runner.github_path(), format!("{bin}\n"));
    let version = Command::new(format!("{bin}/herculean"))
        .arg("--version")
        .output()
        .unwrap();
    assert_eq!(
        ok(version),
        format!("herculean {}\n", env!("CARGO_PKG_VERSION"))
    );

    // The report step finds the installed binary on its own PATH.
    let out = work.0.join("report");
    let clean_app = repo_root().join("examples/clean-app");
    ok(runner.run(
        "Run herculean report",
        &[
            ("out", out.to_str().unwrap()),
            ("repo", clean_app.to_str().unwrap()),
        ],
    ));
    assert_eq!(runner.github_output(), "code=0\n");
    assert!(out.join("readiness.md").exists());
}

#[test]
fn action_builds_with_cargo_when_the_release_has_no_binary_for_the_runner() {
    let work = TempDir::new();
    let empty_release = work.0.join("empty-release");
    fs::create_dir_all(&empty_release).unwrap();
    let tag = format!("v{}", env!("CARGO_PKG_VERSION"));
    let runner = ActionRunner::new(&work.0, &tag, &empty_release);

    ok(runner.run("Install herculean", &[]));
    assert_eq!(
        runner.cargo_calls(),
        format!(
            "install --locked --root {}/herculean --path {}/herculean\n",
            runner.runner_temp(),
            repo_root().display()
        )
    );
}

#[test]
fn action_on_a_branch_builds_with_cargo_into_the_same_directory() {
    let work = TempDir::new();
    let runner = ActionRunner::new(&work.0, "main", &work.0);

    ok(runner.run("Install herculean", &[]));
    assert_eq!(
        runner.cargo_calls(),
        format!(
            "install --locked --root {}/herculean --path {}/herculean\n",
            runner.runner_temp(),
            repo_root().display()
        )
    );
    assert_eq!(
        runner.github_path(),
        format!("{}/herculean/bin\n", runner.runner_temp())
    );
}

#[test]
fn action_fails_when_the_release_archive_fails_its_checksum() {
    let work = TempDir::new();
    let release = release_dist(
        &work.0.join("checkout"),
        Path::new(env!("CARGO_BIN_EXE_herculean")),
    );
    // A corrupt or tampered archive: one byte differs from what SHA256SUMS records.
    let archive = release.join(format!("herculean-{}.tar.gz", host_target()));
    let mut bytes = fs::read(&archive).unwrap();
    bytes[100] ^= 0xff;
    fs::write(&archive, bytes).unwrap();
    let tag = format!("v{}", env!("CARGO_PKG_VERSION"));
    let runner = ActionRunner::new(&work.0, &tag, &release);

    let out = runner.run("Install herculean", &[]);
    assert_eq!(out.status.code(), Some(3), "{out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains(&format!(
            "::error::herculean: release {tag} failed checksum verification"
        )),
        "{stdout}"
    );
    assert_eq!(runner.cargo_calls(), "", "the Action built herculean");
    let bin = format!("{}/herculean/bin/herculean", runner.runner_temp());
    assert!(!Path::new(&bin).exists());
}

#[test]
fn action_builds_with_cargo_when_the_release_binary_does_not_run_here() {
    let work = TempDir::new();
    // Stands in for a binary this runner cannot execute, such as one built against a newer glibc.
    let broken = work.0.join("broken-herculean");
    fs::write(&broken, "#!/bin/sh\nexit 127\n").unwrap();
    fs::set_permissions(&broken, fs::Permissions::from_mode(0o755)).unwrap();
    let release = release_dist(&work.0.join("checkout"), &broken);
    let tag = format!("v{}", env!("CARGO_PKG_VERSION"));
    let runner = ActionRunner::new(&work.0, &tag, &release);

    ok(runner.run("Install herculean", &[]));
    assert_eq!(
        runner.cargo_calls(),
        format!(
            "install --locked --root {}/herculean --path {}/herculean\n",
            runner.runner_temp(),
            repo_root().display()
        )
    );
    let bin = format!("{}/herculean/bin/herculean", runner.runner_temp());
    assert!(
        !Path::new(&bin).exists(),
        "install.sh installed a binary that does not run"
    );
}

#[test]
fn action_ref_input_beats_the_action_ref_and_builds_that_commit_with_cargo() {
    let work = TempDir::new();
    // The action's own tag has an installable release, which `ref` must override.
    let release = release_dist(
        &work.0.join("checkout"),
        Path::new(env!("CARGO_BIN_EXE_herculean")),
    );
    let tag = format!("v{}", env!("CARGO_PKG_VERSION"));
    let runner = ActionRunner::new(&work.0, &tag, &release);
    let sha = "0123456789abcdef0123456789abcdef01234567";

    ok(runner.run("Install herculean", &[("ref", sha)]));
    assert_eq!(
        runner.cargo_calls(),
        format!(
            "install --locked --root {}/herculean --git https://github.com/Herculean-io/herculean --rev {sha} herculean\n",
            runner.runner_temp()
        )
    );
}

#[test]
fn action_ref_input_naming_a_branch_builds_that_branch_with_cargo() {
    let work = TempDir::new();
    let runner = ActionRunner::new(&work.0, "main", &work.0);

    // cargo's `--rev` takes commits and tags only; a branch needs `--branch`.
    ok(runner.run("Install herculean", &[("ref", "feature/x")]));
    assert_eq!(
        runner.cargo_calls(),
        format!(
            "install --locked --root {}/herculean --git https://github.com/Herculean-io/herculean --branch feature/x herculean\n",
            runner.runner_temp()
        )
    );
}

#[test]
fn a_fork_of_the_action_at_a_release_tag_builds_its_own_code() {
    let work = TempDir::new();
    // Upstream has a release at this tag; a fork or mirror must not install it.
    let release = release_dist(
        &work.0.join("checkout"),
        Path::new(env!("CARGO_BIN_EXE_herculean")),
    );
    let tag = format!("v{}", env!("CARGO_PKG_VERSION"));
    let mut runner = ActionRunner::new(&work.0, &tag, &release);
    runner.action_repository = "myorg/herculean-fork".into();

    ok(runner.run("Install herculean", &[]));
    assert_eq!(
        runner.cargo_calls(),
        format!(
            "install --locked --root {}/herculean --path {}/herculean\n",
            runner.runner_temp(),
            repo_root().display()
        )
    );
}
