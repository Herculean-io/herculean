# Herculean

Herculean is a command-line tool that scans a Postgres database's schema (through a read-only role) and a repo's migrations and code for personal data. It reports the tables with no deletion path, the replication, triggers and foreign tables that copy it elsewhere or bring it back, roles with more access than they need, and drift between migrations and the live schema, then writes a SOC 2 readiness report with evidence files. It reads the system catalogs, not your rows (unless you pass `--sample`). The report states what Herculean found; it does not certify anything.

**New here? Start with [`docs/quickstart.md`](docs/quickstart.md)**: install, create the read-only role, get a first report in minutes.

## Layout

| path | what |
|---|---|
| `herculean/` | **Herculean CLI** (Rust, Apache-2.0, see [`LICENSE`](LICENSE)): maps personal data in Postgres and repos and writes findings plus a SOC 2 readiness report. Read-only role grant list: `herculean/read-only-role.sql` |
| `plugin/` | **Claude Code plugin**: `/herculean:scan`, `/herculean:readiness`, `/herculean:fix` (a finding becomes a reviewable migration PR), a drift hook and the `herculean mcp` server. Marketplace manifest: `.claude-plugin/marketplace.json` |
| `install.sh`, `.github/workflows/release.yml` | **Binary releases**: a `v*` tag builds `herculean` for Linux, macOS and Windows and publishes each archive (binary, `read-only-role.sql`, `LICENSE`) with `SHA256SUMS`; `install.sh` installs the right binary and checks it |
| `action.yml` | **GitHub Action**: runs `herculean report` on pull requests, uploads the report and fails the job at a severity threshold (`fail-on`). At a release tag (`@v0.2.0`) it installs that release's checksummed binary; at any other ref it builds from source |
| `examples/` | sample repos the CI runs the Action against: `sample-app/` (exits 2), `clean-app/` (exits 0) |

## License

Apache License 2.0: see [`LICENSE`](LICENSE).

This repository is published from Herculean's development repo. Open issues and pull requests here.
