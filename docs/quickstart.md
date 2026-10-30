# Quickstart

This takes you from nothing to a first report in a few minutes. Herculean runs on your machine or in your CI. It needs no Herculean service.

You need:

- The `herculean` binary: a prebuilt release, or Rust 1.88 or newer (`cargo`, from <https://rustup.rs>) and a C compiler to build it.
- `psql`, and a role on your database that can create roles (for example `postgres`).
- PostgreSQL 14 or newer (the least-privilege check reads membership in `pg_read_all_data`, which 14 added).

The commands below use a database called `mydb`. Replace it with yours. `psql` connects the way it usually does: set `PGHOST`, `PGPORT` and `PGUSER` for your admin role if the defaults are wrong.

CI runs every `sh` block on this page, in order, on a fresh runner. Keep them runnable.

## 1. Install

Each GitHub Release has prebuilt binaries for Linux (x86_64, arm64), macOS (Intel, Apple silicon) and Windows (x86_64),
with a `SHA256SUMS` file. On Linux and macOS, the install script downloads the right one, checks its checksum and puts it in
`~/.local/bin` (set `HERCULEAN_INSTALL_DIR` to change that, `HERCULEAN_VERSION=v0.2.0` to pin a release):

```text
curl -fsSL https://raw.githubusercontent.com/Herculean-io/herculean/main/install.sh | sh
```

On Windows, download `herculean-x86_64-pc-windows-msvc.zip` from the Releases page and unpack it.

To build from source instead, from a clone of this repo:

```text
git clone https://github.com/Herculean-io/herculean
cd herculean
```

```sh
cargo install --locked --path herculean
```

Or install straight from GitHub without cloning:

```text
cargo install --locked --git https://github.com/Herculean-io/herculean herculean
```

## 2. Create the read-only role

Herculean reads the system catalogs. It does not read rows from your tables. The full grant list is `herculean/read-only-role.sql`. Read it before you run it.

Pick a password for the new role, then create it:

```sh
export HERCULEAN_READER_PASSWORD='change-me-to-a-long-random-password'
psql -d mydb -v ON_ERROR_STOP=1 \
  -v role=herculean_reader \
  -v password="$HERCULEAN_READER_PASSWORD" \
  -v database=mydb \
  -f herculean/read-only-role.sql
```

If you installed without cloning, download the file for the version you installed, read it before you run it, then pass `-f read-only-role.sql`:
`curl -fsSLO "https://raw.githubusercontent.com/Herculean-io/herculean/v$(herculean --version | cut -d' ' -f2)/herculean/read-only-role.sql"`.

## 3. Point Herculean at the database

Herculean reads the connection string from `HERCULEAN_DATABASE_URL`. It never prints it.

```sh
export HERCULEAN_DATABASE_URL="host=localhost dbname=mydb user=herculean_reader password=$HERCULEAN_READER_PASSWORD"
```

A `postgres://` URL works too.

`sslmode` and `sslrootcert` work as in libpq. For any remote database and in CI, use `sslmode=verify-full`: it encrypts the connection and checks that the server's certificate is signed by a trusted CA and names the host you connect to. The trusted CAs are the Mozilla root CAs, or, with `sslrootcert=<path>`, the CA certificates in that PEM file instead. A private CA needs `sslrootcert`. For AWS RDS, download the RDS CA bundle (`global-bundle.pem`) and pass it:

```text
export HERCULEAN_DATABASE_URL="host=mydb.abc123.eu-west-1.rds.amazonaws.com dbname=mydb user=herculean_reader password=... sslmode=verify-full sslrootcert=/path/to/global-bundle.pem"
```

Per service:

- RDS / Aurora: direct needs `sslmode=verify-full sslrootcert=global-bundle.pem`. Through RDS Proxy the public (ACM) certificate works with no `sslrootcert`. https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html
- Cloud SQL: use `sslmode=verify-ca sslrootcert=server-ca.pem` (each instance has its own CA). https://docs.cloud.google.com/sql/docs/postgres/authorize-ssl
- AlloyDB: a direct connection supports only `sslmode=require` (no server authentication). Use the AlloyDB Auth Proxy. https://docs.cloud.google.com/alloydb/docs/choose-alloydb-connectivity
- Azure Flexible Server: `sslmode=verify-full` with no `sslrootcert` in public regions. https://learn.microsoft.com/en-us/azure/postgresql/security/security-tls
- Neon: `sslmode=verify-full` on the direct host (not the `-pooler` host, which drops the session's read-only setting), no `sslrootcert`. https://neon.com/docs/connect/connect-securely
- Supabase: `sslmode=verify-full sslrootcert=prod-ca-2021.crt`. In GitHub Actions use the session pooler (port 5432), because runners have no IPv6. https://supabase.com/docs/guides/platform/ssl-enforcement
- Supabase: expect one grant finding per older personal table (default grants to `anon` and `authenticated`). Purges run outside the database (app code, edge functions) are not seen.
- Herculean refuses the Supabase transaction pooler (`*.pooler.supabase.com:6543`). Use the direct host or the session pooler.
- Existing installs: re-running `read-only-role.sql` stops at `CREATE ROLE`. To get the role-level read-only guard, run `ALTER ROLE herculean_reader SET default_transaction_read_only = on;` instead.

The other modes:

- `verify-ca` checks the CA chain but not the host name.
- `require` encrypts but does not authenticate the server: anyone who can intercept the connection can pose as the database. With `sslrootcert` set, `require` acts as `verify-ca`, as in libpq.
- `prefer` (the default) uses TLS when the server offers it and otherwise connects without it. It does not check the certificate either, so keep it to local development.
- `disable` never uses TLS.

## 4. Run

`herculean scan` prints the data map and the findings as JSON:

```sh
herculean scan
```

`herculean report` writes the SOC 2 readiness report to a directory:

```sh
herculean report --out herculean-report --fail-on high || echo "herculean report exited $?"
```

The exit code tells CI what happened:

- `0`: no finding at or above `--fail-on`;
- `2`: at least one finding at or above `--fail-on` (low < medium < high);
- `1`: an error, for example a bad connection string.

## 5. Read the report

Open `herculean-report/readiness.md`. It lists each SOC 2 criterion, the open findings mapped to it, and the evidence file for it. The report states what Herculean found. It does not certify anything.

```sh
cat herculean-report/readiness.md
```

The other files:

- `herculean-report/report.json`: the full data map and every finding, with remediation and verification steps;
- `herculean-report/evidence/<criterion>.json`: one evidence item per criterion.

## Also scan your repo

Add `--repo <path>` to read migrations and code too. That adds the drift check, which compares migrations to the live schema. Schema facts come from the `*.sql` files in the migrations directory: `--migrations-dir <dir>` (relative to the repo), or else the first of `migrations/`, `db/migrations/` and `supabase/migrations/` that exists. With none of those, every `*.sql` file in the repo is read as a migration and the report says so in a note. `herculean fix` writes its migration into that same directory, and refuses when there is none. Down migrations (`down.sql`, `*.down.sql`) are never applied. Code that deletes rows is found in every file. Herculean applies migrations in path order, compared byte by byte (`001_init.sql` before `002_users.sql`, but `10_x.sql` before `9_x.sql`), so zero-pad numeric prefixes:

```text
herculean report --out herculean-report --repo . --fail-on high
```

With no `HERCULEAN_DATABASE_URL` set, `--repo` runs on the repo alone. Checks that need the database are listed as skipped.

```text
unset HERCULEAN_DATABASE_URL
herculean report --out herculean-report --repo . --fail-on high
```

## Commit the data map

`herculean scan --repo . --write-data-map` writes `data-map.yaml` at the repo root: the personal-data stores it found (each column's category, confidence and source), the data flows and the deletion paths. Commit it. Re-running it rewrites the generated sections and keeps your `overrides:` section as you wrote it:

```text
overrides:
  - column: public.orders.notes
    category: free_text
  - column: public.contacts.desk_phone
    personal: false
```

Overrides win over detection. With `--repo`, every command (and the Action, the plugin and its hook) uses the repo's `data-map.yaml` when there is one; `--data-map <path>` points elsewhere.

## Run it on pull requests

The GitHub Action in this repo (`action.yml`) installs Herculean, runs `herculean report`, uploads the report as an artifact, and fails the job at the threshold:

```text
- uses: actions/checkout@v4
- uses: Herculean-io/herculean@main
  with:
    repo: .
    fail-on: high
    # optional; without it the run is repo-only
    database-url: ${{ secrets.HERCULEAN_DATABASE_URL }}
```

Inputs: `repo` (default `.`), `fail-on` (default `high`), `out` (default `herculean-report`), `database-url`, `ref` (Herculean version to install; default: the action's own ref), `artifact-name` (default `herculean-report`). Output: `exit-code`.

At a release tag (`uses: Herculean-io/herculean@v<version>`, or `ref: v<version>`), the Action installs that release's prebuilt binary with `install.sh`, checked against its `SHA256SUMS`, without building. An archive that fails that check fails the step. A fork or mirror of the Action builds its own checkout instead, unless `ref` names a release. At a branch or commit, or on a runner with no prebuilt binary, it builds Herculean from source with `cargo install` (installing Rust if the runner has none). Either way the binary goes in `$RUNNER_TEMP/herculean/bin`, which the Action adds to `PATH` for the rest of the job.

## Use it from Claude Code

Install the plugin from this repo. It adds `/herculean:scan`, `/herculean:readiness`, `/herculean:fix`, a drift hook and an MCP server. All of them call the `herculean` binary from step 1, so install that first. Until you do, the commands tell you how to install it and the drift hook does nothing.

```text
claude plugin marketplace add Herculean-io/herculean
claude plugin install herculean@herculean
```

From a local clone, use `claude plugin marketplace add ./` instead.
