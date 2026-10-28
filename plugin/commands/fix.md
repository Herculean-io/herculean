---
description: Turn one herculean finding into a SQL migration on a branch and open a pull request for review
argument-hint: <check>/<kind>/<resource_id>
allowed-tools: Bash(herculean fix:*), Bash(git switch -c herculean/fix-:*), Bash(git add migrations/:*), Bash(git add db/migrations/:*), Bash(git add supabase/migrations/:*), Bash(git commit -m:*), Bash(git push -u origin herculean/fix-:*), Bash(gh pr create:*)
---

The finding selector is `$ARGUMENTS`, as `<check>/<kind>/<resource_id>` (from a `/herculean:scan` finding). If it contains anything other than letters, digits, `_`, `.` and `/`, do not run anything: tell the user the fix must be written by hand.

Before running anything, ask the user how many days rows should be kept before the generated purge deletes them (the retention period). Do not pick a value yourself. Use their answer in place of `<days>`; if it is not a whole number of at least 1, ask again.

From the repository root, run with the Bash tool, exactly as written, with the selector in single quotes:

```sh
herculean fix --finding '$ARGUMENTS' --repo . --retention-days <days>
```

It writes one SQL migration implementing only that finding's remediation, into the repo's migrations dir (the first of `migrations/`, `db/migrations/`, `supabase/migrations/`). It never runs the SQL. When `HERCULEAN_DATABASE_URL` is set, it reads the database's catalog (read-only). If it fails, show its error message and stop: it lists the available findings or the supported fixes, or says the fix must be written by hand. If `herculean` is not installed, tell the user to install it with the install script (`curl -fsSL https://raw.githubusercontent.com/Herculean-io/herculean/main/install.sh | sh`), or by building it with `cargo install --locked --git https://github.com/Herculean-io/herculean herculean`.

On success it prints a JSON object: `path`, `branch`, `commit_message` (also the pull request title) and `pr_body`. Use those values verbatim in the commands below, in place of `<path>`, `<branch>` and so on, keeping the single quotes. Do not put the selector or any other text of your own into these commands:

```sh
git switch -c <branch>
git add <path>
git commit -m '<commit_message>' -- <path>
git push -u origin <branch>
gh pr create --head <branch> --title '<commit_message>' --body '<pr_body>'
```

Commit only the generated file: `-- <path>` keeps anything else that is staged out of the commit. Never commit other files and never force-push. If `gh` is not available or `gh pr create` fails, tell the user the branch name so they can open the pull request themselves.

Do not edit the generated SQL, apply it, or connect to the database yourself. Show the user the file's contents and the pull request link.
