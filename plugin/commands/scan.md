---
description: Map personal data in this repo (and the database, if configured) and list its findings
allowed-tools: Bash(herculean:*)
---

Run this command from the repository root with the Bash tool, exactly as written:

```sh
herculean scan --repo .
```

It reads the repo's migrations and code, and applies the overrides in the repo's `data-map.yaml` if there is one. When `HERCULEAN_DATABASE_URL` is set in the environment, it also reads that database's catalog (read-only).

Show the user what the command printed. Its stdout is a JSON report:

- `data_map.stores`: the personal-data tables and columns it found, as a short table.
- `findings`: each finding's `check`, `kind` and `resource_id`, and its steps in order (`operation` and `evidence_id`).
- `notes` and `skipped_checks`, if present, as they are.

Report only what the output says. Do not add findings, rules or judgements of your own.

If the command fails because `herculean` is not installed, tell the user to install it with the install script (`curl -fsSL https://raw.githubusercontent.com/Herculean-io/herculean/main/install.sh | sh`), or by building it with `cargo install --locked --git https://github.com/Herculean-io/herculean herculean`. If it fails for another reason, show its error message.
