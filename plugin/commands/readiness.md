---
description: Summarise SOC 2 data-handling readiness from the herculean evidence pack
allowed-tools: Bash(herculean:*)
---

Run this command from the repository root with the Bash tool, exactly as written:

```sh
herculean report --out .herculean --repo .
```

It writes the readiness summary to `.herculean/readiness.md`, an evidence item per criterion under `.herculean/evidence/`, and `.herculean/report.json`. When `HERCULEAN_DATABASE_URL` is set in the environment, the database's catalog (read-only) is included.

Then read `.herculean/readiness.md` and show it to the user: each criterion, its checks and their result. Mention where the evidence pack was written.

Report only what the files say. It is audit-ready evidence, not an auditor's opinion: never call the system compliant or say a criterion passed.

If the command fails because `herculean` is not installed, tell the user to install it with the install script (`curl -fsSL https://raw.githubusercontent.com/Herculean-io/herculean/main/install.sh | sh`), or by building it with `cargo install --locked --git https://github.com/Herculean-io/herculean herculean`. If it fails for another reason, show its error message.
