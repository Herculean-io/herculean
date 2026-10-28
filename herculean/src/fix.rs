//! `herculean fix`: the SQL migration implementing one finding's remediation.
//! Built from the report alone; it is written for review, never executed.

use crate::steps::Phase;
use crate::{printable, quote_ident, ForeignKey, Report, SOFT_DELETE_COLUMNS};

const SUPPORTED: &[&str] = &[
    "deletion_path/soft_delete_without_purge",
    "deletion_path/no_deletion_path",
    "deletion_path/fk_without_on_delete",
    "least_privilege/public_grant",
];

/// One finding's fix: the migration and the git / PR text for it, all built
/// from the finding's validated resource id and fixed text only.
pub struct Fix {
    pub file_name: String,
    pub sql: String,
    pub branch: String,
    /// Also the pull request title.
    pub commit_message: String,
    pub pr_body: String,
}

/// The fix for the finding `selector` (`<check>/<kind>/<resource_id>`), or why there is none.
pub fn migration(report: &Report, selector: &str, retention_days: u32) -> Result<Fix, String> {
    let selector_of = |f: &crate::Finding| format!("{}/{}/{}", f.check, f.kind, f.resource_id);
    let Some(finding) = report.findings.iter().find(|f| selector_of(f) == selector) else {
        let mut available: Vec<String> = report
            .findings
            .iter()
            .map(|f| format!("{}/{}/{}", f.check, f.kind, printable(&f.resource_id, "")))
            .collect();
        available.dedup();
        return Err(format!(
            "herculean: no finding {selector}; available: {}",
            available.join(", ")
        ));
    };
    let fix = format!("{}/{}", finding.check, finding.kind);
    if fix == "least_privilege/missing_rls" {
        return Err(format!(
            "herculean: no automatic fix for {fix}/{}: no row-level security policy can be \
             guessed safely. Write the policy by hand, with ENABLE and FORCE ROW LEVEL SECURITY \
             so the table owner is filtered too. A partition read directly bypasses its \
             parent's policies: give each partition the same policy, or revoke direct access to it.",
            printable(&finding.resource_id, "")
        ));
    }
    if !SUPPORTED.contains(&fix.as_str()) {
        return Err(format!(
            "herculean: no automatic fix for {fix}; supported: {}",
            SUPPORTED.join(", ")
        ));
    }
    let id = &finding.resource_id;
    // The id ends up in a file name, SQL comments, a branch name and git/gh
    // arguments: only plain identifier characters go there.
    if id.is_empty()
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
    {
        return Err(format!(
            "herculean: no automatic fix for {fix} on a table whose name has characters \
             outside [A-Za-z0-9_.]; the fix must be written by hand"
        ));
    }
    // Every (schema, table) the id can name; more than one is ambiguous.
    let matches: Vec<_> = id
        .match_indices('.')
        .filter_map(|(i, _)| {
            let key = (id[..i].to_string(), id[i + 1..].to_string());
            report.facts.tables.get_key_value(&key)
        })
        .collect();
    let ((schema, table), facts) = match matches.as_slice() {
        [one] => *one,
        [] => return Err(format!("herculean: no schema facts for {id}")),
        _ => {
            return Err(format!(
                "herculean: {id} names more than one table (a schema or table name \
                 contains a dot); the fix must be written by hand"
            ))
        }
    };
    let target = format!("{}.{}", quote_ident(schema), quote_ident(table));
    let has = |name: &str| facts.columns.iter().any(|(c, _)| c == name);
    let purge = |column: &str, note: String| {
        // ponytail: the soft-delete column's type is read from its name (`*_at` is a timestamp, else boolean).
        let condition = if column.ends_with("_at") {
            format!(
                "{} < now() - interval '{retention_days} days'",
                quote_ident(column)
            )
        } else {
            quote_ident(column)
        };
        format!(
            "{note}SELECT cron.schedule('herculean_purge__{schema}__{table}', '0 3 * * *', \
             $$DELETE FROM {target} WHERE {condition}$$);\n"
        )
    };
    let body = match finding.kind {
        "soft_delete_without_purge" => {
            // deleted_at when present; otherwise the one marker there is, never a guess.
            let markers: Vec<&str> = SOFT_DELETE_COLUMNS
                .iter()
                .copied()
                .filter(|c| has(c))
                .collect();
            let column = match markers.as_slice() {
                _ if markers.contains(&"deleted_at") => "deleted_at",
                [one] => *one,
                [] => return Err(format!("herculean: no soft-delete column on {id}")),
                _ => {
                    return Err(format!(
                        "herculean: {id} has more than one soft-delete marker ({}) and no \
                         deleted_at; its purge rule must be written by hand",
                        markers.join(", ")
                    ))
                }
            };
            let note = if column.ends_with("_at") {
                String::new()
            } else {
                format!(
                    "-- {column} is a boolean flag: rows are purged at the next run after\n\
                     -- they are marked; --retention-days does not apply.\n"
                )
            };
            purge(column, note)
        }
        "no_deletion_path" => {
            // Never updated_at: it would delete long-lived rows nobody has edited.
            let column = "created_at";
            if !has(column) {
                return Err(format!(
                    "herculean: {id} has no created_at column; \
                     its retention rule must be written by hand"
                ));
            }
            let note = format!(
                "-- WARNING: this purge deletes ALL rows of {id} whose {column} is older than\n\
                 -- {retention_days} days, not only rows marked deleted. Check the retention period.\n"
            );
            purge(column, note)
        }
        // Every foreign key on the table without a delete rule: they share the selector.
        "fk_without_on_delete" => {
            let changes: Vec<String> = facts
                .foreign_keys
                .iter()
                .filter(|fk| fk.lacks_on_delete())
                .map(|fk| {
                    let name = quote_ident(&fk.name);
                    format!(
                        "DROP CONSTRAINT {name}, ADD CONSTRAINT {name} {}",
                        cascading(fk)
                    )
                })
                .collect();
            format!("ALTER TABLE {target} {};\n", changes.join(", "))
        }
        // The finding is the whole table (relacl) and/or personal columns (attacl,
        // one finding per column, same selector).
        "public_grant" => {
            let column_prefix = format!("pg_attribute.attacl:{id}.");
            let (mut columns, mut whole_table) = (Vec::new(), false);
            for f in report
                .findings
                .iter()
                .filter(|f| selector_of(f) == selector)
            {
                match f
                    .steps
                    .first()
                    .and_then(|s| s.evidence_id.strip_prefix(&column_prefix))
                {
                    Some(column) => columns.push(quote_ident(column)),
                    None => whole_table = true,
                }
            }
            let mut sql = String::new();
            if whole_table {
                sql += &format!("REVOKE ALL ON {target} FROM PUBLIC;\n");
            }
            if !columns.is_empty() {
                sql += &format!(
                    "REVOKE SELECT ({}) ON {target} FROM PUBLIC;\n",
                    columns.join(", ")
                );
            }
            sql
        }
        _ => unreachable!("kind is in SUPPORTED"),
    };
    let operation = finding
        .steps
        .iter()
        .find(|s| s.phase == Phase::Remediation)
        .unwrap()
        .operation;
    let kind = finding.kind;
    Ok(Fix {
        // UTC `YYYYMMDDHHMMSS_` first, so the file sorts after the migrations before it.
        file_name: format!(
            "{}_herculean_fix_{kind}__{id}.sql",
            crate::soc2::now()
                .chars()
                .filter(char::is_ascii_digit)
                .take(14)
                .collect::<String>()
        ),
        sql: format!(
            "-- herculean fix: {selector}\n\
             -- remediation: {operation}\n\
             -- Review before applying; Herculean never applies changes.\n\n{body}"
        ),
        branch: format!("herculean/fix-{kind}-{schema}-{table}"),
        commit_message: format!("herculean fix: {selector}"),
        pr_body: format!(
            "Generated by herculean fix for the finding {selector} (remediation {operation}). \
             Review the migration before applying it: Herculean never applies changes to a database."
        ),
    })
}

/// The foreign key's definition with ON DELETE CASCADE, keeping its columns,
/// MATCH, ON UPDATE, deferrability and NOT VALID.
fn cascading(fk: &ForeignKey) -> String {
    let list = |names: &[String]| {
        let quoted: Vec<String> = names.iter().map(|n| quote_ident(n)).collect();
        quoted.join(", ")
    };
    let mut def = format!(
        "FOREIGN KEY ({}) REFERENCES {}.{}",
        list(&fk.columns),
        quote_ident(&fk.references.0),
        quote_ident(&fk.references.1)
    );
    if !fk.referred_columns.is_empty() {
        def += &format!(" ({})", list(&fk.referred_columns));
    }
    if fk.match_full {
        def += " MATCH FULL";
    }
    def += match fk.on_update {
        'r' => " ON UPDATE RESTRICT",
        'c' => " ON UPDATE CASCADE",
        'n' => " ON UPDATE SET NULL",
        'd' => " ON UPDATE SET DEFAULT",
        _ => "",
    };
    def += " ON DELETE CASCADE";
    if fk.deferrable {
        def += " DEFERRABLE";
    }
    if fk.deferred {
        def += " INITIALLY DEFERRED";
    }
    if !fk.validated {
        def += " NOT VALID";
    }
    def
}
