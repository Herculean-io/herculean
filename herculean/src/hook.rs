//! `herculean hook`: the Claude Code PostToolUse drift hook. Warns when an
//! edited migration defines personal data with no deletion path, or grants a
//! personal-data table to PUBLIC. Repo facts only, never a database.

use crate::{deletion_check, printable, repo, Overrides};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::Path;

/// The hook's stdout for a PostToolUse payload; None (no output) for an
/// unrelated change or anything it cannot read: a hook never breaks the session.
pub fn run(payload: &str) -> Option<String> {
    let payload: Value = serde_json::from_str(payload).ok()?;
    let root = Path::new(payload["cwd"].as_str()?).canonicalize().ok()?;
    let file = root
        .join(payload["tool_input"]["file_path"].as_str()?)
        .canonicalize()
        .ok()?;
    let meta = std::fs::metadata(&file).ok()?;
    if file.extension()? != "sql" || !meta.is_file() || meta.len() > repo::MAX_FILE_BYTES {
        return None;
    }
    let rel = repo::rel_path(&root, &file)?;
    let text = std::fs::read_to_string(&file).ok()?;
    let warnings = warnings(&root, &rel, &text)?;
    if warnings.is_empty() {
        return None;
    }
    let rel = printable(&rel, "/-");
    let context = format!(
        "herculean drift warning for {rel}:\n{}",
        warnings.join("\n")
    );
    let out = json!({
        "hookSpecificOutput": { "hookEventName": "PostToolUse", "additionalContext": context },
        "systemMessage": format!("herculean: personal-data drift in {rel}"),
    });
    Some(out.to_string())
}

/// One line per personal-data table this file leaves without a deletion path
/// or grants to PUBLIC; deletion paths come from the
/// `deletion_path` check over the whole repo.
fn warnings(root: &Path, rel: &str, text: &str) -> Option<Vec<String>> {
    let facts = crate::read_repo(root, None).ok()?;
    let file = repo::read_file(rel, text);
    let overrides = match crate::committed_data_map(root) {
        None => Overrides::new(),
        Some(text) => crate::parse_data_map(&text.ok()?).ok()?,
    };
    let (stores, _, findings) = deletion_check(&facts, &overrides, &BTreeSet::new(), "repo");
    let mut warnings = Vec::new();
    for store in &stores {
        let key = (store.schema.clone(), store.table.clone());
        let resource_id = format!("{}.{}", store.schema, store.table);
        let shown = printable(&resource_id, "");
        let Some(t) = file.tables.get(&key) else {
            continue;
        };
        let columns: Vec<&str> = store
            .columns
            .iter()
            .map(|c| c.name.as_str())
            .filter(|c| t.columns.iter().any(|(n, _)| n == c))
            .map(|c| printable(c, ""))
            .collect();
        let kinds: BTreeSet<&str> = findings
            .iter()
            .filter(|f| f.resource_id == resource_id)
            .map(|f| f.kind)
            .collect();
        if !columns.is_empty() && !kinds.is_empty() {
            warnings.push(format!(
                "- {shown}: personal data ({}) with no deletion path ({})",
                columns.join(", "),
                kinds.into_iter().collect::<Vec<_>>().join(", ")
            ));
        }
    }
    for (schema, table) in file
        .grants
        .iter()
        .filter(|(_, g)| g.iter().any(|(grantee, _)| grantee == "PUBLIC"))
        .map(|(key, _)| key)
    {
        if stores
            .iter()
            .any(|s| s.schema == *schema && s.table == *table)
        {
            let name = format!("{schema}.{table}");
            warnings.push(format!(
                "- {}: personal-data table granted to PUBLIC",
                printable(&name, "")
            ));
        }
    }
    Some(warnings)
}
