//! `herculean report`: SOC 2 readiness summary and evidence pack, driven by the
//! check -> criteria/severity mapping in `soc2-mapping.yaml` (data, not code).

use crate::{Finding, Report, SkippedCheck};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// The mapping shipped with Herculean, used unless `--mapping` overrides it.
pub const DEFAULT_MAPPING: &str = include_str!("../soc2-mapping.yaml");

#[derive(Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
}

/// `low`, `medium` or `high`, as the mapping file spells them.
impl std::str::FromStr for Severity {
    type Err = serde_json::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_value(Value::String(s.into()))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mapping {
    criteria: Vec<Criterion>,
    checks: BTreeMap<String, CheckMapping>,
    /// Hex SHA-256 of the mapping text: readiness.md names the mapping it came from.
    #[serde(skip)]
    sha256: String,
}

impl Mapping {
    /// IDs of the criteria a qualified human has not yet verified against the AICPA TSC.
    fn unverified(&self) -> Vec<&str> {
        self.criteria
            .iter()
            .filter(|c| c.verify_before_release)
            .map(|c| c.id.as_str())
            .collect()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Criterion {
    id: String,
    title: String,
    verify_before_release: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckMapping {
    severity: Severity,
    criteria: Vec<String>,
}

pub fn parse_mapping(text: &str) -> Result<Mapping, String> {
    let mut mapping: Mapping = serde_norway::from_str(text).map_err(|e| e.to_string())?;
    mapping.sha256 = crate::hex(&Sha256::digest(text));
    // The id names the evidence file: a plain file name only.
    for c in &mapping.criteria {
        let plain =
            c.id.chars()
                .all(|ch| ch.is_ascii_alphanumeric() || "._-".contains(ch));
        if c.id.is_empty() || !plain || c.id == "." || c.id == ".." {
            return Err(format!(
                "criterion id {:?} must be [A-Za-z0-9._-]+ and not . or ..",
                c.id
            ));
        }
        // An evidence file with no items fails the verify step.
        if !mapping.checks.values().any(|m| m.criteria.contains(&c.id)) {
            return Err(format!("criterion {} has no check mapped to it", c.id));
        }
    }
    for (check, m) in &mapping.checks {
        for id in &m.criteria {
            if !mapping.criteria.iter().any(|c| &c.id == id) {
                return Err(format!("check {check} maps to unlisted criterion {id}"));
            }
        }
    }
    Ok(mapping)
}

/// What `sha256` covers and how; bump it when either changes (ADR 0004).
const ENVELOPE_VERSION: u32 = 1;

#[derive(Serialize)]
struct EvidenceItem<'a> {
    envelope_version: u32,
    criterion: &'a str,
    check: &'a str,
    /// findings_open | no_findings | not_run: never a pass/attestation verdict.
    result: &'static str,
    timestamp: &'a str,
    herculean_version: &'static str,
    notes: &'a [String],
    skipped_checks: &'a [SkippedCheck],
    /// repo_head, catalog_sha256 (digest of the catalog rows read), data_map_sha256.
    provenance: &'a Value,
    findings: Vec<&'a Finding>,
    /// SHA-256 of this item without `sha256`, as JSON with sorted keys and no whitespace.
    #[serde(skip_serializing_if = "String::is_empty")]
    sha256: String,
}

/// The documented verify step, run in the pack directory (ADR 0004).
const VERIFY: &str = "\n## Verifying this pack\n\n\
Each evidence item carries `sha256`: the SHA-256 of the item without that field, as JSON with \
sorted keys and no whitespace. It covers the result, findings, notes, skipped checks, timestamp, \
version and provenance: the repo's HEAD commit, a digest of the catalog rows read and a digest of \
the data map in `report.json`. The step also lists every evidence file Herculean wrote with the \
SHA-256 of the whole file. Run this in the pack directory (it needs `jq` and `shasum`); it prints \
`pack verifies`, or exits non-zero if a listed evidence file is missing or differs in any byte \
(an item edited, added or removed), an item or the data map changed after Herculean wrote them, \
or an evidence file is unreadable or has no items:\n\n\
```sh
set -eu
command -v jq >/dev/null && command -v shasum >/dev/null || { echo 'needs jq and shasum' >&2; exit 1; }
shasum -a 256 -c <<'EOF'
{files}EOF
map=$(jq -cSj .data_map report.json | shasum -a 256 | cut -d ' ' -f 1)
for f in evidence/*.json; do
  items=$(jq -ce '.items[]' \"$f\") || { echo \"$f: no readable items\" >&2; exit 1; }
  printf '%s\\n' \"$items\" | while read -r item; do
    want=$(printf '%s' \"$item\" | jq -r '.sha256 + \" \" + .provenance.data_map_sha256')
    got=$(printf '%s' \"$item\" | jq -cSj 'del(.sha256)' | shasum -a 256 | cut -d ' ' -f 1)
    [ \"$want\" = \"$got $map\" ] || { echo \"$f: an item does not verify\" >&2; exit 1; }
  done
done
echo 'pack verifies'
```

Anyone who can edit the pack can also recompute these hashes, so they show tampering only while \
the pack is kept where it cannot be rewritten: store or sign this pack outside the repository.\n";

/// Writes `readiness.md`, `evidence/<criterion>.json` and `report.json` into
/// `out`; returns the stdout summary. `not_run` lists checks that did not run.
pub fn write(
    report: &Report,
    mapping: &Mapping,
    not_run: &[&str],
    now: &str,
    repo_head: Option<&str>,
    out: &Path,
) -> Result<String, String> {
    let findings = &report.findings;
    // Sorted keys and no whitespace, as the hash contract (ADR 0004) says.
    let data_map = serde_json::to_value(&report.data_map).map_err(|e| e.to_string())?;
    let provenance = json!({
        "repo_head": repo_head,
        "catalog_sha256": report.catalog_sha256,
        "data_map_sha256": crate::hex(&Sha256::digest(data_map.to_string())),
    });
    // Notes on unread input come first, every note on each incomplete_input
    // source; the rest are informational and leave every count standing.
    let (unread, info) = report.notes.split_at(report.unread_notes);
    if let Some(f) = findings
        .iter()
        .find(|f| !mapping.checks.contains_key(f.check))
    {
        return Err(format!("check \"{}\" is not in the SOC 2 mapping", f.check));
    }
    let io = |e: std::io::Error| e.to_string();
    let evidence_dir = out.join("evidence");
    // A repo can commit symlinks anywhere on the way to the out dir: refuse
    // before creating or deleting anything. Links in `/` itself (macOS `/var`,
    // `/tmp`) are the system's, not the repo's.
    let mut walked = PathBuf::new();
    for part in evidence_dir.components() {
        walked.push(part);
        if walked.parent() != Some(Path::new("/"))
            && std::fs::symlink_metadata(&walked).is_ok_and(|m| m.is_symlink())
        {
            return Err(format!(
                "{} is a symlink; not writing there",
                walked.display()
            ));
        }
    }
    std::fs::create_dir_all(&evidence_dir).map_err(io)?;
    // Evidence from an earlier run's mapping must not linger; other files in
    // the dir are not ours. Earlier runs may have used the default mapping.
    let ours: Vec<String> = mapping
        .criteria
        .iter()
        .chain(
            parse_mapping(DEFAULT_MAPPING)
                .iter()
                .flat_map(|m| &m.criteria),
        )
        .map(|c| format!("{}.json", c.id))
        .collect();
    for entry in std::fs::read_dir(&evidence_dir).map_err(io)? {
        let entry = entry.map_err(io)?;
        if entry.file_type().map_err(io)?.is_file()
            && ours.contains(&entry.file_name().to_string_lossy().into_owned())
        {
            std::fs::remove_file(entry.path()).map_err(io)?;
        }
    }
    let version = env!("CARGO_PKG_VERSION");
    // A custom mapping can clear the banner below, so the pack says which mapping it used.
    let shipped = crate::hex(&Sha256::digest(DEFAULT_MAPPING));
    let mapping_line = if mapping.sha256 == shipped {
        format!("SOC 2 mapping: built-in (sha256 {shipped}).")
    } else {
        format!(
            "SOC 2 mapping: custom file, sha256 {}; not the mapping shipped with this release.",
            mapping.sha256
        )
    };
    let unverified = mapping.unverified();
    let banner = if unverified.is_empty() {
        String::new()
    } else {
        format!(
            "Criterion IDs and titles must be verified against the AICPA Trust Services \
             Criteria before release. Not yet verified: {}.\n\n",
            unverified.join(", ")
        )
    };
    let mut md = format!(
        "# SOC 2 readiness summary\n\n\
         This is audit-ready evidence generated by herculean {version} at {now}. \
         It lists open findings per criterion; it is not an auditor's opinion.\n\n\
         {mapping_line}\n\n\
         {banner}\
         A broad role grant is any privilege on a personal-data table granted to a group role \
         (a role with at least one member), other than the table owner. Grants to `PUBLIC` are \
         reported separately; login roles without members, such as an application's role, are not \
         reported. Column-level grants are reported only when `SELECT` is granted to `PUBLIC`.\n"
    );
    let mut stdout = format!(
        "herculean report: audit-ready evidence in {}\n",
        out.display()
    );
    let mut list = |heading: &str, notes: &[String]| {
        if !notes.is_empty() {
            md.push_str(heading);
        }
        for note in notes {
            // One line each, whatever a name in it holds.
            let note = note.replace(char::is_control, " ");
            let _ = writeln!(md, "- {note}");
            let _ = writeln!(stdout, "note: {note}");
        }
    };
    list(
        "\n## Input not fully read\n\n\
         Findings may be incomplete: each source below is also a \
         `data_map/incomplete_input` finding.\n\n",
        unread,
    );
    list("\n## Notes\n\n", info);
    // `shasum -c` lines for every evidence file: the verify step's expected set.
    let mut files = String::new();
    for criterion in &mapping.criteria {
        let id = criterion.id.as_str();
        let mut items = Vec::new();
        for (check, _) in mapping
            .checks
            .iter()
            .filter(|(_, m)| m.criteria.iter().any(|c| c == id))
        {
            let check_findings: Vec<&Finding> =
                findings.iter().filter(|f| f.check == *check).collect();
            let result = if not_run.contains(&check.as_str()) {
                "not_run"
            } else if check_findings.is_empty() {
                "no_findings"
            } else {
                "findings_open"
            };
            let mut item = EvidenceItem {
                envelope_version: ENVELOPE_VERSION,
                criterion: id,
                check,
                result,
                timestamp: now,
                herculean_version: version,
                notes: &report.notes,
                skipped_checks: &report.skipped_checks,
                provenance: &provenance,
                findings: check_findings,
                sha256: String::new(),
            };
            // Without its (empty) sha256; serde_json's Value sorts keys, as `jq -S` does.
            let envelope = serde_json::to_value(&item).map_err(|e| e.to_string())?;
            item.sha256 = crate::hex(&Sha256::digest(envelope.to_string()));
            items.push(item);
        }
        let verify = if criterion.verify_before_release {
            " (verify against the AICPA TSC before release)"
        } else {
            ""
        };
        let not_run = items.iter().filter(|i| i.result == "not_run").count();
        // Some input went unread: only data_map's count still holds.
        let partly = |i: &EvidenceItem| !unread.is_empty() && i.check != "data_map";
        let unread_items = items.iter().any(partly);
        let status = match not_run {
            0 if !unread_items => format!(
                "{} open finding(s)",
                items.iter().map(|i| i.findings.len()).sum::<usize>()
            ),
            n if n == items.len() => "not run".into(),
            _ => "partly run".into(),
        };
        let _ = write!(
            md,
            "\n## {id} {}{verify}\n\nStatus: {status}\n\n\
             | Check | Result | Open findings |\n|---|---|---|\n",
            criterion.title
        );
        for i in &items {
            let (result, count) = match i.result {
                "not_run" => ("not_run".into(), "-".into()),
                r if partly(i) => (format!("{r} (partly run)"), i.findings.len().to_string()),
                r => (r.into(), i.findings.len().to_string()),
            };
            let _ = writeln!(md, "| {} | {result} | {count} |", i.check);
        }
        let _ = writeln!(md, "\nEvidence: `evidence/{id}.json`");
        let _ = writeln!(
            stdout,
            "{id} {}: {status}, evidence/{id}.json",
            criterion.title
        );
        let mut evidence = json!({
            "criterion": id,
            "title": criterion.title,
            "verify_before_release": criterion.verify_before_release,
            "status": status,
            "items": items,
        });
        if !unread.is_empty() {
            evidence["notes"] = json!(unread);
        }
        let text = serde_json::to_string_pretty(&evidence).map_err(|e| e.to_string())? + "\n";
        replace(&evidence_dir.join(format!("{id}.json")), &text).map_err(io)?;
        let _ = writeln!(
            files,
            "{}  evidence/{id}.json",
            crate::hex(&Sha256::digest(&text))
        );
    }
    md.push_str(&VERIFY.replace("{files}", &files));
    replace(&out.join("readiness.md"), &md).map_err(io)?;
    // Through a Value: sorted keys, as report.json has always been written.
    let report = serde_json::to_value(report).map_err(|e| e.to_string())?;
    let text = serde_json::to_string_pretty(&report).map_err(|e| e.to_string())? + "\n";
    replace(&out.join("report.json"), &text).map_err(io)?;
    Ok(stdout)
}

/// Writes `path` through a fresh temp file renamed over it: a symlink already
/// at `path` is replaced, never followed.
pub fn replace(path: &Path, text: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{}.tmp", std::process::id()));
    let tmp = path.with_file_name(name);
    let _ = std::fs::remove_file(&tmp);
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .and_then(|mut f| f.write_all(text.as_bytes()));
    written
        .and_then(|_| std::fs::rename(&tmp, path))
        .inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp);
        })
}

/// Whether any finding's check has a severity at or above `threshold`.
/// Incomplete input meets every threshold: unread input cannot be called clean.
pub fn meets(report: &Report, mapping: &Mapping, threshold: Severity) -> bool {
    report.findings.iter().any(|f| {
        f.kind == "incomplete_input"
            || mapping
                .checks
                .get(f.check)
                .is_some_and(|m| m.severity >= threshold)
    })
}

/// The commit checked out at `repo`, if it is in a git repository.
pub fn repo_head(repo: &Path) -> Option<String> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "--verify", "--quiet", "HEAD"])
        .output()
        .ok()?;
    let head = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (out.status.success() && !head.is_empty() && head.chars().all(|c| c.is_ascii_hexdigit()))
        .then_some(head)
}

/// RFC 3339 UTC: the system clock, or `HERCULEAN_NOW` in debug builds (tests).
pub fn now() -> String {
    if cfg!(debug_assertions) {
        if let Ok(now) = std::env::var("HERCULEAN_NOW") {
            return now;
        }
    }
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let (days, rem) = (secs / 86400, secs % 86400);
    // Howard Hinnant's civil_from_days, for days since 1970-01-01 >= 0.
    let z = days + 719_468;
    let (era, doe) = (z / 146_097, z % 146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    /// Release gate, run by release.yml with `--ignored`: it fails until a
    /// qualified human has verified every shipped criterion (soc2-mapping.yaml).
    #[test]
    #[ignore = "release gate: fails until the shipped mapping is verified"]
    fn shipped_mapping_has_no_unverified_entries() {
        let mapping = super::parse_mapping(super::DEFAULT_MAPPING).unwrap();
        let unverified = mapping.unverified();
        assert!(
            unverified.is_empty(),
            "verify before release: {unverified:?}"
        );
        assert!(
            !super::DEFAULT_MAPPING.contains("(pending)"),
            "fill in every criterion's `Verified by` line in soc2-mapping.yaml"
        );
    }
}
