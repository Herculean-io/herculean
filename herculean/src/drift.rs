//! Repo-to-live drift: where the live schema differs from the migrations on
//! personal-data tables (tables, columns, foreign keys and their ON DELETE
//! rules, table grants).
//! Types, defaults and indexes are not compared.

use crate::steps::RECONCILE;
use crate::{is_personal, Facts, Finding, ForeignKey, Overrides};
use std::collections::{BTreeMap, BTreeSet};

/// Every table's owner and table privileges (grantee 0 is PUBLIC); a table
/// without grants gives one row with no grantee or privilege.
const GRANTS_SQL: &str = "SELECT n.nspname, c.relname, \
       pg_catalog.pg_get_userbyid(c.relowner)::text, \
       CASE WHEN acl.grantee = 0 THEN 'PUBLIC' \
            ELSE pg_catalog.pg_get_userbyid(acl.grantee)::text END, \
       acl.privilege_type \
     FROM pg_catalog.pg_class c \
     JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
     LEFT JOIN LATERAL pg_catalog.aclexplode(c.relacl) acl ON true \
     WHERE c.relkind IN ('r', 'p')";

/// Drift findings for every table that is personal on either side: `personal`
/// holds the live run's personal `schema.table` names; repo tables are
/// classified by overrides, the name rules and column comments.
pub fn findings(
    client: &mut crate::Catalog,
    live: &Facts,
    repo: &Facts,
    personal: &BTreeSet<String>,
    overrides: &Overrides,
    system_id: &str,
) -> Result<Vec<Finding>, postgres::Error> {
    let reader: String = client.query("SELECT current_user::text")?[0].get(0);
    let mut owners: BTreeMap<(String, String), String> = BTreeMap::new();
    let mut live_grants: BTreeMap<(String, String), BTreeSet<(String, String)>> = BTreeMap::new();
    for row in client.query(GRANTS_SQL)? {
        let key: (String, String) = (row.get(0), row.get(1));
        owners.insert(key.clone(), row.get(2));
        if let (Some(grantee), Some(privilege)) = (row.get(3), row.get(4)) {
            live_grants
                .entry(key)
                .or_default()
                .insert((grantee, privilege));
        }
    }
    let mut findings = Vec::new();
    let mut push = |kind, resource_id: &str, evidence: &str| {
        findings.push(Finding::treatment(
            "drift",
            kind,
            resource_id,
            RECONCILE,
            system_id,
            evidence,
        ))
    };
    let keys: BTreeSet<_> = live.tables.keys().chain(repo.tables.keys()).collect();
    for key in keys {
        let (schema, table) = key;
        let id = format!("{schema}.{table}");
        let (l, r) = (live.tables.get(key), repo.tables.get(key));
        let repo_personal = r.is_some_and(|r| {
            r.columns.iter().any(|(c, _)| {
                is_personal(
                    overrides,
                    schema,
                    table,
                    c,
                    r.markers.contains(c),
                    r.comments.get(c).map(String::as_str),
                )
            })
        });
        if !personal.contains(&id) && !repo_personal {
            continue;
        }
        let (l, r) = match (l, r) {
            (Some(_), None) => {
                push("extra_live_table", &id, &format!("pg_class:{id}"));
                continue;
            }
            (None, Some(r)) => {
                push("missing_live_table", &id, &r.evidence);
                continue;
            }
            (Some(l), Some(r)) => (l, r),
            (None, None) => unreachable!("key comes from one side"),
        };
        for (kind, from, other) in [("extra_live_column", l, r), ("missing_live_column", r, l)] {
            for (name, evidence) in &from.columns {
                if !other.columns.iter().any(|(n, _)| n == name) {
                    push(kind, &format!("{id}.{name}"), evidence);
                }
            }
        }
        for fk in &r.foreign_keys {
            match l.foreign_keys.iter().find(|f| same_key(f, fk)) {
                None => push("missing_live_fk", &id, &fk.evidence),
                Some(f) if f.on_delete != fk.on_delete => {
                    push("on_delete_mismatch", &id, &f.evidence)
                }
                Some(_) => {}
            }
        }
        for f in &l.foreign_keys {
            if !r.foreign_keys.iter().any(|fk| same_key(f, fk)) {
                push("extra_live_fk", &id, &f.evidence);
            }
        }
        // The same grantees are left out on both sides: the table owner, Herculean's
        // reader, and roles the migrations give default privileges (not modelled).
        let skip = |g: &String| {
            *g == reader || owners.get(key) == Some(g) || repo.default_grantees.contains(g)
        };
        let compared = |grants: Option<&BTreeSet<(String, String)>>| {
            let grants = grants.into_iter().flatten();
            grants
                .filter(|(g, _)| !skip(g))
                .cloned()
                .collect::<BTreeSet<_>>()
        };
        if compared(live_grants.get(key)) != compared(repo.grants.get(key)) {
            push("grant_mismatch", &id, &format!("pg_class.relacl:{id}"));
        }
    }
    Ok(findings)
}

/// Whether a live and a repo foreign key are the same key: same columns,
/// referenced table and referenced columns. A repo key that names no
/// referenced columns means the primary key, which repo facts don't record,
/// so it matches any referenced columns.
fn same_key(live: &ForeignKey, repo: &ForeignKey) -> bool {
    live.columns == repo.columns
        && live.references == repo.references
        && (repo.referred_columns.is_empty() || live.referred_columns == repo.referred_columns)
}
