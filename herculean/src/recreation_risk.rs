//! Recreation-risk check: catalog objects that copy personal data elsewhere, or back.

use crate::steps::DISABLE;
use crate::{is_personal, Finding, Flow, Overrides};
use std::collections::BTreeSet;

/// Tables each publication ships (FOR ALL TABLES, TABLES IN SCHEMA and explicit
/// lists alike), with partitions mapped to their partitioned root.
const PUBLICATIONS_SQL: &str = "SELECT DISTINCT pt.pubname::text, rn.nspname, rc.relname \
     FROM pg_catalog.pg_publication_tables pt \
     JOIN pg_catalog.pg_namespace n ON n.nspname = pt.schemaname \
     JOIN pg_catalog.pg_class c ON c.relnamespace = n.oid AND c.relname = pt.tablename \
     JOIN pg_catalog.pg_class rc ON rc.oid = COALESCE(pg_catalog.pg_partition_root(c.oid), c.oid) \
     JOIN pg_catalog.pg_namespace rn ON rn.oid = rc.relnamespace";

/// Tables this database's subscriptions replicate in. Explicit columns only:
/// pg_subscription.subconninfo is not readable by non-superusers.
const SUBSCRIPTIONS_SQL: &str = "SELECT s.subname::text, n.nspname, c.relname \
     FROM pg_catalog.pg_subscription_rel sr \
     JOIN pg_catalog.pg_subscription s ON s.oid = sr.srsubid \
     JOIN pg_catalog.pg_class c ON c.oid = sr.srrelid \
     JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
     JOIN pg_catalog.pg_database d ON d.oid = s.subdbid \
     WHERE d.datname = pg_catalog.current_database()";

/// User triggers, their function's source (pg_proc.prosrc is PUBLIC-readable)
/// and schema. The function is never run.
const TRIGGERS_SQL: &str = "SELECT n.nspname, c.relname, t.tgname::text, p.prosrc, pn.nspname \
     FROM pg_catalog.pg_trigger t \
     JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid \
     JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
     JOIN pg_catalog.pg_proc p ON p.oid = t.tgfoid \
     JOIN pg_catalog.pg_namespace pn ON pn.oid = p.pronamespace \
     WHERE NOT t.tgisinternal";

/// The channel a trigger function sends rows out of the database through, if
/// any: a Supabase Database Webhook (function in `supabase_functions`), or a
/// pg_net / http / aws_lambda call in its body.
// ponytail: substring match on the body, like insert_target; `http_` also hits
// identifiers such as `http_status`, which over-reports rather than misses.
fn export_channel(function_schema: &str, source: &str) -> Option<&'static str> {
    if function_schema == "supabase_functions" {
        return Some("supabase_functions");
    }
    let source = source.to_ascii_lowercase();
    ["aws_lambda.invoke", "http_"]
        .into_iter()
        .find(|call| source.contains(call))
}

/// The table after the first `INSERT INTO` in a function body, if any.
// ponytail: first INSERT only, no SQL parsing; dynamic SQL (EXECUTE format(...)) is missed.
fn insert_target(source: &str) -> Option<String> {
    let at = source.to_ascii_lowercase().find("insert into")? + "insert into".len();
    let name = source[at..]
        .split(|c: char| c.is_whitespace() || c == '(' || c == ';')
        .find(|word| !word.is_empty())?;
    Some(name.replace('"', ""))
}

/// Foreign tables' columns and their foreign server.
const FOREIGN_COLUMNS_SQL: &str = "SELECT n.nspname, c.relname, s.srvname::text, a.attname::text, \
     a.atttypid IN ('bool'::regtype, 'timestamp'::regtype, 'timestamptz'::regtype, 'interval'::regtype) \
     FROM pg_catalog.pg_attribute a \
     JOIN pg_catalog.pg_class c ON c.oid = a.attrelid \
     JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
     JOIN pg_catalog.pg_foreign_table ft ON ft.ftrelid = c.oid \
     JOIN pg_catalog.pg_foreign_server s ON s.oid = ft.ftserver \
     WHERE c.relkind = 'f' AND a.attnum > 0 AND NOT a.attisdropped";

/// Every data flow touching a table in `personal` (`schema.table` names), sorted.
pub fn flows(
    client: &mut crate::Catalog,
    personal: &BTreeSet<String>,
    overrides: &Overrides,
) -> Result<Vec<Flow>, postgres::Error> {
    let mut flows = Vec::new();
    for (kind, sql) in [
        ("publication", PUBLICATIONS_SQL),
        ("subscription", SUBSCRIPTIONS_SQL),
    ] {
        for row in client.query(sql)? {
            let name: &str = row.get(0);
            let table = format!("{}.{}", row.get::<_, &str>(1), row.get::<_, &str>(2));
            if personal.contains(&table) {
                flows.push(Flow {
                    kind,
                    object: format!("{kind}:{name}"),
                    table,
                    target: None,
                    evidence_id: format!("pg_{kind}:{name}"),
                });
            }
        }
    }
    for row in client.query_without(TRIGGERS_SQL, &[], 3)? {
        let table = format!("{}.{}", row.get::<_, &str>(0), row.get::<_, &str>(1));
        if !personal.contains(&table) {
            continue;
        }
        let id = format!("{table}.{}", row.get::<_, &str>(2));
        let source: &str = row.get(3);
        let copy = insert_target(source).map(|target| ("copy_trigger", target));
        let export = export_channel(row.get(4), source).map(|c| ("export_trigger", c.to_owned()));
        for (kind, target) in copy.into_iter().chain(export) {
            flows.push(Flow {
                kind,
                object: format!("trigger:{id}"),
                table: table.clone(),
                target: Some(target),
                evidence_id: format!("pg_trigger:{id}"),
            });
        }
    }
    // Foreign tables are classified by column name and overrides only: sampling
    // one would query the remote server.
    for row in client.query(FOREIGN_COLUMNS_SQL)? {
        let (schema, table): (&str, &str) = (row.get(0), row.get(1));
        if is_personal(overrides, schema, table, row.get(3), row.get(4), None) {
            let table = format!("{schema}.{table}");
            flows.push(Flow {
                kind: "foreign_table",
                object: format!("foreign_table:{table}"),
                evidence_id: format!("pg_foreign_table:{table}"),
                table,
                target: Some(row.get(2)),
            });
        }
    }
    flows.sort();
    flows.dedup();
    Ok(flows)
}

/// The solver's DISABLE treatment for one flow, citing its catalog object.
pub fn finding(flow: &Flow, system_id: &str) -> Finding {
    let id = flow.object.as_str();
    Finding {
        table: Some(flow.table.clone()),
        ..Finding::treatment(
            "recreation_risk",
            flow.kind,
            id,
            DISABLE,
            system_id,
            &flow.evidence_id,
        )
    }
}
