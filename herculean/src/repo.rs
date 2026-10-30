//! Repo facts, read without a database: the schema and table grants from
//! `*.sql` migrations and `DELETE FROM` lines in any text file. Evidence ids
//! are `file:<path>:<line>`.

use crate::{Deleter, Facts, ForeignKey, TableFacts};
use sqlparser::ast::{
    Action, AlterColumnOperation, AlterTableOperation, ColumnDef, ColumnOption, CommentObject,
    ConstraintReferenceMatchKind, DataType, DeferrableInitial, Expr, ForeignKeyConstraint,
    GrantObjects, Grantee, GranteeName, GranteesType, Ident, ObjectName, ObjectNamePart,
    ObjectType, Privileges, ReferentialAction, RenameTableNameKind, Reset, ResetStatement, Set,
    Statement, TableConstraint,
};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::keywords::Keyword;
use sqlparser::parser::Parser;
use sqlparser::tokenizer::Token;
use std::path::{Component, Path, PathBuf};

const SKIP_DIRS: &[&str] = &["target", ".git", "node_modules"];

/// Documentation: its deletes are examples, never deletion paths.
const DOC_EXTENSIONS: [&str; 8] = ["md", "markdown", "mdx", "txt", "rst", "adoc", "html", "htm"];

/// Languages where a line starting with `#` is a comment (not C's `#define`).
const HASH_COMMENT_EXTENSIONS: [&str; 9] =
    ["py", "rb", "sh", "bash", "yml", "yaml", "toml", "pl", "r"];

/// Larger files are not read (a repo is untrusted input; the hook runs on every edit).
pub(crate) const MAX_FILE_BYTES: u64 = 1 << 20;

/// Every regular file under `root` outside the skip-list: (path relative to
/// `root` with `/`, path, size), sorted. Symlinks, FIFOs and devices are skipped.
fn files(root: &Path) -> std::io::Result<Vec<(String, PathBuf, u64)>> {
    let mut out = Vec::new();
    let mut dirs = vec![root.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            // DirEntry::file_type does not follow symlinks.
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                if !SKIP_DIRS.iter().any(|d| entry.file_name() == *d) {
                    dirs.push(path);
                }
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            out.push((
                rel_path(root, &path).unwrap(),
                path,
                entry.metadata()?.len(),
            ));
        }
    }
    out.sort();
    Ok(out)
}

/// `path` under `root`, relative and `/`-separated.
pub(crate) fn rel_path(root: &Path, path: &Path) -> Option<String> {
    let parts: Vec<_> = path
        .strip_prefix(root)
        .ok()?
        .components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect();
    Some(parts.join("/"))
}

/// Where schema facts come from when `--migrations-dir` is not given: the
/// first of these that is a directory.
const MIGRATIONS_DIRS: [&str; 3] = ["migrations", "db/migrations", "supabase/migrations"];

/// `MIGRATIONS_DIRS` as prose: "migrations/, db/migrations/, supabase/migrations/".
pub fn default_migrations_dirs() -> String {
    MIGRATIONS_DIRS.map(|d| format!("{d}/")).join(", ")
}

/// The migrations dir, relative to `root`: `given` once checked to be a
/// directory inside the repo, else the first of `MIGRATIONS_DIRS` that exists.
pub fn migrations_dir(root: &Path, given: Option<&str>) -> std::io::Result<Option<String>> {
    // DirEntry walks never follow symlinks, so neither does this.
    let is_dir = |d: &str| std::fs::symlink_metadata(root.join(d)).is_ok_and(|m| m.is_dir());
    let Some(d) = given else {
        return Ok(MIGRATIONS_DIRS
            .into_iter()
            .find(|d| is_dir(d))
            .map(Into::into));
    };
    let invalid = |why| std::io::Error::other(format!("migrations dir {d} is {why}"));
    let inside = Path::new(d)
        .components()
        .all(|c| matches!(c, Component::Normal(_) | Component::CurDir));
    if !inside {
        return Err(invalid("outside the repo"));
    }
    if !is_dir(d) {
        return Err(invalid("not a directory in the repo"));
    }
    Ok(Some(d.into()))
}

/// Reads the repo's schema facts and deletion lines. Schema facts come from the
/// `*.sql` files under `migrations_dir` (see [`migrations_dir`]; with none,
/// every `*.sql` file, with a note), skipping down migrations; deletion lines
/// from every file. Files that are not UTF-8 text are skipped; unparsable SQL
/// statements are skipped with a note.
pub fn read(root: &Path, migrations_dir: Option<&str>) -> std::io::Result<Facts> {
    // The dir as a prefix of the paths `files` gives: `a/b/`, or empty for `.`.
    let dir = self::migrations_dir(root, migrations_dir)?.map(|d| -> String {
        Path::new(&d)
            .components()
            .filter_map(|c| match c {
                Component::Normal(n) => Some(format!("{}/", n.to_string_lossy())),
                _ => None,
            })
            .collect()
    });
    let mut applied_any = false;
    let mut facts = Facts::default();
    for (rel, path, size) in files(root)? {
        // Notes reach readiness.md and an agent's context: never a raw repo name.
        let shown = crate::printable(&rel, "/-");
        if size > MAX_FILE_BYTES {
            let note = format!("skipped_large_file: {shown} is over 1 MiB and was not read");
            facts.notes.push((rel, note));
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let migration = path.extension().is_some_and(|e| e == "sql")
            && rel.starts_with(dir.as_deref().unwrap_or_default());
        // Docs and comments describe deletes; they don't run them. Comments are
        // judged by how the line starts: a trailing or block comment still counts.
        let ext = path.extension().map(|e| e.to_string_lossy().to_lowercase());
        let doc = ext.as_deref().is_some_and(|e| DOC_EXTENSIONS.contains(&e));
        let hash = ext
            .as_deref()
            .is_some_and(|e| HASH_COMMENT_EXTENSIONS.contains(&e));
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let start = line.trim_start();
            let comment = ["--", "//", "/*", "* "]
                .iter()
                .any(|c| start.starts_with(c))
                || start == "*"
                || (hash && start.starts_with('#'));
            if doc || comment || !line.to_lowercase().contains("delete") {
                continue;
            }
            // `DELETE FROM` at the end of a line: its table is on the next.
            let mut command = line.to_string();
            let words: Vec<String> = line
                .to_lowercase()
                .split(|c: char| !c.is_alphanumeric())
                .filter(|w| !w.is_empty())
                .map(str::to_string)
                .collect();
            if words.ends_with(&["delete".into(), "from".into()])
                || words.ends_with(&["delete".into(), "from".into(), "only".into()])
            {
                if let Some(next) = lines.get(i + 1) {
                    command = format!("{line} {next}");
                }
            }
            facts.deleters.push(Deleter {
                kind: "code",
                evidence: format!("file:{rel}:{}", i + 1),
                command,
                migration,
            });
        }
        let name = rel.rsplit('/').next().unwrap_or_default();
        let down = name == "down.sql" || name.ends_with(".down.sql");
        if migration && !down {
            applied_any = true;
            if !read_sql(&rel, &text, &mut facts) {
                let note = format!(
                    "unparsed_sql: {shown}: a statement could not be parsed and was skipped"
                );
                facts.notes.push((rel, note));
            }
        }
    }
    if dir.is_none() && applied_any {
        facts.info_notes.push(format!(
            "no_migrations_dir: none of {} exists (pass --migrations-dir), \
             so every *.sql file except down migrations was read as a migration",
            default_migrations_dirs()
        ));
    }
    Ok(facts)
}

/// The schema facts one `*.sql` file defines on its own.
pub(crate) fn read_file(rel: &str, text: &str) -> Facts {
    let mut facts = Facts::default();
    read_sql(rel, text, &mut facts);
    facts
}

/// What `GRANT ALL` on a table means (Postgres 16).
// ponytail: Postgres 17 adds MAINTAIN to ALL; add it when the live server is 17+.
const TABLE_PRIVILEGES: &[&str] = &[
    "DELETE",
    "INSERT",
    "REFERENCES",
    "SELECT",
    "TRIGGER",
    "TRUNCATE",
    "UPDATE",
];

/// Reads CREATE TABLE, DROP TABLE, ALTER TABLE ... ADD / DROP / RENAME COLUMN,
/// ADD [CONSTRAINT] FOREIGN KEY, DROP CONSTRAINT and RENAME TO, and table
/// GRANT / REVOKE, applied in migration order; false if any statement failed to parse.
/// Unqualified names are in the first schema of the file's `SET search_path`
/// (`public` until one, and again after RESET / DEFAULT); the path resets at the end of the file.
fn read_sql(rel: &str, text: &str, facts: &mut Facts) -> bool {
    let Ok(mut parser) = Parser::new(&PostgreSqlDialect {}).try_with_sql(text) else {
        return false;
    };
    let mut parsed_all = true;
    let mut path = String::from("public");
    loop {
        while parser.consume_token(&Token::SemiColon) {}
        if parser.peek_token().token == Token::EOF {
            return parsed_all;
        }
        if parser.parse_keywords(&[Keyword::ALTER, Keyword::DEFAULT, Keyword::PRIVILEGES]) {
            if !default_privileges(&mut parser, facts) {
                parsed_all = false;
                while !matches!(parser.next_token().token, Token::SemiColon | Token::EOF) {}
            }
            continue;
        }
        let statement = match parser.parse_statement() {
            Ok(s) => s,
            Err(_) => {
                parsed_all = false;
                while !matches!(parser.next_token().token, Token::SemiColon | Token::EOF) {}
                continue;
            }
        };
        let ev = |i: &Ident| format!("file:{rel}:{}", i.span.start.line);
        let path_change = match &statement {
            Statement::Set(Set::SingleAssignment {
                variable, values, ..
            }) if variable.to_string().eq_ignore_ascii_case("search_path") => {
                Some(match values.first() {
                    // DEFAULT is the server default path: as at the start of the file.
                    Some(Expr::Identifier(i)) if i.value.eq_ignore_ascii_case("default") => {
                        Some("public".to_string())
                    }
                    // `$user` names no schema.
                    Some(Expr::Identifier(i)) if ident(i) != "$user" => Some(ident(i)),
                    _ => None,
                })
            }
            Statement::Reset(ResetStatement {
                reset: Reset::ALL, ..
            }) => Some(Some("public".to_string())),
            Statement::Reset(ResetStatement {
                reset: Reset::ConfigurationParameter(p),
            }) if p.to_string().eq_ignore_ascii_case("search_path") => {
                Some(Some("public".to_string()))
            }
            // ponytail: only the literal `set_config('search_path', ...)`; other spellings stay silent.
            Statement::Query(q) => {
                let q = q.to_string().to_lowercase();
                // pg_dump's empty path: every name is schema-qualified, the path is moot.
                (q.contains("set_config")
                    && q.contains("'search_path'")
                    && !q.contains("'search_path', '',"))
                .then_some(None)
            }
            _ => None,
        };
        if let Some(schema) = path_change {
            match schema {
                Some(schema) => path = schema,
                None => {
                    let note = format!(
                        "search_path_ignored: {}: a search_path form that is not a plain \
                         schema name was ignored; unqualified names keep the schema {}",
                        crate::printable(rel, "/-"),
                        crate::printable(&path, "")
                    );
                    if !facts.notes.iter().any(|(s, _)| s == rel) {
                        facts.notes.push((rel.to_string(), note));
                    }
                }
            }
            continue;
        }
        match statement {
            Statement::CreateTable(create) => {
                let Some((key, name)) = table(&create.name, &path) else {
                    continue;
                };
                let t = table_facts(facts, key.clone(), ev(name));
                for column in &create.columns {
                    add_column(t, &key.1, column, &path, &ev);
                }
                for constraint in &create.constraints {
                    if let TableConstraint::ForeignKey(fk) = constraint {
                        t.foreign_keys
                            .push(foreign_key(fk, &key.1, &[], &path, &ev));
                    }
                }
            }
            Statement::AlterTable(alter) => {
                let Some((mut key, name)) = table(&alter.name, &path) else {
                    continue;
                };
                let evidence = ev(name);
                for op in &alter.operations {
                    alter_table(facts, &mut key, &evidence, op, &path, &ev);
                }
            }
            Statement::Drop {
                object_type: ObjectType::Table,
                names,
                ..
            } => {
                for (key, _) in names.iter().filter_map(|n| table(n, &path)) {
                    facts.tables.remove(&key);
                    facts.grants.remove(&key);
                    // Its foreign keys go too: CASCADE drops them, without it Postgres refuses.
                    for t in facts.tables.values_mut() {
                        t.foreign_keys.retain(|fk| fk.references != key);
                    }
                }
            }
            Statement::Comment {
                object_type: CommentObject::Column,
                object_name,
                comment,
                ..
            } => {
                // [schema.]table.column
                let parts = &object_name.0;
                let Some((column, table_name)) = parts.split_last() else {
                    continue;
                };
                let (Some(column), Some((key, _))) = (
                    column.as_ident().map(ident),
                    table(&ObjectName(table_name.to_vec()), &path),
                ) else {
                    continue;
                };
                if let Some(t) = facts.tables.get_mut(&key) {
                    match comment {
                        Some(c) => t.comments.insert(column, c),
                        None => t.comments.remove(&column),
                    };
                }
            }
            Statement::Grant(g) => {
                apply_grant(facts, &g.privileges, &g.objects, &g.grantees, true, &path)
            }
            Statement::Revoke(r) if !r.grant_option_for => {
                apply_grant(facts, &r.privileges, &r.objects, &r.grantees, false, &path)
            }
            _ => {}
        }
    }
}

/// Records the grantees of an `ALTER DEFAULT PRIVILEGES ... GRANT ... ON TABLES`
/// whose first three words are already read; false if it does not parse.
/// sqlparser has no such statement: FOR ROLE and IN SCHEMA are skipped and the
/// GRANT or REVOKE after them is parsed, `ON TABLES` reading as a table named
/// `tables`. A REVOKE only takes privileges away from future tables, so it names
/// no one (`REVOKE ALL ON TABLES FROM PUBLIC` must not hide PUBLIC grants).
// ponytail: grantees are named, not modelled (which tables get the privileges
// depends on the role creating them); drift leaves their grants out on both sides.
fn default_privileges(parser: &mut Parser, facts: &mut Facts) -> bool {
    loop {
        match &parser.peek_token().token {
            Token::Word(w) if matches!(w.keyword, Keyword::GRANT | Keyword::REVOKE) => break,
            Token::SemiColon | Token::EOF => return false,
            _ => {
                parser.next_token();
            }
        }
    }
    let grant = match parser.parse_statement() {
        Ok(Statement::Grant(g)) => g,
        Ok(Statement::Revoke(_)) => return true,
        _ => return false,
    };
    let on_tables = matches!(&grant.objects, Some(GrantObjects::Tables(t))
        if t.len() == 1 && t[0].to_string().eq_ignore_ascii_case("tables"));
    if on_tables {
        facts
            .default_grantees
            .extend(grant.grantees.iter().filter_map(grantee));
    }
    true
}

/// The table's facts; its evidence is the first statement that names it.
fn table_facts(facts: &mut Facts, key: (String, String), evidence: String) -> &mut TableFacts {
    let t = facts.tables.entry(key).or_default();
    if t.evidence.is_empty() {
        t.evidence = evidence;
    }
    t
}

/// Applies one ALTER TABLE operation to `key`'s facts; RENAME TO updates `key`.
/// Dropping a column drops the foreign keys on it, as Postgres does.
fn alter_table(
    facts: &mut Facts,
    key: &mut (String, String),
    evidence: &str,
    op: &AlterTableOperation,
    path: &str,
    ev: &impl Fn(&Ident) -> String,
) {
    match op {
        AlterTableOperation::AddColumn { column_def, .. } => {
            let t = table_facts(facts, key.clone(), evidence.into());
            add_column(t, &key.1, column_def, path, ev);
        }
        AlterTableOperation::AddConstraint {
            constraint: TableConstraint::ForeignKey(fk),
            not_valid,
        } => {
            let t = table_facts(facts, key.clone(), evidence.into());
            let mut fk = foreign_key(fk, &key.1, &[], path, ev);
            fk.validated = !not_valid;
            t.foreign_keys.push(fk);
        }
        AlterTableOperation::RenameTable {
            table_name: RenameTableNameKind::To(name) | RenameTableNameKind::As(name),
        } => {
            // The new name is unqualified: the table stays in its schema.
            let Some(((_, new), _)) = table(name, path) else {
                return;
            };
            let new_key = (key.0.clone(), new);
            if let Some(t) = facts.tables.remove(key) {
                facts.tables.insert(new_key.clone(), t);
            }
            if let Some(g) = facts.grants.remove(key) {
                facts.grants.insert(new_key.clone(), g);
            }
            for fk in facts.tables.values_mut().flat_map(|t| &mut t.foreign_keys) {
                if fk.references == *key {
                    fk.references = new_key.clone();
                }
            }
            *key = new_key;
        }
        _ => {
            let Some(t) = facts.tables.get_mut(key) else {
                return;
            };
            match op {
                AlterTableOperation::DropColumn { column_names, .. } => {
                    for c in column_names.iter().map(ident) {
                        t.comments.remove(&c);
                        t.markers.remove(&c);
                        t.columns.retain(|(n, _)| *n != c);
                        t.foreign_keys.retain(|fk| !fk.columns.contains(&c));
                    }
                    // Foreign keys referencing a dropped column go too, as with DROP TABLE.
                    // ponytail: a key naming no columns references the primary key, which repo
                    // facts don't record, so it survives dropping that column.
                    let dropped: Vec<String> = column_names.iter().map(ident).collect();
                    for t in facts.tables.values_mut() {
                        t.foreign_keys.retain(|fk| {
                            fk.references != *key
                                || !fk.referred_columns.iter().any(|c| dropped.contains(c))
                        });
                    }
                }
                AlterTableOperation::DropConstraint { name, .. } => {
                    let name = ident(name);
                    t.foreign_keys.retain(|fk| fk.name != name);
                }
                AlterTableOperation::RenameColumn {
                    old_column_name,
                    new_column_name,
                } => {
                    let (old, new) = (ident(old_column_name), ident(new_column_name));
                    if let Some(c) = t.comments.remove(&old) {
                        t.comments.insert(new.clone(), c);
                    }
                    if t.markers.remove(&old) {
                        t.markers.insert(new.clone());
                    }
                    let names = t.columns.iter_mut().map(|(n, _)| n);
                    let fk_columns = t.foreign_keys.iter_mut().flat_map(|fk| &mut fk.columns);
                    for n in names.chain(fk_columns).filter(|n| **n == old) {
                        *n = new.clone();
                    }
                    // Foreign keys referencing the column follow it, as with RENAME TO.
                    let referred = facts.tables.values_mut().flat_map(|t| &mut t.foreign_keys);
                    let referred = referred
                        .filter(|fk| fk.references == *key)
                        .flat_map(|fk| &mut fk.referred_columns);
                    for n in referred.filter(|n| **n == old) {
                        *n = new.clone();
                    }
                }
                AlterTableOperation::AlterColumn {
                    column_name,
                    op: AlterColumnOperation::SetDataType { data_type, .. },
                } => {
                    let name = ident(column_name);
                    if is_marker(data_type) {
                        t.markers.insert(name);
                    } else {
                        t.markers.remove(&name);
                    }
                }
                _ => {}
            }
        }
    }
}

/// A column already defined (`ADD COLUMN IF NOT EXISTS` again) is left as it was.
fn add_column(
    t: &mut TableFacts,
    table: &str,
    column: &ColumnDef,
    path: &str,
    ev: &impl Fn(&Ident) -> String,
) {
    let name = ident(&column.name);
    if t.columns.iter().any(|(n, _)| *n == name) {
        return;
    }
    for option in &column.options {
        if let ColumnOption::ForeignKey(fk) = &option.option {
            let mut fk = foreign_key(fk, table, std::slice::from_ref(&name), path, ev);
            if let Some(constraint) = &option.name {
                fk.name = ident(constraint);
            }
            t.foreign_keys.push(fk);
        }
    }
    if is_marker(&column.data_type) {
        t.markers.insert(name.clone());
    }
    t.columns.push((name, ev(&column.name)));
}

/// Whether the type makes the column's name a marker (`email boolean`,
/// `email_verified_at timestamptz`) rather than the data.
fn is_marker(data_type: &DataType) -> bool {
    matches!(
        data_type,
        DataType::Bool | DataType::Boolean | DataType::Timestamp(..) | DataType::Interval { .. }
    )
}

/// The foreign key, with evidence at the REFERENCES line. A column-level
/// REFERENCES names no columns of its own: `column` is the one it is on.
/// Unnamed, it gets Postgres's default name `<table>_<columns>_fkey`.
fn foreign_key(
    fk: &ForeignKeyConstraint,
    table_name: &str,
    column: &[String],
    path: &str,
    ev: &impl Fn(&Ident) -> String,
) -> ForeignKey {
    let (references, evidence) = table(&fk.foreign_table, path)
        .map(|(key, name)| (key, ev(name)))
        .unwrap_or_default();
    let on_delete = rule(fk.on_delete);
    let columns: Vec<String> = match fk.columns.as_slice() {
        [] => column.to_vec(),
        columns => columns.iter().map(ident).collect(),
    };
    let deferred = fk
        .characteristics
        .is_some_and(|c| c.initially == Some(DeferrableInitial::Deferred));
    ForeignKey {
        referred_columns: fk.referred_columns.iter().map(ident).collect(),
        on_update: rule(fk.on_update),
        match_full: fk.match_kind == Some(ConstraintReferenceMatchKind::Full),
        deferrable: deferred
            || fk
                .characteristics
                .is_some_and(|c| c.deferrable == Some(true)),
        deferred,
        validated: true,
        evidence,
        name: fk
            .name
            .as_ref()
            .map(ident)
            .unwrap_or_else(|| format!("{table_name}_{}_fkey", columns.join("_"))),
        columns,
        references,
        on_delete,
    }
}

/// A referential action as pg_constraint's letter: a/r no action/restrict; c/n/d cascade/set null/set default.
fn rule(action: Option<ReferentialAction>) -> char {
    match action {
        Some(ReferentialAction::Cascade) => 'c',
        Some(ReferentialAction::SetNull) => 'n',
        Some(ReferentialAction::SetDefault) => 'd',
        Some(ReferentialAction::Restrict) => 'r',
        Some(ReferentialAction::NoAction) | None => 'a',
    }
}

/// Adds (GRANT) or removes (REVOKE) table-level (grantee, privilege) pairs on
/// named tables, or on `ALL TABLES IN SCHEMA` (the tables the migrations define
/// there so far). Anything else (column privileges, role membership, ...) is ignored.
fn apply_grant(
    facts: &mut Facts,
    privileges: &Privileges,
    objects: &Option<GrantObjects>,
    grantees: &[Grantee],
    grant: bool,
    path: &str,
) {
    let keys: Vec<(String, String)> = match objects {
        Some(GrantObjects::Tables(tables)) => tables
            .iter()
            .filter_map(|n| table(n, path))
            .map(|(k, _)| k)
            .collect(),
        Some(GrantObjects::AllTablesInSchema { schemas }) => {
            let schemas: Vec<String> = schemas
                .iter()
                .filter_map(|s| s.0.last()?.as_ident().map(ident))
                .collect();
            let keys = facts.tables.keys();
            keys.filter(|(s, _)| schemas.contains(s)).cloned().collect()
        }
        _ => return,
    };
    let privileges = match privileges {
        Privileges::All { .. } => Some(TABLE_PRIVILEGES.to_vec()),
        Privileges::Actions(actions) => actions.iter().map(table_privilege).collect(),
    };
    let grantees: Option<Vec<String>> = grantees.iter().map(grantee).collect();
    let (Some(privileges), Some(grantees)) = (privileges, grantees) else {
        return;
    };
    for key in keys {
        let set = facts.grants.entry(key).or_default();
        for g in &grantees {
            for p in &privileges {
                let pair = (g.clone(), p.to_string());
                if grant {
                    set.insert(pair);
                } else {
                    set.remove(&pair);
                }
            }
        }
    }
}

/// The privilege name as `aclexplode` reports it; None for column privileges.
fn table_privilege(action: &Action) -> Option<&'static str> {
    match action {
        Action::Select { columns: None } => Some("SELECT"),
        Action::Insert { columns: None } => Some("INSERT"),
        Action::Update { columns: None } => Some("UPDATE"),
        Action::References { columns: None } => Some("REFERENCES"),
        Action::Delete => Some("DELETE"),
        Action::Truncate => Some("TRUNCATE"),
        Action::Trigger => Some("TRIGGER"),
        _ => None,
    }
}

/// `PUBLIC` or a role name.
fn grantee(g: &Grantee) -> Option<String> {
    match (&g.grantee_type, &g.name) {
        (GranteesType::Public, _) => Some("PUBLIC".into()),
        (GranteesType::Role | GranteesType::None, Some(GranteeName::ObjectName(name))) => {
            match name.0.as_slice() {
                [part] => part.as_ident().map(ident),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Postgres folds unquoted identifiers to lower case.
fn ident(i: &Ident) -> String {
    match i.quote_style {
        Some(_) => i.value.clone(),
        None => i.value.to_lowercase(),
    }
}

/// ((schema, table), the table-name identifier); unqualified tables are in `path`.
fn table<'a>(name: &'a ObjectName, path: &str) -> Option<((String, String), &'a Ident)> {
    let parts: Vec<&Ident> = name
        .0
        .iter()
        .map(ObjectNamePart::as_ident)
        .collect::<Option<_>>()?;
    match parts.as_slice() {
        [t] => Some(((path.into(), ident(t)), t)),
        [.., s, t] => Some(((ident(s), ident(t)), t)),
        [] => None,
    }
}
