mod drift;
pub mod fix;
pub mod hook;
mod least_privilege;
mod recreation_risk;
mod repo;
pub mod soc2;
pub mod steps;

/// Reads a repo's migrations and code (no database involved).
pub use repo::{default_migrations_dirs, migrations_dir, read as read_repo};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use steps::{Step, Treatment, DELETE};

/// Rules-first personal-data classification: exact column-name matches, after
/// `words()` (`firstName`, `FIRST_NAME` and `first_name` are one name).
const NAME_RULES: &[(&str, &str)] = &[
    ("address", "contact"),
    ("date_of_birth", "identity"),
    ("email", "contact"),
    ("first_name", "identity"),
    ("full_name", "identity"),
    ("ip_address", "online_identifier"),
    ("last_name", "identity"),
    ("name", "identity"),
    ("phone", "contact"),
];

/// Column-name keywords, matched as whole words of the name (`user_email`,
/// `phoneNumber`, `phone2`, `last_lab_result`). `name` is exact-only: `file_name`
/// and `product_name` hold no personal data. `allergy` is comment-only (a recipe app)
/// and `condition` is no keyword at all (`order_condition`, "Current condition").
// ponytail: `email_id` (a foreign key) and `email_count` classify too; guard `_id` and numeric types when a real schema shows it.
const TOKEN_RULES: &[(&str, &str)] = &[
    ("email", "contact"),
    ("phone", "contact"),
    ("postal", "contact"),
    ("postcode", "contact"),
    ("zip", "contact"),
    ("zipcode", "contact"),
    ("ssn", "identity"),
    ("dob", "identity"),
    ("birth", "identity"),
    ("birthdate", "identity"),
    ("birthday", "identity"),
    ("diagnosis", "health"),
    ("icd", "health"),
    ("mrn", "health"),
    ("medical record number", "health"),
    ("medication", "health"),
    ("prescription", "health"),
    ("lab result", "health"),
    ("insurance member id", "health"),
];

/// Column-comment keywords (whole words, any case), most specific first.
/// Names win over comments; overrides win over both.
// ponytail: `health` also matches "Health status"; require a phrase when a pilot schema shows the misfire.
const COMMENT_RULES: &[(&str, &str)] = &[
    ("date of birth", "identity"),
    ("social security", "identity"),
    ("ssn", "identity"),
    ("email", "contact"),
    ("phone", "contact"),
    ("address", "contact"),
    ("phi", "health"),
    ("health", "health"),
    ("medical", "health"),
    ("diagnosis", "health"),
    ("allergy", "health"),
    ("pii", "personal"),
    ("personal", "personal"),
];

/// `" word word "`: `text` lowercased and split at anything that is not a letter
/// or digit, at camelCase humps and between letters and digits, so that
/// `" {keyword} "` matches whole words only.
fn words(text: &str) -> String {
    let mut out = String::from(" ");
    let mut prev = ' ';
    for c in text.chars() {
        if !c.is_alphanumeric() {
            if prev != ' ' {
                out.push(' ');
            }
            prev = ' ';
            continue;
        }
        let hump = c.is_uppercase() && (prev.is_lowercase() || prev.is_ascii_digit());
        let edge = prev.is_alphanumeric() && c.is_ascii_digit() != prev.is_ascii_digit();
        if hump || edge {
            out.push(' ');
        }
        out.extend(c.to_lowercase());
        prev = c;
    }
    if prev != ' ' {
        out.push(' ');
    }
    out
}

/// The category of the first rule whose keyword appears whole in `words(text)`.
// ponytail: keyword match only; "no personal data here" still classifies. Add negation when it bites.
fn keyword(text: &str, rules: &'static [(&str, &'static str)]) -> Option<&'static str> {
    let text = words(text);
    rules
        .iter()
        .find(|(keyword, _)| text.contains(&format!(" {keyword} ")))
        .map(|&(_, category)| category)
}

/// Soft-delete markers: a personal-data table with one of these needs a purge job.
const SOFT_DELETE_COLUMNS: &[&str] = &["archived_at", "deleted", "deleted_at", "is_deleted"];

/// Ordinary and partitioned tables' live columns, from pg_catalog only.
/// information_schema would hide columns the read-only role has no privilege on.
/// Partitions are skipped: their partitioned parent stands for them.
const COLUMNS_SQL: &str = "SELECT n.nspname, c.relname, a.attname, \
     a.atttypid IN ('text'::regtype, 'varchar'::regtype, 'bpchar'::regtype), \
     pg_catalog.col_description(a.attrelid, a.attnum), a.atttypid IN ('bool'::regtype, 'timestamp'::regtype, 'timestamptz'::regtype, 'interval'::regtype) \
     FROM pg_catalog.pg_attribute a \
     JOIN pg_catalog.pg_class c ON c.oid = a.attrelid \
     JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
     WHERE c.relkind IN ('r', 'p') AND NOT c.relispartition \
       AND a.attnum > 0 AND NOT a.attisdropped \
       AND n.nspname <> 'information_schema' AND n.nspname NOT LIKE 'pg\\_%'";

/// Foreign keys: delete rule (a/r: no action/restrict; c/n/d: cascade/set null/set default),
/// referenced table, referencing and referenced columns in key order, and the
/// rest of the constraint (ON UPDATE rule, MATCH FULL, deferrable, deferred, validated).
const FOREIGN_KEYS_SQL: &str = "SELECT n.nspname, c.relname, con.conname, con.confdeltype::text, \
       rn.nspname, r.relname, \
       ARRAY(SELECT a.attname::text FROM unnest(con.conkey) WITH ORDINALITY k(attnum, i) \
             JOIN pg_catalog.pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = k.attnum \
             ORDER BY k.i), \
       ARRAY(SELECT a.attname::text FROM unnest(con.confkey) WITH ORDINALITY k(attnum, i) \
             JOIN pg_catalog.pg_attribute a ON a.attrelid = con.confrelid AND a.attnum = k.attnum \
             ORDER BY k.i), \
       con.confupdtype::text, con.confmatchtype = 'f', con.condeferrable, con.condeferred, \
       con.convalidated \
     FROM pg_catalog.pg_constraint con \
     JOIN pg_catalog.pg_class c ON c.oid = con.conrelid \
     JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
     JOIN pg_catalog.pg_class r ON r.oid = con.confrelid \
     JOIN pg_catalog.pg_namespace rn ON rn.oid = r.relnamespace \
     WHERE con.contype = 'f' \
     ORDER BY n.nspname, c.relname, con.conname";

/// One row when pg_cron's job table exists: whether row-level security hides
/// other roles' jobs from us (pg_cron's policy shows each role only its own).
const CRON_PRESENT_SQL: &str = "SELECT c.relrowsecurity AND NOT \
       (pg_catalog.pg_has_role(c.relowner, 'USAGE') OR r.rolsuper OR r.rolbypassrls) \
     FROM pg_catalog.pg_class c \
     JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
     JOIN pg_catalog.pg_roles r ON r.rolname = current_user \
     WHERE n.nspname = 'cron' AND c.relname = 'job'";

const CRON_HIDDEN_NOTE: &str = "scheduled_jobs_unreadable: cron.job is protected by row-level \
     security; scheduled purge jobs owned by other roles were not seen";

/// Active jobs that run in database $1 (cron.job may hold other databases' jobs).
const CRON_JOBS_SQL: &str = "SELECT jobid, command FROM cron.job WHERE active AND database = $1";

/// Where pg_cron keeps cron.job; NULL when pg_cron is not loaded. pg_cron makes
/// it superuser-only: without pg_read_all_settings this fails with 42501.
const CRON_DATABASE_SQL: &str = "SELECT pg_catalog.current_setting('cron.database_name', true)";

/// Extensions that call other databases or services at run time (pg_extension
/// is PUBLIC-readable).
const LINK_EXTENSIONS_SQL: &str = "SELECT extname::text FROM pg_catalog.pg_extension \
     WHERE extname IN ('dblink', 'postgres_fdw', 'aws_s3', 'aws_lambda', 'azure_storage', \
     'pg_net', 'http') ORDER BY 1";

#[derive(Serialize)]
pub struct Report {
    pub data_map: DataMap,
    pub findings: Vec<Finding>,
    /// Notes on input not fully read (the first `unread_notes`), then
    /// informational notes.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    #[serde(skip)]
    pub(crate) unread_notes: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub skipped_checks: Vec<SkippedCheck>,
    /// The schema facts the findings came from; `herculean fix` reads them.
    #[serde(skip)]
    pub(crate) facts: Facts,
    /// Live runs: hex SHA-256 of the catalog rows read (see [`Catalog`]).
    #[serde(skip)]
    pub catalog_sha256: Option<String>,
}

/// Lowercase hex of `bytes`.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The connection for catalog queries: every row they return is folded into a
/// digest. Sampling uses the bare client, so row values never reach it.
pub(crate) struct Catalog<'a> {
    client: &'a mut postgres::Client,
    digest: Sha256,
}

/// A column in Postgres's binary wire format, whatever its type.
struct Raw<'a>(&'a [u8]);

impl<'a> postgres::types::FromSql<'a> for Raw<'a> {
    fn from_sql(
        _: &postgres::types::Type,
        raw: &'a [u8],
    ) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        Ok(Raw(raw))
    }
    fn accepts(_: &postgres::types::Type) -> bool {
        true
    }
}

impl Catalog<'_> {
    pub(crate) fn query(&mut self, sql: &str) -> Result<Vec<postgres::Row>, postgres::Error> {
        self.query_without(sql, &[], usize::MAX)
    }

    /// Like `query`, but column `text` is left out of the digest: command text
    /// may hold secrets, and an unkeyed hash of it would let them be guessed.
    pub(crate) fn query_without(
        &mut self,
        sql: &str,
        params: &[&(dyn postgres::types::ToSql + Sync)],
        text: usize,
    ) -> Result<Vec<postgres::Row>, postgres::Error> {
        let rows = self.client.query(sql, params)?;
        // Length-prefixed columns (u32::MAX for NULL), rows sorted: the digest
        // does not depend on the order the server returns them in.
        let mut encoded: Vec<Vec<u8>> = rows
            .iter()
            .map(|row| {
                let mut bytes = Vec::new();
                for i in (0..row.len()).filter(|&i| i != text) {
                    match row.get::<_, Option<Raw>>(i) {
                        None => bytes.extend(u32::MAX.to_be_bytes()),
                        Some(Raw(v)) => {
                            bytes.extend((v.len() as u32).to_be_bytes());
                            bytes.extend(v);
                        }
                    }
                }
                bytes
            })
            .collect();
        encoded.sort();
        self.digest.update((sql.len() as u64).to_be_bytes());
        self.digest.update(sql);
        self.digest.update((encoded.len() as u64).to_be_bytes());
        for row in encoded {
            self.digest.update((row.len() as u64).to_be_bytes());
            self.digest.update(row);
        }
        Ok(rows)
    }
}

#[derive(Serialize)]
pub struct DataMap {
    pub stores: Vec<Store>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub deletion_paths: Vec<DeletionPath>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub flows: Vec<Flow>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub samples: Vec<Sample>,
}

/// A catalog object that copies a personal-data table somewhere else, or back.
#[derive(Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Flow {
    pub kind: &'static str,
    pub object: String,
    pub table: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    pub evidence_id: String,
}

/// Opt-in sampling result for one column: counts only, never a value.
#[derive(Serialize)]
pub struct Sample {
    pub column: String,
    /// Why the column could not be read (SQLSTATE only); it then counts as not sampled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped: Option<String>,
    pub sampled: u32,
    pub matches: Matches,
}

#[derive(Serialize, Default)]
pub struct Matches {
    pub email: u32,
    pub phone: u32,
}

#[derive(Serialize)]
pub struct Store {
    pub schema: String,
    pub table: String,
    pub columns: Vec<Column>,
}

#[derive(Serialize)]
pub struct Column {
    pub name: String,
    pub category: String,
    pub source: &'static str,
    /// confirmed (override), high (column name), medium (comment, sample).
    pub confidence: &'static str,
}

#[derive(Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeletionPath {
    pub table: String,
    pub kind: &'static str,
    pub evidence_id: String,
}

impl Finding {
    /// A finding with its treatment's steps numbered 1..3; the FINDING step
    /// cites `evidence`, the proposed remediation and verification cite nothing.
    pub(crate) fn treatment(
        check: &'static str,
        kind: &'static str,
        resource_id: &str,
        treatment: Treatment,
        system_id: &str,
        evidence: &str,
    ) -> Finding {
        let steps = treatment
            .iter()
            .zip([evidence, "", ""])
            .enumerate()
            .map(|(i, (&op, evidence))| Step::new(i + 1, op, system_id, resource_id, evidence))
            .collect();
        Finding {
            check,
            kind,
            resource_id: resource_id.into(),
            table: None,
            steps,
        }
    }
}

#[derive(Serialize)]
pub struct Finding {
    pub check: &'static str,
    pub kind: &'static str,
    pub resource_id: String,
    /// The personal-data table a flow carries (recreation_risk findings only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub table: Option<String>,
    pub steps: Vec<Step>,
}

/// Engineer overrides from data-map.yaml: `schema.table.column` -> its category,
/// or `None` for a column marked not personal. Overrides win over detection.
pub type Overrides = BTreeMap<String, Option<String>>;

/// data-map.yaml: the generated `stores`, `flows` and `deletion_paths`
/// (written by `scan --write-data-map`, ignored on reading) and the engineer's `overrides`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DataMapFile {
    #[serde(default)]
    overrides: Option<Vec<OverrideEntry>>,
    #[serde(rename = "stores")]
    _stores: Option<serde::de::IgnoredAny>,
    #[serde(rename = "flows")]
    _flows: Option<serde::de::IgnoredAny>,
    #[serde(rename = "deletion_paths")]
    _deletion_paths: Option<serde::de::IgnoredAny>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OverrideEntry {
    column: String,
    category: Option<String>,
    personal: Option<bool>,
}

pub fn parse_data_map(text: &str) -> Result<Overrides, String> {
    let file: DataMapFile = serde_norway::from_str(text).map_err(|e| e.to_string())?;
    file.overrides
        .unwrap_or_default()
        .into_iter()
        .map(|o| match (o.category, o.personal) {
            (Some(category), None | Some(true)) => Ok((o.column, Some(category))),
            (None, Some(false)) => Ok((o.column, None)),
            _ => Err(format!(
                "override for {} needs a category, or personal: false",
                o.column
            )),
        })
        .collect()
}

/// The data map's file name in a repo, used when `--data-map` is not given.
pub const DATA_MAP_FILE: &str = "data-map.yaml";

/// `<repo>/data-map.yaml`'s text, when it is a regular file (never read
/// through a symlink: a repo is untrusted) of at most 1 MiB; None otherwise.
pub fn committed_data_map(repo: &Path) -> Option<std::io::Result<String>> {
    let path = repo.join(DATA_MAP_FILE);
    let meta = std::fs::symlink_metadata(&path).ok()?;
    (meta.is_file() && meta.len() <= repo::MAX_FILE_BYTES).then(|| std::fs::read_to_string(path))
}

/// data-map.yaml for `report`: the generated stores, flows and deletion paths,
/// then `existing`'s `overrides:` section verbatim (or an empty one).
pub fn data_map_yaml(report: &Report, existing: &str) -> String {
    #[derive(Serialize)]
    struct Generated<'a> {
        stores: &'a [Store],
        flows: &'a [Flow],
        deletion_paths: &'a [DeletionPath],
    }
    let generated = serde_norway::to_string(&Generated {
        stores: &report.data_map.stores,
        flows: &report.data_map.flows,
        deletion_paths: &report.data_map.deletion_paths,
    })
    .expect("the data map serializes");
    // The overrides section runs from its key to the next top-level key.
    let mut overrides = String::new();
    let mut inside = false;
    for line in existing.split_inclusive('\n') {
        let top_level_key =
            line.starts_with(|c: char| c.is_ascii_alphabetic() || "\"'".contains(c));
        if top_level_key {
            inside = ["overrides:", "\"overrides\":", "'overrides':"]
                .iter()
                .any(|key| line.starts_with(key));
        }
        if inside {
            overrides.push_str(line);
        }
    }
    if overrides.is_empty() {
        overrides = "overrides: []\n".into();
    } else if !overrides.ends_with('\n') {
        overrides.push('\n');
    }
    format!(
        "# Generated by `herculean scan --write-data-map`, except `overrides`:\n\
         # edit only that section; its entries win over detection.\n{generated}{overrides}"
    )
}

/// A column's personal-data category and its source, by override, else name, else
/// comment (never sampling). `Some(None)` is a `personal: false` override; `None`
/// means nothing classified it, so only sampling may. A boolean, timestamp or
/// interval column's name says whether or when (`email boolean`,
/// `email_verified_at timestamptz`), not what it is, so only its comment or an
/// override can classify it; a `date` (`dob`) is the data.
fn classify(
    overrides: &Overrides,
    schema: &str,
    table: &str,
    column: &str,
    marker: bool,
    comment: Option<&str>,
) -> Option<Option<(String, &'static str)>> {
    if let Some(category) = overrides.get(&format!("{schema}.{table}.{column}")) {
        return Some(category.clone().map(|c| (c, "override")));
    }
    let by_name = || {
        let snake = words(column).trim().replace(' ', "_");
        NAME_RULES
            .iter()
            .find(|(rule, _)| *rule == snake)
            .map(|&(_, category)| category)
            .or_else(|| keyword(column, TOKEN_RULES))
    };
    (!marker)
        .then(by_name)
        .flatten()
        .map(|c| (c, "column_name"))
        .or_else(|| {
            comment
                .and_then(|c| keyword(c, COMMENT_RULES))
                .map(|c| (c, "comment"))
        })
        .map(|(category, source)| Some((category.to_string(), source)))
}

/// Whether an override or a rule says the column holds personal data.
fn is_personal(
    overrides: &Overrides,
    schema: &str,
    table: &str,
    column: &str,
    marker: bool,
    comment: Option<&str>,
) -> bool {
    classify(overrides, schema, table, column, marker, comment)
        .flatten()
        .is_some()
}

const SAMPLE_ROWS: u32 = 100;

fn looks_like_email(v: &str) -> bool {
    let v = v.trim();
    match v.split_once('@') {
        Some((local, domain)) => {
            !local.is_empty()
                && !v.contains(char::is_whitespace)
                && !domain.contains('@')
                && domain.split('.').count() >= 2
                && domain.split('.').all(|part| !part.is_empty())
        }
        None => false,
    }
}

/// A phone number has 7-15 digits and either a leading `+` or separator
/// grouping. Pure digit strings (ids), dotted strings (IPs, decimals) and
/// ISO dates are rejected.
// ponytail: dotted phone numbers (555.123.4567) are missed; accept them when a pattern tells them from IPs.
fn looks_like_phone(v: &str) -> bool {
    let v = v.trim();
    let digits = v.chars().filter(char::is_ascii_digit).count();
    let groups: Vec<usize> = v.split('-').map(str::len).collect();
    let iso_date = groups == [4, 2, 2];
    (7..=15).contains(&digits)
        && v.chars().all(|c| c.is_ascii_digit() || " +-()".contains(c))
        && (v.starts_with('+') || v.contains([' ', '-', '(']))
        && !iso_date
}

/// `name` when it is only `[A-Za-z0-9_.]` (plus `extra`), else a placeholder:
/// a name from a repo or a catalog must not inject text into an agent's context.
pub(crate) fn printable<'a>(name: &'a str, extra: &str) -> &'a str {
    let plain = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || extra.contains(c));
    if plain && !name.is_empty() {
        name
    } else {
        "<unprintable name>"
    }
}

fn quote_ident(ident: &str) -> String {
    format!("\"{}\"", ident.replace('"', "\"\""))
}

/// Reads up to SAMPLE_ROWS values of one column, checks each against the
/// patterns in-process and drops it: only the counts leave this function.
fn sample_column(
    client: &mut postgres::Client,
    schema: &str,
    table: &str,
    column: &str,
) -> Result<Sample, postgres::Error> {
    let sql = format!(
        "SELECT {}::text FROM {}.{} LIMIT {SAMPLE_ROWS}",
        quote_ident(column),
        quote_ident(schema),
        quote_ident(table)
    );
    let mut sample = Sample {
        column: format!("{schema}.{table}.{column}"),
        skipped: None,
        sampled: 0,
        matches: Matches::default(),
    };
    let rows = match client.query(&sql, &[]) {
        Ok(rows) => rows,
        // A column we may not read (e.g. 42501, no SELECT grant) is skipped, not fatal.
        Err(e) => match e.code() {
            Some(code) => {
                sample.skipped = Some(format!("SQLSTATE {}", code.code()));
                return Ok(sample);
            }
            None => return Err(e),
        },
    };
    for row in rows {
        let Some(value) = row.get::<_, Option<&str>>(0) else {
            continue;
        };
        sample.sampled += 1;
        sample.matches.email += u32::from(looks_like_email(value));
        sample.matches.phone += u32::from(looks_like_phone(value));
    }
    Ok(sample)
}

/// Whether `command` (a pg_cron command or a line of code) deletes from
/// `schema.table`, qualified or bare, quoted or not.
fn purges(command: &str, schema: &str, table: &str) -> bool {
    let lower = command.to_lowercase().replace(['"', '`'], "");
    let words: Vec<&str> = lower
        .split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '.'))
        .filter(|w| !w.is_empty())
        .collect();
    words.windows(3).any(|w| {
        w[0] == "delete" && w[1] == "from" && (w[2] == table || w[2] == format!("{schema}.{table}"))
    })
}

/// Schema and deletion facts from the catalog or a repo, keyed by (schema, table).
#[derive(Default)]
pub struct Facts {
    pub(crate) tables: BTreeMap<(String, String), TableFacts>,
    pub(crate) deleters: Vec<Deleter>,
    /// (source not fully read, note saying why).
    pub(crate) notes: Vec<(String, String)>,
    /// Informational notes: nothing went unread, so no finding and no CI failure.
    pub(crate) info_notes: Vec<String>,
    /// Repo only: table-level (grantee, privilege) pairs the migrations grant.
    pub(crate) grants: BTreeMap<(String, String), BTreeSet<(String, String)>>,
    /// Repo only: grantees of `ALTER DEFAULT PRIVILEGES ... GRANT ... ON TABLES`.
    pub(crate) default_grantees: BTreeSet<String>,
}

#[derive(Default)]
pub(crate) struct TableFacts {
    /// Where the table is defined; a no-deletion-path finding cites it.
    pub(crate) evidence: String,
    /// (column name, where it is defined).
    pub(crate) columns: Vec<(String, String)>,
    /// Column name -> its comment.
    pub(crate) comments: BTreeMap<String, String>,
    /// Columns of type boolean, timestamp or interval; their names do not classify them.
    pub(crate) markers: BTreeSet<String>,
    pub(crate) foreign_keys: Vec<ForeignKey>,
}

pub(crate) struct ForeignKey {
    /// Where the foreign key is defined.
    pub(crate) evidence: String,
    /// The constraint name (repo: Postgres's default when unnamed).
    pub(crate) name: String,
    pub(crate) columns: Vec<String>,
    /// The referenced (schema, table).
    pub(crate) references: (String, String),
    /// pg_constraint.confdeltype: a/r no action/restrict; c/n/d cascade/set null/set default.
    pub(crate) on_delete: char,
    /// The referenced columns in key order (repo: empty when the migration names none).
    pub(crate) referred_columns: Vec<String>,
    /// pg_constraint.confupdtype, same letters as `on_delete`.
    pub(crate) on_update: char,
    pub(crate) match_full: bool,
    pub(crate) deferrable: bool,
    pub(crate) deferred: bool,
    /// False for a constraint added NOT VALID and not validated since.
    pub(crate) validated: bool,
}

impl ForeignKey {
    /// Whether deleting the referenced row deletes this row. SET NULL / SET DEFAULT keep it.
    fn removes(&self) -> bool {
        self.on_delete == 'c'
    }

    /// NO ACTION / RESTRICT: a gap. SET NULL / SET DEFAULT are handled, but are no path.
    pub(crate) fn lacks_on_delete(&self) -> bool {
        matches!(self.on_delete, 'a' | 'r')
    }
}

/// A pg_cron command or a line of code that may delete rows.
pub(crate) struct Deleter {
    pub(crate) kind: &'static str,
    pub(crate) evidence: String,
    pub(crate) command: String,
    /// A line in a repo migration: in a live run the catalog shows what it did.
    pub(crate) migration: bool,
}

/// Checks that did not run for lack of an input, and that input.
#[derive(Serialize)]
pub struct SkippedCheck {
    pub check: &'static str,
    pub reason: &'static str,
}

/// Classifies every table's columns and runs the `deletion_path` check.
/// `sampled` holds `schema.table.column` names that sampling found personal.
fn deletion_check(
    facts: &Facts,
    overrides: &Overrides,
    sampled: &BTreeSet<String>,
    system_id: &str,
) -> (Vec<Store>, Vec<DeletionPath>, Vec<Finding>) {
    let mut stores = Vec::new();
    let mut deletion_paths = Vec::new();
    let mut findings = Vec::new();
    for ((schema, table), t) in &facts.tables {
        let mut table_columns = t.columns.clone();
        table_columns.sort();
        let mut columns = Vec::new();
        for (name, _) in &table_columns {
            let key = format!("{schema}.{table}.{name}");
            let comment = t.comments.get(name).map(String::as_str);
            let marker = t.markers.contains(name);
            let (category, source) = match classify(overrides, schema, table, name, marker, comment)
            {
                Some(Some(classified)) => classified,
                Some(None) => continue,
                None if sampled.contains(&key) => ("contact".to_string(), "sample"),
                None => continue,
            };
            let confidence = match source {
                "override" => "confirmed",
                "column_name" => "high",
                _ => "medium",
            };
            columns.push(Column {
                name: name.clone(),
                category,
                source,
                confidence,
            });
        }
        if columns.is_empty() {
            continue;
        }
        let resource_id = format!("{schema}.{table}");
        let path = |kind, evidence_id| DeletionPath {
            table: resource_id.clone(),
            kind,
            evidence_id,
        };
        let mut paths = Vec::new();
        let mut gaps = Vec::new();
        for fk in &t.foreign_keys {
            if fk.removes() {
                paths.push(path("on_delete", fk.evidence.clone()));
            } else if fk.lacks_on_delete() {
                gaps.push(Finding::treatment(
                    "deletion_path",
                    "fk_without_on_delete",
                    &resource_id,
                    DELETE,
                    system_id,
                    &fk.evidence,
                ));
            }
        }
        let mut purged = false;
        for d in facts
            .deleters
            .iter()
            .filter(|d| purges(&d.command, schema, table))
        {
            purged = true;
            paths.push(path(d.kind, d.evidence.clone()));
        }
        if !purged {
            for (_, evidence) in table_columns
                .iter()
                .filter(|(n, _)| SOFT_DELETE_COLUMNS.contains(&n.as_str()))
            {
                gaps.push(Finding::treatment(
                    "deletion_path",
                    "soft_delete_without_purge",
                    &resource_id,
                    DELETE,
                    system_id,
                    evidence,
                ));
            }
        }
        if paths.is_empty() && gaps.is_empty() {
            gaps.push(Finding::treatment(
                "deletion_path",
                "no_deletion_path",
                &resource_id,
                DELETE,
                system_id,
                &t.evidence,
            ));
        }
        findings.append(&mut gaps);
        deletion_paths.append(&mut paths);
        stores.push(Store {
            schema: schema.clone(),
            table: table.clone(),
            columns,
        });
    }
    deletion_paths.sort();
    (stores, deletion_paths, findings)
}

fn sort_findings(findings: &mut [Finding]) {
    let evidence = |f: &Finding| f.steps.first().map(|s| s.evidence_id.clone());
    findings.sort_by(|a, b| {
        (a.check, &a.resource_id, a.kind, &a.table, evidence(a)).cmp(&(
            b.check,
            &b.resource_id,
            b.kind,
            &b.table,
            evidence(b),
        ))
    });
}

/// The notes' text; each source not fully read also becomes one low
/// `data_map/incomplete_input` finding, which fails CI at any `--fail-on` (see `soc2::meets`).
// ponytail: no steps; a coverage gap has no data to remediate, and new
// operations would need an ADR. Add them if a fix for coverage gaps appears.
fn incomplete_input(notes: Vec<(String, String)>, findings: &mut Vec<Finding>) -> Vec<String> {
    let mut sources = BTreeSet::new();
    notes
        .into_iter()
        .map(|(source, note)| {
            if sources.insert(source.clone()) {
                findings.push(Finding {
                    check: "data_map",
                    kind: "incomplete_input",
                    resource_id: source,
                    table: None,
                    steps: Vec::new(),
                });
            }
            note
        })
        .collect()
}

/// Repo-only run: the data map and `deletion_path` check from repo facts alone.
pub fn scan_repo(mut facts: Facts, overrides: &Overrides) -> Report {
    let (stores, deletion_paths, mut findings) =
        deletion_check(&facts, overrides, &BTreeSet::new(), "repo");
    let mut notes = incomplete_input(std::mem::take(&mut facts.notes), &mut findings);
    let unread_notes = notes.len();
    notes.append(&mut facts.info_notes);
    sort_findings(&mut findings);
    let skipped = |check| SkippedCheck {
        check,
        reason: "no database connection",
    };
    Report {
        data_map: DataMap {
            stores,
            deletion_paths,
            flows: Vec::new(),
            samples: Vec::new(),
        },
        findings,
        notes,
        unread_notes,
        skipped_checks: vec![
            skipped("recreation_risk"),
            skipped("least_privilege"),
            skipped("drift"),
        ],
        facts,
        catalog_sha256: None,
    }
}

/// Active pg_cron jobs for `client`'s database, when cron.job is there; None when it is not.
fn jobs_here(
    client: &mut Catalog,
    db: &str,
    notes: &mut Vec<(String, String)>,
) -> Result<Option<Vec<postgres::Row>>, postgres::Error> {
    let cron = client.query(CRON_PRESENT_SQL)?;
    let Some(hidden) = cron.first() else {
        return Ok(None);
    };
    if hidden.get(0) {
        notes.push(("cron.job".to_string(), CRON_HIDDEN_NOTE.to_string()));
    }
    client.query_without(CRON_JOBS_SQL, &[&db], 1).map(Some)
}

/// Active pg_cron jobs that run in `db`: from this database, else from the one
/// pg_cron keeps them in, over a second connection. A cron database that cannot
/// be read is a note (incomplete input), never "no jobs".
fn cron_jobs(
    client: &mut Catalog,
    db: &str,
    yugabyte: bool,
    connect_db: &dyn Fn(&str) -> Option<postgres::Client>,
    notes: &mut Vec<(String, String)>,
) -> Result<Vec<postgres::Row>, postgres::Error> {
    if let Some(jobs) = jobs_here(client, db, notes)? {
        return Ok(jobs);
    }
    let (name, known) = match client.query(CRON_DATABASE_SQL) {
        Ok(rows) => match rows[0].get::<_, Option<String>>(0) {
            // pg_cron is not loaded; or its database is this one, without the extension yet.
            None => return Ok(Vec::new()),
            Some(name) if name == db => return Ok(Vec::new()),
            Some(name) => (name, true),
        },
        Err(e) if e.code() == Some(&postgres::error::SqlState::INSUFFICIENT_PRIVILEGE) => {
            // pg_cron is loaded but hides the name: try the services' default.
            let name = if yugabyte { "yugabyte" } else { "postgres" };
            (name.to_string(), false)
        }
        Err(e) => return Err(e),
    };
    // ADR 0004: the database the jobs come from is a digest input.
    client.digest.update((name.len() as u64).to_be_bytes());
    client.digest.update(&name);
    let jobs = (name != db)
        .then(|| connect_db(&name))
        .flatten()
        .and_then(|mut other| {
            let mut cron = Catalog {
                client: &mut other,
                digest: client.digest.clone(),
            };
            let jobs = jobs_here(&mut cron, db, notes).ok().flatten();
            client.digest = cron.digest;
            jobs
        });
    Ok(jobs.unwrap_or_else(|| {
        let shown = if known {
            printable(&name, "")
        } else {
            "unknown"
        };
        notes.push((
            "cron.job".to_string(),
            format!(
                "scheduled_jobs_elsewhere: pg_cron keeps jobs in another database ({shown}); \
                 grant the reader access there"
            ),
        ));
        Vec::new()
    }))
}

/// Live run; with `repo` facts, the repo's code adds deletion paths and the
/// `drift` check compares the live schema with the migrations. `connect_db`
/// opens another database of the same server, read-only, as the same reader.
pub fn scan(
    connection: &mut postgres::Client,
    connect_db: &dyn Fn(&str) -> Option<postgres::Client>,
    overrides: &Overrides,
    sample: bool,
    mut repo: Option<Facts>,
) -> Result<Report, postgres::Error> {
    let client = &mut Catalog {
        client: connection,
        digest: Sha256::new(),
    };
    let system_id: String = client.query("SELECT current_database()")?[0].get(0);
    // Read once, outside the digest: a server patch upgrade changes version().
    let yugabyte: bool = client
        .client
        .query_one("SELECT pg_catalog.version() LIKE '%-YB-%'", &[])?
        .get(0);
    let mut facts = Facts::default();
    // Text-like columns, the only ones sampling may read.
    let mut text_columns = BTreeSet::new();
    for row in client.query(COLUMNS_SQL)? {
        let (schema, table, column): (String, String, String) =
            (row.get(0), row.get(1), row.get(2));
        let resource_id = format!("{schema}.{table}");
        if row.get(3) {
            text_columns.insert((schema.clone(), table.clone(), column.clone()));
        }
        let t = facts.tables.entry((schema, table)).or_default();
        t.evidence = format!("pg_class:{resource_id}");
        if let Some(comment) = row.get::<_, Option<String>>(4) {
            t.comments.insert(column.clone(), comment);
        }
        if row.get(5) {
            t.markers.insert(column.clone());
        }
        t.columns.push((
            column.clone(),
            format!("pg_attribute:{resource_id}.{column}"),
        ));
    }
    for fk in client.query(FOREIGN_KEYS_SQL)? {
        let key: (String, String) = (fk.get(0), fk.get(1));
        if let Some(t) = facts.tables.get_mut(&key) {
            t.foreign_keys.push(ForeignKey {
                evidence: format!("pg_constraint:{}.{}.{}", key.0, key.1, fk.get::<_, &str>(2)),
                name: fk.get(2),
                columns: fk.get(6),
                references: (fk.get(4), fk.get(5)),
                on_delete: fk.get::<_, &str>(3).chars().next().unwrap_or('a'),
                referred_columns: fk.get(7),
                on_update: fk.get::<_, &str>(8).chars().next().unwrap_or('a'),
                match_full: fk.get(9),
                deferrable: fk.get(10),
                deferred: fk.get(11),
                validated: fk.get(12),
            });
        }
    }
    let mut notes = Vec::new();
    for job in cron_jobs(client, &system_id, yugabyte, connect_db, &mut notes)? {
        facts.deleters.push(Deleter {
            kind: "scheduled_job",
            evidence: format!("cron.job:{}", job.get::<_, i64>(0)),
            command: job.get(1),
            migration: false,
        });
    }
    // Migration text never closes a gap the catalog can answer; app code can.
    let mut migration_deleters = Vec::new();
    if let Some(repo) = &mut repo {
        let (migration, code): (Vec<_>, Vec<_>) =
            repo.deleters.drain(..).partition(|d| d.migration);
        migration_deleters = migration;
        facts.deleters.extend(code);
        notes.append(&mut repo.notes);
    }

    let mut samples = Vec::new();
    let mut sampled = BTreeSet::new();
    if sample {
        for (schema, table, column) in &text_columns {
            let t = &facts.tables[&(schema.clone(), table.clone())];
            let comment = t.comments.get(column).map(String::as_str);
            let marker = t.markers.contains(column);
            if classify(overrides, schema, table, column, marker, comment).is_some() {
                continue;
            }
            let key = format!("{schema}.{table}.{column}");
            let s = sample_column(client.client, schema, table, column)?;
            // ponytail: majority vote of two contact patterns; add patterns when a category needs them.
            if s.matches.email.max(s.matches.phone) * 2 > s.sampled {
                sampled.insert(key);
            }
            samples.push(s);
        }
    }

    let (stores, deletion_paths, mut findings) =
        deletion_check(&facts, overrides, &sampled, &system_id);
    let mut migration_notes = Vec::new();
    for s in &stores {
        for d in migration_deleters
            .iter()
            .filter(|d| purges(&d.command, &s.schema, &s.table))
        {
            migration_notes.push(format!(
                "migration_deleter_not_counted: {} deletes from {}.{}, but a live scan \
                 counts only the catalog's deletion paths, not migration text",
                printable(&d.evidence, "/-:"),
                printable(&s.schema, ""),
                printable(&s.table, "")
            ));
        }
    }
    let personal: BTreeSet<String> = stores
        .iter()
        .map(|s| format!("{}.{}", s.schema, s.table))
        .collect();
    let flows = recreation_risk::flows(client, &personal, overrides)?;
    // A postgres_fdw foreign table on personal data is already a flow.
    let has_foreign_table = flows.iter().any(|f| f.kind == "foreign_table");
    // An export extension is a channel that exists, not unread input: an
    // informational note, never a data_map/incomplete_input finding.
    let mut export_notes = Vec::new();
    for row in client.query(LINK_EXTENSIONS_SQL)? {
        let extension: String = row.get(0);
        match extension.as_str() {
            "postgres_fdw" if has_foreign_table => {}
            "dblink" | "postgres_fdw" => {
                let note = format!(
                    "cross_database_link: {extension} extension is installed; \
                     calls through it are not analysed"
                );
                notes.push((extension, note));
            }
            _ => export_notes.push(format!(
                "export_channel: {extension} extension is installed; it can copy personal \
                 data out of the database, and calls through it are not analysed"
            )),
        }
    }
    findings.extend(
        flows
            .iter()
            .map(|f| recreation_risk::finding(f, &system_id)),
    );
    let (privilege, mut role_notes) =
        least_privilege::findings(client, &stores, &system_id, yugabyte)?;
    findings.extend(privilege);
    let mut skipped_checks = Vec::new();
    match &repo {
        Some(repo) => findings.extend(drift::findings(
            client, &facts, repo, &personal, overrides, &system_id,
        )?),
        None => skipped_checks.push(SkippedCheck {
            check: "drift",
            reason: "no repo given",
        }),
    }
    let mut notes = incomplete_input(notes, &mut findings);
    let unread_notes = notes.len();
    if let Some(repo) = &mut repo {
        notes.append(&mut repo.info_notes);
    }
    notes.append(&mut export_notes);
    notes.append(&mut migration_notes);
    notes.append(&mut role_notes);
    let defaults: Vec<&str> = repo
        .iter()
        .flat_map(|r| &r.default_grantees)
        .map(|g| printable(g, ""))
        .collect();
    if !defaults.is_empty() {
        notes.push(format!(
            "default_privileges_not_compared: the migrations set default table privileges \
             for {}; Herculean does not model ALTER DEFAULT PRIVILEGES, so drift compares no \
             table grants to those roles, in the migrations or live",
            defaults.join(", ")
        ));
    }
    sort_findings(&mut findings);
    Ok(Report {
        data_map: DataMap {
            stores,
            deletion_paths,
            flows,
            samples,
        },
        findings,
        notes,
        unread_notes,
        skipped_checks,
        facts,
        catalog_sha256: Some(hex(&client.digest.clone().finalize())),
    })
}
