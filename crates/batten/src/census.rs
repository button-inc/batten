//! The shell census (CLOUD-843): every place a consumer still writes shell,
//! counted in code lines and reported as pointers.
//!
//! # Why a verb and not a hand count
//!
//! The retirement campaign's rule is that every wave moves the count down, and a
//! count typed into a tracker row is a claim nothing re-derives. This is the
//! derivation: one pass over the tree, one number per home, byte-stable, so a
//! wave's before and after are two runs of the same command rather than two
//! estimates.
//!
//! # What it counts, and why the detection is not this module's to choose
//!
//! Three homes, each with the reading the consumer's own ban already applies:
//!
//! * **A manifest's command strings** — a declared key's triple-quoted body
//!   (every code line, when the body is shell logic), its one-line value, and
//!   its multi-line array entries (each when the string it holds is shell
//!   logic). Grouped into named units where the manifest declares a unit header,
//!   so a task runner's tasks are named.
//! * **A workflow's steps** — every code line of a `run: |` / `run: >` block
//!   that is shell logic, bounded by indentation, and a one-line `run:` that is.
//! * **A shell file** — a tracked path [`crate::shell::shell_path`] names, or
//!   one whose shebang [`crate::shell::shebang`] reads as a shell. Its code
//!   lines.
//!
//! Whether a text is shell logic is [`crate::shell::logic`]'s answer on the
//! parser's AST (CLOUD-2625), never a scan here. The ban — the `shell-hygiene`
//! preset's `no-new-shell` module, which reads this same `[census.shell]` table
//! as its list of homes, through a glob language [`ShellCensus::validate`] holds
//! to what both matchers read alike (`*`, `?`, `**`) — reads the same answer
//! through [`tree_fact`], so the two agree BY CONSTRUCTION: there is one
//! detection, computed here, and the module only compares its two sides.
//! `crates/batten/tests/it/census_shell.rs` still runs both over one fixture.
//!
//! # What is the consumer's, never the engine's (non-negotiable rule 1)
//!
//! Which manifests, which keys, which unit header, which workflow globs and which
//! files must stay shell are all `[census.shell]` in the consumer's `batten.toml`.
//! The engine owns the grammar of "is this line shell" and nothing about where a
//! repository keeps its commands. An exempt file is still measured and reported —
//! apart, and outside the total — so the exemption is visible rather than a hole.
//! The ban reads `exempt` for FILES only: an exempt manifest or workflow is set
//! apart here and still judged there, so on those two homes the ban is the
//! stricter reading, never the laxer one.
//!
//! # Pointer-only (non-negotiable rule 4)
//!
//! A path, a line, a unit's declared name and a count. Never a byte of a body.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::Path;

use anyhow::Result;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::UsageError;
use crate::exit::ExitCode;
use crate::rules::Selector;

/// The `[census]` table: the measurements a consumer declares over its own tree.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Census {
    /// Where this repository writes shell, for `batten census shell`. Absent
    /// means the census has nothing declared to read, which the verb refuses
    /// rather than reporting a zero it did not measure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell: Option<ShellCensus>,
}

/// `[census.shell]`: the homes shell may live in, and the files that must stay
/// shell.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ShellCensus {
    /// Manifests whose command strings are counted, one row per file.
    #[serde(default, rename = "manifest", skip_serializing_if = "Vec::is_empty")]
    pub manifests: Vec<Manifest>,
    /// Workflow files whose `run:` steps are counted, as globs over tracked paths.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub workflows: Vec<String>,
    /// Paths that must stay shell because nothing else can run where they do, as
    /// globs. Still measured, reported apart, and never totalled.
    ///
    /// LEGACY (CLOUD-2628): a non-empty list with no `mode` reads as
    /// `mode = "migrate"` with these paths exempt, exactly as before the ban
    /// judged presence. Removing that reading is CLOUD-2745's.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exempt: Vec<String>,
    /// How the `shell-hygiene` ban judges this tree. Absent is presence: any
    /// shell no `generated` entry covers is refused. `migrate` judges growth
    /// only, while a repository ports what it has.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<ShellMode>,
    /// The only shell the presence ban admits: files a named generator writes
    /// and a named test holds, one row per glob.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub generated: Vec<Generated>,
    /// The only shell engine source may spawn (CLOUD-2770): one row per
    /// function whose string-literal argv runs a shell because an external
    /// format forces it. Held in both directions, whatever `mode` says.
    #[serde(default, rename = "spawn", skip_serializing_if = "Vec::is_empty")]
    pub spawns: Vec<Spawn>,
}

/// One `[[census.shell.spawn]]` row: an engine function that spawns a shell,
/// and the external contract that forces it to.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Spawn {
    /// The source file, repo-relative.
    pub path: String,
    /// The function holding the spawn, by its name. Optional to the parser so
    /// that [`ShellCensus::validate`] is what refuses its absence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    /// The external format that makes the argv a shell command line, with a
    /// citation (a URL). Optional to the parser so that
    /// [`ShellCensus::validate`] is what refuses its absence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract: Option<String>,
}

/// `[census.shell] mode`: the one knob between presence and growth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum ShellMode {
    /// Presence is not judged; the growth arms refuse new shell and shell that
    /// grows, so the existing surface may only shrink.
    Migrate,
}

/// One `[[census.shell.generated]]` row: shell a generator writes and a test
/// holds.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Generated {
    /// The generated files, as a glob over tracked paths (`*`, `?`, `**`).
    pub path: String,
    /// The command or function that writes them, as free text. Optional to the
    /// parser so that [`ShellCensus::validate`] is what refuses its absence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generator: Option<String>,
    /// The test that holds their bytes, as `<test file>::<test name>`. Optional
    /// to the parser so that [`ShellCensus::validate`] is what refuses it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check: Option<String>,
}

/// A `check` value split into its file and its test name, when it has the
/// `<test file>::<test name>` shape: both halves non-empty and free of
/// whitespace.
#[must_use]
pub fn check_parts(check: &str) -> Option<(&str, &str)> {
    let (file, name) = check.split_once("::")?;
    let bare = |part: &str| !part.is_empty() && !part.chars().any(char::is_whitespace);
    (bare(file) && bare(name)).then_some((file, name))
}

/// Whether a line of `text` holds `name`: a substring over lines, assuming no
/// language.
fn holds_test(text: &str, name: &str) -> bool {
    text.lines().any(|line| line.contains(name))
}

/// One manifest whose command strings are counted.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Manifest {
    /// The manifest's repo-relative path.
    pub path: String,
    /// The carrier whose fields this manifest's commands are, by its id in
    /// `crate::shell::CARRIERS` (`mise-task` or `hk-step`, the two with a
    /// manifest reader). Exactly one of `carrier` and `keys`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carrier: Option<String>,
    /// The keys whose values are commands, as they are spelled before ` = `,
    /// for a manifest no carrier describes. Exactly one of `carrier` and
    /// `keys`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<String>,
    /// The header prefix that opens one named unit — a task table, say. Every
    /// shell line between one such header and the next is that unit's. Absent,
    /// each shell line is reported on its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
}

/// The carriers a manifest row may name: the ones this module has a manifest
/// reader for. Every other `crate::shell::CARRIERS` row is cited data only.
const MANIFEST_CARRIERS: [&crate::shell::Carrier; 2] =
    [&crate::shell::MISE_TASK, &crate::shell::HK_STEP];

impl Manifest {
    /// The carrier this row names, when it names one this module reads.
    #[must_use]
    pub fn carrier(&self) -> Option<&'static crate::shell::Carrier> {
        manifest_carrier(self.carrier.as_deref()?)
    }

    /// The command fields: the carrier's, or the row's own `keys`.
    #[must_use]
    pub fn fields(&self) -> Vec<String> {
        match self.carrier() {
            Some(carrier) => carrier.fields.iter().map(|&f| f.to_owned()).collect(),
            None => self.keys.clone(),
        }
    }
}

/// A manifest-readable carrier by id.
fn manifest_carrier(id: &str) -> Option<&'static crate::shell::Carrier> {
    MANIFEST_CARRIERS
        .iter()
        .copied()
        .find(|carrier| carrier.id == id)
}

/// A generated entry with no test behind it admits shell on nothing; the row
/// below skips the `check` key, and the compiled tier's load case goes green
/// where it must refuse.
//MUTANT-SUITE crates/batten/tests/it/shell_banned.rs
//MUTANT generated-entry-unchecked|s@^            if entry.check.as_deref().and_then(check_parts).is_none() {$@            if false {@|a_generated_entry_without_a_check_is_refused_at_load
impl ShellCensus {
    /// Refuse a declaration that would count nothing while reading as covered.
    ///
    /// # Errors
    ///
    /// A [`UsageError`] (→ exit `1`) for a manifest with no path, with both or
    /// neither of `carrier` and `keys`, naming a carrier with no manifest
    /// reader, a key that is empty or carries whitespace, an empty unit header,
    /// a glob `globset` cannot parse, or a glob spelling an operator the ban
    /// cannot read (`BAN_UNREAD_OPERATORS`).
    pub fn validate(&self) -> Result<()> {
        for manifest in &self.manifests {
            if manifest.path.trim().is_empty() {
                return Err(UsageError::raise(
                    "census.shell.manifest: `path` must name a file",
                ));
            }
            match (&manifest.carrier, manifest.keys.is_empty()) {
                (Some(_), false) => {
                    return Err(UsageError::raise(format!(
                        "census.shell.manifest {}: both `carrier` and `keys` — a row names its \
                         command fields one way",
                        manifest.path
                    )));
                }
                (None, true) => {
                    return Err(UsageError::raise(format!(
                        "census.shell.manifest {}: neither `carrier` nor `keys` — a manifest \
                         with no command key counts nothing",
                        manifest.path
                    )));
                }
                (Some(id), true) if manifest_carrier(id).is_none() => {
                    let known: Vec<&str> = MANIFEST_CARRIERS.iter().map(|c| c.id).collect();
                    return Err(UsageError::raise(format!(
                        "census.shell.manifest {}: carrier {id:?} has no manifest reader; one \
                         of {known:?}",
                        manifest.path
                    )));
                }
                _ => {}
            }
            for key in &manifest.keys {
                if key.is_empty() || key.chars().any(char::is_whitespace) {
                    return Err(UsageError::raise(format!(
                        "census.shell.manifest {}: key {key:?} is not one bare word",
                        manifest.path
                    )));
                }
            }
            if manifest
                .unit
                .as_deref()
                .is_some_and(|unit| unit.trim().is_empty())
            {
                return Err(UsageError::raise(format!(
                    "census.shell.manifest {}: `unit` is empty — every line would open a unit",
                    manifest.path
                )));
            }
        }
        if !self.exempt.is_empty() && !self.generated.is_empty() {
            return Err(UsageError::raise(
                "census.shell: both `exempt` and `generated` — `exempt` is the legacy migrating \
                 list and `generated` the presence ban's table; move each exempt file into a \
                 generated entry, or keep `exempt` until the tree is ported",
            ));
        }
        for entry in &self.generated {
            if entry.path.trim().is_empty() {
                return Err(UsageError::raise(
                    "census.shell.generated: `path` must name a glob",
                ));
            }
            if entry
                .generator
                .as_deref()
                .is_none_or(|generator| generator.trim().is_empty())
            {
                return Err(UsageError::raise(format!(
                    "census.shell.generated {}: no `generator` — name the command or function \
                     that writes it",
                    entry.path
                )));
            }
            if entry.check.as_deref().and_then(check_parts).is_none() {
                return Err(UsageError::raise(format!(
                    "census.shell.generated {}: `check` must be `<test file>::<test name>`, the \
                     test that holds the generated bytes",
                    entry.path
                )));
            }
        }
        self.validate_spawns()?;
        let generated = self.generated.iter().map(|entry| &entry.path);
        for glob in self.workflows.iter().chain(&self.exempt).chain(generated) {
            Selector::new(glob)?;
            if let Some(operator) = ban_unread(glob) {
                return Err(UsageError::raise(format!(
                    "census.shell: glob `{glob}` spells `{operator}`, which the census reads as a \
                     glob operator and the `shell-hygiene` ban reads as a literal character — \
                     the two would judge different files off this one list; write each \
                     alternative as its own entry"
                )));
            }
        }
        Ok(())
    }

    /// Refuse a `[[census.shell.spawn]]` row that names no file or function,
    /// or whose `contract` carries no citation URL.
    fn validate_spawns(&self) -> Result<()> {
        for spawn in &self.spawns {
            let bare = |field: Option<&str>| field.is_none_or(|text| text.trim().is_empty());
            if spawn.path.trim().is_empty() || bare(spawn.function.as_deref()) {
                return Err(UsageError::raise(format!(
                    "census.shell.spawn {}: a row names the file and the function that spawns",
                    spawn.path
                )));
            }
            if bare(spawn.contract.as_deref())
                || !spawn
                    .contract
                    .as_deref()
                    .unwrap_or_default()
                    .contains("://")
            {
                return Err(UsageError::raise(format!(
                    "census.shell.spawn {}: `contract` must name the external format that forces \
                     a shell, with a citation URL",
                    spawn.path
                )));
            }
        }
        Ok(())
    }

    /// The effective mode: migrating when `mode = "migrate"` is declared or a
    /// legacy `exempt` list is non-empty, presence otherwise. `exempt = []` is
    /// the same as absent, so it is presence.
    #[must_use]
    pub fn migrating(&self) -> bool {
        self.mode == Some(ShellMode::Migrate) || !self.exempt.is_empty()
    }
}

/// The `globset` operators the ban's matcher does not implement.
///
/// **ONE LIST, TWO MATCHERS, SO THE LANGUAGE IS THEIR INTERSECTION.** The census
/// matches `workflows` and `exempt` through [`Selector`] (`globset`), and the
/// `shell-hygiene` preset's `no-new-shell` module matches the same strings with
/// its own glob-to-regex, which implements `*`, `?` and `**` and escapes
/// everything else as a literal. Over a brace, a class or a backslash escape the
/// two therefore select different files: `ci/*.{yml,yaml}` is every workflow to
/// the census and none to the ban, so the ban judges nothing while the census
/// counts. Refused at load instead, so no declaration can hold a glob the two
/// read differently. A stray `**` inside a component is not listed: `globset`
/// already refuses it in [`Selector::new`].
const BAN_UNREAD_OPERATORS: [char; 5] = ['{', '}', '[', ']', '\\'];

/// The first operator in `glob` the ban does not implement, if any.
///
/// The row below reads every glob as portable, and the unit case's brace, class
/// and escape then load.
//MUTANT-SUITE crates/batten/src/census.rs
//MUTANT ban-unread-operator-admitted|s@^    glob.chars().find(.c. BAN_UNREAD_OPERATORS.contains(c))$@    glob.chars().find(char::is_ascii_control)@|a_glob_the_ban_reads_differently_is_refused
fn ban_unread(glob: &str) -> Option<char> {
    glob.chars().find(|c| BAN_UNREAD_OPERATORS.contains(c))
}

// ---------------------------------------------------------------------------
// Where the shell is: which lines of a home carry it. Whether a text IS shell
// is `crate::shell`'s, and nothing here re-decides it.
// ---------------------------------------------------------------------------

/// The two quotes that open a multi-line string body.
const QUOTES: [&str; 2] = ["\"\"\"", "'''"];

/// A line that is not blank and not a comment.
///
/// The census's own mutation rows: each breaks a clause of WHERE a home's
/// lines are, and each is caught by the unit case it names, run from this file.
/// Whether a text is shell is the detector's, whose rows live in `shell.rs`.
//MUTANT-SUITE crates/batten/src/census.rs
//MUTANT comments-counted|s@    !text.is_empty() && !text.starts_with('#')@    !text.is_empty()@|a_body_counts_its_code_lines_and_skips_comments_and_blanks
//MUTANT block-never-ends|s@        indent(line) + 2$@        indent(line) + 200@|a_block_ends_at_the_first_line_at_or_left_of_its_key
//MUTANT workflow-one-liner-unread|s@^        } else if let Some(reason) = shell_reason(&yaml_scalar(rest)) {$@        } else if let Some(reason) = None::<\&'static str> {@|a_block_ends_at_the_first_line_at_or_left_of_its_key
#[must_use]
pub fn code_line(line: &str) -> bool {
    let text = line.trim();
    !text.is_empty() && !text.starts_with('#')
}

/// The detector's reason when `text` is shell logic, `None` when it is argv.
fn shell_reason(text: &str) -> Option<&'static str> {
    match crate::shell::logic(text) {
        crate::shell::Verdict::Shell(reason) => Some(reason),
        crate::shell::Verdict::Argv(_) => None,
    }
}

/// A body of source lines, parsed ONCE as one text: its reason when it is
/// shell logic. A body holding one plain command is not.
fn body_reason(lines: &[&str], body: std::ops::Range<usize>) -> Option<&'static str> {
    shell_reason(&lines.get(body)?.join("\n"))
}

/// The reason a carrier's verdict on one spelling carries, `None` for argv.
fn judged(
    carrier: Option<&crate::shell::Carrier>,
    spelling: &crate::shell::Spelling<'_>,
) -> Option<&'static str> {
    match crate::shell::judge(carrier, spelling) {
        crate::shell::Verdict::Shell(reason) => Some(reason),
        crate::shell::Verdict::Argv(_) => None,
    }
}

/// A TOML value's shell reason, judged on the string it holds rather than on
/// its quoting: `run = "a | b"` is a pipeline, not one quoted word. An inline
/// array is judged in the carrier's list form — for a mise task a list of
/// shell strings, shell when any is. A value TOML cannot read is judged as
/// written, which leaves the detector to call a stray quote unparseable rather
/// than reading it clean.
fn toml_reason(value: &str, carrier: Option<&crate::shell::Carrier>) -> Option<&'static str> {
    let parsed = toml::from_str::<toml::Table>(&format!("v = {value}"))
        .ok()
        .and_then(|mut table| table.remove("v"));
    match parsed {
        Some(toml::Value::String(text)) => judged(carrier, &crate::shell::Spelling::Text(&text)),
        Some(toml::Value::Array(items)) => {
            let texts: Vec<&str> = items.iter().filter_map(toml::Value::as_str).collect();
            judged(carrier, &crate::shell::Spelling::List(&texts))
        }
        _ => shell_reason(value),
    }
}

/// A one-line YAML scalar as the string it holds, its quoting removed; the
/// text as written where YAML reads it as something other than a string.
fn yaml_scalar(value: &str) -> String {
    yaml_rust2::YamlLoader::load_from_str(value)
        .ok()
        .and_then(|documents| {
            documents
                .first()
                .and_then(|doc| doc.as_str().map(str::to_owned))
        })
        .unwrap_or_else(|| value.to_owned())
}

/// Every line index of `lines` a manifest's `keys` make shell, in order, read
/// in `carrier`'s forms (`None`: every spelling is shell).
#[must_use]
pub fn manifest_lines(
    lines: &[&str],
    keys: &[String],
    carrier: Option<&crate::shell::Carrier>,
) -> BTreeSet<usize> {
    manifest_reasons(lines, keys, carrier).into_keys().collect()
}

/// Every line index of `lines` a manifest's `keys` make shell, with the
/// detector's reason.
///
/// A key's triple-quoted body is parsed as one text, and when it is shell every
/// code line of it counts. A one-line value counts when the carrier's form of
/// it is shell. A multi-line array is a list: in shell form each entry counts
/// itself when the string it holds is shell; in exec form the entries are one
/// argv, and every entry counts when that argv runs a script.
#[must_use]
pub fn manifest_reasons(
    lines: &[&str],
    keys: &[String],
    carrier: Option<&crate::shell::Carrier>,
) -> BTreeMap<usize, &'static str> {
    let mut shell = BTreeMap::new();
    for key in keys {
        let assign = format!("{key} = ");
        for (i, line) in lines.iter().enumerate() {
            let text = line.trim();
            let Some(value) = text.strip_prefix(assign.as_str()) else {
                continue;
            };
            // A body opener: the quote opens a string that does not close here.
            // One that closes on its own line is a one-line value, below.
            if let Some(quote) = QUOTES.iter().find(|quote| value.starts_with(**quote))
                && !value.get(quote.len()..).unwrap_or_default().contains(quote)
            {
                let closer = lines
                    .iter()
                    .enumerate()
                    .skip(i + 1)
                    .find(|(_, other)| other.contains(quote))
                    .map(|(j, _)| j);
                if let Some(closer) = closer
                    && let Some(reason) = body_reason(lines, i + 1..closer)
                {
                    for j in (i + 1..closer).filter(|&j| lines.get(j).is_some_and(|l| code_line(l)))
                    {
                        shell.entry(j).or_insert(reason);
                    }
                }
                continue;
            }
            // A multi-line array: every entry up to the line opening with `]`.
            if value == "[" {
                let closer = lines
                    .iter()
                    .enumerate()
                    .skip(i + 1)
                    .find(|(_, other)| other.trim().starts_with(']'))
                    .map(|(j, _)| j);
                if let Some(closer) = closer {
                    array_reasons(lines, i + 1..closer, carrier, &mut shell);
                }
                continue;
            }
            // A one-line value, judged on the string it holds.
            if let Some(reason) = toml_reason(value, carrier) {
                shell.entry(i).or_insert(reason);
            }
        }
    }
    shell
}

/// A multi-line array's entries over `entries`, read in `carrier`'s list form.
fn array_reasons(
    lines: &[&str],
    entries: std::ops::Range<usize>,
    carrier: Option<&crate::shell::Carrier>,
    shell: &mut BTreeMap<usize, &'static str>,
) {
    let entry = |j: usize| lines.get(j).map_or("", |l| l.trim().trim_end_matches(','));
    let strings: Vec<(usize, String)> = entries
        .clone()
        .filter_map(|j| {
            let parsed = toml::from_str::<toml::Table>(&format!("v = {}", entry(j))).ok()?;
            Some((j, parsed.get("v")?.as_str()?.to_owned()))
        })
        .collect();
    let texts: Vec<&str> = strings.iter().map(|(_, text)| text.as_str()).collect();
    let list = crate::shell::Spelling::List(&texts);
    if carrier.is_none_or(|carrier| crate::shell::form(carrier, &list) == crate::shell::Form::Shell)
    {
        // Shell form: each entry is its own script, judged as written so a
        // stray quote is the detector's to call.
        for j in entries {
            if let Some(reason) = toml_reason(entry(j), None) {
                shell.entry(j).or_insert(reason);
            }
        }
    } else if let Some(reason) = judged(carrier, &list) {
        for (j, _) in strings {
            shell.entry(j).or_insert(reason);
        }
    }
}

/// The run of leading spaces, in characters.
fn indent(line: &str) -> usize {
    line.chars().count() - line.trim_start_matches(' ').chars().count()
}

/// The value of a `run:` key on this line, if the line is one: a field of
/// the `gha-run` carrier, a workflow's or a composite action's step, either
/// of which has only a shell form.
fn run_key(line: &str) -> Option<&str> {
    let text = line.trim();
    let text = text.strip_prefix("- ").unwrap_or(text);
    crate::shell::GHA_RUN.fields.iter().find_map(|field| {
        text.strip_prefix(field)
            .and_then(|rest| rest.strip_prefix(':'))
            .map(str::trim)
    })
}

/// The column a block's lines must exceed: the `run:` key's own.
fn key_column(line: &str) -> usize {
    if line.trim().starts_with("- ") {
        indent(line) + 2
    } else {
        indent(line)
    }
}

/// Every step in a workflow that carries shell: the `run:` key's line index,
/// mapped to the line indices it contributes.
///
/// A line claimed by two overlapping blocks is counted once, for the step that
/// opened nearest above it, so the per-step counts sum to the file's total.
#[must_use]
pub fn workflow_steps(lines: &[&str]) -> BTreeMap<usize, BTreeSet<usize>> {
    let mut steps: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
    for (line, (step, _)) in workflow_owned(lines) {
        steps.entry(step).or_default().insert(line);
    }
    steps
}

/// Every shell line of a workflow, mapped to the step that owns it and the
/// detector's reason.
///
/// A `run: |` or `run: >` block is fed to the detector as its SOURCE lines,
/// never folded, so two lines are two commands whichever marker opened them.
fn workflow_owned(lines: &[&str]) -> BTreeMap<usize, (usize, &'static str)> {
    let mut owner: BTreeMap<usize, (usize, &'static str)> = BTreeMap::new();
    for (i, line) in lines.iter().enumerate() {
        let Some(rest) = run_key(line) else {
            continue;
        };
        if rest.starts_with('|') || rest.starts_with('>') {
            let column = key_column(line);
            let closer = lines
                .iter()
                .enumerate()
                .skip(i + 1)
                .find(|(_, other)| !other.trim().is_empty() && indent(other) <= column)
                .map_or(lines.len(), |(k, _)| k);
            let Some(reason) = body_reason(lines, i + 1..closer) else {
                continue;
            };
            for j in i + 1..closer {
                if lines.get(j).is_some_and(|l| code_line(l)) {
                    owner.insert(j, (i, reason));
                }
            }
        } else if let Some(reason) = shell_reason(&yaml_scalar(rest)) {
            owner.insert(i, (i, reason));
        }
    }
    owner
}

// ---------------------------------------------------------------------------
// The report.
// ---------------------------------------------------------------------------

/// One counted run of manifest lines: a named unit, or a lone line outside one.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ManifestEntry {
    /// The manifest.
    pub path: String,
    /// The 1-based line of the unit's header, or of the lone line.
    pub line: usize,
    /// The unit's name as its header spells it; absent for a lone line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    /// How many shell code lines.
    pub lines: usize,
}

/// One workflow step carrying shell.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct StepEntry {
    /// The workflow.
    pub path: String,
    /// The 1-based line of the step's `run:` key.
    pub line: usize,
    /// How many shell code lines.
    pub lines: usize,
}

/// One shell file, or one exempt path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct FileEntry {
    /// The file.
    pub path: String,
    /// How many code lines.
    pub lines: usize,
}

/// The sums a reader compares across two runs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Totals {
    /// Shell lines in manifests.
    pub manifests: usize,
    /// Shell lines in workflow steps.
    pub steps: usize,
    /// Code lines in shell files.
    pub files: usize,
    /// Lines under an exempt path, never part of `total`.
    pub exempt: usize,
    /// `manifests + steps + files`.
    pub total: usize,
}

/// The whole census, in the order it renders.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Report {
    /// Manifest units and lone lines.
    pub manifests: Vec<ManifestEntry>,
    /// Workflow steps.
    pub steps: Vec<StepEntry>,
    /// Shell files.
    pub files: Vec<FileEntry>,
    /// Exempt paths, measured and set apart.
    pub exempt: Vec<FileEntry>,
    /// Each `[[census.shell.generated]]` entry, held to what is behind it.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub generated: Vec<GeneratedEntry>,
    /// Engine source spawning a shell (CLOUD-2770), declared or not.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub spawns: Vec<SpawnEntry>,
    /// The sums.
    pub totals: Totals,
}

/// One generated entry as the tree holds it: how many tracked paths its glob
/// matches, and whether a line of its check file carries the test name. The
/// same shape `input.tree.shell.generated` hands the ban.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct GeneratedEntry {
    /// The entry's glob.
    pub path: String,
    /// Tracked paths the glob matches.
    pub matches: usize,
    /// Whether the check file exists and a line of it holds the test name.
    pub check_found: bool,
}

/// The census's generated entries, measured on the tree at `root`. The check
/// file is a NEW read: [`take`]'s loop skips every file that is not shell, and a
/// test file is not.
fn generated_on_disk(
    root: &Path,
    declared: &ShellCensus,
    tracked: &BTreeSet<String>,
) -> Vec<GeneratedEntry> {
    generated_entries(
        declared
            .generated
            .iter()
            .map(|entry| (entry.path.as_str(), entry.check.as_deref())),
        &mut tracked.iter().map(String::as_str),
        &|file| std::fs::read_to_string(root.join(file)).ok(),
    )
}

/// Every generated entry measured against `tracked`, reading each check file
/// through `read`. A glob `globset` refuses matches nothing; `validate` has
/// already refused one at load.
fn generated_entries<'g>(
    generated: impl IntoIterator<Item = (&'g str, Option<&'g str>)>,
    tracked: &mut dyn Iterator<Item = &str>,
    read: &dyn Fn(&str) -> Option<String>,
) -> Vec<GeneratedEntry> {
    let tracked: Vec<&str> = tracked.collect();
    generated
        .into_iter()
        .map(|(path, check)| {
            let matches = Selector::new(path).map_or(0, |selector| {
                tracked.iter().filter(|p| selector.matches(p)).count()
            });
            let check_found = check
                .and_then(check_parts)
                .is_some_and(|(file, name)| read(file).is_some_and(|text| holds_test(&text, name)));
            GeneratedEntry {
                path: path.to_owned(),
                matches,
                check_found,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Engine source that spawns a shell (CLOUD-2770). Whether an argv runs one is
// `crate::shell::spawns_shell`'s; this walk only finds the argv.
// ---------------------------------------------------------------------------

/// One engine spawn site: a string-literal argv, outside test code, whose
/// program [`crate::shell::spawns_shell`] reads as running a shell.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct SpawnEntry {
    /// The source file.
    pub path: String,
    /// The 1-based line of the argv's program.
    pub line: usize,
    /// The function (or `const`/`static`) holding it. Absent for a file the
    /// parser refused, which is one site no row can declare: could-not-look is
    /// never clean.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
}

/// How a site of a file the parser refused renders.
const UNPARSED: &str = "<unparsed>";

/// Whether a tracked path is engine source: a `.rs` file under a `src`
/// directory. A crate's tests, benches and build script are not; a test module
/// inside `src` is skipped by the walk.
fn engine_source(path: &str) -> bool {
    Path::new(path)
        .extension()
        .is_some_and(|extension| extension == "rs")
        && (path.starts_with("src/") || path.contains("/src/"))
}

/// Every engine spawn site in the tracked tree at `root`.
fn spawns_on_disk(root: &Path, tracked: &BTreeSet<String>) -> Vec<SpawnEntry> {
    tracked
        .iter()
        .filter(|path| engine_source(path))
        .filter_map(|path| {
            let bytes = std::fs::read(root.join(path)).ok()?;
            Some(spawn_sites(path, &String::from_utf8_lossy(&bytes)))
        })
        .flatten()
        .collect()
}

/// Every shell spawn site in one engine source file, in source order.
fn spawn_sites(path: &str, text: &str) -> Vec<SpawnEntry> {
    let Ok(file) = crate::source::rust(text) else {
        return vec![SpawnEntry {
            path: path.to_owned(),
            line: 1,
            function: None,
        }];
    };
    if test_only(&file.attrs) {
        return Vec::new();
    }
    let mut walk = SpawnWalk {
        owner: None,
        found: BTreeMap::new(),
    };
    syn::visit::Visit::visit_file(&mut walk, &file);
    walk.found
        .into_iter()
        .map(|((line, _), function)| SpawnEntry {
            path: path.to_owned(),
            line,
            function,
        })
        .collect()
}

/// Whether `attrs` mark an item as test code: `#[test]` or exactly
/// `#[cfg(test)]`. Test code is CLOUD-2336's, not this arm's.
fn test_only(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("test")
            || (attr.path().is_ident("cfg")
                && attr
                    .parse_args::<syn::Ident>()
                    .is_ok_and(|ident| ident == "test"))
    })
}

/// An item's attributes, for the kinds that can hold code.
fn item_attrs(item: &syn::Item) -> &[syn::Attribute] {
    match item {
        syn::Item::Const(item) => &item.attrs,
        syn::Item::Fn(item) => &item.attrs,
        syn::Item::Impl(item) => &item.attrs,
        syn::Item::Macro(item) => &item.attrs,
        syn::Item::Mod(item) => &item.attrs,
        syn::Item::Static(item) => &item.attrs,
        syn::Item::Trait(item) => &item.attrs,
        _ => &[],
    }
}

/// A string literal, through `&` and parentheses.
fn literal(expr: &syn::Expr) -> Option<String> {
    literal_token(expr).map(syn::LitStr::value)
}

/// [`literal`]'s token, for its position.
fn literal_token(expr: &syn::Expr) -> Option<&syn::LitStr> {
    match expr {
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(text),
            ..
        }) => Some(text),
        syn::Expr::Reference(inner) => literal_token(&inner.expr),
        syn::Expr::Paren(inner) => literal_token(&inner.expr),
        _ => None,
    }
}

/// The word standing for an argument the source computes: an inline flag whose
/// script is computed still carries one.
const COMPUTED: &str = "<computed>";

/// A sequence's leading string literals, then [`COMPUTED`] once for whatever
/// follows them.
fn literal_argv<'e>(items: impl IntoIterator<Item = &'e syn::Expr>) -> Vec<String> {
    let mut argv = Vec::new();
    for item in items {
        if let Some(word) = literal(item) {
            argv.push(word);
        } else {
            argv.push(COMPUTED.to_owned());
            break;
        }
    }
    argv
}

/// `Command::new("<literal>")` by any path ending in it: the call's span and
/// the program.
fn command_new(call: &syn::ExprCall) -> Option<(proc_macro2::Span, String)> {
    let syn::Expr::Path(path) = &*call.func else {
        return None;
    };
    let [.., ty, new] = path.path.segments.iter().collect::<Vec<_>>()[..] else {
        return None;
    };
    if ty.ident != "Command" || new.ident != "new" {
        return None;
    }
    let program = literal_token(call.args.first()?)?;
    Some((program.span(), program.value()))
}

/// The walk: the item owning the code under it, and each site found, keyed by
/// its program's position so a method chain and the call it starts from are
/// one site.
struct SpawnWalk {
    owner: Option<String>,
    found: BTreeMap<(usize, usize), Option<String>>,
}

impl SpawnWalk {
    /// Record `argv`, whose program sits at `at`, when it runs a shell. The
    /// first record at a position wins: an outer method chain is visited before
    /// the call it starts from, and carries more of the argv.
    fn record(&mut self, at: proc_macro2::Span, argv: &[String]) {
        let words: Vec<&str> = argv.iter().map(String::as_str).collect();
        if crate::shell::spawns_shell(&words) {
            let start = at.start();
            let owner = self.owner.clone();
            self.found
                .entry((start.line, start.column))
                .or_insert(owner);
        }
    }

    /// A sequence spelled as an argv: its first two elements are string
    /// literals. One literal beside a value is a table row, not an argv.
    fn sequence(&mut self, items: &[&syn::Expr]) {
        if let [first, second, ..] = items
            && let Some(program) = literal_token(first)
            && literal(second).is_some()
        {
            let argv = literal_argv(items.iter().copied());
            self.record(program.span(), &argv);
        }
    }

    /// Walk `visit` with `name` as the owner.
    fn owned(&mut self, name: String, visit: impl FnOnce(&mut Self)) {
        let outer = self.owner.replace(name);
        visit(self);
        self.owner = outer;
    }
}

impl<'ast> syn::visit::Visit<'ast> for SpawnWalk {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        if test_only(item_attrs(item)) {
            return;
        }
        match item {
            syn::Item::Fn(function) => self.owned(function.sig.ident.to_string(), |walk| {
                syn::visit::visit_item(walk, item);
            }),
            syn::Item::Const(constant) => self.owned(constant.ident.to_string(), |walk| {
                syn::visit::visit_item(walk, item);
            }),
            syn::Item::Static(value) => self.owned(value.ident.to_string(), |walk| {
                syn::visit::visit_item(walk, item);
            }),
            _ => syn::visit::visit_item(self, item),
        }
    }

    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        match item {
            syn::ImplItem::Fn(function) if test_only(&function.attrs) => {}
            syn::ImplItem::Fn(function) => self.owned(function.sig.ident.to_string(), |walk| {
                syn::visit::visit_impl_item(walk, item);
            }),
            syn::ImplItem::Const(constant) => self.owned(constant.ident.to_string(), |walk| {
                syn::visit::visit_impl_item(walk, item);
            }),
            _ => syn::visit::visit_impl_item(self, item),
        }
    }

    fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
        self.owned(item.sig.ident.to_string(), |walk| {
            syn::visit::visit_trait_item_fn(walk, item);
        });
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Some((at, program)) = command_new(call) {
            self.record(at, &[program]);
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        // The chain from this call down to its root, outermost first.
        let mut chain = vec![call];
        let mut root = &*call.receiver;
        while let syn::Expr::MethodCall(inner) = root {
            chain.push(inner);
            root = &inner.receiver;
        }
        if let syn::Expr::Call(root) = root
            && let Some((at, program)) = command_new(root)
        {
            let mut argv = vec![program];
            for link in chain.iter().rev() {
                if argv.last().is_some_and(|word| word == COMPUTED) {
                    break;
                }
                if link.method == "arg" {
                    argv.extend(literal_argv(link.args.first()));
                } else if link.method == "args" {
                    let array = link.args.first().map(|arg| match arg {
                        syn::Expr::Reference(inner) => &*inner.expr,
                        other => other,
                    });
                    match array {
                        Some(syn::Expr::Array(array)) => argv.extend(literal_argv(&array.elems)),
                        _ => argv.push(COMPUTED.to_owned()),
                    }
                }
            }
            self.record(at, &argv);
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_tuple(&mut self, tuple: &'ast syn::ExprTuple) {
        self.sequence(&tuple.elems.iter().collect::<Vec<_>>());
        syn::visit::visit_expr_tuple(self, tuple);
    }

    fn visit_expr_array(&mut self, array: &'ast syn::ExprArray) {
        self.sequence(&array.elems.iter().collect::<Vec<_>>());
        syn::visit::visit_expr_array(self, array);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        // A macro body is tokens to `syn`; one whose body is comma-separated
        // expressions (`vec!`, `format!`, `assert!`) is walked as them, and
        // `vec!`'s is an argv as an array literal's is.
        let Ok(args) = mac.parse_body_with(
            syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated,
        ) else {
            return;
        };
        if mac.path.is_ident("vec") {
            self.sequence(&args.iter().collect::<Vec<_>>());
        }
        for arg in &args {
            syn::visit::Visit::visit_expr(self, arg);
        }
    }
}

impl Report {
    /// The pointer lines, one per entry, then the totals.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        let mut rendered = Vec::new();
        for entry in &self.manifests {
            match entry.unit {
                Some(ref unit) => rendered.push(format!(
                    "{}:{} unit {unit} {}",
                    entry.path, entry.line, entry.lines
                )),
                None => rendered.push(format!(
                    "{}:{} line {}",
                    entry.path, entry.line, entry.lines
                )),
            }
        }
        for entry in &self.steps {
            rendered.push(format!(
                "{}:{} step {}",
                entry.path, entry.line, entry.lines
            ));
        }
        for entry in &self.files {
            rendered.push(format!("{} file {}", entry.path, entry.lines));
        }
        for entry in &self.exempt {
            rendered.push(format!("{} exempt {}", entry.path, entry.lines));
        }
        for entry in &self.spawns {
            rendered.push(format!(
                "{}:{} spawn {}",
                entry.path,
                entry.line,
                entry.function.as_deref().unwrap_or(UNPARSED)
            ));
        }
        let totals = self.totals;
        rendered.push(format!(
            "total {} manifests={} steps={} files={} exempt={}",
            totals.total, totals.manifests, totals.steps, totals.files, totals.exempt
        ));
        rendered
    }
}

/// The unit a header line opens, as the header spells it past `prefix`.
fn unit_name(header: &str, prefix: &str) -> String {
    let rest = header.trim().strip_prefix(prefix).unwrap_or_default();
    let rest = rest
        .rfind(']')
        .map_or(rest, |end| rest.get(..end).unwrap_or(rest));
    rest.trim().trim_matches('"').trim_matches('\'').to_owned()
}

/// Group a manifest's shell lines into its units, or into lone lines.
fn manifest_entries(path: &str, lines: &[&str], manifest: &Manifest) -> Vec<ManifestEntry> {
    let shell = manifest_lines(lines, &manifest.fields(), manifest.carrier());
    let headers: Vec<usize> = match manifest.unit.as_deref() {
        Some(prefix) => lines
            .iter()
            .enumerate()
            .filter(|(_, line)| line.trim().starts_with(prefix))
            .map(|(h, _)| h)
            .collect(),
        None => Vec::new(),
    };
    let mut units: BTreeMap<usize, usize> = BTreeMap::new();
    let mut lone: Vec<usize> = Vec::new();
    for &j in &shell {
        // The nearest header at or above the line owns it: a span runs from its
        // header to the next one.
        match headers.iter().rev().find(|&&h| h <= j) {
            Some(&h) => *units.entry(h).or_default() += 1,
            None => lone.push(j),
        }
    }
    let prefix = manifest.unit.as_deref().unwrap_or_default();
    let mut entries: Vec<ManifestEntry> = units
        .into_iter()
        .map(|(h, count)| ManifestEntry {
            path: path.to_owned(),
            line: h + 1,
            unit: Some(unit_name(lines.get(h).copied().unwrap_or_default(), prefix)),
            lines: count,
        })
        .chain(lone.into_iter().map(|j| ManifestEntry {
            path: path.to_owned(),
            line: j + 1,
            unit: None,
            lines: 1,
        }))
        .collect();
    entries.sort();
    entries
}

/// Take the census of the tree at `root` under `declared`.
///
/// An exempt file is set apart and never totalled; the row below reads the
/// exempt list as empty, and the compiled tier's pinned totals go red.
//MUTANT-SUITE crates/batten/tests/it/census_shell.rs
//MUTANT exempt-unread|s@    let exempt: Vec<Selector> = declared$@    let exempt: Vec<Selector> = ShellCensus::default()@|the_census_counts_the_fixture_as_the_shapes_say
///
/// A workflow glob selects a composite action's metadata as readily as a
/// workflow: both carry `gha-run` steps. The row below drops the composite
/// action, and its fixture case goes red.
//MUTANT composite-action-unread|s@^        let is_workflow = workflows.iter().any(.selector. selector.matches(path));$@        let is_workflow = workflows.iter().any(\x7cselector\x7c selector.matches(path)) \&\& !path.ends_with("action.yml");@|a_composite_actions_steps_are_counted_only_where_declared
///
/// `tracked` is the tree's tracked paths, which is where workflows and shell
/// files are found; a declared manifest is read by its path whether or not it
/// is tracked, because the consumer named it.
///
/// # Errors
///
/// A [`UsageError`] (→ exit `1`) for a declaration [`ShellCensus::validate`]
/// refuses, and an internal error (→ exit `3`) for a declared manifest that
/// cannot be read — a census that skipped it would report a smaller number than
/// the tree carries.
pub fn take(root: &Path, declared: &ShellCensus, tracked: &BTreeSet<String>) -> Result<Report> {
    declared.validate()?;
    let exempt: Vec<Selector> = declared
        .exempt
        .iter()
        .map(|glob| Selector::new(glob))
        .collect::<Result<_>>()?;
    let workflows: Vec<Selector> = declared
        .workflows
        .iter()
        .map(|glob| Selector::new(glob))
        .collect::<Result<_>>()?;
    let is_exempt = |path: &str| exempt.iter().any(|selector| selector.matches(path));

    let mut report = Report::default();
    let mut set_apart: BTreeMap<String, usize> = BTreeMap::new();

    for manifest in &declared.manifests {
        let text = std::fs::read_to_string(root.join(&manifest.path)).map_err(|err| {
            anyhow::anyhow!(
                "census shell: the declared manifest {} cannot be read: {err}",
                manifest.path
            )
        })?;
        let lines: Vec<&str> = text.lines().collect();
        let entries = manifest_entries(&manifest.path, &lines, manifest);
        if is_exempt(&manifest.path) {
            *set_apart.entry(manifest.path.clone()).or_default() +=
                entries.iter().map(|entry| entry.lines).sum::<usize>();
        } else {
            report.manifests.extend(entries);
        }
    }

    let declared_manifests: BTreeSet<&str> =
        declared.manifests.iter().map(|m| m.path.as_str()).collect();
    for path in tracked {
        if declared_manifests.contains(path.as_str()) {
            continue;
        }
        // A workflow glob may name a composite action as readily as a workflow:
        // both carry `gha-run` steps (`composite-action-unread` above).
        let is_workflow = workflows.iter().any(|selector| selector.matches(path));
        // A path that is not a file — a submodule's gitlink, a file deleted from
        // the working tree — has no lines to count.
        let Ok(bytes) = std::fs::read(root.join(path)) else {
            continue;
        };
        // Decoding every tracked file to ask about its first two bytes would
        // cost the whole tree for the few files that can be shell at all.
        if !is_workflow && !crate::shell::shell_path(path) && !bytes.starts_with(b"#!") {
            continue;
        }
        let text = String::from_utf8_lossy(&bytes);
        let lines: Vec<&str> = text.lines().collect();
        if is_workflow {
            let steps: Vec<StepEntry> = workflow_steps(&lines)
                .into_iter()
                .map(|(line, counted)| StepEntry {
                    path: path.clone(),
                    line: line + 1,
                    lines: counted.len(),
                })
                .collect();
            if is_exempt(path) {
                let sum: usize = steps.iter().map(|step| step.lines).sum();
                if sum > 0 {
                    *set_apart.entry(path.clone()).or_default() += sum;
                }
            } else {
                report.steps.extend(steps);
            }
            continue;
        }
        let first = lines.first().copied().unwrap_or_default();
        if !(crate::shell::shell_path(path) || crate::shell::shebang(first).is_some()) {
            continue;
        }
        let count = lines.iter().filter(|line| code_line(line)).count();
        if is_exempt(path) {
            *set_apart.entry(path.clone()).or_default() += count;
        } else {
            report.files.push(FileEntry {
                path: path.clone(),
                lines: count,
            });
        }
    }

    report.generated = generated_on_disk(root, declared, tracked);
    report.spawns = spawns_on_disk(root, tracked);
    report.manifests.sort();
    report.steps.sort();
    report.files.sort();
    report.exempt = set_apart
        .into_iter()
        .map(|(path, lines)| FileEntry { path, lines })
        .collect();
    let manifests: usize = report.manifests.iter().map(|entry| entry.lines).sum();
    let steps: usize = report.steps.iter().map(|entry| entry.lines).sum();
    let files: usize = report.files.iter().map(|entry| entry.lines).sum();
    report.totals = Totals {
        manifests,
        steps,
        files,
        exempt: report.exempt.iter().map(|entry| entry.lines).sum(),
        total: manifests + steps + files,
    };
    Ok(report)
}

// ---------------------------------------------------------------------------
// The fact the ban reads.
// ---------------------------------------------------------------------------

/// The `[census.shell]` homes a tree document declares, found by SHAPE as the
/// `shell-hygiene` preset finds them: any declared document carrying
/// `census.shell`. Read leniently, field by field, for the same reason the
/// module did: a row that hands over no such table has declared no homes.
struct Homes {
    /// Manifest path -> its command fields, unioned across rows naming one
    /// path, and the carrier the last row naming one declared.
    manifests: BTreeMap<String, (Vec<String>, Option<&'static crate::shell::Carrier>)>,
    /// The workflow globs.
    workflows: Vec<Selector>,
    /// The `[[census.shell.generated]]` rows, as `(glob, check)`.
    generated: Vec<(String, Option<String>)>,
    /// Whether any document declared a `[census.shell]` table at all.
    declared: bool,
}

impl Homes {
    fn find(documents: &serde_json::Map<String, serde_json::Value>) -> Self {
        let mut homes = Homes {
            manifests: BTreeMap::new(),
            workflows: Vec::new(),
            generated: Vec::new(),
            declared: false,
        };
        let declarations = documents
            .values()
            .filter_map(|doc| doc.get("census")?.get("shell"))
            .filter(|shell| shell.is_object());
        for shell in declarations {
            homes.declared = true;
            let rows = shell.get("generated").and_then(serde_json::Value::as_array);
            for row in rows.into_iter().flatten() {
                let Some(path) = row.get("path").and_then(serde_json::Value::as_str) else {
                    continue;
                };
                let check = row.get("check").and_then(serde_json::Value::as_str);
                homes
                    .generated
                    .push((path.to_owned(), check.map(str::to_owned)));
            }
            let rows = shell.get("manifest").and_then(serde_json::Value::as_array);
            for row in rows.into_iter().flatten() {
                let Some(path) = row.get("path").and_then(serde_json::Value::as_str) else {
                    continue;
                };
                let carrier = row
                    .get("carrier")
                    .and_then(serde_json::Value::as_str)
                    .and_then(manifest_carrier);
                let keys = row.get("keys").and_then(serde_json::Value::as_array);
                let (fields, read_as) = homes.manifests.entry(path.to_owned()).or_default();
                if carrier.is_some() {
                    *read_as = carrier;
                }
                let named = carrier
                    .into_iter()
                    .flat_map(|carrier| carrier.fields.iter().copied());
                let listed = keys
                    .into_iter()
                    .flatten()
                    .filter_map(serde_json::Value::as_str);
                for key in named.chain(listed) {
                    if !fields.iter().any(|known| known == key) {
                        fields.push(key.to_owned());
                    }
                }
            }
            let globs = shell.get("workflows").and_then(serde_json::Value::as_array);
            for glob in globs
                .into_iter()
                .flatten()
                .filter_map(serde_json::Value::as_str)
            {
                if let Ok(selector) = Selector::new(glob) {
                    homes.workflows.push(selector);
                }
            }
        }
        homes
    }

    /// One path's entry on one side: its kind and its shell lines, or `None`
    /// for a path that is no home and no shell file. `lines` is `None` where the
    /// row did not hand the path over as lines.
    fn entry(&self, path: &str, lines: Option<&[&str]>) -> Option<serde_json::Value> {
        let (kind, reasons): (&str, BTreeMap<usize, &'static str>) =
            if let Some((fields, carrier)) = self.manifests.get(path) {
                ("manifest", manifest_reasons(lines?, fields, *carrier))
            } else if self.workflows.iter().any(|selector| selector.matches(path)) {
                let owned = workflow_owned(lines?);
                (
                    "workflow",
                    owned
                        .into_iter()
                        .map(|(j, (_, reason))| (j, reason))
                        .collect(),
                )
            } else {
                let first = lines
                    .and_then(|lines| lines.first().copied())
                    .unwrap_or_default();
                let reason = if crate::shell::shell_path(path) {
                    "path"
                } else if crate::shell::shebang(first).is_some() {
                    "shebang"
                } else {
                    return None;
                };
                let counted = lines
                    .unwrap_or_default()
                    .iter()
                    .enumerate()
                    .filter(|(_, line)| code_line(line))
                    .map(|(j, _)| (j, reason))
                    .collect();
                ("file", counted)
            };
        let lines: Vec<serde_json::Value> = reasons
            .into_iter()
            .map(|(j, reason)| serde_json::json!({"line": j + 1, "reason": reason}))
            .collect();
        Some(serde_json::json!({"kind": kind, "lines": lines}))
    }
}

/// The working tree the shell fact reads beyond a row's `line_sources`
/// (CLOUD-2628): presence is judged over EVERY tracked file, so a shell file no
/// line source names must still reach the fact.
///
/// One per run, shared by every row: which tracked paths can be shell at all is
/// probed once (a shell name, or a file opening with `#!`), and each file read
/// is kept, so a second row reading the same tree pays nothing.
#[derive(Debug)]
pub struct TreeReader<'a> {
    root: &'a Path,
    tracked: &'a [String],
    candidates: std::sync::OnceLock<BTreeSet<String>>,
    read: std::sync::Mutex<BTreeMap<String, Option<Vec<String>>>>,
}

impl<'a> TreeReader<'a> {
    /// A reader over `tracked`, rooted at `root`. Reads nothing until asked.
    #[must_use]
    pub fn new(root: &'a Path, tracked: &'a [String]) -> Self {
        Self {
            root,
            tracked,
            candidates: std::sync::OnceLock::new(),
            read: std::sync::Mutex::new(BTreeMap::new()),
        }
    }

    /// Every tracked path that can be shell: a shell name, or a file whose
    /// first two bytes are `#!`. Decoding every tracked file to ask about two
    /// bytes would cost the whole tree for the few that can be shell at all.
    fn candidates(&self) -> &BTreeSet<String> {
        self.candidates.get_or_init(|| {
            self.tracked
                .iter()
                .filter(|path| crate::shell::shell_path(path) || hash_bang(&self.root.join(path)))
                .cloned()
                .collect()
        })
    }

    /// A tracked file's lines, read once and kept; `None` for one that cannot
    /// be read.
    fn lines(&self, path: &str) -> Option<Vec<String>> {
        let mut read = self
            .read
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        read.entry(path.to_owned())
            .or_insert_with(|| {
                std::fs::read(self.root.join(path)).ok().map(|bytes| {
                    String::from_utf8_lossy(&bytes)
                        .lines()
                        .map(str::to_owned)
                        .collect()
                })
            })
            .clone()
    }
}

/// Whether the file at `path` opens with `#!`.
fn hash_bang(path: &Path) -> bool {
    use std::io::Read as _;
    let mut first = [0_u8; 2];
    std::fs::File::open(path)
        .and_then(|mut file| file.read_exact(&mut first))
        .is_ok_and(|()| &first == b"#!")
}

/// How far a row's shell fact reaches past its `line_sources`.
#[derive(Debug, Clone, Copy)]
pub struct Reach<'r, 'a> {
    /// The run's reader.
    pub reader: &'r TreeReader<'a>,
    /// Read the whole tree even when the row's documents declare no
    /// `[census.shell]`: the row enables the `shell-hygiene` preset, whose ban
    /// judges presence for a consumer that declares nothing.
    pub always: bool,
}

/// `input.tree.shell` (CLOUD-2625): every declared home's shell lines, and
/// every shell file, on both sides of the row's delta, as the detector reads
/// them; and each `[[census.shell.generated]]` entry held to what is behind it
/// (CLOUD-2628).
///
/// The head side reads `input.tree.lines` and the delta's `added` paths, so an
/// added file is shell by its name even where no line source covers it. With a
/// [`Reach`] that applies — the row enables the preset, or hands over a
/// `[census.shell]` table — it also reads every tracked file that can be shell,
/// every declared manifest and every tracked path a workflow glob selects, so
/// presence is judged over the whole tree rather than the row's line sources.
/// The base side reads the delta's `base-lines`. A path absent from a side is
/// either no home or one that side could not read, and the ban reads both as
/// nothing there — never as clean.
///
/// `generated` is one `{path, matches, check_found}` per entry: how many of
/// `tracked` its glob matches, and whether a line of its check file holds the
/// test name. A check file that cannot be read is `check_found: false`.
///
/// `spawn` is one `{path, line, function}` per engine spawn site (CLOUD-2770):
/// a string-literal argv outside test code in a tracked `src/**.rs` file whose
/// program runs a shell. Present only with a [`Reach`] that applies, since
/// both directions of the `[[census.shell.spawn]]` table need the whole tree.
///
/// Pointer-only (non-negotiable rule 4): a kind, a 1-based line, the detector's
/// reason, a count and a boolean. Never a byte of the body.
#[must_use]
pub fn tree_fact(
    documents: &serde_json::Map<String, serde_json::Value>,
    head: &serde_json::Map<String, serde_json::Value>,
    delta: Option<&crate::git::BaseDelta>,
    tracked: &[String],
    reach: Option<Reach<'_, '_>>,
) -> serde_json::Value {
    let homes = Homes::find(documents);
    let reader = reach
        .filter(|reach| reach.always || homes.declared)
        .map(|reach| reach.reader);
    let lines_of = |value: &serde_json::Value| -> Vec<String> {
        value
            .as_array()
            .map(|lines| {
                lines
                    .iter()
                    .filter_map(|line| line.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    };
    let added = delta
        .map(|delta| delta.added.as_slice())
        .unwrap_or_default();
    let mut paths: BTreeSet<&str> = head
        .keys()
        .map(String::as_str)
        .chain(added.iter().map(String::as_str))
        .collect();
    if let Some(reader) = reader {
        paths.extend(reader.candidates().iter().map(String::as_str));
        paths.extend(homes.manifests.keys().map(String::as_str));
        paths.extend(
            tracked
                .iter()
                .filter(|path| homes.workflows.iter().any(|glob| glob.matches(path)))
                .map(String::as_str),
        );
    }
    let read = |path: &str| -> Option<Vec<String>> {
        head.get(path)
            .map(lines_of)
            .or_else(|| reader.and_then(|reader| reader.lines(path)))
    };
    let mut head_side = serde_json::Map::new();
    for path in paths {
        let owned = read(path);
        let borrowed: Option<Vec<&str>> = owned
            .as_ref()
            .map(|lines| lines.iter().map(String::as_str).collect());
        if let Some(entry) = homes.entry(path, borrowed.as_deref()) {
            head_side.insert(path.to_owned(), entry);
        }
    }
    let generated = generated_entries(
        homes
            .generated
            .iter()
            .map(|(path, check)| (path.as_str(), check.as_deref())),
        &mut tracked.iter().map(String::as_str),
        &|file| read(file).map(|lines| lines.join("\n")),
    );
    let mut base_side = serde_json::Map::new();
    for (path, lines) in delta.map(|delta| &delta.base_lines).into_iter().flatten() {
        let borrowed: Vec<&str> = lines.iter().map(String::as_str).collect();
        if let Some(entry) = homes.entry(path, Some(&borrowed)) {
            base_side.insert(path.clone(), entry);
        }
    }
    let mut fact =
        serde_json::json!({"head": head_side, "base": base_side, "generated": generated});
    // Engine spawn sites (CLOUD-2770), only where the whole tree was read: a
    // fact that read a row's line sources alone would hand the ban an absent
    // site as no site, and every declared row would read as naming nothing.
    if let Some(reader) = reader {
        let sources: BTreeSet<&str> = reader
            .tracked
            .iter()
            .map(String::as_str)
            .chain(head.keys().map(String::as_str))
            .filter(|path| engine_source(path))
            .collect();
        let spawn: Vec<SpawnEntry> = sources
            .into_iter()
            .filter_map(|path| Some(spawn_sites(path, &read(path)?.join("\n"))))
            .flatten()
            .collect();
        if let Some(object) = fact.as_object_mut() {
            object.insert("spawn".to_owned(), serde_json::json!(spawn));
        }
    }
    fact
}

/// `batten census shell`: render the census of this repository.
///
/// # Errors
///
/// A [`UsageError`] (→ exit `1`) when the authority declares no
/// `[census.shell]` — a census over nothing declared would report a zero it
/// never measured — and whatever [`take`] refuses.
pub fn run_shell(
    declared: Option<&ShellCensus>,
    root: &Path,
    json: bool,
    out: &mut dyn Write,
) -> Result<ExitCode> {
    let declared = declared.ok_or_else(|| {
        UsageError::raise(format!(
            "census shell: no [census.shell] in {}; nothing declares where shell lives here",
            crate::config::CONFIG_FILE
        ))
    })?;
    let tracked = crate::git::tracked_paths(root)?;
    let report = take(root, declared, &tracked)?;
    if json {
        writeln!(out, "{}", serde_json::to_string_pretty(&report)?)?;
    } else {
        for line in report.lines() {
            writeln!(out, "{line}")?;
        }
    }
    Ok(ExitCode::Success)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn keys(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    #[test]
    fn a_body_counts_its_code_lines_and_skips_comments_and_blanks() {
        let lines = [
            "[tasks.a]",
            "run = '''",
            "# why",
            "",
            "echo one",
            "echo two",
            "'''",
        ];
        let shell = manifest_lines(&lines, &keys(&["run"]), None);
        assert_eq!(shell, BTreeSet::from([4, 5]));
    }

    #[test]
    fn a_body_that_closes_on_its_opening_line_is_no_body() {
        let lines = ["run = '''echo one'''", "echo two"];
        assert!(manifest_lines(&lines, &keys(&["run"]), None).is_empty());
    }

    /// Through the detector (CLOUD-2625): a plain command is argv, a list and
    /// an assignment prefix are shell.
    #[test]
    fn a_plain_argv_is_not_shell_and_a_pipeline_is() {
        let lines = [
            "run = \"cargo nextest run\"",
            "run = \"cargo build && cargo test\"",
            "run = \"FOO=1 cargo test\"",
        ];
        assert_eq!(
            manifest_lines(&lines, &keys(&["run"]), None),
            BTreeSet::from([1, 2])
        );
    }

    #[test]
    fn set_e_is_argv_whichever_way_it_is_quoted() {
        // INVERTED BY CLOUD-2625. The scan read a quoted value's first word with
        // its quote attached and listed `set` as a keyword, so `"set -e"` was
        // argv and a bare `set -e` shell. On the grammar both are one plain
        // command: `set` is a word like any other.
        let lines = [
            "run = \"set -e\"",
            "run = 'set -e'",
            "run = [",
            "  \"set -e\",",
            "]",
        ];
        assert!(manifest_lines(&lines, &keys(&["run"]), None).is_empty());
    }

    #[test]
    fn a_quoted_metacharacter_is_one_word_and_a_bare_one_is_shell() {
        // The value is judged on the string TOML hands back, so the TOML quote is
        // gone and the shell quote inside it is what decides.
        let lines = [
            "run = \"echo 'a|b'\"",
            "run = 'echo \">\" x'",
            "run = \"a | b\"",
            "run = '''ls *.rs'''",
        ];
        let reasons = manifest_reasons(&lines, &keys(&["run"]), None);
        assert_eq!(
            reasons.into_iter().collect::<Vec<_>>(),
            [(2, "Pipeline"), (3, "glob")]
        );
    }

    #[test]
    fn a_body_of_one_plain_command_is_not_shell() {
        let lines = ["run = '''", "cargo build \\", "  --release", "'''"];
        assert!(manifest_lines(&lines, &keys(&["run"]), None).is_empty());
    }

    #[test]
    fn an_array_entry_counts_only_when_it_carries_shell() {
        let lines = ["run = [", "  \"cargo build\",", "  \"a | b\",", "]"];
        assert_eq!(
            manifest_lines(&lines, &keys(&["run"]), None),
            BTreeSet::from([2])
        );
    }

    #[test]
    fn an_array_closer_is_searched_for_after_its_opening_line() {
        // A key spelled `]` opens with a line that itself starts with `]`; a
        // closer search that began AT the opener would end the array there.
        let lines = ["] = [", "  \"a | b\",", "]"];
        assert_eq!(
            manifest_lines(&lines, &keys(&["]"]), None),
            BTreeSet::from([1])
        );
    }

    #[test]
    fn an_array_opening_line_is_never_one_of_its_entries() {
        // `set` is a shell keyword, so the opener would read as shell syntax if
        // the entry range began at it rather than after it.
        let lines = ["set = [", "  \"a | b\",", "]"];
        assert_eq!(
            manifest_lines(&lines, &keys(&["set"]), None),
            BTreeSet::from([1])
        );
    }

    #[test]
    fn a_second_key_is_read_on_the_same_terms() {
        let lines = ["check = \"x && y\"", "fix = \"z\"", "run = \"a | b\""];
        assert_eq!(
            manifest_lines(&lines, &keys(&["check", "fix"]), None),
            BTreeSet::from([0])
        );
    }

    #[test]
    fn a_block_ends_at_the_first_line_at_or_left_of_its_key() {
        let lines = [
            "jobs:",
            "  a:",
            "    steps:",
            "      - run: |",
            "          echo one",
            "",
            "          # a comment",
            "          echo two",
            "      - uses: x",
            "      - name: n",
            "        run: >",
            "          echo three",
            "          echo four",
            "      - run: mise run verify",
            "      - run: a && b",
            "      - run: >",
            "          echo five",
        ];
        let steps = workflow_steps(&lines);
        assert_eq!(steps.get(&3), Some(&BTreeSet::from([4, 7])));
        // A folded block is fed as its source lines: two lines, two commands.
        assert_eq!(steps.get(&10), Some(&BTreeSet::from([11, 12])));
        assert_eq!(steps.get(&13), None, "a single command is not shell");
        assert_eq!(steps.get(&14), Some(&BTreeSet::from([14])));
        assert_eq!(steps.get(&15), None, "a one-command block is not shell");
    }

    #[test]
    fn a_trigger_is_not_a_step() {
        let lines = ["on:", "  workflow_run:", "    workflows: [x]"];
        assert!(workflow_steps(&lines).is_empty());
    }

    #[test]
    fn units_are_named_by_their_header_and_lone_lines_stand_alone() {
        let lines = [
            "run = \"a | b\"",
            "[tasks.a]",
            "run = '''",
            "echo a",
            "echo b",
            "'''",
            "[tasks.\"b:c\"]",
            "run = \"x; y\"",
            "[tasks.clean]",
            "run = \"cargo clean\"",
        ];
        let manifest = Manifest {
            path: "m.toml".to_owned(),
            carrier: None,
            keys: keys(&["run"]),
            unit: Some("[tasks.".to_owned()),
        };
        let entries = manifest_entries("m.toml", &lines, &manifest);
        let rendered: Vec<(usize, Option<&str>, usize)> = entries
            .iter()
            .map(|entry| (entry.line, entry.unit.as_deref(), entry.lines))
            .collect();
        assert_eq!(
            rendered,
            [(1, None, 1), (2, Some("a"), 2), (7, Some("b:c"), 1)]
        );
    }

    #[test]
    fn an_inert_declaration_is_refused() {
        let empty_keys = ShellCensus {
            manifests: vec![Manifest {
                path: "m".to_owned(),
                carrier: None,
                keys: Vec::new(),
                unit: None,
            }],
            ..ShellCensus::default()
        };
        assert!(empty_keys.validate().is_err());
        let spaced_key = ShellCensus {
            manifests: vec![Manifest {
                path: "m".to_owned(),
                carrier: None,
                keys: keys(&["a b"]),
                unit: None,
            }],
            ..ShellCensus::default()
        };
        assert!(spaced_key.validate().is_err());
        let empty_unit = ShellCensus {
            manifests: vec![Manifest {
                path: "m".to_owned(),
                carrier: None,
                keys: keys(&["run"]),
                unit: Some(String::new()),
            }],
            ..ShellCensus::default()
        };
        assert!(empty_unit.validate().is_err());
    }

    fn row(carrier: Option<&str>, names: &[&str]) -> ShellCensus {
        ShellCensus {
            manifests: vec![Manifest {
                path: "m".to_owned(),
                carrier: carrier.map(str::to_owned),
                keys: keys(names),
                unit: None,
            }],
            ..ShellCensus::default()
        }
    }

    #[test]
    fn a_row_names_its_fields_by_exactly_one_of_carrier_and_keys() {
        assert!(row(Some("mise-task"), &["run"]).validate().is_err(), "both");
        assert!(row(None, &[]).validate().is_err(), "neither");
        assert!(row(Some("mise-task"), &[]).validate().is_ok());
        assert!(row(None, &["run"]).validate().is_ok());
        // A cited carrier with no manifest reader, and an unknown one.
        assert!(row(Some("dockerfile"), &[]).validate().is_err());
        assert!(row(Some("make"), &[]).validate().is_err());
        // A carrier's fields are the keys it reads.
        let hk = &row(Some("hk-step"), &[]).manifests[0];
        assert_eq!(hk.fields(), keys(&["check", "fix"]));
    }

    #[test]
    fn a_carrier_reads_a_list_in_its_own_form() {
        let lines = ["run = [", "  \"cargo build\",", "  \"a && b\",", "]"];
        let mise = Some(&crate::shell::MISE_TASK);
        assert_eq!(
            manifest_lines(&lines, &keys(&["run"]), mise),
            BTreeSet::from([2])
        );
        assert_eq!(
            manifest_lines(
                &["run = [\"cargo build\", \"a | b\"]"],
                &keys(&["run"]),
                mise
            ),
            BTreeSet::from([0])
        );
    }

    #[test]
    fn a_glob_the_ban_reads_differently_is_refused() {
        // Each parses under `globset`, so `Selector::new` alone admits it; each
        // selects different files under the ban's matcher.
        for glob in ["ci/*.{yml,yaml}", "[ab].sh", "a\\*.sh"] {
            let workflows = ShellCensus {
                workflows: vec![glob.to_owned()],
                ..ShellCensus::default()
            };
            assert!(workflows.validate().is_err(), "workflows {glob}");
            let exempt = ShellCensus {
                exempt: vec![glob.to_owned()],
                ..ShellCensus::default()
            };
            assert!(exempt.validate().is_err(), "exempt {glob}");
        }
        let shared = ShellCensus {
            workflows: vec!["ci/**/*.yml".to_owned()],
            exempt: vec!["boot?.sh".to_owned(), "vendor/**".to_owned()],
            ..ShellCensus::default()
        };
        assert!(
            shared.validate().is_ok(),
            "`*`, `?` and `**` are read alike"
        );
    }

    /// Fails by: an exempt manifest, workflow or file measured as anything but
    /// its own line count, or an exempt workflow with no shell reported at zero.
    #[test]
    fn exempt_paths_are_measured_apart_at_their_own_count() {
        let root = crate::scratch::scratch("census-exempt");
        std::fs::write(root.join("m.toml"), "[tasks.a]\nrun = \"a | b\"\n").unwrap();
        std::fs::write(
            root.join("w.yml"),
            "jobs:\n  a:\n    steps:\n      - run: a && b\n",
        )
        .unwrap();
        std::fs::write(
            root.join("quiet.yml"),
            "jobs:\n  a:\n    steps:\n      - run: mise run verify\n",
        )
        .unwrap();
        std::fs::write(root.join("x.sh"), "echo one\necho two\n").unwrap();
        let declared = ShellCensus {
            manifests: vec![Manifest {
                path: "m.toml".to_owned(),
                carrier: None,
                keys: keys(&["run"]),
                unit: None,
            }],
            workflows: keys(&["*.yml"]),
            exempt: keys(&["m.toml", "w.yml", "quiet.yml", "x.sh"]),
            ..ShellCensus::default()
        };
        let tracked: BTreeSet<String> = ["m.toml", "w.yml", "quiet.yml", "x.sh"]
            .map(str::to_owned)
            .into();
        let report = take(&root, &declared, &tracked).unwrap();
        let exempt: Vec<(&str, usize)> = report
            .exempt
            .iter()
            .map(|entry| (entry.path.as_str(), entry.lines))
            .collect();
        assert_eq!(exempt, [("m.toml", 1), ("w.yml", 1), ("x.sh", 2)]);
        assert_eq!(report.totals.exempt, 4);
        assert_eq!(report.totals.total, 0, "exempt lines are never totalled");
    }

    /// The walk finds a shell argv in every place engine code holds one, names
    /// the item that owns it, and skips test code by attribute on every item
    /// kind (CLOUD-2770).
    ///
    /// Fails by: an item, impl, trait or macro body left unwalked, an owner
    /// misnamed, a `cfg` other than exactly `test` read as test code, a
    /// test-only item of any kind walked, or a call that is not
    /// `Command::new` read as one.
    #[test]
    fn a_spawn_is_found_wherever_engine_code_holds_one() {
        let source = [
            r#"const SHELL: (&str, &str) = ("sh", "-c");"#,
            r#"static PWSH: [&str; 2] = ["pwsh", "-c"];"#,
            r#"fn by_call() { let _ = Command::new("bash"); }"#,
            r#"fn by_chain() { Command::new("env").arg("-i").arg("sh"); }"#,
            r#"fn by_args() { Command::new("env").args(&["-i", "sh"]); }"#,
            r#"fn by_macro() { let _ = vec!["zsh", "-c"]; }"#,
            r#"fn by_reference() { Command::new(&"sh"); }"#,
            r#"fn by_paren() { Command::new(("sh")); }"#,
            "struct S;",
            "impl S {",
            r#"    fn method() { Command::new("dash"); }"#,
            r#"    const C: [&str; 2] = ["ksh", "-c"];"#,
            "    #[test]",
            r#"    fn case() { Command::new("sh"); }"#,
            "}",
            r#"trait T { fn provided() { Command::new("mksh"); } }"#,
            "#[cfg(not(test))]",
            r#"fn kept() { Command::new("ash"); }"#,
            r#"fn plain() { Command::new("git").arg("x"); let _ = ("sh", 1); Other::new("sh"); Command::open("sh"); }"#,
            r#"#[cfg(test)] const X: [&str; 2] = ["sh", "-c"];"#,
            r#"#[cfg(test)] fn tested() { Command::new("sh"); }"#,
            r#"#[cfg(test)] impl S { fn m() { Command::new("sh"); } }"#,
            r#"#[cfg(test)] wrapped!(Command::new("sh"));"#,
            r#"#[cfg(test)] mod tests { fn x() { Command::new("sh"); } }"#,
            r#"#[cfg(test)] static Y: [&str; 2] = ["sh", "-c"];"#,
            r#"#[cfg(test)] trait U { fn p() { Command::new("sh"); } }"#,
        ]
        .join("\n");
        let found: Vec<(usize, Option<String>)> = spawn_sites("src/a.rs", &source)
            .into_iter()
            .map(|site| (site.line, site.function))
            .collect();
        let expected: Vec<(usize, Option<String>)> = [
            (1, "SHELL"),
            (2, "PWSH"),
            (3, "by_call"),
            (4, "by_chain"),
            (5, "by_args"),
            (6, "by_macro"),
            (7, "by_reference"),
            (8, "by_paren"),
            (11, "method"),
            (12, "C"),
            (16, "provided"),
            (18, "kept"),
        ]
        .into_iter()
        .map(|(line, function)| (line, Some(function.to_owned())))
        .collect();
        assert_eq!(found, expected);
    }

    /// The two on-disk readers measure the tracked tree at `root`: generated
    /// entries against their globs and check files, and spawns in engine
    /// source only.
    ///
    /// Fails by: either reader answering nothing.
    #[test]
    fn the_on_disk_readers_measure_the_tracked_tree() {
        let root = crate::scratch::scratch("census-on-disk");
        std::fs::create_dir_all(root.join("gen")).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join("tests")).unwrap();
        std::fs::write(root.join("gen/a.sh"), "x\n").unwrap();
        std::fs::write(root.join("t.rs"), "fn holds_it() {}\n").unwrap();
        let spawning = "fn f() { Command::new(\"sh\"); }\n";
        std::fs::write(root.join("src/a.rs"), spawning).unwrap();
        std::fs::write(root.join("tests/b.rs"), spawning).unwrap();
        let tracked: BTreeSet<String> = ["gen/a.sh", "t.rs", "src/a.rs", "tests/b.rs"]
            .map(str::to_owned)
            .into();
        let declared = ShellCensus {
            generated: vec![Generated {
                path: "gen/*.sh".to_owned(),
                generator: Some("g".to_owned()),
                check: Some("t.rs::holds_it".to_owned()),
            }],
            ..ShellCensus::default()
        };
        assert_eq!(
            generated_on_disk(&root, &declared, &tracked),
            [GeneratedEntry {
                path: "gen/*.sh".to_owned(),
                matches: 1,
                check_found: true,
            }]
        );
        assert_eq!(
            spawns_on_disk(&root, &tracked),
            [SpawnEntry {
                path: "src/a.rs".to_owned(),
                line: 1,
                function: Some("f".to_owned()),
            }]
        );
        // `#!` is read off the first two bytes, and a short file has none.
        std::fs::write(root.join("bang"), "#!/bin/sh\n").unwrap();
        std::fs::write(root.join("hash"), "#").unwrap();
        assert!(hash_bang(&root.join("bang")));
        assert!(!hash_bang(&root.join("hash")));
        assert!(!hash_bang(&root.join("t.rs")));
    }

    /// A `check` is `<file>::<name>`, both halves present and unspaced; a
    /// spawn row names its file, its function and a cited contract.
    ///
    /// Fails by: either half of a check, or any one of a spawn row's three
    /// fields, accepted alone.
    #[test]
    fn a_check_and_a_spawn_row_carry_every_part() {
        assert_eq!(check_parts("t.rs::holds"), Some(("t.rs", "holds")));
        for bad in ["t.rs::", "::holds", "t rs::holds", "t.rs::a b", "t.rs"] {
            assert_eq!(check_parts(bad), None, "{bad}");
        }
        let spawn = |path: &str, function: Option<&str>, contract: Option<&str>| ShellCensus {
            spawns: vec![Spawn {
                path: path.to_owned(),
                function: function.map(str::to_owned),
                contract: contract.map(str::to_owned),
            }],
            ..ShellCensus::default()
        };
        let cited = Some("an MCP `headersHelper`, https://example.com/spec");
        assert!(spawn("src/a.rs", Some("f"), cited).validate().is_ok());
        assert!(spawn(" ", Some("f"), cited).validate().is_err(), "no file");
        assert!(
            spawn("src/a.rs", None, cited).validate().is_err(),
            "no function"
        );
        assert!(
            spawn("src/a.rs", Some("f"), None).validate().is_err(),
            "no contract"
        );
        assert!(
            spawn("src/a.rs", Some("f"), Some("a format"))
                .validate()
                .is_err(),
            "no citation"
        );
    }

    /// Migrating is `mode = "migrate"` or a non-empty legacy `exempt`;
    /// presence is everything else.
    #[test]
    fn the_mode_is_migrate_only_when_declared_or_legacy() {
        assert!(!ShellCensus::default().migrating());
        let declared = ShellCensus {
            mode: Some(ShellMode::Migrate),
            ..ShellCensus::default()
        };
        assert!(declared.migrating());
        let legacy = ShellCensus {
            exempt: keys(&["x.sh"]),
            ..ShellCensus::default()
        };
        assert!(legacy.migrating());
    }

    /// A TOML array is judged as the list it holds, not as its bracketed text.
    ///
    /// Fails by: the array arm dropped, which reads `["cargo test"]` as a glob.
    #[test]
    fn a_toml_array_is_judged_as_its_items() {
        assert_eq!(toml_reason(r#"["cargo test"]"#, None), None);
        assert_eq!(toml_reason(r#"["a", "b && c"]"#, None), Some("List"));
        assert_eq!(toml_reason(r#""a | b""#, None), Some("Pipeline"));
    }

    /// Two rows naming one manifest union their keys, each once.
    ///
    /// Fails by: a key already held compared the wrong way round, which drops
    /// every key after the first.
    #[test]
    fn rows_naming_one_manifest_union_their_keys() {
        let documents: serde_json::Map<String, serde_json::Value> = serde_json::from_value(
            serde_json::json!({"b.toml": {"census": {"shell": {"manifest": [
                {"path": "m", "keys": ["run", "x"]},
                {"path": "m", "keys": ["x", "y"]},
            ]}}}}),
        )
        .unwrap();
        let homes = Homes::find(&documents);
        assert!(homes.declared);
        assert_eq!(homes.manifests["m"].0, keys(&["run", "x", "y"]));
    }

    /// A reach that asks for the whole tree reads it even where no document
    /// declares a census; one that does not reads only the row's own lines.
    ///
    /// Fails by: the two conditions both required, which reads nothing for
    /// a consumer that declares nothing.
    #[test]
    fn an_always_reach_reads_the_whole_tree_without_a_declaration() {
        let root = crate::scratch::scratch("census-reach");
        std::fs::write(root.join("x.sh"), "echo one\n").unwrap();
        let tracked = vec!["x.sh".to_owned()];
        let reader = TreeReader::new(&root, &tracked);
        let none = serde_json::Map::new();
        let fact = |always: bool| {
            tree_fact(
                &none,
                &none,
                None,
                &tracked,
                Some(Reach {
                    reader: &reader,
                    always,
                }),
            )
        };
        assert_ne!(fact(true), fact(false));
        assert_eq!(fact(false), tree_fact(&none, &none, None, &tracked, None));
    }

    #[test]
    fn the_source_bakes_in_no_consumer_path() {
        // Non-negotiable rule 1: which manifest, which workflow directory and
        // which files stay shell are the consumer's. Assembled so this test's own
        // text is not a match.
        // The carrier table in `shell.rs` holds no path either (CLOUD-2627).
        for source in [include_str!("census.rs"), include_str!("shell.rs")] {
            assert_no_consumer_path(source);
        }
    }

    fn assert_no_consumer_path(source: &str) {
        for baked in [
            ["mise", ".toml"].concat(),
            [".github", "/workflows"].concat(),
            ["hk", ".pkl"].concat(),
            ["install", ".sh"].concat(),
            ["mise-", "tasks"].concat(),
        ] {
            assert!(
                !source.contains(&baked),
                "census source hardcodes {baked}; it comes from [census.shell]"
            );
        }
    }
}
