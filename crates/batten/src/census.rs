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
//! * **A shell file** — a tracked path [`crate::shell_logic::shell_path`] names, or
//!   one whose shebang [`crate::shell_logic::shebang`] reads as a shell. Its code
//!   lines.
//!
//! Whether a text is shell logic is [`crate::shell_logic::logic`]'s answer on the
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
use serde::Serialize;

use crate::error::UsageError;
use crate::exit::ExitCode;
use crate::selector::Selector;
// The section's declaration lives with the model (CLOUD-2789).
use crate::config_model::{
    MANIFEST_CARRIERS, Manifest, ShellCensus, check_parts, manifest_carrier,
};

/// `ShellCensus` behaviour that belongs to this module's layer, not the type's (CLOUD-2793).
pub trait ShellCensusExt: Sized {
    /// Refuse a declaration that would count nothing while reading as covered.
    ///
    /// # Errors
    ///
    /// A [`UsageError`] (→ exit `1`) for a manifest with no path, with both or
    /// neither of `carrier` and `keys`, naming a carrier with no manifest
    /// reader, a key that is empty or carries whitespace, an empty unit header,
    /// a glob `globset` cannot parse, or a glob spelling an operator the ban
    /// cannot read (`BAN_UNREAD_OPERATORS`).
    fn validate(&self) -> Result<()>;
}

/// Refuse a `[[census.shell.spawn]]` row that names no file or function, or
/// whose `contract` carries no citation URL (CLOUD-2770).
fn validate_spawns(census: &ShellCensus) -> Result<()> {
    for spawn in &census.spawns {
        let bare = |field: Option<&str>| field.is_none_or(|text| text.trim().is_empty());
        if spawn.path.trim().is_empty() || bare(spawn.function.as_deref()) {
            return Err(UsageError::raise(format!(
                "census.shell.spawn {}: a row names the file and the function that spawns",
                spawn.path
            )));
        }
        if !spawn
            .contract
            .as_deref()
            .is_some_and(|contract| !contract.trim().is_empty() && contract.contains("://"))
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

impl ShellCensusExt for ShellCensus {
    fn validate(&self) -> Result<()> {
        validate_spawns(self)?;
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
}

/// Whether the test file `file`, holding `text`, defines the test `name`: read
/// off the one lossless Rust parse as a function of that name, never a substring
/// over lines (rule 6, no blind scan). A file in a language with no loud parser
/// here is could-not-look, which holds nothing (CLOUD-1009).
fn holds_test(file: &str, text: &str, name: &str) -> bool {
    use ra_ap_syntax::AstNode as _;
    use ra_ap_syntax::ast::HasName as _;
    if std::path::Path::new(file)
        .extension()
        .is_none_or(|extension| extension != "rs")
    {
        return false;
    }
    batten_facts::source::rust_parse(text, ra_ap_syntax::Edition::Edition2024)
        .tree()
        .syntax()
        .descendants()
        .filter_map(ra_ap_syntax::ast::Fn::cast)
        .any(|function| function.name().is_some_and(|ident| ident.text() == name))
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
/// Whether a text is shell is the detector's (`crate::shell_logic::logic`);
/// this file decides only WHERE a home's lines are.
#[must_use]
pub fn code_line(line: &str) -> bool {
    let text = line.trim();
    !text.is_empty() && !text.starts_with('#')
}

/// The detector's reason when `text` is shell logic, `None` when it is argv.
fn shell_reason(text: &str) -> Option<&'static str> {
    match crate::shell_logic::logic(text) {
        crate::shell_logic::Verdict::Shell(reason) => Some(reason),
        // `Argv`, and any answer a later detector adds (`#[non_exhaustive]`):
        // only a named shell reason counts.
        _ => None,
    }
}

/// A body of source lines, parsed ONCE as one text: its reason when it is
/// shell logic. A body holding one plain command is not.
fn body_reason(lines: &[&str], body: std::ops::Range<usize>) -> Option<&'static str> {
    shell_reason(&lines.get(body)?.join("\n"))
}

/// The reason a carrier's verdict on one spelling carries, `None` for argv.
fn judged(
    carrier: Option<&crate::shell_logic::Carrier>,
    spelling: &crate::shell_logic::Spelling<'_>,
) -> Option<&'static str> {
    match crate::shell_logic::judge(carrier, spelling) {
        crate::shell_logic::Verdict::Shell(reason) => Some(reason),
        // `Argv`, and any answer a later detector adds (`#[non_exhaustive]`).
        _ => None,
    }
}

/// A TOML value's shell reason, judged on the string it holds rather than on
/// its quoting: `run = "a | b"` is a pipeline, not one quoted word. An inline
/// array is judged in the carrier's list form — for a mise task a list of
/// shell strings, shell when any is. A value TOML cannot read is judged as
/// written, which leaves the detector to call a stray quote unparseable rather
/// than reading it clean.
fn toml_reason(value: &str, carrier: Option<&crate::shell_logic::Carrier>) -> Option<&'static str> {
    let parsed = toml::from_str::<toml::Table>(&format!("v = {value}"))
        .ok()
        .and_then(|mut table| table.remove("v"));
    match parsed {
        Some(toml::Value::String(text)) => {
            judged(carrier, &crate::shell_logic::Spelling::Text(&text))
        }
        Some(toml::Value::Array(items)) => {
            let texts: Vec<&str> = items.iter().filter_map(toml::Value::as_str).collect();
            judged(carrier, &crate::shell_logic::Spelling::List(&texts))
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
    carrier: Option<&crate::shell_logic::Carrier>,
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
    carrier: Option<&crate::shell_logic::Carrier>,
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
    carrier: Option<&crate::shell_logic::Carrier>,
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
    let list = crate::shell_logic::Spelling::List(&texts);
    if carrier.is_none_or(|carrier| {
        crate::shell_logic::form(carrier, &list) == crate::shell_logic::Form::Shell
    }) {
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
    crate::shell_logic::GHA_RUN.fields.iter().find_map(|field| {
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
            let check_found = check.and_then(check_parts).is_some_and(|(file, name)| {
                read(file).is_some_and(|text| holds_test(file, &text, name))
            });
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

/// Every shell spawn site in one engine source file, in source order, read off
/// the one lossless parse (`batten_facts::source::rust_tree`, CLOUD-1008). A
/// file the parser refuses is one site no row can declare: could-not-look is
/// never clean.
fn spawn_sites(path: &str, text: &str) -> Vec<SpawnEntry> {
    use ra_ap_syntax::AstNode as _;
    let crate::facts::Look::Is(tree) =
        crate::source::rust_tree(text, ra_ap_syntax::Edition::Edition2024)
    else {
        return vec![SpawnEntry {
            path: path.to_owned(),
            line: 1,
            function: None,
        }];
    };
    let mut found: BTreeMap<usize, Option<String>> = BTreeMap::new();
    walk_spawns(tree.syntax(), text, 0, &mut found);
    found
        .into_iter()
        .map(|(offset, function)| SpawnEntry {
            path: path.to_owned(),
            line: text[..offset.min(text.len())].matches('\n').count() + 1,
            function,
        })
        .collect()
}

/// Record every shell spawn under `root`, whose text starts at byte `base` of
/// the file, keyed by its program's offset. Pre-order, so an outer method chain
/// is seen before the call it starts from and, carrying more of the argv, wins.
fn walk_spawns(
    root: &ra_ap_syntax::SyntaxNode,
    text: &str,
    base: usize,
    found: &mut BTreeMap<usize, Option<String>>,
) {
    use ra_ap_syntax::AstNode as _;
    use ra_ap_syntax::ast;
    // PRUNED TOP-DOWN: a test item's whole subtree is skipped on entry, which
    // is exactly "some ancestor-or-self is test code" with each node judged
    // once. Asking that of every node by walking its ancestors (and
    // `cfg_test` walking theirs again) was depth-squared per node, and 58% of
    // `state record`'s samples.
    let mut walk = root.preorder();
    while let Some(event) = walk.next() {
        let ra_ap_syntax::WalkEvent::Enter(node) = event else {
            continue;
        };
        if test_item(&node) {
            walk.skip_subtree();
            continue;
        }
        let mut record = |at: ra_ap_syntax::TextSize, argv: &[String]| {
            let words: Vec<&str> = argv.iter().map(String::as_str).collect();
            if crate::shell_logic::spawns_shell(&words) {
                found
                    .entry(base + usize::from(at))
                    .or_insert_with(|| owner_of(&node));
            }
        };
        if let Some(chain) = ast::MethodCallExpr::cast(node.clone()) {
            if let Some((at, argv)) = chained_argv(&chain) {
                record(at, &argv);
            }
        } else if let Some(call) = ast::CallExpr::cast(node.clone()) {
            if let Some((at, program)) = command_new(&call) {
                record(at, &[program]);
            }
        } else if let Some(tuple) = ast::TupleExpr::cast(node.clone()) {
            if !field_value(&node)
                && let Some((at, argv)) = sequence(tuple.fields())
            {
                record(at, &argv);
            }
        } else if let Some(array) = ast::ArrayExpr::cast(node.clone()) {
            if !field_value(&node)
                && let Some((at, argv)) = sequence(array.exprs())
            {
                record(at, &argv);
            }
        } else if let Some(mac) = ast::MacroCall::cast(node.clone()) {
            walk_macro(&mac, text, base, found);
        }
    }
}

/// Whether a sequence literal is a struct field's VALUE (`read: &["bash",
/// "command"]`), looked through any `&`. A field holding names is data a type
/// declares, not an argv handed to a spawn: `hook.rs`'s `COPILOT_ENTRY` names
/// the keys a host writes, and read as an argv it was a false `shell write
/// other`. A spawn's argv is a call's argument or a binding, never a field.
fn field_value(node: &ra_ap_syntax::SyntaxNode) -> bool {
    use ra_ap_syntax::AstNode as _;
    use ra_ap_syntax::ast;
    let mut parent = node.parent();
    while let Some(at) = parent.clone() {
        if ast::RefExpr::can_cast(at.kind()) {
            parent = at.parent();
            continue;
        }
        return ast::RecordExprField::can_cast(at.kind());
    }
    false
}

/// A macro body is a token tree to the parser. One whose body is comma-separated
/// expressions (`vec!`, `format!`, `assert!`) is re-read as a bracketed list and
/// walked the same way, and `vec!`'s list is an argv as an array literal's is.
fn walk_macro(
    mac: &ra_ap_syntax::ast::MacroCall,
    text: &str,
    base: usize,
    found: &mut BTreeMap<usize, Option<String>>,
) {
    use ra_ap_syntax::AstNode as _;
    let Some(body) = mac.token_tree() else {
        return;
    };
    let range = body.syntax().text_range();
    let (start, end) = (usize::from(range.start()) + 1, usize::from(range.end()) - 1);
    let Some(inner) = text.get(start..end) else {
        return;
    };
    // `fn _f() { [` is 12 bytes, so an offset in the wrapper less 12 is one in
    // the body.
    let wrapped = format!("fn _f() {{ [{inner}]; }}");
    let crate::facts::Look::Is(tree) =
        crate::source::rust_tree(&wrapped, ra_ap_syntax::Edition::Edition2024)
    else {
        return;
    };
    let shift = |found: BTreeMap<usize, Option<String>>| -> BTreeMap<usize, Option<String>> {
        found
            .into_iter()
            .map(|(at, owner)| (at.saturating_sub(12), owner))
            .collect()
    };
    let mut inner_found = BTreeMap::new();
    walk_spawns(tree.syntax(), &wrapped, 0, &mut inner_found);
    let is_vec = mac.path().is_some_and(|path| path.syntax().text() == "vec");
    if !is_vec {
        // Only `vec!` makes its list an argv; drop the wrapper array's own site.
        if let Some(array) = tree
            .syntax()
            .descendants()
            .find_map(ra_ap_syntax::ast::ArrayExpr::cast)
            && let Some((at, _)) = sequence(array.exprs())
        {
            inner_found.remove(&usize::from(at));
        }
    }
    let owner = owner_of(mac.syntax());
    for (at, _) in shift(inner_found) {
        found
            .entry(base + start + at)
            .or_insert_with(|| owner.clone());
    }
}

/// Whether `node` ITSELF opens test code: an item carrying exactly
/// `#[cfg(test)]`, or a function carrying `#[test]`. Test code is CLOUD-2336's,
/// not this arm's; [`walk_spawns`] skips the subtree this answers true for.
fn test_item(node: &ra_ap_syntax::SyntaxNode) -> bool {
    use ra_ap_syntax::AstNode as _;
    use ra_ap_syntax::ast::HasAttrs as _;
    crate::module_graph::carries_cfg_test(node)
        || ra_ap_syntax::ast::Fn::cast(node.clone()).is_some_and(|function| {
            function.attrs().any(|attr| {
                attr.path()
                    .is_some_and(|path| path.syntax().text() == "test")
            })
        })
}

/// The function, `const` or `static` holding `node`, by name.
fn owner_of(node: &ra_ap_syntax::SyntaxNode) -> Option<String> {
    use ra_ap_syntax::AstNode as _;
    use ra_ap_syntax::ast::{self, HasName as _};
    node.ancestors().find_map(|ancestor| {
        ast::Fn::cast(ancestor.clone())
            .and_then(|item| item.name())
            .or_else(|| ast::Const::cast(ancestor.clone()).and_then(|item| item.name()))
            .or_else(|| ast::Static::cast(ancestor).and_then(|item| item.name()))
            .map(|name| name.text().to_string())
    })
}

/// A string literal, through `&` and parentheses, with its position.
fn literal(expr: &ra_ap_syntax::ast::Expr) -> Option<(ra_ap_syntax::TextSize, String)> {
    use ra_ap_syntax::AstNode as _;
    use ra_ap_syntax::ast;
    match expr {
        ast::Expr::Literal(literal) => match literal.kind() {
            ast::LiteralKind::String(text) => Some((
                literal.syntax().text_range().start(),
                text.value().ok()?.into_owned(),
            )),
            _ => None,
        },
        ast::Expr::RefExpr(inner) => literal(&inner.expr()?),
        ast::Expr::ParenExpr(inner) => literal(&inner.expr()?),
        _ => None,
    }
}

/// The word standing for an argument the source computes: an inline flag whose
/// script is computed still carries one.
const COMPUTED: &str = "<computed>";

/// A sequence's leading string literals, then [`COMPUTED`] once for whatever
/// follows them.
fn literal_argv(items: impl IntoIterator<Item = ra_ap_syntax::ast::Expr>) -> Vec<String> {
    let mut argv = Vec::new();
    for item in items {
        if let Some((_, word)) = literal(&item) {
            argv.push(word);
        } else {
            argv.push(COMPUTED.to_owned());
            break;
        }
    }
    argv
}

/// A sequence spelled as an argv: its first two elements are string literals.
/// One literal beside a value is a table row, not an argv.
fn sequence(
    items: impl Iterator<Item = ra_ap_syntax::ast::Expr>,
) -> Option<(ra_ap_syntax::TextSize, Vec<String>)> {
    let items: Vec<_> = items.collect();
    let [first, second, ..] = items.as_slice() else {
        return None;
    };
    let (at, _) = literal(first)?;
    literal(second)?;
    Some((at, literal_argv(items)))
}

/// `Command::new("<literal>")` by any path ending in it: the program's position
/// and the program.
fn command_new(call: &ra_ap_syntax::ast::CallExpr) -> Option<(ra_ap_syntax::TextSize, String)> {
    use ra_ap_syntax::ast::{self, HasArgList as _};
    let ast::Expr::PathExpr(callee) = call.expr()? else {
        return None;
    };
    let segments: Vec<String> = std::iter::successors(callee.path(), ast::Path::qualifier)
        .filter_map(|path| path.segment()?.name_ref())
        .map(|name| name.text().to_string())
        .collect();
    // `successors` walks from the last segment outward.
    let [new, ty, ..] = segments.as_slice() else {
        return None;
    };
    if ty != "Command" || new != "new" {
        return None;
    }
    literal(&call.arg_list()?.args().next()?)
}

/// A method chain rooted at `Command::new(<literal>)`: the program's position
/// and the argv its `.arg`/`.args` links spell, up to the first computed word.
fn chained_argv(
    call: &ra_ap_syntax::ast::MethodCallExpr,
) -> Option<(ra_ap_syntax::TextSize, Vec<String>)> {
    use ra_ap_syntax::ast::{self, HasArgList as _};
    let mut chain = vec![call.clone()];
    let mut root = call.receiver()?;
    while let ast::Expr::MethodCallExpr(inner) = root {
        root = inner.receiver()?;
        chain.push(inner);
    }
    let ast::Expr::CallExpr(root) = root else {
        return None;
    };
    let (at, program) = command_new(&root)?;
    let mut argv = vec![program];
    for link in chain.iter().rev() {
        if argv.last().is_some_and(|word| word == COMPUTED) {
            break;
        }
        let method = link.name_ref().map(|name| name.text().to_string());
        let first = link.arg_list().and_then(|args| args.args().next());
        match method.as_deref() {
            Some("arg") => argv.extend(literal_argv(first)),
            Some("args") => {
                let array = first.map(|arg| match arg {
                    ast::Expr::RefExpr(inner) => inner.expr(),
                    other => Some(other),
                });
                match array.flatten() {
                    Some(ast::Expr::ArrayExpr(array)) => argv.extend(literal_argv(array.exprs())),
                    _ => argv.push(COMPUTED.to_owned()),
                }
            }
            _ => {}
        }
    }
    Some((at, argv))
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
/// An exempt file is set apart and never totalled.
///
/// A workflow glob selects a composite action's metadata as readily as a
/// workflow: both carry `gha-run` steps.
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
        let text = crate::fsio::read_to_string(root.join(&manifest.path)).map_err(|err| {
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
        let Ok(bytes) = crate::fsio::read(root.join(path)) else {
            continue;
        };
        // Decoding every tracked file to ask about its first two bytes would
        // cost the whole tree for the few files that can be shell at all.
        if !is_workflow && !crate::shell_logic::shell_path(path) && !bytes.starts_with(b"#!") {
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
        if !(crate::shell_logic::shell_path(path) || crate::shell_logic::shebang(first).is_some()) {
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
    manifests: BTreeMap<String, (Vec<String>, Option<&'static crate::shell_logic::Carrier>)>,
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
                let reason = if crate::shell_logic::shell_path(path) {
                    "path"
                } else if crate::shell_logic::shebang(first).is_some() {
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
                .filter(|path| {
                    crate::shell_logic::shell_path(path) || hash_bang(&self.root.join(path))
                })
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
            crate::config_model::CONFIG_FILE
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
    #[cfg(test)]
    fn keys(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    /// Fails by: every file read as opening with `#!`, so any untracked text
    /// file is taken for a script.
    #[test]
    fn only_a_file_opening_with_hash_bang_is_one() {
        let dir =
            std::env::temp_dir().join(format!("batten-census-hash-bang-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("script"), "#!/bin/sh\necho\n").unwrap();
        std::fs::write(dir.join("notes"), "# a heading\n").unwrap();
        assert!(hash_bang(&dir.join("script")));
        assert!(!hash_bang(&dir.join("notes")));
        assert!(!hash_bang(&dir.join("absent")));
    }

    /// Fails by: a macro body re-read past its closing delimiter, which no
    /// longer parses, so a spawn in a macro's arguments is no site.
    #[test]
    fn a_shell_spawn_inside_a_macros_arguments_is_a_site() {
        let text = "use std::process::Command;\n\npub fn run() {\n    \
                    let _ = format!(\"{:?}\", Command::new(\"sh\").args([\"-c\", \"x\"]).status());\n}\n";
        let sites: Vec<(usize, Option<String>)> = spawn_sites("src/lib.rs", text)
            .into_iter()
            .map(|site| (site.line, site.function))
            .collect();
        assert_eq!(sites, [(4, Some(String::from("run")))]);
    }

    /// Fails by: a macro's body re-read from before its opening delimiter,
    /// which no longer parses, so a spawn argv inside `vec![…]` is no site.
    #[test]
    fn a_spawn_argv_inside_a_vec_macro_is_a_site() {
        let sites = spawn_sites(
            "src/a.rs",
            "fn f() {\n    let v = vec![\"sh\", \"-c\", \"x\"];\n}\n",
        );
        assert_eq!(
            sites
                .iter()
                .map(|site| (site.line, site.function.as_deref()))
                .collect::<Vec<_>>(),
            [(2, Some("f"))]
        );
    }

    /// Fails by: the tracked engine sources not read off disk, so the census
    /// reports no spawn where a file holds one.
    #[test]
    fn a_tracked_engine_source_on_disk_is_read_for_spawns() {
        let root = crate::scratch::scratch("census-spawns-on-disk");
        std::fs::create_dir_all(root.join("src")).expect("mkdir");
        std::fs::write(
            root.join("src/a.rs"),
            "fn f() {\n    let v = vec![\"sh\", \"-c\", \"x\"];\n}\n",
        )
        .expect("write");
        let tracked = BTreeSet::from([String::from("src/a.rs"), String::from("tests/t.rs")]);
        let sites = spawns_on_disk(&root, &tracked);
        assert_eq!(
            sites
                .iter()
                .map(|site| site.path.as_str())
                .collect::<Vec<_>>(),
            ["src/a.rs"]
        );
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
        let mise = Some(&crate::shell_logic::MISE_TASK);
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

    /// Fails by: a contract that names a format but cites no URL admitted —
    /// each half of the contract test refuses alone.
    #[test]
    fn a_spawn_contract_without_a_citation_url_is_refused() {
        let spawn = |contract: &str| ShellCensus {
            spawns: vec![crate::config_model::Spawn {
                path: "src/x.rs".to_owned(),
                function: Some("f".to_owned()),
                contract: Some(contract.to_owned()),
            }],
            ..ShellCensus::default()
        };
        assert!(spawn("an external format, uncited").validate().is_err());
        assert!(spawn("   ").validate().is_err());
        assert!(
            spawn("a format, https://example.test/spec")
                .validate()
                .is_ok()
        );
    }

    /// Fails by: the generated entries dropped before the report, or a check
    /// file read from anywhere but under the root.
    #[test]
    fn a_generated_entry_is_measured_on_the_tree() {
        let root = crate::scratch::scratch("census-generated");
        std::fs::create_dir_all(root.join("gen")).unwrap();
        std::fs::create_dir_all(root.join("tests")).unwrap();
        std::fs::write(root.join("gen/a.sh"), "echo a\n").unwrap();
        std::fs::write(root.join("tests/g.rs"), "fn holds() {}\n").unwrap();
        let declared = ShellCensus {
            generated: vec![crate::config_model::Generated {
                path: "gen/*.sh".to_owned(),
                generator: Some("gen".to_owned()),
                check: Some("tests/g.rs::holds".to_owned()),
            }],
            ..ShellCensus::default()
        };
        let tracked: BTreeSet<String> = ["gen/a.sh", "tests/g.rs"].map(str::to_owned).into();
        assert_eq!(
            generated_on_disk(&root, &declared, &tracked),
            [GeneratedEntry {
                path: "gen/*.sh".to_owned(),
                matches: 1,
                check_found: true,
            }]
        );
    }

    /// Fails by: any argv shape the walk reads dropped — a `.arg` chain, a
    /// parenthesized program, a `vec!` list (its offset mapped back from the
    /// re-read body), a bare array — or a constructor that is not
    /// `Command::new` read as one.
    #[test]
    fn every_argv_shape_the_spawn_walk_reads_is_found_at_its_line() {
        let source = "fn chained(script: &str) {\n\
                      \x20   std::process::Command::new(\"python3\").arg(\"-c\").arg(script);\n\
                      }\n\
                      fn parenthesized() {\n\
                      \x20   Command::new((\"sh\"));\n\
                      }\n\
                      fn listed() {\n\
                      \x20   let argv = vec![\n\
                      \x20       \"sh\",\n\
                      \x20       \"-c\",\n\
                      \x20   ];\n\
                      }\n\
                      fn bound() {\n\
                      \x20   let argv = [\"sh\", \"-c\"];\n\
                      }\n\
                      fn other() {\n\
                      \x20   Builder::new(\"sh\");\n\
                      }\n";
        let found: Vec<(usize, Option<String>)> = spawn_sites("src/x.rs", source)
            .into_iter()
            .map(|entry| (entry.line, entry.function))
            .collect();
        let at = |line: usize, function: &str| (line, Some(function.to_owned()));
        assert_eq!(
            found,
            [
                at(2, "chained"),
                at(5, "parenthesized"),
                at(9, "listed"),
                at(14, "bound"),
            ]
        );
    }

    #[test]
    fn the_source_bakes_in_no_consumer_path() {
        // Non-negotiable rule 1: which manifest, which workflow directory and
        // which files stay shell are the consumer's. Assembled so this test's own
        // text is not a match.
        // The carrier table holds no path either (CLOUD-2627); it is checked
        // in `batten_core::shell_logic`'s own tests, beside it.
        assert_no_consumer_path(include_str!("census.rs"));
    }

    /// Fails by: a spawn row that names its file but no function passes,
    /// because the refusal needs BOTH halves missing rather than either.
    #[test]
    fn a_spawn_row_without_a_function_is_refused() {
        let spawn = |function: Option<&str>| ShellCensus {
            spawns: vec![crate::config_model::Spawn {
                path: "src/a.rs".to_owned(),
                function: function.map(str::to_owned),
                contract: Some("an external format https://example.invalid".to_owned()),
            }],
            ..ShellCensus::default()
        };
        assert!(
            spawn(Some("run")).validate().is_ok(),
            "premise: a whole row"
        );
        assert!(spawn(None).validate().is_err());
        assert!(spawn(Some(" ")).validate().is_err());
    }

    /// Fails by: a `.rs` file outside `src`, or a non-Rust file inside it,
    /// read as engine source because either half alone sufficed.
    #[test]
    fn engine_source_is_a_rust_file_under_src() {
        assert!(engine_source("src/a.rs"));
        assert!(engine_source("crates/x/src/a.rs"));
        assert!(!engine_source("crates/x/tests/a.rs"));
        assert!(!engine_source("crates/x/src/a.md"));
    }

    /// Each spawn site `spawn_sites` reads in `text`, as `(line, function)`.
    fn sites(text: &str) -> Vec<(usize, Option<String>)> {
        spawn_sites("f.rs", text)
            .into_iter()
            .map(|entry| (entry.line, entry.function))
            .collect()
    }

    fn at(line: usize, function: &str) -> (usize, Option<String>) {
        (line, Some(function.to_owned()))
    }

    /// Fails by: the `!` dropped from the tuple arm's field test, so a bound
    /// tuple argv is missed and a struct field's tuple of names is read as one.
    #[test]
    fn a_tuple_argv_counts_unless_it_is_a_field_value() {
        let text = "fn a() {\n    let t = (\"bash\", \"x\");\n    \
                    let s = S { argv: (\"bash\", \"y\") };\n}\n";
        assert_eq!(sites(text), [at(2, "a")]);
    }

    /// Fails by: the macro body's end widened past its closing bracket, or its
    /// offset in the file multiplied rather than added, so a `vec!` argv is lost
    /// or placed on the wrong line.
    #[test]
    fn a_vec_macro_argv_is_placed_on_its_own_line() {
        let text = "fn m() {\n    let o = 1;\n    let v = vec![\"bash\", \"x\"];\n}\n";
        assert_eq!(sites(text), [at(3, "m")]);
    }

    /// Fails by: `#[test]` matched by `!=`, so a function with any other
    /// attribute is skipped as test code and a `#[test]` function is walked.
    #[test]
    fn only_a_test_attribute_makes_a_function_test_code() {
        let text = "#[inline]\nfn kept() {\n    let a = [\"bash\", \"x\"];\n}\n\
                    #[test]\nfn skipped() {\n    let a = [\"bash\", \"y\"];\n}\n";
        assert_eq!(sites(text), [at(3, "kept")]);
    }

    /// Fails by: the `&` arm deleted from `literal`, or `literal_argv`/`sequence`
    /// answering an empty word, so an array argv whose program is borrowed is
    /// never read as the shell it names.
    #[test]
    fn a_borrowed_literal_still_names_the_program() {
        let text = "fn r() {\n    let a = [&\"bash\", \"x\"];\n}\n";
        assert_eq!(sites(text), [at(2, "r")]);
    }

    /// Fails by: `chained_argv` answering nothing, or its computed-word stop
    /// inverted so the chain stops after the program: `env` alone is no shell,
    /// and only the `.arg("bash")` link makes it one.
    #[test]
    fn a_method_chain_carries_its_links_into_the_argv() {
        let text = "fn c() {\n    Command::new(\"env\").arg(\"bash\");\n}\n";
        assert_eq!(sites(text), [at(2, "c")]);
        let bare = "fn c() {\n    Command::new(\"env\");\n}\n";
        assert!(sites(bare).is_empty(), "the program alone is not a shell");
    }

    /// Fails by: an array argv binding read as no spawn — every sequence
    /// taken for a field value, its argv read empty, or its words dropped —
    /// or a field's value read as one.
    #[test]
    fn an_array_argv_is_a_spawn_and_a_field_value_is_not() {
        assert_eq!(
            sites("fn run() {\n    let argv = [\"sh\", \"-c\", \"x\"];\n}\n"),
            [(2, Some("run".to_owned()))]
        );
        assert!(
            sites("fn run() {\n    let s = S { read: &[\"sh\", \"-c\", \"x\"] };\n}\n").is_empty()
        );
    }

    /// Fails by: a `vec!` argv lost (its body sliced with the delimiter, so
    /// the re-read refuses; or `vec!` treated as any other macro), placed on
    /// the wrong line (its body offset subtracted), or a non-`vec!` macro's
    /// own list read as an argv.
    #[test]
    fn a_vec_macro_argv_is_a_spawn_on_its_line() {
        assert_eq!(
            sites("fn run() {\n    let argv = vec![\n        \"sh\", \"-c\", \"x\"];\n}\n"),
            [(3, Some("run".to_owned()))]
        );
        assert!(sites("fn run() {\n    other!(\"sh\", \"-c\", \"x\");\n}\n").is_empty());
    }

    /// Fails by: a `Command::new` chain's argv replaced, so a program that
    /// runs a script only through its `.arg`/`.args` links is missed; or an
    /// `.args` array read as computed, so `--version` reads as a script.
    #[test]
    fn a_command_chain_spells_its_argv_through_its_links() {
        assert!(
            sites("fn run() {\n    Command::new(\"python3\");\n}\n").is_empty(),
            "premise: the program alone runs no script"
        );
        assert_eq!(
            sites("fn run() {\n    Command::new(\"python3\").arg(\"-c\").arg(\"x\");\n}\n"),
            [(2, Some("run".to_owned()))]
        );
        assert_eq!(
            sites("fn run() {\n    Command::new(\"python3\").args([\"-c\", \"x\"]);\n}\n"),
            [(2, Some("run".to_owned()))]
        );
        assert!(
            sites("fn run() {\n    Command::new(\"python3\").args([\"--version\"]);\n}\n")
                .is_empty()
        );
    }

    /// Fails by: a key two rows name for one manifest listed twice, or a
    /// second distinct key dropped, by an inverted duplicate test.
    #[test]
    fn homes_union_a_manifests_keys_once_each() {
        let documents = serde_json::json!({
            "batten.toml": {"census": {"shell": {"manifest": [
                {"path": "m", "keys": ["a", "b"]},
                {"path": "m", "keys": ["b", "c"]},
            ]}}}
        });
        let serde_json::Value::Object(documents) = documents else {
            unreachable!("a json! object literal");
        };
        let homes = Homes::find(&documents);
        let fields = homes.manifests.get("m").map(|(fields, _)| fields.clone());
        assert_eq!(fields, Some(keys(&["a", "b", "c"])));
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

    /// Fails by: `vec!`'s list dropped as an argv, or another macro's wrapper
    /// list kept as one.
    #[test]
    fn only_vec_makes_a_macro_list_an_argv() {
        let lines = |text: &str| -> Vec<usize> {
            spawn_sites("src/a.rs", text)
                .iter()
                .map(|site| site.line)
                .collect()
        };
        assert_eq!(
            lines("fn f() {\n    let argv = vec![\"bash\", \"-c\", \"x\"];\n}\n"),
            [2]
        );
        assert!(lines("fn f() {\n    m!(\"bash\", \"-c\", \"x\");\n}\n").is_empty());
    }

    /// `vec!`'s body is re-read from just past its open bracket: one byte
    /// early and the wrapped list carries the bracket, no longer parses, and
    /// the argv it holds is never seen.
    #[test]
    fn a_vec_macro_argv_is_a_spawn_site_on_its_own_line() {
        let text = "fn run() {\n    let argv =\n        vec![\"bash\", \"-c\", \"true\"];\n}\n";
        let sites = spawn_sites("src/run.rs", text);
        assert_eq!(
            sites.iter().map(|site| site.line).collect::<Vec<_>>(),
            vec![3],
            "{sites:?}"
        );
    }
}
