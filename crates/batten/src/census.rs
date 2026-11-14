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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exempt: Vec<String>,
}

/// One manifest whose command strings are counted.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Manifest {
    /// The manifest's repo-relative path.
    pub path: String,
    /// The keys whose values are commands, as they are spelled before ` = `.
    pub keys: Vec<String>,
    /// The header prefix that opens one named unit — a task table, say. Every
    /// shell line between one such header and the next is that unit's. Absent,
    /// each shell line is reported on its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
}

impl ShellCensus {
    /// Refuse a declaration that would count nothing while reading as covered.
    ///
    /// # Errors
    ///
    /// A [`UsageError`] (→ exit `1`) for a manifest with no path or no key, a
    /// key that is empty or carries whitespace, an empty unit header, a glob
    /// `globset` cannot parse, or a glob spelling an operator the ban cannot read
    /// (`BAN_UNREAD_OPERATORS`).
    pub fn validate(&self) -> Result<()> {
        for manifest in &self.manifests {
            if manifest.path.trim().is_empty() {
                return Err(UsageError::raise(
                    "census.shell.manifest: `path` must name a file",
                ));
            }
            if manifest.keys.is_empty() {
                return Err(UsageError::raise(format!(
                    "census.shell.manifest {}: `keys` is empty — a manifest with no command key \
                     counts nothing",
                    manifest.path
                )));
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
        for glob in self.workflows.iter().chain(&self.exempt) {
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

/// A TOML value's shell reason, judged on the string it holds rather than on
/// its quoting: `run = "a | b"` is a pipeline, not one quoted word. An inline
/// array is shell when any of its strings is. A value TOML cannot read is
/// judged as written, which leaves the detector to call a stray quote
/// unparseable rather than reading it clean.
fn toml_reason(value: &str) -> Option<&'static str> {
    let parsed = toml::from_str::<toml::Table>(&format!("v = {value}"))
        .ok()
        .and_then(|mut table| table.remove("v"));
    match parsed {
        Some(toml::Value::String(text)) => shell_reason(&text),
        Some(toml::Value::Array(items)) => items
            .iter()
            .filter_map(toml::Value::as_str)
            .find_map(shell_reason),
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

/// Every line index of `lines` a manifest's `keys` make shell, in order.
#[must_use]
pub fn manifest_lines(lines: &[&str], keys: &[String]) -> BTreeSet<usize> {
    manifest_reasons(lines, keys).into_keys().collect()
}

/// Every line index of `lines` a manifest's `keys` make shell, with the
/// detector's reason.
///
/// A key's triple-quoted body is parsed as one text, and when it is shell every
/// code line of it counts; a one-line value and a multi-line array's entries
/// count themselves when the string each holds is shell.
#[must_use]
pub fn manifest_reasons(lines: &[&str], keys: &[String]) -> BTreeMap<usize, &'static str> {
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
                    for j in i + 1..closer {
                        let entry = lines.get(j).map_or("", |l| l.trim().trim_end_matches(','));
                        if let Some(reason) = toml_reason(entry) {
                            shell.entry(j).or_insert(reason);
                        }
                    }
                }
                continue;
            }
            // A one-line value, judged on the string it holds.
            if let Some(reason) = toml_reason(value) {
                shell.entry(i).or_insert(reason);
            }
        }
    }
    shell
}

/// The run of leading spaces, in characters.
fn indent(line: &str) -> usize {
    line.chars().count() - line.trim_start_matches(' ').chars().count()
}

/// The value of a `run:` key on this line, if the line is one.
fn run_key(line: &str) -> Option<&str> {
    let text = line.trim();
    ["- run:", "run:"]
        .iter()
        .find_map(|prefix| text.strip_prefix(prefix))
        .map(str::trim)
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
    /// The sums.
    pub totals: Totals,
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
    let shell = manifest_lines(lines, &manifest.keys);
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
    /// Manifest path -> its command keys, unioned across rows naming one path.
    manifests: BTreeMap<String, Vec<String>>,
    /// The workflow globs.
    workflows: Vec<Selector>,
}

impl Homes {
    fn find(documents: &serde_json::Map<String, serde_json::Value>) -> Self {
        let mut homes = Homes {
            manifests: BTreeMap::new(),
            workflows: Vec::new(),
        };
        let declarations = documents
            .values()
            .filter_map(|doc| doc.get("census")?.get("shell"))
            .filter(|shell| shell.is_object());
        for shell in declarations {
            let rows = shell.get("manifest").and_then(serde_json::Value::as_array);
            for row in rows.into_iter().flatten() {
                let Some(path) = row.get("path").and_then(serde_json::Value::as_str) else {
                    continue;
                };
                let keys = row.get("keys").and_then(serde_json::Value::as_array);
                let entry = homes.manifests.entry(path.to_owned()).or_default();
                for key in keys
                    .into_iter()
                    .flatten()
                    .filter_map(serde_json::Value::as_str)
                {
                    if !entry.iter().any(|known| known == key) {
                        entry.push(key.to_owned());
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
            if let Some(keys) = self.manifests.get(path) {
                ("manifest", manifest_reasons(lines?, keys))
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

/// `input.tree.shell` (CLOUD-2625): every declared home's shell lines, and
/// every shell file, on both sides of the row's delta, as the detector reads
/// them.
///
/// The head side reads `input.tree.lines` and the delta's `added` paths, so an
/// added file is shell by its name even where no line source covers it; the base
/// side reads the delta's `base-lines`. A path absent from a side is either no
/// home or one that side could not read, and the ban reads both as nothing
/// there — never as clean.
///
/// Pointer-only (non-negotiable rule 4): a kind, a 1-based line and the
/// detector's reason. Never a byte of the body.
#[must_use]
pub fn tree_fact(
    documents: &serde_json::Map<String, serde_json::Value>,
    head: &serde_json::Map<String, serde_json::Value>,
    delta: Option<&crate::git::BaseDelta>,
) -> serde_json::Value {
    let homes = Homes::find(documents);
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
    let paths: BTreeSet<&str> = head
        .keys()
        .map(String::as_str)
        .chain(added.iter().map(String::as_str))
        .collect();
    let mut head_side = serde_json::Map::new();
    for path in paths {
        let owned = head.get(path).map(lines_of);
        let borrowed: Option<Vec<&str>> = owned
            .as_ref()
            .map(|lines| lines.iter().map(String::as_str).collect());
        if let Some(entry) = homes.entry(path, borrowed.as_deref()) {
            head_side.insert(path.to_owned(), entry);
        }
    }
    let mut base_side = serde_json::Map::new();
    for (path, lines) in delta.map(|delta| &delta.base_lines).into_iter().flatten() {
        let borrowed: Vec<&str> = lines.iter().map(String::as_str).collect();
        if let Some(entry) = homes.entry(path, Some(&borrowed)) {
            base_side.insert(path.clone(), entry);
        }
    }
    serde_json::json!({"head": head_side, "base": base_side})
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
        let shell = manifest_lines(&lines, &keys(&["run"]));
        assert_eq!(shell, BTreeSet::from([4, 5]));
    }

    #[test]
    fn a_body_that_closes_on_its_opening_line_is_no_body() {
        let lines = ["run = '''echo one'''", "echo two"];
        assert!(manifest_lines(&lines, &keys(&["run"])).is_empty());
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
            manifest_lines(&lines, &keys(&["run"])),
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
        assert!(manifest_lines(&lines, &keys(&["run"])).is_empty());
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
        let reasons = manifest_reasons(&lines, &keys(&["run"]));
        assert_eq!(
            reasons.into_iter().collect::<Vec<_>>(),
            [(2, "Pipeline"), (3, "glob")]
        );
    }

    #[test]
    fn a_body_of_one_plain_command_is_not_shell() {
        let lines = ["run = '''", "cargo build \\", "  --release", "'''"];
        assert!(manifest_lines(&lines, &keys(&["run"])).is_empty());
    }

    #[test]
    fn an_array_entry_counts_only_when_it_carries_shell() {
        let lines = ["run = [", "  \"cargo build\",", "  \"a | b\",", "]"];
        assert_eq!(manifest_lines(&lines, &keys(&["run"])), BTreeSet::from([2]));
    }

    #[test]
    fn an_array_closer_is_searched_for_after_its_opening_line() {
        // A key spelled `]` opens with a line that itself starts with `]`; a
        // closer search that began AT the opener would end the array there.
        let lines = ["] = [", "  \"a | b\",", "]"];
        assert_eq!(manifest_lines(&lines, &keys(&["]"])), BTreeSet::from([1]));
    }

    #[test]
    fn an_array_opening_line_is_never_one_of_its_entries() {
        // `set` is a shell keyword, so the opener would read as shell syntax if
        // the entry range began at it rather than after it.
        let lines = ["set = [", "  \"a | b\",", "]"];
        assert_eq!(manifest_lines(&lines, &keys(&["set"])), BTreeSet::from([1]));
    }

    #[test]
    fn a_second_key_is_read_on_the_same_terms() {
        let lines = ["check = \"x && y\"", "fix = \"z\"", "run = \"a | b\""];
        assert_eq!(
            manifest_lines(&lines, &keys(&["check", "fix"])),
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
                keys: Vec::new(),
                unit: None,
            }],
            ..ShellCensus::default()
        };
        assert!(empty_keys.validate().is_err());
        let spaced_key = ShellCensus {
            manifests: vec![Manifest {
                path: "m".to_owned(),
                keys: keys(&["a b"]),
                unit: None,
            }],
            ..ShellCensus::default()
        };
        assert!(spaced_key.validate().is_err());
        let empty_unit = ShellCensus {
            manifests: vec![Manifest {
                path: "m".to_owned(),
                keys: keys(&["run"]),
                unit: Some(String::new()),
            }],
            ..ShellCensus::default()
        };
        assert!(empty_unit.validate().is_err());
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
                keys: keys(&["run"]),
                unit: None,
            }],
            workflows: keys(&["*.yml"]),
            exempt: keys(&["m.toml", "w.yml", "quiet.yml", "x.sh"]),
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

    #[test]
    fn the_source_bakes_in_no_consumer_path() {
        // Non-negotiable rule 1: which manifest, which workflow directory and
        // which files stay shell are the consumer's. Assembled so this test's own
        // text is not a match.
        let source = include_str!("census.rs");
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
