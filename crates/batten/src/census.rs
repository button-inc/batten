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
//!   (every code line), its one-line value, and its multi-line array entries (each
//!   only when it carries shell syntax). Grouped into named units where the
//!   manifest declares a unit header, so a task runner's tasks are named.
//! * **A workflow's steps** — every code line of a `run: |` / `run: >` block,
//!   bounded by indentation, and a one-line `run:` carrying shell syntax.
//! * **A shell file** — a tracked `.sh`, `.bash` or `.bats` path, or one whose
//!   shebang names a shell. Its code lines.
//!
//! The first two are EXACTLY the detection a line-unit ban over the same files
//! applies — the `shell-hygiene` preset's `no-new-shell` module, which reads
//! this same `[census.shell]` table as its list of homes — down to its quirks:
//! a one-liner's first word is read with its quote still attached, and an array
//! entry is judged without a comment test. That is deliberate. A census that
//! counted differently from the gate would make "the census reads 0" and "the
//! gate passes" two claims that can disagree, and
//! `crates/batten/tests/it/census_shell.rs` runs both over one fixture to prove
//! they do not.
//!
//! # What is the consumer's, never the engine's (non-negotiable rule 1)
//!
//! Which manifests, which keys, which unit header, which workflow globs and which
//! files must stay shell are all `[census.shell]` in the consumer's `batten.toml`.
//! The engine owns the grammar of "is this line shell" and nothing about where a
//! repository keeps its commands. An exempt file is still measured and reported —
//! apart, and outside the total — so the exemption is visible rather than a hole.
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
    /// key that is empty or carries whitespace, an empty unit header, or a glob
    /// `globset` cannot parse.
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
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The grammar of "is this shell".
// ---------------------------------------------------------------------------

/// Characters a shell interprets and an argv never needs.
const METACHARACTERS: [char; 9] = ['|', ';', '&', '$', '`', '<', '>', '(', ')'];

/// Words that only a shell can run as a first word.
const KEYWORDS: [&str; 9] = [
    "if", "for", "while", "until", "case", "set", "export", "source", ".",
];

/// Shells a shebang may name.
const SHELLS: [&str; 5] = ["sh", "bash", "zsh", "dash", "ksh"];

/// File extensions that are shell whatever the first line says.
const EXTENSIONS: [&str; 3] = [".sh", ".bash", ".bats"];

/// The two quotes that open a multi-line string body.
const QUOTES: [&str; 2] = ["\"\"\"", "'''"];

/// A line that is not blank and not a comment.
///
/// The grammar's mutation rows. Each one breaks a clause the ban's own module
/// carries, so a census that lost it would count differently from the gate; each
/// is caught by the unit case it names, run from this file.
//MUTANT-SUITE crates/batten/src/census.rs
//MUTANT comments-counted|s@    !text.is_empty() && !text.starts_with('#')@    !text.is_empty()@|a_body_counts_its_code_lines_and_skips_comments_and_blanks
//MUTANT metacharacters-unread|s@    if value.contains(METACHARACTERS) {@    if false {@|a_plain_argv_is_not_shell_and_a_pipeline_is
//MUTANT env-prefix-unread|s@ || first.contains('=')@ || false@|a_plain_argv_is_not_shell_and_a_pipeline_is
//MUTANT block-never-ends|s@        indent(line) + 2$@        indent(line) + 200@|a_block_ends_at_the_first_line_at_or_left_of_its_key
//MUTANT workflow-one-liner-unread|s@        } else if !rest.is_empty() && shell_syntax(rest) {@        } else if false {@|a_block_ends_at_the_first_line_at_or_left_of_its_key
#[must_use]
pub fn code_line(line: &str) -> bool {
    let text = line.trim();
    !text.is_empty() && !text.starts_with('#')
}

/// Whether a command string needs a shell rather than an argv to run.
///
/// The first word is read as written, quote included — the ban's reading, kept
/// so the two can never disagree about one value.
#[must_use]
pub fn shell_syntax(value: &str) -> bool {
    if value.contains(METACHARACTERS) {
        return true;
    }
    let first = value.trim().split(' ').next().unwrap_or_default();
    KEYWORDS.contains(&first) || first.contains('=')
}

/// Whether a path is shell by its name alone.
#[must_use]
pub fn shell_path(path: &str) -> bool {
    EXTENSIONS.iter().any(|extension| path.ends_with(extension))
}

/// Whether a first line is a shebang naming a shell.
#[must_use]
pub fn shell_shebang(first: &str) -> bool {
    first.starts_with("#!")
        && first
            .replace('/', " ")
            .split(' ')
            .any(|word| SHELLS.contains(&word))
}

/// Every line index of `lines` a manifest's `keys` make shell, in order.
///
/// A key's triple-quoted body contributes its code lines; a one-line value and a
/// multi-line array's entries contribute themselves when they carry shell syntax.
#[must_use]
pub fn manifest_lines(lines: &[&str], keys: &[String]) -> BTreeSet<usize> {
    let mut shell = BTreeSet::new();
    for key in keys {
        let assign = format!("{key} = ");
        for (i, line) in lines.iter().enumerate() {
            let text = line.trim();
            let Some(value) = text.strip_prefix(assign.as_str()) else {
                continue;
            };
            // A body opener: the quote opens a string that does not close here.
            if let Some(quote) = QUOTES.iter().find(|quote| value.starts_with(**quote)) {
                let rest = value.get(quote.len()..).unwrap_or_default();
                if rest.contains(quote) {
                    continue;
                }
                let closer = lines
                    .iter()
                    .enumerate()
                    .skip(i + 1)
                    .find(|(_, other)| other.contains(quote))
                    .map(|(j, _)| j);
                if let Some(closer) = closer {
                    shell.extend(
                        (i + 1..closer).filter(|&j| lines.get(j).is_some_and(|l| code_line(l))),
                    );
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
                    shell.extend(
                        (i + 1..closer)
                            .filter(|&j| lines.get(j).is_some_and(|l| shell_syntax(l.trim()))),
                    );
                }
                continue;
            }
            // A one-line value, quotes and all.
            if shell_syntax(value) {
                shell.insert(i);
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
    let mut owner: BTreeMap<usize, usize> = BTreeMap::new();
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
            for j in i + 1..closer {
                if lines.get(j).is_some_and(|l| code_line(l)) {
                    owner.insert(j, i);
                }
            }
        } else if !rest.is_empty() && shell_syntax(rest) {
            owner.insert(i, i);
        }
    }
    let mut steps: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
    for (line, step) in owner {
        steps.entry(step).or_default().insert(line);
    }
    steps
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
        if !is_workflow && !shell_path(path) && !bytes.starts_with(b"#!") {
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
        if !(shell_path(path) || shell_shebang(first)) {
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
    fn a_keyword_is_read_with_its_quote_attached() {
        // The ban's reading, kept so the census and the gate cannot disagree: a
        // quoted value's first word carries the quote, so no keyword matches.
        assert!(!shell_syntax("\"set -e\""));
        assert!(shell_syntax("set -e"));
    }

    #[test]
    fn an_array_entry_counts_only_when_it_carries_shell() {
        let lines = ["run = [", "  \"cargo build\",", "  \"a | b\",", "]"];
        assert_eq!(manifest_lines(&lines, &keys(&["run"])), BTreeSet::from([2]));
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
            "      - run: mise run verify",
            "      - run: a && b",
        ];
        let steps = workflow_steps(&lines);
        assert_eq!(steps.get(&3), Some(&BTreeSet::from([4, 7])));
        assert_eq!(steps.get(&10), Some(&BTreeSet::from([11])));
        assert_eq!(steps.get(&12), None, "a single command is not shell");
        assert_eq!(steps.get(&13), Some(&BTreeSet::from([13])));
    }

    #[test]
    fn a_trigger_is_not_a_step() {
        let lines = ["on:", "  workflow_run:", "    workflows: [x]"];
        assert!(workflow_steps(&lines).is_empty());
    }

    #[test]
    fn a_shebang_naming_a_shell_is_shell_and_one_naming_another_language_is_not() {
        assert!(shell_shebang("#!/usr/bin/env bash"));
        assert!(shell_shebang("#!/bin/sh"));
        assert!(!shell_shebang("#!/usr/bin/env python3"));
        assert!(!shell_shebang("# bash"));
        assert!(shell_path("x.bats") && shell_path("a/b.sh") && !shell_path("a/sh"));
    }

    #[test]
    fn units_are_named_by_their_header_and_lone_lines_stand_alone() {
        let lines = [
            "run = \"a | b\"",
            "[tasks.a]",
            "run = '''",
            "echo a",
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
            [(1, None, 1), (2, Some("a"), 1), (6, Some("b:c"), 1)]
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
