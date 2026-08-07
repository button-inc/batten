//! The rule and check engine (CLOUD-12).
//!
//! A rule is a **declarative predicate over the repository**: it selects files
//! with a `glob` and applies a `kind`-specific test to them, mapping the outcome
//! onto the exit-code contract (§7) — a clean run exits `0`, any finding `1`.
//!
//! **Two entry points, split by effect (§5, CLOUD-170).** [`run_static`] backs
//! the `read`-effect `batten check` and admits only kinds that cannot spawn a
//! process; [`run_all`] backs the unclassified `batten enforce` and admits
//! every kind. The split is what keeps `check`'s `read` classification — and so
//! the derived agent read-only allowlist — honest once a kind can execute a
//! command declared in `batten.toml`. `check` **refuses** such a rule rather
//! than skipping it, because a skipped gate that still exits `0` is the
//! false-green Batten exists to catch.
//!
//! Two kinds ship: [`RuleKind::Forbid`], a static banned-shape literal check,
//! and [`RuleKind::Command`], the dynamic escape hatch that runs a configured
//! command and reads its exit code as the predicate. Further kinds slot in as
//! new variants with one match arm each. Two properties are load-bearing and
//! preserved by every kind added later:
//!
//! * **Pointer-only output** (non-negotiable rule 4): a finding is a
//!   `path:line`, never the matched bytes.
//! * **Byte-stable results** (§6): findings are sorted, so identical input yields
//!   identical output.
//!
//! File selection is intentionally simple at this stage: a walk of the working
//! tree, skipping `.git`. Scoping selection to the git change-set / protected /
//! unlanded sets is a separate concern (CLOUD-36, CLOUD-37) that layers on top of
//! this walk without changing the rule model.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::UsageError;

/// The kind of predicate a [`Rule`] applies to its matched files.
///
/// Serialized as a lowercase `kind = "..."` token in `batten.toml`. Marked
/// `#[non_exhaustive]` because the engine is designed to grow kinds (the dynamic
/// `command` kind is CLOUD-89) without that being a breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RuleKind {
    /// A static banned shape: every line of a matched file that contains the
    /// literal `pattern` is a finding. The check is inspection-only.
    Forbid,
    /// A dynamic check: run the `run` template and treat its exit code as the
    /// predicate — `0` passes, non-zero is a violation. The sanctioned escape
    /// hatch for rules no static shape can express.
    ///
    /// It is an **exit-code predicate, not a judge** (CLOUD-93): the command's
    /// output is never parsed for meaning. Because it executes a process
    /// declared in `batten.toml`, it runs only on the non-`read` surface (§5,
    /// CLOUD-170).
    Command,
}

impl RuleKind {
    /// Every kind the engine knows, so the spawn partition below is total.
    ///
    /// A new variant must be added here or [`tests::all_covers_every_kind`]
    /// fails — which is what keeps [`RuleKind::spawns_processes`] from silently
    /// defaulting a spawning kind to "safe".
    pub const ALL: &'static [RuleKind] = &[RuleKind::Forbid, RuleKind::Command];

    /// Whether running this kind can execute a process declared in
    /// `batten.toml`.
    ///
    /// This is the load-bearing predicate behind the §5 effect split
    /// (CLOUD-170): a `read`-classified verb may only run kinds for which this
    /// is `false`. It is stated per-kind rather than inferred, so adding a
    /// spawning kind (the `command` kind, CLOUD-89) is a deliberate act that
    /// automatically routes it away from the read-only surface.
    #[must_use]
    pub const fn spawns_processes(self) -> bool {
        match self {
            RuleKind::Forbid => false,
            RuleKind::Command => true,
        }
    }
}

/// One declarative rule from `batten.toml`'s `[[rule]]` array.
///
/// `deny_unknown_fields` keeps the surface narrow (§8): a mistyped key is a hard
/// error, never a silently ignored setting that disables a gate. The struct is
/// flat rather than an enum with `#[serde(flatten)]` precisely so this guarantee
/// holds — `flatten` silently defeats `deny_unknown_fields`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// A stable identifier for the rule, surfaced in findings so a violation
    /// points back at the policy that produced it.
    pub id: String,
    /// Which predicate to apply to the matched files.
    pub kind: RuleKind,
    /// The glob selecting which files the rule inspects, matched against
    /// repo-relative paths (`/`-separated). `**` matches any run of path
    /// segments, `*` and `?` match within a single segment.
    pub glob: String,
    /// The literal substring a [`RuleKind::Forbid`] rule bans from matched
    /// files. Required by that kind, rejected by any other.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    /// The command template a [`RuleKind::Command`] rule runs. Required by that
    /// kind, rejected by any other.
    ///
    /// Split on whitespace into `program` plus arguments and executed
    /// **directly — never through a shell**, so what runs is exactly what a
    /// reviewer reads (§9: rules "name a command already on the operator's
    /// PATH"). A bare [`FILES_PLACEHOLDER`] argument expands in place to the
    /// matched paths; omit it and the command self-discovers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<String>,
}

impl Rule {
    /// Validate that the per-kind fields present match the declared `kind`.
    ///
    /// The struct is flat (a `#[serde(flatten)]` enum would silently defeat
    /// `deny_unknown_fields`), so the kind/field agreement that a tagged enum
    /// would give for free is asserted here instead — and a field belonging to
    /// another kind is an *error*, never ignored, so a rule can never half-apply.
    fn validate(&self) -> anyhow::Result<()> {
        let (required, extra) = match self.kind {
            RuleKind::Forbid => (self.pattern.is_some(), self.run.is_some().then_some("run")),
            RuleKind::Command => (
                self.run.is_some(),
                self.pattern.is_some().then_some("pattern"),
            ),
        };
        let (needs, kind) = match self.kind {
            RuleKind::Forbid => ("pattern", "forbid"),
            RuleKind::Command => ("run", "command"),
        };
        if !required {
            return Err(UsageError::raise(format!(
                "rule {}: kind \"{kind}\" requires `{needs}`",
                self.id
            )));
        }
        if let Some(extra) = extra {
            return Err(UsageError::raise(format!(
                "rule {}: `{extra}` is not valid for kind \"{kind}\"",
                self.id
            )));
        }
        Ok(())
    }
}

/// A single policy violation: the rule that fired and where, as a pointer only.
///
/// A finding never carries the matched bytes (non-negotiable rule 4) — only the
/// rule id and a `path:line` location the caller can open.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// The [`Rule::id`] that produced this finding.
    pub rule: String,
    /// Where the violation is. A file-scoped kind reports the repo-relative
    /// path (`/`-separated); a rule-scoped kind — a command whose exit code
    /// condemns a whole batch rather than one line — reports the rule's `glob`,
    /// which is the tightest honest pointer available for it.
    pub path: String,
    /// The 1-based line number of the offending line, when the kind locates one.
    /// `None` for a rule-scoped finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
}

/// The name of the verb that runs process-spawning rule kinds, quoted in the
/// refusal [`run_static`] emits. Named once so the message and the surface
/// cannot drift.
pub const SPAWNING_VERB: &str = "batten enforce";

/// Run only the rules that cannot spawn a process — the surface a `read`-effect
/// verb is allowed to reach (house-style §5, CLOUD-170).
///
/// A configured rule whose kind *can* spawn is **refused loudly**, never
/// silently skipped: a skipped gate that still exits `0` is exactly the
/// false-green Batten exists to catch.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `2`) when any configured rule's kind spawns
/// processes, naming [`SPAWNING_VERB`] as the verb that runs it, and for a
/// malformed rule. An I/O failure propagates as an internal error (→ exit `3`).
pub fn run_static(rules: &[Rule], root: &Path) -> anyhow::Result<Vec<Finding>> {
    // Refuse before any work: the read-only surface must not even begin a run
    // it cannot complete honestly.
    for rule in rules {
        if rule.kind.spawns_processes() {
            return Err(UsageError::raise(format!(
                "rule {}: this rule kind runs a configured command, which `batten check` \
                 (a read-effect verb) will not do; run `{SPAWNING_VERB}` instead",
                rule.id
            )));
        }
    }
    run(rules, root)
}

/// Run every configured rule, including process-spawning kinds.
///
/// This is the non-`read` surface: it may execute commands declared in
/// `batten.toml`, so its verb is classified `unclassified` (§5).
///
/// # Errors
///
/// As [`run_static`], minus the spawning-kind refusal.
pub fn run_all(rules: &[Rule], root: &Path) -> anyhow::Result<Vec<Finding>> {
    run(rules, root)
}

/// Run every rule in `rules` against the tree rooted at `root`, returning all
/// findings sorted for byte-stability.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `2`) for a malformed rule (e.g. an empty
/// `glob`). An I/O failure while walking the tree propagates as an internal
/// error (→ exit `3`).
fn run(rules: &[Rule], root: &Path) -> anyhow::Result<Vec<Finding>> {
    let mut files = Vec::new();
    collect_files(root, root, &mut files)?;
    // A stable input order makes the finding order deterministic (§6).
    files.sort();

    let mut findings = Vec::new();
    for rule in rules {
        run_rule(rule, root, &files, &mut findings)?;
    }
    // Sort by the pointer tuple so identical input yields identical output.
    findings.sort_by(|a, b| {
        (a.path.as_str(), a.line, a.rule.as_str()).cmp(&(b.path.as_str(), b.line, b.rule.as_str()))
    });
    Ok(findings)
}

/// Apply one rule to the pre-collected, sorted `files` list.
fn run_rule(
    rule: &Rule,
    root: &Path,
    files: &[String],
    findings: &mut Vec<Finding>,
) -> anyhow::Result<()> {
    if rule.glob.is_empty() {
        return Err(UsageError::raise(format!(
            "rule {}: glob must not be empty",
            rule.id
        )));
    }
    rule.validate()?;
    let matched: Vec<&String> = files
        .iter()
        .filter(|path| glob_match(&rule.glob, path))
        .collect();
    // The glob is a gate before it is an argv source (§4 "cheap when
    // irrelevant"): no match means the rule is skipped entirely — for a command
    // rule, without ever spawning.
    if matched.is_empty() {
        return Ok(());
    }
    match rule.kind {
        RuleKind::Forbid => {
            for path in matched {
                forbid_in_file(rule, root, path, findings)?;
            }
        }
        RuleKind::Command => command_rule(rule, root, &matched, findings)?,
    }
    Ok(())
}

/// The argument a `run` template uses to mark where the matched paths go.
pub const FILES_PLACEHOLDER: &str = "{{files}}";

/// The upper bound, in bytes, on the matched paths handed to one invocation.
///
/// Kept well under every platform's real argv limit (Windows' ~32 KiB command
/// line is the tightest), so a large match set is split across independent
/// invocations instead of overflowing. Batching is invisible to the predicate:
/// a non-zero exit in *any* batch is a violation.
pub const MAX_FILES_BYTES: usize = 16_384;

/// Run a [`RuleKind::Command`] rule over its matched paths.
///
/// If the template contains [`FILES_PLACEHOLDER`], the paths are substituted at
/// that position, batched under [`MAX_FILES_BYTES`]; otherwise the command runs
/// once and self-discovers its own inputs (the glob still gated it).
fn command_rule(
    rule: &Rule,
    root: &Path,
    matched: &[&String],
    findings: &mut Vec<Finding>,
) -> anyhow::Result<()> {
    let template = rule.run.as_deref().ok_or_else(|| {
        UsageError::raise(format!("rule {}: kind \"command\" requires `run`", rule.id))
    })?;
    let tokens: Vec<&str> = template.split_whitespace().collect();
    let Some((program, args)) = tokens.split_first() else {
        return Err(UsageError::raise(format!(
            "rule {}: `run` must not be empty",
            rule.id
        )));
    };

    if !args.contains(&FILES_PLACEHOLDER) {
        // Self-discovering form: one invocation, no paths passed.
        run_once(rule, root, program, args, &[], findings)?;
        return Ok(());
    }

    for batch in batches(matched) {
        run_once(rule, root, program, args, &batch, findings)?;
    }
    Ok(())
}

/// Split `matched` into groups whose joined byte length stays under
/// [`MAX_FILES_BYTES`]. Order is preserved, so batching is deterministic and the
/// resulting findings stay byte-stable (§6).
fn batches<'a>(matched: &[&'a String]) -> Vec<Vec<&'a str>> {
    let mut batches = Vec::new();
    let mut current: Vec<&str> = Vec::new();
    let mut bytes = 0usize;
    for path in matched {
        let len = path.len() + 1;
        // Always place at least one path per batch, so a single path longer
        // than the bound still runs rather than looping forever.
        if !current.is_empty() && bytes + len > MAX_FILES_BYTES {
            batches.push(std::mem::take(&mut current));
            bytes = 0;
        }
        current.push(path.as_str());
        bytes += len;
    }
    if !current.is_empty() {
        batches.push(current);
    }
    batches
}

/// Spawn one invocation, substituting `files` for [`FILES_PLACEHOLDER`], and
/// record a finding if it exits non-zero.
///
/// A command that cannot run at all (missing binary, not executable) is a
/// *config* error (exit `2`), never a silent pass — the failure mode that would
/// turn a broken gate into a false green.
fn run_once(
    rule: &Rule,
    root: &Path,
    program: &str,
    args: &[&str],
    files: &[&str],
    findings: &mut Vec<Finding>,
) -> anyhow::Result<()> {
    let mut expanded: Vec<&str> = Vec::with_capacity(args.len() + files.len());
    for arg in args {
        if *arg == FILES_PLACEHOLDER {
            expanded.extend_from_slice(files);
        } else {
            expanded.push(arg);
        }
    }

    let status = std::process::Command::new(program)
        .args(&expanded)
        .current_dir(root)
        // The predicate is the exit code alone; the command's own streams are
        // not parsed for meaning (CLOUD-93) and are not surfaced here — a
        // bounded, pointer-only drain is the advisory subsystem's job (CLOUD-82).
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    let status = match status {
        Ok(status) => status,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(UsageError::raise(format!(
                "rule {}: cannot run `{program}`: not found on PATH",
                rule.id
            )));
        }
        Err(err) => {
            return Err(UsageError::raise(format!(
                "rule {}: cannot run `{program}`: {err}",
                rule.id
            )));
        }
    };

    if !status.success() {
        findings.push(Finding {
            rule: rule.id.clone(),
            path: rule.glob.clone(),
            line: None,
        });
    }
    Ok(())
}

/// Emit a finding for every line of `rel_path` that contains the rule's literal
/// `pattern`. A non-UTF-8 file cannot contain the literal, so it never matches.
fn forbid_in_file(
    rule: &Rule,
    root: &Path,
    rel_path: &str,
    findings: &mut Vec<Finding>,
) -> anyhow::Result<()> {
    let contents = match fs::read(root.join(rel_path)) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err.into()),
    };
    let Ok(text) = String::from_utf8(contents) else {
        return Ok(());
    };
    let Some(pattern) = rule.pattern.as_deref() else {
        return Err(UsageError::raise(format!(
            "rule {}: kind \"forbid\" requires `pattern`",
            rule.id
        )));
    };
    for (index, line) in text.lines().enumerate() {
        if line.contains(pattern) {
            findings.push(Finding {
                rule: rule.id.clone(),
                path: rel_path.to_owned(),
                line: Some(index + 1),
            });
        }
    }
    Ok(())
}

/// Recursively collect repo-relative file paths under `dir`, `/`-separated and
/// skipping the `.git` directory. `root` is the walk origin the paths are made
/// relative to.
fn collect_files(root: &Path, dir: &Path, out: &mut Vec<String>) -> anyhow::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            // The object store is never policy input; skip it wholesale.
            if entry.file_name() == ".git" {
                continue;
            }
            collect_files(root, &path, out)?;
        } else if file_type.is_file() {
            if let Ok(rel) = path.strip_prefix(root) {
                out.push(rel_to_slash(rel));
            }
        }
    }
    Ok(())
}

/// Render a relative path with `/` separators, so globbing and output are
/// identical across platforms (§6 byte-stability spans OSes).
fn rel_to_slash(rel: &Path) -> String {
    rel.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

/// Match a `/`-separated glob against a `/`-separated path.
///
/// `**` matches any run of path segments (including none); within a segment `*`
/// matches any run of non-`/` characters and `?` matches exactly one.
#[must_use]
pub fn glob_match(pattern: &str, path: &str) -> bool {
    let pat: Vec<&str> = pattern.split('/').collect();
    let path: Vec<&str> = path.split('/').collect();
    match_segments(&pat, &path)
}

fn match_segments(pat: &[&str], path: &[&str]) -> bool {
    let Some((first, rest)) = pat.split_first() else {
        // The pattern is exhausted; it matches only if the path is too.
        return path.is_empty();
    };
    if *first == "**" {
        // `**` consumes zero or more path segments; try each split point.
        for split in 0..=path.len() {
            if match_segments(rest, &path[split..]) {
                return true;
            }
        }
        return false;
    }
    let Some((head, tail)) = path.split_first() else {
        return false;
    };
    if match_one_segment(first, head) {
        match_segments(rest, tail)
    } else {
        false
    }
}

/// Match a single glob segment (no `/`) against a single path segment, honouring
/// `*` (any run of chars) and `?` (one char).
fn match_one_segment(pat: &str, seg: &str) -> bool {
    let pat: Vec<char> = pat.chars().collect();
    let seg: Vec<char> = seg.chars().collect();
    wildcard(&pat, &seg)
}

fn wildcard(pat: &[char], seg: &[char]) -> bool {
    match pat.split_first() {
        None => seg.is_empty(),
        Some(('*', rest)) => {
            // `*` matches zero or more characters: skip it, or consume one char.
            wildcard(rest, seg) || (!seg.is_empty() && wildcard(pat, &seg[1..]))
        }
        Some(('?', rest)) => !seg.is_empty() && wildcard(rest, &seg[1..]),
        Some((literal, rest)) => match seg.split_first() {
            Some((first, seg_rest)) if first == literal => wildcard(rest, seg_rest),
            _ => false,
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        // `CARGO_TARGET_TMPDIR` is only defined for integration-test crates, not
        // the library's own unit tests, so derive a scratch dir at runtime.
        let dir = std::env::temp_dir().join("batten-rules-tests").join(name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(dir: &Path, rel: &str, contents: &str) {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, contents).unwrap();
    }

    fn forbid(id: &str, glob: &str, pattern: &str) -> Rule {
        Rule {
            id: id.to_owned(),
            kind: RuleKind::Forbid,
            glob: glob.to_owned(),
            pattern: Some(pattern.to_owned()),
            run: None,
        }
    }

    fn command(id: &str, glob: &str, run: &str) -> Rule {
        Rule {
            id: id.to_owned(),
            kind: RuleKind::Command,
            glob: glob.to_owned(),
            pattern: None,
            run: Some(run.to_owned()),
        }
    }

    #[test]
    fn glob_star_stays_within_a_segment() {
        assert!(glob_match("*.rs", "lib.rs"));
        assert!(!glob_match("*.rs", "src/lib.rs"));
    }

    #[test]
    fn glob_double_star_spans_segments() {
        assert!(glob_match("**/*.rs", "src/a/b/lib.rs"));
        assert!(glob_match("**/*.rs", "lib.rs"));
        assert!(glob_match("src/**", "src/a/b/c"));
        assert!(!glob_match("src/**/*.rs", "other/lib.rs"));
    }

    #[test]
    fn glob_question_matches_one_char() {
        assert!(glob_match("a?c.txt", "abc.txt"));
        assert!(!glob_match("a?c.txt", "ac.txt"));
    }

    #[test]
    fn forbid_reports_pointer_only_findings() {
        let dir = temp_dir("rules-forbid-hit");
        write(&dir, "src/a.rs", "ok line\nTODO here\nanother TODO\n");
        write(&dir, "README.md", "TODO in docs is ignored by the glob\n");

        let findings = run_static(&[forbid("no-todo", "**/*.rs", "TODO")], &dir).unwrap();

        assert_eq!(
            findings,
            vec![
                Finding {
                    rule: "no-todo".to_owned(),
                    path: "src/a.rs".to_owned(),
                    line: Some(2),
                },
                Finding {
                    rule: "no-todo".to_owned(),
                    path: "src/a.rs".to_owned(),
                    line: Some(3),
                },
            ]
        );
    }

    #[test]
    fn clean_tree_yields_no_findings() {
        let dir = temp_dir("rules-forbid-clean");
        write(&dir, "src/a.rs", "all clear\n");
        let findings = run_static(&[forbid("no-todo", "**/*.rs", "TODO")], &dir).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn results_are_byte_stable_across_runs() {
        let dir = temp_dir("rules-stable");
        write(&dir, "b.rs", "TODO\n");
        write(&dir, "a.rs", "TODO\n");
        write(&dir, "src/c.rs", "TODO\n");
        let rule = forbid("no-todo", "**/*.rs", "TODO");
        let first = run_static(std::slice::from_ref(&rule), &dir).unwrap();
        let second = run_static(std::slice::from_ref(&rule), &dir).unwrap();
        assert_eq!(first, second);
        // Sorted by path: a.rs, b.rs, src/c.rs.
        let paths: Vec<&str> = first.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, vec!["a.rs", "b.rs", "src/c.rs"]);
    }

    #[test]
    fn git_directory_is_never_inspected() {
        let dir = temp_dir("rules-skip-git");
        write(&dir, ".git/config", "TODO must not be read\n");
        write(&dir, "a.rs", "clean\n");
        let findings = run_static(&[forbid("no-todo", "**", "TODO")], &dir).unwrap();
        assert!(findings.is_empty(), "the .git dir must be skipped");
    }

    #[test]
    fn non_utf8_file_never_matches() {
        let dir = temp_dir("rules-binary");
        fs::write(dir.join("blob.rs"), [0xff, 0xfe, 0x00]).unwrap();
        let findings = run_static(&[forbid("no-todo", "**/*.rs", "TODO")], &dir).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn all_covers_every_kind() {
        // The spawn partition must be total. `ALL` is what the gate below
        // iterates, so a kind missing from it would be silently untested —
        // exactly how a spawning kind could slip onto the read-only surface.
        // The match is exhaustive by the compiler; this asserts `ALL` agrees.
        for kind in RuleKind::ALL {
            match kind {
                RuleKind::Forbid | RuleKind::Command => {}
            }
        }
        assert_eq!(
            RuleKind::ALL.len(),
            2,
            "a new RuleKind must be added to RuleKind::ALL"
        );
    }

    #[test]
    fn the_read_only_surface_refuses_every_spawning_kind() {
        // CLOUD-170's computable gate, stated over *every* kind rather than a
        // named one: no kind that can spawn a process may run under
        // `run_static` (the `read`-effect `check`). Vacuous while `forbid` is
        // the only kind; it starts biting the moment CLOUD-89 adds `command`,
        // which is the point — the invariant is in place before the risk is.
        let dir = temp_dir("rules-spawn-gate");
        write(&dir, "a.rs", "TODO\n");
        for kind in RuleKind::ALL {
            if !kind.spawns_processes() {
                continue;
            }
            let rule = Rule {
                id: "spawner".to_owned(),
                kind: *kind,
                glob: "**".to_owned(),
                pattern: None,
                run: Some("true".to_owned()),
            };
            let err = run_static(std::slice::from_ref(&rule), &dir).unwrap_err();
            assert!(
                err.downcast_ref::<UsageError>().is_some(),
                "a spawning kind must be refused as a usage error, not run"
            );
            assert!(
                err.to_string().contains(SPAWNING_VERB),
                "the refusal must name the verb that does run it"
            );
        }
    }

    #[test]
    fn non_spawning_kinds_run_on_both_surfaces() {
        // The split must not change *results* for admissible kinds — only which
        // kinds are admissible. Otherwise the two verbs drift.
        let dir = temp_dir("rules-both-surfaces");
        write(&dir, "a.rs", "TODO\n");
        let rule = forbid("no-todo", "**/*.rs", "TODO");
        assert_eq!(
            run_static(std::slice::from_ref(&rule), &dir).unwrap(),
            run_all(std::slice::from_ref(&rule), &dir).unwrap()
        );
    }

    #[test]
    fn command_exit_zero_passes_and_non_zero_is_a_violation() {
        let dir = temp_dir("cmd-exit");
        write(&dir, "a.rs", "x\n");
        let pass = run_all(&[command("ok", "**/*.rs", "true")], &dir).unwrap();
        assert!(pass.is_empty(), "exit 0 must pass");

        let fail = run_all(&[command("bad", "**/*.rs", "false")], &dir).unwrap();
        assert_eq!(
            fail,
            vec![Finding {
                rule: "bad".to_owned(),
                // Rule-scoped: the exit code condemns the batch, not a line.
                path: "**/*.rs".to_owned(),
                line: None,
            }]
        );
    }

    #[test]
    fn a_glob_matching_nothing_never_spawns() {
        // §4 "cheap when irrelevant": the glob gates before it feeds argv. The
        // canary is a command that would fail loudly if it ever ran — a missing
        // binary is a usage error, so reaching the spawn would surface here.
        let dir = temp_dir("cmd-no-match");
        write(&dir, "a.txt", "x\n");
        let findings = run_all(
            &[command(
                "never",
                "**/*.rs",
                "definitely-not-a-real-binary-xyz",
            )],
            &dir,
        )
        .unwrap();
        assert!(
            findings.is_empty(),
            "an unmatched glob must skip, not spawn"
        );
    }

    #[test]
    fn missing_binary_is_a_usage_error_not_a_silent_pass() {
        let dir = temp_dir("cmd-missing-bin");
        write(&dir, "a.rs", "x\n");
        let err = run_all(
            &[command(
                "gone",
                "**/*.rs",
                "definitely-not-a-real-binary-xyz",
            )],
            &dir,
        )
        .unwrap_err();
        assert!(
            err.downcast_ref::<UsageError>().is_some(),
            "a command that cannot run is a config error (exit 2), never a pass"
        );
    }

    #[test]
    fn files_placeholder_receives_the_matched_paths() {
        // `test -e <path>` succeeds only if the path was actually substituted
        // and resolves relative to the run root, so this asserts interpolation
        // rather than merely that something ran.
        let dir = temp_dir("cmd-files");
        write(&dir, "present.rs", "x\n");
        let findings = run_all(&[command("subst", "**/*.rs", "test -e {{files}}")], &dir).unwrap();
        assert!(findings.is_empty(), "the matched path must reach the argv");
    }

    #[test]
    fn a_template_without_the_placeholder_runs_once_and_self_discovers() {
        // Three matches, no placeholder: the command still runs exactly once.
        // `false` fails every time it runs, so one finding proves one spawn.
        let dir = temp_dir("cmd-self-discover");
        write(&dir, "a.rs", "x\n");
        write(&dir, "b.rs", "x\n");
        write(&dir, "c.rs", "x\n");
        let findings = run_all(&[command("once", "**/*.rs", "false")], &dir).unwrap();
        assert_eq!(findings.len(), 1, "self-discovering form runs once");
    }

    #[test]
    fn matched_paths_are_batched_under_the_argv_bound() {
        // Every batch stays under the documented bound, and batching preserves
        // order — the property that keeps findings byte-stable (§6).
        let paths: Vec<String> = (0..2000).map(|i| format!("src/file-{i:04}.rs")).collect();
        let refs: Vec<&String> = paths.iter().collect();
        let batches = batches(&refs);
        assert!(batches.len() > 1, "a large match set must split");
        for batch in &batches {
            let bytes: usize = batch.iter().map(|p| p.len() + 1).sum();
            assert!(bytes <= MAX_FILES_BYTES, "batch overflows the argv bound");
        }
        let flattened: Vec<&str> = batches.concat();
        let expected: Vec<&str> = paths.iter().map(String::as_str).collect();
        assert_eq!(flattened, expected, "batching must preserve order");
    }

    #[test]
    fn a_kind_only_accepts_its_own_fields() {
        // The flat-struct tension: without a tagged enum, kind/field agreement
        // is asserted here. A field from another kind is an error, never ignored.
        let dir = temp_dir("cmd-schema");
        write(&dir, "a.rs", "x\n");
        let cases = [
            Rule {
                id: "a".into(),
                kind: RuleKind::Command,
                glob: "**".into(),
                pattern: None,
                run: None,
            },
            Rule {
                id: "b".into(),
                kind: RuleKind::Command,
                glob: "**".into(),
                pattern: Some("x".into()),
                run: Some("true".into()),
            },
            Rule {
                id: "c".into(),
                kind: RuleKind::Forbid,
                glob: "**".into(),
                pattern: None,
                run: None,
            },
            Rule {
                id: "d".into(),
                kind: RuleKind::Forbid,
                glob: "**".into(),
                pattern: Some("x".into()),
                run: Some("true".into()),
            },
        ];
        for rule in cases {
            let id = rule.id.clone();
            let err = run_all(std::slice::from_ref(&rule), &dir).unwrap_err();
            assert!(
                err.downcast_ref::<UsageError>().is_some(),
                "rule {id}: mismatched kind/fields must be a usage error"
            );
        }
    }

    #[test]
    fn empty_glob_is_a_usage_error() {
        let dir = temp_dir("rules-empty-glob");
        write(&dir, "a.rs", "TODO\n");
        let err = run_static(&[forbid("bad", "", "TODO")], &dir).unwrap_err();
        assert!(err.downcast_ref::<UsageError>().is_some());
    }
}
