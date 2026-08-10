//! The rule and check engine (CLOUD-12).
//!
//! A rule is a **declarative predicate over the repository**: it selects files
//! with a `glob` and applies a `kind`-specific test to them, mapping the outcome
//! onto the exit-code contract (§7) through the rule's `severity` (CLOUD-61) —
//! a clean run exits `0`, any `deny` finding exits `2`, a `warn` finding is
//! reported without failing the run, and an `allow` rule is configured off.
//! `severity` is required per rule with no implicit fallback, and is a separate
//! key from `scope` ([`RuleScope`]) — where a rule looks is never what a match
//! does.
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
//! Three kinds ship: [`RuleKind::Forbid`], a static banned-shape literal check
//! over files; [`RuleKind::Command`], the dynamic escape hatch that runs a
//! configured command and reads its exit code as the predicate; and
//! [`RuleKind::Shape`], a banned *command* shape adjudicated by `batten hook`
//! against one mediated call. [`RuleScope`] is what routes a rule to the surface
//! that evaluates it, and [`RuleKind::scopes`] pairs the two so a rule no
//! surface would ever run cannot load. Two properties are load-bearing and
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

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::UsageError;
use crate::severity::{self, ReportLevel, RuleSeverity};

/// The kind of predicate a [`Rule`] applies to its matched files.
///
/// Serialized as a lowercase `kind = "..."` token in `batten.toml`. Marked
/// `#[non_exhaustive]` because the engine is designed to grow kinds (the dynamic
/// `command` kind is CLOUD-89) without that being a breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
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
    /// A banned **command shape**: the mediated call `batten hook` is
    /// adjudicating matches `pattern` read as an effective program plus the
    /// adjacent words that must follow it.
    ///
    /// Distinct from [`RuleKind::Command`], which *runs* a declared command.
    /// This one runs nothing — it is a string match over a command line the
    /// host handed us, so it cannot spawn and stays on the read-safe surface.
    Shape,
}

impl RuleKind {
    /// Every kind the engine knows, so the partitions below are total.
    ///
    /// A new variant must be added here or [`tests::all_covers_every_kind`]
    /// fails — which is what keeps [`RuleKind::spawns_processes`] from silently
    /// defaulting a spawning kind to "safe".
    pub const ALL: &'static [RuleKind] = &[RuleKind::Forbid, RuleKind::Command, RuleKind::Shape];

    /// The stable lowercase token used in config and machine output (§6).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            RuleKind::Forbid => "forbid",
            RuleKind::Command => "command",
            RuleKind::Shape => "shape",
        }
    }

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
            RuleKind::Forbid | RuleKind::Shape => false,
            RuleKind::Command => true,
        }
    }

    /// The columns this kind cannot load without.
    #[must_use]
    pub const fn requires(self) -> &'static [&'static str] {
        match self {
            RuleKind::Forbid => &["glob", "pattern"],
            RuleKind::Command => &["glob", "run"],
            // A shape row's `reason` is required, not optional: the deny it
            // produces reaches a model as the whole explanation, and a refusal
            // with nothing but an id is the un-actionable shape CLOUD-122 exists
            // to prevent.
            RuleKind::Shape => &["pattern", "reason"],
        }
    }

    /// Every column this kind accepts — a superset of [`RuleKind::requires`].
    ///
    /// Anything outside this set is a usage error rather than an ignored key: a
    /// `glob` on a shape rule selects files a shape rule never reads, so
    /// accepting it would let a reviewer believe a rule is scoped when it is not.
    #[must_use]
    pub const fn permits(self) -> &'static [&'static str] {
        match self {
            RuleKind::Forbid => &["glob", "pattern"],
            RuleKind::Command => &["glob", "run"],
            RuleKind::Shape => &["pattern", "reason", "contains", "policy_url"],
        }
    }

    /// The scopes this kind may declare.
    ///
    /// The pairing is what makes the scope key a real router rather than a label:
    /// a file kind scoped to the mediated call, or a shape kind scoped to the
    /// tree, would be a rule that no surface ever evaluates — present, inert, and
    /// reading as covered.
    #[must_use]
    pub const fn scopes(self) -> &'static [RuleScope] {
        match self {
            RuleKind::Forbid | RuleKind::Command => &[RuleScope::Tree],
            RuleKind::Shape => &[RuleScope::MediatedCall],
        }
    }
}

/// Which file domain a rule evaluates over — *where a rule looks*, never what a
/// match does (CLOUD-61).
///
/// Scope and severity are two independent keys on a [`Rule`], deliberately: the
/// question "which files does this gate watch" and the question "what happens
/// when it matches" ([`RuleSeverity`]) are different axes, and conflating them
/// is the config bug this type makes inexpressible. Neither vocabulary
/// deserializes as the other, so a severity token in the `scope` key (or the
/// reverse) is a usage error (exit `1`), never a silent reinterpretation.
///
/// Marked `#[non_exhaustive]` like [`RuleKind`]: the git change-set / protected
/// / unlanded domains (CLOUD-36, CLOUD-37) slot in as new variants without a
/// breaking change. The default is pinned as data —
/// [`tests::scope_default_is_pinned`] asserts it — so it is an explicit,
/// per-field default rather than an implicit fallback buried in code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RuleScope {
    /// The whole working tree: every file the walk yields. The pinned default.
    #[default]
    Tree,
    /// The single command `batten hook` is adjudicating — not a file domain at
    /// all, which is why a rule declaring it reads no `glob`.
    ///
    /// Spelled `mediated_call` rather than `command` on purpose: `command` is
    /// already a [`RuleKind`] token meaning "run this", and one word meaning two
    /// unrelated things across two keys is the cross-vocabulary confusion
    /// [`tests::severity_and_scope_vocabularies_do_not_cross`] exists to prevent.
    MediatedCall,
}

impl RuleScope {
    /// Every scope the engine knows, so vocabulary tests stay total.
    pub const ALL: &'static [RuleScope] = &[RuleScope::Tree, RuleScope::MediatedCall];

    /// The stable lowercase token used in config and machine output (§6).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            RuleScope::Tree => "tree",
            RuleScope::MediatedCall => "mediated_call",
        }
    }
}

/// One declarative rule from `batten.toml`'s `[[rule]]` array.
///
/// `deny_unknown_fields` keeps the surface narrow (§8): a mistyped key is a hard
/// error, never a silently ignored setting that disables a gate. The struct is
/// flat rather than an enum with `#[serde(flatten)]` precisely so this guarantee
/// holds — `flatten` silently defeats `deny_unknown_fields`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
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
    ///
    /// Optional at the type level and required per-kind: a file kind cannot load
    /// without it, and [`RuleKind::Shape`] — which inspects no files — rejects it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub glob: Option<String>,
    /// What a match does: `deny` fails the run, `warn` reports without failing
    /// (until `--fail-on-warning` promotes it, CLOUD-49), `allow` switches the
    /// rule off (cargo-deny's model, CLOUD-61).
    ///
    /// **Required, deliberately**: every committed rule states its severity
    /// default explicitly, and there is no implicit fallback — omitting the key
    /// is a usage error (exit `1`), never a silently assumed level.
    pub severity: RuleSeverity,
    /// Which file domain the rule evaluates over. Independent of `severity` —
    /// scope says *where* the rule looks, severity says *what a match does* —
    /// and neither key's vocabulary parses as the other's. Defaults to
    /// [`RuleScope::Tree`], the pinned per-field default.
    #[serde(default)]
    pub scope: RuleScope,
    /// The literal shape this rule bans — one meaning, two domains.
    ///
    /// For [`RuleKind::Forbid`] it is a substring banned from matched *files*.
    /// For [`RuleKind::Shape`] it is a banned *command line*: the first word is
    /// the effective program (matched after wrapper look-through) and the rest
    /// are the adjacent non-flag words that must follow it, so
    /// `pattern = "gh pr merge"` reads exactly as a reviewer would say it aloud.
    /// Required by both kinds, rejected by [`RuleKind::Command`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    /// An extra literal that must appear in the mediated command **as written**
    /// for a [`RuleKind::Shape`] rule to fire. Optional, that kind only.
    ///
    /// It exists for one real case rather than as a general escape hatch: a
    /// landing directive lives inside a quoted `--body`, so it is not one of the
    /// words the shape matches, and without this an ordinary `gh pr comment`
    /// would be denied alongside the one that carries the directive. Matched
    /// against the raw text of the same segment, quotes included.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contains: Option<String>,
    /// Why this rule refuses, and what to do instead — the deny's whole text.
    ///
    /// Required by [`RuleKind::Shape`], where the refusal is all a caller gets;
    /// optional elsewhere, where a `path:line` pointer plus the id already says
    /// where to look.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// An optional link to the policy this rule enforces, appended to the deny.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_url: Option<String>,
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
    /// The program a [`RuleKind::Command`] rule invokes: the first
    /// whitespace-separated token of [`Rule::run`].
    ///
    /// Shared rather than re-split at each caller, so `doctor`'s PATH probe
    /// (CLOUD-66) and the runner below can never disagree about which token is
    /// the program — a probe that checked a different word than the one executed
    /// would report health about the wrong binary.
    ///
    /// `None` for any other kind, and for a `run` with no tokens (which the
    /// runner refuses as a usage error).
    #[must_use]
    pub fn program(&self) -> Option<&str> {
        if self.kind != RuleKind::Command {
            return None;
        }
        self.run.as_deref()?.split_whitespace().next()
    }

    /// Validate that the per-kind fields present match the declared `kind`.
    ///
    /// The struct is flat (a `#[serde(flatten)]` enum would silently defeat
    /// `deny_unknown_fields`), so the kind/field agreement that a tagged enum
    /// would give for free is asserted here instead — and a field belonging to
    /// another kind is an *error*, never ignored, so a rule can never half-apply.
    /// Every optional column, paired with whether this rule carries it.
    ///
    /// The census is what keeps [`Rule::validate`] total. The previous version
    /// hand-wrote one match arm per kind naming one required and one forbidden
    /// field, which was correct for two kinds and two columns and goes stale
    /// silently the moment either grows: a new column simply appears in no arm,
    /// so every kind accepts it. Listing the columns once and asking each kind
    /// about all of them makes that failure impossible, and
    /// [`tests::every_optional_rule_field_is_classified_by_every_kind`] fails if
    /// a column is added here without being placed.
    fn columns(&self) -> [(&'static str, bool); 6] {
        [
            ("glob", self.glob.is_some()),
            ("pattern", self.pattern.is_some()),
            ("run", self.run.is_some()),
            ("contains", self.contains.is_some()),
            ("reason", self.reason.is_some()),
            ("policy_url", self.policy_url.is_some()),
        ]
    }

    fn validate(&self) -> anyhow::Result<()> {
        let kind = self.kind.as_str();
        for column in self.kind.requires() {
            let present = self
                .columns()
                .into_iter()
                .any(|(name, present)| name == *column && present);
            if !present {
                return Err(UsageError::raise(format!(
                    "rule {}: kind \"{kind}\" requires `{column}`",
                    self.id
                )));
            }
        }
        for (name, present) in self.columns() {
            if present && !self.kind.permits().contains(&name) {
                return Err(UsageError::raise(format!(
                    "rule {}: `{name}` is not valid for kind \"{kind}\"",
                    self.id
                )));
            }
        }
        // Scope routes a rule to the surface that evaluates it, so a pairing the
        // engine cannot honour must be refused rather than accepted and never
        // run. An inert rule reads as coverage.
        if !self.kind.scopes().contains(&self.scope) {
            return Err(UsageError::raise(format!(
                "rule {}: kind \"{kind}\" does not evaluate over scope \"{}\"",
                self.id,
                self.scope.as_str()
            )));
        }
        if self.glob.as_deref().is_some_and(str::is_empty) {
            return Err(UsageError::raise(format!(
                "rule {}: `glob` must not be empty",
                self.id
            )));
        }
        Ok(())
    }

    /// The banned command shape: the effective program, then the adjacent words
    /// that must follow it.
    ///
    /// `None` for any kind but [`RuleKind::Shape`], and for a `pattern` with no
    /// program token.
    #[must_use]
    pub fn shape(&self) -> Option<(&str, Vec<&str>)> {
        if self.kind != RuleKind::Shape {
            return None;
        }
        let mut words = self.pattern.as_deref()?.split_whitespace();
        let program = words.next()?;
        Some((program, words.collect()))
    }
}

/// Validate a whole `[[rule]]` table, and refuse a duplicated id.
///
/// Called at **load** rather than only by a runner (`config::parse_ungated`),
/// because there are now two runners: the tree engine and `batten hook`. A rule
/// validated only by the surface that happens to run it is a rule the other
/// surface accepts malformed — and for the hook that means a policy row that
/// loads, matches nothing, and reads as coverage.
///
/// Two rows for one id is a policy question with two answers, and silently
/// taking the first is how a tightening edit gets lost behind a stale row. Same
/// reasoning, and the same shape, as [`crate::verbs::validate`].
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) for a malformed or duplicated rule.
pub fn validate(rules: &[Rule]) -> anyhow::Result<()> {
    for (index, rule) in rules.iter().enumerate() {
        rule.validate()?;
        if rules[..index].iter().any(|prior| prior.id == rule.id) {
            return Err(UsageError::raise(format!(
                "rule {}: declared twice; a rule has one definition",
                rule.id
            )));
        }
    }
    Ok(())
}

/// A single policy finding: the rule that fired and where, as a pointer only.
///
/// A finding never carries the matched bytes (non-negotiable rule 4) — only the
/// rule id and a `path:line` location the caller can open.
///
/// The `severity` is the producing rule's — the value the exit contract
/// consumes: a `deny` finding fails the run, a `warn` finding reports without
/// failing it (CLOUD-49 promotes it). It rides along for that decision only; it
/// is **never** an identity input (see [`crate::identity`] — re-rating a
/// finding must not re-mint it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// The [`Rule::id`] that produced this finding.
    pub rule: String,
    /// The producing rule's [`Rule::severity`], for the exit-contract decision.
    pub severity: RuleSeverity,
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
/// Returns a [`UsageError`] (→ exit `1`) when any configured rule's kind spawns
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
/// Returns a [`UsageError`] (→ exit `1`) for a malformed rule (e.g. an empty
/// `glob`). An I/O failure while walking the tree propagates as an internal
/// error (→ exit `3`).
fn run(rules: &[Rule], root: &Path) -> anyhow::Result<Vec<Finding>> {
    let files = tree_files(root)?;

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
    // Validation first, and it owns the empty-glob refusal now: the census in
    // `Rule::validate` is the one place that knows which columns a kind needs,
    // so a second check here could only disagree with it.
    rule.validate()?;
    // A rule the tree engine does not evaluate is not this surface's business.
    // `validate` has already refused an unevaluable kind/scope pairing, so a
    // skip here is a rule another surface owns, never one nothing runs.
    if rule.scope != RuleScope::Tree {
        return Ok(());
    }
    let Some(glob) = rule.glob.as_deref() else {
        // Unreachable for a tree-scoped kind, whose census requires `glob`.
        return Ok(());
    };
    // An `allow` rule is configured off: a match is not a finding at all. It is
    // still validated above — a malformed rule is a config error even when off,
    // because "off" must never double as "unreadable" — but it matches nothing
    // and (for a command kind) never spawns. Severity does not change which
    // surface admits a rule: `run_static`'s spawning refusal fires first,
    // regardless of severity, so the two axes stay independent.
    if rule.severity == RuleSeverity::Allow {
        return Ok(());
    }
    let matched: Vec<&String> = files.iter().filter(|path| glob_match(glob, path)).collect();
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
        // Unreachable: a shape rule is `mediated_call`-scoped, and the scope
        // guard above returned before the walk. Stated rather than caught by a
        // wildcard so adding a kind that *is* tree-scoped has to come here.
        RuleKind::Shape => {}
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
/// *config* error (exit `1`), never a silent pass — the failure mode that would
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
            severity: rule.severity,
            // The rule's glob is the tightest honest pointer for a finding a
            // command condemned as a batch. A command kind cannot load without
            // one, so the fallback is unreachable; naming the rule id rather
            // than an empty string keeps it a usable pointer if it ever is not.
            path: rule.glob.as_deref().unwrap_or(&rule.id).to_owned(),
            line: None,
        });
    }
    Ok(())
}

/// Whether a set of findings fails the run: does any finding's severity rank as
/// a blocking [`ReportLevel::Fail`], once the resolved `fail_on_warning` setting
/// has been applied?
///
/// The one place the rule axis is converted for the exit contract, derived
/// through the severity taxonomy's own table ([`severity::row_for_rule`])
/// rather than a name-match — a `warn` finding renders and does not block until
/// [`severity::promote`] lifts it (CLOUD-49).
///
/// `fail_on_warning` is a parameter rather than a value read here so that the
/// §8 chain resolves it exactly once, in [`crate::resolve`], and every caller is
/// forced by the signature to supply that resolved value. A default read inside
/// this function would be a second place the setting could be decided.
#[must_use]
pub fn any_blocking(findings: &[Finding], fail_on_warning: bool) -> bool {
    findings.iter().any(|finding| {
        severity::promote(
            severity::row_for_rule(finding.severity).report,
            fail_on_warning,
        ) == ReportLevel::Fail
    })
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
                severity: rule.severity,
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
/// Every file under `root`, as sorted repo-relative `/`-separated paths — the
/// one tree walk the crate has.
///
/// Sorted, so any pass over it is deterministic (§6), and `.git` is skipped:
/// the object store is never policy input. A second walker would be a second
/// answer to "what does Batten look at", which is the divergence
/// [`crate::markers`] reuses this to avoid.
///
/// # Errors
///
/// An I/O failure while walking propagates as an internal error (→ exit `3`).
pub fn tree_files(root: &Path) -> anyhow::Result<Vec<String>> {
    let mut files = Vec::new();
    collect_files(root, root, &mut files)?;
    files.sort();
    Ok(files)
}

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

/// The marker that turns a glob into an exclude inside an ordered
/// include/exclude list: gitignore's `!` prefix, so a reader who knows one knows
/// the other.
const EXCLUDE_PREFIX: char = '!';

/// One glob evaluator over repo-relative, `/`-separated paths.
///
/// A set answers exactly one question — *is this path a member?* — from its own
/// list and nothing else. Two sets built from two lists share no state, so
/// membership in each is computed independently (CLOUD-37). That independence is
/// the whole point: `scope`, `protected` and `unlanded` overlap in practice but
/// are not the same set, and collapsing them changes policy silently.
///
/// **An exclude beats an include.** Membership is `any include matches AND no
/// exclude matches`, so the outcome does not depend on the order the patterns
/// were written in — the strongest reading of "excludes win", and the one that
/// makes evaluation deterministic and order-stable for identical config (§6).
///
/// An empty include list makes the set empty. Absent config is *not* read as
/// "everything": a set that silently defaults to universal membership is a
/// widening, and widening is the one direction a policy engine may never drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathSet {
    includes: Vec<String>,
    excludes: Vec<String>,
}

impl PathSet {
    /// The set that contains nothing.
    ///
    /// Spelled out rather than derived as `Default`, because the safe empty value
    /// and the *obvious* one point in opposite directions here: an absent list
    /// must mean "no paths", never "all paths", and a `Default` impl is exactly
    /// the thing a future caller reaches for without reading which way it went
    /// (see the type's own doc comment). [`PathSet::contains`] needs at least one
    /// matching include, so this matches nothing by construction.
    #[must_use]
    pub const fn empty() -> Self {
        PathSet {
            includes: Vec::new(),
            excludes: Vec::new(),
        }
    }

    /// Whether this set can match anything.
    ///
    /// A set with no includes contains nothing, so a caller can skip the work of
    /// even asking. Excludes alone cannot make a set non-empty — they only
    /// subtract.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.includes.is_empty()
    }
}

impl PathSet {
    /// Build the ordered include/exclude set the `scope` key declares: a plain
    /// glob includes, a `!`-prefixed glob excludes.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) for a `!` with no glob after it —
    /// an exclude that excludes nothing is a typo, not an empty instruction.
    pub fn scope(patterns: &[String]) -> anyhow::Result<Self> {
        let mut set = PathSet {
            includes: Vec::new(),
            excludes: Vec::new(),
        };
        for pattern in patterns {
            match pattern.strip_prefix(EXCLUDE_PREFIX) {
                Some("") => {
                    return Err(UsageError::raise(
                        "scope: `!` must be followed by a glob".to_owned(),
                    ));
                }
                Some(rest) => set.excludes.push(rest.to_owned()),
                None => set.includes.push(pattern.clone()),
            }
        }
        Ok(set)
    }

    /// Build a plain include set from `key`'s list.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) for a `!`-prefixed entry. Only
    /// `scope` carries exclude semantics, so a `!` here would either be read as
    /// a literal glob or silently dropped — and a pattern the author believes
    /// excludes a path while the engine treats it as an include is precisely the
    /// silent policy change this issue exists to prevent. Refuse instead.
    pub fn includes(key: &str, patterns: &[String]) -> anyhow::Result<Self> {
        for pattern in patterns {
            if pattern.starts_with(EXCLUDE_PREFIX) {
                return Err(UsageError::raise(format!(
                    "{key}: `{pattern}` — only `scope` takes `!` excludes; {key} is a plain \
                     include set"
                )));
            }
        }
        Ok(PathSet {
            includes: patterns.to_vec(),
            excludes: Vec::new(),
        })
    }

    /// Whether `path` is a member of this set, computed from this set's lists
    /// alone.
    #[must_use]
    pub fn contains(&self, path: &str) -> bool {
        self.includes
            .iter()
            .any(|pattern| glob_match(pattern, path))
            && !self
                .excludes
                .iter()
                .any(|pattern| glob_match(pattern, path))
    }
}

/// The three sets Batten's policy is defined over, each parsed from its own list
/// in `batten.toml` (CLOUD-37).
///
/// Grouped for construction only. Nothing here consults another field: a path's
/// membership in `scope`, in `protected`, and in `unlanded` are three separate
/// answers, and no code may derive one from another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sets {
    /// The paths policy applies to — the one ordered include/exclude set.
    pub scope: PathSet,
    /// The paths whose modification is guarded.
    pub protected: PathSet,
    /// The paths whose work is not yet landed.
    pub unlanded: PathSet,
}

impl Sets {
    /// Build all three evaluators from a parsed config.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) when a list is malformed — a bare
    /// `!` in `scope`, or a `!` entry in an include-only key.
    pub fn from_config(config: &crate::config::Config) -> anyhow::Result<Self> {
        Ok(Sets {
            scope: PathSet::scope(&config.scope)?,
            protected: PathSet::includes("protected", &config.protected)?,
            unlanded: PathSet::includes("unlanded", &config.unlanded)?,
        })
    }
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

    /// A rule with every column empty, for a test to fill in the one it means.
    ///
    /// Keeps the fixtures below from re-listing six `None`s each, so adding a
    /// column touches this one place rather than every test.
    fn blank(id: &str, kind: RuleKind) -> Rule {
        Rule {
            id: id.to_owned(),
            kind,
            glob: None,
            severity: RuleSeverity::Deny,
            scope: kind.scopes()[0],
            pattern: None,
            contains: None,
            reason: None,
            policy_url: None,
            run: None,
        }
    }

    fn forbid(id: &str, glob: &str, pattern: &str) -> Rule {
        Rule {
            glob: Some(glob.to_owned()),
            pattern: Some(pattern.to_owned()),
            ..blank(id, RuleKind::Forbid)
        }
    }

    fn command(id: &str, glob: &str, run: &str) -> Rule {
        Rule {
            glob: Some(glob.to_owned()),
            run: Some(run.to_owned()),
            ..blank(id, RuleKind::Command)
        }
    }

    fn shape(id: &str, pattern: &str, reason: &str) -> Rule {
        Rule {
            pattern: Some(pattern.to_owned()),
            reason: Some(reason.to_owned()),
            ..blank(id, RuleKind::Shape)
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
                    severity: RuleSeverity::Deny,
                    path: "src/a.rs".to_owned(),
                    line: Some(2),
                },
                Finding {
                    rule: "no-todo".to_owned(),
                    severity: RuleSeverity::Deny,
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
    fn every_optional_rule_field_is_classified_by_every_kind() {
        // The census's own gate. Every column a rule can carry must be either
        // required or permitted by at least one kind — a column classified by no
        // kind is one every kind rejects, which is a field nobody can ever set.
        // This is what the hand-written per-kind match could not give: it named
        // fields, so a new one simply appeared in no arm.
        let all = blank("probe", RuleKind::Forbid).columns();
        for (name, _) in all {
            let classified = RuleKind::ALL
                .iter()
                .any(|kind| kind.permits().contains(&name));
            assert!(
                classified,
                "column `{name}` is permitted by no kind, so it can never be set"
            );
        }
        // And `requires` must be a subset of `permits` for every kind, or a kind
        // would demand a column it then rejects.
        for kind in RuleKind::ALL {
            for required in kind.requires() {
                assert!(
                    kind.permits().contains(required),
                    "{kind:?} requires `{required}` but does not permit it"
                );
            }
        }
    }

    #[test]
    fn no_mediated_call_kind_spawns_a_process() {
        // What actually makes `hook`'s dispatch structurally unable to run a
        // configured command, stated over the whole cross product rather than a
        // named pair. `Policy::from_resolved` filters on scope alone, so this is
        // the property that filter relies on.
        for kind in RuleKind::ALL {
            if kind.scopes().contains(&RuleScope::MediatedCall) {
                assert!(
                    !kind.spawns_processes(),
                    "{kind:?} is adjudicable at the mediation channel and can spawn"
                );
            }
        }
    }

    #[test]
    fn kind_and_scope_vocabularies_do_not_cross() {
        // The same separation `severity_and_scope_vocabularies_do_not_cross`
        // enforces, applied to the pair that nearly collided: `command` is a
        // kind, and naming a scope `command` too would make one word mean two
        // unrelated things across two keys in the same table.
        for kind in RuleKind::ALL {
            for scope in RuleScope::ALL {
                assert_ne!(
                    kind.as_str(),
                    scope.as_str(),
                    "the token {:?} names both a kind and a scope",
                    kind.as_str()
                );
            }
        }
    }

    #[test]
    fn a_kind_only_accepts_its_own_scopes() {
        // A kind/scope pairing the engine cannot honour must be refused, never
        // accepted and then never evaluated. An inert rule reads as coverage,
        // which is the failure this whole file is written against.
        for kind in RuleKind::ALL {
            for scope in RuleScope::ALL {
                let mut rule = blank("pairing", *kind);
                rule.scope = *scope;
                // Fill whatever this kind requires so the only possible
                // complaint is the pairing.
                for column in kind.requires() {
                    match *column {
                        "glob" => rule.glob = Some("**".to_owned()),
                        "pattern" => rule.pattern = Some("x".to_owned()),
                        "run" => rule.run = Some("true".to_owned()),
                        "reason" => rule.reason = Some("because".to_owned()),
                        other => panic!("unclassified required column `{other}`"),
                    }
                }
                let result = rule.validate();
                if kind.scopes().contains(scope) {
                    assert!(result.is_ok(), "{kind:?}/{scope:?} must load");
                } else {
                    let err = result.expect_err("an unevaluable pairing must be refused");
                    assert!(err.downcast_ref::<UsageError>().is_some());
                }
            }
        }
    }

    #[test]
    fn a_shape_rule_requires_a_pattern_and_a_reason() {
        let mut no_pattern = blank("s", RuleKind::Shape);
        no_pattern.reason = Some("because".to_owned());
        assert!(no_pattern.validate().is_err(), "a shape needs a pattern");

        let mut no_reason = blank("s", RuleKind::Shape);
        no_reason.pattern = Some("gh pr merge".to_owned());
        // A mediated deny reaches a model as the whole explanation, so a row
        // that would refuse with nothing but an id cannot load (CLOUD-122).
        assert!(no_reason.validate().is_err(), "a shape needs a reason");
    }

    #[test]
    fn a_shape_rule_rejects_a_glob_and_a_run() {
        for column in ["glob", "run"] {
            let mut rule = shape("s", "gh pr merge", "because");
            match column {
                "glob" => rule.glob = Some("**".to_owned()),
                _ => rule.run = Some("true".to_owned()),
            }
            let err = rule
                .validate()
                .expect_err("a shape rule inspects no files and runs nothing");
            assert!(
                format!("{err}").contains(column),
                "the refusal must name `{column}`"
            );
        }
    }

    #[test]
    fn the_tree_engine_skips_a_mediated_call_rule_without_running_it() {
        // Routing, from the tree side: a shape row contributes no finding and no
        // error to `check`. It must not be refused either — `check` refusing a
        // rule another surface owns would make every hook-using repo unable to
        // run `check` at all.
        let dir = temp_dir("rules-skip-mediated");
        write(&dir, "a.rs", "gh pr merge\n");
        let rule = shape("no-hand-merge", "gh pr merge", "use the landing path");
        let findings = run_static(std::slice::from_ref(&rule), &dir).unwrap();
        assert!(findings.is_empty(), "a shape rule is not a file rule");
    }

    #[test]
    fn a_rule_id_declared_twice_is_a_usage_error() {
        // Two rows for one id is a policy question with two answers, and taking
        // the first silently is how a tightening edit gets lost behind a stale
        // row. Same reasoning as the verb table's duplicate refusal.
        let rules = [forbid("dup", "**", "a"), forbid("dup", "**", "b")];
        let err = validate(&rules).expect_err("a duplicated id must be refused");
        assert!(err.downcast_ref::<UsageError>().is_some());
    }

    #[test]
    fn all_covers_every_kind() {
        // The spawn partition must be total. `ALL` is what the gate below
        // iterates, so a kind missing from it would be silently untested —
        // exactly how a spawning kind could slip onto the read-only surface.
        // The match is exhaustive by the compiler; this asserts `ALL` agrees.
        for kind in RuleKind::ALL {
            match kind {
                RuleKind::Forbid | RuleKind::Command | RuleKind::Shape => {}
            }
        }
        assert_eq!(
            RuleKind::ALL.len(),
            3,
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
                glob: Some("**".to_owned()),
                run: Some("true".to_owned()),
                ..blank("spawner", *kind)
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
                severity: RuleSeverity::Deny,
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
            "a command that cannot run is a config error (exit 1), never a pass"
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
            // command with no `run`
            Rule {
                glob: Some("**".into()),
                ..blank("a", RuleKind::Command)
            },
            // command carrying a forbid-only column
            Rule {
                glob: Some("**".into()),
                pattern: Some("x".into()),
                run: Some("true".into()),
                ..blank("b", RuleKind::Command)
            },
            // forbid with no `pattern`
            Rule {
                glob: Some("**".into()),
                ..blank("c", RuleKind::Forbid)
            },
            // forbid carrying a command-only column
            Rule {
                glob: Some("**".into()),
                pattern: Some("x".into()),
                run: Some("true".into()),
                ..blank("d", RuleKind::Forbid)
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

    #[test]
    fn scope_default_is_pinned() {
        // The per-field default, as data: `tree` is what an omitted `scope` key
        // means, byte-stable in both directions. This is the "pinned" in
        // "per-field-pinned default" — the fallback is a declared, tested value,
        // never an accident of code.
        assert_eq!(RuleScope::default(), RuleScope::Tree);
        assert_eq!(RuleScope::default().as_str(), "tree");
        for &scope in RuleScope::ALL {
            let json = serde_json::to_string(&scope).unwrap();
            assert_eq!(json, format!("\"{}\"", scope.as_str()));
            assert_eq!(serde_json::from_str::<RuleScope>(&json).unwrap(), scope);
        }
        // `ALL` stays total: a new variant must extend it or this stops compiling.
        for scope in RuleScope::ALL {
            match scope {
                RuleScope::Tree | RuleScope::MediatedCall => {}
            }
        }
    }

    #[test]
    fn severity_and_scope_vocabularies_do_not_cross() {
        // The key separation, one layer below the config file: a severity token
        // does not deserialize as a scope, nor a scope token as a severity, so
        // conflating the two keys cannot even be *expressed* — it fails as a
        // usage error at parse time rather than silently re-reading one axis as
        // the other.
        for &severity in RuleSeverity::ALL {
            let token = format!("\"{}\"", severity.as_str());
            assert!(
                serde_json::from_str::<RuleScope>(&token).is_err(),
                "severity token {token} must not parse as a scope"
            );
        }
        for &scope in RuleScope::ALL {
            let token = format!("\"{}\"", scope.as_str());
            assert!(
                serde_json::from_str::<RuleSeverity>(&token).is_err(),
                "scope token {token} must not parse as a severity"
            );
        }
    }

    #[test]
    fn an_allow_rule_is_configured_off() {
        // `allow` means off: a match is not a finding at all, on both surfaces.
        let dir = temp_dir("rules-allow-off");
        write(&dir, "a.rs", "TODO\n");
        let mut rule = forbid("no-todo", "**/*.rs", "TODO");
        rule.severity = RuleSeverity::Allow;
        assert!(
            run_static(std::slice::from_ref(&rule), &dir)
                .unwrap()
                .is_empty()
        );
        assert!(
            run_all(std::slice::from_ref(&rule), &dir)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn an_allow_rule_is_still_validated() {
        // "Off" must never double as "unreadable": a malformed rule is a config
        // error even at severity `allow`, so flipping a broken rule on can
        // never be the moment its config first fails to parse.
        let dir = temp_dir("rules-allow-validated");
        write(&dir, "a.rs", "x\n");
        let mut rule = forbid("broken", "**/*.rs", "x");
        rule.severity = RuleSeverity::Allow;
        rule.pattern = None;
        let err = run_static(std::slice::from_ref(&rule), &dir).unwrap_err();
        assert!(err.downcast_ref::<UsageError>().is_some());
    }

    #[test]
    fn an_allow_command_rule_never_spawns() {
        // The missing binary would be a usage error if the spawn were reached,
        // so a clean exit proves the `allow` skip happens before any process.
        let dir = temp_dir("rules-allow-no-spawn");
        write(&dir, "a.rs", "x\n");
        let mut rule = command("off", "**/*.rs", "definitely-not-a-real-binary-xyz");
        rule.severity = RuleSeverity::Allow;
        assert!(
            run_all(std::slice::from_ref(&rule), &dir)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn severity_never_changes_which_surface_admits_a_rule() {
        // Scope ≠ severity, and severity ≠ effect either: the §5 spawning
        // refusal on the read-only surface fires for a command rule at *every*
        // severity, `allow` included. An axis that silently widened the read
        // surface would conflate "what a match does" with "what may run".
        let dir = temp_dir("rules-allow-still-refused");
        write(&dir, "a.rs", "x\n");
        for &severity in RuleSeverity::ALL {
            let mut rule = command("spawner", "**/*.rs", "true");
            rule.severity = severity;
            let err = run_static(std::slice::from_ref(&rule), &dir).unwrap_err();
            assert!(
                err.downcast_ref::<UsageError>().is_some(),
                "severity {} must not admit a spawning kind to `check`",
                severity.as_str()
            );
        }
    }

    #[test]
    fn warn_findings_report_without_blocking() {
        // The middle rank end to end at the library layer: a `warn` finding is
        // produced and carries its severity, and the exit-contract predicate
        // says it does not block — that promotion is `--fail-on-warning`'s job
        // (CLOUD-49), not the default's.
        let dir = temp_dir("rules-warn-reports");
        write(&dir, "a.rs", "TODO\n");
        let mut rule = forbid("no-todo", "**/*.rs", "TODO");
        rule.severity = RuleSeverity::Warn;
        let findings = run_static(std::slice::from_ref(&rule), &dir).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, RuleSeverity::Warn);
        assert!(
            !any_blocking(&findings, false),
            "a warn finding must not block"
        );
        // …and the same finding, unchanged, blocks once the setting promotes it
        // (CLOUD-49). The finding itself is identical in both runs: promotion
        // acts on the exit decision, never on what was stored or reported.
        assert!(
            any_blocking(&findings, true),
            "fail_on_warning must promote a warn finding"
        );

        let deny = run_static(&[forbid("no-todo", "**/*.rs", "TODO")], &dir).unwrap();
        for promote in [false, true] {
            assert!(
                any_blocking(&deny, promote),
                "a deny finding must block either way"
            );
            assert!(!any_blocking(&[], promote), "no findings, nothing blocks");
        }
    }

    /// The three-set fixture (CLOUD-37), written as the config it is.
    ///
    /// Deliberately overlapping and deliberately not nested: `src/**` is in
    /// scope, `src/generated/**` is excluded from it, `src/api.rs` is protected,
    /// and `src/draft.rs` is unlanded but *not* protected — the case the
    /// acceptance names, and the one a collapsed set gets wrong.
    const SETS_FIXTURE: &str = "\
version = 1
scope = [\"src/**\", \"!src/generated/**\"]
protected = [\"src/api.rs\", \"migrations/**\"]
unlanded = [\"src/draft.rs\", \"src/generated/**\"]
";

    fn sets(text: &str) -> Sets {
        let config = crate::config::parse(text, "test").unwrap();
        Sets::from_config(&config).unwrap()
    }

    #[test]
    fn three_independent_evaluators_exist() {
        // (a) Three sets, each answering from its own list alone. Every
        // assertion below is a path where at least two of the three disagree —
        // if any pair were collapsed, one of these flips.
        let sets = sets(SETS_FIXTURE);

        // In scope, protected, not unlanded.
        assert!(sets.scope.contains("src/api.rs"));
        assert!(sets.protected.contains("src/api.rs"));
        assert!(!sets.unlanded.contains("src/api.rs"));

        // Protected but out of scope: `migrations/**` is in no scope include.
        assert!(!sets.scope.contains("migrations/001.sql"));
        assert!(sets.protected.contains("migrations/001.sql"));
        assert!(!sets.unlanded.contains("migrations/001.sql"));

        // Unlanded and excluded from scope: membership in one says nothing
        // about the other, in either direction.
        assert!(!sets.scope.contains("src/generated/api.rs"));
        assert!(sets.unlanded.contains("src/generated/api.rs"));
        assert!(!sets.protected.contains("src/generated/api.rs"));
    }

    #[test]
    fn a_path_in_unlanded_but_not_protected_is_classified_by_each_set() {
        // (b) The acceptance's named case, stated as three independent answers
        // about one path. A single collapsed set cannot produce this row.
        let sets = sets(SETS_FIXTURE);
        assert!(sets.unlanded.contains("src/draft.rs"), "unlanded: yes");
        assert!(!sets.protected.contains("src/draft.rs"), "protected: no");
        assert!(sets.scope.contains("src/draft.rs"), "scope: yes");
    }

    #[test]
    fn an_exclude_beats_an_include_inside_scope() {
        // (c) `src/generated/api.rs` matches the `src/**` include and the
        // `!src/generated/**` exclude. The exclude wins.
        let sets = sets(SETS_FIXTURE);
        assert!(sets.scope.contains("src/a.rs"), "a plain include matches");
        assert!(
            !sets.scope.contains("src/generated/api.rs"),
            "an exclude must beat an overlapping include"
        );

        // …and it wins from either position in the list, so "excludes win" is a
        // property of the set rather than an artifact of authoring order.
        let reversed =
            PathSet::scope(&["!src/generated/**".to_owned(), "src/**".to_owned()]).unwrap();
        assert!(!reversed.contains("src/generated/api.rs"));
        assert!(reversed.contains("src/a.rs"));
    }

    #[test]
    fn evaluation_is_deterministic_for_identical_config() {
        // (d) Same config, same paths, same answers — twice over, across
        // separately-built evaluators, so nothing is carried between runs.
        let paths = [
            "src/a.rs",
            "src/api.rs",
            "src/draft.rs",
            "src/generated/api.rs",
            "migrations/001.sql",
            "README.md",
        ];
        let first = sets(SETS_FIXTURE);
        let second = sets(SETS_FIXTURE);
        assert_eq!(first, second, "identical config builds identical sets");
        for path in paths {
            assert_eq!(first.scope.contains(path), second.scope.contains(path));
            assert_eq!(
                first.protected.contains(path),
                second.protected.contains(path)
            );
            assert_eq!(
                first.unlanded.contains(path),
                second.unlanded.contains(path)
            );
            // Repeating a query on one evaluator is stable too: `contains` is a
            // pure function of the set, with no memo to go stale.
            assert_eq!(first.scope.contains(path), first.scope.contains(path));
        }
    }

    #[test]
    fn an_absent_list_is_the_empty_set_never_everything() {
        // The widening a default must never perform: no `scope` key means
        // nothing is in scope, not that every path is.
        let sets = sets("version = 1\n");
        for path in ["src/a.rs", "README.md", ""] {
            assert!(!sets.scope.contains(path));
            assert!(!sets.protected.contains(path));
            assert!(!sets.unlanded.contains(path));
        }
    }

    #[test]
    fn an_exclude_in_an_include_only_key_is_a_usage_error() {
        // Only `scope` carries exclude semantics. A `!` elsewhere would read as
        // an exclude to its author and as an include to the engine, so it is
        // refused rather than reinterpreted.
        for key in ["protected", "unlanded"] {
            let text = format!("version = 1\n{key} = [\"!src/**\"]\n");
            let config = crate::config::parse(&text, "test").unwrap();
            let err = Sets::from_config(&config).unwrap_err();
            assert!(err.downcast_ref::<UsageError>().is_some());
            assert!(
                err.to_string().contains(key),
                "the refusal must name the key, got: {err}"
            );
        }
    }

    #[test]
    fn a_bare_exclude_marker_is_a_usage_error() {
        let config = crate::config::parse("version = 1\nscope = [\"!\"]\n", "test").unwrap();
        let err = Sets::from_config(&config).unwrap_err();
        assert!(err.downcast_ref::<UsageError>().is_some());
    }
}
