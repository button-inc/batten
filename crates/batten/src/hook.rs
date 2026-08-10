//! The `hook` adjudicator (CLOUD-202): the agent-neutral envelope, the
//! wrapper-lookthrough command parser, and the first policy table, ported from
//! the battle-tested shell guards (`mise-tasks/gh-guard-check` et al.).
//!
//! Three layers, deliberately separated:
//!
//! * [`Envelope`] — the one normalized shape every harness adapter decodes
//!   into: `event`, `tool`, and `command`. Harness-specific field names live in
//!   the adapter for that harness, never here. (`cwd` and `session` are *not*
//!   fields yet; the absence is why an absolute path argument cannot be resolved
//!   against the repo root.)
//! * the parser — quoted spans become words rather than a sentinel, segments
//!   split on unquoted shell separators, env prefixes and wrapper programs
//!   (`env`, `timeout`, `mise exec -- …`) looked through, so policy judges the
//!   **effective** program. Judging the wrapper token instead is the bug class
//!   CLOUD-181 hardened the shell guards against; the port keeps that hard-won
//!   shape, and CLOUD-269 extended it so a quoted operand survives as a word.
//! * the policy — **config, not code** (CLOUD-48). [`Policy`] is the
//!   `mediated_call`-scoped rows of the resolved `batten.toml`, so the shapes a
//!   repository refuses are readable without reading Rust (§9) and the engine
//!   carries no consumer's task names (non-negotiable rule 1). This module owns
//!   the matcher; the table lives in the consumer's config.
//!
//! **Posture: fail open.** Unreadable stdin, unparseable JSON, an envelope with
//! no command — all resolve to [`Decision::Allow`]. A guard must never be the
//! reason a session cannot proceed; the escape hatch (`BATTEN_GH_GUARD_BYPASS`)
//! is honoured exactly as the shell guard honours it. Fail-open needs no care
//! here beyond the returns below: §7 spends `2` on the policy verdict alone, so
//! neither code a Batten failure can produce is one a host reads as a deny.

use serde::Serialize;
use serde_json::Value;

use crate::resolve::Resolved;
use crate::rules::{PathSet, Rule, RuleScope};
use crate::severity::{self, ReportLevel, RuleSeverity};
use crate::verbs::MutatingVerb;

/// The harness adapters `batten hook` can speak. Each owns the decode of its
/// host's payload into an [`Envelope`] and the encode of a [`Decision`] into
/// what that host consumes; the core between them is harness-blind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Harness {
    /// Claude Code's `PreToolUse` payload; a deny is returned as the
    /// `hookSpecificOutput.permissionDecision` JSON object on stdout with exit
    /// `0` — the channel the production shell guards already use.
    ClaudeCode,
    /// The neutral core contract: envelope in, decision as exit code out —
    /// `0` allow, `2` deny (reason on stderr), for any host whose only decision
    /// channel is an exit status. Both codes are the §7 table's, unmodified.
    ExitCode,
}

impl Harness {
    /// Every harness, so anything ranging over them is derived rather than
    /// re-typed — the CLOUD-40 decision-channel matrix reads this, which is what
    /// stops a third adapter from landing with no fixture row.
    pub const ALL: &'static [Harness] = &[Harness::ClaudeCode, Harness::ExitCode];

    /// The CLI token, identical to the `ValueEnum` spelling `--harness` accepts.
    ///
    /// Stated here rather than read off `clap` so the matrix can name a harness
    /// without building a command; `tests::every_harness_token_matches_its_clap_spelling`
    /// is what keeps the two from drifting.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Harness::ClaudeCode => "claude-code",
            Harness::ExitCode => "exit-code",
        }
    }
}

/// The normalized hook envelope — the shape the core adjudicates, whatever the
/// host called its fields.
///
/// Deliberately three fields and no more for now. A `session` id was described
/// here before it existed; anything keyed on one would have to degrade to
/// per-invocation anyway, since some harnesses expose two and some events none.
/// A `cwd` is the gap that bites: without it a path operand cannot be resolved
/// against the repo root, so an absolute path is compared as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// The lifecycle event, e.g. `PreToolUse`.
    pub event: String,
    /// The tool being mediated, e.g. `Bash`.
    pub tool: String,
    /// The command text for shell-shaped tools; empty when the tool has none.
    pub command: String,
}

/// The adjudication verdict. `Deny` carries the reason, which by the refusal
/// contract (CLOUD-122) names the redirect — the exact command to run instead —
/// and the bypass hatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Let the mediated call proceed.
    Allow,
    /// Block the mediated call, with an actionable reason.
    Deny(String),
}

/// Decode a harness payload into the normalized envelope.
///
/// Fail-open by returning `None` for anything that does not decode: absent
/// fields are an allow, never an error. Claude Code's `PreToolUse` shape is
/// `{hook_event_name, tool_name, tool_input: {command, …}, …}`.
#[must_use]
pub fn decode(harness: Harness, raw: &str) -> Option<Envelope> {
    match harness {
        Harness::ClaudeCode | Harness::ExitCode => {
            let value: Value = serde_json::from_str(raw).ok()?;
            let command = value
                .pointer("/tool_input/command")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            Some(Envelope {
                event: value
                    .get("hook_event_name")
                    .and_then(Value::as_str)
                    .unwrap_or("PreToolUse")
                    .to_owned(),
                tool: value
                    .get("tool_name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                command,
            })
        }
    }
}

/// The escape hatch, named once so the boundary and the reason text agree.
pub const BYPASS_ENV: &str = "BATTEN_GH_GUARD_BYPASS";

/// The mediated-call policy this run adjudicates against.
///
/// Built from the *resolved* config (§8), not the committed file alone, so a
/// `batten.local.toml` that **adds** a shape row is a gate the hook actually
/// applies — the raise-only override model is worth nothing at a surface that
/// ignores it — and `--config-from` is inherited for free.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    shapes: Vec<Rule>,
    fail_on_warning: bool,
    /// Which programs change the world, and what to run instead (CLOUD-36).
    verbs: Vec<MutatingVerb>,
    /// Which paths are guarded (CLOUD-37).
    ///
    /// Crossed with `verbs` this is CLOUD-96's gate. It is a *derived* predicate
    /// rather than `[[rule]]` rows because the two tables are sets: expressing
    /// the cross product as rules would need one row per verb × path pair, and
    /// the config would restate what an intersection already says.
    protected: PathSet,
}

impl Policy {
    /// The policy that denies nothing.
    ///
    /// Not an error state: a repository with no authority, or a bypassed run, has
    /// declared no mediated-call policy, and "nothing declared" means "nothing
    /// denied". Mirrors `Config::declaring_nothing`.
    #[must_use]
    pub fn declaring_nothing() -> Policy {
        Policy {
            shapes: Vec::new(),
            fail_on_warning: false,
            verbs: Vec::new(),
            protected: PathSet::empty(),
        }
    }

    /// Take the mediated-call rules out of a resolved config.
    ///
    /// Filters on `scope`, so the tree engine's rules are simply absent here
    /// rather than skipped per-call, and a spawning kind can never reach this
    /// surface — [`RuleKind::scopes`] pairs every spawning kind with
    /// [`RuleScope::Tree`] alone, which is what keeps `hook` structurally unable
    /// to execute a configured command.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) when the protected list is malformed
    /// — a `!` entry in an include-only key. Never a deny: a policy that cannot be
    /// read must fail loud, not refuse the call.
    pub fn from_resolved(resolved: &Resolved) -> anyhow::Result<Policy> {
        Ok(Policy {
            shapes: resolved
                .rules
                .iter()
                .filter(|rule| rule.scope == RuleScope::MediatedCall)
                .cloned()
                .collect(),
            fail_on_warning: resolved.fail_on_warning,
            verbs: resolved.verbs.clone(),
            protected: PathSet::includes("protected", &resolved.protected)?,
        })
    }

    /// Whether this policy can deny anything at all.
    ///
    /// Both halves must be empty. The protected gate needs *both* its tables to
    /// bite, so a repository declaring verbs but no protected paths (or the
    /// reverse) can deny nothing through it — but a shape row alone still can.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.shapes.is_empty() && (self.verbs.is_empty() || self.protected.is_empty())
    }
}

/// Adjudicate an envelope against the policy.
///
/// Pure: no I/O, no environment, no clock. `bypass` is the caller-resolved
/// escape hatch (the boundary reads [`BYPASS_ENV`]), and the policy arrives as a
/// value, so every verdict is a function of config plus argv and nothing else.
#[must_use]
pub fn adjudicate(policy: &Policy, envelope: &Envelope, bypass: bool) -> Decision {
    if bypass || envelope.command.is_empty() || policy.is_empty() {
        return Decision::Allow;
    }
    // Explicit rows first, then the derived gate: a row a reviewer wrote by hand
    // should be the one they see quoted back, and its reason is more specific
    // than the generic protected-path message.
    match shape_rules(policy, &envelope.command) {
        Decision::Deny(reason) => Decision::Deny(reason),
        Decision::Allow => protected_mutation(policy, &envelope.command),
    }
}

/// The first shape row that matches the mediated command, in declaration order.
///
/// Declaration order is the tie-break rather than "most specific wins": a
/// reviewer reads the table top to bottom, and any cleverer precedence would be
/// a rule about rules that the config does not state.
fn shape_rules(policy: &Policy, command: &str) -> Decision {
    for segment in segments(command) {
        let tokens: Vec<&str> = segment.words.iter().map(String::as_str).collect();
        let Some(program_index) = effective_program(&tokens) else {
            continue;
        };
        // Subcommand words with flags dropped. A value-taking flag leaves its
        // value behind, but the blocked words are adjacent, so that never hides
        // a real match (`gh -R o/r pr merge` still matches; `gh pr view
        // merge-fix` never does).
        let words: Vec<&str> = tokens[program_index + 1..]
            .iter()
            .copied()
            .filter(|token| !token.starts_with('-'))
            .collect();
        for rule in &policy.shapes {
            if !blocks(rule.severity, policy.fail_on_warning) {
                continue;
            }
            let Some((program, wanted)) = rule.shape() else {
                continue;
            };
            if tokens[program_index] != program {
                continue;
            }
            if !words
                .windows(wanted.len().max(1))
                .any(|w| w == wanted.as_slice())
            {
                continue;
            }
            // The extra literal is matched against the segment as written,
            // because the thing it looks for lives inside a quoted argument and
            // so is not one of the words above.
            if let Some(needle) = rule.contains.as_deref() {
                if !segment.raw.contains(needle) {
                    continue;
                }
            }
            return Decision::Deny(deny_reason(rule));
        }
    }
    Decision::Allow
}

/// The id the derived protected-path gate denies under.
///
/// It has no `[[rule]]` row to name — the gate is an intersection of two config
/// tables, not a row — so the id is declared once here and used by both the
/// refusal and its tests, which is what stops the two from drifting.
pub const PROTECTED_MUTATION: &str = "protected-mutation";

/// The pseudo-programs a shell redirect is reported as.
///
/// A truncating redirect mutates a file with no program to classify: in
/// `cat x > p` the program is `cat`, which mutates nothing. So the operator is
/// surfaced *as if* it were a program, and a consumer that wants truncation
/// gated declares `verb = ">"` in `[[verb]]` like any other.
///
/// Declared as a constant because it is a crate↔config contract: a consumer
/// writing `verb = "redirect"` would get silence, and nothing else in the tree
/// would say why. `tests::the_redirect_pseudo_program_token_is_declared_not_implied`
/// is the gate.
pub const REDIRECT_VERBS: &[&str] = &[">", ">>"];

/// Deny a declared mutating verb aimed at a protected path (CLOUD-96).
///
/// The predicate is an intersection and nothing more: `{program ∈ [[verb]]} ×
/// {path ∈ protected}`. Both tables are the consumer's, so the crate holds no
/// path literal and no verb name (`tests::the_source_bakes_in_no_protected_path`).
fn protected_mutation(policy: &Policy, command: &str) -> Decision {
    for segment in segments(command) {
        let tokens: Vec<&str> = segment.words.iter().map(String::as_str).collect();
        // Operands of the effective program, plus any redirect target. Both are
        // candidates; a redirect needs no program at all.
        let mut candidates: Vec<(&str, &str)> = Vec::new();
        if let Some(index) = effective_program(&tokens) {
            let program = tokens[index];
            for operand in operands(&tokens, index + 1) {
                candidates.push((program, operand));
            }
        }
        candidates.extend(redirect_targets(&tokens));

        for (program, path) in candidates {
            let Some(verb) = crate::verbs::classify(&policy.verbs, program) else {
                continue;
            };
            if !policy.protected.contains(normalise(path)) {
                continue;
            }
            return Decision::Deny(protected_reason(program, path, verb));
        }
    }
    Decision::Allow
}

/// The non-flag, non-env operands of a segment, from `start`.
///
/// A `--` ends option parsing, and everything after it is an operand even if it
/// begins with a dash — the shape `rm -- -weird-name` uses, which a naive flag
/// filter would drop and so fail to guard.
fn operands<'a>(tokens: &[&'a str], start: usize) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut literal = false;
    for token in tokens.iter().skip(start) {
        if !literal && *token == "--" {
            literal = true;
            continue;
        }
        if !literal && (token.starts_with('-') || is_env_assignment(token)) {
            continue;
        }
        if REDIRECT_VERBS.iter().any(|op| token.starts_with(op)) {
            continue;
        }
        out.push(*token);
    }
    out
}

/// The `(operator, target)` pairs a segment's shell redirects name.
///
/// Handles the glued form (`>p`) and the separated one (`> p`), and normalises a
/// numbered descriptor (`2>p`). **Not** `&>`: [`segments`] splits on an unquoted
/// `&`, so that form never arrives here as one token — the `> p` remainder
/// becomes its own segment and is caught there instead.
fn redirect_targets<'a>(tokens: &[&'a str]) -> Vec<(&'static str, &'a str)> {
    let mut out = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        // A leading descriptor is shell syntax, not part of the operator.
        let bare = token.trim_start_matches(|c: char| c.is_ascii_digit());
        // Longest first, so `>>` is never read as `>` with a stray `>` target.
        let Some(op) = REDIRECT_VERBS
            .iter()
            .find(|op| bare.starts_with(**op))
            .copied()
        else {
            continue;
        };
        let target = bare.trim_start_matches('>').trim();
        if target.is_empty() {
            if let Some(next) = tokens.get(index + 1) {
                out.push((op, *next));
            }
        } else {
            out.push((op, target));
        }
    }
    out
}

/// Strip a leading `./`, which names the same path.
///
/// Deliberately the *only* normalisation. An absolute path, a `..` traversal, or
/// a `~` are not resolved against the repo root — `Envelope` carries no `cwd`, so
/// there is nothing honest to resolve against. Every such miss under-denies,
/// which is the sanctioned direction, and
/// `tests::an_absolute_path_is_not_resolved_against_the_repo_root` pins the limit
/// so it cannot change silently.
fn normalise(path: &str) -> &str {
    path.strip_prefix("./").unwrap_or(path)
}

/// Compose the protected-path refusal: what was aimed where, and what to run.
///
/// The path is a *pointer* and rule 4 permits it — it is what the caller already
/// typed, and naming it is the difference between an actionable refusal and a
/// riddle. The file's contents never appear.
fn protected_reason(program: &str, path: &str, verb: &MutatingVerb) -> String {
    let mutation = verb
        .redirect
        .as_deref()
        .unwrap_or("change it through the surface that owns it, or restore it with git");
    format!(
        "Refused by {PROTECTED_MUTATION}: `{program}` targets the protected path \
         {path} — {mutation}. Bypass with {BYPASS_ENV}=1."
    )
}

/// Whether a rule at this severity blocks, once promotion has been applied.
///
/// Routed through [`severity`] rather than matched here, so `allow` / `warn` /
/// `deny` mean the same thing at the mediation channel as in the checks
/// pipeline. One interpretation, two surfaces.
fn blocks(severity: RuleSeverity, fail_on_warning: bool) -> bool {
    severity::promote(severity::row_for_rule(severity).report, fail_on_warning) == ReportLevel::Fail
}

/// Compose a deny reason: the rule that refused, why, and where the policy lives.
///
/// Pointer-only (rule 4) — it names the rule and the fix, never the mediated
/// command, which is the caller's own text and could carry anything.
fn deny_reason(rule: &Rule) -> String {
    let mut reason = format!(
        "Refused by {}: {}",
        rule.id,
        rule.reason.as_deref().unwrap_or("policy")
    );
    if let Some(url) = rule.policy_url.as_deref() {
        reason.push_str(" See ");
        reason.push_str(url);
        reason.push('.');
    }
    reason.push_str(" Bypass with ");
    reason.push_str(BYPASS_ENV);
    reason.push_str("=1.");
    reason
}

/// One shell-separated span of a mediated command, in the two forms policy needs.
///
/// `words` is the span split into arguments with quoting resolved, so a quoted
/// operand survives as a single **word** rather than being thrown away. `raw` is
/// the same span exactly as written, for the one kind of predicate that must
/// look *inside* a quoted span.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Segment {
    /// The span's arguments, quotes resolved and escapes applied.
    words: Vec<String>,
    /// The span exactly as written, quotes and all.
    raw: String,
}

/// Split a command into shell-separated segments, resolving quotes as we go.
///
/// The earlier version replaced each quoted span with the literal sentinel
/// `QUOTED`. That got the `gh` policy right — `git commit -m "gh pr merge"` must
/// not read as an invocation — but it discarded the span's *contents*, so a path
/// gate could not see `rm "some/guarded path"` at all: the operand had become
/// the word `QUOTED`. Quoting a path is the ordinary way to write one with a
/// space in it, so that hole is the shape of a common, legitimate spelling
/// rather than an adversarial one (CLOUD-269, the same class as CLOUD-181).
///
/// Keeping the span as one word preserves every verdict the sentinel bought: a
/// quoted `gh pr merge` is a single word, and one word never equals the adjacent
/// pair the policy matches on. It tightens exactly one case — `gh "pr" "merge"`,
/// a real invocation, now denies.
///
/// **Bounds, deliberate.** This is a pre-execution textual gate, not a shell:
/// variable expansion, command substitution, and globbing all hide operands from
/// it, and nothing here pretends otherwise. Every such miss under-denies, which
/// is the sanctioned direction. An unterminated quote runs to the end of the
/// command and keeps its tail as one word.
fn segments(command: &str) -> Vec<Segment> {
    let mut out: Vec<Segment> = Vec::new();
    let mut words: Vec<String> = Vec::new();
    let mut word = String::new();
    let mut has_word = false;
    let mut raw = String::new();
    let mut chars = command.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '\'' | '"' => {
                let quote = c;
                raw.push(c);
                // An empty `""` is still an argument, so the word exists the
                // moment the quote opens.
                has_word = true;
                while let Some(inner) = chars.next() {
                    raw.push(inner);
                    if inner == quote {
                        break;
                    }
                    // Inside single quotes a backslash is literal; inside double
                    // quotes it escapes only this handful. Written without a
                    // let-chain: those are unstable at the crate's 1.85 MSRV,
                    // and a newer local toolchain compiles them happily while
                    // `cross-check` does not.
                    if quote == '"'
                        && inner == '\\'
                        && chars
                            .peek()
                            .is_some_and(|next| matches!(*next, '"' | '\\' | '$' | '`'))
                    {
                        if let Some(next) = chars.next() {
                            raw.push(next);
                            word.push(next);
                        }
                        continue;
                    }
                    word.push(inner);
                }
            }
            '\\' => {
                raw.push(c);
                if let Some(next) = chars.next() {
                    raw.push(next);
                    word.push(next);
                    has_word = true;
                }
            }
            '&' | '|' | ';' => {
                // `&&` and `||` are one separator, not two.
                if (c == '&' || c == '|') && chars.peek() == Some(&c) {
                    chars.next();
                }
                if has_word {
                    words.push(std::mem::take(&mut word));
                    has_word = false;
                }
                if !words.is_empty() {
                    out.push(Segment {
                        words: std::mem::take(&mut words),
                        raw: raw.trim().to_owned(),
                    });
                }
                raw.clear();
            }
            c if c.is_whitespace() => {
                raw.push(c);
                if has_word {
                    words.push(std::mem::take(&mut word));
                    has_word = false;
                }
            }
            _ => {
                raw.push(c);
                word.push(c);
                has_word = true;
            }
        }
    }
    if has_word {
        words.push(word);
    }
    if !words.is_empty() {
        out.push(Segment {
            words,
            raw: raw.trim().to_owned(),
        });
    }
    out
}

/// Find the index of the effective program in a segment's tokens: skip
/// `VAR=value` env prefixes, then look through known wrapper programs so the
/// wrapped program is judged, not the wrapper. Known wrappers only; anything
/// unrecognised keeps the fail-open posture.
fn effective_program(tokens: &[&str]) -> Option<usize> {
    let mut i = 0;
    while i < tokens.len() && is_env_assignment(tokens[i]) {
        i += 1;
    }
    loop {
        match *tokens.get(i)? {
            "env" | "command" | "nice" | "stdbuf" | "timeout" | "xargs" | "sudo" | "doas" => {
                i += 1;
                // The wrapper's own flags, env assignments, and bare numeric
                // arguments (timeout's duration) precede the wrapped program.
                while i < tokens.len()
                    && (tokens[i].starts_with('-')
                        || is_env_assignment(tokens[i])
                        || tokens[i].starts_with(|c: char| c.is_ascii_digit()))
                {
                    i += 1;
                }
            }
            "mise" => {
                // Only `mise exec` / `mise x` run another program; `mise run`
                // names a task, which is the sanctioned surface.
                match tokens.get(i + 1) {
                    Some(&("exec" | "x")) => {
                        i += 2;
                        // Tool pins (node@22), flags, and the `--` separator
                        // precede the program.
                        while i < tokens.len()
                            && (tokens[i].starts_with('-') || tokens[i].contains('@'))
                        {
                            i += 1;
                        }
                    }
                    _ => return Some(i),
                }
            }
            _ => return Some(i),
        }
    }
}

fn is_env_assignment(token: &str) -> bool {
    let mut chars = token.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && token
            .chars()
            .take_while(|&c| c != '=')
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
        && token.contains('=')
}

/// Claude Code's deny payload: the `hookSpecificOutput.permissionDecision`
/// object the host reads from stdout. Field order is struct order, so the
/// emission is byte-stable.
#[derive(Serialize)]
struct ClaudeDeny<'a> {
    #[serde(rename = "hookSpecificOutput")]
    hook_specific_output: ClaudeDenyInner<'a>,
}

#[derive(Serialize)]
struct ClaudeDenyInner<'a> {
    #[serde(rename = "hookEventName")]
    hook_event_name: &'a str,
    #[serde(rename = "permissionDecision")]
    permission_decision: &'a str,
    #[serde(rename = "permissionDecisionReason")]
    permission_decision_reason: &'a str,
}

/// Encode a deny for the Claude Code adapter.
///
/// # Errors
///
/// Serialization of this fixed shape cannot practically fail; the `Result` is
/// the honest signature for a serde boundary.
pub fn encode_claude_deny(event: &str, reason: &str) -> serde_json::Result<String> {
    serde_json::to_string(&ClaudeDeny {
        hook_specific_output: ClaudeDenyInner {
            hook_event_name: event,
            permission_decision: "deny",
            permission_decision_reason: reason,
        },
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn shape(id: &str, pattern: &str, contains: Option<&str>) -> Rule {
        Rule {
            id: id.to_owned(),
            kind: crate::rules::RuleKind::Shape,
            glob: None,
            severity: RuleSeverity::Deny,
            scope: RuleScope::MediatedCall,
            pattern: Some(pattern.to_owned()),
            contains: contains.map(ToOwned::to_owned),
            reason: Some(format!("use the sanctioned path for {id}")),
            policy_url: None,
            run: None,
        }
    }

    /// The `gh` lifecycle table as config, standing in for the rows this repo's
    /// own `batten.toml` now carries. The policy left the crate in CLOUD-48, so
    /// these tests supply it rather than assert against a baked-in table.
    fn verb(name: &str, redirect: Option<&str>) -> MutatingVerb {
        MutatingVerb {
            verb: name.to_owned(),
            effect: crate::effect::Effect::Destructive,
            redirect: redirect.map(ToOwned::to_owned),
        }
    }

    /// A policy with the CLOUD-96 cross product declared: two mutating verbs and
    /// one protected glob. Both tables are the consumer's, so a test supplies
    /// them exactly as a `batten.toml` would.
    fn protected_policy(verbs: Vec<MutatingVerb>) -> Policy {
        Policy {
            shapes: Vec::new(),
            fail_on_warning: false,
            verbs,
            protected: PathSet::includes(
                "protected",
                &[".serena/memories/**".to_owned(), "batten.toml".to_owned()],
            )
            .expect("the fixture protected set is well formed"),
        }
    }

    fn guarded(command: &str) -> Decision {
        adjudicate(
            &protected_policy(vec![
                verb("rm", Some("restore it with git")),
                verb("mv", None),
                verb(">", Some("write through the surface that owns it")),
            ]),
            &envelope(command),
            false,
        )
    }

    fn gh_policy() -> Policy {
        Policy {
            verbs: Vec::new(),
            protected: PathSet::empty(),
            shapes: vec![
                shape("gh-pr-merge", "gh pr merge", None),
                shape(
                    "gh-pr-comment-fast-forward",
                    "gh pr comment",
                    Some("fast-forward"),
                ),
                shape("gh-pr-checks", "gh pr checks", None),
                shape("gh-run-watch", "gh run watch", None),
            ],
            fail_on_warning: false,
        }
    }

    fn envelope(command: &str) -> Envelope {
        Envelope {
            event: "PreToolUse".to_owned(),
            tool: "Bash".to_owned(),
            command: command.to_owned(),
        }
    }

    fn adjudicate_command(command: &str) -> Decision {
        adjudicate(&gh_policy(), &envelope(command), false)
    }

    fn is_deny(command: &str) -> bool {
        matches!(adjudicate_command(command), Decision::Deny(_))
    }

    #[test]
    fn blocked_shapes_are_denied() {
        assert!(is_deny("gh pr merge 42"));
        assert!(is_deny("gh pr checks --watch"));
        assert!(is_deny("gh run watch 123"));
        assert!(is_deny("gh pr comment 7 --body /fast-forward"));
    }

    #[test]
    fn wrapper_lookthrough_judges_the_effective_program() {
        // The web-sandbox shape: the wrapper form is the only working form, so
        // a guard that stops at the wrapper token sees none of the calls that
        // matter (CLOUD-181).
        assert!(is_deny("mise exec -- gh pr merge 42"));
        assert!(is_deny("env GH_PAGER= gh pr merge"));
        assert!(is_deny("timeout 30 gh pr checks"));
        assert!(is_deny("FOO=bar gh pr merge"));
    }

    #[test]
    fn interposed_flag_values_do_not_hide_a_match() {
        assert!(is_deny("gh -R owner/repo pr merge"));
    }

    #[test]
    fn reads_and_lookalikes_are_allowed() {
        assert!(!is_deny("gh pr view 42"));
        assert!(!is_deny("gh pr ready 42"));
        assert!(!is_deny("gh pr view merge-fix"));
        assert!(!is_deny("gh api repos/o/r/pulls"));
        assert!(!is_deny("mise run land"));
        assert!(!is_deny("gh pr comment 7 --body thanks"));
    }

    #[test]
    fn quoted_spans_are_not_commands() {
        assert!(!is_deny("git commit -m \"gh pr merge\""));
        assert!(!is_deny("echo 'gh run watch'"));
    }

    #[test]
    fn words_survive_quoting_while_a_quoted_span_is_never_a_command() {
        // Both halves of CLOUD-269 in one assertion pair. The span stays a
        // single WORD — so a path gate can read it, which the `QUOTED` sentinel
        // made impossible — and being one word is also exactly why it still
        // cannot match the adjacent pair the policy looks for.
        let parsed = segments("git commit -m \"gh pr merge\"");
        assert_eq!(parsed.len(), 1);
        assert_eq!(
            parsed[0].words,
            ["git", "commit", "-m", "gh pr merge"],
            "the quoted span is one word, contents intact"
        );
        assert!(!is_deny("git commit -m \"gh pr merge\""));
    }

    #[test]
    fn a_quoted_separator_does_not_split_a_segment() {
        let parsed = segments("echo \"x; gh pr merge\"");
        assert_eq!(parsed.len(), 1, "the `;` is inside quotes");
        assert_eq!(parsed[0].words, ["echo", "x; gh pr merge"]);
        assert!(!is_deny("echo \"x; gh pr merge\""));
    }

    #[test]
    fn a_quoted_operand_keeps_its_contents_for_a_path_gate() {
        // The case the sentinel form could not see at all: under `QUOTED` this
        // command carried no path token, so a protected-path gate had nothing
        // to match (CLOUD-96).
        let parsed = segments("rm \".serena/memories/x.md\"");
        assert_eq!(parsed[0].words, ["rm", ".serena/memories/x.md"]);
    }

    #[test]
    fn a_backslash_escape_keeps_one_word() {
        let parsed = segments("rm foo\\ bar.md");
        assert_eq!(parsed[0].words, ["rm", "foo bar.md"]);
    }

    #[test]
    fn a_quoted_invocation_is_still_an_invocation() {
        // The one intended tightening: a real `gh pr merge`, spelled with
        // quotes, that the sentinel form allowed through.
        assert!(is_deny("gh \"pr\" \"merge\""));
    }

    #[test]
    fn the_raw_text_is_scoped_to_its_own_segment() {
        // The directive predicate reads raw text because the directive lives
        // inside a quoted `--body`. Scoping it to the segment is what stops an
        // unrelated earlier mention from making a later comment look like the
        // landing directive.
        assert!(is_deny("gh pr comment 7 --body /fast-forward"));
        assert!(!is_deny(
            "echo fast-forward && gh pr comment 7 --body thanks"
        ));
    }

    #[test]
    fn an_unterminated_quote_keeps_its_tail_as_one_word() {
        let parsed = segments("rm \"unclosed path");
        assert_eq!(parsed[0].words, ["rm", "unclosed path"]);
    }

    #[test]
    fn a_denied_shape_in_any_segment_is_a_deny() {
        assert!(is_deny("git push && gh pr merge 42"));
    }

    #[test]
    fn bypass_allows_everything() {
        assert_eq!(
            adjudicate(&gh_policy(), &envelope("gh pr merge"), true),
            Decision::Allow
        );
    }

    #[test]
    fn decode_reads_the_claude_payload() {
        let raw = r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"gh pr merge"}}"#;
        let envelope = decode(Harness::ClaudeCode, raw).expect("decodes");
        assert_eq!(envelope.command, "gh pr merge");
        assert_eq!(envelope.tool, "Bash");
    }

    #[test]
    fn decode_fails_open_on_junk() {
        assert_eq!(decode(Harness::ClaudeCode, "not json"), None);
        // A payload with no command decodes to an empty command, which
        // adjudicates to Allow rather than erroring.
        let envelope = decode(Harness::ClaudeCode, "{}").expect("decodes");
        assert_eq!(adjudicate(&gh_policy(), &envelope, false), Decision::Allow);
    }

    #[test]
    fn an_empty_policy_denies_nothing() {
        // The default state, and the one most invocations are in: `hook` is
        // registered once and mediates calls in directories that declare no
        // policy at all.
        assert_eq!(
            adjudicate(
                &Policy::declaring_nothing(),
                &envelope("gh pr merge 42"),
                false
            ),
            Decision::Allow
        );
    }

    #[test]
    fn the_deny_names_the_rule_and_its_reason() {
        // Acceptance (c). The id is what a reviewer greps for in `batten.toml`;
        // the reason is what the model acts on.
        let Decision::Deny(reason) = adjudicate_command("gh pr merge 42") else {
            panic!("a configured shape must deny");
        };
        assert!(reason.contains("gh-pr-merge"), "names the rule: {reason}");
        assert!(reason.contains("sanctioned path"), "names why: {reason}");
        assert!(reason.contains(BYPASS_ENV), "names the hatch: {reason}");
    }

    #[test]
    fn the_deny_never_echoes_the_mediated_command() {
        // Rule 4 at the mediation channel. The command is the caller's own text
        // and can carry anything — a token, a path, a customer name — so a deny
        // names the policy that refused, never the thing refused.
        let secret = "gh pr merge --repo o/r-SENTINEL-9f3a";
        let Decision::Deny(reason) = adjudicate_command(secret) else {
            panic!("a configured shape must deny");
        };
        assert!(
            !reason.contains("SENTINEL"),
            "the deny echoed the mediated command: {reason}"
        );
    }

    #[test]
    fn a_shape_rule_at_allow_is_configured_off() {
        // `allow` is cargo-deny's "this rule is off", and it must mean the same
        // thing here as in the checks pipeline — that is what routing through
        // `severity::promote` buys.
        let mut rule = shape("gh-pr-merge", "gh pr merge", None);
        rule.severity = RuleSeverity::Allow;
        let policy = Policy {
            shapes: vec![rule],
            fail_on_warning: false,
            verbs: Vec::new(),
            protected: PathSet::empty(),
        };
        assert_eq!(
            adjudicate(&policy, &envelope("gh pr merge 42"), false),
            Decision::Allow
        );
    }

    #[test]
    fn a_warn_shape_rule_blocks_only_once_promotion_is_on() {
        let mut rule = shape("gh-pr-merge", "gh pr merge", None);
        rule.severity = RuleSeverity::Warn;
        let call = envelope("gh pr merge 42");

        let advisory = Policy {
            shapes: vec![rule.clone()],
            fail_on_warning: false,
            verbs: Vec::new(),
            protected: PathSet::empty(),
        };
        assert_eq!(
            adjudicate(&advisory, &call, false),
            Decision::Allow,
            "a warn row does not block a mediated call on its own"
        );

        let promoted = Policy {
            shapes: vec![rule],
            fail_on_warning: true,
            verbs: Vec::new(),
            protected: PathSet::empty(),
        };
        assert!(
            matches!(adjudicate(&promoted, &call, false), Decision::Deny(_)),
            "promotion applies at the mediation channel too"
        );
    }

    #[test]
    fn the_first_matching_row_wins_in_declaration_order() {
        // Declaration order, not "most specific": a reviewer reads the table top
        // to bottom, and any cleverer precedence would be a rule about rules the
        // config never states.
        let policy = Policy {
            shapes: vec![
                shape("first", "gh pr merge", None),
                shape("second", "gh pr merge", None),
            ],
            fail_on_warning: false,
            verbs: Vec::new(),
            protected: PathSet::empty(),
        };
        let Decision::Deny(reason) = adjudicate(&policy, &envelope("gh pr merge"), false) else {
            panic!("must deny");
        };
        assert!(reason.contains("first"), "got: {reason}");
    }

    #[test]
    fn an_extra_literal_condition_is_matched_against_the_command_as_written() {
        // `contains` exists for exactly this pair: the directive lives inside a
        // quoted argument, so it is not one of the words the shape matches.
        assert!(matches!(
            adjudicate_command("gh pr comment 7 --body /fast-forward"),
            Decision::Deny(_)
        ));
        assert_eq!(
            adjudicate_command("gh pr comment 7 --body thanks"),
            Decision::Allow,
            "an ordinary comment is not the lifecycle"
        );
    }

    #[test]
    fn a_policy_url_rides_the_deny_when_declared() {
        let mut rule = shape("gh-pr-merge", "gh pr merge", None);
        rule.policy_url = Some("https://example.invalid/policy".to_owned());
        let policy = Policy {
            shapes: vec![rule],
            fail_on_warning: false,
            verbs: Vec::new(),
            protected: PathSet::empty(),
        };
        let Decision::Deny(reason) = adjudicate(&policy, &envelope("gh pr merge"), false) else {
            panic!("must deny");
        };
        assert!(reason.contains("example.invalid/policy"), "got: {reason}");
    }

    #[test]
    fn a_mutating_verb_against_a_protected_path_is_denied() {
        // The incident this gate is written from: an agent reaching for `rm` on
        // its own managed state instead of the surface that owns it.
        assert!(matches!(
            guarded("rm .serena/memories/core.md"),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn the_same_verb_against_an_unprotected_path_is_allowed() {
        assert_eq!(guarded("rm target/debug/scratch"), Decision::Allow);
    }

    #[test]
    fn every_operand_is_a_candidate_so_a_destination_is_guarded_too() {
        // `mv` overwrites its destination, so guarding only the source would miss
        // the direction that destroys the protected file.
        assert!(matches!(
            guarded("mv notes.md batten.toml"),
            Decision::Deny(_)
        ));
        assert!(matches!(
            guarded("mv batten.toml notes.md"),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn a_redirect_target_is_a_mutation_even_with_no_program() {
        // A truncating redirect has no mutating program to classify — in
        // `cat x > p` the program is `cat` — so the operator is surfaced as a
        // pseudo-program the consumer declares like any other verb.
        for command in [
            "cat notes.md > batten.toml",
            "cat notes.md >batten.toml",
            "echo x >> batten.toml",
            "cat notes.md 2>batten.toml",
        ] {
            assert!(
                matches!(guarded(command), Decision::Deny(_)),
                "must deny: {command}"
            );
        }
    }

    #[test]
    fn an_undeclared_program_against_a_protected_path_is_allowed() {
        // The table is the authority on what mutates. `cat` reads, so it is not
        // this gate's business even against a protected path — the conservative
        // reading of an unknown program belongs to the consumer's config, not to
        // a guess here.
        assert_eq!(guarded("cat .serena/memories/core.md"), Decision::Allow);
    }

    #[test]
    fn the_deny_names_the_sanctioned_mutation_declared_beside_the_verb() {
        let Decision::Deny(reason) = guarded("rm .serena/memories/core.md") else {
            panic!("must deny");
        };
        assert!(
            reason.contains(PROTECTED_MUTATION),
            "names the gate: {reason}"
        );
        assert!(
            reason.contains("restore it with git"),
            "names the fix: {reason}"
        );
        assert!(
            reason.contains(".serena/memories/core.md"),
            "names where: {reason}"
        );
    }

    #[test]
    fn a_verb_with_no_redirect_names_a_fallback_rather_than_nothing() {
        // `redirect` is optional on a verb, so the refusal must still say
        // something actionable — CLOUD-280 is the per-path-class version.
        let Decision::Deny(reason) = guarded("mv batten.toml elsewhere") else {
            panic!("must deny");
        };
        assert!(reason.contains("surface that owns it"), "got: {reason}");
    }

    #[test]
    fn flags_are_never_treated_as_paths() {
        // And `--` ends option parsing, so a dash-leading operand after it is
        // still an operand — the shape `rm -- -weird` uses.
        assert_eq!(guarded("rm -rf target"), Decision::Allow);
        assert!(matches!(guarded("rm -- batten.toml"), Decision::Deny(_)));
    }

    #[test]
    fn a_leading_dot_slash_is_the_same_path() {
        assert!(matches!(guarded("rm ./batten.toml"), Decision::Deny(_)));
    }

    #[test]
    fn an_absolute_path_is_not_resolved_against_the_repo_root() {
        // A stated limit, pinned so it cannot change silently. `Envelope` carries
        // no `cwd`, so there is nothing honest to resolve against; this
        // under-denies, which is the sanctioned direction.
        assert_eq!(guarded("rm /home/user/batten/batten.toml"), Decision::Allow);
    }

    #[test]
    fn a_quoted_protected_path_is_still_guarded() {
        // The whole reason CLOUD-269 landed first: under the old sentinel parser
        // this command carried no path token at all.
        assert!(matches!(
            guarded("rm \".serena/memories/core.md\""),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn the_protected_gate_denies_nothing_when_either_table_is_empty() {
        // The cross product needs both halves. A repository declaring verbs but
        // no protected paths — or the reverse — has declared no gate.
        let no_verbs = protected_policy(Vec::new());
        assert_eq!(
            adjudicate(&no_verbs, &envelope("rm batten.toml"), false),
            Decision::Allow
        );
        let no_paths = Policy {
            shapes: Vec::new(),
            fail_on_warning: false,
            verbs: vec![verb("rm", None)],
            protected: PathSet::empty(),
        };
        assert_eq!(
            adjudicate(&no_paths, &envelope("rm batten.toml"), false),
            Decision::Allow
        );
    }

    #[test]
    fn an_explicit_row_wins_over_the_derived_protected_gate() {
        // A row a reviewer wrote by hand carries a more specific reason than the
        // generic protected-path message, so it should be the one quoted back.
        let mut policy = protected_policy(vec![verb("rm", Some("restore it with git"))]);
        policy.shapes = vec![shape("no-rm-memories", "rm .serena/memories/core.md", None)];
        let Decision::Deny(reason) =
            adjudicate(&policy, &envelope("rm .serena/memories/core.md"), false)
        else {
            panic!("must deny");
        };
        assert!(reason.contains("no-rm-memories"), "got: {reason}");
    }

    #[test]
    fn the_protected_gate_honours_the_bypass_hatch() {
        assert_eq!(
            adjudicate(
                &protected_policy(vec![verb("rm", None)]),
                &envelope("rm batten.toml"),
                true
            ),
            Decision::Allow
        );
    }

    #[test]
    fn the_redirect_pseudo_program_token_is_declared_not_implied() {
        // The crate↔config contract: a consumer declaring `verb = "redirect"`
        // would get silence, and nothing would say why. Naming the tokens here
        // is what makes the contract greppable.
        assert!(REDIRECT_VERBS.contains(&">"));
        assert!(REDIRECT_VERBS.contains(&">>"));
    }

    #[test]
    fn the_source_bakes_in_no_protected_path() {
        // Acceptance (d), in the `verbs::the_source_bakes_in_no_verb` idiom. The
        // literals are assembled so this test's own prose is not a match.
        //
        // Asserted behaviourally rather than by grepping the source. A grep is
        // what `verbs::the_source_bakes_in_no_verb` uses, and it works there
        // because a verb name is a short token. A *path* is not: the module doc
        // legitimately cites `mise-tasks/gh-guard-check` as the provenance of
        // this port, and prose examples name paths too, so a grep either fails on
        // documentation or needs an escape clause loose enough to pass always.
        // Both were tried; both were worse than the property itself.
        //
        // The property is that the set is *config*: the same command must get
        // opposite verdicts from two policies differing only in `protected`. A
        // hardcoded path could not produce that.
        let verbs = vec![verb("rm", None)];
        let guarding = Policy {
            shapes: Vec::new(),
            fail_on_warning: false,
            verbs: verbs.clone(),
            protected: PathSet::includes("protected", &["guarded/**".to_owned()])
                .expect("well formed"),
        };
        let elsewhere = Policy {
            shapes: Vec::new(),
            fail_on_warning: false,
            verbs,
            protected: PathSet::includes("protected", &["other/**".to_owned()])
                .expect("well formed"),
        };
        let call = envelope("rm guarded/thing");
        assert!(
            matches!(adjudicate(&guarding, &call, false), Decision::Deny(_)),
            "the declared set must deny"
        );
        assert_eq!(
            adjudicate(&elsewhere, &call, false),
            Decision::Allow,
            "a different declared set must allow the same command"
        );
    }

    #[test]
    fn every_harness_token_matches_its_clap_spelling() {
        // `as_str` exists so the E2E matrix can name a harness without building
        // a clap command. That is only safe while the two spellings agree, and
        // nothing else would notice if a `ValueEnum` rename left `as_str`
        // behind — the matrix would keep passing against a token the binary no
        // longer accepts.
        use clap::ValueEnum;
        for harness in Harness::ALL {
            let value = harness.to_possible_value().expect("harness is selectable");
            assert_eq!(harness.as_str(), value.get_name());
        }
    }

    #[test]
    fn the_claude_deny_shape_is_byte_stable() {
        let one = encode_claude_deny("PreToolUse", "reason").expect("serializes");
        let two = encode_claude_deny("PreToolUse", "reason").expect("serializes");
        assert_eq!(one, two);
        assert!(one.contains("\"permissionDecision\":\"deny\""));
    }
}
