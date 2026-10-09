//! What this repository's own hooks cost the session that runs them (CLOUD-417).
//!
//! # The finding this exists for
//!
//! Non-negotiable rule 4 holds every check to "a count, `path:line`, or boolean —
//! never the content itself", and each hook obeys it individually. Nobody had
//! measured them **in aggregate**, over a session, where one line that obeys the
//! rule is emitted hundreds of times and every copy stays in context forever.
//!
//! Measured on one captured transcript (758 turns, 5.83 MB): `hook_success` at
//! 1181 KB and `hook_additional_context` at 42 KB against 95 KB of edited files
//! and 88 KB of delivered memories — **hook output alone is 20% of the
//! transcript**. The single largest contributor said one true, correctly
//! pointer-shaped, identical thing on essentially every turn.
//!
//! # Why the rule was unstatable before
//!
//! The output rule is stated per-CHECK and enforced per-CHECK. There is no rule
//! about a check's output over a SESSION, so a hook that is silent by default
//! (correct) and one that confirms success every turn (also individually
//! defensible) are indistinguishable to every gate that exists. That is the same
//! shape CLOUD-896 found one layer down, where three producers each within their
//! own budget shared a channel with none — and the answer is the same: put the
//! ceiling on the aggregate, because the aggregate is what is actually spent.
//!
//! # Two predicates, and the second is most of the win
//!
//! [`Ceiling::max_tokens`] is the blunt one: hook output over a whole session has
//! a ceiling. [`Ceiling::max_repeats`] is the sharp one, and it is what makes
//! "silence on success is the default" and "a repeat is a pointer to the first,
//! not a copy" **decidable** rather than prose. A hook that says the same thing
//! every turn is byte-identical every turn, so it is exactly a digest repeated —
//! and prose asking hooks to be quiet is the feedforward this repository refuses
//! (non-negotiable rule 2).
//!
//! # Pointer-only, structurally
//!
//! Everything here is a count, a digest prefix, or a host-supplied producer name.
//! The emitted text never reaches this module: [`crate::transcript`] hashes it and
//! drops it at the parse. A measurement of an over-wide channel that itself
//! carried what the channel said would be the joke writing itself.
//!
//! # It applies to itself
//!
//! [`Reading::line`] is ONE line. The row's acceptance says so, and it is not
//! decoration: a gate about hook volume whose own report is a paragraph would be
//! the defect wearing the sensor's clothes.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::identity::{FindingKind, StoredIdentity};
use crate::rules::Finding;
use crate::severity::RuleSeverity;
use crate::transcript::{Event, Stream};

/// The `[hook_output]` table: what this repository's hooks may cost one session.
///
/// **Absent means unenforced**, on `[budget]`'s reading — a threshold nobody
/// declared is not a threshold of zero — so a consumer that has not adopted the
/// table measures exactly as it did before and refuses nothing.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Ceiling {
    /// The ceiling on estimated tokens of hook output across the whole session.
    /// The boundary is `<=`, matching `[budget]`, `[refusal]` and `[advisory]`
    /// so the four thresholds in this tree do not disagree about their own edge.
    pub max_tokens: usize,
    /// How many times one hook may emit byte-identical text in one session.
    ///
    /// **The floor is 1, not 0.** Saying a thing once is the report; saying it
    /// again is the copy. A ceiling of 0 would refuse the first emission, which
    /// is a hook switched off rather than a hook made quiet — and this row puts
    /// "removing any hook, or weakening what it detects" explicitly out of scope.
    pub max_repeats: usize,
}

/// Refuse a ceiling nothing could satisfy.
///
/// # Errors
///
/// When `max_tokens` is zero — no hook could speak at all — or when
/// `max_repeats` is zero, which refuses a hook's FIRST emission and so silences
/// the finding rather than its restatement.
pub fn validate(ceiling: Option<&Ceiling>) -> Result<(), String> {
    let Some(declared) = ceiling else {
        return Ok(());
    };
    if declared.max_tokens == 0 {
        return Err(
            "`[hook_output] max_tokens = 0` refuses every hook that speaks at all — remove the \
             table to leave hook output unbounded, or name a ceiling a session can fit inside"
                .to_owned(),
        );
    }
    if declared.max_repeats == 0 {
        return Err(
            "`[hook_output] max_repeats = 0` refuses a hook's FIRST emission, which silences the \
             finding rather than its restatement; 1 is the floor — say it once"
                .to_owned(),
        );
    }
    Ok(())
}

/// One producer's cost over the session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Cost {
    /// Estimated tokens this producer spent in total.
    pub tokens: usize,
    /// How many times it emitted anything at all.
    pub emissions: usize,
}

/// One thing said more than once.
///
/// Pointer-only: the producer's host-given name, a digest PREFIX, a count, and
/// the line the first copy landed on. Never the text, and never the full digest —
/// eight hex characters name the repeat in a report and cannot reconstruct it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Repeat {
    /// The producer, as the host named it.
    pub hook: String,
    /// The first eight hex characters of the emission's digest.
    pub digest: String,
    /// How many copies the session carried.
    pub count: usize,
    /// The transcript line the FIRST copy landed on — the pointer a repeat is
    /// supposed to be, which is the row's own remedy stated as an output field.
    pub first_line: usize,
}

/// What [`measure`] found.
///
/// Byte-stable for identical input: producers are reported in name order,
/// repeats in (producer, digest) order, and no field derives from the clock, the
/// environment, or where the repository lives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Reading {
    /// Estimated tokens of hook output over the whole session.
    pub tokens: usize,
    /// Estimated tokens of the whole transcript, the denominator that turns the
    /// number above into the row's headline share.
    pub session_tokens: usize,
    /// Per-producer costs, in producer-name order.
    pub per_hook: BTreeMap<String, Cost>,
    /// Every emission the session carried more than once, whatever the declared
    /// ceiling — the measurement is separate from the judgement, so a reading
    /// taken with no table declared still reports what a table would refuse.
    pub repeats: Vec<Repeat>,
}

impl Reading {
    /// Hook output as a percentage of the session, rounded down.
    ///
    /// **Zero when the session measured nothing**, rather than a division that
    /// cannot be performed: an empty transcript has no share, and reporting one
    /// would be an answer where there is no reading.
    #[must_use]
    pub fn share(&self) -> usize {
        if self.session_tokens == 0 {
            return 0;
        }
        self.tokens * 100 / self.session_tokens
    }

    /// The whole report, as ONE line.
    ///
    /// The row's acceptance clause, and this module's self-application: a gate
    /// about hook volume answers in the shape it demands. Counts and a share,
    /// never a producer's text — and the producers themselves are named in the
    /// findings, which is where a reader who needs one goes.
    #[must_use]
    pub fn line(&self) -> String {
        format!(
            "hook output {} token(s), {}% of {} session token(s), {} producer(s), {} repeat(s)",
            self.tokens,
            self.share(),
            self.session_tokens,
            self.per_hook.len(),
            self.repeats.len()
        )
    }
}

/// `policy hooks`' one summary line. ONE line always, which is the self-applying
/// property: a gate about hook volume whose own report grew with what it found
/// would be the defect wearing the sensor's clothes.
///
/// Forwards to [`Reading::line`] rather than restating it: CLOUD-371 unifies
/// which types may reach the data channel, never what any of them renders, so
/// the bytes here are the bytes this type already emitted.
impl crate::output::Line for Reading {
    fn line(&self) -> String {
        Reading::line(self)
    }
}

/// The rule id a session-budget finding carries.
pub const BUDGET_RULE: &str = "hook-output-budget";

/// The rule id a repeated-emission finding carries.
pub const REPEAT_RULE: &str = "hook-repeat-pointer";

/// Count what the hooks spent, from the parsed stream alone.
///
/// **No I/O and no clock**, which is what lets the second test tier run this over
/// a fixture transcript and get the same answer the live path would.
///
/// **Repeats are counted per compaction cycle** (CLOUD-2075): every
/// [`Event::SessionBoundary`] opens a new segment, because the contract is a
/// finding's full arm ONCE per cycle — so a full arm after a `SessionStart` is the
/// one copy that cycle holds, not a repeat. An emission carrying labelled
/// findings is judged per finding: a full arm counts per `(segment, key)`, and a
/// pointer arm never counts, since pointing is what a repeat is meant to do.
/// Unlabelled output keeps the `(segment, hook, digest)` key.
//MUTANT-SUITE crates/batten/src/hookcost.rs
//MUTANT segment-not-reset|s@^            segment += 1;$@            segment += 0;@|a_full_arm_after_a_session_start_is_not_a_repeat_and_a_pointer_arm_never_is
#[must_use]
pub fn measure(stream: &Stream) -> Reading {
    let mut per_hook: BTreeMap<String, Cost> = BTreeMap::new();
    // Keyed on (segment, producer, digest) so one hook saying two different
    // things is two entries and two hooks saying one thing is two entries.
    // Collapsing either way would report a repeat that nobody made.
    let mut seen: BTreeMap<(usize, String, String), (usize, usize)> = BTreeMap::new();
    let mut tokens = 0;
    let mut segment: usize = 0;
    for record in &stream.records {
        if record.event == Event::SessionBoundary {
            segment += 1;
            continue;
        }
        let Event::HookOutput {
            hook,
            tokens: cost,
            digest,
            findings,
        } = &record.event
        else {
            continue;
        };
        tokens += cost;
        let entry = per_hook.entry(hook.clone()).or_insert(Cost {
            tokens: 0,
            emissions: 0,
        });
        entry.tokens += cost;
        entry.emissions += 1;
        if findings.is_empty() {
            let slot = seen
                .entry((segment, hook.clone(), digest.clone()))
                .or_insert((0, record.line));
            slot.0 += 1;
            continue;
        }
        for (key, arm) in findings {
            if *arm == crate::refusal::Arm::Pointer {
                continue;
            }
            // The key's last field is the definition's digest; the names before
            // it are pointers, and the report carries only the digest prefix.
            let digest = key.rsplit('\u{1f}').next().unwrap_or(key).to_owned();
            let slot = seen
                .entry((segment, hook.clone(), digest))
                .or_insert((0, record.line));
            slot.0 += 1;
        }
    }
    let repeats = seen
        .into_iter()
        .filter(|(_, (count, _))| *count > 1)
        .map(|((_, hook, digest), (count, first_line))| Repeat {
            hook,
            // A PREFIX. Eight characters name the thing in a report; the whole
            // digest would let a reader who already holds a candidate text
            // confirm it, which is a payload channel opened by arithmetic.
            digest: digest.chars().take(8).collect(),
            count,
            first_line,
        })
        .collect();
    Reading {
        tokens,
        session_tokens: crate::budget::estimate_tokens_over(stream.bytes),
        per_hook,
        repeats,
    }
}

/// Judge a reading against the declared ceiling.
///
/// **An undeclared ceiling judges nothing and is not an error.** That is the
/// anti-vacuity direction stated as behaviour: `measure` still reports, so a
/// consumer can read its own number before choosing one, and adopting the table
/// is a separate act from being measured by it.
#[must_use]
pub fn judge(reading: &Reading, ceiling: Option<&Ceiling>) -> Vec<Finding> {
    let Some(ceiling) = ceiling else {
        return Vec::new();
    };
    let mut found = Vec::new();
    if reading.tokens > ceiling.max_tokens {
        found.push(finding(
            BUDGET_RULE,
            // The SUBJECT is the session, named as a count rather than as a
            // path: there is no file to point at, and pointing at the transcript
            // would name a document rule 4 keeps every byte of off this channel.
            format!("session:{}", reading.tokens),
            None,
            "cut what the hooks restate until the session is under its budget",
        ));
    }
    for repeat in &reading.repeats {
        if repeat.count > ceiling.max_repeats {
            found.push(finding(
                REPEAT_RULE,
                format!("{}:{}x{}", repeat.hook, repeat.digest, repeat.count),
                Some(repeat.first_line),
                "emit it once and make the later turns point at the first, the way \
                 `contract-drift` already reports a change-set once",
            ));
        }
    }
    found
}

/// One engine-produced finding, in `budget.rs`'s shape.
///
/// Engine-produced rather than a `[[rule]]` row, for that module's reason
/// exactly: re-measuring the session IS the check, and the fix is cutting what a
/// hook restates — prose no command can write, so [`Remediation::NoFix`] states
/// it rather than a `Fix::Run` naming a command that would not help.
fn finding(rule: &str, subject: String, line: Option<usize>, remedy: &str) -> Finding {
    Finding {
        owner: None,
        rule: rule.to_owned(),
        severity: RuleSeverity::Deny,
        identity: StoredIdentity::new(
            FindingKind::Scope,
            crate::identity::scope_fingerprint(rule, &subject),
        ),
        path: subject,
        line,
        check: crate::findings::Check::Reevaluate,
        remediation: Some(crate::findings::Remediation::NoFix(remedy.to_owned())),
        reason: None,
    }
}

/// What the call after a refusal did (CLOUD-2141), in report order.
///
/// Decided mechanically from the next [`Event::ToolCall`] and never from prose:
/// what the agent SAID is dropped at the parse (rule 4), and judging it would be
/// an estimate (rule 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Follow {
    /// The next call started with a route the refusal's class declares.
    Followed,
    /// The next call was the refused call again.
    Repeated,
    /// The next call looked the refusal up.
    Dereferenced,
    /// Any other next call.
    Other,
    /// No call followed.
    Ended,
}

impl Follow {
    /// Every bucket, in report order.
    pub const ALL: [Follow; 5] = [
        Follow::Followed,
        Follow::Repeated,
        Follow::Dereferenced,
        Follow::Other,
        Follow::Ended,
    ];
}

/// One context window's census: everything between two `SessionStart`s.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Window {
    /// Distinct gates the window carried, a gate's full arm and its addresses
    /// counted once — the number a per-gate doc budget is divided by.
    pub distinct: usize,
    /// Tokens of emissions carrying at least one full arm.
    pub full_tokens: usize,
    /// Tokens of emissions carrying findings, none of them full.
    pub pointer_tokens: usize,
    /// Tokens of emissions carrying no finding at all.
    pub unlabelled_tokens: usize,
    /// Refusals in the window.
    pub refusals: usize,
    /// Refusals no line of which parsed as a finding.
    pub unlabelled_refusals: usize,
    /// Refusals per [`Follow`] bucket, in [`Follow::ALL`]'s order.
    pub buckets: [usize; 5],
}

/// [`windows`]' answer: one entry per context window, in stream order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Windows {
    /// The windows, `k + 1` of them over `k` session boundaries.
    pub segments: Vec<Window>,
}

/// The command a call ran, as a route is compared against it.
fn command_of(name: &str, input: &serde_json::Value) -> String {
    match input["command"].as_str() {
        Some(command) if name == "Bash" => command.to_owned(),
        _ => input.to_string(),
    }
}

/// Whether a call named `name` running `command` takes `route`, one a finding
/// line printed (CLOUD-2141).
///
/// `run <command>`: the call opens with the route's words up to its first
/// `<placeholder>`, and carries every literal word after it — so a route
/// `batten policy explain '<id>' --history` is taken by the history read and
/// not by a bare lookup. `read <path>[ via <tool>]`: the call names the path,
/// or is the tool the route reads it through.
fn takes(route: &str, name: &str, command: &str) -> bool {
    if let Some(run) = route.strip_prefix("run ") {
        // The lookup hop every line prints is a dereference, not a remedy: the
        // history read is the one lookup a route asks for as its remedy.
        let lookup =
            run.starts_with("batten policy explain") || run.starts_with("batten policy rule");
        if lookup && !run.contains("--history") {
            return false;
        }
        let words: Vec<&str> = run.split_whitespace().collect();
        let opening = words.iter().take_while(|word| !word.contains('<')).count();
        // PER SEGMENT, NOT PER LINE: `cd <dir> && mise run land` takes the
        // route `mise run land`, and a prefix test of the whole line never saw
        // it. Measured: every Bash call of the census's own session opened
        // with a `cd`.
        return opening > 0
            && command.split(['&', ';', '|']).any(|segment| {
                let said: Vec<&str> = segment.split_whitespace().collect();
                said.starts_with(&words[..opening])
                    && words[opening..]
                        .iter()
                        .filter(|word| !word.contains('<'))
                        .all(|word| said.contains(word))
            });
    }
    if let Some(read) = route.strip_prefix("read ") {
        let (path, via) = match read.split_once(" via ") {
            Some((path, via)) => (path, Some(via)),
            None => (read, None),
        };
        return command.contains(path) || via.is_some_and(|tool| name.ends_with(tool));
    }
    false
}

/// The bucket a refusal of `call` falls in, given the call after it.
//MUTANT offered-routes-unread|s@^    if offered.iter().any(|route| takes(route, name, \&command)) {$@    if false {@|a_route_the_refusal_printed_is_followed
fn follow(
    findings: &[(String, crate::refusal::Arm)],
    offered: &[String],
    refused: Option<(&str, &serde_json::Value)>,
    next: Option<(&str, &serde_json::Value)>,
    routes: &BTreeMap<String, Vec<String>>,
) -> Follow {
    let Some((name, input)) = next else {
        return Follow::Ended;
    };
    let command = command_of(name, input);
    // A ROUTE THE LINE PRINTED, FIRST: the refusal's own pointers are what it
    // asked for, and a class's declared routes are only the ones every row of
    // it shares. Measured over 81 refusals: counting only the latter bucketed
    // the `--history` read the history gate names as "other".
    if offered.iter().any(|route| takes(route, name, &command)) {
        return Follow::Followed;
    }
    if command.starts_with("batten policy explain") || command.starts_with("batten policy rule") {
        return Follow::Dereferenced;
    }
    let followed = findings.iter().any(|(key, _)| {
        key.split('\u{1f}')
            .nth(1)
            .and_then(|class| routes.get(class))
            .is_some_and(|targets| {
                targets
                    .iter()
                    .any(|target| command.starts_with(target.as_str()))
            })
    });
    if followed {
        return Follow::Followed;
    }
    if refused == Some((name, input)) {
        return Follow::Repeated;
    }
    Follow::Other
}

/// How many distinct gates each context window met, what their output cost, and
/// what the agent did after each refusal (CLOUD-2141).
///
/// **No I/O, no clock, no tokenizer**, for [`measure`]'s reason; the shipped
/// binary must not link a tokenizer, so tokens are the transcript's own
/// estimate. `routes` maps a class token to its declared command targets — the
/// registry declares routes per class only.
//MUTANT segment-key-not-reset|s@^                    keys.clear();$@                    let _ = keys.len();@|a_window_census_reports_distinct_gates_per_segment
//MUTANT deny-follow-misbucketed|s@^            \.nth(1)$@            .nth(0)@|a_deny_is_bucketed_by_the_call_that_follows_it
#[must_use]
pub fn windows(stream: &Stream, routes: &BTreeMap<String, Vec<String>>) -> Windows {
    let calls: BTreeMap<&str, (&str, &serde_json::Value)> = stream
        .records
        .iter()
        .filter_map(|record| match &record.event {
            Event::ToolCall { id, name, input } => Some((id.as_str(), (name.as_str(), input))),
            _ => None,
        })
        .collect();
    let mut segments = Vec::new();
    let mut window = Window::default();
    let mut keys: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    // What each gate's full arm told this window, by name: a repeat is only the
    // address (CLOUD-2145), so its class and routes are the ones already shown.
    let mut told: BTreeMap<String, (String, Vec<String>)> = BTreeMap::new();
    for (index, record) in stream.records.iter().enumerate() {
        let findings =
            match &record.event {
                Event::SessionBoundary => {
                    window.distinct = keys.len();
                    keys.clear();
                    told.clear();
                    segments.push(std::mem::take(&mut window));
                    continue;
                }
                Event::HookOutput {
                    tokens, findings, ..
                } => {
                    charge(&mut window, *tokens, findings);
                    remember(&mut told, findings, &[]);
                    findings
                }
                Event::Refused {
                    call,
                    tokens,
                    findings,
                    routes: offered,
                } => {
                    charge(&mut window, *tokens, findings);
                    window.refusals += 1;
                    if findings.is_empty() {
                        window.unlabelled_refusals += 1;
                    }
                    remember(&mut told, findings, offered);
                    let (findings_seen, offered_seen) = recalled(&told, findings, offered);
                    let next =
                        stream.records.iter().skip(index + 1).find_map(|later| {
                            match &later.event {
                                Event::ToolCall { name, input, .. } => Some((name.as_str(), input)),
                                _ => None,
                            }
                        });
                    let bucket = follow(
                        &findings_seen,
                        &offered_seen,
                        calls.get(call.as_str()).copied(),
                        next,
                        routes,
                    );
                    for (slot, candidate) in window.buckets.iter_mut().zip(Follow::ALL) {
                        if candidate == bucket {
                            *slot += 1;
                        }
                    }
                    findings
                }
                _ => continue,
            };
        keys.extend(findings.iter().map(|(key, _)| gate_name(key).to_owned()));
    }
    window.distinct = keys.len();
    segments.push(window);
    Windows { segments }
}

/// The gate a finding key names: its rule, or its class where it has no rule.
/// The same gate's two arms key differently — the address carries no class and
/// no definition — and are one gate.
fn gate_name(key: &str) -> &str {
    let mut fields = key.split('\u{1f}');
    let rule = fields.next().unwrap_or_default();
    if rule.is_empty() {
        fields.next().unwrap_or_default()
    } else {
        rule
    }
}

/// Record what each FULL arm in `findings` told the window: its class and the
/// routes its emission printed.
fn remember(
    told: &mut BTreeMap<String, (String, Vec<String>)>,
    findings: &[(String, crate::refusal::Arm)],
    offered: &[String],
) {
    for (key, arm) in findings {
        if *arm != crate::refusal::Arm::Full {
            continue;
        }
        let class = key.split('\u{1f}').nth(1).unwrap_or_default().to_owned();
        let entry = told
            .entry(gate_name(key).to_owned())
            .or_insert_with(|| (class.clone(), Vec::new()));
        if entry.0.is_empty() {
            entry.0 = class;
        }
        for route in offered {
            if !entry.1.contains(route) {
                entry.1.push(route.clone());
            }
        }
    }
}

/// A refusal's findings and routes with each ADDRESS filled in from what its
/// gate's full arm told the window: the class into its key, its routes into the
/// offered set. A gate the window never saw in full is left as it is.
//MUTANT address-recall-skipped|s@^        let Some((class, earlier)) = told.get(gate_name(key)) else {$@        let Some((class, earlier)) = None::<\&(String, Vec<String>)> else {@|a_repeat_is_bucketed_by_what_its_full_arm_offered
fn recalled(
    told: &BTreeMap<String, (String, Vec<String>)>,
    findings: &[(String, crate::refusal::Arm)],
    offered: &[String],
) -> (Vec<(String, crate::refusal::Arm)>, Vec<String>) {
    let mut keys = Vec::new();
    let mut routes = offered.to_vec();
    for (key, arm) in findings {
        let Some((class, earlier)) = told.get(gate_name(key)) else {
            keys.push((key.clone(), *arm));
            continue;
        };
        let mut fields: Vec<&str> = key.split('\u{1f}').collect();
        if fields.len() > 1 && fields[1].is_empty() {
            fields[1] = class;
        }
        keys.push((fields.join("\u{1f}"), *arm));
        for route in earlier {
            if !routes.contains(route) {
                routes.push(route.clone());
            }
        }
    }
    (keys, routes)
}

/// Charge one emission's tokens to the class its findings put it in.
fn charge(window: &mut Window, tokens: usize, findings: &[(String, crate::refusal::Arm)]) {
    if findings.is_empty() {
        window.unlabelled_tokens += tokens;
    } else if findings
        .iter()
        .any(|(_, arm)| *arm == crate::refusal::Arm::Full)
    {
        window.full_tokens += tokens;
    } else {
        window.pointer_tokens += tokens;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::transcript::Record;

    fn emitted(line: usize, hook: &str, digest: &str, tokens: usize) -> Record {
        Record {
            line,
            event: Event::HookOutput {
                hook: hook.to_owned(),
                tokens,
                digest: digest.to_owned(),
                findings: Vec::new(),
            },
        }
    }

    /// One emission carrying one labelled finding of `key` on `arm`.
    fn finding_at(line: usize, key: &str, arm: crate::refusal::Arm) -> Record {
        Record {
            line,
            event: Event::HookOutput {
                hook: "PreToolUse:Bash".to_owned(),
                tokens: 10,
                digest: format!("{line:012}"),
                findings: vec![(key.to_owned(), arm)],
            },
        }
    }

    /// A Bash call running `command`.
    fn call_at(line: usize, id: &str, name: &str, command: &str) -> Record {
        Record {
            line,
            event: Event::ToolCall {
                id: id.to_owned(),
                name: name.to_owned(),
                input: serde_json::json!({ "command": command }),
            },
        }
    }

    /// A refusal of `call`, labelled with `key` or unlabelled.
    fn refused_at(line: usize, call: &str, key: Option<&str>) -> Record {
        Record {
            line,
            event: Event::Refused {
                call: call.to_owned(),
                tokens: 7,
                findings: key
                    .map(|key| vec![(key.to_owned(), crate::refusal::Arm::Full)])
                    .unwrap_or_default(),
                routes: Vec::new(),
            },
        }
    }

    /// A refusal of `call` whose line offered `routes`.
    fn refused_offering(line: usize, call: &str, routes: &[&str]) -> Record {
        let mut record = refused_at(line, call, Some("r\u{1f}c9\u{1f}d"));
        if let Event::Refused {
            routes: offered, ..
        } = &mut record.event
        {
            *offered = routes.iter().map(|route| (*route).to_owned()).collect();
        }
        record
    }

    /// A route the refusal's own line printed is followed when the next call
    /// takes it, and the lookup hop every line prints is still a dereference
    /// (CLOUD-2141). Measured before this: 0 of 81 refusals bucketed as
    /// followed, the history read the history gate names among them.
    ///
    /// The suite `offered-routes-unread` is killed in.
    #[test]
    fn a_route_the_refusal_printed_is_followed() {
        let history = "run batten policy explain '<id>' --history";
        let lookup = "run batten policy explain 'r' 'c9'";
        let read = "read rules/scanning.md";
        let records = vec![
            // followed: the history read, placeholder filled.
            call_at(1, "a", "Edit", "batten.toml"),
            refused_offering(2, "a", &[history, lookup]),
            call_at(
                3,
                "b",
                "Bash",
                "batten policy explain 'tool pin other' --history",
            ),
            // dereferenced: the bare lookup the same line printed.
            refused_offering(4, "b", &[history, lookup]),
            call_at(5, "c", "Bash", "batten policy explain 'r' 'c9'"),
            // followed: the document route, read.
            refused_offering(6, "c", &[read, lookup]),
            call_at(7, "d", "Read", "/home/x/rules/scanning.md"),
            // other: a route's opening words without its literal tail.
            refused_offering(8, "d", &["run mise exec -- <program> --pinned"]),
            call_at(9, "e", "Bash", "mise exec -- cargo build"),
            // followed: the route as the second segment of a compound line.
            refused_offering(10, "e", &["run mise run land"]),
            call_at(11, "f", "Bash", "cd /x && mise run land"),
        ];
        let census = windows(&session(records, 4_000), &BTreeMap::new());
        assert_eq!(census.segments[0].buckets, [3, 0, 1, 1, 0]);
    }

    /// A REPEAT IS ONLY THE ADDRESS (CLOUD-2145), so the route a window's full
    /// arm offered is the one a repeat's follow-up is judged against, and the
    /// gate's two arms are one gate. The suite `address-recall-skipped` is
    /// killed in.
    #[test]
    fn a_repeat_is_bucketed_by_what_its_full_arm_offered() {
        use crate::refusal::Arm;
        // The full arm keys `rule, class, digest`; the address keys `rule`
        // alone, since it carries neither class nor definition.
        let mut repeat = refused_at(4, "b", Some("r\u{1f}\u{1f}d2"));
        if let Event::Refused { findings, .. } = &mut repeat.event {
            findings[0].1 = Arm::Pointer;
        }
        let records = vec![
            call_at(1, "a", "Bash", "head -40 batten.toml"),
            refused_offering(2, "a", &["run mise run land"]),
            call_at(3, "b", "Bash", "head -40 batten.toml"),
            repeat,
            call_at(5, "c", "Bash", "mise run land"),
        ];
        let census = windows(&session(records, 4_000), &BTreeMap::new());
        let window = &census.segments[0];
        assert_eq!(window.distinct, 1, "one gate, two arms");
        // The full arm's next call repeats it; the address's takes the route
        // only the full arm printed.
        assert_eq!(window.buckets, [1, 1, 0, 0, 0]);
    }

    #[test]
    fn a_window_census_reports_distinct_gates_per_segment() {
        use crate::refusal::Arm;
        let boundary = |line| Record {
            line,
            event: Event::SessionBoundary,
        };
        let census = windows(
            &session(
                vec![
                    finding_at(1, "x", Arm::Full),
                    finding_at(2, "y", Arm::Full),
                    boundary(3),
                    finding_at(4, "x", Arm::Full),
                    finding_at(5, "z", Arm::Pointer),
                    boundary(6),
                    finding_at(7, "z", Arm::Pointer),
                ],
                4_000,
            ),
            &BTreeMap::new(),
        );
        let distinct: Vec<usize> = census.segments.iter().map(|w| w.distinct).collect();
        assert_eq!(
            distinct,
            vec![2, 2, 1],
            "a key counts once in each window it appears in"
        );
        assert_eq!(census.segments[1].full_tokens, 10);
        assert_eq!(census.segments[1].pointer_tokens, 10);
    }

    #[test]
    fn a_deny_is_bucketed_by_the_call_that_follows_it() {
        let key = Some("r\u{1f}c1\u{1f}d");
        let routes = BTreeMap::from([
            ("c1".to_owned(), vec!["mise run fix".to_owned()]),
            ("c2".to_owned(), vec!["mise run other".to_owned()]),
        ]);
        let records = vec![
            // followed: the next call starts with c1's route.
            call_at(1, "a", "Bash", "cat f"),
            refused_at(2, "a", key),
            call_at(3, "b", "Bash", "mise run fix"),
            // repeated: the next call is the refused one again.
            call_at(4, "c", "Bash", "ls -la"),
            refused_at(5, "c", key),
            call_at(6, "d", "Bash", "ls -la"),
            // dereferenced: the next call looks the refusal up.
            refused_at(7, "d", key),
            call_at(8, "e", "Bash", "batten policy explain 'c1'"),
            // other.
            refused_at(9, "e", key),
            call_at(10, "f", "Bash", "ls"),
            // other: unlabelled, so there is no class to follow, even though
            // the next command is a route.
            refused_at(11, "f", None),
            call_at(12, "g", "Bash", "mise run fix"),
            // ended: nothing after it.
            refused_at(13, "g", key),
        ];
        let census = windows(&session(records, 4_000), &routes);
        let window = &census.segments[0];
        assert_eq!(window.refusals, 6);
        assert_eq!(window.unlabelled_refusals, 1);
        assert_eq!(window.buckets, [1, 1, 1, 2, 1]);
        assert_eq!(window.buckets.iter().sum::<usize>(), window.refusals);
    }

    #[test]
    fn a_full_arm_after_a_session_start_is_not_a_repeat_and_a_pointer_arm_never_is() {
        use crate::refusal::Arm;
        let key = "r\u{1f}c\u{1f}abcdef0123456789";
        let boundary = |line| Record {
            line,
            event: Event::SessionBoundary,
        };
        let mut records = vec![finding_at(1, key, Arm::Full), boundary(2)];
        records.push(finding_at(3, key, Arm::Full));
        records.extend((4..9).map(|line| finding_at(line, key, Arm::Pointer)));
        let clean = measure(&session(records, 4_000));
        assert!(clean.repeats.is_empty(), "{:?}", clean.repeats);
        assert!(judge(&clean, Some(&Ceiling::once())).is_empty());

        let twice = measure(&session(
            vec![finding_at(1, key, Arm::Full), finding_at(2, key, Arm::Full)],
            4_000,
        ));
        assert_eq!(twice.repeats.len(), 1, "two full arms in one cycle repeat");
        assert_eq!(judge(&twice, Some(&Ceiling::once())).len(), 1);
    }

    fn session(records: Vec<Record>, bytes: usize) -> Stream {
        Stream {
            session: Some("s-1".to_owned()),
            records,
            agent: crate::transcript::AgentContext::default(),
            bytes,
            // Unkeyed: this suite is about hook OUTPUT cost, and a fixture that
            // claimed a key it never used would say the stream had been
            // fingerprinted when nothing was.
            keyed: false,
        }
    }

    #[test]
    fn a_hook_saying_one_thing_n_times_is_a_violation() {
        // THE ROW'S OWN CASE, and the mutation case with it: drop the `count > 1`
        // filter in `measure` and every single emission becomes a repeat, so the
        // clean case below goes red.
        let reading = measure(&session(
            vec![
                emitted(3, "SessionStart:mcp", "aaaaaaaabbbb", 40),
                emitted(9, "SessionStart:mcp", "aaaaaaaabbbb", 40),
                emitted(14, "SessionStart:mcp", "aaaaaaaabbbb", 40),
            ],
            4_000,
        ));
        assert_eq!(reading.repeats.len(), 1);
        assert_eq!(reading.repeats[0].count, 3);
        assert_eq!(
            reading.repeats[0].first_line, 3,
            "the pointer is the FIRST copy"
        );
        assert_eq!(
            reading.repeats[0].digest, "aaaaaaaa",
            "a prefix, not the key"
        );

        let refused = judge(&reading, Some(&Ceiling::once()));
        assert_eq!(refused.len(), 1);
        assert_eq!(refused[0].rule, REPEAT_RULE);
    }

    #[test]
    fn a_hook_reporting_one_change_set_once_is_clean() {
        // The discriminating half. Without it a rule that refused every emission
        // would satisfy the case above and gate nothing.
        let reading = measure(&session(
            vec![
                emitted(3, "PostToolBatch:drift", "cccccccc1111", 30),
                emitted(9, "PostToolBatch:drift", "dddddddd2222", 30),
            ],
            4_000,
        ));
        assert!(
            reading.repeats.is_empty(),
            "two different things are not one"
        );
        assert!(judge(&reading, Some(&Ceiling::once())).is_empty());
    }

    #[test]
    fn a_hook_silent_on_success_is_clean_and_costs_nothing() {
        // Silence is the default, and it has to be spellable as a reading rather
        // than only as a posture: no records, no cost, no share, no findings.
        let reading = measure(&session(Vec::new(), 4_000));
        assert_eq!(reading.tokens, 0);
        assert_eq!(reading.share(), 0);
        assert!(reading.per_hook.is_empty());
        assert!(judge(&reading, Some(&Ceiling::once())).is_empty());
    }

    #[test]
    fn two_hooks_saying_the_same_thing_are_two_producers_not_one_repeat() {
        // The key is (producer, digest). Collapsing to the digest alone would
        // report a repeat neither hook made, and blame it on whichever name
        // sorted first.
        let reading = measure(&session(
            vec![
                emitted(3, "one", "eeeeeeee3333", 10),
                emitted(4, "two", "eeeeeeee3333", 10),
            ],
            4_000,
        ));
        assert!(reading.repeats.is_empty());
        assert_eq!(reading.per_hook.len(), 2);
    }

    #[test]
    fn the_session_share_is_the_headline_figure_recomputed() {
        // The row's acceptance: the 20% figure is re-runnable rather than
        // believed. 1000 tokens of hook output against a 4000-byte transcript,
        // which the estimator reads as 1000 session tokens... so the share is
        // over the denominator the estimator gives, not over a byte count.
        let reading = measure(&session(vec![emitted(3, "loud", "ffff4444", 200)], 4_000));
        assert_eq!(reading.session_tokens, 1_000);
        assert_eq!(reading.tokens, 200);
        assert_eq!(reading.share(), 20);
    }

    #[test]
    fn an_undeclared_ceiling_measures_and_refuses_nothing() {
        // ANTI-VACUITY. The reading still reports the repeat; only the judgement
        // is withheld, so a consumer can read its own number before adopting one.
        let reading = measure(&session(
            vec![
                emitted(3, "loud", "aaaaaaaa", 9_000),
                emitted(4, "loud", "aaaaaaaa", 9_000),
            ],
            10,
        ));
        assert_eq!(reading.repeats.len(), 1, "measured");
        assert!(judge(&reading, None).is_empty(), "and not judged");
    }

    #[test]
    fn the_budget_arm_fires_on_the_total_and_the_boundary_is_inclusive() {
        let reading = measure(&session(vec![emitted(3, "loud", "aaaaaaaa", 100)], 4_000));
        assert!(
            judge(
                &reading,
                Some(&Ceiling {
                    max_tokens: 100,
                    max_repeats: 1
                })
            )
            .is_empty(),
            "exactly at budget passes, as `[budget]` does"
        );
        let over = judge(
            &reading,
            Some(&Ceiling {
                max_tokens: 99,
                max_repeats: 1,
            }),
        );
        assert_eq!(over.len(), 1);
        assert_eq!(over[0].rule, BUDGET_RULE);
    }

    #[test]
    fn a_ceiling_nothing_can_satisfy_is_refused_at_load() {
        assert!(validate(None).is_ok());
        assert!(validate(Some(&Ceiling::once())).is_ok());
        assert!(
            validate(Some(&Ceiling {
                max_tokens: 0,
                max_repeats: 1
            }))
            .is_err()
        );
        assert!(
            validate(Some(&Ceiling {
                max_tokens: 10,
                max_repeats: 0
            }))
            .is_err(),
            "zero repeats refuses the finding rather than its restatement"
        );
    }

    #[test]
    fn the_reports_own_output_is_one_line() {
        // THE SELF-APPLYING PROPERTY, asserted rather than intended.
        let reading = measure(&session(
            vec![
                emitted(3, "a", "1111", 5),
                emitted(4, "b", "2222", 5),
                emitted(5, "b", "2222", 5),
            ],
            400,
        ));
        assert_eq!(reading.line().lines().count(), 1);
    }

    impl Ceiling {
        /// A ceiling that refuses only a repeat, so a case can vary one predicate.
        fn once() -> Ceiling {
            Ceiling {
                max_tokens: usize::MAX,
                max_repeats: 1,
            }
        }
    }
}
