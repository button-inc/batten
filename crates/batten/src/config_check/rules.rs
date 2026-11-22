use crate::config_model::{CeilingUnit, Direction, ReceiptKey, ReceiptTrigger, Rule, RuleKind};
use crate::error::UsageError;
use crate::preset_catalog::RuleScope;
use crate::rules::RuleExt as _;
use crate::rules::RuleKindExt as _;

use crate::selector::Selector;

use regex::Regex;

use std::collections::BTreeMap;

/// Refuse a keying an agent-sourced record cannot be filed under (CLOUD-859).
///
/// `key` became load-bearing on this path when the record started honouring it,
/// and exactly one of the three values is unreachable here. **The two halves run
/// on different envelopes**: the record is WRITTEN on the post-tool event of the
/// fact's own command — a shell call carrying a command line and nothing else —
/// and READ on the mediated call the receipt row selects. A `head` or `branch`
/// subject is a fact about the checkout and resolves identically at both moments;
/// a `named` subject is projected out of the reading call's own arguments, which
/// the writing call does not have.
///
/// So a `named` agent-sourced check would deny with a `Fix::Run`, the agent would
/// run the command it names, and no record would be filed — a gate nobody can
/// satisfy by doing what it asks. That is the failure this whole row exists to
/// end, so it is refused at load rather than shipped as a column that reads as
/// configured and files nothing.
///
/// # Errors
///
/// Returns a [`crate::error::UsageError`] (→ exit `1`) naming the fact and the
/// row. Pointer-only: two ids, never a command.
///
/// Housed in `rules` rather than `crate::facts` (CLOUD-2789): it reads rule rows,
/// and `facts` names no module above it.
pub fn validate_keying(facts: &[crate::facts::Declared], rules: &[Rule]) -> anyhow::Result<()> {
    for rule in rules {
        if rule.kind != RuleKind::Receipt || rule.receipt_key() != ReceiptKey::Named {
            continue;
        }
        for check in rule.receipt_names() {
            if facts.iter().any(|fact| &fact.name == check) {
                return Err(crate::error::UsageError::raise(format!(
                    "rule {}: `key = \"named\"` over the agent-sourced fact `{check}` — a named \
                     subject is projected from the call this row SELECTS, and the record is \
                     written on the post-tool event of the fact's own command, which carries no \
                     such subject. No record could ever be filed, so the check would deny \
                     forever and running the command it names would not satisfy it. Key it \
                     `head` or `branch`.",
                    rule.id
                )));
            }
        }
    }
    Ok(())
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
    validate_rows(rules)?;
    validate_composition(rules, None)
}

/// Everything [`validate`] checks except the cross-row composition — split out so
/// [`validate_in`] can run the composition half with a locator instead of
/// running it twice and reporting the unlocated message first.
pub(crate) fn validate_rows(rules: &[Rule]) -> anyhow::Result<()> {
    for (index, rule) in rules.iter().enumerate() {
        rule.validate()?;
        if rules[..index].iter().any(|prior| prior.id == rule.id) {
            return Err(UsageError::raise(format!(
                "rule {}: declared twice; a rule has one definition",
                rule.id
            )));
        }
        // One check name, one keying (CLOUD-444). The boundary resolves each
        // required name to a single verdict, so two rows disagreeing about what
        // invalidates the same receipt would silently resolve it one row's way —
        // a branch-keyed claim expiring per commit, or a HEAD-keyed verification
        // outliving the bytes it validated. Both are false greens, and the
        // per-row `validate` cannot see the collision, so it is refused here.
        for prior in &rules[..index] {
            let (Some(mine), Some(theirs)) = (rule.checks.as_ref(), prior.checks.as_ref()) else {
                continue;
            };
            if rule.receipt_key() == prior.receipt_key() {
                continue;
            }
            if let Some(shared) = mine.iter().find(|check| theirs.contains(check)) {
                return Err(UsageError::raise(format!(
                    "rules {} and {}: both require the receipt `{shared}` under different `key` values; one check name has one keying",
                    prior.id, rule.id
                )));
            }
        }
        // ONE PLAN ID, ONE QUERY — the same argument as the row above, over
        // `[[rule.plan]]` (CLOUD-949). `plan_facts` writes every declared query
        // into one map keyed by `id`, so two queries sharing an id and differing
        // in `hook`, `required` or `prohibited_profiles` resolve to whichever
        // was inserted last. That is a false green of the worst kind: the
        // module reads `input.tree.plan["gate"]` and is answered about a
        // DIFFERENT surface than the row it belongs to declared, so a required
        // step can go unchecked while the gate reports clean.
        //
        // Refused at LOAD rather than deduplicated at acquisition, because
        // silently picking one of two disagreeing declarations is the same
        // defect one layer down. An IDENTICAL redeclaration is accepted: it
        // names one query, so there is nothing to resolve.
        //
        // The per-row `validate` cannot see this — the collision is between
        // rows as often as within one — which is why it lives here beside
        // CLOUD-444's, whose reasoning it borrows wholesale.
        for query in &rule.plan {
            let collides =
                |other: &crate::config_model::PlanQuery| other.id == query.id && other != query;
            if let Some(prior) = rules[..index]
                .iter()
                .find(|prior| prior.plan.iter().any(collides))
            {
                return Err(UsageError::raise(format!(
                    "rules {} and {}: both declare the plan `{}` with different terms; one plan id has one query",
                    prior.id, rule.id, query.id
                )));
            }
            if rule.plan.iter().any(collides) {
                return Err(UsageError::raise(format!(
                    "rule {}: declares the plan `{}` twice with different terms; one plan id has one query",
                    rule.id, query.id
                )));
            }
        }
    }
    Ok(())
}

/// [`validate`], with the config text in hand so a composition refusal can point
/// at a **line** rather than only at a rule id (CLOUD-773's §5).
///
/// The located form is what the two real loaders call; the bare [`validate`]
/// stays for callers holding a rule table and no file — the defaults, and the
/// runner's own defence in depth. One implementation, an optional locator, so
/// the two can never disagree about what is refused.
///
/// # Errors
///
/// As [`validate`].
pub fn validate_in(rules: &[Rule], text: &str, source: &str) -> anyhow::Result<()> {
    validate_rows(rules)?;
    validate_composition(rules, Some(Located { text, source }))
}

/// The config text and its path, for turning a rule id into `path:line`.
#[derive(Clone, Copy)]
pub(crate) struct Located<'a> {
    pub(crate) text: &'a str,
    pub(crate) source: &'a str,
}

/// Where a rule id renders when there is no config text to locate it in.
pub(crate) fn pointer_for(at: Option<Located<'_>>, id: &str) -> String {
    match at {
        Some(located) => located.pointer(id),
        None => format!("rule {id}"),
    }
}

/// Refuse a composition a run could not honour, **at load and never later**.
///
/// Four refusals, and the ordering matters only in that each is checked over the
/// whole table rather than per row — which is why this cannot live in
/// [`Rule::validate`]:
///
/// 1. **Two rows deriving one name.** "Which one did I read" is not a question a
///    reviewer should have to answer, and the answer would be positional.
/// 2. **A reference to a name nothing derives.** The row loads, matches a
///    document, and compares against a value that will never exist — the
///    present-and-inert gate this file is written against.
/// 3. **A cycle.** Once B can reference A, A can reference B. CLOUD-647 measured
///    that the obvious candidate engine reports cycles at *evaluation*, which on
///    the mediated path is the worst possible time and the wrong exit class.
/// 4. **A reference that changes the reading rule's class.** CLOUD-757 settled
///    composition as the **meet on both axes**: a derived fact is at most as
///    cheap as its most expensive input and at most as wide as its narrowest.
///    So if meeting the derivation's class with the reader's own moves it, the
///    reader is not the rule it declares itself to be — a `read`-class row would
///    silently inherit an `effect`-class dependency, or a hook-surface row would
///    answer from a fact never resolvable there.
///
/// Pointer-only (rule 4): a `path:line` and a rule id, never a derived value.
///
/// # Errors
///
/// A [`UsageError`] (→ exit `1`) for each of the four. A config declaring a
/// composition the engine cannot honour is the config-or-usage class, never a
/// policy verdict about the repository.
pub(crate) fn validate_composition(rules: &[Rule], at: Option<Located<'_>>) -> anyhow::Result<()> {
    let mut derived: BTreeMap<&str, &Rule> = BTreeMap::new();
    for rule in rules {
        let Some(name) = rule.derives.as_deref() else {
            continue;
        };
        if let Some(prior) = derived.insert(name, rule) {
            return Err(UsageError::raise(format!(
                "{} and {}: both derive `{name}`; a derived value has one definition",
                pointer_for(at, &prior.id),
                pointer_for(at, &rule.id)
            )));
        }
    }
    for rule in rules {
        let Some(name) = rule.reads.as_deref() else {
            continue;
        };
        let Some(producer) = derived.get(name).copied() else {
            return Err(UsageError::raise(format!(
                "{}: reads `{name}`, which no rule derives",
                pointer_for(at, &rule.id)
            )));
        };
        // The meet on BOTH axes. Equality with the reader's own class is the
        // predicate rather than a comparison per axis, because "did this
        // reference move me" is one question and asking it twice invites the
        // two halves to drift.
        //
        // EACH SIDE IS JUDGED AT ITS OWN SCOPE (CLOUD-833). `fact_class` used to
        // key on the kind alone; a `policy` row is `Free` x `Hook` on the
        // mediated call and `Read` x `Check` on the tree, so asking for one
        // rule's class while holding the other's scope would compare two things
        // neither row declares. `rule.scope` and `producer.scope` are the values
        // each row actually carries, and passing anything else here is how this
        // check would start answering a question nobody asked.
        let mine = rule.kind.fact_class(rule.scope);
        let theirs = producer.kind.fact_class(producer.scope);
        if mine.meet(theirs) != mine {
            return Err(UsageError::raise(format!(
                "{}: reads `{name}`, derived by {} at cost `{}` on surface `{}`, which a rule at \
                 cost `{}` on surface `{}` cannot carry — composition takes the meet on both axes",
                pointer_for(at, &rule.id),
                pointer_for(at, &producer.id),
                theirs.cost.as_str(),
                theirs.surface.as_str(),
                mine.cost.as_str(),
                mine.surface.as_str()
            )));
        }
    }
    // Depth-first over the reference edges. The graph is tiny — one edge per row
    // that reads — so the walk is the whole algorithm and there is nothing to
    // memoise that would pay for itself.
    for rule in rules {
        if rule.reads.is_none() {
            continue;
        }
        let mut seen: Vec<&str> = vec![rule.id.as_str()];
        let mut here = rule;
        while let Some(name) = here.reads.as_deref() {
            let Some(next) = derived.get(name).copied() else {
                break;
            };
            if seen.contains(&next.id.as_str()) {
                return Err(UsageError::raise(format!(
                    "{} and {}: their `reads`/`derives` references form a cycle, so neither \
                     value can be resolved; refused at load, where a cycle costs a config error \
                     rather than a decision",
                    pointer_for(at, &here.id),
                    pointer_for(at, &next.id)
                )));
            }
            seen.push(next.id.as_str());
            here = next;
        }
    }
    Ok(())
}

pub(crate) struct Declared<'a> {
    /// Files a row declared as parsed documents.
    pub documents: &'a [String],
    /// Files a row declared as line sets.
    pub lines: &'a [String],
    /// Rust files a row declared as call sites.
    pub invocations: &'a [String],
    /// Rust files a row declared as a `use` graph.
    pub uses: &'a [String],
    /// The source files to acquire as unit nodes (CLOUD-1008).
    pub units: &'a [String],
    /// The rev this row's per-file facts are ALSO acquired at, as
    /// `input.tree.base.<family>` (plan item 4), or `None` for a row with no
    /// `base`.
    pub base: Option<&'a str>,
    /// The paths this row declared a STAGED read of (CLOUD-1203).
    ///
    /// The ROW's own list rather than the run's, which is what scopes the read to
    /// the declaration: another row's staged path is not in this document.
    pub staged: &'a [String],
    /// The `[[rule.external]]` rows this row declared (CLOUD-1167).
    ///
    /// The ROW's own rows rather than the run's, which is what scopes the read
    /// to the declaration: another row's `external` id is not in this document,
    /// so a module cannot reach a file its own row did not name.
    pub external: &'a [crate::facts::Rooted],
    /// The format to read a STAGED path with when its extension names none.
    ///
    /// `None` is the ordinary case and means the extension is the only authority.
    /// See the `format` column's own note on why this is a fallback rather than
    /// an override.
    pub staged_format: Option<crate::facts::Format>,
}

/// `Rule` behaviour that belongs to this module's layer, not the type's (CLOUD-2793).
pub trait RuleExt: Sized {
    /// # Errors
    ///
    /// When the row is refused because any of its columns does not hold, naming the row.
    fn validate(&self) -> anyhow::Result<()>;

    /// The obligation [`RuleKind::permits`] cannot express (CLOUD-758).
    ///
    /// # Errors
    ///
    /// A [`UsageError`] (→ exit `1`) for a shape row carrying neither column, or
    /// both, or a `content` expression the matcher cannot compile.
    ///
    /// A shape row is keyed on a command or on content — exactly one (CLOUD-758).
    ///
    /// The "one of" `forbid`'s `pattern`/`regex` pair carries, and for the same
    /// reason: a row with NEITHER loads, matches every mediated call, and turns
    /// a ban into a universal gate; a row with BOTH is two predicates where the
    /// reader can see one, and a precedence rule nobody can read is worse than a
    /// refusal.
    ///
    /// # Errors
    ///
    ///
    /// # Errors
    ///
    /// When the row is refused because its shape columns does not hold, naming the row.
    fn validate_shape_columns(&self) -> anyhow::Result<()>;

    /// The three ceiling columns travel together, or none of them does
    /// (CLOUD-925).
    ///
    /// A value inside the row decides the obligation, so the per-kind census
    /// structurally cannot state it — the same reason `receipt`'s
    /// trigger-dependent columns and `policy`'s one-of-three source live here.
    ///
    /// Each partial row is a distinct silent failure and that is why all three
    /// are refused rather than defaulted: a `max` with no `measures` caps
    /// something unnamed, a `measures` with no `max` measures and decides
    /// nothing, and a pair with no `counts` cannot say whether 6000 means tokens
    /// or artifacts — which is a cap off by three orders of magnitude, in the
    /// permissive direction.
    ///
    /// # Errors
    ///
    /// A [`UsageError`] (→ exit `1`) naming the columns a partial row is missing.
    /// The two polarity modifiers may not name the same projection (CLOUD-987).
    ///
    /// A row asking for one key to be both absent and present can never fire, so
    /// it loads, matches nothing, and reads from the file as a narrowing — the
    /// inert-coverage failure this whole validation surface refuses. Naming
    /// *different* projections is legitimate and is what row 3 wants.
    ///
    /// # Errors
    ///
    /// A [`UsageError`] (→ exit `1`) naming the projection asked for twice.
    ///
    /// # Errors
    ///
    /// When the row is refused because its polarity does not hold, naming the row.
    fn validate_polarity(&self) -> anyhow::Result<()>;

    /// Refuse the command-only modifiers on a row keyed by `keyed_on`, a column
    /// that names no command line.
    ///
    /// Shared by the `content` and `tool` arms of [`Rule::validate_shape_columns`]
    /// because the argument is identical one column over, and stating it twice is
    /// how the two would drift when an eighth modifier lands. Each of the seven
    /// names a COMMAND: `contains` and `unless_contains` are substring tests over
    /// an argv in the two polarities, `word` and `unless_word` the same over its
    /// whole words, `require_via` is a via-shape test over the
    /// same argv, `requires_key` asks whether the work is keyed before a
    /// command may run, and `base` exists only to tell `requires_key` which
    /// commits to read. A write and a structured call carry no argv for any of
    /// them to read, so left to load they are accepted, ignored on every call,
    /// and the row narrows nothing the configuration appears to narrow.
    ///
    /// # Errors
    ///
    /// A [`UsageError`] (→ exit `1`) naming the first modifier present.
    fn refuse_command_modifiers(&self, keyed_on: &str) -> anyhow::Result<()>;

    /// Refuse a `pattern` the command matcher cannot honour (CLOUD-401).
    ///
    /// The empty-operand fix closed one row that loaded into silence; this
    /// closes the **class**. `hook::matching_shape_rows` and
    /// `hook::matching_receipt_rows` compare a pattern against a command that
    /// has already been normalised two ways — `effective_program` has stepped
    /// past env assignments and look-through wrappers, and the operand words
    /// have had every flag dropped — so a pattern naming what that
    /// normalisation removes is a row that can never fire. It loads clean,
    /// gates nothing, and reads as coverage, which is the exact defect
    /// [`validate`]'s doc comment is written against.
    ///
    /// Refused here rather than in the per-kind column census because the
    /// census is a const list of column NAMES: this depends on the value inside
    /// the column. Both surfaces that key on a command line are covered — a
    /// `shape` row's ban and a `receipt` row's trigger read the same pattern
    /// through the same matcher (`Rule::trigger`), so a rule inert on one is
    /// inert on the other.
    ///
    /// A program-only pattern is **valid**, and that is the point: it is the
    /// reading `Rule::pattern`'s doc comment already invites, and the one this
    /// validator must not take back.
    ///
    /// # Errors
    ///
    /// When the row is refused because its command pattern does not hold, naming the row.
    fn validate_command_pattern(&self) -> anyhow::Result<()>;

    /// The value-dependent obligations on the two ratchet admission columns,
    /// [`Rule::retires_with`] and [`Rule::admits_with`].
    ///
    /// Extracted from [`Rule::validate`] for `validate_conserves`'s reason — the
    /// per-kind census sees a present column and nothing about what is inside it
    /// — and the two are here together because they are the same three refusals
    /// mirrored, so a reader comparing them should not have to hold two screens.
    ///
    /// Each column admits ONE direction of change, and all three refusals close
    /// the same failure: a column that reads as a configured permission and
    /// decides nothing.
    ///
    /// * **`base` must be there.** Each column asks a question about another
    ///   tree — was this subject alive, was this file absent — and there is no
    ///   such tree without it. The ratchet kind already requires `base`, but the
    ///   obligation is on the VALUE, so a future kind taking either column
    ///   inherits the refusal rather than the omission.
    /// * **The token must not be blank.** An empty prefix matches at the start of
    ///   every line, so every file would "declare" whatever its first line
    ///   happens to say. That is `requires_key`'s compile-at-load failure in the
    ///   one form these columns can take it.
    /// * **The direction must be the one the column governs.** This is the blank
    ///   token's failure reached by the other axis, and it is the sharper of the
    ///   two because the column is not merely inert on the wrong row — it
    ///   switches the row OFF. `retires_with`'s block inspects only the files
    ///   whose count FELL, so on a `non_increasing` row it collects no subject,
    ///   leaves the blocker set empty, and the evaluator returns clean over every
    ///   increase. `undeclared_growth` is the mirror: it inspects only the files
    ///   that ROSE, so on a `non_decreasing` row every decrease is admitted in
    ///   silence. Found by review of #694 on `admits_with`; the sibling had
    ///   carried it latent since CLOUD-807.
    ///
    /// # Errors
    ///
    /// When the row is refused because its admission columns does not hold, naming the row.
    fn validate_admission_columns(&self) -> anyhow::Result<()>;

    /// Every token in a [`Conserves`] decides something, so a blank one is a
    /// configured admission (CLOUD-908).
    ///
    /// The obligations, and each closes a way the mapping could read as present
    /// and decide nothing:
    ///
    /// * **`retires_with` must be there.** This column refines that admission. A
    ///   ratchet that never permits a decrease has no deletion to map, so the
    ///   mapping would be inert — and inert coverage is what the whole row is
    ///   about.
    /// * **No token may be blank.** An empty prefix matches at the start of every
    ///   line, so every line would "declare" a case or claim one. The same
    ///   reading `retires_with` takes over its own token.
    /// * **The three arms must be distinct.** Two arms spelled alike make "exactly
    ///   one arm" undecidable: one line would claim a case twice, and the refusal
    ///   for a double claim would fire on every correct mapping instead.
    /// * **`declared_in` must compile.** A glob `globset` cannot parse selects
    ///   nothing, and a mapping read over nothing admits every deletion.
    ///
    /// # Errors
    ///
    /// When the row is refused because its conserves does not hold, naming the row.
    fn validate_conserves(&self) -> anyhow::Result<()>;

    /// # Errors
    ///
    /// When the row is refused because its remediation does not hold, naming the row.
    fn validate_remediation(&self) -> anyhow::Result<()>;

    /// # Errors
    ///
    /// When the row is refused because its ceiling does not hold, naming the row.
    fn validate_ceiling(&self) -> anyhow::Result<()>;

    /// The modifiers that read the command's ARGV (CLOUD-2662): refused on a
    /// row keyed by anything that names none, which an `on` row does not either,
    /// since its routes include structured calls.
    ///
    /// # Errors
    ///
    /// When the row is refused because it is keyed on an argv and carries a modifier that argv cannot express, naming the row.
    fn refuse_argv_modifiers(&self, keyed_on: &str) -> anyhow::Result<()>;

    fn modifier_refused(&self, keyed_on: &str, field: &str) -> anyhow::Error;

    /// The columns an `on` row may not carry (CLOUD-2662): the argv modifiers,
    /// and the per-call projections, which differ per route (`input-draft` is
    /// absent on every shell call) and so would silently drop whole routes.
    /// `requires_key`, `base` and the branch modifiers read the branch, which
    /// every route has, and stay.
    ///
    /// # Errors
    ///
    /// When the row is refused because its on columns does not hold, naming the row.
    fn validate_on_columns(&self) -> anyhow::Result<()>;

    /// The obligations a receipt row carries that [`RuleKind::permits`] cannot
    /// express (CLOUD-444).
    ///
    /// Which columns a receipt row owes depends on its `trigger`, a value inside
    /// the row — so the per-kind census cannot state it, exactly as it cannot
    /// state a policy row's one-of-three source. Both refusals have the same
    /// reasoning: a column that reads as configured and decides nothing is the
    /// defect this kind was added to close.
    ///
    /// # Errors
    ///
    /// A [`UsageError`] (→ exit `1`) for a command-triggered row with no
    /// `pattern`, for a write-triggered row carrying either command column, and
    /// for an empty `checks` list.
    /// The `delta` key and its base travel together (CLOUD-1547).
    ///
    /// Refused in BOTH directions, for the reason `key_from`'s pair is and with
    /// the same pair of silent failures one keying over.
    ///
    /// A `delta` key with no base has no second side to diff against, so it has
    /// no identity at all and would read no file for any call — which reads as
    /// *never reviewed* and denies everything. That is the direction that gets a
    /// guard switched off rather than satisfied, and it is worse than the
    /// permissive one here precisely because it looks like the gate working. A
    /// base on any other key is the mirror: a column that reads as configured and
    /// is never consulted.
    ///
    /// **Its own function rather than a fourth arm inside
    /// [`Rule::validate_receipt_columns`]**, which clippy's line ceiling forced
    /// and which is the right shape anyway: that one decides what a `trigger`
    /// owes, and this decides what a `key` owes.
    ///
    /// # Errors
    ///
    /// A [`UsageError`] (→ exit `1`) for `key = "delta"` with no `key_base`, and
    /// for a `key_base` on any other keying.
    ///
    /// # Errors
    ///
    /// When the row is refused because its delta base does not hold, naming the row.
    fn validate_delta_base(&self) -> anyhow::Result<()>;

    /// A receipt row's selectors (CLOUD-2662): exactly one of `pattern`, `tool`
    /// and `on` on a command-triggered row, and no command selector on a
    /// write-triggered one. Split from [`Rule::validate_receipt_columns`], whose
    /// line budget the third selector spent.
    ///
    /// # Errors
    ///
    /// When the row is refused because its receipt selectors does not hold, naming the row.
    fn validate_receipt_selectors(&self) -> anyhow::Result<()>;

    /// # Errors
    ///
    /// When the row is refused because its receipt columns does not hold, naming the row.
    fn validate_receipt_columns(&self) -> anyhow::Result<()>;

    /// A `while_marker` must name a family that landing sweeps (CLOUD-1390).
    ///
    /// **A REFUSAL NEEDS A SPEND, and this is the only thing that supplies one.**
    /// The column's whole contract is *fires while the marker exists*; what makes
    /// that finite is [`crate::land::retire_branch`] deleting the file. Name a
    /// family outside [`crate::config_model::BRANCH_KEYED_RECEIPTS`] and the row is a
    /// deny nothing clears — the work lands, the marker survives the retirement,
    /// and the next piece of work to reuse the branch name is refused for a punt
    /// somebody else took. That is CLOUD-774's inherited-suppression defect in the
    /// refusing direction, which is strictly worse than the advisory one.
    ///
    /// Asserted at load rather than documented, because the doc on
    /// [`Rule::while_marker`] said exactly this and a sentence in a doc comment
    /// stops nobody (non-negotiable rule 2). The pair can now only drift by
    /// failing.
    ///
    /// # Errors
    ///
    /// A [`UsageError`] (→ exit `1`) naming the row and the marker. Pointer-only:
    /// the two ids and the permitted list, never a path from the receipt store.
    ///
    /// # Errors
    ///
    /// When the row is refused because its marker does not hold, naming the row.
    fn validate_marker(&self) -> anyhow::Result<()>;

    /// The three refusals over a receipt row's two name columns (CLOUD-1297).
    ///
    /// Split out of [`Rule::validate_receipt_columns`] because that function
    /// crossed the 100-line bound when the alternation arrived, and this is the
    /// half that comes out whole: every arm here is about WHICH RECEIPTS the row
    /// names, where everything left behind is about the trigger and the columns
    /// it implies.
    ///
    /// # Errors
    ///
    /// A [`UsageError`] (→ exit `1`) for an empty `checks` list, an empty
    /// `checks_any` list, or a row naming neither column.
    ///
    /// # Errors
    ///
    /// When the row is refused because its receipt names does not hold, naming the row.
    fn validate_receipt_names(&self) -> anyhow::Result<()>;

    /// `ask` is a MEDIATED-CALL disposition, and both refusals below are config
    /// faults rather than silent downgrades (CLOUD-340).
    ///
    /// Extracted for the reason its neighbours are: `validate` is at its line
    /// ceiling, and this is a question about a value INSIDE the row — a
    /// severity, not a kind — which the per-kind census structurally cannot ask.
    ///
    /// # Errors
    ///
    /// A [`UsageError`] (→ exit `1`) when a non-`mediated_call` row declares
    /// `ask`, or when an `ask` row carries no `reason`.
    ///
    /// # Errors
    ///
    /// When the row is refused because its ask disposition does not hold, naming the row.
    fn validate_ask_disposition(&self) -> anyhow::Result<()>;

    /// The load-time refusals the three repository-state columns owe
    /// (CLOUD-843).
    ///
    /// Each refuses a declaration the acquisition could only answer wrongly: an
    /// empty tag glob lists nothing, a config key git cannot address resolves to
    /// a permanent `unset`, and a `:`-magic pathspec read as a literal selects
    /// nothing. Every one would load, acquire, and hand its module an answer to a
    /// question nobody asked — CLOUD-845's dead gate by way of a typo — so each is
    /// named here with the column and the entry.
    ///
    /// # Errors
    ///
    /// A [`UsageError`] (→ exit `1`) naming the first offending entry.
    ///
    /// # Errors
    ///
    /// When the row is refused because its repository state does not hold, naming the row.
    fn validate_repository_state(&self) -> anyhow::Result<()>;

    /// The three obligations a policy row carries that [`RuleKind::permits`]
    /// cannot express (CLOUD-833, CLOUD-836).
    ///
    /// All three depend on a value INSIDE the row rather than on its kind, which
    /// is what a flat per-kind column list structurally cannot say — the same
    /// reason `forbid`'s `pattern`/`regex` pair and `receipt`'s trigger-dependent
    /// columns live in `validate` rather than in the census.
    ///
    /// # Errors
    ///
    /// A [`UsageError`] (→ exit `1`) when the row names no source or more than
    /// one, when a mediated-call row declares `documents`, or when a tree-scoped
    /// row declares none.
    ///
    /// # Errors
    ///
    /// When the row is refused because its policy source does not hold, naming the row.
    fn validate_policy_source(&self) -> anyhow::Result<()>;

    /// Refuse a `document` row whose declared `format` contradicts the extension
    /// its glob names (CLOUD-1787).
    ///
    /// # The trap this closes
    ///
    /// `format` is declared and never inferred, which is right — a `.json` file
    /// that is really JSON5 must be declarable as JSON5. But nothing checked the
    /// declaration against the paths it would meet, and one pairing is actively
    /// dangerous rather than merely wrong: `format = "yaml"` over `*.md`
    /// **appears to work**, because `---` is YAML's document-start marker, so a
    /// markdown file's frontmatter is document 1 of the stream and gets read.
    /// Document 2 is the body, which is only accidentally valid YAML. Measured
    /// in CLOUD-1787: with identical correct frontmatter, prose and `**bold**`
    /// passed while a table, a task list and a block quote failed — the verdict
    /// decided by the prose, not the data.
    ///
    /// A row whose correctness depends on whether prose happens to lex is not a
    /// gate, and it fails silently in both directions, so it is refused at load
    /// where a config error costs a config error.
    ///
    /// # Why the literal suffix and not the glob
    ///
    /// Deciding what an arbitrary glob *can* match needs a glob engine and
    /// answers "possibly" for most inputs. The extension a glob ENDS in is a
    /// string, it is what every real row writes (`*.md`, `**/*.md`,
    /// `notes/*.md`), and it is exactly the case above. A computed or
    /// extensionless glob is not caught here and the message says so rather than
    /// implying a totality this does not have.
    ///
    /// # Errors
    ///
    /// When the row is refused because its declared format matches glob does not hold, naming the row.
    fn validate_declared_format_matches_glob(&self) -> anyhow::Result<()>;

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
    fn columns(&self) -> [(&'static str, bool); 64];

    /// What makes this row fire, with the pinned default applied — the one place
    /// absence is resolved, so no call site reads it a second way.
    #[must_use]
    fn receipt_trigger(&self) -> ReceiptTrigger;

    /// Which git fact this row's receipts are keyed to, default applied.
    #[must_use]
    fn receipt_key(&self) -> ReceiptKey;

    /// The pipeline row's own tables (CLOUD-443).
    ///
    /// Refused for the reason everything in [`Rule::validate`] is refused: a
    /// list that narrows nothing, or a row whose conditions contradict, loads
    /// clean and decides nothing. Extracted rather than inlined so `validate`
    /// stays under the line limit as columns accumulate — the census below it
    /// is the part that must stay whole.
    ///
    /// # Errors
    ///
    /// When the row is refused because its pipeline tables does not hold, naming the row.
    fn validate_pipeline_tables(&self) -> anyhow::Result<()>;

    /// `fix` and `no_fix_reason` are alternatives, never both (CLOUD-81).
    ///
    /// Not expressible in [`RuleKind::requires`] for the same reason
    /// `pattern`-xor-`regex` is not: that list is columns that must *all* be
    /// present. [`RuleKind::permits`] carries the other half — a `shape` row is
    /// refused both columns there, because it is adjudicated per mediated call
    /// and never reaches the store, the same reasoning that already denies it
    /// `identity_key`.
    ///
    /// **Carrying neither is refused at ingest, not here** (§5). A rule with no
    /// remediation still loads and still gates: `check` and `enforce` render its
    /// findings and exit on them exactly as before. What it cannot do is put one
    /// in the store, because a *stored* finding is one something later has to
    /// close. Refusing at load would instead make an un-actionable rule
    /// un-runnable, which turns a store-shaped requirement into a gate outage
    /// for every consumer whose config predates this field.
    /// The out-of-root bound's own obligations, refused at LOAD (CLOUD-1167).
    ///
    /// Its own function rather than a block inside `validate` for
    /// [`Rule::validate_tool_rows`]' reason: that function is at its 100-line
    /// ceiling, and every declared-read family adds a paragraph to it.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) for a row missing an `id` or a
    /// `root`, one whose `path` can leave the root it named, or one id declared
    /// twice over different files.
    ///
    /// # Errors
    ///
    /// When the row is refused because its external rows does not hold, naming the row.
    fn validate_external_rows(&self) -> anyhow::Result<()>;

    /// The tool-verdict key's own obligations, refused at LOAD (CLOUD-1171).
    ///
    /// Its own function rather than another block inside `validate` for the
    /// reason `validate_sink` is one: that function is at its line ceiling and
    /// every declared-read family adds a paragraph to it.
    ///
    /// Every refusal here is a CONFIG FAULT rather than a verdict, which is the
    /// choice `NotAcquired::UnknownFormat` already makes: no state of the
    /// filesystem makes an empty tool name or a separator inside a version
    /// admissible, so reporting either as could-not-look would present a
    /// permanent authoring error as a transient one.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) for a row whose key cannot be
    /// composed unambiguously, or for one id declared twice over different keys.
    ///
    /// # Errors
    ///
    /// When the row is refused because its tool rows does not hold, naming the row.
    fn validate_tool_rows(&self) -> anyhow::Result<()>;

    /// Refuse a `[[rule.minted]]` row that cannot address a receipt, or an id
    /// declared twice over different questions (CLOUD-1310).
    ///
    /// **The mint NAME is not resolved against the mint table, and that is
    /// deliberate.** A mint that has never fired leaves no receipts, which is
    /// could-not-look and is the ordinary state on any fresh clone — so refusing
    /// the row at load would refuse the common case rather than an authoring
    /// error. What is refused here is only what no state of the filesystem could
    /// make admissible.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) for a row naming an unusable mint or
    /// id, for a row whose two column indices are the same, and for one id
    /// declared twice over different questions.
    ///
    /// # Errors
    ///
    /// When the row is refused because its minted rows does not hold, naming the row.
    fn validate_minted_rows(&self) -> anyhow::Result<()>;

    /// A declared sink must be on a kind that can actually request one
    /// (CLOUD-851).
    ///
    /// The request set is built from a [`Scan`], which only the TREE surface
    /// produces: `adjudicate` returns a decision about one call and has no
    /// findings vector to digest. So a `produces` on a `mediated_call`-only kind
    /// would parse, read as configured, and write nothing on every call — the
    /// inert-coverage failure `validate_shape_columns` and
    /// `validate_receipt_columns` each close one column over, and the same one
    /// `Rule::fix`'s refusal states rather than pretends about.
    ///
    /// Refused at LOAD rather than skipped at run time, because a skip is
    /// invisible: the run reports its findings and the record simply is not
    /// there, which looks exactly like a run that had nothing to produce.
    ///
    /// # Errors
    ///
    /// When the row is refused because its sink does not hold, naming the row.
    fn validate_sink(&self) -> anyhow::Result<()>;

    /// `exclude_paths` has to be honoured by everything that reads the rule's
    /// selection, and two shapes cannot honour it (CLOUD-883).
    ///
    /// **No `glob`.** The column subtracts from an include set, so with nothing to
    /// subtract from it narrows nothing while reading as a narrowing — the
    /// inert-coverage failure `validate_sink` and `validate_shape_columns` each
    /// close one column over.
    ///
    /// **A ratchet.** Its verdict compares the working tree against a count taken
    /// at the base rev by `git::count_at_rev`, which globs on its own and knows
    /// nothing of this column. The two sides would select different sets, and the
    /// direction is the dangerous one CLOUD-328 measured: a working side narrowed
    /// below a base that counted everything sits permanently under its baseline,
    /// so no addition could ever push it over and **the gate cannot fail**.
    /// Refused rather than half-implemented, because a ratchet that cannot fail
    /// reads exactly like one that is passing.
    ///
    /// # Errors
    ///
    /// When the row is refused because its exclude paths does not hold, naming the row.
    fn validate_exclude_paths(&self) -> anyhow::Result<()>;

    /// The `pattern`-xor-`regex` rule, and the regexes' own well-formedness.
    ///
    /// Not expressible in [`RuleKind::requires`], which is a flat list of
    /// columns that must all be present — "exactly one of these two" needs a
    /// check of its own (CLOUD-283). Refusing a row that carries both is what
    /// keeps this a *choice* rather than a precedence rule a reader has to know.
    ///
    /// Each expression is compiled here, at load, so a bad one is a config error
    /// naming the row rather than a failure part-way through a scan.
    /// A document row's predicate: exactly one of `pattern` or `reads`.
    ///
    /// The same "one of" the forbid predicate carries and for the same reason —
    /// a flat column list cannot express it, so it lives here where the pair is
    /// in scope. A row with neither loads, matches a document, and asks nothing
    /// of it; a row with both declares two answers to one comparison.
    ///
    /// # Errors
    ///
    /// When the row is refused because its document predicate does not hold, naming the row.
    fn validate_document_predicate(&self) -> anyhow::Result<()>;

    /// A ratchet's `counts` and `per_file` columns (CLOUD-2663).
    ///
    /// # Errors
    ///
    /// When the row is refused because its ratchet measure does not hold, naming the row.
    fn validate_ratchet_measure(&self) -> anyhow::Result<()>;

    /// # Errors
    ///
    /// When the row is refused because its forbid predicate does not hold, naming the row.
    fn validate_forbid_predicate(&self) -> anyhow::Result<()>;

    /// The first column this row declares whose fact the mediated call cannot
    /// resolve (CLOUD-1282).
    ///
    /// Derived rather than listed: [`COLUMN_CENSUS`] says which fact each column
    /// declares and [`crate::facts::Fact::class`] says where that fact resolves,
    /// so a column added to this struct is covered the day it lands — and a fact
    /// RECLASSIFIED onto the hook surface stops being refused here without an
    /// edit, which a list could not manage in either direction.
    ///
    /// `Surface::Hook` is the NARROWEST surface a fact may be resolved on, so it
    /// is the one value that reaches the mediated call; every other means the
    /// column would parse, load and never be acquired.
    ///
    /// Census order decides which column a multi-column row is refused for,
    /// which is declaration order in the struct — the same tie-break every other
    /// table here uses, and the one a reviewer reading top to bottom expects.
    #[must_use]
    fn tree_only_column(&self) -> Option<TreeOnlyColumn>;
}

impl RuleExt for Rule {
    fn validate(&self) -> anyhow::Result<()> {
        let kind = self.kind.as_str();
        // Ahead of every per-kind question, so the rename is what the author
        // reads. Left to the census, a `run` on a command rule would report
        // "requires `check`" — true, and silent about the key already holding
        // the value.
        if self.run.is_some() {
            return Err(UsageError::raise(format!(
                "rule {}: `run` is now `check` (house style §9's check/fix duality); rename the key",
                self.id
            )));
        }
        self.validate_external_rows()?;
        self.validate_tool_rows()?;
        self.validate_minted_rows()?;
        self.validate_pipeline_tables()?;
        self.validate_sink()?;
        self.validate_exclude_paths()?;
        // The key modifier's own obligations (CLOUD-446). Both here rather than
        // in the column census for the reason stated below it: the census is a
        // per-kind const, and these depend on a value inside the row.
        if let Some(expression) = self.requires_key.as_deref() {
            // Without a range there is nothing to read commit subjects over, so
            // the row would fall back to the branch name alone — a narrowing
            // nobody wrote, arrived at by omission.
            if self.base.is_none() {
                return Err(UsageError::raise(format!(
                    "rule {}: `requires_key` requires `base` — the rev its commit evidence is read since",
                    self.id
                )));
            }
            // Compiled at load, like `regex` and `exclude`: an expression the
            // matcher cannot parse must name its row. Left to adjudication it
            // would fail open on every call, which is a gate that reads as
            // present and denies nothing.
            Regex::new(expression).map_err(|err| {
                UsageError::raise(format!(
                    "rule {}: `requires_key` is not valid: {err}",
                    self.id
                ))
            })?;
        }
        self.validate_admission_columns()?;
        self.validate_conserves()?;
        // Extracted for `validate_policy_source`'s reason, and it is the same
        // class of obligation: which columns a receipt row owes depends on a
        // value inside it, which the per-kind census cannot say.
        self.validate_shape_columns()?;
        self.validate_polarity()?;
        self.validate_receipt_columns()?;
        // Extracted rather than inlined, because `validate` is at its line ceiling
        // and a per-kind block is what it should shed first: the census above is
        // the general mechanism, and these are the three things a flat column
        // list structurally cannot say about one kind.
        self.validate_policy_source()?;
        self.validate_ask_disposition()?;
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
        // Compiled at load, like `regex` and `exclude` above it (CLOUD-214): a
        // pattern the matcher cannot parse must name the row that carries it,
        // rather than becoming a rule that selects nothing and reads as a gate
        // that found nothing wrong.
        if let Some(glob) = self.glob.as_deref() {
            Selector::new(glob)
                .map_err(|err| UsageError::raise(format!("rule {}: {err}", self.id)))?;
        }
        self.validate_command_pattern()?;
        self.validate_forbid_predicate()?;
        self.validate_document_predicate()?;
        self.validate_remediation()
    }

    fn validate_shape_columns(&self) -> anyhow::Result<()> {
        if self.kind != RuleKind::Shape {
            return Ok(());
        }
        // CLOUD-2669: compiled at load, anchored as the matcher anchors them, so
        // an unparseable word expression never reaches adjudication.
        for (field, shape) in [("word", &self.word), ("unless_word", &self.unless_word)] {
            if let Some(shape) = shape.as_deref() {
                Regex::new(&format!("^(?:{shape})$")).map_err(|err| {
                    UsageError::raise(format!(
                        "rule {}: `{field}` is not a valid regular expression: {err}",
                        self.id
                    ))
                })?;
            }
        }
        // THREE KEYING COLUMNS NOW, EXACTLY ONE OF WHICH A ROW CARRIES
        // (CLOUD-924). Counted rather than matched as a tuple: a 2x2 match was
        // already at its readable limit and a 2x2x2 one would spell six
        // impossible arms to reach the two that matter.
        let keys: Vec<&str> = [
            ("pattern", self.pattern.is_some()),
            ("content", self.content.is_some()),
            ("tool", self.tool.is_some()),
            ("on", self.on.is_some()),
        ]
        .into_iter()
        .filter_map(|(name, present)| present.then_some(name))
        .collect();
        if keys.len() > 1 {
            return Err(UsageError::raise(format!(
                "rule {}: kind \"shape\" carries {}; a row is keyed on a command \
                 (`pattern`), on written content (`content`), or on the tool a call names \
                 (`tool`) — never on more than one",
                self.id,
                keys.join(" and ")
            )));
        }
        if self.on.is_some() {
            self.validate_on_columns()?;
            return self.validate_ceiling();
        }
        if let Some(selector) = self.tool.as_deref() {
            // Refused at load rather than at adjudication, where an empty
            // selector would match the empty final segment of every name ending
            // in `__` — a row that reads as naming one tool and selects a family.
            if selector.is_empty() {
                return Err(UsageError::raise(format!(
                    "rule {}: `tool` is empty; name the tool this row is about",
                    self.id
                )));
            }
            // The same command-only modifiers `content` refuses below, refused
            // for the same reason one column over: a structured call carries no
            // argv either, so each would read as configured and narrow nothing.
            self.refuse_command_modifiers("tool")?;
            return self.validate_ceiling();
        }
        match (self.pattern.is_some(), self.content.as_deref()) {
            (true, None) => self.validate_ceiling(),
            // Compiled at load, the way `regex`, `exclude` and `requires_key`
            // already are. Left to adjudication an unparseable expression is
            // skipped on every mediated call, which is a gate that reads as
            // configured in the file and denies nothing — the one failure this
            // kind's whole validation surface exists to close.
            (false, Some(expression)) => {
                Regex::new(expression).map_err(|err| {
                    UsageError::raise(format!(
                        "rule {}: `content` is not a valid regular expression: {err}",
                        self.id
                    ))
                })?;
                // AND THE COMMAND-ONLY MODIFIERS ARE REFUSED HERE, because the
                // column census permits them on this kind and `adjudicate`
                // evaluates only `content` for a content-keyed row. Left to load
                // they are accepted, ignored on every call, and the row denies
                // writes the configuration appears to narrow — a rule that reads
                // as scoped and is not, which is the same inert-coverage failure
                // the `content` compile above closes one column over.
                //
                self.refuse_command_modifiers("content")?;
                self.validate_ceiling()
            }
            (false, None) => Err(UsageError::raise(format!(
                "rule {}: kind \"shape\" requires `pattern` (a command line), `content` (a \
                 regex over what a write would land), or `tool` (the tool a call names)",
                self.id
            ))),
            // Unreachable: the count above refuses every row carrying more than
            // one keying column, and this is one of those. Kept as an arm rather
            // than wildcarded so a fourth keying column has to come back here and
            // be decided (non-negotiable rule 6's shape, applied to a match).
            (true, Some(_)) => Err(UsageError::raise(format!(
                "rule {}: kind \"shape\" carries both `pattern` and `content`; a row is keyed \
                 on a command or on written content, never on both",
                self.id
            ))),
        }
    }

    fn validate_polarity(&self) -> anyhow::Result<()> {
        if let (Some(absent), Some(present)) = (self.when_absent, self.when_present)
            && absent == present
        {
            return Err(UsageError::raise(format!(
                "rule {}: `when_absent` and `when_present` both name the same projection, so \
                 this row can never fire; name different ones or drop one",
                self.id
            )));
        }
        // THE VALUE QUALIFIER TRAVELS WITH ITS PROJECTION (CLOUD-312 row 3), and
        // both directions are refused because each is a different silent failure.
        //
        // A value with no `when_present` names nothing to read it out of, so the
        // row compares against a projection it never took — a column that reads as
        // a narrowing and performs none.
        //
        // **HERE RATHER THAN IN `validate_receipt_columns`**, which is where these
        // two were written first and where they were half-dead: `when_value` is
        // permitted on `shape` as well as `receipt`, and that function returns
        // early for every other kind — so a `shape` row carrying the column with
        // no projection loaded clean and narrowed nothing. Caught in review on
        // #680. Every kind that can carry the column reaches this function.
        if self.when_value.is_some() && self.when_present.is_none() {
            return Err(UsageError::raise(format!(
                "rule {}: `when_value` qualifies `when_present` — name the projection whose value \
                 this is, or the row compares against nothing and narrows nothing",
                self.id
            )));
        }
        // EMPTY **AFTER FOLDING**, not before, and the difference is the whole
        // check. The comparison drops spaces, underscores and hyphens, so `"___"`
        // and `"---"` fold to nothing and then compare equal to any value made
        // only of separators — a match nobody intended. Testing the raw string for
        // emptiness caught `""` and let the other two through, which is the defect
        // the previous version of this comment described without covering.
        if self
            .when_value
            .as_deref()
            .is_some_and(|value| crate::config_model::comparable(value).is_empty())
        {
            return Err(UsageError::raise(format!(
                "rule {}: `when_value` folds to nothing, so it matches any value made only of \
                 spaces, underscores or hyphens; name the value this row is about",
                self.id
            )));
        }
        Ok(())
    }

    fn refuse_command_modifiers(&self, keyed_on: &str) -> anyhow::Result<()> {
        self.refuse_argv_modifiers(keyed_on)?;
        for (field, present) in [
            ("requires_key", self.requires_key.is_some()),
            ("base", self.base.is_some()),
        ] {
            if present {
                return Err(self.modifier_refused(keyed_on, field));
            }
        }
        Ok(())
    }

    fn validate_command_pattern(&self) -> anyhow::Result<()> {
        // The kinds that key on a command line. A `write`-triggered receipt row
        // is refused a `pattern` outright above, so it never reaches here.
        let keys_on_a_command = self.kind == RuleKind::Shape
            || (self.kind == RuleKind::Receipt
                && self.receipt_trigger() == ReceiptTrigger::Command);
        if !keys_on_a_command {
            return Ok(());
        }
        if self.pattern.is_none() {
            return Ok(());
        }
        // `trigger()` yields nothing for a pattern with no word in it, and a
        // row it cannot read is a row the matcher skips.
        let Some((program, wanted)) = self.trigger() else {
            return Err(UsageError::raise(format!(
                "rule {}: `pattern` names no program; a pattern of only whitespace matches no command",
                self.id
            )));
        };
        if crate::interpreter::is_lookthrough_wrapper(program) {
            return Err(UsageError::raise(format!(
                "rule {}: `pattern` names the wrapper `{program}`, which the matcher looks THROUGH to judge the program it wraps; name that program instead",
                self.id
            )));
        }
        if crate::config_model::is_env_assignment(program) {
            return Err(UsageError::raise(format!(
                "rule {}: `pattern` starts with the environment assignment `{program}`, which the matcher steps past; name the program instead",
                self.id
            )));
        }
        if let Some(flag) = wanted.iter().find(|word| word.starts_with('-')) {
            return Err(UsageError::raise(format!(
                "rule {}: `pattern` requires the flag `{flag}`, and the matcher compares operand words with flags already dropped; use `contains` for a flag",
                self.id
            )));
        }
        Ok(())
    }

    fn validate_admission_columns(&self) -> anyhow::Result<()> {
        for (name, token, wanted, wanted_name, base_reason) in [
            (
                "retires_with",
                self.retires_with.as_deref(),
                Direction::NonDecreasing,
                "DECREASE",
                "the rev a subject must have been alive at",
            ),
            (
                "admits_with",
                self.admits_with.as_deref(),
                Direction::NonIncreasing,
                "INCREASE",
                "an increase is only decidable against the tree a file was absent from",
            ),
        ] {
            let Some(token) = token else {
                continue;
            };
            if self.base.is_none() {
                return Err(UsageError::raise(format!(
                    "rule {}: `{name}` requires `base` — {base_reason}",
                    self.id
                )));
            }
            if token.trim().is_empty() {
                return Err(UsageError::raise(format!(
                    "rule {}: `{name}` cannot be blank — it is the line prefix a declaration is read after, and an empty one matches every line",
                    self.id
                )));
            }
            if self.direction != Some(wanted) {
                return Err(UsageError::raise(format!(
                    "rule {}: `{name}` requires `direction = \"{}\"` — it admits a {wanted_name}, and on a row that refuses the other direction it switches the row off instead of refining it",
                    self.id,
                    wanted.as_str(),
                )));
            }
        }
        Ok(())
    }

    fn validate_conserves(&self) -> anyhow::Result<()> {
        let Some(conserves) = self.conserves.as_ref() else {
            return Ok(());
        };
        if self.retires_with.is_none() {
            return Err(UsageError::raise(format!(
                "rule {}: `conserves` requires `retires_with` — it obliges a mapping INSIDE that column's admission, and a ratchet that admits no decrease has no deletion to map",
                self.id
            )));
        }
        for (name, token) in [
            ("case", &conserves.case),
            ("close", &conserves.close),
            ("carried", &conserves.carried),
            ("subsumed", &conserves.subsumed),
            ("changed", &conserves.changed),
            ("declared_in", &conserves.declared_in),
        ] {
            if token.trim().is_empty() {
                return Err(UsageError::raise(format!(
                    "rule {}: `conserves.{name}` cannot be blank — every token here decides something, and an empty one matches every line",
                    self.id
                )));
            }
        }
        // Blank is refused for the optional arm too, where it is DECLARED: an
        // empty token matches every line, so `withdrawn = ""` would claim every
        // case in the ledger. Absent and blank are different answers, and only the
        // first one means "this row has three arms".
        for (name, token) in [
            ("withdrawn", conserves.withdrawn.as_deref()),
            ("ported", conserves.ported.as_deref()),
        ] {
            if let Some(token) = token
                && token.trim().is_empty()
            {
                return Err(UsageError::raise(format!(
                    "rule {}: `conserves.{name}` is declared but blank — an empty token matches every line, which would claim every case. Remove the key to leave the arm undeclared.",
                    self.id
                )));
            }
        }
        let arms: Vec<&String> = [
            Some(&conserves.carried),
            Some(&conserves.subsumed),
            Some(&conserves.changed),
            conserves.withdrawn.as_ref(),
            conserves.ported.as_ref(),
        ]
        .into_iter()
        .flatten()
        .collect();
        for (index, arm) in arms.iter().enumerate() {
            if arms[index + 1..].contains(arm) {
                return Err(UsageError::raise(format!(
                    "rule {}: `conserves` spells two arms alike, so \"exactly one arm\" cannot be decided — one line would claim a case twice",
                    self.id
                )));
            }
        }
        Selector::new(&conserves.declared_in)?;
        Ok(())
    }

    fn validate_remediation(&self) -> anyhow::Result<()> {
        if let Some(why) =
            crate::remedy::malformed(self.fix.as_deref(), self.no_fix_reason.as_deref())
        {
            return Err(UsageError::raise(format!("rule {}: {why}", self.id)));
        }
        // `no_retry_reason` WITHOUT a repair says why something that never runs
        // does not hand back — a sentence about nothing (CLOUD-1639). The
        // converse (a `fix` with no `no_retry_reason`) is legal and is the
        // ordinary `retry` row; what makes it owed is the CLASS declaring
        // `silent`, which is a cross-table question and lives in
        // `crate::policy::check_repairs_are_applicable`.
        if self.no_retry_reason.is_some() && self.fix.is_none() {
            return Err(UsageError::raise(format!(
                "rule {}: `no_retry_reason` says why a repair does not hand the call back, and \
                 this row declares no `fix` to repair with",
                self.id
            )));
        }
        Ok(())
    }

    fn validate_ceiling(&self) -> anyhow::Result<()> {
        let declared: Vec<&str> = [
            ("measures", self.measures.is_some()),
            ("counts", self.counts.is_some()),
            ("max", self.max.is_some()),
        ]
        .into_iter()
        .filter_map(|(name, present)| present.then_some(name))
        .collect();
        if declared.is_empty() {
            // A rewrite table with no ceiling to serve rewrites nothing, and
            // reads from the file as though it narrowed a count.
            if !self.resolves.is_empty() {
                return Err(UsageError::raise(format!(
                    "rule {}: `resolves` needs a `counts = \"tracked-artifacts\"` ceiling to \
                     serve; on its own it rewrites nothing",
                    self.id
                )));
            }
            return Ok(());
        }
        if declared.len() != 3 {
            return Err(UsageError::raise(format!(
                "rule {}: a per-call ceiling needs `measures`, `counts` and `max` together; \
                 this row carries only {}. A partial ceiling measures something it cannot \
                 decide over, or caps a number whose unit is unstated",
                self.id,
                declared.join(" and ")
            )));
        }
        // TOOL-KEYED ONLY, and narrower than the column census can say.
        //
        // A ceiling is a modifier over a selection, and the only selection it has
        // a consumer for is a tool: CLOUD-312's row 6 is `fanout-guard`, which
        // fires on `Task`. Admitting it on a `pattern` row would ship a
        // combination with no test behind it and no caller asking for it, and
        // `rules/rust.md`'s reading is that the cheap default is the one
        // direction the mistake is expensive in. Widening this is one line plus
        // the cases that prove it.
        if self.tool.is_none() {
            return Err(UsageError::raise(format!(
                "rule {}: a per-call ceiling is keyed on `tool` — the ceiling decides whether \
                 that selection refuses, and a command-keyed one has no consumer yet",
                self.id
            )));
        }
        // A lint count measures a file, not a call: it has nothing to read on an
        // envelope.
        if self.counts == Some(CeilingUnit::LintEscapes) {
            return Err(UsageError::raise(format!(
                "rule {}: `lint_escapes` is a ratchet's file measure; a per-call ceiling \
                 counts `tokens` or `tracked_artifacts`",
                self.id
            )));
        }
        // A rewrite table only means something to the unit that resolves paths.
        // On a token ceiling it would load, rewrite nothing, and read as a
        // narrowing — the inert-coverage failure this whole surface refuses.
        if !self.resolves.is_empty() && self.counts != Some(CeilingUnit::TrackedArtifacts) {
            return Err(UsageError::raise(format!(
                "rule {}: `resolves` belongs to `counts = \"tracked-artifacts\"`; a token \
                 ceiling resolves no paths",
                self.id
            )));
        }
        // Compiled at load, the way `regex`, `exclude` and `content` are: left to
        // adjudication an unparseable expression is skipped on every call, which
        // makes the ceiling count LESS than it should — the permissive direction,
        // and silent.
        for rewrite in &self.resolves {
            Regex::new(&rewrite.reference).map_err(|err| {
                UsageError::raise(format!(
                    "rule {}: `resolves.reference` is not a valid regular expression: {err}",
                    self.id
                ))
            })?;
        }
        Ok(())
    }

    fn refuse_argv_modifiers(&self, keyed_on: &str) -> anyhow::Result<()> {
        for (field, present) in [
            ("contains", self.contains.is_some()),
            ("unless_contains", self.unless_contains.is_some()),
            ("word", self.word.is_some()), // the argv's own words
            ("unless_word", self.unless_word.is_some()), // the argv's own words, exempting
            ("require_via", self.require_via.is_some()),
        ] {
            if present {
                return Err(self.modifier_refused(keyed_on, field));
            }
        }
        Ok(())
    }

    fn modifier_refused(&self, keyed_on: &str, field: &str) -> anyhow::Error {
        UsageError::raise(format!(
            "rule {}: kind \"{}\" keyed on `{keyed_on}` cannot carry `{field}`; \
             that column narrows a command line, and this row names none",
            self.id,
            self.kind.as_str()
        ))
    }

    fn validate_on_columns(&self) -> anyhow::Result<()> {
        self.refuse_argv_modifiers("on")?;
        for (field, present) in [
            ("when_absent", self.when_absent.is_some()),
            ("when_present", self.when_present.is_some()),
            ("when_value", self.when_value.is_some()),
        ] {
            if present {
                return Err(self.modifier_refused("on", field));
            }
        }
        Ok(())
    }

    fn validate_delta_base(&self) -> anyhow::Result<()> {
        match (self.receipt_key(), self.key_base.as_deref()) {
            (ReceiptKey::Delta, None) => Err(UsageError::raise(format!(
                "rule {}: `key = \"delta\"` requires `key_base` — the ref the identity is taken \
                 against. Without one the change has no second side to diff, so the receipt \
                 would be keyed on nothing and no call could ever satisfy it",
                self.id
            ))),
            (key, Some(_)) if key != ReceiptKey::Delta => Err(UsageError::raise(format!(
                "rule {}: `key_base` belongs to `key = \"delta\"`; a {} receipt is keyed on a ref \
                 or a value rather than on a diff, so there is nothing to take a base against",
                self.id,
                match key {
                    ReceiptKey::Head => "head-keyed",
                    ReceiptKey::Branch => "branch-keyed",
                    ReceiptKey::Named => "named-keyed",
                    ReceiptKey::Delta => unreachable!("guarded by the arm above"),
                }
            ))),
            _ => Ok(()),
        }
    }

    fn validate_receipt_selectors(&self) -> anyhow::Result<()> {
        match self.receipt_trigger() {
            // A command-triggered row selecting on NOTHING matches every
            // mediated call, turning a precondition into a universal gate.
            // `tool` satisfies the obligation as well as `pattern` does
            // (CLOUD-924): both name what the row is about, one by command line
            // and one by the tool a structured call names — and CLOUD-312's rows
            // 1-3 are precisely the second shape.
            ReceiptTrigger::Command
                if self.pattern.is_none() && self.tool.is_none() && self.on.is_none() =>
            {
                return Err(UsageError::raise(format!(
                    "rule {}: kind \"receipt\" with `trigger = \"command\"` (the default) requires `pattern` (the command whose precondition this is) or `tool` (the tool a structured call names)",
                    self.id
                )));
            }
            // Both columns key on one call, and a row carrying both is two
            // selectors where a reader can see one — `validate_shape_columns`'
            // argument, on the kind that shares the columns.
            ReceiptTrigger::Command
                if [
                    self.pattern.is_some(),
                    self.tool.is_some(),
                    self.on.is_some(),
                ]
                .into_iter()
                .filter(|present| *present)
                .count()
                    > 1 =>
            {
                return Err(UsageError::raise(format!(
                    "rule {}: kind \"receipt\" carries both `pattern` and `tool`; a row is keyed on a command line or on the tool a call names, never on both",
                    self.id
                )));
            }
            // A write carries no command line, so either column would sit there
            // matching nothing while reading as a narrowing. `tool` is NOT
            // refused here: a write tool has a name, and keying a write-triggered
            // row to one is how a precondition narrows from every write to the
            // writes a particular tool makes.
            ReceiptTrigger::Write if self.on.is_some() => {
                return Err(UsageError::raise(format!(
                    "rule {}: kind \"receipt\" with `trigger = \"write\"` cannot carry `on`; the event is a call, not a write",
                    self.id
                )));
            }
            ReceiptTrigger::Write if self.pattern.is_some() || self.contains.is_some() => {
                return Err(UsageError::raise(format!(
                    "rule {}: kind \"receipt\" with `trigger = \"write\"` takes neither `pattern` nor `contains` — a write has no command line for either to match",
                    self.id
                )));
            }
            _ => {}
        }
        if self.on.is_some() {
            self.validate_on_columns()?;
        }
        Ok(())
    }

    fn validate_receipt_columns(&self) -> anyhow::Result<()> {
        if self.kind != RuleKind::Receipt {
            return Ok(());
        }
        // `key = "branch"` was refused from this same spot until the
        // branch-keyed store existed; every refusal here has that one's
        // reasoning — a column that reads as configured and decides nothing is
        // the defect this kind was added to close.
        self.validate_receipt_selectors()?;
        // THE `named` KEY AND ITS PROJECTION TRAVEL TOGETHER (CLOUD-987), and
        // both halves are refused because each is a different silent failure.
        //
        // A `named` key with no projection has no subject, so it would read one
        // file for every call — `ReceiptKey::Branch` under another name, and the
        // collapse that variant's doc refuses. A projection with some other key
        // is a column that reads as configured and is never consulted.
        match (self.receipt_key(), self.key_from) {
            (ReceiptKey::Named, None) => {
                return Err(UsageError::raise(format!(
                    "rule {}: `key = \"named\"` requires `key_from` — the projection that supplies \
                     the subject. Without one the receipt would be keyed on nothing and read the \
                     same file for every call",
                    self.id
                )));
            }
            (key, Some(_)) if key != ReceiptKey::Named => {
                return Err(UsageError::raise(format!(
                    "rule {}: `key_from` belongs to `key = \"named\"`; a {} receipt takes its \
                     subject from the checkout, not from the call",
                    self.id,
                    match key {
                        ReceiptKey::Head => "head-keyed",
                        ReceiptKey::Branch => "branch-keyed",
                        ReceiptKey::Named => unreachable!("guarded by the arm above"),
                        ReceiptKey::Delta => "delta-keyed",
                    }
                )));
            }
            _ => {}
        }
        self.validate_delta_base()?;
        // COMPILED AT LOAD, for the reason `resolves.reference` is and with the
        // failure running the same direction: left to adjudication an unparseable
        // expression is discarded per call, the subject resolves to absent,
        // `verdicts` reads that as could-not-look, and the call is ALLOWED. So a
        // typo silently disables the row it was meant to qualify — the permissive
        // direction, and invisible.
        //
        // This clause is here because the column shipped without it while its own
        // doc comment claimed it: caught in review on #680, and the comment was
        // the worse half, because a stated invariant is what stops the next reader
        // checking.
        if let Some(shape) = self.key_shape.as_deref() {
            Regex::new(shape).map_err(|err| {
                UsageError::raise(format!(
                    "rule {}: `key_shape` is not a valid regular expression: {err}",
                    self.id
                ))
            })?;
        }
        // A zero bound expires a receipt the instant it is written, so the row
        // refuses every call it selects while reading from the file as though it
        // permitted a fresh one. Same shape as the empty-`checks` refusal below:
        // a column whose value makes the row unsatisfiable is a config error, not
        // a very strict policy.
        if self.max_age == Some(0) {
            return Err(UsageError::raise(format!(
                "rule {}: `max_age = 0` expires every receipt the moment it is written, so no call \
                 can satisfy this row; name the number of seconds a receipt stays good for",
                self.id
            )));
        }
        // Refused for `validate_shape_columns`' reason, on the kind that shares
        // the column: an empty selector would match the empty final segment of
        // every name ending in `__`.
        if self.tool.as_deref().is_some_and(str::is_empty) {
            return Err(UsageError::raise(format!(
                "rule {}: `tool` is empty; name the tool this row is about",
                self.id
            )));
        }
        // Both halves of the field bound are refused for the reason `max_age = 0`
        // is: a value that makes the column decide nothing reads from the file as
        // though it decided something. `at = 0` names no field under 1-indexed
        // counting, so it can never match and the row would satisfy every call
        // through the absent-is-could-not-look arm; an empty `is` would be
        // satisfied only by a receipt field that is itself empty, which the
        // whitespace split cannot produce.
        if let Some(bound) = self.requires_field.as_ref() {
            if bound.at == 0 {
                return Err(UsageError::raise(format!(
                    "rule {}: `requires_field.at = 0` names no field — receipt fields are counted \
                     from 1, as every reader of these receipts already counts them",
                    self.id
                )));
            }
            if bound.is.is_empty() {
                return Err(UsageError::raise(format!(
                    "rule {}: `requires_field.is` is empty, so no receipt field can ever match it \
                     and the row would decide nothing; name the value that satisfies this row",
                    self.id
                )));
            }
        }
        self.validate_receipt_names()?;
        self.validate_marker()
    }

    fn validate_marker(&self) -> anyhow::Result<()> {
        let Some(marker) = self.while_marker.as_deref() else {
            return Ok(());
        };
        if crate::config_model::BRANCH_KEYED_RECEIPTS.contains(&marker) {
            return Ok(());
        }
        Err(UsageError::raise(format!(
            "rule {}: `while_marker = \"{marker}\"` names no branch-keyed receipt family, so \
             landing would not clear it and the row would deny forever — including on the next \
             piece of work to reuse the branch name. Name one of: {}",
            self.id,
            crate::config_model::BRANCH_KEYED_RECEIPTS.join(", ")
        )))
    }

    fn validate_receipt_names(&self) -> anyhow::Result<()> {
        // A row naming an empty `checks` list gates its trigger on nothing and
        // allows every call, which reads as coverage from the file.
        if self.checks.as_ref().is_some_and(Vec::is_empty) {
            return Err(UsageError::raise(format!(
                "rule {}: kind \"receipt\" requires at least one entry in `checks`; an empty list gates nothing",
                self.id
            )));
        }
        // The same refusal for the alternation, and it is worth its own arm
        // rather than folding into the one above: an empty ALTERNATION is
        // satisfied by nothing, so a row carrying one can never allow a call at
        // all. That fails in the opposite direction to an empty conjunction —
        // one gates nothing, the other gates everything — and a reader handed a
        // single message would be told the wrong thing about their row.
        if self.checks_any.as_ref().is_some_and(Vec::is_empty) {
            return Err(UsageError::raise(format!(
                "rule {}: kind \"receipt\" requires at least one entry in `checks_any`; an empty alternation is satisfied by no receipt, so the row could never allow a call",
                self.id
            )));
        }
        // CLOUD-1297's conditional requirement, standing in for the `checks`
        // entry `RuleKind::permits` used to carry. A row naming NEITHER column
        // gates its trigger on nothing and allows every call — the same defect
        // the empty-`checks` arm above refuses, arrived at by omission rather
        // than by an empty list, and the census cannot express "one of these
        // two".
        if self.checks.is_none() && self.checks_any.is_none() {
            return Err(UsageError::raise(format!(
                "rule {}: kind \"receipt\" requires `checks` (every named receipt must be valid) or `checks_any` (any one of them), or both; a row naming neither gates its trigger on nothing",
                self.id
            )));
        }
        Ok(())
    }

    fn validate_ask_disposition(&self) -> anyhow::Result<()> {
        // A tree-scoped rule has no caller to ask: `batten check` walks a
        // repository and answers to whoever ran it, so there is no in-band
        // decision channel and no call to hold open. Accepting `ask` there and
        // rendering it as a deny would be a downgrade nobody wrote down — the
        // shape this repository refuses everywhere else — so it is exit 1 here.
        //
        // The `reason` requirement is the same one a deny carries and for a
        // sharper version of the same purpose: an escalation reaches a HUMAN as
        // the entire explanation, with none of the surrounding output a check
        // run has. A refusal that reads "denied by rule 7" is poor; an escalation
        // that reads that way is unanswerable.
        if self.severity == Some(crate::severity::RuleSeverity::Ask) {
            if self.scope != RuleScope::MediatedCall {
                return Err(UsageError::raise(format!(
                    "rule {}: `severity = \"ask\"` hands the decision to a human, and a \
                     `scope = \"{}\"` rule has no caller to hand it to — a repository walk \
                     answers to whoever ran it. Use `deny`, or move the row to \
                     `scope = \"mediated_call\"`",
                    self.id,
                    self.scope.as_str(),
                )));
            }
            if self.reason.as_ref().is_none_or(|it| it.trim().is_empty()) {
                return Err(UsageError::raise(format!(
                    "rule {}: `severity = \"ask\"` requires a `reason` — it reaches a person \
                     as the whole explanation, with none of the output a check run carries \
                     around it",
                    self.id,
                )));
            }
        }
        Ok(())
    }

    fn validate_repository_state(&self) -> anyhow::Result<()> {
        if self.tags.iter().any(String::is_empty) {
            return Err(UsageError::raise(format!(
                "rule {}: `tags` carries an empty glob, which lists no tag and would read as \
                 a repository that has none",
                self.id
            )));
        }
        if let Some(key) = self
            .git_config
            .iter()
            .find(|key| !crate::git::config_key_parses(key))
        {
            return Err(UsageError::raise(format!(
                "rule {}: `git_config` key `{key}` is not one git can address — a key is \
                 `section.name` or `section.subsection.name`, and this one would read as unset \
                 forever",
                self.id
            )));
        }
        if let Some(spec) = self
            .index
            .iter()
            .find(|spec| !crate::git::pathspec_is_supported(spec))
        {
            return Err(UsageError::raise(format!(
                "rule {}: `index` pathspec `{spec}` is empty or uses pathspec magic, which this \
                 build does not implement; read as a literal it would select nothing",
                self.id
            )));
        }
        Ok(())
    }

    fn validate_policy_source(&self) -> anyhow::Result<()> {
        // A QUALIFIER WITH NOTHING TO QUALIFY IS THE DEAD COLUMN THIS ROW EXISTS
        // TO END (CLOUD-1625). `provider` selects among a preset's modules and is
        // read nowhere else, so a row declaring it without `preset` — on this kind
        // or any other — parses, loads, and has the key read by nothing, which is
        // exactly the silence `columns()`'s census refuses one layer over. Checked
        // BEFORE the kind guard, because the wrong kind is the case where the
        // silence is total.
        if self.provider.is_some() && self.preset.is_none() {
            return Err(UsageError::raise(format!(
                "rule {}: `provider` qualifies `preset`, and this row names no preset; \
                 nothing reads the column, so it would declare a CI provider that \
                 selects nothing",
                self.id
            )));
        }
        // `except` qualifies `preset` exactly as `provider` does (CLOUD-2290).
        if !self.except.is_empty() && self.preset.is_none() {
            return Err(UsageError::raise(format!(
                "rule {}: `except` names modules of a preset to skip, and this row names \
                 no preset; nothing reads the column, so it would skip nothing",
                self.id
            )));
        }
        if self.kind != RuleKind::Policy {
            return Ok(());
        }
        // A policy row names exactly one source, and `permits` cannot say so —
        // a flat column list has no "one of" (CLOUD-833). Same split
        // `Document`'s `pattern`/`reads` pair already carries, and the same
        // reason: a row with both is a load error rather than a precedence rule
        // nobody can read.
        let sources = [
            self.module.as_deref().map(|_| "module"),
            self.bundle.as_deref().map(|_| "bundle"),
            self.preset.as_deref().map(|_| "preset"),
        ];
        let named: Vec<&str> = sources.into_iter().flatten().collect();
        match named.len() {
            0 => {
                return Err(UsageError::raise(format!(
                    "rule {}: kind \"policy\" requires one of `module` (one file), \
                         `bundle` (a folder) or `preset` (a vendored bundle); a row naming \
                         none enables no policy and could only ever decide nothing",
                    self.id
                )));
            }
            1 => {}
            _ => {
                return Err(UsageError::raise(format!(
                    "rule {}: kind \"policy\" takes exactly one of `module`, `bundle` or \
                         `preset`, and this names {}; two sources for one row is a precedence \
                         question nobody should have to answer",
                    self.id,
                    named.join(" and ")
                )));
            }
        }
        // THE COLUMN REFUSAL IS DERIVED (CLOUD-1282). Six hand-written blocks
        // stood here — `documents`, `sources`, `lines`, `line_sources`, `uses`,
        // `invocations` — and the second one's own comment recorded how the list
        // grew: "`sources` and `lines` are tree columns for the same reason
        // `documents` is, and they were added to `permits` without this."
        //
        // So the list was already KNOWN to lag the struct, and it still did:
        // `git`, `refs`, `ranges`, `commits`, `staged`, `history`, `state`,
        // `forge`, `tools`, `captured`, `landing`, `delta_sources`, `external`
        // and `symbols` were all declarable on a mediated row, and each parsed,
        // loaded, was never acquired for that scope, and left the module reading
        // the corresponding `input.tree.*` key deciding nothing — CLOUD-845's
        // dead-gate class one layer up.
        //
        // Adding fourteen more names is the wrong fix and is the mechanism that
        // produced the gap. `COLUMN_CENSUS` says which FACT each column
        // declares, `Fact::class().surface` says where that fact resolves, and
        // the two together answer for a column added tomorrow with no edit here.
        if self.scope == RuleScope::MediatedCall
            && let Some(column) = self.tree_only_column()
        {
            return Err(UsageError::raise(format!(
                "rule {}: `{}` declares `{}`, a fact resolvable only on the {} surface, and this \
                 row is `scope = \"mediated_call\"` — the column would parse, load, and never be \
                 acquired, leaving a module that reads it deciding nothing",
                self.id,
                column.field,
                column.fact.as_str(),
                column.fact.class().surface.as_str(),
            )));
        }
        // A MALFORMED SELECTOR IS A CONFIG FAULT, REFUSED HERE. `acquire_declared`
        // and `policy_rule` both discard the error `declared_documents` returns —
        // deliberately, because by then the run is under way — so without this the
        // row would be SILENTLY SKIPPED under `check` while `policy test` (which
        // propagates it) hard-failed. A bad pattern disabling a gate quietly is
        // the exact failure CLOUD-845 and CLOUD-850 exist to close, and adding a
        // column without this check reopened it for the new field.
        for pattern in &self.sources {
            Selector::new(pattern).map_err(|err| {
                UsageError::raise(format!(
                    "rule {}: `sources` pattern `{pattern}` is not valid: {err}",
                    self.id
                ))
            })?;
        }
        // CLOUD-843, for the reason the selector check above states: a
        // declaration the acquisition could only ever answer wrongly is a config
        // fault at load, never a gate that quietly decides over nothing.
        self.validate_repository_state()?;
        // A DECLARED DOCUMENT THIS BUILD CAN NEVER PARSE IS A CONFIG FAULT, not
        // a verdict (CLOUD-845). It used to be neither: `tree_document` checked
        // the extension BEFORE any I/O and dropped the path into `missing`, so
        // `policy_rule` skipped the whole rule — silently, green, without the
        // file ever being opened. A row declaring a prose, script or
        // configuration-language path this build parses none of therefore looked
        // exactly like a row whose document was absent, and a migrated gate could
        // go dead by declaring the wrong extension just as surely as by naming a
        // field the engine never emits.
        //
        // The split is what §5's exit-1 attaches to: no state of the filesystem
        // makes an unparseable extension parseable, so reporting it as
        // could-not-look would report a permanent authoring error as a transient
        // one. Absent, unreadable and unparsed stay verdicts; this one is caught
        // at load, where a config error belongs.
        for path in &self.documents {
            if crate::facts::Format::for_path(path).is_none() {
                return Err(UsageError::raise(format!(
                    "rule {}: `documents` names `{path}`, whose extension this build has no \
                     parser for — the row would skip silently rather than decide. Parseable \
                     extensions are {}",
                    self.id,
                    crate::facts::parseable_extensions()
                )));
            }
        }
        self.validate_declared_format_matches_glob()?;
        // THE CONVERSE WAS A REFUSAL AND IS NOT ONE ANY MORE (CLOUD-845). It
        // read: a tree row with no declared documents "is handed an empty tree
        // and decides nothing about the repository", so refusing it was better
        // than letting it read as a configured gate.
        //
        // That reasoning was exactly right while `documents` was the ONLY thing
        // the tree document carried. It is not any more: `tracked` is emitted on
        // every tree evaluation, from the walk the run already did, so a row
        // declaring no documents is handed the checkout's path list and can
        // decide plenty about the repository — `no-docs-tree`-shaped predicates
        // over *which files exist* are precisely that row, and CLOUD-846 counts
        // three of the twenty tree-scoped gates that read no file literals at
        // all.
        //
        // The bound the old refusal protected still holds and is unweakened,
        // because it was a bound on CONTENT: a row still reads no file it did
        // not name. `tracked` is paths, costs nothing per rule, and cannot carry
        // a byte of any file — which is why widening here does not widen what a
        // module may see of a file's insides.
        Ok(())
    }

    fn validate_declared_format_matches_glob(&self) -> anyhow::Result<()> {
        let (Some(declared), Some(glob)) = (self.format, self.glob.as_deref()) else {
            return Ok(());
        };
        let Some(named) = crate::facts::Format::for_path(glob) else {
            return Ok(());
        };
        if named == declared {
            return Ok(());
        }
        Err(UsageError::raise(format!(
            "rule {}: `glob` is `{glob}`, whose extension names {}, but `format` says {} — one \
             of the two is wrong, and the pairing is admitted by neither. Declare `format = \
             \"{}\"` to read the file as its extension says. (Checked on the literal extension \
             a glob ends in; a computed glob is not checked.)",
            self.id,
            named.as_str(),
            declared.as_str(),
            named.as_str()
        )))
    }

    fn columns(&self) -> [(&'static str, bool); 64] {
        [
            // In the census because it is now per-kind, which is what makes
            // "required by every kind but the judge" a fact the existing
            // machinery decides rather than a special case anyone maintains.
            ("severity", self.severity.is_some()),
            ("criteria", self.criteria.is_some()),
            ("tier", self.tier.is_some()),
            ("no_fix_reason", self.no_fix_reason.is_some()),
            ("no_retry_reason", self.no_retry_reason.is_some()),
            ("glob", self.glob.is_some()),
            ("pattern", self.pattern.is_some()),
            ("regex", self.regex.is_some()),
            ("exclude", self.exclude.is_some()),
            ("content", self.content.is_some()),
            ("tool", self.tool.is_some()),
            ("measures", self.measures.is_some()),
            ("counts", self.counts.is_some()),
            ("max", self.max.is_some()),
            ("resolves", !self.resolves.is_empty()),
            ("when_absent", self.when_absent.is_some()),
            ("when_present", self.when_present.is_some()),
            ("when_value", self.when_value.is_some()),
            ("key_from", self.key_from.is_some()),
            ("key_base", self.key_base.is_some()),
            ("key_shape", self.key_shape.is_some()),
            ("max_age", self.max_age.is_some()),
            ("requires_field", self.requires_field.is_some()),
            ("check", self.check.is_some()),
            ("fix", self.fix.is_some()),
            ("contains", self.contains.is_some()),
            ("unless_contains", self.unless_contains.is_some()),
            ("word", self.word.is_some()),
            ("unless_word", self.unless_word.is_some()),
            ("on", self.on.is_some()),
            ("require_via", self.require_via.is_some()),
            ("requires_key", self.requires_key.is_some()),
            ("reason", self.reason.is_some()),
            ("policy_url", self.policy_url.is_some()),
            ("bypass_env", self.bypass_env.is_some()),
            ("verbatim", self.verbatim.is_some()),
            ("identity_key", self.identity_key.is_some()),
            ("direction", self.direction.is_some()),
            ("base", self.base.is_some()),
            ("retires_with", self.retires_with.is_some()),
            ("conserves", self.conserves.is_some()),
            ("admits_with", self.admits_with.is_some()),
            ("per_file", self.per_file),
            ("format", self.format.is_some()),
            ("node", self.node.is_some()),
            ("derives", self.derives.is_some()),
            ("cites", self.cites.is_some()),
            ("reads", self.reads.is_some()),
            ("module", self.module.is_some()),
            ("checks", self.checks.is_some()),
            ("checks_any", self.checks_any.is_some()),
            ("key", self.key.is_some()),
            ("trigger", self.trigger.is_some()),
            ("verdict", self.verdict.is_some()),
            ("filters", self.filters.is_some()),
            ("substitutes", self.substitutes.is_some()),
            ("interprets", self.interprets.is_some()),
            // CLOUD-2291: a `native` row's whole predicate is which gate.
            ("gate", self.gate.is_some()),
            // `landing` is NOT here, and neither are `git`, `refs` or `ranges`
            // (CLOUD-880, following CLOUD-907). The census drives the per-kind
            // permit/require validation, and a column in it owes an entry in some
            // kind's `permits()` — `every_optional_rule_field_is_classified_by_
            // every_kind` is the gate, and it caught this column the first time it
            // was added here. The four git-family columns are declared reads
            // rather than per-kind capabilities, so they follow their siblings
            // rather than inventing a fifth classification for one of them.
            ("line_sources", !self.line_sources.is_empty()),
            ("invocations", !self.invocations.is_empty()),
            ("invocation_sources", !self.invocation_sources.is_empty()),
            ("uses", !self.uses.is_empty()),
            ("use_sources", !self.use_sources.is_empty()),
            ("unit_sources", !self.unit_sources.is_empty()),
        ]
    }

    fn receipt_trigger(&self) -> ReceiptTrigger {
        self.trigger.unwrap_or_default()
    }

    fn receipt_key(&self) -> ReceiptKey {
        self.key.unwrap_or_default()
    }

    fn validate_pipeline_tables(&self) -> anyhow::Result<()> {
        if self.kind != RuleKind::Pipeline {
            return Ok(());
        }
        for entry in self.verdict.iter().flatten() {
            entry.validate(&self.id)?;
        }
        if self.verdict.as_ref().is_some_and(Vec::is_empty) {
            return Err(UsageError::raise(format!(
                "rule {}: kind \"pipeline\" requires at least one `verdict` entry; with none it judges no command",
                self.id
            )));
        }
        if self.filters.as_ref().is_some_and(Vec::is_empty) {
            return Err(UsageError::raise(format!(
                "rule {}: kind \"pipeline\" requires at least one `filters` entry; with none it cannot recognise the substitution it refuses",
                self.id
            )));
        }
        if self.substitutes.as_ref().is_some_and(Vec::is_empty) {
            return Err(UsageError::raise(format!(
                "rule {}: kind \"pipeline\" requires at least one `substitutes` entry; with none it recognises no substitution",
                self.id
            )));
        }
        if self.interprets.as_ref().is_some_and(Vec::is_empty) {
            return Err(UsageError::raise(format!(
                "rule {}: kind \"pipeline\" requires at least one `interprets` entry; with none it recognises no interpreter",
                self.id
            )));
        }
        // ONE of the two families, whole (CLOUD-864). The per-kind required
        // table cannot express this — it is a disjunction over sibling columns,
        // and that table is a flat list — so the obligation lands here, which is
        // the same place `Receipt`'s conditional `pattern` requirement lives.
        //
        // Stated as a disjunction rather than as "at least one column set" on
        // purpose: a row carrying `verdict` and no `filters` recognises a
        // verdict-bearing command and nothing that could discard it, which
        // matches and decides nothing. Half a family is the inert row, not a
        // narrower gate.
        let discard_family = self.verdict.is_some() && self.filters.is_some();
        let substitution_family = self.substitutes.is_some() || self.interprets.is_some();
        if !discard_family && !substitution_family {
            return Err(UsageError::raise(format!(
                "rule {}: kind \"pipeline\" needs either `verdict` AND `filters` (the discard family) or `substitutes` or `interprets` (the substitution family); with neither it matches nothing",
                self.id
            )));
        }
        Ok(())
    }

    fn validate_external_rows(&self) -> anyhow::Result<()> {
        // THE OUT-OF-ROOT BOUND, REFUSED AT LOAD (CLOUD-1167). Both halves are
        // config faults rather than verdicts: no state of the filesystem makes
        // either admissible, so reporting them as could-not-look would present a
        // permanent authoring error as a transient one — the choice
        // `NotAcquired::UnknownFormat` already makes one layer down.
        //
        // Checked before the kind gate below so it binds every kind that may
        // carry the column, and stated here rather than in the per-kind census
        // because the census is a flat list of column NAMES and this is a
        // property of a column's CONTENTS.
        let mut seen_external: BTreeMap<&str, (&str, &str)> = BTreeMap::new();
        for row in &self.external {
            if row.id.trim().is_empty() {
                return Err(UsageError::raise(format!(
                    "rule {}: an `external` row needs a non-empty `id`; it is the key the file is projected under and a module has no other way to name it",
                    self.id
                )));
            }
            if row.root.trim().is_empty() {
                return Err(UsageError::raise(format!(
                    "rule {}: `external` row {:?} needs a non-empty `root`; it is the NAME of the environment variable the path resolves beneath, and an empty one would resolve against the process's working directory",
                    self.id, row.id
                )));
            }
            // THE ANTI-ESCAPE HALF. A declaration that can walk back out of the
            // root it named is a scanner with extra steps, and this is the one
            // place it can be refused for good rather than per run.
            if row.path.trim().is_empty() || row.escapes() {
                return Err(UsageError::raise(format!(
                    "rule {}: `external` row {:?} needs a `path` that is relative and stays beneath its root; an absolute path or a `..` component would read outside the root the row declared, which is the bound this column exists to hold",
                    self.id, row.id
                )));
            }
            // THE ONE-ID-ONE-FILE HALF. Acquisition caches by id across the whole
            // rule set, so two rows declaring one id differently would resolve by
            // whichever row the loop reached first — a silent precedence rule
            // over which file a module actually reads. `Wanted` records the same
            // lesson one family over, where keying a cache on the path alone
            // starved the losing row.
            if let Some((root, path)) = seen_external.insert(&row.id, (&row.root, &row.path))
                && (root != row.root || path != row.path)
            {
                return Err(UsageError::raise(format!(
                    "rule {}: `external` id {:?} is declared twice with different roots or paths; one id names one file, or which file a module reads depends on rule order",
                    self.id, row.id
                )));
            }
        }
        Ok(())
    }

    fn validate_tool_rows(&self) -> anyhow::Result<()> {
        let mut seen: BTreeMap<&str, &crate::facts::ToolQuery> = BTreeMap::new();
        for row in &self.tools {
            if row.id.trim().is_empty() || row.input.trim().is_empty() {
                return Err(UsageError::raise(format!(
                    "rule {}: a `tools` row needs a non-empty `id` and `input`; the id is the key the verdict is projected under, and the input is the file whose digest keys the record",
                    self.id
                )));
            }
            // THE AMBIGUOUS-KEY HALF. The three components are joined into one
            // record name, so a component carrying the separator or a path
            // component would let two different declarations compose the same
            // key — two questions with one answer, decided by whichever producer
            // wrote last.
            if row.malformed() {
                return Err(UsageError::raise(format!(
                    "rule {}: `tools` row {:?} needs a `tool` and `version` that are non-empty and carry no `{}` or path separator; all three key components are joined into one record name, and a separator inside one would let two declarations compose the same key",
                    self.id,
                    row.id,
                    crate::facts::KEY_SEPARATOR
                )));
            }
            // THE ONE-ID-ONE-KEY HALF, for `external`'s reason: acquisition keys
            // by id, so two rows declaring one id differently would resolve by
            // whichever the loop reached first — a silent precedence rule over
            // which verdict a module actually reads.
            if let Some(first) = seen.insert(&row.id, row)
                && (first.tool != row.tool
                    || first.version != row.version
                    || first.input != row.input)
            {
                return Err(UsageError::raise(format!(
                    "rule {}: `tools` id {:?} is declared twice with different keys; one id names one verdict, or which record a module reads depends on rule order",
                    self.id, row.id
                )));
            }
        }
        Ok(())
    }

    fn validate_minted_rows(&self) -> anyhow::Result<()> {
        let mut seen: BTreeMap<&str, &crate::facts::MintedQuery> = BTreeMap::new();
        for row in &self.minted {
            if row.malformed() {
                return Err(UsageError::raise(format!(
                    "rule {}: a `minted` row needs a non-empty `id` and a `mint` that is non-empty and carries no path separator; the mint names the receipt files this reads and a separator would send it outside the store",
                    self.id
                )));
            }
            // THE TWO-COLUMNS-ARE-DIFFERENT HALF. The value and the time it was
            // read are different columns of one line; declaring them the same
            // index projects the timestamp as the value while the bound compares
            // the timestamp against itself, so the row is always fresh and always
            // answers with a clock. It reads as a working gate.
            if row.field == row.recency {
                return Err(UsageError::raise(format!(
                    "rule {}: `minted` row {:?} declares `field` and `recency` at the same index {}; the value and the time it was read are different columns, and collapsing them projects the timestamp as the value while the age bound compares it against itself",
                    self.id, row.id, row.field
                )));
            }
            // THE ONE-ID-ONE-QUESTION HALF, for `tools`' reason one function up:
            // acquisition keys by id, so two rows declaring one id differently
            // would resolve by whichever the loop reached first.
            if let Some(first) = seen.insert(&row.id, row)
                && (first.mint != row.mint
                    || first.field != row.field
                    || first.recency != row.recency
                    || first.max_age_days != row.max_age_days)
            {
                return Err(UsageError::raise(format!(
                    "rule {}: `minted` id {:?} is declared twice with different questions; one id names one field of one mint at one bound, or which reading a module gets depends on rule order",
                    self.id, row.id
                )));
            }
        }
        Ok(())
    }

    fn validate_sink(&self) -> anyhow::Result<()> {
        if self.produces.is_none() {
            return Ok(());
        }
        // THE ROW'S OWN SCOPE, not the kind's CAPABILITY, and the difference is a
        // real hole the first version left. `RuleKind::Policy` scopes to BOTH
        // surfaces, so `kind.scopes().contains(&Tree)` is true for a policy row
        // configured `scope = "mediated_call"` — it passed validation, the tree
        // runner skipped it as another surface's business, `requested_sinks`
        // excluded it as not-evaluated, and the declared record was never
        // written. Exactly the inert-coverage failure this function exists to
        // refuse, reached through the one kind that spans both scopes.
        if self.scope != RuleScope::Tree {
            return Err(UsageError::raise(format!(
                "rule {}: `produces` on a `{}`-scoped row, which is decided by `adjudicate` \
                 rather than by a findings scan; there is nothing for a sink to summarise \
                 and the record would never be written",
                self.id,
                self.scope.as_str()
            )));
        }
        Ok(())
    }

    fn validate_exclude_paths(&self) -> anyhow::Result<()> {
        if self.exclude_paths.is_empty() {
            return Ok(());
        }
        if self.glob.is_none() {
            return Err(UsageError::raise(format!(
                "rule {}: `exclude_paths` subtracts from `glob`, and this row declares none — \
                 it would narrow nothing while reading as a narrowing",
                self.id
            )));
        }
        if self.kind == RuleKind::Ratchet {
            return Err(UsageError::raise(format!(
                "rule {}: kind \"ratchet\" counts the base rev with its own glob, which cannot \
                 read `exclude_paths`; the two sides would select different sets and the \
                 working side could never rise above the base, so the gate could not fail",
                self.id
            )));
        }
        Ok(())
    }

    fn validate_document_predicate(&self) -> anyhow::Result<()> {
        if self.kind != RuleKind::Document {
            return Ok(());
        }
        match (self.pattern.is_some(), self.reads.is_some()) {
            (true, true) => Err(UsageError::raise(format!(
                "rule {}: `pattern` and `reads` are alternatives; a row carries exactly one, \
                 never both",
                self.id
            ))),
            (false, false) => Err(UsageError::raise(format!(
                "rule {}: kind \"document\" requires `pattern` (a literal) or `reads` (another \
                 rule's derived value)",
                self.id
            ))),
            _ => Ok(()),
        }
    }

    fn validate_ratchet_measure(&self) -> anyhow::Result<()> {
        if self.kind != RuleKind::Ratchet {
            return Ok(());
        }
        if let Some(unit) = self.counts {
            // A LINT COUNT NAMES ITS LINT IN `pattern`, and is the one measure
            // that takes it: the lint is the counter's subject, not a token.
            if unit == CeilingUnit::LintEscapes {
                if self.pattern.is_none() || self.regex.is_some() {
                    return Err(UsageError::raise(format!(
                        "rule {}: `counts = \"lint_escapes\"` names its lint in `pattern` \
                         (`clippy::disallowed_types`), and takes no `regex`",
                        self.id
                    )));
                }
                return Ok(());
            }
            if unit != CeilingUnit::Tokens {
                return Err(UsageError::raise(format!(
                    "rule {}: a ratchet counts `tokens`, `lint_escapes` or a literal; \
                     `counts = {unit:?}` measures a call, not a file",
                    self.id
                )));
            }
            if self.pattern.is_some() || self.regex.is_some() {
                return Err(UsageError::raise(format!(
                    "rule {}: `counts`, `pattern` and `regex` are alternatives; a ratchet \
                     counts exactly one",
                    self.id
                )));
            }
        }
        if self.per_file && (self.retires_with.is_some() || self.conserves.is_some()) {
            return Err(UsageError::raise(format!(
                "rule {}: `per_file` judges each file on its own, and `retires_with` and \
                 `conserves` buy an aggregate decrease a per-file row does not have",
                self.id
            )));
        }
        Ok(())
    }

    fn validate_forbid_predicate(&self) -> anyhow::Result<()> {
        if !matches!(self.kind, RuleKind::Forbid | RuleKind::Ratchet) {
            return Ok(());
        }
        self.validate_ratchet_measure()?;
        if self.kind == RuleKind::Ratchet && self.counts.is_some() {
            // The token measure stands in for both literal columns, and
            // `validate_ratchet_measure` has refused it beside either.
            return Ok(());
        }
        match (self.pattern.is_some(), self.regex.is_some()) {
            (true, true) => {
                return Err(UsageError::raise(format!(
                    "rule {}: `pattern` and `regex` are alternatives; a row carries exactly one, \
                     never both",
                    self.id
                )));
            }
            (false, false) => {
                return Err(UsageError::raise(format!(
                    "rule {}: kind \"{}\" requires `pattern` (a literal) or `regex` (a shape)",
                    self.id,
                    self.kind.as_str()
                )));
            }
            _ => {}
        }
        for (column, expression) in [("regex", &self.regex), ("exclude", &self.exclude)] {
            if let Some(expression) = expression {
                Regex::new(expression).map_err(|err| {
                    UsageError::raise(format!("rule {}: `{column}` is not valid: {err}", self.id))
                })?;
            }
        }
        Ok(())
    }

    fn tree_only_column(&self) -> Option<TreeOnlyColumn> {
        COLUMN_CENSUS
            .iter()
            .find_map(|column| match column.declares {
                Declares::Fact(fact, declared)
                    if fact.class().surface != crate::facts::Surface::Hook && declared(self) =>
                {
                    Some(TreeOnlyColumn {
                        field: column.field,
                        fact,
                    })
                }
                Declares::Fact(..) | Declares::NotFactBearing(_) => None,
            })
    }
}

impl Located<'_> {
    /// `<source>:<line>` for the row declaring `id`, or `<source>` where the
    /// declaration cannot be located.
    ///
    /// A literal search for the `id` key rather than a second TOML parse: the
    /// pointer is a courtesy on an error path, and a parser here would be a
    /// second reader of the file the loader already read.
    pub(crate) fn pointer(self, id: &str) -> String {
        let needle = format!("id = \"{id}\"");
        for (index, line) in self.text.lines().enumerate() {
            if line.trim_start().starts_with(&needle) {
                return format!("{}:{}", self.source, index + 1);
            }
        }
        self.source.to_owned()
    }
}

/// One `Rule` column and what the fact model says about it (CLOUD-1282).
///
/// # Why a census rather than a list of tree-only columns
///
/// A list of the columns to refuse is exactly what stood here before, and its
/// own comment recorded it lagging the struct. A census answers for EVERY field,
/// so a column added to `Rule` fails
/// [`tests::every_rule_column_carries_a_fact_verdict`] until somebody decides
/// what it declares — the same shape [`crate::trust::CENSUS`] uses, and for the
/// same reason: the field list is read off the struct's own source, so the table
/// cannot silently fall behind it.
#[derive(Debug, Clone, Copy)]
pub struct ColumnCensus {
    /// The column, spelled as `Rule` declares it.
    pub field: &'static str,
    /// What it says about fact acquisition.
    pub declares: Declares,
}

/// A column's verdict in [`COLUMN_CENSUS`]: it declares a fact, or it does not.
#[derive(Debug, Clone, Copy)]
pub enum Declares {
    /// The column declares acquisition of this fact, and the closure answers
    /// whether a given row actually declared anything in it.
    ///
    /// The closure is what makes the derivation possible at all: a census of
    /// names could say WHICH columns are tree-only and not whether THIS row
    /// declared one, and the refusal has to name a column the author wrote.
    Fact(crate::facts::Fact, fn(&Rule) -> bool),
    /// The column acquires no fact, with the reason — a selector, a remedy, a
    /// severity, a shape. Recorded rather than omitted, because "not covered"
    /// and "considered and not fact-bearing" are the two readings a silent
    /// absence cannot be told apart from.
    NotFactBearing(&'static str),
}

/// One column named as declaring a fact that this scope cannot resolve.
#[derive(Debug, Clone, Copy)]
pub struct TreeOnlyColumn {
    /// The column the author wrote.
    pub field: &'static str,
    /// The fact it declares.
    pub fact: crate::facts::Fact,
}

/// Every `Rule` column, with what it declares.
///
/// **Read the surface off the fact, never off this table.** A row names a
/// [`crate::facts::Fact`] and nothing else; whether that fact reaches the
/// mediated call is `Fact::class().surface`'s answer, so reclassifying a fact
/// moves this refusal with it and cannot leave the two disagreeing.
pub const COLUMN_CENSUS: &[ColumnCensus] = &[
    ColumnCensus {
        field: "id",
        declares: Declares::NotFactBearing("the row's own name"),
    },
    ColumnCensus {
        field: "kind",
        declares: Declares::NotFactBearing("which predicate decides the row"),
    },
    ColumnCensus {
        field: "glob",
        declares: Declares::NotFactBearing(
            "selects files; the tree walk is the engine's, not a declared fact",
        ),
    },
    ColumnCensus {
        field: "severity",
        declares: Declares::NotFactBearing("the exit contract"),
    },
    ColumnCensus {
        field: "scope",
        declares: Declares::NotFactBearing(
            "the surface this row is judged on — the question, never an answer to it",
        ),
    },
    ColumnCensus {
        field: "pattern",
        declares: Declares::NotFactBearing("a literal the predicate matches"),
    },
    ColumnCensus {
        field: "regex",
        declares: Declares::NotFactBearing("a pattern the predicate matches"),
    },
    ColumnCensus {
        field: "exclude",
        declares: Declares::NotFactBearing("narrows a match"),
    },
    ColumnCensus {
        field: "content",
        declares: Declares::NotFactBearing("a literal the predicate matches"),
    },
    ColumnCensus {
        field: "tool",
        declares: Declares::NotFactBearing(
            "selects on the call's own tool name, which the envelope carries",
        ),
    },
    ColumnCensus {
        field: "when_absent",
        declares: Declares::NotFactBearing("a condition over a fact another column declared"),
    },
    ColumnCensus {
        field: "key_from",
        declares: Declares::NotFactBearing("names where a receipt's key comes from"),
    },
    ColumnCensus {
        field: "key_base",
        declares: Declares::NotFactBearing(
            "names the ref a delta-keyed receipt's identity is taken against",
        ),
    },
    ColumnCensus {
        field: "when_value",
        declares: Declares::NotFactBearing("a condition over a fact another column declared"),
    },
    ColumnCensus {
        field: "key_shape",
        declares: Declares::NotFactBearing("the shape a key must have"),
    },
    ColumnCensus {
        field: "max_age",
        declares: Declares::NotFactBearing("a bound on a receipt another column declared"),
    },
    ColumnCensus {
        field: "requires_field",
        declares: Declares::NotFactBearing("a condition over the call's own payload"),
    },
    ColumnCensus {
        field: "when_present",
        declares: Declares::NotFactBearing("a condition over a fact another column declared"),
    },
    ColumnCensus {
        field: "while_marker",
        // NOT `Fact::Receipts`, and the distinction is the reason this column can
        // exist at all (CLOUD-1390). That fact is the boundary RESOLVING receipt
        // verdicts — validity, staleness, the key it was filed under — and every
        // one of those questions costs the resolution `checks` pays for. This
        // column asks whether one path exists. A marker carries no conclusion, so
        // there is nothing to resolve and nothing that could come back stale.
        //
        // Declaring the fact anyway would not be a harmless over-statement: it
        // would put receipt resolution on the acquisition list for every row
        // carrying this column, which is CLOUD-460's regression — a resolution
        // paid for by `ls` and by every file edit — and the whole economy of
        // `modifier_admits` reaching the filesystem only for a row that asked.
        declares: Declares::NotFactBearing(
            "a branch-keyed marker's PRESENCE, which is a path test rather than a \
             receipt verdict — nothing is resolved, so nothing is acquired",
        ),
    },
    ColumnCensus {
        field: "while_unpushed",
        declares: Declares::NotFactBearing(
            "whether HEAD is on a remote-tracking ref, walked by the modifier that \
             asked — no receipt is resolved, so nothing is acquired",
        ),
    },
    ColumnCensus {
        field: "measures",
        declares: Declares::NotFactBearing(
            "names a projection of the call, which the envelope carries",
        ),
    },
    ColumnCensus {
        field: "counts",
        declares: Declares::NotFactBearing("a condition over a fact another column declared"),
    },
    ColumnCensus {
        field: "max",
        declares: Declares::NotFactBearing("a ceiling on a measurement"),
    },
    ColumnCensus {
        field: "resolves",
        declares: Declares::NotFactBearing("a condition over a fact another column declared"),
    },
    ColumnCensus {
        field: "contains",
        declares: Declares::NotFactBearing("a condition over a fact another column declared"),
    },
    ColumnCensus {
        field: "unless_contains",
        declares: Declares::NotFactBearing(
            "a condition over a fact another column declared, in the exempting polarity",
        ),
    },
    ColumnCensus {
        field: "word",
        declares: Declares::NotFactBearing("a condition over a fact another column declared"),
    },
    ColumnCensus {
        field: "unless_word",
        declares: Declares::NotFactBearing(
            "a condition over a fact another column declared, in the exempting polarity",
        ),
    },
    ColumnCensus {
        field: "on",
        declares: Declares::NotFactBearing("selects by an event the engine resolves"),
    },
    ColumnCensus {
        field: "require_via",
        declares: Declares::NotFactBearing("narrows how a requirement may be met"),
    },
    ColumnCensus {
        field: "requires_key",
        // Hook-surface: the boundary already resolves the key evidence for the
        // typed rule table, so a mediated row declaring it is asking for
        // something it is handed.
        declares: Declares::Fact(crate::facts::Fact::Keys, |rule| rule.requires_key.is_some()),
    },
    ColumnCensus {
        field: "reason",
        declares: Declares::NotFactBearing("the consumer's remedy prose"),
    },
    ColumnCensus {
        field: "policy_url",
        declares: Declares::NotFactBearing("a pointer a refusal carries"),
    },
    ColumnCensus {
        field: "bypass_env",
        declares: Declares::NotFactBearing("names this row's hatch"),
    },
    ColumnCensus {
        field: "check",
        declares: Declares::NotFactBearing(
            "the command a `command` row runs; a spawn, which no mediated kind may do",
        ),
    },
    ColumnCensus {
        field: "fix",
        declares: Declares::NotFactBearing("the command a `command` row repairs with"),
    },
    ColumnCensus {
        field: "produces",
        declares: Declares::Fact(crate::facts::Fact::Produced, |rule| rule.produces.is_some()),
    },
    ColumnCensus {
        field: "exclude_paths",
        declares: Declares::NotFactBearing("narrows `glob`"),
    },
    ColumnCensus {
        field: "run",
        declares: Declares::NotFactBearing("the command a row runs"),
    },
    ColumnCensus {
        field: "verbatim",
        declares: Declares::NotFactBearing("normalisation of a hashed span"),
    },
    ColumnCensus {
        field: "identity_key",
        declares: Declares::NotFactBearing("how a finding is identified across runs"),
    },
    ColumnCensus {
        field: "direction",
        declares: Declares::NotFactBearing("which way a ratchet turns"),
    },
    // ONE COLUMN, ONE QUESTION — *since where* (`Rule::base`'s own doc). On a
    // ratchet or a shape row it names the rev a count or a subject list is
    // read since; on a tree `policy` row it is where the row's per-file facts
    // are ALSO acquired, as `input.tree.base.<family>` (plan item 4).
    ColumnCensus {
        field: "base",
        declares: Declares::Fact(crate::facts::Fact::Base, |rule| {
            rule.base.is_some() && rule.kind == crate::config_model::RuleKind::Policy
        }),
    },
    ColumnCensus {
        field: "retires_with",
        declares: Declares::NotFactBearing("an admission's shape"),
    },
    ColumnCensus {
        field: "conserves",
        declares: Declares::NotFactBearing("an obligation inside an admission"),
    },
    ColumnCensus {
        field: "admits_with",
        declares: Declares::NotFactBearing("an admission's shape on the other side of the count"),
    },
    ColumnCensus {
        field: "per_file",
        declares: Declares::NotFactBearing("the grain a ratchet's count is judged at"),
    },
    ColumnCensus {
        field: "format",
        declares: Declares::NotFactBearing(
            "how a declared document is parsed, not whether one is acquired",
        ),
    },
    ColumnCensus {
        field: "node",
        declares: Declares::NotFactBearing("addresses inside a document another column declared"),
    },
    ColumnCensus {
        field: "derives",
        declares: Declares::NotFactBearing(
            "how a value is computed from a fact another column declared",
        ),
    },
    ColumnCensus {
        field: "cites",
        declares: Declares::NotFactBearing(
            "which declared register a reference row resolves against, and how it cites; the \
             files read are the register's own declared paths, never a fact",
        ),
    },
    ColumnCensus {
        field: "reads",
        declares: Declares::NotFactBearing("addresses inside a fact another column declared"),
    },
    ColumnCensus {
        field: "predicate_severity",
        declares: Declares::NotFactBearing("per-predicate exit contract"),
    },
    ColumnCensus {
        field: "preset",
        declares: Declares::NotFactBearing(
            "names a vendored module; the facts are that module's own declarations",
        ),
    },
    ColumnCensus {
        field: "provider",
        declares: Declares::NotFactBearing(
            "qualifies `preset`, selecting which of its modules compile; the facts stay \
             those modules' own declarations (CLOUD-1625)",
        ),
    },
    ColumnCensus {
        field: "gate",
        declares: Declares::NotFactBearing(
            "names one of the engine's compiled gates; the facts are the gate's own (CLOUD-2291)",
        ),
    },
    ColumnCensus {
        field: "except",
        declares: Declares::NotFactBearing(
            "qualifies `preset`, naming modules it does not compile; the facts stay the \
             remaining modules' own declarations (CLOUD-2290)",
        ),
    },
    ColumnCensus {
        field: "bundle",
        declares: Declares::NotFactBearing("names a vendored bundle, as `preset` does"),
    },
    ColumnCensus {
        field: "documents",
        declares: Declares::Fact(crate::facts::Fact::Document, |rule| {
            !rule.documents.is_empty()
        }),
    },
    ColumnCensus {
        field: "requires_path",
        // A `try_exists` per entry — no glob expansion, no read, nothing
        // spawned — and permitted on every kind by design. It is a filesystem
        // question and NOT a `Fact`, so the derivation does not reach it. Named
        // here rather than left silent, because "the census does not cover it"
        // and "the census considered it" are the two readings an omission
        // cannot be told apart from.
        declares: Declares::NotFactBearing(
            "a `try_exists` per declared entry, permitted on every kind and acquiring no fact",
        ),
    },
    ColumnCensus {
        field: "sources",
        declares: Declares::Fact(crate::facts::Fact::Document, |rule| {
            !rule.sources.is_empty()
        }),
    },
    ColumnCensus {
        field: "lines",
        declares: Declares::Fact(crate::facts::Fact::Lines, |rule| !rule.lines.is_empty()),
    },
    ColumnCensus {
        field: "line_sources",
        declares: Declares::Fact(crate::facts::Fact::Lines, |rule| {
            !rule.line_sources.is_empty()
        }),
    },
    ColumnCensus {
        field: "invocations",
        declares: Declares::Fact(crate::facts::Fact::Invocations, |rule| {
            !rule.invocations.is_empty()
        }),
    },
    ColumnCensus {
        field: "invocation_sources",
        declares: Declares::Fact(crate::facts::Fact::Invocations, |rule| {
            !rule.invocation_sources.is_empty()
        }),
    },
    ColumnCensus {
        field: "uses",
        declares: Declares::Fact(crate::facts::Fact::Uses, |rule| !rule.uses.is_empty()),
    },
    ColumnCensus {
        field: "use_sources",
        declares: Declares::Fact(crate::facts::Fact::Uses, |rule| {
            !rule.use_sources.is_empty()
        }),
    },
    ColumnCensus {
        field: "unit_sources",
        declares: Declares::Fact(crate::facts::Fact::Units, |rule| {
            !rule.unit_sources.is_empty()
        }),
    },
    ColumnCensus {
        field: "git",
        // The head/status/remote/worktrees family. All four are
        // `Surface::Check`, so the column is tree-only whichever read a row
        // asked for and one fact answers for it.
        declares: Declares::Fact(crate::facts::Fact::GitHead, |rule| !rule.git.is_empty()),
    },
    ColumnCensus {
        field: "symbols",
        declares: Declares::Fact(crate::facts::Fact::Symbols, |rule| rule.symbols),
    },
    ColumnCensus {
        field: "review",
        declares: Declares::Fact(crate::facts::Fact::Review, |rule| !rule.review.is_empty()),
    },
    ColumnCensus {
        field: "refs",
        declares: Declares::Fact(crate::facts::Fact::GitRef, |rule| !rule.refs.is_empty()),
    },
    ColumnCensus {
        field: "ranges",
        declares: Declares::Fact(crate::facts::Fact::GitRange, |rule| !rule.ranges.is_empty()),
    },
    ColumnCensus {
        field: "commits",
        declares: Declares::Fact(crate::facts::Fact::CommitMeta, |rule| {
            !rule.commits.is_empty()
        }),
    },
    ColumnCensus {
        field: "staged",
        declares: Declares::Fact(crate::facts::Fact::Staged, |rule| !rule.staged.is_empty()),
    },
    ColumnCensus {
        field: "history",
        declares: Declares::Fact(crate::facts::Fact::GitHistory, |rule| {
            !rule.history.is_empty()
        }),
    },
    ColumnCensus {
        field: "tags",
        declares: Declares::Fact(crate::facts::Fact::GitTags, |rule| !rule.tags.is_empty()),
    },
    ColumnCensus {
        field: "git_config",
        declares: Declares::Fact(crate::facts::Fact::GitConfig, |rule| {
            !rule.git_config.is_empty()
        }),
    },
    ColumnCensus {
        field: "index",
        declares: Declares::Fact(crate::facts::Fact::GitIndex, |rule| !rule.index.is_empty()),
    },
    ColumnCensus {
        field: "state",
        declares: Declares::Fact(crate::facts::Fact::State, |rule| !rule.state.is_empty()),
    },
    ColumnCensus {
        field: "forge",
        declares: Declares::Fact(crate::facts::Fact::Forge, |rule| !rule.forge.is_empty()),
    },
    ColumnCensus {
        field: "tools",
        declares: Declares::Fact(crate::facts::Fact::ToolVerdict, |rule| {
            !rule.tools.is_empty()
        }),
    },
    ColumnCensus {
        field: "plan",
        declares: Declares::Fact(crate::facts::Fact::Plan, |rule| !rule.plan.is_empty()),
    },
    ColumnCensus {
        field: "minted",
        declares: Declares::Fact(crate::facts::Fact::Minted, |rule| !rule.minted.is_empty()),
    },
    ColumnCensus {
        field: "captured",
        declares: Declares::Fact(crate::facts::Fact::Captured, |rule| {
            !rule.captured.is_empty()
        }),
    },
    ColumnCensus {
        field: "tasks",
        // Hook-surface (CLOUD-856): read from a receipt minted at session start,
        // so the mediated path parses no manifest. A mediated row declaring it
        // is asking for something this surface can answer.
        declares: Declares::Fact(crate::facts::Fact::Tasks, |rule| !rule.tasks.is_empty()),
    },
    ColumnCensus {
        field: "extract",
        // Hook-surface (CLOUD-1172): a declared extractor's COUNT over this
        // session's transcript, an integer over typed events.
        declares: Declares::Fact(crate::facts::Fact::Extracted, |rule| {
            !rule.extract.is_empty()
        }),
    },
    ColumnCensus {
        field: "landing",
        declares: Declares::Fact(crate::facts::Fact::Landing, |rule| !rule.landing.is_empty()),
    },
    ColumnCensus {
        field: "delta_sources",
        declares: Declares::Fact(crate::facts::Fact::BaseDelta, |rule| {
            !rule.delta_sources.is_empty()
        }),
    },
    ColumnCensus {
        field: "external",
        declares: Declares::Fact(crate::facts::Fact::External, |rule| {
            !rule.external.is_empty()
        }),
    },
    ColumnCensus {
        field: "module",
        declares: Declares::NotFactBearing(
            "names the module file; the facts are that module's own declarations",
        ),
    },
    ColumnCensus {
        field: "no_fix_reason",
        declares: Declares::NotFactBearing("states why a row declares no fix"),
    },
    ColumnCensus {
        field: "no_retry_reason",
        declares: Declares::NotFactBearing(
            "states why a repaired call has nothing to re-issue, so the row's \
             class may be `silent` rather than `retry` (CLOUD-1639)",
        ),
    },
    ColumnCensus {
        field: "checks",
        // Hook-surface: the boundary already resolves receipt verdicts for the
        // typed rule table, which is what makes `ready-guard` a mediated row.
        declares: Declares::Fact(crate::facts::Fact::Receipts, |rule| rule.checks.is_some()),
    },
    ColumnCensus {
        field: "checks_any",
        // THE SAME FACT AS `checks`, and that is the whole of the entry: the two
        // columns differ in how they are ADJUDICATED — all of one, any of the
        // other — and not at all in what has to be resolved to adjudicate them.
        // A row naming three receipts in an alternation needs all three verdicts
        // resolved, because "any one is valid" cannot be answered without asking
        // about each; the alternation is applied to the answers, never to which
        // questions get asked.
        //
        // So this entry is what makes `Rule::receipt_names` honest at the
        // acquisition layer, the same way that helper makes it honest at every
        // resolution site: a column declaring no fact here would say the
        // alternation's names need not be resolved, which is the dead gate
        // CLOUD-1297 exists to have avoided.
        declares: Declares::Fact(crate::facts::Fact::Receipts, |rule| {
            rule.checks_any.is_some()
        }),
    },
    ColumnCensus {
        field: "key",
        declares: Declares::NotFactBearing(
            "which git fact a receipt is keyed to, not a fact itself",
        ),
    },
    ColumnCensus {
        field: "trigger",
        declares: Declares::NotFactBearing("what makes a receipt row fire"),
    },
    ColumnCensus {
        field: "verdict",
        declares: Declares::NotFactBearing("the verdict-bearing programs a pipeline row knows"),
    },
    ColumnCensus {
        field: "filters",
        declares: Declares::NotFactBearing("the filter programs a pipeline row knows"),
    },
    ColumnCensus {
        field: "substitutes",
        declares: Declares::NotFactBearing("the utilities a pipeline row redirects"),
    },
    ColumnCensus {
        field: "interprets",
        declares: Declares::NotFactBearing("the interpreters a pipeline row contains"),
    },
    ColumnCensus {
        field: "criteria",
        declares: Declares::NotFactBearing("what a judge row asks a model"),
    },
    ColumnCensus {
        field: "tier",
        declares: Declares::NotFactBearing("a judge finding's advisory tier"),
    },
];
