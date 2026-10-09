//! The refusal contract (CLOUD-122): **every deny points to the fix.**
//!
//! One type, constructed at every deny site, projected onto whatever channel the
//! caller's host reads. Before this each deny site composed its own `format!` —
//! [`crate::hook`]'s shape rows, [`crate::hook`]'s derived protected-path gate,
//! and [`crate::rules::run_static`]'s refusal of a kind `check` cannot honestly
//! run — so "does this deny name a fix?" was a property of prose, and a fourth
//! deny site could land carrying a bare "no" with every gate green.
//!
//! Three choices carry the contract:
//!
//! * **Completeness is structural, not tested.** [`Refusal::new`] is the only
//!   constructor and it takes a [`Fix`] positionally, with no default and no
//!   `Option`. A deny that declares no disposition does not compile; a deny that
//!   genuinely has no safe remedy spells [`Fix::None`], which is a statement
//!   rather than an omission. That is the difference between a contract and a
//!   convention — a test can only catch the deny sites someone remembered.
//! * **The payload is `{rule, reason, fix}`, and `fix` is never dropped.** The
//!   serialization carries `"fix": null` for [`Fix::None`] rather than skipping
//!   the key, because a consumer cannot tell an omitted field from a field the
//!   producer forgot. Byte-stable by construction (house-style §6): field order
//!   is struct order, and no value here reads a clock, a path, or an ordering.
//! * **Pointer-only** (non-negotiable rule 4). A refusal names a rule id, an
//!   operand the caller already typed, and a command to run — never file content,
//!   and never the mediated command text, which is the caller's own and could
//!   carry anything.
//!
//! **Bound (CLOUD-211, recorded on CLOUD-122):** a mediated deny originates only
//! from a computable predicate, never a judge verdict — any model signal is
//! advisory-only and structurally unable to block (house-style §0.3). So this
//! shape deliberately does **not** model advisory output: there is no confidence,
//! no severity and no "maybe", and nothing under [`crate::judge`] constructs one.
//!
//! **Why a leaf module rather than a field of the hook policy table**, which is
//! where the issue's Ready block put it: [`crate::hook`] already imports
//! [`crate::rules`], and `rules::run_static` is a deny site too. Housing the type
//! in `hook` would make `rules` import `hook` and close a module cycle for no
//! gain. The load-bearing half of that clause — *one* authoritative shape in
//! `crates/batten`, constructed at every deny site, never re-typed per harness —
//! is what this module is.

use std::path::Path;

use serde::{Deserialize, Serialize, Serializer};

/// The `[refusal]` table: what one emitted mediated line may cost.
///
/// **Declared, never a literal in the crate** (non-negotiable rule 2, and the
/// same reasoning `[budget.instructions]` is built on): a ceiling written into
/// `crates/batten` is this repository's judgement compiled into every consumer's
/// engine, and a consumer whose harness renders differently could not move it
/// without a release. [`crate::budget::BudgetSet`] is the landed shape this
/// copies — a ceiling and nothing else, absent meaning unenforced, because a
/// threshold nobody declared is not a threshold of zero.
///
/// The unit is **estimated tokens**, on `budget.rs`'s own bytes-per-token
/// convention rather than a tokenizer: this is a ceiling on a line, checked off
/// the hot path, and a real BPE pass here would be the dependency CLOUD-1284
/// deliberately kept to `[dev-dependencies]`.
///
/// It is not [`crate::verdict`]'s `GLOSS_MAX`, which stays. That bounds one
/// FIELD — the gloss `explain` prints — and this bounds the emitted LINE. Both
/// exist for the same reason and neither substitutes for the other: with the
/// gloss off the hot path, `GLOSS_MAX` is what stops it growing back into a
/// paragraph where nothing measures it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Ceiling {
    /// The ceiling on estimated tokens for ONE emitted mediated refusal line.
    /// The boundary is `<=`: exactly at budget passes, matching
    /// [`crate::budget::Report::over_budget`] so the two thresholds in this tree
    /// do not disagree about their own edge.
    ///
    /// **Bounds the REPEAT arm** — the compact `<token> <pointers> <rule-id>`
    /// every firing after the first emits. The first sighting is a different
    /// quantity and has its own key below.
    pub max_tokens: usize,
    /// The ceiling on the FIRST sighting of a rule, which carries the class
    /// definition (CLOUD-1637).
    ///
    /// **A second key rather than a second meaning for the first**, because the
    /// two arms are different quantities: `max_tokens` prices prose a reader has
    /// already read, and this prices the one firing where they have not. Folding
    /// them would force a consumer to choose between bounding the repeat usefully
    /// and letting the definition arrive at all.
    ///
    /// Absent means unbounded, which is the answer every other budget in this
    /// tree gives an undeclared row: the ceiling is the consumer's statement
    /// about their own line, and inventing one here would be this crate deciding
    /// a consumer fact.
    ///
    /// What it bounds is the ROUTE LIST, never the line. Over budget, routes are
    /// dropped from the end and the gloss never is; when `<token> <pointers>
    /// <rule-id> — <gloss>; <first route>` is itself over, it is emitted anyway.
    /// See [`crate::hook::deny_text`] for why that irreducible case is a decision
    /// rather than an oversight.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_sighting_max_tokens: Option<usize>,
}

impl Ceiling {
    /// Whether one emitted REPEAT line is over the declared ceiling.
    #[must_use]
    pub fn over(&self, line: &str) -> bool {
        crate::budget::estimate_tokens(line) > self.max_tokens
    }

    /// Whether one emitted FIRST-SIGHTING line is over the declared ceiling.
    ///
    /// `false` when no first-sighting ceiling is declared — unbounded, per the
    /// field's own contract, rather than falling back to [`Ceiling::max_tokens`].
    /// A fallback would bound the long arm by the short arm's number, which is a
    /// ceiling nothing can satisfy wearing a default.
    #[must_use]
    pub fn over_first_sighting(&self, line: &str) -> bool {
        self.first_sighting_max_tokens
            .is_some_and(|max| crate::budget::estimate_tokens(line) > max)
    }
}

/// Refuse a `[refusal]` table that declares a ceiling nothing could satisfy.
///
/// A zero ceiling would refuse every line including the shortest possible one,
/// which is the switched-off gate CLOUD-418 names: it fires on everything, so
/// the first person to run it turns it off. Refused at load, in the same
/// direction and for the same reason `budget.rs` refuses an empty set.
///
/// # Errors
///
/// When the declared ceiling is zero.
pub fn validate(ceiling: Option<&Ceiling>) -> Result<(), String> {
    let Some(declared) = ceiling else {
        return Ok(());
    };
    if declared.max_tokens == 0 {
        return Err(
            "`[refusal] max_tokens = 0` refuses every line a refusal could emit, including the \
             shortest one the grammar can spell — a ceiling nothing can satisfy is a gate that \
             gets switched off rather than one that holds"
                .to_owned(),
        );
    }
    if declared.first_sighting_max_tokens == Some(0) {
        return Err(
            "`[refusal] first_sighting_max_tokens = 0` refuses every first sighting a refusal \
             could emit, including the irreducible one — and the first sighting is the only \
             firing that carries the class definition, so a zero there withholds the remedy \
             from the one reader who has not read it"
                .to_owned(),
        );
    }
    // The first sighting carries strictly more than the repeat — the same line
    // plus a gloss and at least one route — so a first-sighting ceiling at or
    // below the repeat's cannot be met by any line that arm can compose. Refused
    // here rather than discovered as an arm that silently never renders its
    // definition, which is the defect this row exists to remove.
    if let Some(first) = declared.first_sighting_max_tokens
        && first <= declared.max_tokens
    {
        return Err(format!(
            "`[refusal] first_sighting_max_tokens = {first}` is not above `max_tokens = {}`, and \
             a first sighting is the repeat line plus a gloss and a route — so no line this arm \
             can compose would fit, and the definition would never render",
            declared.max_tokens
        ));
    }
    Ok(())
}

/// What to run instead — the half of a refusal that makes it actionable.
///
/// Two variants and no third: either a sanctioned alternative is declared, or it
/// is declared absent. "Not stated" is deliberately unrepresentable, which is the
/// whole mechanism (see the module doc).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fix {
    /// The sanctioned alternative for the refused intent — the exact command to
    /// run, or the surface that owns the change.
    Run(String),
    /// No safe remedy is declared for this refusal.
    ///
    /// Spelled at the deny site rather than inferred from an absent field, so the
    /// gap is a decision someone made and a reader can see. It renders as an
    /// explicit "none declared" plus the caller's general recourse, and
    /// serializes as JSON `null`.
    None,
}

impl Fix {
    /// A declared alternative, or [`Fix::None`] when the config states none.
    ///
    /// The adapter for the several config columns that are `Option<String>`
    /// today (a verb's `redirect`, a rule's stated remedy). Written once here so
    /// no deny site re-derives "absent means none".
    #[must_use]
    pub fn declared(alternative: Option<&str>) -> Fix {
        match alternative {
            Some(text) if !text.trim().is_empty() => Fix::Run(text.trim().to_owned()),
            _ => Fix::None,
        }
    }

    /// The declared alternative, if there is one.
    #[must_use]
    pub fn declared_alternative(&self) -> Option<&str> {
        match self {
            Fix::Run(text) => Some(text),
            Fix::None => None,
        }
    }
}

/// `Fix::Run` is a string and `Fix::None` is `null` — never an absent key.
///
/// Hand-written rather than derived because serde's enum representations all
/// encode the *variant*, and a consumer of `{rule, reason, fix}` wants the fix or
/// an explicit nothing, not a tag it has to unwrap.
impl Serialize for Fix {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Fix::Run(text) => serializer.serialize_str(text),
            Fix::None => serializer.serialize_none(),
        }
    }
}

/// The refusal every deny site constructs: what refused, why, and what to run.
///
/// Fields are private so [`Refusal::new`] is the only way to make one — that is
/// what makes the fix disposition mandatory rather than merely conventional.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Refusal {
    /// The id that refused: a `[[rule]]` row's id, or a derived gate's declared
    /// constant. What a reviewer greps for in `batten.toml`.
    rule: String,
    /// How the finding bears on the call: the line's second word (CLOUD-2145).
    /// `Deny` unless the channel that carries it says otherwise
    /// ([`Refusal::with_severity`]). A rendering input, so not serialized.
    #[serde(skip)]
    severity: Severity,
    /// Every route the class declares, override routes included, unrendered
    /// (CLOUD-2075). [`finding_line`] renders them by kind on BOTH arms.
    ///
    /// **Skipped in serialization**, because it is a RENDERING input rather than
    /// part of the refusal payload: a consumer of `{rule, verdict, reason, fix}`
    /// asked for the remedy, and `fix` is still that. Resolved here because this
    /// is where the registry is already in hand, which keeps the projection pure
    /// and the boundary free of a second registry lookup.
    #[serde(skip)]
    routes: Vec<crate::verdict::Route>,
    /// The rendered pointers, as [`crate::verdict::render_subjects`] spells them
    /// (CLOUD-2075). The ` at <subjects>` clause of both arms.
    #[serde(skip)]
    subjects: String,
    /// Which reader a document route's target is read through, where the
    /// consumer declares one (`[[redirect]] read`), keyed by target
    /// ([`Refusal::read_through`]).
    #[serde(skip)]
    readers: std::collections::BTreeMap<String, String>,
    /// The one-line gloss of the declared class, for the first-sighting arm
    /// (CLOUD-1637).
    ///
    /// **Skipped in serialization for the same reason `routes` is**: it is a
    /// rendering input resolved where the registry is already in hand, not part
    /// of the `{rule, verdict, reason, fix}` payload a consumer asked for. That
    /// also keeps `-J` byte-identical and leaves `schema/*.json` unmoved by this
    /// change — the schemas follow `Ceiling`, which does gain a key.
    ///
    /// Empty for a refusal composed from consumer prose, which declares no class
    /// and so has no gloss to carry.
    #[serde(skip)]
    gloss: String,
    /// The class's interaction doc, rendered on the full arm after the gloss
    /// (CLOUD-2143). Skipped for [`Refusal::gloss`]'s reason: the `-J` payload
    /// is unchanged. Empty for a refusal with no class.
    #[serde(skip)]
    doc: crate::doc::Doc,
    /// The declared class this refusal belongs to, when it has one (CLOUD-1050).
    ///
    /// `Some` for every one of Batten's OWN refusal sites, which name a
    /// [`crate::verdict::Native`] variant and so cannot raise a class nobody
    /// declared — the coupling is the type system's rather than a convention's.
    /// `None` for a refusal composed from a consumer's `[[rule]]` row, whose
    /// remedy is the consumer's declared `reason` under house style §8 and which
    /// is deliberately not a Batten class.
    ///
    /// Serialized as an explicit `null` rather than dropped, the same reason
    /// `fix` is: a consumer cannot tell an omitted key from an absent value.
    verdict: Option<String>,
    /// One line of why, pointer-only.
    reason: String,
    /// What to run instead, or an explicit none.
    fix: Fix,
    /// Every spelling a MEDIATED admission binds to, in order
    /// ([`admission_bindings`] carries which and why).
    ///
    /// The tree surface binds `finding.path` instead and anchors by fingerprint,
    /// so it never reads this; the two are different questions (CLOUD-1826).
    ///
    /// **Carried rather than re-derived at the boundary**, and that is the whole
    /// reason the field exists. [`crate::admission::admitted`] binds five fields,
    /// one of which is the subject; a boundary that recomputed "which path was
    /// refused" from the envelope would be a second authority over a question the
    /// deny site already answered, and the two can disagree on exactly the
    /// normalization cases that made CLOUD-1133 a defect.
    ///
    /// **Not serialized**, so `-J` output is byte-identical to before (house style
    /// §6). It is an internal binding rather than news: the same pointers are
    /// already in `reason`, and a consumer gains nothing from a second copy under
    /// its own key.
    #[serde(skip_serializing)]
    bindings: Vec<String>,
}

/// Every spelling a mediated refusal of `token` naming `subjects` binds, in
/// order (CLOUD-1826).
///
/// - **(a) The printed spelling, always first** —
///   [`crate::verdict::bound_subject`] of exactly the pointers
///   [`crate::verdict::render_line`] prints, counts included. A reader pastes
///   the line into `override request --subject`, which spells through the same
///   function, so the pasted line binds as the refusal does.
/// - **(b) The first path**, when it differs from (a): the `--subject <path>`
///   spelling the protected-path route documents.
/// - **(c) The class token in bound spelling**, only when there are no subjects:
///   `call name refused` binds `call,name,refused`, which is exactly what a
///   request for that subject stores. The raw token it replaces was a spelling no
///   request could produce.
///
/// Every entry is a fixed point of `bound_subject`, so any spelling the boundary
/// asks about is one a request can store.
///
/// # A count binds only inside the whole printed spelling
///
/// So an admission for `1 <sha>` cannot fit `2 <sha> <sha>` — the harvest hole
/// CLOUD-1871 closed stays closed. A count-only class with no override route
/// stays inert, because `override request` refuses such a class.
///
/// # Why not `rules::first_pointer`
///
/// That is the TREE pointer: one path slot, anchored by fingerprint. Forcing it
/// to equal this binding would either widen tree output or drop pointers here.
///
/// Rule 4 is untouched: this binds only what the refusal already renders, and
/// `bindings` is `skip_serializing`, so `-J` output and `schema/*.json` do not
/// move.
//MUTANT-SUITE crates/batten/src/hook.rs
//MUTANT printed-spelling-dropped|s@^    let mut spellings = vec!\[bound_subject(&render_subjects(subjects))\];$@    let mut spellings: Vec<String> = Vec::new();@|a_subject_copied_from_the_refusal_line_admits_the_write
//MUTANT path-spelling-dropped|s@^    let path = subjects.iter().find_map(crate::verdict::Subject::path).map(bound_subject);$@    let path: Option<String> = None;@|a_spent_admission_admits_the_write_it_was_taken_for
//MUTANT class-spelling-raw|s@^        return vec!\[bound_subject(token)\];$@        return vec![token.to_owned()];@|a_refusal_naming_nothing_binds_its_class_as_a_request_spells_it
fn admission_bindings(token: &str, subjects: &[crate::verdict::Subject]) -> Vec<String> {
    use crate::verdict::{bound_subject, render_subjects};
    if subjects.is_empty() {
        return vec![bound_subject(token)];
    }
    let mut spellings = vec![bound_subject(&render_subjects(subjects))];
    // One line, because `path-spelling-dropped` anchors on it whole.
    #[rustfmt::skip]
    let path = subjects.iter().find_map(crate::verdict::Subject::path).map(bound_subject);
    spellings.extend(path.filter(|path| !spellings.contains(path)));
    spellings
}

/// Whether this RULE has already explained itself this session, marking it if
/// not (CLOUD-1386, re-keyed by CLOUD-1637).
///
/// **KEYED ON THE PAIR — the rule AND the class — because each alone is wrong in
/// one direction, and both directions were measured.**
///
/// It digested the CLASS TOKEN for its whole life, on the premise that the class
/// is what gets explained. That holds only where a class has one raiser, and it
/// does not for the native-kind population: `[[rule]]` rows of kind `shape`,
/// `receipt`, `forbid`, `pipeline`, `command`, `ratchet` and `secrets` declare no
/// class of their own and raise the kind's native one, so every plain `shape`
/// row (eleven in this config when CLOUD-1806 counted) raises `call name
/// refused` and ten `receipt` rows share four classes. Under a token key the
/// first `shape` row to fire consumed the sighting for all of them, and the
/// next row's FIRST firing rendered as a repeat with its
/// rule-specific remedy never pointed at. CLOUD-1637's second amendment is where
/// that was corrected, and it prescribed the rule id.
///
/// **The rule id alone is wrong the other way, which the amendment did not
/// count.** A rule can raise SEVERAL classes: `verdict-not-discarded` is one row
/// and raises `verdict read dropped`, `verdict carry other` and `turn watch
/// dropped`. Measured on a fixture whose store started empty, firing the three in
/// order: the first carried its definition and the second and third came back
/// compact on their own FIRST firing — the same silent withholding, one axis over.
///
/// So the key is what the line actually delivers, which is neither name by
/// itself: the class's gloss AND the row's remedy, and a reader who has seen one
/// pairing has not seen the other. Recorded on CLOUD-1637 so the prescribed
/// single key is not reinstated as a simplification.
///
/// The key space does not grow for the population that was already 1:1: where a
/// rule is its class's sole raiser the pair has one member per name, and after
/// CLOUD-1638 collapses the two names there it is one string repeated.
///
/// It also makes the store reachable for an UNDECLARED refusal, which has a rule
/// id and no token — the pair degenerates to the id. That is what lets the
/// undeclared arm below be bounded at all rather than repeating its long form
/// identically forever.
///
/// **The repeat cost and the first-sighting value are different quantities**, and
/// a refusal renderer that cannot tell them apart has to pick one and be wrong
/// about the other. CLOUD-1286 removed the class's route from every declared
/// refusal because it was paying it on every firing; the measured consequence was
/// a reader who met `branch write unsafe` for the first time, learned nothing
/// actionable, and reported a working gate as a design defect. Neither "always"
/// nor "never" is right. "Once" is.
///
/// SCOPED TO THE CONTEXT, NOT THE CLONE (CLOUD-2075). The store lives under
/// `$GIT_DIR/batten-sightings/<digest(context)>/<digest(key)>`, where the context
/// is the session plus the agent id where a subagent is the reader — a
/// subagent's first sighting used to come back compact because another context
/// in the clone had already marked it. Each file holds the full arm's text, for
/// a reader of the store; nothing re-delivers it.
///
/// **A window is an epoch, and a new one starts empty (CLOUD-2145).** A
/// `SessionStart` that loses the window — `compact`, `clear`, `startup` —
/// forgets this context alone, and each gate's NEXT firing is full again; one
/// that carries it over — `resume`, `fork` — keeps it. Nothing is pushed at the
/// boundary: an eager re-delivery paid for every gate the previous window met,
/// most of which never fire again, into one channel with a size cap.
///
/// **A failure to read or write answers TRUE**, which is the direction that
/// matters: an unreadable store means the class explains itself again, costing a
/// clause. The opposite default would silently withhold the remedy from a reader
/// who has never seen it, which is the whole defect.
#[must_use]
pub fn first_sighting(root: &Path, context: &str, key: &str, full: &str) -> bool {
    let Some(dir) = context_dir(root, context) else {
        return true;
    };
    // One file per key, CREATED EXCLUSIVELY (CLOUD-2145): the existence test and
    // the mark are one operation, so of a parallel batch of identical firings
    // exactly one reads "first". A check-then-write let every one of them.
    let path = dir.join(crate::provision::digest(key.as_bytes()));
    let _ = std::fs::create_dir_all(&dir);
    // An error other than "already there" answers TRUE: an unwritable store
    // means the next firing explains itself again, which is the safe direction.
    crate::durable::create_exclusive(&path, full).unwrap_or(true)
}

/// How to read a finding line, delivered once per epoch ahead of the first
/// finding that reaches a context (CLOUD-2145). At most 96 `o200k` tokens.
pub const LEGEND: &str = "batten findings read `batten <deny|warn|note> <class> at <subjects>; \
<routes>`; the first of a class in a window adds `—` and what it means, and \
`batten policy explain <class>` prints any you forget.";

/// The sighting key the legend is marked under: no class token has a space-free
/// spelling, so it collides with none.
const LEGEND_KEY: &str = "legend";

/// Whether this context's epoch still owes the legend, marking it delivered.
//MUTANT legend-every-firing|s@^    first_sighting(root, context, LEGEND_KEY, LEGEND)$@    true@|the_first_finding_of_an_epoch_carries_the_legend
#[must_use]
pub fn legend_due(root: &Path, context: &str) -> bool {
    first_sighting(root, context, LEGEND_KEY, LEGEND)
}

/// `text` with the legend ahead of it if this context has not had it this epoch.
#[must_use]
pub fn with_legend(root: &Path, context: &str, text: &str) -> String {
    if legend_due(root, context) {
        return format!("{LEGEND}\n{text}");
    }
    text.to_owned()
}

/// The directory one context's sightings live in.
//MUTANT sighting-context-ignored|s@^    Some(store.join(crate::provision::digest(context.as_bytes())))$@    Some(store.join(crate::provision::digest(b"")))@|two_contexts_in_one_clone_each_get_the_full_text
fn context_dir(root: &Path, context: &str) -> Option<std::path::PathBuf> {
    let store = crate::git::git_dir(root).ok()?.join(STORE);
    Some(store.join(crate::provision::digest(context.as_bytes())))
}

/// Which arm this firing of `refusal` gets in `context`, marking it seen.
//MUTANT sight-always-first|s@^    if !first_sighting(root, context, \&key, \&full) {$@    if false {@|a_warn_advisory_is_full_once_then_a_pointer
#[must_use]
pub fn sight(root: &Path, context: &str, refusal: &Refusal) -> Arm {
    let full = refusal.render_finding(Arm::Full);
    let key = refusal.sighting_key();
    if !first_sighting(root, context, &key, &full) {
        return Arm::Pointer;
    }
    Arm::Full
}

/// Which arm `refusal` WOULD get in `context`, marking nothing (CLOUD-2175).
///
/// The advisory channel decides what fits by this, then marks only what it
/// admits: a finding marked and then cut would read as delivered to a reader
/// who never saw it, and its next firing would be the pointer alone.
#[must_use]
pub fn peek(root: &Path, context: &str, refusal: &Refusal) -> Arm {
    let Some(dir) = context_dir(root, context) else {
        return Arm::Full;
    };
    let key = refusal.sighting_key();
    if dir.join(crate::provision::digest(key.as_bytes())).exists() {
        Arm::Pointer
    } else {
        Arm::Full
    }
}

/// Forget every item this ONE context has seen (CLOUD-2075). Other contexts in
/// the clone are never touched.
//MUTANT forget-sightings-noop|s@^        let _ = std::fs::remove_dir_all(dir);$@        let _ = dir;@|a_session_start_forgets_only_that_contexts_sightings
pub fn forget_sightings(root: &Path, context: &str) {
    if let Some(dir) = context_dir(root, context) {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// An item's identity: the rule, the class, and a digest of its DEFINITION, so
/// an edit to a gloss, route, precondition or reason mid-cycle is a new item
/// that renders in full again (CLOUD-1582, absorbed).
//MUTANT sighting-key-ignores-definition|s@^    let digest = crate::provision::digest(definition.as_bytes());$@    let digest = crate::provision::digest(b"");@|an_edited_definition_is_a_new_item_mid_cycle
fn key_of(rule: &str, class: Option<&str>, definition: &str) -> String {
    let digest = crate::provision::digest(definition.as_bytes());
    format!("{rule}\u{1f}{}\u{1f}{digest}", class.unwrap_or_default())
}

/// One finding line read back: its names, its arm and its key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    /// The class, where the line is labelled with one.
    pub verdict: Option<String>,
    /// The rule id.
    pub rule: String,
    /// `Full` iff the line carries the ` — ` definition clause.
    pub arm: Arm,
    /// [`key_of`] over the line's definition.
    pub key: String,
    /// The routes the line offered, each as printed (`run <command>`,
    /// `read <path>[ via <tool>]`), override requests excluded: pointers, which
    /// is what lets a census ask whether the next call took one (CLOUD-2141).
    pub routes: Vec<String>,
}

/// Read one quoted name from the front of `text`, returning it and the rest.
fn unquote(text: &str) -> Option<(String, &str)> {
    let mut rest = text.strip_prefix('\'')?;
    let mut name = String::new();
    loop {
        let index = rest.find(['\'', '\\'])?;
        name.push_str(&rest[..index]);
        if rest[index..].starts_with("\\'") {
            name.push('\'');
            rest = &rest[index + 2..];
        } else if rest[index..].starts_with('\'') {
            return Some((name, &rest[index + 1..]));
        } else {
            name.push('\\');
            rest = &rest[index + 1..];
        }
    }
}

/// The class a pre-CLOUD-2145 `rule` line names as its lookup hop's second name.
fn named_class(line: &str, rule: &str) -> Option<String> {
    let (_, after) = line.split_once("; run batten policy explain ")?;
    let (first, rest) = unquote(after)?;
    if first != rule {
        return None;
    }
    let (class, _) = unquote(rest.strip_prefix(' ')?)?;
    Some(class)
}

/// The ONE reader of the finding grammar
/// `batten <severity> <name>[ at <S>](; <route>)*[ — <definition>]`, and of the
/// labelled lines releases before CLOUD-2145 printed.
///
/// `None` for a line that does not open with the head, which is every line that
/// is not a finding. The name is returned as `verdict` — on a headed line it is
/// the class, or a classless row's id — and `rule` is empty: the line names the
/// violation, not the row that raised it.
///
/// A CHANNEL PREFIX ending `: ` (`::error:: land: `) is read past rather than
/// part of the grammar. Only a prefix ending `: ` qualifies, so prose that
/// merely mentions a finding mid-sentence is never read as one.
#[must_use]
pub fn parse_finding(line: &str) -> Option<Parsed> {
    parse_headed(line).or_else(|| parse_labelled(line))
}

/// The CLOUD-2145 line: `batten <severity> <name>[ at <S>](; <route>)*[ — …]`.
///
/// The head is the recogniser: no harness writes a line opening `batten deny `,
/// `batten warn ` or `batten note `, so nothing else is read as a finding. The
/// name runs to the first ` at `, `; ` or ` —`, which no name may contain.
fn parse_headed(line: &str) -> Option<Parsed> {
    let (opening, severity) = Severity::ALL
        .iter()
        .filter_map(|severity| {
            line.find(&format!("{PROVENANCE} {} ", severity.word()))
                .map(|at| (at, *severity))
        })
        .min_by_key(|(at, _)| *at)?;
    let (prefix, line) = line.split_at(opening);
    if !(prefix.is_empty() || prefix.ends_with(": ")) {
        return None;
    }
    let after = &line[PROVENANCE.len() + severity.word().len() + 2..];
    let end = [" at ", "; ", " —"]
        .iter()
        .filter_map(|delimiter| after.find(delimiter))
        .min()
        .unwrap_or(after.len());
    let name = after[..end].to_owned();
    if name.is_empty() {
        return None;
    }
    Some(read_body(line, String::new(), Some(name)))
}

/// A line from a release before CLOUD-2145, opening with a quoted label:
/// `[verdict '<T>' ]rule '<R>'…` or `verdict '<T>'…`. Read so a transcript a
/// session wrote then still measures.
fn parse_labelled(line: &str) -> Option<Parsed> {
    let opening = ["verdict '", "rule '"]
        .iter()
        .filter_map(|label| line.find(label))
        .min()?;
    let (prefix, line) = line.split_at(opening);
    if !(prefix.is_empty() || prefix.ends_with(": ")) {
        return None;
    }
    // ONE LABEL, ONE NAME (CLOUD-2142). A `rule` line names its class, where it
    // has a different one, as the hop's second name; a line from a release that
    // still printed `verdict '<T>' rule '<R>'` reads the same way.
    let (mut verdict, rest) = match line.strip_prefix("verdict ") {
        Some(after) => {
            let (name, tail) = unquote(after)?;
            (Some(name), tail)
        }
        None => (None, line),
    };
    let rule = match rest
        .strip_prefix(" rule ")
        .or_else(|| rest.strip_prefix("rule "))
    {
        Some(after) => unquote(after)?.0,
        None if verdict.is_some() => String::new(),
        None => return None,
    };
    if verdict.is_none() {
        verdict = named_class(line, &rule);
    }
    Some(read_body(line, rule, verdict))
}

/// The arm, routes and key of a finding line whose names were read.
fn read_body(line: &str, rule: String, verdict: Option<String>) -> Parsed {
    let (head, tail) = match line.split_once(" —") {
        Some((head, tail)) => (head, Some(tail)),
        None => (line, None),
    };
    let arm = if tail.is_some() {
        Arm::Full
    } else {
        Arm::Pointer
    };
    // THE DEFINITION IS THE LINE MINUS ITS PER-FIRING PARTS: the labels and
    // subjects (the first `; `-segment) and every override request, whose
    // `--subject` varies per firing.
    let routes: Vec<&str> = head
        .split("; ")
        .skip(1)
        .filter(|segment| !segment.starts_with(OVERRIDE_OPENER))
        .collect();
    let definition = format!("{} —{}", routes.join("; "), tail.unwrap_or_default());
    let key = key_of(&rule, verdict.as_deref(), &definition);
    let routes = routes.iter().map(|route| (*route).to_owned()).collect();
    Parsed {
        verdict,
        rule,
        arm,
        key,
        routes,
    }
}

/// Cut every full arm `mark` reports already seen to its pointer prefix,
/// leaving every other line byte-identical (CLOUD-2075 §D). `mark(key, full)`
/// consults and marks the reader's store and answers whether this is the first
/// sighting.
//MUTANT boundary-collapse-skipped|s@^        let rewritten = if arm == Arm::Pointer { pointer } else { body };$@        let rewritten = body;@|collapse_cuts_a_marked_full_arm_to_its_pointer_prefix
pub fn collapse(text: &str, mut mark: impl FnMut(&str, &str) -> bool) -> String {
    let mut lines: Vec<&str> = Vec::new();
    for body in text.split('\n') {
        let arm = match parse_finding(body) {
            Some(parsed) if parsed.arm == Arm::Full && !mark(&parsed.key, body) => Arm::Pointer,
            Some(_) | None => Arm::Full,
        };
        let pointer = body.split(" —").next().unwrap_or(body);
        let rewritten = if arm == Arm::Pointer { pointer } else { body };
        lines.push(rewritten);
    }
    lines.join("\n")
}

/// Where the per-session sightings live, under `$GIT_DIR`.
///
/// A FACT ABOUT THIS SESSION, NOT A RECEIPT: nothing here attests that a decision
/// was taken, it records that a sentence has been read. Filing it beside the
/// receipts would put a note where every reader expects a claim.
const STORE: &str = "batten-sightings";

/// Which of a finding's two renderings a firing gets (CLOUD-2075).
///
/// The pointer arm is a byte PREFIX of the full arm and carries the same
/// subjects and routes; the full arm adds the ` — <definition>` tail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arm {
    /// Labels, subjects, every route and the definition — once per context per
    /// compaction cycle.
    Full,
    /// Labels, subjects and every route, on every other firing.
    Pointer,
}

/// The word every finding line opens with, naming the binary that raised it and
/// that `policy explain` is run through (CLOUD-2145). No harness writes a line
/// opening `batten <severity> `, so it is also what tells a finding apart from
/// a host's own messages.
pub const PROVENANCE: &str = "batten";

/// How a finding bears on the call, as its line's second word (CLOUD-2145):
/// `deny` refused it, `warn` must be answered soon, `note` eventually. One ASCII
/// token each, the shape of a compiler's `error`/`warning`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Severity {
    /// The call was refused.
    #[default]
    Deny,
    /// An advisory to answer before the work goes much further.
    Warn,
    /// An advisory with no deadline.
    Note,
}

impl Severity {
    /// Every severity, in rank order.
    pub const ALL: [Severity; 3] = [Severity::Deny, Severity::Warn, Severity::Note];

    /// The word the line carries.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Severity::Deny => "deny",
            Severity::Warn => "warn",
            Severity::Note => "note",
        }
    }

    /// The severity an advisory of `tier` is printed under.
    #[must_use]
    pub const fn of_tier(tier: crate::severity::AdvisoryTier) -> Severity {
        match tier {
            crate::severity::AdvisoryTier::Warning | crate::severity::AdvisoryTier::Caution => {
                Severity::Warn
            }
            crate::severity::AdvisoryTier::Advisory => Severity::Note,
        }
    }
}

/// Whether `text` opens with a finding's head, `batten <severity> `.
#[must_use]
pub fn is_headed(text: &str) -> bool {
    Severity::ALL.iter().any(|severity| {
        text.strip_prefix(PROVENANCE)
            .and_then(|rest| rest.strip_prefix(' '))
            .and_then(|rest| rest.strip_prefix(severity.word()))
            .is_some_and(|rest| rest.starts_with(' '))
    })
}

/// The ONE spelling of a finding's head, `batten <severity> <name>`. Every line
/// that reports a finding opens with this; `emission_census` refuses a
/// hand-spelled one.
#[must_use]
pub fn head(severity: Severity, name: &str) -> String {
    format!("{PROVENANCE} {} {}", severity.word(), plain(name))
}

/// The two names a finding line labels, so a reader can always tell a rule
/// from a verdict (CLOUD-2075).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Label {
    /// A declared class, dereferenced by `batten policy explain`.
    Verdict,
    /// A `[[rule]]` id; `batten policy explain` dereferences both labels.
    Rule,
}

impl Label {
    /// The label's word.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Label::Verdict => "verdict",
            Label::Rule => "rule",
        }
    }
}

/// The ONE spelling of `verdict '<token>'` and `rule '<id>'`. Every emitter
/// that labels a name calls this; `emission_census` refuses a hand-spelled one.
#[must_use]
pub fn label(kind: Label, name: &str) -> String {
    format!("{} {}", kind.word(), quoted(name))
}

/// A name in single quotes. A `'` inside it is written `\'`; [`parse_finding`]
/// undoes exactly that.
fn quoted(name: &str) -> String {
    format!("'{}'", name.replace('\'', "\\'"))
}

/// Pointer text made safe for the grammar: it can never contain the tail
/// opener or the clause separator.
fn plain(text: &str) -> String {
    text.replace(" — ", " - ").replace("; ", ", ")
}

/// How every rendered override route opens; [`parse_finding`] drops these
/// segments from an item's definition because their subject varies per firing.
const OVERRIDE_OPENER: &str = "admit with batten override request ";

/// CLOUD-1806's class route. The hop [`finding_line`] appends names the same
/// verb with the real id, so a route whose target is this placeholder is
/// dropped at render rather than printed twice.
pub(crate) const RULE_HOP_PLACEHOLDER: &str = "batten policy explain '<rule-id>'";

/// The one projection every channel carries (CLOUD-2075, CLOUD-2142):
/// `<label> '<name>'[ at <S>](; <route>)*[ — ['<T>' ]<definition>]`,
/// the label `rule` or, for an engine finding with no row, `verdict`.
///
/// **Every firing carries every pointer**: the name, the subjects, and every
/// route — override routes included, each a ready `override request` with the
/// subject the refusal binds. Those are how a finding is fixed.
///
/// **Only the definition is said once per window** (CLOUD-2145): the repeat is
/// a byte prefix of the first firing, stopping before ` — `. The definition is
/// the row that raised the class (`<rule>:`, where it is another name), the
/// class gloss (or the undeclared refusal's reason), the row's own remedy, and
/// each override's precondition. A compaction forgets the window, so the next firing after one
/// is full again. No line carries a lookup hop: the legend says how to look up.
///
/// Nothing is shed and no ceiling is consulted: `[refusal]`'s keys are
/// measured by `refusal_ceiling`'s corpus case, which reports an over-ceiling
/// line rather than truncating one.
//MUTANT full-arm-reason-dropped|s@^    let remedy = refusal.remedy();$@    let remedy = None::<\&str>;@|a_first_sighting_carries_the_rows_reason_and_both_labels
//MUTANT reason-replaces-do-dropped|s@^        Some(remedy) => vec!\[remedy\],$@        Some(_) => refusal.doc.act.iter().map(String::as_str).collect(),@|a_rule_reason_replaces_the_class_do
//MUTANT repeat-carries-definition|s@^    let repeat = arm == Arm::Pointer;$@    let repeat = false;@|the_repeat_carries_every_pointer_and_no_definition
//MUTANT repeat-drops-routes|s@^    for route in routes(refusal) {$@    for route in routes(refusal).into_iter().take(if arm == Arm::Full { usize::MAX } else { 0 }) {@|the_repeat_carries_every_pointer_and_no_definition
//MUTANT named-by-rule|s@^    let name = refusal.verdict().unwrap_or(refusal.rule());$@    let name = if refusal.rule().is_empty() { refusal.verdict().unwrap_or_default() } else { refusal.rule() };@|a_finding_is_named_by_its_violation_class
//MUTANT advice-routes-dropped|s@^    for route in routes(refusal) {$@    for route in routes(refusal).into_iter().take(0) {@|a_warn_advisory_carries_its_document_route_on_an_allowed_pre_tool_call
//MUTANT raising-row-dropped|s@^    if raised_by {$@    if false {@|a_first_sighting_names_the_row_that_raised_it
//MUTANT severity-unprinted|s@^    let mut line = head(refusal.severity, name);$@    let mut line = head(Severity::Deny, name);@|an_advisory_finding_carries_its_severity
fn finding_line(refusal: &Refusal, arm: Arm) -> String {
    // THE VIOLATION'S NAME (CLOUD-2145): the class, whose definition is the one
    // a reader holds and looks up, and which explains the pointers below. Only a
    // classless consumer row is named by its own id. The row that raised a class
    // is named where a route needs it: the override request's `--rule`.
    let name = refusal.verdict().unwrap_or(refusal.rule());
    let mut line = head(refusal.severity, name);
    if !refusal.subjects.is_empty() {
        line.push_str(" at ");
        line.push_str(&plain(&refusal.subjects));
    }
    // EVERY POINTER, ON EVERY FIRING (CLOUD-2145): the routes are how the
    // finding is fixed, so a repeat that dropped them would say what is wrong
    // and not what to do about it.
    for route in routes(refusal) {
        line.push_str("; ");
        line.push_str(&route);
    }
    // THE REPEAT STOPS HERE: only the definition is said once per window.
    let repeat = arm == Arm::Pointer;
    if repeat {
        return line;
    }
    // No per-line lookup hop: the legend says how to look a name up.
    line.push_str(" —");
    // THE ROW THAT RAISED IT, ONCE (CLOUD-1806): a reader can find it in the
    // config, and two rows raising one class are two definitions, each with
    // its own remedy. Not on the repeat: the class is what is looked up.
    let raised_by = refusal
        .verdict()
        .is_some_and(|class| !refusal.rule().is_empty() && class != refusal.rule());
    if raised_by {
        line.push(' ');
        line.push_str(&plain(refusal.rule()));
        line.push(':');
    }
    let definition = if refusal.verdict.is_some() {
        &refusal.gloss
    } else {
        &refusal.reason
    };
    if !definition.is_empty() {
        line.push(' ');
        line.push_str(&sentence(definition));
    }
    // THE CLASS'S DOC (CLOUD-2143), with the firing row's own remedy in place
    // of the class's `do` where it declares one: the row knows this
    // repository's way out, the class only the general one.
    let remedy = refusal.remedy();
    let act: Vec<&str> = match remedy {
        Some(remedy) => vec![remedy],
        None => refusal.doc.act.iter().map(String::as_str).collect(),
    };
    let sections = crate::doc::render(&refusal.doc, &act);
    if !sections.is_empty() {
        line.push(' ');
        line.push_str(&plain(&sections));
    }
    for (id, precondition) in refusal.preconditions() {
        line.push_str(" Admissible as ");
        line.push_str(&quoted(id));
        line.push_str(" when ");
        line.push_str(&sentence(precondition));
    }
    line
}

/// Every route rendered, de-duplicated, in declaration order.
fn routes(refusal: &Refusal) -> Vec<String> {
    let mut rendered: Vec<String> = Vec::new();
    for route in &refusal.routes {
        if let Some(text) = route_text(refusal, route)
            && !rendered.contains(&text)
        {
            rendered.push(text);
        }
    }
    rendered
}

/// One route's text, or `None` where it does not render.
//MUTANT override-route-unrendered|s@^    if route.kind == RouteKind::Override {$@    if route.kind == RouteKind::Override \&\& false {@|the_override_route_on_the_line_is_the_request_that_admits
//MUTANT route-reader-unnamed|s@^        Some(reader) => format!("{text} via {reader}"),$@        Some(_) => text,@|a_document_route_into_a_read_redirected_path_names_its_reader
fn route_text(refusal: &Refusal, route: &crate::verdict::Route) -> Option<String> {
    use crate::verdict::RouteKind;
    if route.kind == RouteKind::Override {
        let class = refusal.verdict()?;
        let subject = refusal.bindings().first()?;
        return Some(format!(
            "{OVERRIDE_OPENER}--rule {} --verdict {} --subject {}",
            quoted(refusal.rule()),
            quoted(class),
            quoted(subject),
        ));
    }
    if route.target == RULE_HOP_PLACEHOLDER {
        return None;
    }
    let text = plain(&crate::verdict::render_route(route)?);
    Some(match refusal.readers.get(&route.target) {
        Some(reader) => format!("{text} via {reader}"),
        None => text,
    })
}

/// A CLI failure as one classed finding (CLOUD-2078), plus the diagnosis lines
/// that follow it: `None` for a [`crate::error::Passthrough`] (no output of
/// Batten's own) or a [`crate::error::Denial`] (already a rendered finding).
///
/// A [`crate::UsageError`] is its declared class, or `input parse refused`; any
/// other error is `verb run broken` with its chain as subjects, outermost first.
/// A finding is ONE line, so each message's first line is the subject and the
/// rest — a TOML parse caret, a multi-line detail — is returned to print after it.
//MUTANT usage-failure-misclassed|s@^        let class = usage.verdict.unwrap_or(Native::UsageRefused);$@        let class = usage.verdict.unwrap_or(Native::RunBroken);@|every_cli_failure_renders_its_verdict_label
//MUTANT config-fault-class-dropped|s@^        let class = usage.verdict.unwrap_or(Native::UsageRefused);$@        let class = Native::UsageRefused;@|every_config_fault_names_its_table_s_declared_class
#[must_use]
pub fn of_failure(failure: &anyhow::Error) -> Option<(Refusal, String)> {
    if failure
        .downcast_ref::<crate::error::Passthrough>()
        .is_some()
        || failure.downcast_ref::<crate::error::Denial>().is_some()
    {
        return None;
    }
    let split = |text: &str| -> (String, String) {
        let mut lines = text.lines();
        let head = lines.next().unwrap_or_default().trim().to_owned();
        (head, lines.collect::<Vec<_>>().join("\n"))
    };
    if let Some(usage) = failure.downcast_ref::<crate::UsageError>() {
        use crate::verdict::Native;
        let class = usage.verdict.unwrap_or(Native::UsageRefused);
        let (head, rest) = split(&usage.message);
        // ALREADY A FINDING: a raiser that rendered its own refusal (`check`'s
        // spawning-kind refusal) is printed as it is, never wrapped as the
        // subject of a second one.
        if usage.verdict.is_none() && parse_finding(&head).is_some() {
            return None;
        }
        let subjects = [crate::verdict::artifact(&head)];
        return Some((Refusal::engine(class, &subjects, Fix::None), rest));
    }
    let mut subjects = Vec::new();
    let mut rest = Vec::new();
    for cause in failure.chain() {
        let (head, tail) = split(&cause.to_string());
        subjects.push(crate::verdict::artifact(&head));
        if !tail.is_empty() {
            rest.push(tail);
        }
    }
    let refusal = Refusal::engine(crate::verdict::Native::RunBroken, &subjects, Fix::None);
    Some((refusal, rest.join("\n")))
}

/// The remediation-bearing finding for a `check` or drain rule (CLOUD-2078):
/// once per rule, carrying the row's `fix` argv or its `no_fix_reason`.
///
/// A rule whose id is also a declared class renders that class; any other rule
/// is a rule-only line whose definition is its `no_fix_reason`.
//MUTANT rule-remedy-dropped|s@^        Some(crate::findings::Remediation::Fix(argv)) => Fix::Run(argv.join(" ")),$@        Some(crate::findings::Remediation::Fix(_)) => Fix::None,@|a_rules_fix_is_its_remedy_and_its_reason_its_definition
#[must_use]
pub fn of_rule(
    rule: &str,
    registry: &[crate::verdict::DeclaredVerdict],
    findings: u64,
    remediation: Option<&crate::findings::Remediation>,
) -> Refusal {
    let fix = match remediation {
        Some(crate::findings::Remediation::Fix(argv)) => Fix::Run(argv.join(" ")),
        Some(crate::findings::Remediation::NoFix(_)) | None => Fix::None,
    };
    let count = crate::verdict::Subject::Count { count: findings };
    if crate::verdict::resolve(registry, rule).is_some() {
        return Refusal::from_class(rule, registry, rule, &[count], fix);
    }
    let why = match remediation {
        Some(crate::findings::Remediation::NoFix(why)) => why.as_str(),
        Some(crate::findings::Remediation::Fix(_)) | None => "",
    };
    Refusal::new(rule, why, fix).at(format!("{findings} finding(s)"))
}

impl Refusal {
    /// Build a refusal. The [`Fix`] is required, which is the contract.
    pub fn new(rule: impl Into<String>, reason: impl Into<String>, fix: Fix) -> Refusal {
        Refusal {
            rule: rule.into(),
            severity: Severity::Deny,
            // A consumer-composed refusal names no class, so there is no registry
            // row whose routes could be read. Empty rather than absent: the
            // rendering arm asks whether there is anything to say, not whether a
            // class exists.
            routes: Vec::new(),
            subjects: String::new(),
            readers: std::collections::BTreeMap::new(),
            // Likewise: no class, so no gloss. The undeclared arm's payload is
            // the consumer's own `reason`, which the full arm carries.
            gloss: String::new(),
            doc: crate::doc::Doc::default(),
            verdict: None,
            reason: reason.into(),
            fix,
            // A consumer-composed refusal carries no declared class, so there is
            // nothing a request could name — and a binding with no class behind
            // it would read as admissible.
            bindings: Vec::new(),
        }
    }

    /// The pointers this firing names, for a refusal composed from prose
    /// (CLOUD-2075). A declared refusal takes them from its subjects instead.
    #[must_use]
    pub fn at(mut self, subjects: impl Into<String>) -> Refusal {
        self.subjects = subjects.into();
        self
    }

    /// The refusal for a config that did not load (CLOUD-2075).
    ///
    /// Identical to [`Refusal::new`] since CLOUD-2142: it used to drop the line's
    /// hop because no `[[rule]]` row resolved without a config, and now
    /// `policy explain` answers an engine id from [`crate::verdict::native_definition`]
    /// with no config at all, so the hop resolves and stays.
    #[must_use]
    pub fn unloaded(rule: impl Into<String>, reason: impl Into<String>, fix: Fix) -> Refusal {
        Refusal::new(rule, reason, fix)
    }

    /// Name the reader each document route's target is read through, where the
    /// consumer's `[[redirect]]` declares one (CLOUD-2075).
    #[must_use]
    pub fn read_through(mut self, redirects: &[crate::redirect::Redirect]) -> Refusal {
        for route in &self.routes {
            if route.kind == crate::verdict::RouteKind::Document
                && let Some(reader) = crate::redirect::resolve_read(redirects, &route.target)
            {
                self.readers.insert(route.target.clone(), reader.to_owned());
            }
        }
        self
    }

    /// The same finding, printed under `severity` — an advisory channel's.
    #[must_use]
    pub fn with_severity(mut self, severity: Severity) -> Refusal {
        self.severity = severity;
        self
    }

    /// The one projection (CLOUD-2075); see [`finding_line`].
    #[must_use]
    pub fn render_finding(&self, arm: Arm) -> String {
        finding_line(self, arm)
    }

    /// The row's own remedy: the `Fix::Run` text, unless it is one of the
    /// class's route targets already on the line.
    #[must_use]
    pub fn remedy(&self) -> Option<&str> {
        let text = self.fix.declared_alternative()?;
        if self.routes.iter().any(|route| route.target == text) {
            return None;
        }
        Some(text)
    }

    /// `(id, precondition)` for each override route the class declares.
    #[must_use]
    pub fn preconditions(&self) -> Vec<(&str, &str)> {
        self.routes
            .iter()
            .filter(|route| route.kind == crate::verdict::RouteKind::Override)
            .filter_map(|route| Some((route.id.as_str(), route.precondition.as_deref()?)))
            .collect()
    }

    /// Build one of Batten's OWN refusals, from a declared class (CLOUD-1050).
    ///
    /// The caller names a [`crate::verdict::Native`] variant and the pointers it
    /// can offer; the gloss and the remedy come off the vendored registry, so
    /// neither is a string this call site chose. That is what makes CLOUD-122's
    /// contract structural on the native path: [`crate::verdict::validate`]
    /// refuses a class with no route and refuses one whose only route is an
    /// override, so a site physically cannot construct a refusal with no way out.
    ///
    /// `fix` is still a parameter rather than derived outright, because two of
    /// these sites can offer something narrower than the class's own route — the
    /// consumer's declared `redirect` for a protected path, for one — and a
    /// three-tier fallback that could only ever make a refusal MORE specific is
    /// worth keeping. Passing [`Fix::None`] takes the declared route.
    #[must_use]
    pub fn declared(
        rule: impl Into<String>,
        native: crate::verdict::Native,
        subjects: &[crate::verdict::Subject],
        fix: Fix,
    ) -> Refusal {
        let registry = crate::verdict::vendored();
        Refusal::from_class(rule, &registry, native.id(), subjects, fix)
    }

    /// One of Batten's own refusals with NO `[[rule]]` row behind it
    /// (CLOUD-2078): a CLI failure, a Stop rung, a handler's report, a capture
    /// notice, a failing doctor check, a land stop.
    ///
    /// [`Refusal::declared`] with an empty rule, so the line prints the class
    /// label alone and its one lookup hop names the class. The engine's own
    /// discriminating id travels in `subjects` instead — a doctor check's name,
    /// `hook.handler.<id>`, a capture reason.
    #[must_use]
    pub fn engine(
        native: crate::verdict::Native,
        subjects: &[crate::verdict::Subject],
        fix: Fix,
    ) -> Refusal {
        Refusal::declared(String::new(), native, subjects, fix)
    }

    /// The same constructor, over a registry and a token the caller resolved.
    ///
    /// **Not a third constructor** (CLOUD-1285 is explicit about not writing
    /// one): [`Refusal::declared`] is this function with the token taken from a
    /// [`crate::verdict::Native`], and every line below used to live there. It is
    /// split out because a POLICY MODULE's refusal carries a token the module
    /// raised and the consumer's registry declares, so there is no `Native` to
    /// name — and before this that path called [`Refusal::new`] and threw the
    /// class away, leaving `verdict()` as `None` even though it had already
    /// rendered the class's own line.
    #[must_use]
    pub fn from_class(
        rule: impl Into<String>,
        registry: &[crate::verdict::DeclaredVerdict],
        token: &str,
        subjects: &[crate::verdict::Subject],
        fix: Fix,
    ) -> Refusal {
        let fix = match fix {
            Fix::Run(text) => Fix::Run(text),
            Fix::None => Fix::declared(crate::verdict::first_command_route(registry, token)),
        };
        Refusal {
            rule: rule.into(),
            severity: Severity::Deny,
            // Resolved here rather than at the boundary because the registry is
            // already in hand — a second lookup downstream would be a second
            // authority over which routes the class declares.
            routes: crate::verdict::resolve(registry, token)
                .map(|(entry, _)| entry.routes.clone())
                .unwrap_or_default(),
            subjects: crate::verdict::render_subjects(subjects),
            readers: std::collections::BTreeMap::new(),
            gloss: crate::verdict::gloss_of(registry, token)
                .unwrap_or_default()
                .to_owned(),
            doc: crate::verdict::resolve(registry, token)
                .map(|(entry, _)| entry.doc.clone())
                .unwrap_or_default(),
            verdict: Some(token.to_owned()),
            reason: crate::verdict::render_line(registry, token, subjects),
            fix,
            bindings: admission_bindings(token, subjects),
        }
    }

    /// The rendered subjects, as the ` at ` clause prints them.
    #[must_use]
    pub fn subjects_text(&self) -> &str {
        &self.subjects
    }

    /// Fold `other` into this refusal when the two differ only in their subjects
    /// (CLOUD-2175): one class raised over several subjects in one emission is
    /// one line naming them all, so its label, routes and definition are paid
    /// once. `false`, and nothing changed, for any other pair.
    pub fn absorb(&mut self, other: &Refusal) -> bool {
        let same = self.rule == other.rule
            && self.verdict == other.verdict
            && self.routes == other.routes
            && self.fix == other.fix
            && self.gloss == other.gloss
            && self.readers == other.readers;
        if !same || self.verdict.is_none() {
            return false;
        }
        if other.subjects != self.subjects && !other.subjects.is_empty() {
            if !self.subjects.is_empty() {
                self.subjects.push_str(", ");
            }
            self.subjects.push_str(&other.subjects);
            for binding in &other.bindings {
                if !self.bindings.contains(binding) {
                    self.bindings.push(binding.clone());
                }
            }
        }
        true
    }

    /// Every spelling a mediated admission binds to, printed spelling first
    /// ([`admission_bindings`]). Empty only for a consumer-composed refusal.
    #[must_use]
    pub fn bindings(&self) -> &[String] {
        &self.bindings
    }

    /// The declared class, or `None` for a refusal composed from consumer prose.
    #[must_use]
    pub fn verdict(&self) -> Option<&str> {
        self.verdict.as_deref()
    }

    /// The id that refused.
    #[must_use]
    pub fn rule(&self) -> &str {
        &self.rule
    }

    /// Why it refused.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// The fix disposition.
    #[must_use]
    pub fn fix(&self) -> &Fix {
        &self.fix
    }

    /// Every non-override route the class declares, rendered by kind
    /// (CLOUD-1386, CLOUD-1637).
    ///
    /// **All of them, not the first**, and that distinction is the row: `fix`
    /// carries one route because it renders on every firing and a list there is
    /// the per-firing cost CLOUD-1286 measured. This renders once per session,
    /// where picking by declaration order withholds the route a reader needs —
    /// measured on `leased-push`, whose second route is the one that works.
    ///
    /// **And every KIND, not only `command`.** Filtering to what the agent runs
    /// left 144 of 201 classes with an empty list and therefore a bare line on
    /// the first sighting too; a `document` route is a way out, and saying `read
    /// rules/scanning.md` is what the reader of a refused `grep` needed.
    /// [`crate::verdict::sighting_routes`] carries the mapping and the exhaustive
    /// match that keeps a future kind from being dropped silently.
    ///
    /// Rendered exactly as the line carries them, override routes included
    /// (CLOUD-2075).
    #[must_use]
    pub fn routes(&self) -> Vec<String> {
        routes(self)
    }

    /// What the sightings store keys this refusal by: the rule, the class and
    /// the definition (CLOUD-2075).
    ///
    /// Read off the full arm through [`parse_finding`], so ONE authority keys
    /// both a refusal the engine built and a line the boundary read back from
    /// tool output.
    #[must_use]
    pub fn sighting_key(&self) -> String {
        let full = self.render_finding(Arm::Full);
        parse_finding(&full).map_or(full, |parsed| parsed.key)
    }

    /// The class's one-line gloss, or empty for a refusal with no class.
    ///
    /// The first-sighting arm's payload. Undroppable by contract there: routes
    /// are what a ceiling sheds, the gloss is what it never does, because a
    /// reader who cannot act on a bare token is exactly the case the arm exists
    /// for.
    #[must_use]
    pub fn gloss(&self) -> &str {
        &self.gloss
    }

    /// The machine-readable payload: `{rule, reason, fix}`, byte-stable.
    ///
    /// `hook` has no `-J` channel by design — its stdout is already a
    /// harness-shaped decision document, and a second JSON shape on the same
    /// stream would break the decision channel CLOUD-40 pinned — so this is the
    /// shape a data-emitting surface projects, and what pins the serialization in
    /// tests today.
    ///
    /// # Errors
    ///
    /// Serialization of this fixed shape cannot practically fail; the `Result` is
    /// the honest signature for a serde boundary.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }
}

/// One clause, terminated exactly once.
///
/// A config author writes a paragraph ending in a period and the crate writes a
/// bare command; both are spliced into the same sentence slot, so the terminator
/// is normalised here rather than at each call site. Keeps the rendering a pure
/// function of its inputs, which is what §6 byte-stability needs.
fn sentence(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.ends_with(['.', '!', '?']) {
        trimmed.to_owned()
    } else {
        format!("{trimmed}.")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// AN ENGINE FINDING NAMES ITS CLASS, NEVER A RULE NOTHING RESOLVES
    /// (CLOUD-2078), and its first sighting names no raising row: it has none.
    #[test]
    fn an_engine_finding_carries_no_rule_label() {
        let refusal = Refusal::engine(
            crate::verdict::Native::RunBroken,
            &[crate::verdict::artifact("disk full")],
            Fix::None,
        );
        let class = crate::verdict::Native::RunBroken.id();
        for arm in [Arm::Pointer, Arm::Full] {
            let line = refusal.render_finding(arm);
            assert!(
                line.starts_with(&format!("batten deny {class} at disk full")),
                "the class leads, then the subject: {line}"
            );
            if arm == Arm::Full {
                assert!(!line.contains(" — :"), "no raising row: {line}");
            }
            let parsed = parse_finding(&line).expect("an engine line parses");
            assert_eq!(parsed.verdict.as_deref(), Some(class), "{line}");
            assert!(parsed.rule.is_empty(), "{line}");
        }
    }

    /// A CLASSLESS ROW IS NAMED BY ITS OWN ID (CLOUD-2145): a consumer row with
    /// no class has no other name, so its id stands where a class would.
    #[test]
    fn a_rule_finding_opens_with_its_rule_label() {
        let refusal = Refusal::new("some-gate", "it fired", Fix::None);
        for arm in [Arm::Pointer, Arm::Full] {
            let line = refusal.render_finding(arm);
            assert!(line.starts_with("batten deny some-gate"), "named: {line}");
            let parsed = parse_finding(&line).expect("a headed line parses");
            assert_eq!(parsed.verdict.as_deref(), Some("some-gate"), "{line}");
        }
    }

    /// A FAILURE CHAIN IS ONE LINE (CLOUD-2078): every cause's first line is a
    /// subject, outermost first, and what follows a first line is returned to
    /// print after the finding rather than broken across it.
    #[test]
    fn a_failure_chain_renders_one_classed_line_and_returns_the_rest() {
        let failure = anyhow::anyhow!("disk full\ncaret detail").context("write the store");
        let (refusal, rest) = of_failure(&failure).expect("an internal failure renders");
        assert_eq!(
            refusal.verdict(),
            Some(crate::verdict::Native::RunBroken.id())
        );
        let line = refusal.render_finding(Arm::Pointer);
        let outer = line.find("write the store").expect("outer cause named");
        let inner = line.find("disk full").expect("inner cause named");
        assert!(outer < inner, "outermost first: {line}");
        assert!(!line.contains('\n'), "one line: {line}");
        assert_eq!(rest, "caret detail");
    }

    /// `of_rule` (CLOUD-2078): a row's `fix` is the remedy a full arm names, and
    /// a row's `no_fix_reason` is its definition.
    #[test]
    fn a_rules_fix_is_its_remedy_and_its_reason_its_definition() {
        let fix =
            crate::findings::Remediation::Fix(vec!["mise".into(), "run".into(), "unban".into()]);
        let fixed = of_rule("banned", &[], 3, Some(&fix)).render_finding(Arm::Full);
        assert!(fixed.contains("mise run unban"), "{fixed}");
        assert!(fixed.contains("at 3 finding(s)"), "{fixed}");
        let why = crate::findings::Remediation::NoFix("by hand".into());
        let reasoned = of_rule("banned", &[], 1, Some(&why)).render_finding(Arm::Full);
        assert!(reasoned.contains("by hand"), "{reasoned}");
    }

    /// A usage refusal whose message is ALREADY a rendered finding is printed
    /// as it is, never nested as the subject of `input parse refused`.
    #[test]
    fn a_rendered_usage_refusal_is_not_wrapped_in_a_second_finding() {
        let inner = Refusal::declared(
            "banned",
            crate::verdict::Native::SpawningRuleOnReadVerb,
            &[crate::verdict::artifact("command")],
            Fix::None,
        )
        .render_finding(Arm::Full);
        let failure = crate::UsageError::raise(inner);
        assert!(of_failure(&failure).is_none(), "printed as raised");
        let plain = crate::UsageError::raise("unexpected argument");
        assert!(
            of_failure(&plain).is_some(),
            "a prose refusal is still classed"
        );
    }

    #[test]
    fn the_payload_carries_an_explicit_null_rather_than_dropping_the_key() {
        // The acceptance's load-bearing half: a consumer cannot tell an omitted
        // field from one the producer forgot, so "no safe remedy" is a value.
        let refusal = Refusal::new("some-gate", "it fired", Fix::None);
        assert_eq!(
            refusal.to_json().expect("the fixed shape serializes"),
            r#"{"rule":"some-gate","verdict":null,"reason":"it fired","fix":null}"#
        );
    }

    #[test]
    fn a_refusal_from_consumer_prose_declares_no_class() {
        // The direction that keeps the key honest (CLOUD-1050). A refusal
        // composed from a `[[rule]]` row's own `reason` is the CONSUMER's
        // statement, and labelling it with a Batten class would make the two
        // indistinguishable to any reader keying on the token — which is the
        // whole reason the token exists.
        assert_eq!(
            Refusal::new("some-gate", "it fired", Fix::None).verdict(),
            None
        );
    }

    #[test]
    fn a_native_refusal_carries_its_declared_class_and_that_classs_remedy() {
        // The other direction, and the structural half of CLOUD-122. Nothing at
        // the call site chose either the gloss or the fix: passing `Fix::None`
        // takes the class's first `command` route, and `verdict::validate`
        // refuses a class that declares none reachable — so a native site cannot
        // construct a refusal with no way out even by omission.
        let refusal = Refusal::declared(
            "provision",
            crate::verdict::Native::ScannerUnprovisioned,
            &[crate::verdict::Subject::Artifact {
                artifact: "gitleaks".to_owned(),
            }],
            Fix::None,
        );
        assert_eq!(refusal.verdict(), Some("scanner install missing"));
        assert!(
            refusal.reason().starts_with("scanner install missing"),
            "the hot path leads with the token: {}",
            refusal.reason()
        );
        assert!(
            !refusal.reason().contains('('),
            "and does not inline the class's own definition after it (CLOUD-1286): {}",
            refusal.reason()
        );
        assert!(
            refusal.reason().ends_with(" gitleaks"),
            "and carries the pointer inline rather than behind `explain`: {}",
            refusal.reason()
        );
        assert_eq!(
            refusal.fix(),
            &Fix::Run("batten provision".to_owned()),
            "the remedy came off the declared route, not off this call site"
        );
    }

    #[test]
    fn a_narrower_fix_at_the_site_still_wins_over_the_declared_route() {
        // The protected-path tier (CLOUD-280): a consumer's own `[[redirect]]`
        // is more specific than the class's general route, so the class is a
        // FLOOR rather than a ceiling. Without this the migration would have
        // silently flattened three tiers into one.
        let refusal = Refusal::declared(
            "protected-mutation",
            crate::verdict::Native::ProtectedMutation,
            &[],
            Fix::Run("use `serena rename_memory`".to_owned()),
        );
        assert_eq!(
            refusal.fix(),
            &Fix::Run("use `serena rename_memory`".to_owned())
        );
    }

    #[test]
    fn a_declared_fix_is_the_bare_string_never_a_tagged_variant() {
        let refusal = Refusal::new("some-gate", "it fired", Fix::Run("run this".to_owned()));
        assert_eq!(
            refusal.to_json().expect("the fixed shape serializes"),
            r#"{"rule":"some-gate","verdict":null,"reason":"it fired","fix":"run this"}"#
        );
    }

    #[test]
    fn the_payload_is_byte_stable() {
        // §6: same input, same bytes. Nothing here reads a clock or a path, so
        // this is a property of the type rather than of the caller.
        let refusal = Refusal::new("some-gate", "it fired", Fix::Run("run this".to_owned()));
        assert_eq!(refusal.to_json().unwrap(), refusal.to_json().unwrap());
    }

    #[test]
    fn every_line_names_its_rule_hop_whatever_the_fix() {
        // NO LINE CARRIES A LOOKUP HOP (CLOUD-2145): the legend says once how a
        // name is looked up, and the name itself is the argument. Both
        // dispositions, and a config that did not load, keep the name.
        for fix in [Fix::None, Fix::Run("do this".to_owned())] {
            let full = Refusal::new("g", "why", fix).render_finding(Arm::Full);
            assert!(full.starts_with("batten deny g"), "{full}");
            assert!(!full.contains("policy explain"), "{full}");
        }
        let unloaded = Refusal::unloaded("g", "why", Fix::None).render_finding(Arm::Full);
        assert!(unloaded.starts_with("batten deny g"), "{unloaded}");
    }

    #[test]
    fn a_clause_is_terminated_exactly_once() {
        // A config author's paragraph already ends in a period; a bare command
        // does not. Both land in the same slot, so the terminator is normalised
        // rather than doubled.
        let authored = Refusal::new("g", "Because it does.", Fix::Run("mise run x".to_owned()));
        assert_eq!(
            authored.render_finding(Arm::Full),
            "batten deny g — Because it does. Do: mise run x."
        );
        let bare = Refusal::new("g", "because it does", Fix::Run("mise run x.".to_owned()));
        assert_eq!(
            bare.render_finding(Arm::Full),
            "batten deny g — because it does. Do: mise run x."
        );
    }

    #[test]
    fn the_pointer_arm_is_a_byte_prefix_of_the_full_arm() {
        let refusal = Refusal::declared(
            "protected-mutation",
            crate::verdict::Native::ProtectedMutation,
            &[crate::verdict::Subject::Path {
                path: "docs/a.md".to_owned(),
            }],
            Fix::None,
        );
        let full = refusal.render_finding(Arm::Full);
        let pointer = refusal.render_finding(Arm::Pointer);
        assert!(full.starts_with(&pointer), "{pointer}\n{full}");
        assert!(!pointer.contains(" —"), "{pointer}");
        assert!(
            pointer.starts_with("batten deny path write refused at "),
            "{pointer}"
        );
        let parsed = parse_finding(&full).expect("the full arm parses");
        assert_eq!(parsed.arm, Arm::Full);
        assert_eq!(parsed.verdict.as_deref(), Some("path write refused"));
        assert_eq!(
            parse_finding(&pointer).expect("the pointer parses").arm,
            Arm::Pointer
        );
        assert_eq!(parsed.key, refusal.sighting_key());
    }

    #[test]
    fn a_quote_in_a_name_round_trips_through_the_grammar() {
        let line = format!("{} — x.", label(Label::Rule, "it's"));
        assert_eq!(parse_finding(&line).expect("parses").rule, "it's");
        assert!(parse_finding("not a finding").is_none());
    }

    #[test]
    fn collapse_cuts_a_marked_full_arm_to_its_pointer_prefix() {
        let full = Refusal::new("g", "why", Fix::None).render_finding(Arm::Full);
        let pointer = Refusal::new("g", "why", Fix::None).render_finding(Arm::Pointer);
        let text = format!("{full}\ncanary\n{full}\n{pointer}\nrule 'unterminated");
        let mut seen = std::collections::HashSet::new();
        let cut = collapse(&text, |key, _| seen.insert(key.to_owned()));
        assert_eq!(
            cut,
            format!("{full}\ncanary\n{pointer}\n{pointer}\nrule 'unterminated")
        );
    }

    #[test]
    fn an_absent_or_blank_declaration_is_none_never_an_empty_fix() {
        // `declared` is the one adapter from the config columns that are
        // `Option<String>`. A whitespace-only value is a declaration nobody made,
        // and rendering it would produce `Fix: .` — a fix clause that is present
        // and says nothing, which is worse than the explicit none.
        assert_eq!(Fix::declared(None), Fix::None);
        assert_eq!(Fix::declared(Some("   ")), Fix::None);
        assert_eq!(Fix::declared(Some(" x ")), Fix::Run("x".to_owned()));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod sightings {
    use super::*;

    /// A git repository to key the store against.
    fn repo(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("batten-sighting-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the fixture directory");
        // A real git directory, because `first_sighting` keys its store off
        // `$GIT_DIR`: without one every case below measures the unreadable-store
        // arm instead of the once-per-session one under test. In-process through
        // `gix` — the fixture needs a `.git`, not the git binary (CLOUD-1924).
        crate::gitwrite::init_on_main(&dir).expect("git init");
        dir
    }

    /// ONCE, THEN NEVER — and both halves are the assertion.
    ///
    /// The first half alone is satisfied by a predicate that always answers true,
    /// which is the "always" rendering CLOUD-1286 removed for cost. The second
    /// alone is satisfied by one that always answers false, which is the "never"
    /// rendering that cost a session. Neither is right and only the pair says so.
    #[test]
    fn a_class_explains_itself_once_and_then_stops() {
        let dir = repo("once");
        assert!(
            first_sighting(&dir, "s", "branch write unsafe", "full"),
            "a class this context has not raised explains itself"
        );
        assert!(
            !first_sighting(&dir, "s", "branch write unsafe", "full"),
            "and does not explain itself a second time"
        );
    }

    /// The store is KEYED, so one class going quiet does not silence another.
    #[test]
    fn each_class_is_counted_on_its_own() {
        let dir = repo("keyed");
        assert!(first_sighting(&dir, "s", "branch write unsafe", "a"));
        assert!(
            first_sighting(&dir, "s", "path write refused", "b"),
            "a different class has still never been seen"
        );
    }

    /// THE CLEAR IS THE LOAD-BEARING HALF, and it is per context: forgetting one
    /// context leaves another's sightings alone (CLOUD-2075).
    #[test]
    fn a_new_session_hears_it_again() {
        let dir = repo("cleared");
        assert!(first_sighting(&dir, "a", "branch write unsafe", "full"));
        assert!(first_sighting(&dir, "b", "branch write unsafe", "full"));
        assert!(!first_sighting(&dir, "a", "branch write unsafe", "full"));

        forget_sightings(&dir, "a");
        assert!(
            first_sighting(&dir, "a", "branch write unsafe", "full"),
            "session start forgets, so the next reader is told"
        );
        assert!(
            !first_sighting(&dir, "b", "branch write unsafe", "full"),
            "and another context keeps what it saw"
        );
    }

    /// The legend rides the first delivery of an epoch and no later one, and a
    /// forgotten context hears it again (CLOUD-2145).
    #[test]
    fn the_legend_comes_once_per_epoch() {
        let dir = repo("legend");
        let first = with_legend(&dir, "s", "line one");
        assert!(first.starts_with(LEGEND) && first.ends_with("line one"));
        assert_eq!(with_legend(&dir, "s", "line two"), "line two");
        assert!(
            with_legend(&dir, "t", "other").starts_with(LEGEND),
            "another context is its own epoch"
        );
        forget_sightings(&dir, "s");
        assert!(with_legend(&dir, "s", "again").starts_with(LEGEND));
    }

    /// A TREE WITH NO GIT DIRECTORY ANSWERS TRUE, which is the safe direction:
    /// an unreachable store costs a clause, where the opposite default costs a
    /// reader the only actionable part of the refusal.
    #[test]
    fn an_unreachable_store_explains_itself_rather_than_going_quiet() {
        let dir = std::env::temp_dir().join(format!("batten-no-git-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the fixture directory");
        assert!(first_sighting(&dir, "s", "branch write unsafe", "full"));
        assert!(
            first_sighting(&dir, "s", "branch write unsafe", "full"),
            "and keeps doing so, because nothing could record that it had"
        );
    }
}
