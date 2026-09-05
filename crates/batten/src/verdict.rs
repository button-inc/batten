//! The refusal vocabulary: what a gate may say, declared once as data
//! (CLOUD-1050).
//!
//! # The defect this closes
//!
//! A refusal was a **free string**. `policy::Violation { rule, msg }` and the
//! native `Refusal { rule, reason, fix }` both carried prose no mechanism could
//! check, so every remedy defect CLOUD-122 and CLOUD-871 named was expressible
//! and none was checkable: a refusal could name no remedy, name a task that does
//! not exist, offer an override with no precondition, or say the same thing in
//! nineteen spellings — and every one of those passes a string field.
//!
//! CLOUD-843's migration is the deadline rather than the motive. Every gate
//! ported to Rego under the free-string shape is a gate ported twice.
//!
//! # What replaces it
//!
//! A refusal is `{rule, verdict, subjects}`:
//!
//! * `rule` — the predicate id that fired, unchanged (CLOUD-832).
//! * `verdict` — a **token** declared in this registry. The prose lives here,
//!   once, where a gate can read it.
//! * `subjects` — ordered pointers, each a tagged variant. Never a payload
//!   (non-negotiable rule 4).
//!
//! The registry is the sole authority for **both** emitters, which is the
//! reversal CLOUD-1050 records of its own first review: a policy-only registry
//! plus a native authority is the drift defect one layer up, and the two would
//! disagree the first time either moved.
//!
//! # Deny-only survives, by construction
//!
//! A verdict declares refusal classes and nothing else. There is no allow
//! spelling here for the same reason `.claude/rules/policy-modules.md` gives for
//! the module shape: enabling a vocabulary can only ever add ways to refuse, so
//! house style §8's raise-only invariant is untouched.
//!
//! # What the config spelling is, and why it is not `[[policy.verdict]]`
//!
//! CLOUD-1050's body writes the table as `[[policy.verdict]]`. It is spelled
//! `[[verdict]]` here, and the reason is the surface rather than the row: every
//! named table this config already carries — `[[pattern]]`, `[[verb]]`,
//! `[[redirect]]` — is top level, and a nested one introduces a second nesting
//! convention for a single row type while deciding nothing differently. The
//! registry's semantics are exactly the ones the row specifies.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::error::UsageError;

// THE `V-` AND `R-` PREFIXES ARE GONE (CLOUD-1284).
//
// They existed to make a token recognisable AS a token in a line that also
// carries a rule id and a path, and a fixed prefix bought that without a
// convention a reader had to know. The three-word grammar buys the same thing
// and more cheaply: fixed arity is what separates the name from the pointers,
// so the prefix was paying tokens for a job the arity now does for free.
//
// Measured over all 130 classes with `tiktoken` `o200k_base`, and the prefix is
// most of the bill rather than a rounding error: `screaming kebab probe` costs 9.9
// tokens on average against a curated three-word name's 3.0, and the drop from
// `V-` plus the uppercase run alone is 9.9 -> 5.2. At ~300 refusals a session
// that is ~2,000 tokens the agent used to pay for a sigil.

/// The longest a gloss may be.
///
/// The gloss is the **hot path's whole payload** (CLOUD-1053): one line, beside
/// a token and a pointer. A bound here is what keeps "one line" a property of
/// the data rather than of the author's restraint — the class definition is
/// where a paragraph goes, and `batten policy explain` is what fetches it.
const GLOSS_MAX: usize = 120;

/// What a route offers the reader.
///
/// **A closed set, deliberately.** The whole defect is a remedy nobody can
/// check; an open `kind` string would put it straight back, because a typo'd
/// kind would be a route that resolves to nothing and refuses nothing.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RouteKind {
    /// Run something. `target` is the command.
    Command,
    /// Read something in this tree. `target` is a repo-relative path.
    Document,
    /// Take it to the tracker. `target` is the issue key.
    Issue,
    /// Ask for the refusal to be lifted. `target` is unread; `precondition` is
    /// what the asker must be able to state, and is required (CLOUD-1051 reads
    /// it to generate the questions an admission answers).
    Override,
}

impl RouteKind {
    /// The token a rendered route carries.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            RouteKind::Command => "command",
            RouteKind::Document => "document",
            RouteKind::Issue => "issue",
            RouteKind::Override => "override",
        }
    }
}

/// One way out of a refusal.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Route {
    /// The id a rendered refusal names, e.g. `task read first`.
    ///
    /// Stable and referenceable: an agent told `task read first` twice has
    /// been told the same thing twice, which a paraphrase cannot establish.
    pub id: String,
    /// Which kind of way out this is.
    pub kind: RouteKind,
    /// What it points at, read according to [`Route::kind`].
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub target: String,
    /// What the asker must be able to state. [`RouteKind::Override`] only, and
    /// required there.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precondition: Option<String>,
}

/// One declared vocabulary word: the spelling, and what it means in a name.
///
/// The gloss is what makes dropping the per-class essay from the hot path safe
/// rather than merely cheap (CLOUD-1284). A class used to buy a new essay to
/// explain its own free-text name; a word buys one gloss that every name using
/// it reuses, so the *marginal* class costs no new prose at all.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VocabularyWord {
    /// The spelling, as it appears in a name. One token under the declared pin.
    pub word: String,
    /// What this word contributes to a name that uses it.
    pub gloss: String,
}

/// The three positional lists a name is drawn from, and the pin they were
/// measured under (CLOUD-1284).
///
/// # Why the middle list is `action` and not `verb`
///
/// The grammar is `<subject> <action> <condition>` and the issue writes the
/// middle slot as "verb". The config key cannot be `verb`: `[[verb]]` is already
/// this config's table of mutating **shell** verbs, and two unrelated tables one
/// letter apart is the drift a reader pays for every time. The prose keeps the
/// grammatical word; the key states which table it belongs to.
///
/// # Why the pin is data and not a constant
///
/// The token counts are model-specific, and `bench/tokens/method.toml` already
/// sets this repository's discipline for a constant a published figure depends
/// on: state it with its source and the date it was read, so a reader checks the
/// arithmetic against the primary rather than trusting a program. The *ratio*
/// argument survives a different tokenizer — common English words are
/// single-merge in every modern BPE vocabulary — but the exact integer does not,
/// so the integer's provenance travels with it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Vocabulary {
    /// The encoding every word's token count was measured under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokenizer: Option<String>,
    /// Where that encoding is published.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokenizer_source: Option<String>,
    /// When it was read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokenizer_retrieved: Option<String>,
    /// Slot 1: what the finding is about.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subject: Vec<VocabularyWord>,
    /// Slot 2: what was done, or what relation is being judged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub action: Vec<VocabularyWord>,
    /// Slot 3: the state that makes it a refusal.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub condition: Vec<VocabularyWord>,
}

impl Vocabulary {
    /// The list for one slot, by position.
    fn slot(&self, position: usize) -> &[VocabularyWord] {
        match position {
            0 => &self.subject,
            1 => &self.action,
            _ => &self.condition,
        }
    }

    /// Whether this vocabulary declares anything at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.subject.is_empty() && self.action.is_empty() && self.condition.is_empty()
    }

    /// Every declared word, with the slot it was declared in.
    fn words(&self) -> impl Iterator<Item = (usize, &VocabularyWord)> {
        (0..SLOTS).flat_map(move |slot| self.slot(slot).iter().map(move |word| (slot, word)))
    }
}

/// The name of each slot, for a refusal that has to say which one failed.
const SLOT_NAMES: [&str; SLOTS] = ["subject", "action", "condition"];

/// Fixed arity, and it is load-bearing rather than stylistic (CLOUD-1284).
///
/// **Exactly three, never `<= N`.** Fixed arity is what lets `<class> <pointer…>`
/// parse on one line with no delimiter between the class and the first pointer:
/// a reader — human or machine — takes three words and everything after them is
/// pointers. Relax it and the line needs a separator, which is the free-text
/// namespace this grammar replaced, wearing a delimiter.
const SLOTS: usize = 3;

/// One declared refusal class.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeclaredVerdict {
    /// The token, e.g. `task name undefined`.
    pub id: String,
    /// One line, the hot path's whole payload.
    pub gloss: String,
    /// What the class means, at length. `batten policy explain`'s payload, and
    /// the **deliberate exception** to pointer-only output (house style §6):
    /// `explain` is local documentation rather than a finding, and carrying the
    /// text the hot path no longer does is its entire purpose.
    pub class: String,
    /// The ways out, in the order a reader should consider them.
    #[serde(default, rename = "route", skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<Route>,
    /// The token that replaced this one, for a class that has been retired.
    ///
    /// A **tombstone**: the entry stays so a historical token is still
    /// explainable, which git history cannot do at runtime. A tombstone is
    /// exempt from the emitted-somewhere half of registry equality, because the
    /// whole point is that nothing emits it any more.
    ///
    /// One of **two** retirement arms — see [`DeclaredVerdict::withdrawn`] for
    /// the other, and why naming both is refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub successor: Option<String>,
    /// Why this class was **withdrawn**, for one that was not replaced at all
    /// (CLOUD-1114).
    ///
    /// The second retirement arm, and it exists because the first cannot express
    /// this case. A class can be withdrawn rather than replaced — the thing it
    /// refused should no longer be refused by anything — so there is no successor
    /// and naming one would be a false claim about where the class went. Before
    /// this arm the only ways past were to invent a successor that does not hold
    /// the predicate, or to delete the row and lose the ability to explain a
    /// historical token, which is the whole thing a tombstone exists for.
    ///
    /// **It owes a reason and names no target**, exactly as
    /// [`crate::rules::Conserves::withdrawn`] does one registry over (CLOUD-1080,
    /// the precedent for this arm's shape): a column demanding a target here
    /// would be the invented successor again. An empty reason is refused, so the
    /// arm cannot be spent as a bare "gone".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdrawn: Option<String>,
}

impl DeclaredVerdict {
    /// Whether this entry is a tombstone, by **either** arm.
    ///
    /// A withdrawn class is as retired as a replaced one — that is the point of
    /// the arm — so the tombstone exemption from the emitted-somewhere half of
    /// registry equality covers both, and a withdrawn token is still wrong to
    /// emit.
    #[must_use]
    pub fn retired(&self) -> bool {
        self.successor.is_some() || self.withdrawn.is_some()
    }
}

/// One pointer a refusal carries.
///
/// **Tagged, ordered, and never a payload.** Each variant is a shape a reader
/// can act on: a file, a line in a file, a count, or a derived artifact. Prose
/// is not among them, which is what makes rule 4 structural here rather than a
/// habit each emitter has to keep.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(untagged)]
pub enum Subject {
    /// A path in this tree.
    Path {
        /// The repo-relative path.
        path: String,
    },
    /// A path and a line in it.
    Line {
        /// The repo-relative path.
        path: String,
        /// The 1-based line.
        line: u64,
    },
    /// How many. The shape a finding over a whole set takes, where naming one
    /// member would misdirect.
    Count {
        /// The number.
        count: u64,
    },
    /// A named thing that is not a path — a task, a rule id, a token, a tool.
    Artifact {
        /// The name.
        artifact: String,
    },
}

impl Subject {
    /// The pointer as one line of output.
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Subject::Path { path } => path.clone(),
            Subject::Line { path, line } => format!("{path}:{line}"),
            Subject::Count { count } => count.to_string(),
            Subject::Artifact { artifact } => artifact.clone(),
        }
    }

    /// Read one subject off a policy module's `subjects` array.
    ///
    /// `None` is could-not-look, never an empty subject: a member whose shape
    /// this cannot read is a module speaking a dialect the decoder does not
    /// have, and inventing a pointer for it would put the engine's words in the
    /// module's mouth.
    ///
    /// The arms are tried **most specific first** — `{path, line}` before
    /// `{path}` — because `untagged` decoding is order-sensitive and a
    /// line-bearing subject read as a bare path silently loses the line.
    #[must_use]
    pub fn from_json(value: &serde_json::Value) -> Option<Subject> {
        let object = value.as_object()?;
        let path = object.get("path").and_then(serde_json::Value::as_str);
        let line = object.get("line").and_then(serde_json::Value::as_u64);
        match (path, line) {
            (Some(path), Some(line)) => {
                return Some(Subject::Line {
                    path: path.to_owned(),
                    line,
                });
            }
            (Some(path), None) => {
                return Some(Subject::Path {
                    path: path.to_owned(),
                });
            }
            _ => {}
        }
        if let Some(count) = object.get("count").and_then(serde_json::Value::as_u64) {
            return Some(Subject::Count { count });
        }
        if let Some(artifact) = object.get("artifact").and_then(serde_json::Value::as_str) {
            return Some(Subject::Artifact {
                artifact: artifact.to_owned(),
            });
        }
        None
    }
}

/// Render an ordered subject list as the pointer half of one line.
#[must_use]
pub fn render_subjects(subjects: &[Subject]) -> String {
    subjects
        .iter()
        .map(Subject::render)
        .collect::<Vec<String>>()
        .join(" ")
}

/// What a refusal says on the hot path: the token and its pointers, and stops
/// (CLOUD-1053, narrowed by CLOUD-1286).
///
/// ```text
/// task name undefined batten.toml:1604
/// ```
///
/// **The gloss is gone from this line and that is the whole change.** It used to
/// be emitted unconditionally, and it was ~28 of the ~43 tokens a rendered line
/// cost — the class's own definition, inlined on every one of the ~300 firings a
/// long session pays for, when the class is declared once and a reader who wants
/// it can ask. `batten policy explain <token>` is where it went, together with
/// the `class` prose that was never on this line at all.
///
/// **Dropping it is safe only because the token is a THREE-WORD DECLARED NAME**
/// (CLOUD-1284). Under the old SCREAMING-KEBAB free text this would have traded
/// concision for opacity; under the grammar the name is the gloss's short form,
/// which is what that row bought.
///
/// **The subject stays inline** rather than being dereferenced through
/// `explain`. Making a reader run a second command to learn WHICH file would
/// make the common case slower, which is the opposite of the point. This
/// shortens the prose, never the pointer.
///
/// A token the registry does not carry still renders as itself. It gets no
/// composed apology: `policy::load` refuses an undeclared token at load, so this
/// is reachable only on the mediated path where the AST check is skipped for
/// CLOUD-689's budget, and there the token alone is both the honest answer and
/// the one a reader can look up.
#[must_use]
/// The registry parameter is kept though this line no longer reads it: it is
/// what `explain` resolves the token against, and every call site already holds
/// it. Dropping it from the signature would be a churn across ten composers to
/// buy back one unused reference, and would have to be undone the moment the
/// line carries anything registry-derived again.
pub fn render_line(_registry: &[DeclaredVerdict], token: &str, subjects: &[Subject]) -> String {
    let pointers = render_subjects(subjects);
    if pointers.is_empty() {
        token.to_owned()
    } else {
        format!("{token} {pointers}")
    }
}

/// The first `command` route a class declares, which is what a refusal offers as
/// its fix.
///
/// **This is what makes CLOUD-122's contract structural.** A refusal used to
/// carry whatever remedy its emitter remembered to write; now the remedy comes
/// off the declared class, `validate` refuses a class with no route and refuses
/// one whose only route is an override, so "every refusal names a way out" is a
/// property of the data rather than of each emitter's care.
///
/// `None` when the class declares no command route — a `document` or `issue`
/// route is still a way out, and rendering it in the `Fix:` slot as if it were
/// something to run would be worse than the explicit "none declared" the empty
/// case already produces.
/// Every `command` route a class declares, joined for a first sighting
/// (CLOUD-1386).
///
/// **[`first_command_route`] stays what a `Fix:` clause takes**, because that
/// slot renders on every firing and a list there is the per-firing cost
/// CLOUD-1286 measured. This is the once-per-session projection, where that
/// budget does not apply and picking one route arbitrarily does real harm.
///
/// Measured: `leased-push` declares the rebase first and the explicit
/// `--force-with-lease=<ref>:<sha>` form second. A session read the first, could
/// not tell the class refuses a SPELLING rather than the action, and reported a
/// working gate as a defect. The route it needed was declared, ranked second, and
/// never rendered — so "the first one" is not a summary of the alternatives, it
/// is one of them chosen by declaration order.
///
/// Overrides are excluded, as they are from the `Fix:` slot: a way through that
/// begins by asking to be excused is not an alternative to the action, and
/// `override request` is its own surface.
#[must_use]
pub fn command_routes<'a>(registry: &'a [DeclaredVerdict], token: &str) -> Vec<&'a str> {
    let Some((entry, _)) = resolve(registry, token) else {
        return Vec::new();
    };
    entry
        .routes
        .iter()
        .filter(|route| route.kind == RouteKind::Command)
        .map(|route| route.target.as_str())
        .collect()
}

#[must_use]
pub fn first_command_route<'a>(registry: &'a [DeclaredVerdict], token: &str) -> Option<&'a str> {
    let (entry, _) = resolve(registry, token)?;
    entry
        .routes
        .iter()
        .find(|route| route.kind == RouteKind::Command)
        .map(|route| route.target.as_str())
}

/// Refuse a malformed registry, at load.
///
/// Every clause here decides a property of the **table**, never of a predicate
/// that might use it — the same division [`crate::pattern::validate`] draws, and
/// the reason both live at parse rather than at adjudication (house style §8).
///
/// The clauses, and what each exists to stop:
///
/// * a token is non-empty, `V-`-prefixed and unique — a duplicate makes
///   `explain` ambiguous and a refusal unattributable;
/// * a gloss is one line and within [`GLOSS_MAX`] — the hot path's payload
///   cannot be a paragraph, which is the regression CLOUD-1053 exists to
///   prevent;
/// * a class definition is present — a token with no meaning is a worse string
///   than the prose it replaced;
/// * **at least one route**, and not an override alone. A refusal whose only way
///   out is "ask for it to be waived" is the bare no this contract forbids;
/// * an override route carries a precondition, and a non-override does not —
///   CLOUD-1051 generates its questions from that field, so an empty one is an
///   override nobody can request;
/// * route ids are `R-`-prefixed and unique within their verdict;
/// * a successor names a token this table declares, and the tombstone chain
///   terminates in a live token without cycling.
///
/// **Route TARGET resolution is deliberately not here.** Whether `mise run x`
/// names a task this tree defines is a question about a task RUNNER, and
/// non-negotiable rule 1 keeps the core ignorant of one — the same argument
/// `policy/command-task-defined.rego` already makes for `[[rule]]` rows, which
/// is why the sibling clause for routes is a policy module rather than a line in
/// this function.
///
/// # Errors
///
/// A [`UsageError`] (exit `1`) naming the offending token. The declaration is
/// the config author's own text — the class `config show` exists to echo — so
/// naming it is inside rule 4.
pub fn validate(verdicts: &[DeclaredVerdict], vocabulary: &Vocabulary) -> anyhow::Result<()> {
    validate_vocabulary(vocabulary)?;
    // THE GRAMMAR IS OPT-IN, AND THAT IS THE SAME EXEMPTION `[[pattern]]` MAKES.
    //
    // A consumer who declares no `[vocabulary]` has no lists for a name to be
    // drawn from, so holding their classes to membership would refuse every
    // config that has not adopted the grammar — the wrongly-refusing gate
    // AGENTS.md calls a defect, with no fix available short of authoring 130
    // words. `crate::pattern`'s preset exemption is the landed precedent for
    // exactly this shape: a demand a consumer cannot satisfy is unsatisfiable
    // rather than strict.
    //
    // Declaring the table is what opts in, and it is all-or-nothing from there:
    // every class and every route is held, and arm 5 refuses a word nothing
    // spends. So the exemption cannot be spent as a partial adoption, which is
    // the direction that would let it rot.
    let grammar = if vocabulary.is_empty() {
        None
    } else {
        Some(vocabulary)
    };
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    // Arm 5's evidence, gathered while walking rather than by a second pass: a
    // word is used if some class or route name spends it in its own slot.
    let mut used: BTreeSet<(usize, String)> = BTreeSet::new();
    for verdict in verdicts {
        validate_one(verdict, grammar, &mut used)?;
        // ARM 3, uniqueness of the TRIPLE — and it is the duplicate-id refusal
        // unchanged, because under this grammar the id IS the triple. There is no
        // second uniqueness question to ask.
        if !seen.insert(verdict.id.as_str()) {
            return Err(UsageError::raise(format!(
                "verdict `{}` is declared twice; one class, one name — \
                 `batten policy explain {}` cannot resolve to two definitions",
                verdict.id, verdict.id
            )));
        }
    }
    if grammar.is_some() {
        // ARM 5 COUNTS THE VENDORED NAMES TOO, and without this the arm would
        // refuse a word only a `Native` or preset class spends (CLOUD-1285).
        // The vocabulary serves BOTH halves of the registry — `policy::
        // registry_for` unions them — so a word is an orphan only when nothing
        // in that union spends it. Membership is deliberately NOT checked
        // against the vendored half: a third-party consumer never declared the
        // words Batten's own classes use, and holding them to it would refuse
        // every config that has not copied this repository's vocabulary.
        let vendored = vendored();
        let mut spent = used;
        for entry in &vendored {
            mark_spent(&entry.id, &mut spent);
            for route in &entry.routes {
                mark_spent(&route.id, &mut spent);
            }
        }
        validate_no_orphan_words(vocabulary, &spent)?;
    }
    validate_chains(verdicts, &seen)
}

/// ARM 6, and the shape arms over the vocabulary table itself.
///
/// Separate from [`validate_one`] because these decide the DICTIONARY, not a
/// name that spends it — the same division [`crate::pattern::validate`] draws
/// between a pattern registry and the rows that cite it.
fn validate_vocabulary(vocabulary: &Vocabulary) -> anyhow::Result<()> {
    let mut seen: BTreeSet<(usize, &str)> = BTreeSet::new();
    for (slot, entry) in vocabulary.words() {
        let word = entry.word.as_str();
        let name = SLOT_NAMES[slot];
        if word.is_empty() || word.split_whitespace().count() != 1 {
            return Err(UsageError::raise(format!(
                "vocabulary `{name}`: `{word}` is not a single word — a slot holds one \
                 word, and a spelling carrying a space would make a three-word name \
                 parse as four"
            )));
        }
        if word.chars().any(|c| !c.is_ascii_lowercase()) {
            return Err(UsageError::raise(format!(
                "vocabulary `{name}`: `{word}` is not lowercase ASCII — the measured cost \
                 of this grammar is a property of the spelling, and an uppercase run is \
                 the worst case for a BPE vocabulary trained on running text"
            )));
        }
        // ARM 6. A word with no gloss is the free-text namespace back again: the
        // dictionary is what lets a reader take `task spelling weakened` with no
        // lookup, and a word that explains nothing explains nothing three hundred
        // times over.
        if entry.gloss.trim().is_empty() {
            return Err(UsageError::raise(format!(
                "vocabulary `{name}`: `{word}` carries no gloss — the dictionary is what \
                 replaced the per-class essay, so a word that means nothing declared makes \
                 every name spending it unreadable"
            )));
        }
        if !seen.insert((slot, word)) {
            return Err(UsageError::raise(format!(
                "vocabulary `{name}`: `{word}` is declared twice; one word, one meaning"
            )));
        }
    }
    Ok(())
}

/// Record each slot's word from a name that is already known to be well formed.
///
/// Takes owned copies because the vendored table is built on the fly, where the
/// consumer half is borrowed from the config that outlives this call.
fn mark_spent(name: &str, spent: &mut BTreeSet<(usize, String)>) {
    for (slot, word) in name.split(' ').enumerate().take(SLOTS) {
        spent.insert((slot, word.to_owned()));
    }
}

/// ARM 5: a word no name spends fails the load.
///
/// The mirror of the landed rule that a `[[verdict]]` row nothing raises fails
/// the load, one level down. Dead vocabulary reads as available headroom while
/// nothing has ever walked it, which is the same defect as a class no gate
/// reaches — and the headroom argument for three 64-word lists only holds if the
/// lists are honest about what is in them.
fn validate_no_orphan_words(
    vocabulary: &Vocabulary,
    used: &BTreeSet<(usize, String)>,
) -> anyhow::Result<()> {
    for (slot, entry) in vocabulary.words() {
        if !used.contains(&(slot, entry.word.clone())) {
            return Err(UsageError::raise(format!(
                "vocabulary `{}`: `{}` is declared and no class or route name spends it — \
                 a word nothing uses is dead vocabulary, which reads as headroom while \
                 nothing has walked it",
                SLOT_NAMES[slot], entry.word
            )));
        }
    }
    Ok(())
}

/// ARMS 1 and 2 over one name: exact arity, then membership per position.
///
/// `kind` names what is being judged (`verdict` or a verdict's `route`) so the
/// refusal points at the right table.
fn check_name(
    kind: &str,
    name: &str,
    vocabulary: &Vocabulary,
    used: &mut BTreeSet<(usize, String)>,
) -> anyhow::Result<()> {
    let words: Vec<&str> = name.split(' ').collect();
    // ARM 1.
    if words.len() != SLOTS {
        return Err(UsageError::raise(format!(
            "{kind} `{name}` is {} words — a name is exactly {SLOTS}, \
             `<subject> <action> <condition>`. The arity is fixed rather than a maximum \
             because it is what lets a rendered line be read as a name followed by \
             pointers with nothing separating them",
            words.len()
        )));
    }
    // ARM 2.
    for (slot, word) in words.iter().enumerate() {
        let declared = vocabulary
            .slot(slot)
            .iter()
            .any(|entry| entry.word == *word);
        if !declared {
            return Err(UsageError::raise(format!(
                "{kind} `{name}`: `{word}` is not in the declared `{}` list — \
                 a name is drawn from the vocabulary, which is what makes position \
                 carry meaning and a new name cost no new prose",
                SLOT_NAMES[slot]
            )));
        }
        used.insert((slot, (*word).to_owned()));
    }
    Ok(())
}

/// The per-entry half of [`validate`].
fn validate_one(
    verdict: &DeclaredVerdict,
    grammar: Option<&Vocabulary>,
    used: &mut BTreeSet<(usize, String)>,
) -> anyhow::Result<()> {
    let id = verdict.id.as_str();
    if let Some(vocabulary) = grammar {
        check_name("verdict", id, vocabulary, used)?;
    }
    if verdict.gloss.trim().is_empty() {
        return Err(UsageError::raise(format!(
            "verdict `{id}`: `gloss` is the hot path's whole payload, and an empty one \
             tells its reader nothing the token did not"
        )));
    }
    if verdict.gloss.contains('\n') || verdict.gloss.chars().count() > GLOSS_MAX {
        return Err(UsageError::raise(format!(
            "verdict `{id}`: `gloss` is ONE line of at most {GLOSS_MAX} characters — \
             the paragraph goes in `class`, which `batten policy explain` fetches"
        )));
    }
    if verdict.class.trim().is_empty() {
        return Err(UsageError::raise(format!(
            "verdict `{id}`: `class` is what `batten policy explain` answers with; \
             a token with no definition is a worse string than the prose it replaced"
        )));
    }
    if verdict.routes.is_empty() {
        return Err(UsageError::raise(format!(
            "verdict `{id}` declares no route — a refusal owes its reader a way out, \
             which is the contract `Fix` has carried since CLOUD-122"
        )));
    }
    if verdict
        .routes
        .iter()
        .all(|route| route.kind == RouteKind::Override)
    {
        return Err(UsageError::raise(format!(
            "verdict `{id}`'s only route is an override — \"ask for it to be waived\" \
             is the bare no this contract exists to refuse, so declare the route that \
             fixes the thing as well"
        )));
    }
    // The two retirement arms, refused at load in both directions (CLOUD-1114).
    //
    // BOTH is refused because a row asserting two different accounts of where a
    // class went has stated neither, and a reader following the successor would
    // never learn the class was withdrawn — nor the reverse.
    if verdict.successor.is_some() && verdict.withdrawn.is_some() {
        return Err(UsageError::raise(format!(
            "verdict `{id}` names both a `successor` and a `withdrawn` reason — a class was \
             either replaced or withdrawn, and a row claiming both has said where it went twice \
             and consistently neither time"
        )));
    }
    // EMPTY is refused because the arm's whole job is to carry the reason a
    // successor cannot. A blank one is the bare "gone" that a deleted row already
    // said, with a tombstone's cost and none of its value.
    if verdict
        .withdrawn
        .as_deref()
        .is_some_and(|reason| reason.trim().is_empty())
    {
        return Err(UsageError::raise(format!(
            "verdict `{id}`: `withdrawn` is empty — this arm exists to carry the reason a \
             successor cannot name, so a blank one retires the token while explaining nothing"
        )));
    }
    let mut route_ids: BTreeSet<&str> = BTreeSet::new();
    for route in &verdict.routes {
        validate_route(id, route, grammar, used)?;
        if !route_ids.insert(route.id.as_str()) {
            return Err(UsageError::raise(format!(
                "verdict `{id}` declares the route `{}` twice; a route id is what a \
                 refusal names, and one naming two things names neither",
                route.id
            )));
        }
    }
    Ok(())
}

/// The per-route half of [`validate_one`].
fn validate_route(
    verdict: &str,
    route: &Route,
    grammar: Option<&Vocabulary>,
    used: &mut BTreeSet<(usize, String)>,
) -> anyhow::Result<()> {
    let id = route.id.as_str();
    if let Some(vocabulary) = grammar {
        check_name(&format!("verdict `{verdict}`: route"), id, vocabulary, used)?;
    }
    match route.kind {
        RouteKind::Override => {
            let stated = route
                .precondition
                .as_deref()
                .is_some_and(|text| !text.trim().is_empty());
            if !stated {
                return Err(UsageError::raise(format!(
                    "verdict `{verdict}`: the override route `{id}` states no \
                     `precondition` — an override whose condition nobody wrote down is \
                     one nobody can be held to, and it is the field an admission's \
                     questions are generated from"
                )));
            }
        }
        RouteKind::Command | RouteKind::Document | RouteKind::Issue => {
            if route.precondition.is_some() {
                return Err(UsageError::raise(format!(
                    "verdict `{verdict}`: route `{id}` is a `{}` route and carries a \
                     `precondition`, which only an `override` route is read for — a field \
                     nothing reads is a condition nothing enforces",
                    route.kind.as_str()
                )));
            }
            if route.target.trim().is_empty() {
                return Err(UsageError::raise(format!(
                    "verdict `{verdict}`: route `{id}` is a `{}` route with no `target`",
                    route.kind.as_str()
                )));
            }
        }
    }
    Ok(())
}

/// The tombstone half of [`validate`] (CLOUD-1053).
///
/// A retired token names a successor; the chain has to terminate in a live
/// token and may not cycle. **This is the same predicate CLOUD-1051's admission
/// `prev` chain needs**, and it is written once here rather than twice.
///
/// **The withdrawal arm is deliberately not walked here** (CLOUD-1114). It names
/// no successor, so a withdrawn entry simply ends its own chain — which is what a
/// withdrawal *is*. Nothing about the successor arm is weakened by its existence:
/// the dangling and cycle refusals below are unchanged, and `validate_one` has
/// already refused a row that tried to carry both.
fn validate_chains(verdicts: &[DeclaredVerdict], declared: &BTreeSet<&str>) -> anyhow::Result<()> {
    for verdict in verdicts {
        let mut walked: BTreeSet<&str> = BTreeSet::new();
        walked.insert(verdict.id.as_str());
        let mut cursor = verdict;
        while let Some(next) = cursor.successor.as_deref() {
            if !declared.contains(next) {
                return Err(UsageError::raise(format!(
                    "verdict `{}` names the successor `{next}`, which this registry does \
                     not declare — a tombstone that resolves to nothing leaves a \
                     historical token unexplainable, which is the whole thing it exists \
                     to prevent",
                    verdict.id
                )));
            }
            if !walked.insert(next) {
                return Err(UsageError::raise(format!(
                    "verdict `{}`'s successor chain cycles at `{next}`; a chain has to \
                     terminate in a live token",
                    verdict.id
                )));
            }
            let Some(found) = verdicts.iter().find(|entry| entry.id == next) else {
                // Unreachable: `declared` was built from these ids.
                return Ok(());
            };
            cursor = found;
        }
    }
    Ok(())
}

/// Resolve a token through its tombstone chain to the live class.
///
/// Returns the entry the reader should be shown and whether the token they
/// asked for was itself retired. `None` for a token this registry does not
/// declare, which is `explain`'s exit `1`.
#[must_use]
pub fn resolve<'a>(
    verdicts: &'a [DeclaredVerdict],
    token: &str,
) -> Option<(&'a DeclaredVerdict, bool)> {
    let mut cursor = verdicts.iter().find(|entry| entry.id == token)?;
    let retired = cursor.retired();
    let mut guard = verdicts.len();
    while let Some(next) = cursor.successor.as_deref() {
        // `validate_chains` already refused a cycle, so this bound is the
        // residue for a caller that reached here without validation — it must
        // terminate rather than spin.
        if guard == 0 {
            break;
        }
        guard -= 1;
        let Some(found) = verdicts.iter().find(|entry| entry.id == next) else {
            break;
        };
        cursor = found;
    }
    Some((cursor, retired))
}

/// Every declared token, live and retired, in a stable order.
#[must_use]
pub fn declared_tokens(verdicts: &[DeclaredVerdict]) -> BTreeSet<&str> {
    verdicts.iter().map(|entry| entry.id.as_str()).collect()
}

/// The tokens a module may emit: every declared token that is not a tombstone.
#[must_use]
pub fn live_tokens(verdicts: &[DeclaredVerdict]) -> BTreeSet<&str> {
    verdicts
        .iter()
        .filter(|entry| !entry.retired())
        .map(|entry| entry.id.as_str())
        .collect()
}

// ─── The native half of the registry ─────────────────────────────────────────

/// A refusal class the CRATE owns, as opposed to one a consumer declares.
///
/// # Why this is an enum and not a table of strings
///
/// The registry's whole claim is that a token cannot be raised without being
/// declared. On the policy side that is enforced by reading the module's AST at
/// load; on the native side there is no AST to read, so the coupling has to be
/// in the type system or it is a convention. An enum gives it for free: a native
/// site names a variant, [`Native::ALL`] is asserted exhaustive by a
/// wildcard-free match, and a class that exists but is unreachable — or a site
/// raising a class nobody declared — is a compile error rather than a finding.
///
/// The same discipline `crate::facts::Fact` carries, and for the same reason.
///
/// # These are Batten's OWN words
///
/// Every variant here is a class the crate states about itself: a protected path
/// was targeted, a scanner is unpinned, a read-effect verb was asked to spawn. A
/// refusal composed from a consumer's `[[rule]]` row is a different thing — the
/// remedy is the consumer's declared `reason` and lives in their authority under
/// house style §8 — and it is not represented here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Native {
    /// A mutating verb was aimed at a path the config protects.
    ProtectedMutation,
    /// `batten init` would overwrite the committed authority.
    InitWouldOverwrite,
    /// A configured hook handler denied the call.
    HandlerDenied,
    /// A `secrets` rule needs a scanner and the config pins none.
    ScannerUnpinned,
    /// The pinned scanner is not in the provision cache.
    ScannerUnprovisioned,
    /// A rule kind that spawns was reached through a read-effect verb.
    SpawningRuleOnReadVerb,
    /// The end-of-turn facts do not permit stopping.
    StopConditionUnmet,
    /// A `git reset --hard` would leave commits reachable from no remote.
    HistoryDropUnpushed,
    // ─── the mediated composers' own classes (CLOUD-1285) ────────────────────
    //
    // These are Batten's OWN words about generic concepts, which is what puts
    // them here rather than in a consumer `[[verdict]]` row. The engine composed
    // each cause as a hardcoded `format!` in `hook.rs` and then threw the class
    // away by calling `Refusal::new`, so `refusal.verdict()` was `None` on eight
    // of ten mediated deny paths and `batten policy explain` was unreachable from
    // every path that actually fires.
    //
    // The consumer's `[[rule]]` row still supplies the FIX -- `Refusal::declared`
    // takes it as a parameter and a narrower one wins -- so this does not move
    // the remedy into the crate. It moves the CAUSE, which was already here.
    /// No receipt at all for what the row keys on.
    ReceiptUnusable,
    /// The receipt exists and is older than the row allows.
    ReceiptExpired,
    /// The receipt records something the row does not accept.
    ReceiptRefuted,
    /// An amend or a rebase replaced the bytes the receipt validated.
    ReceiptSuperseded,
    /// The receipt was taken against a trunk this branch has moved off.
    ReceiptOffTrunk,
    /// A shell text utility stood in for the structured file surface.
    ToolSubstituted,
    /// A verdict-bearing command was piped into a pager or filter.
    VerdictPiped,
    /// A verdict-bearing command was followed by `;` or `||`.
    VerdictTrailing,
    /// A verdict-bearing command was detached from its tool call.
    RunOrphaned,
    /// The call measures over a declared ceiling.
    CeilingExceeded,
    /// The call matches a refused command shape.
    ShapeRefused,
    /// The content this call would write matches a refused shape.
    ContentRefused,
    /// The work this call publishes names no tracker key.
    KeyMissing,
    // ─── the config loader's own classes (CLOUD-1313) ────────────────────────
    //
    // A load-time refusal was a bare `UsageError(String)` across ~172 sites, so
    // a config fault was the ONE refusal class in this engine that
    // `batten policy explain` could not resolve and no gate held to the
    // registry -- CLOUD-1050's defect, one surface over.
    //
    // ONE CLASS PER TABLE, NOT PER SITE. Only ~30 of those raises sit at a
    // top-level `validate`; the rest are in per-entry helpers, so a class per
    // site is unbuildable. The class says WHICH TABLE would not load and the
    // message carries the row and key, which is the same division `[[verdict]]`
    // draws between a class and its subjects.
    //
    // They are `Native` rather than consumer rows for the reason the enum's own
    // doc gives: the loader raises them BEFORE any config exists to declare
    // them, so a declared-row spelling would be unsatisfiable at exactly the
    // moment it fires. That also makes them resolvable from `vendored()` with
    // no config load, which is what keeps `policy explain` usable over a config
    // that will not parse.
    /// The `[[verb]]` table would not load.
    VerbTableRefused,
    /// The `[[pattern]]` table would not load.
    PatternTableRefused,
    /// The `[[verdict]]` table would not load.
    VerdictTableRefused,
    /// The `[[redirect]]` table would not load.
    RedirectTableRefused,
    /// A declared remedy names no command that exists (CLOUD-1189's class).
    RemedyUnresolved,
    /// The `[[marker]]` table would not load.
    MarkerTableRefused,
    /// The `[[rule]]` table would not load.
    RuleTableRefused,
    /// The `[[exec_pattern]]` table would not load.
    OutputTableRefused,
    /// The `[[waiver]]` table would not load.
    WaiverTableRefused,
    /// The `[[fact]]` table would not load.
    FactTableRefused,
    /// The `[[mint]]` table would not load.
    MintTableRefused,
    /// The `[[recorder]]` table would not load.
    RecorderTableRefused,
    /// The `[[provision]]` table would not load.
    ProvisionTableRefused,
    /// The `[[startup]]` table would not load.
    StartupTableRefused,
}

impl Native {
    /// Every native class, in declaration order.
    ///
    /// Held exhaustive by `every_native_class_is_listed`, which matches over a
    /// variant with no wildcard — so a new class that is not added here fails to
    /// compile rather than going undeclared.
    pub const ALL: &'static [Native] = &[
        Native::ProtectedMutation,
        Native::InitWouldOverwrite,
        Native::HandlerDenied,
        Native::ScannerUnpinned,
        Native::ScannerUnprovisioned,
        Native::SpawningRuleOnReadVerb,
        Native::StopConditionUnmet,
        Native::HistoryDropUnpushed,
        Native::ReceiptUnusable,
        Native::ReceiptExpired,
        Native::ReceiptRefuted,
        Native::ReceiptSuperseded,
        Native::ReceiptOffTrunk,
        Native::ToolSubstituted,
        Native::VerdictPiped,
        Native::VerdictTrailing,
        Native::RunOrphaned,
        Native::CeilingExceeded,
        Native::ShapeRefused,
        Native::ContentRefused,
        Native::KeyMissing,
        Native::VerbTableRefused,
        Native::PatternTableRefused,
        Native::VerdictTableRefused,
        Native::RedirectTableRefused,
        Native::RemedyUnresolved,
        Native::MarkerTableRefused,
        Native::RuleTableRefused,
        Native::OutputTableRefused,
        Native::WaiverTableRefused,
        Native::FactTableRefused,
        Native::MintTableRefused,
        Native::RecorderTableRefused,
        Native::ProvisionTableRefused,
        Native::StartupTableRefused,
    ];

    /// The classes the CONFIG LOADER raises, in `parse_ungated` order.
    ///
    /// One authority with three readers, which is what stops the set drifting
    /// where it is used (CLOUD-1313): `config.rs`'s census holds its own
    /// per-table list equal to this one in both directions, and the
    /// compiled-binary tier holds its fixture set to it — so a fourteenth table
    /// cannot arrive wrapped-but-untested, and a class cannot be dropped from
    /// the loader while a fixture still claims to reach it.
    ///
    /// A subset of [`Native::ALL`] rather than a separate enum, because these
    /// are resolved from the same vendored table by the same `explain` — the
    /// only thing that distinguishes them is who raises them.
    pub const CONFIG_FAULTS: &'static [Native] = &[
        Native::VerbTableRefused,
        Native::PatternTableRefused,
        Native::VerdictTableRefused,
        Native::RedirectTableRefused,
        Native::RemedyUnresolved,
        Native::MarkerTableRefused,
        Native::RuleTableRefused,
        Native::OutputTableRefused,
        Native::WaiverTableRefused,
        Native::FactTableRefused,
        Native::MintTableRefused,
        Native::RecorderTableRefused,
        Native::ProvisionTableRefused,
        Native::StartupTableRefused,
    ];

    /// The token this class is declared and rendered under.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Native::ProtectedMutation => "path write refused",
            Native::InitWouldOverwrite => "config write refused",
            Native::HandlerDenied => "handler answer denied",
            Native::ScannerUnpinned => "scanner pin missing",
            Native::ScannerUnprovisioned => "scanner install missing",
            Native::SpawningRuleOnReadVerb => "spawn run refused",
            Native::HistoryDropUnpushed => "history drop unpushed",
            Native::StopConditionUnmet => "turn finish unmet",
            Native::ReceiptUnusable => "receipt read missing",
            Native::ReceiptExpired => "receipt read late",
            Native::ReceiptRefuted => "receipt carry other",
            Native::ReceiptSuperseded => "receipt read other",
            Native::ReceiptOffTrunk => "receipt read stale",
            Native::ToolSubstituted => "tool run loose",
            Native::VerdictPiped => "verdict read dropped",
            Native::VerdictTrailing => "verdict carry other",
            Native::RunOrphaned => "turn watch dropped",
            Native::CeilingExceeded => "call count over",
            Native::ShapeRefused => "call name refused",
            Native::ContentRefused => "input write refused",
            Native::KeyMissing => "issue name missing",
            Native::VerbTableRefused => "verb declare refused",
            Native::PatternTableRefused => "pattern declare refused",
            Native::VerdictTableRefused => "verdict declare refused",
            Native::RedirectTableRefused => "redirect declare refused",
            Native::RemedyUnresolved => "remedy resolve missing",
            Native::MarkerTableRefused => "marker declare refused",
            Native::RuleTableRefused => "rule declare refused",
            Native::OutputTableRefused => "output declare refused",
            Native::WaiverTableRefused => "waiver declare refused",
            Native::FactTableRefused => "fact declare refused",
            Native::MintTableRefused => "mint declare refused",
            Native::RecorderTableRefused => "recorder declare refused",
            Native::ProvisionTableRefused => "provision declare refused",
            Native::StartupTableRefused => "startup declare refused",
        }
    }
}

/// Every token the crate's own refusal sites may raise.
///
/// Read by `policy::load` for the half of registry equality that asks whether a
/// declared token is emitted by ANYTHING: a `[[verdict]]` row covering a native
/// class is not dead vocabulary just because no module raises it.
#[must_use]
pub fn native_tokens() -> BTreeSet<&'static str> {
    Native::ALL.iter().map(|native| native.id()).collect()
}

/// One vendored class, in the shape a `const` table can hold.
///
/// A mirror of [`DeclaredVerdict`] over `&'static str`, because that type owns
/// `String`s and cannot be a `const`. [`vendored`] converts. The alternative —
/// building the table at runtime from literals — puts the same data one
/// indirection further from the reader for nothing.
#[derive(Debug)]
pub struct VendoredVerdict {
    /// The three-word class token.
    pub id: &'static str,
    /// The one-line summary.
    pub gloss: &'static str,
    /// The prose a reader dereferences through `batten policy explain`.
    pub class: &'static str,
    /// The declared remedies.
    pub routes: &'static [VendoredRoute],
}

/// One vendored route. See [`VendoredVerdict`].
#[derive(Debug)]
pub struct VendoredRoute {
    /// The route's own three-word id.
    pub id: &'static str,
    /// Which kind of remedy it is.
    pub kind: RouteKind,
    /// What it points at.
    pub target: &'static str,
    /// The condition an override route states.
    pub precondition: Option<&'static str>,
}

/// A `command`-kind route, which is most of them.
#[must_use]
pub const fn run(id: &'static str, target: &'static str) -> VendoredRoute {
    VendoredRoute {
        id,
        kind: RouteKind::Command,
        target,
        precondition: None,
    }
}

/// A `document`-kind route.
#[must_use]
pub const fn read(id: &'static str, target: &'static str) -> VendoredRoute {
    VendoredRoute {
        id,
        kind: RouteKind::Document,
        target,
        precondition: None,
    }
}

/// An `override`-kind route, which is the only kind whose precondition is
/// REQUIRED rather than optional.
///
/// `target` is deliberately absent: [`RouteKind::Override`]'s own doc says it is
/// unread, and the precondition is the whole payload — it is what
/// [`crate::admission::questions_for`] renders the first question from. A helper
/// that took a target would invite one to be written and then silently ignored.
#[must_use]
pub const fn admit(id: &'static str, precondition: &'static str) -> VendoredRoute {
    VendoredRoute {
        id,
        kind: RouteKind::Override,
        target: "",
        precondition: Some(precondition),
    }
}

/// Every class the BINARY ships: the native ones and the vendored presets'.
///
/// # Why the presets' vocabulary ships with the presets
///
/// A preset reaches a consumer who never wrote a `[[verdict]]` row, so holding
/// it to the consumer's registry would make an enabled preset unloadable with no
/// fix available — the wrongly-refusing gate AGENTS.md calls a defect, and the
/// identical argument `policy::check_no_inline_regex` already records for a
/// preset's patterns. The supply-chain claim is unchanged: `include_str!` at
/// build time, no network, no registry, the same checksum as the rest of the
/// binary.
///
/// Non-negotiable rule 1 reaches this table exactly as it reaches the presets
/// themselves: a class here may describe a PRACTICE and may never name a path, a
/// task, a tracker key or an entity. `presets_are_inside_the_rule_one_glob`
/// covers this file, because it is under `crates/**`.
const VENDORED: &[VendoredVerdict] = &[
    // ── native ──────────────────────────────────────────────────────────────
    VendoredVerdict {
        id: "path write refused",
        gloss: "a mutating verb was aimed at a path the config protects",
        class: "The path is in the `protected` set, so a write to it is refused before it \
happens rather than reported after. The set is the consumer's own declaration; what is \
protected is a question about their repository, and the engine only enforces it. A \
narrower remedy may be declared per path class through `[[redirect]]`, which is what the \
refusal names when one exists.",
        routes: &[
            read("config read first", "batten.toml"),
            run("patch run first", "git restore"),
            // THE CLASS COULD NOT BE OVERRIDDEN, AND THAT LEFT ONLY THE PASSWORD.
            //
            // The two routes above are real and are the right first answers, but
            // neither reaches a path whose owning surface IS the protected file —
            // registering a rule, adding a redirect, retiring a gate onto a config
            // row. For that class of change `config read first` names the
            // file being refused, so the remedy is the thing denied.
            //
            // With no override route, `admission::questions_for` returns `None` and
            // `batten override request` answers "declares no `override` route, so
            // it cannot be overridden". The only remaining exit was
            // `BATTEN_HOOK_BYPASS` — a knowable string the guarded party can set,
            // which records nothing and stops nobody. This repository already ruled
            // on that shape for `issue file same`: *the point of the admission
            // mechanism is that the bare variable stops working*.
            //
            // The precondition is what the asker must be ABLE TO STATE, never a
            // judgement the gate makes (non-negotiable rule 3). It names the owning
            // surface deliberately, so the first question forces the asker to say
            // why the route they were already given does not reach.
            admit(
                "articulate the write",
                "the surface this class names cannot express the change, so writing the \
protected path directly is the only route left, and the write is one a reviewer will see \
in the diff it lands in",
            ),
        ],
    },
    VendoredVerdict {
        id: "history drop unpushed",
        gloss: "the reset would discard commits that exist in no other clone",
        class: "`git reset --hard` moves the branch and discards the working tree \
and the index together, with none of the \"you have unstaged changes\" refusals that \
stop git's other destructive verbs. Where every commit in the discarded range is on a \
remote that is the ordinary undo and nothing is lost. Where one is not, the only copy \
of that work is the commit being removed, and it is unreferenced the moment the reflog \
expires. The class fires on the second case only: the verb is not the defect, \
reachability is.",
        routes: &[
            // The two verbs that reach the same outcome without discarding a
            // commit. Named as the FIRST route because a caller who wanted to
            // drop a change usually wanted to drop a change, not a commit.
            //
            // The first draft named the set-aside verb `no_gix_gap_primitive_survives`
            // refuses anywhere in this tree: the primitives built on it retired with
            // the spawn they required (CLOUD-780), and a route naming a retired
            // concept is a remedy nobody here can follow. `--soft` is the better
            // answer anyway — it moves the same ref and leaves both the tree and the
            // index where they were.
            read("ref moved, work kept", "git reset --soft"),
            read("file reverted", "git checkout -- <path>"),
            // The way through that leaves a record, which is what keeps this a
            // gate rather than a wall. Its precondition also makes the class
            // non-suppressible by `BATTEN_HOOK_BYPASS` (CLOUD-1357), which is
            // right for a verb whose subject is gone by the time anyone reads
            // the refusal.
            admit(
                "articulate the loss",
                "the commits this discards are ones you have read and intend to lose, and \
you can name what they contained without consulting them",
            ),
        ],
    },
    VendoredVerdict {
        id: "config write refused",
        gloss: "`init` will not overwrite the committed authority",
        class: "House style §8 gives a repository ONE committed authority, and `init` \
writes it. Overwriting an existing one would replace a reviewed policy with a default \
set, silently, in a verb whose whole purpose is that there was nothing there before. \
Edit the file that exists, or move it aside deliberately.",
        routes: &[read("config read first", "batten.toml")],
    },
    VendoredVerdict {
        id: "handler answer denied",
        gloss: "a configured hook handler denied the call",
        class: "The refusal is the handler's, not the engine's: a `[hook.handler]` row \
names a program, the program answered deny, and this carries that answer through. The \
handler's own reason is free text the consumer configured, so no remedy is invented here \
— the handler is where a remedy would have to be declared.",
        routes: &[read("config read first", "batten.toml")],
    },
    VendoredVerdict {
        id: "scanner pin missing",
        gloss: "a `secrets` rule needs its scanner pinned and none is declared",
        class: "A `secrets` rule delegates to an external scanner, and which scanner \
decides what the rule means. An unpinned one would resolve to whatever is ambient, so a \
green run would say nothing about the tree — the same defect a bare `cargo` has against \
a pinned toolchain. Declare the scanner as a `[[provision]]` entry.",
        routes: &[
            run("check run first", "batten provision"),
            read("config read first", "batten.toml"),
        ],
    },
    VendoredVerdict {
        id: "scanner install missing",
        gloss: "the pinned scanner is not in the provision cache, so nothing was scanned",
        class: "The scanner is declared and absent. This is could-not-look rather than a \
clean tree, and it is reported as a refusal precisely so the two are not spelled the \
same way: a secrets rule that scanned no file and reported nothing is the vacuous pass \
this engine argues against everywhere.",
        routes: &[run("check run first", "batten provision")],
    },
    VendoredVerdict {
        id: "spawn run refused",
        gloss: "this rule kind runs a configured command, which a read-effect verb will not do",
        class: "The effect model (house style §5) puts every verb in one class and holds \
it there. A rule kind that spawns is `Effect`, and `check` is `Read`, so reaching one \
through the other would make the read-only allowlist a claim nobody could rely on. The \
rule is not wrong; the verb is.",
        routes: &[run("check run first", "batten enforce")],
    },
    VendoredVerdict {
        id: "turn finish unmet",
        gloss: "the end-of-turn facts do not permit stopping",
        class: "A stop is a completion signal, and this engine's whole subject is keeping \
that signal aligned with landed-and-verified work. The facts the turn ended on say it is \
not, and the refusal names which. Each has its own route; the shared one is to finish \
the thing rather than to re-declare that it is finished.",
        routes: &[
            run("task run first", "mise run land"),
            read("config read first", "batten.toml"),
        ],
    },
    // ── the mediated composers' classes (CLOUD-1285) ────────────────────────
    //
    // The cause each of these carries used to be a hardcoded `format!` in
    // `hook.rs` that `Refusal::new` then dropped the class for. Moving the prose
    // here is what makes it dereferenceable: `batten policy explain <token>`
    // answers with the `class` below, so the hot path can carry the token and the
    // pointers and stop repeating the paragraph on every firing.
    VendoredVerdict {
        id: "receipt read missing",
        gloss: "a declared receipt does not attest the commit this call is made against",
        class: "A `receipt` row names checks whose verdict must already exist for this \
commit, in this checkout. The receipt is missing, older than the row allows, recorded \
against a different head, or records something the row does not accept -- and the refusal \
names which, because the four call for different repairs. Re-running the check is the \
remedy for a missing one and useless for a refuted one.",
        routes: &[read("config read first", "batten.toml")],
    },
    VendoredVerdict {
        id: "receipt read late",
        gloss: "the receipt exists and is older than the row allows",
        class: "The step RAN, and not recently enough for its verdict to still be evidence. \
That is a different repair from a missing receipt and is why it is a different class: \
re-run the check. A row declaring a `max_age` is saying the world can move underneath the \
answer, so an old verdict is could-not-look rather than a pass.",
        routes: &[read("config read first", "batten.toml")],
    },
    VendoredVerdict {
        id: "receipt carry other",
        gloss: "the receipt records something this row does not accept",
        class: "The step ran and what it recorded is not what the row requires. This is the \
one receipt class that is a statement about what was READ rather than about the read, so \
re-running the check changes nothing until the thing it reports is fixed. An ABSENT field \
is could-not-look and is not this class.",
        routes: &[read("config read first", "batten.toml")],
    },
    VendoredVerdict {
        id: "receipt read other",
        gloss: "an amend or a rebase replaced the bytes this receipt validated",
        class: "The receipt is keyed to a commit this branch no longer carries. Its verdict \
covered the bytes it read and nothing later, so it is not evidence about this head. Re-run \
the check against what is here now. Kept apart from the trunk case because the two name \
different things that moved, and a refusal that says the wrong one sends the reader after \
the wrong repair.",
        routes: &[read("config read first", "batten.toml")],
    },
    VendoredVerdict {
        id: "receipt read stale",
        gloss: "the receipt was taken against a trunk this branch has moved off",
        class: "The branch MOVED FORWARD off the base the receipt was taken against -- \
`git checkout -B <name> origin/main` after a merge, which repoints the name at a new base \
and discards the commits that were the branch, while the receipt survives keyed by that \
name. Re-take the evidence on the branch as it now stands. Distinct from the amend case: \
there the branch's own bytes changed, here the branch is a different branch wearing the \
same name. THE DIRECTION IS THE PREDICATE (CLOUD-1091): a branch merely BEHIND the trunk \
keeps its receipt, because the receipt is then more current than the branch and no amount \
of re-taking it can help -- this text said the opposite for its whole life and prescribed \
the one action guaranteed not to work.",
        routes: &[read("config read first", "batten.toml")],
    },
    VendoredVerdict {
        id: "tool run loose",
        gloss: "a shell text utility stood in for the structured file surface",
        class: "The call reaches for a text utility over a path this repository CONTAINS, as \
its FIRST stage, to answer a question the structured surface answers directly and better: \
a range of one file's contents, a pattern across the tree, paths by glob, or what a name \
resolves to. Which instruments a session carries varies, so the refusal names the question \
classes rather than a product. The same utility DOWNSTREAM of a pipe is untouched, because \
filtering another command's output is not standing in for anything. CONTAINMENT, never the \
INDEX (CLOUD-1109): the boundary resolves the operand against the call's own working \
directory and asks whether the repository contains the result. It does not ask git, because \
a `git ls-files` per mediated call is a spawn `RuleKind::scopes` forbids on this kind and \
`perf-assert` prices out. This text said 'tracks' for its whole life and nothing ever \
checked it -- a class a reader believes is worse than one they cannot look up.",
        routes: &[read("rule read first", ".claude/rules/scanning.md")],
    },
    VendoredVerdict {
        id: "verdict read dropped",
        gloss: "piping a verdict-bearing command into a pager or filter discards its status",
        class: "The pipeline exits with the FILTER's status, which is 0 whether the command \
passed or failed. A verdict is read from the harness, never inferred from output. Redirect \
to a file and read the file in a separate call; a pager over a FILE is fine, a pager over a \
live task is not.",
        routes: &[read("rule read first", ".claude/rules/toolchain.md")],
    },
    VendoredVerdict {
        id: "verdict carry other",
        gloss: "a verdict-bearing command followed by `;` or `||` has its status replaced",
        class: "Only the last element's status survives, so the compound reports the wrong \
command's verdict. This is the laundered shape: it reads as correct, and backgrounded it is \
worse than a misread, because the completion notification then carries the compound's \
status. `&&` is fine -- it short-circuits, so a failure still propagates.",
        routes: &[read("rule read first", ".claude/rules/toolchain.md")],
    },
    VendoredVerdict {
        id: "turn watch dropped",
        gloss: "detaching a verdict-bearing command orphans it from the tool call",
        class: "`nohup` or a trailing `&` returns the call at once, the harness records it \
complete, and the session loses the wake-up it would get when the work actually exits. \
Backgrounding the tool call is the supported shape and keeps the notification; detaching \
inside the call throws it away.",
        routes: &[read("rule read first", ".claude/rules/toolchain.md")],
    },
    VendoredVerdict {
        id: "call count over",
        gloss: "this call measures over a ceiling the config declares",
        class: "A `ceiling` row counts something about the call and refuses above a declared \
maximum. The count and the maximum are the whole finding -- what was counted is the row's \
subject, and the refusal carries neither the measured content nor the call text, which is \
non-negotiable rule 4 decided at the composer rather than at the report.",
        routes: &[read("config read first", "batten.toml")],
    },
    VendoredVerdict {
        id: "call name refused",
        gloss: "the mediated call matches a command shape the config refuses",
        class: "A `shape` row declares a command spelling that is refused outright. The \
refusal names the row rather than echoing the command, because the command is the caller's \
own text and could carry anything. What to run instead is the row's declared remedy.",
        routes: &[read("config read first", "batten.toml")],
    },
    VendoredVerdict {
        id: "input write refused",
        gloss: "the content this call would write matches a refused shape",
        class: "A `content` row judges what a write would PUT somewhere rather than which \
path it targets, so it fires before the bytes land. The refusal names the row and the \
destination and never the matched content -- this rule reads exactly the text somebody \
wanted checked, which is the likeliest place in the surface for a secret to appear.",
        routes: &[read("config read first", "batten.toml")],
    },
    VendoredVerdict {
        id: "issue name missing",
        gloss: "the work this call publishes names no tracker key",
        class: "A `requires_key` row narrows a refusal from \"this command is banned\" to \
\"this command is banned unless the work is keyed\". Three evidence sources are read and any \
one of them allows: the command itself, the branch name, and the commit subjects on the \
range the row declares. None carried a key, so nothing on the published work says which row \
it serves.",
        routes: &[read("config read first", "batten.toml")],
    },
    // ── the config loader's classes (CLOUD-1313) ────────────────────────────
    //
    // One per `VALIDATED_AT_LOAD` table plus the remedy resolver. Each `class`
    // says what the table is FOR and what a refusal from it therefore means,
    // because the message the loader already carries says which row and key
    // failed and repeating that here would be the payload rule 4 refuses.
    //
    // Every route is the config itself, which is not a placeholder: a config
    // fault is edited in exactly one file, and a `command` route would have to
    // name a task that can run over a config that does not load.
    VendoredVerdict {
        id: "verb declare refused",
        gloss: "the verb table would not load",
        class: "`[[verb]]` is how a consumer names the commands their harness mediates and \
what effect each carries. A row that is inert -- declared twice, or read-effect in a table \
named for mutation -- reads as covered while matching nothing, so the table is proven at \
load rather than at the call it would have decided.",
        routes: &[read("config read first", "batten.toml")],
    },
    VendoredVerdict {
        id: "pattern declare refused",
        gloss: "the named-pattern registry would not load",
        class: "`[[pattern]]` gives one concept one spelling, so a module cannot inline a \
regex and duplication becomes unwritable rather than merely detectable. A malformed \
expression here is a config fault, and refusing it at load is what stops a mediated call \
discovering it at adjudication -- the worst moment and the wrong exit class.",
        routes: &[read("config read first", "batten.toml")],
    },
    VendoredVerdict {
        id: "verdict declare refused",
        gloss: "the refusal vocabulary would not load",
        class: "`[[verdict]]` is the registry every other class in this table belongs to: a \
token's arity, a gloss that is one line, a route list that is not an override alone, a \
tombstone chain that terminates. Each clause is a property of the table, so it is knowable \
without a tree and belongs where a config fault is reported.",
        routes: &[read("config read first", "batten.toml")],
    },
    VendoredVerdict {
        id: "redirect declare refused",
        gloss: "the redirect table would not load",
        class: "`[[redirect]]` changes what a refusal SAYS for a class of path, never \
whether it fires -- which is why it needs no raise-only clamp and why a redefinition is \
refused for coherence with the other append-only tables rather than because it lowers a \
bar.",
        routes: &[read("config read first", "batten.toml")],
    },
    VendoredVerdict {
        id: "remedy resolve missing",
        gloss: "a declared remedy names a command that does not exist",
        class: "A refusal whose remedy points at a verb that was renamed away is worse than \
one carrying no remedy: the reader spends the round finding out. This is the one clause \
needing a THIRD table -- the rule ids -- so it lives at the load rather than inside either \
remedy table's own validator, where a checker reaching past its argument would quietly \
become the config's.",
        routes: &[read("config read first", "batten.toml")],
    },
    VendoredVerdict {
        id: "marker declare refused",
        gloss: "the marker table would not load",
        class: "`[[marker]]` declares the tokens a scan treats as significant. An empty \
`token` matches every line of every file, which loads clean and reads as coverage, so the \
table is proven at load.",
        routes: &[read("config read first", "batten.toml")],
    },
    VendoredVerdict {
        id: "rule declare refused",
        gloss: "the rule table would not load",
        class: "`[[rule]]` is the policy surface itself, and it used to be validated only by \
whichever runner happened to evaluate it. That was defensible with one runner; with a tree \
engine and a mediation boundary, a malformed mediated-call row validated only by the tree \
engine is a row that loads, matches nothing at the mediation channel, and reads as \
coverage.",
        routes: &[read("config read first", "batten.toml")],
    },
    VendoredVerdict {
        id: "output declare refused",
        gloss: "the exec output-predicate table would not load",
        class: "`[[exec_pattern]]` is how a wrapped command's OUTPUT becomes a decidable \
object rather than something a reader skims. A duplicate id makes two predicates \
indistinguishable in the record they write.",
        routes: &[read("config read first", "batten.toml")],
    },
    VendoredVerdict {
        id: "waiver declare refused",
        gloss: "the waiver table would not load",
        class: "The stakes here are inverted from every other table: a malformed rule fails \
to gate, but a malformed WAIVER is a hatch whose expiry nobody could read. Refusing at load \
is what makes \"every waiver carries an expiry\" true of the resolved config rather than \
aspirational.",
        routes: &[read("config read first", "batten.toml")],
    },
    VendoredVerdict {
        id: "fact declare refused",
        gloss: "the fact table would not load",
        class: "`[[fact]]` declares what the boundary resolves about a call before any rule \
reads it. A row naming a fact the engine cannot produce is a gate that evaluates, reads \
undefined, and refuses nothing -- the silent dead gate, decided at load instead.",
        routes: &[read("config read first", "batten.toml")],
    },
    VendoredVerdict {
        id: "mint declare refused",
        gloss: "the mint table would not load",
        class: "`[[mint]]` declares what a receipt records and how long it answers for. A \
malformed row is a receipt nothing can satisfy or one that answers forever, and both are \
decidable from the table alone.",
        routes: &[read("config read first", "batten.toml")],
    },
    VendoredVerdict {
        id: "recorder declare refused",
        gloss: "the recorder table would not load",
        class: "`[[recorder]]` binds a captured section to a named pattern. It is validated \
AFTER the pattern registry, because a refusal for a missing pattern id is only honest once \
the ids are known to be well formed themselves.",
        routes: &[read("config read first", "batten.toml")],
    },
    VendoredVerdict {
        id: "provision declare refused",
        gloss: "the provision table would not load",
        class: "`[[provision]]` is how a pinned tool reaches the cache a rule will look for \
it in. A row that cannot resolve is a rule that will report a missing scanner at the moment \
it was supposed to decide something.",
        routes: &[read("config read first", "batten.toml")],
    },
    VendoredVerdict {
        id: "startup declare refused",
        gloss: "the startup table would not load",
        class: "`[[startup]]` is how a repository states what its container must be and how that is repaired. A row that could never decide -- an empty check, a repair that runs nothing, an id declared twice -- is a precondition reported as broken every session with no repair reachable, so it is refused here rather than once per session, where the failure would read as a broken container instead of a typo in this file.",
        routes: &[read("config read first", "batten.toml")],
    },
];

/// Every class the binary ships, as the registry carries them.
///
/// Unioned with the consumer's `[[verdict]]` rows by `policy::load`. A collision
/// between the two is refused there rather than here: which side is at fault is
/// a question about the pair, and this function knows only one of them.
#[must_use]
pub fn vendored() -> Vec<DeclaredVerdict> {
    // Native rows here, preset rows from their own manifests (CLOUD-1181). The
    // presets' half used to sit in this same table under a comment, so a preset
    // class and the preset that raises it were declared in different modules
    // with nothing tying them together.
    VENDORED
        .iter()
        .map(declared_from)
        .chain(crate::preset::verdict_rows())
        .collect()
}

/// One vendored row, as the registry carries it.
///
/// Shared with [`crate::preset`] so the two halves of the vendored registry
/// cannot be projected differently — which is the same "one authority per fact"
/// reason the manifests exist at all.
#[must_use]
pub fn declared_from(entry: &VendoredVerdict) -> DeclaredVerdict {
    DeclaredVerdict {
        id: entry.id.to_owned(),
        gloss: entry.gloss.to_owned(),
        class: entry.class.to_owned(),
        routes: entry
            .routes
            .iter()
            .map(|route| Route {
                id: route.id.to_owned(),
                kind: route.kind,
                target: route.target.to_owned(),
                precondition: route.precondition.map(str::to_owned),
            })
            .collect(),
        successor: None,
        withdrawn: None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn route(id: &str) -> Route {
        Route {
            id: id.to_owned(),
            kind: RouteKind::Command,
            target: "mise run something".to_owned(),
            precondition: None,
        }
    }

    fn entry(id: &str) -> DeclaredVerdict {
        DeclaredVerdict {
            id: id.to_owned(),
            gloss: "a short line".to_owned(),
            class: "the long definition".to_owned(),
            routes: vec![route("do the thing")],
            successor: None,
            withdrawn: None,
        }
    }

    #[test]
    fn a_conforming_entry_validates() {
        validate(&[entry("one probe probe")], &Vocabulary::default())
            .expect("a conforming registry loads");
    }

    /// A three-slot fixture vocabulary, enough to spell `task read first`.
    fn vocab() -> Vocabulary {
        let word = |w: &str| VocabularyWord {
            word: w.to_owned(),
            gloss: "a word".to_owned(),
        };
        Vocabulary {
            tokenizer: Some("o200k_base".to_owned()),
            tokenizer_source: None,
            tokenizer_retrieved: None,
            subject: vec![word("task"), word("shell")],
            action: vec![word("read"), word("edit")],
            condition: vec![word("first"), word("refused")],
        }
    }

    /// A class named in the grammar, with every word spent so arm 5 is quiet.
    fn named(id: &str) -> DeclaredVerdict {
        let mut e = entry(id);
        e.routes[0].id = "shell edit refused".to_owned();
        e
    }

    #[test]
    fn the_declared_registry_passes_its_own_grammar() {
        // ANTI-VACUITY, and it is the load-bearing case (CLOUD-418): an arm that
        // refused everything would satisfy every negative case below and get
        // switched off the first time somebody ran it.
        validate(&[named("task read first")], &vocab()).expect("a conforming registry loads");
    }

    #[test]
    fn a_four_word_class_is_refused() {
        // ARM 1. Fixed arity, not a maximum — this is the constraint an
        // implementer will want to relax, and relaxing it is what puts a
        // delimiter back between the name and the pointers.
        assert!(validate(&[named("task read first refused")], &vocab()).is_err());
        assert!(validate(&[named("task read")], &vocab()).is_err());
    }

    #[test]
    fn a_word_outside_the_declared_list_is_refused() {
        // ARM 2, and in the right SLOT: `edit` is declared, as an action, so a
        // class spelling it in slot 1 must still be refused. A membership check
        // that ignored position would pass this and the grammar would mean
        // nothing.
        assert!(validate(&[named("cargo read first")], &vocab()).is_err());
        assert!(validate(&[named("edit read first")], &vocab()).is_err());
    }

    #[test]
    fn a_duplicate_triple_is_refused() {
        // ARM 3. Under this grammar the id IS the triple, so the duplicate-id
        // refusal is the uniqueness-of-the-triple refusal; there is no second
        // question to ask.
        assert!(
            validate(
                &[named("task read first"), named("task read first")],
                &vocab()
            )
            .is_err()
        );
    }

    #[test]
    fn a_word_no_name_spends_is_refused() {
        // ARM 5. The mirror of the landed rule that a `[[verdict]]` row nothing
        // raises fails the load: dead vocabulary reads as headroom while nothing
        // has walked it.
        let mut wider = vocab();
        wider.condition.push(VocabularyWord {
            // Deliberately a word no VENDORED name spells: `mark_spent` walks the
            // vendored table too, so a plausible-looking condition can be spent
            // from under this case by a class landed elsewhere in the crate.
            word: "unwalked".to_owned(),
            gloss: "answers for a route nothing has taken".to_owned(),
        });
        assert!(validate(&[named("task read first")], &wider).is_err());
    }

    #[test]
    fn a_word_with_no_gloss_is_refused() {
        // ARM 6. A word that explains nothing explains nothing in every name
        // that spends it, which is the free-text namespace back again.
        let mut blank = vocab();
        blank.subject[0].gloss = "  ".to_owned();
        assert!(validate(&[named("task read first")], &blank).is_err());
    }

    #[test]
    fn a_registry_declaring_no_vocabulary_is_not_held_to_the_grammar() {
        // The opt-in exemption, and the direction that keeps it honest: a
        // consumer with no lists cannot satisfy membership, so refusing them
        // would be a demand with no fix available. `[[pattern]]`'s preset
        // exemption is the landed precedent.
        validate(&[entry("legacy name probe")], &Vocabulary::default())
            .expect("a consumer that has not adopted the grammar still loads");
    }

    #[test]
    fn a_duplicate_token_is_refused() {
        assert!(
            validate(
                &[entry("one probe probe"), entry("one probe probe")],
                &Vocabulary::default()
            )
            .is_err()
        );
    }

    #[test]
    fn a_paragraph_gloss_is_refused() {
        let mut bad = entry("one probe probe");
        bad.gloss = "x".repeat(GLOSS_MAX + 1);
        assert!(validate(&[bad], &Vocabulary::default()).is_err());
        let mut wrapped = entry("one probe probe");
        wrapped.gloss = "one\ntwo".to_owned();
        assert!(validate(&[wrapped], &Vocabulary::default()).is_err());
    }

    #[test]
    fn a_verdict_with_no_route_is_refused() {
        let mut bad = entry("one probe probe");
        bad.routes.clear();
        assert!(validate(&[bad], &Vocabulary::default()).is_err());
    }

    #[test]
    fn an_override_alone_is_refused() {
        let mut bad = entry("one probe probe");
        bad.routes = vec![Route {
            id: "ask probe probe".to_owned(),
            kind: RouteKind::Override,
            target: String::new(),
            precondition: Some("you can state why".to_owned()),
        }];
        assert!(validate(&[bad], &Vocabulary::default()).is_err());
    }

    #[test]
    fn an_override_with_no_precondition_is_refused() {
        let mut bad = entry("one probe probe");
        bad.routes.push(Route {
            id: "ask probe probe".to_owned(),
            kind: RouteKind::Override,
            target: String::new(),
            precondition: None,
        });
        assert!(validate(&[bad], &Vocabulary::default()).is_err());
    }

    #[test]
    fn a_command_route_carrying_a_precondition_is_refused() {
        let mut bad = entry("one probe probe");
        bad.routes[0].precondition = Some("something".to_owned());
        assert!(validate(&[bad], &Vocabulary::default()).is_err());
    }

    #[test]
    fn a_successor_naming_nothing_is_refused() {
        let mut bad = entry("old probe probe");
        bad.successor = Some("gone probe probe".to_owned());
        assert!(validate(&[bad], &Vocabulary::default()).is_err());
    }

    #[test]
    fn a_cycling_chain_is_refused() {
        let mut first = entry("a probe probe");
        first.successor = Some("b probe probe".to_owned());
        let mut second = entry("b probe probe");
        second.successor = Some("a probe probe".to_owned());
        assert!(validate(&[first, second], &Vocabulary::default()).is_err());
    }

    #[test]
    fn a_tombstone_resolves_to_its_live_successor() {
        let mut old = entry("old probe probe");
        old.successor = Some("new probe probe".to_owned());
        let new = entry("new probe probe");
        let table = vec![old, new];
        validate(&table, &Vocabulary::default()).expect("a terminating chain loads");
        let (resolved, retired) = resolve(&table, "old probe probe").expect("the token resolves");
        assert_eq!(resolved.id, "new probe probe");
        assert!(retired, "the token the reader asked for was retired");
        assert_eq!(live_tokens(&table), BTreeSet::from(["new probe probe"]));
    }

    #[test]
    fn a_line_bearing_subject_is_not_read_as_a_bare_path() {
        // The order-sensitivity `from_json` documents: read the other way round
        // this silently drops the line, and a finding that loses its line is a
        // pointer a reader cannot follow.
        let value = serde_json::json!({"path": "a.rs", "line": 7});
        assert_eq!(
            Subject::from_json(&value),
            Some(Subject::Line {
                path: "a.rs".to_owned(),
                line: 7
            })
        );
    }

    #[test]
    fn a_shape_the_decoder_does_not_know_is_could_not_look() {
        let value = serde_json::json!({"reason": "because"});
        assert_eq!(Subject::from_json(&value), None);
    }

    /// The exhaustiveness assertion `Native::ALL` rests on.
    ///
    /// The match below carries **no wildcard**, so a new variant fails to
    /// compile here; the loop then asserts the listed set is the same one. Two
    /// halves, because either alone is satisfiable by the defect: a wildcard
    /// match would compile past a new class, and a list with no match beside it
    /// would go stale silently.
    #[test]
    fn every_native_class_is_listed() {
        for native in Native::ALL {
            let named = match native {
                Native::ProtectedMutation
                | Native::InitWouldOverwrite
                | Native::HandlerDenied
                | Native::ScannerUnpinned
                | Native::ScannerUnprovisioned
                | Native::SpawningRuleOnReadVerb
                | Native::StopConditionUnmet
                | Native::HistoryDropUnpushed
                | Native::ReceiptUnusable
                | Native::ReceiptExpired
                | Native::ReceiptRefuted
                | Native::ReceiptSuperseded
                | Native::ReceiptOffTrunk
                | Native::ToolSubstituted
                | Native::VerdictPiped
                | Native::VerdictTrailing
                | Native::RunOrphaned
                | Native::CeilingExceeded
                | Native::ShapeRefused
                | Native::ContentRefused
                | Native::KeyMissing
                | Native::VerbTableRefused
                | Native::PatternTableRefused
                | Native::VerdictTableRefused
                | Native::RedirectTableRefused
                | Native::RemedyUnresolved
                | Native::MarkerTableRefused
                | Native::RuleTableRefused
                | Native::OutputTableRefused
                | Native::WaiverTableRefused
                | Native::FactTableRefused
                | Native::MintTableRefused
                | Native::RecorderTableRefused
                | Native::ProvisionTableRefused
                | Native::StartupTableRefused => native.id(),
            };
            // The prefix is gone (CLOUD-1284), so what makes this a token is the
            // ARITY: exactly three words. Asserting that here rather than a
            // prefix keeps the native half held to the same shape the consumer
            // half is validated against, which is the property the prefix used
            // to stand in for.
            assert_eq!(
                named.split(' ').count(),
                SLOTS,
                "{named} is not a three-word verdict name"
            );
        }
        assert_eq!(
            native_tokens().len(),
            Native::ALL.len(),
            "two native classes share a token, so a refusal under it is unattributable"
        );
    }

    /// The vendored table is held to its own validator.
    ///
    /// Non-negotiable rule 2: the refusals `validate` states are worth nothing
    /// over the one table nobody applies them to, and this is the table that
    /// ships to every consumer.
    #[test]
    fn the_vendored_table_validates() {
        let table = vendored();
        validate(&table, &Vocabulary::default())
            .expect("the table this binary ships is well formed");
        for native in Native::ALL {
            assert!(
                table.iter().any(|entry| entry.id == native.id()),
                "{} is a native class with no declaration, so a refusal under it \
                 could carry no gloss and no route",
                native.id()
            );
        }
    }

    #[test]
    fn subjects_render_in_the_order_they_were_given() {
        let rendered = render_subjects(&[
            Subject::Path {
                path: "a.rs".to_owned(),
            },
            Subject::Line {
                path: "b.rs".to_owned(),
                line: 3,
            },
            Subject::Count { count: 4 },
            Subject::Artifact {
                artifact: "ntia-check".to_owned(),
            },
        ]);
        assert_eq!(rendered, "a.rs b.rs:3 4 ntia-check");
    }
}
