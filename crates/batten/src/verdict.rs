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
//! spelling here for the same reason `rules/policy-modules.md` gives for
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

use serde::Serialize;

use crate::config_check::verdict::vendored;
#[cfg(test)]
use crate::config_model::VocabularyWord;
use crate::config_model::{DeclaredVerdict, Route, Vocabulary};
use crate::error::UsageError;
#[cfg(test)]
use crate::preset_catalog::Applicability;
use crate::preset_catalog::RouteKind;

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
///
/// **THIS NUMBER IS CHOSEN, NOT MEASURED, and saying so is the point** (CLOUD-1637).
/// Its neighbours carry provenance — `[refusal] max_tokens = 24` is read off a
/// live refusal, and the token-prefix figures above are a `tiktoken` run over all
/// 130 classes — so a reader is entitled to assume this one is too, and it is
/// not. 120 characters is a round number picked as "about one line" and nothing
/// was measured against it. It is recorded the way `[hook_output]` records that
/// its own figure is deliberately not the measured one, rather than left to look
/// like evidence.
///
/// What would settle it is a comparison nobody has run: whether a first-sighting
/// gloss beats the refusing row's `reason` for an agent's next attempt.
/// CLOUD-1117 is that trial. Until it reports, this bound is a guard against the
/// gloss growing back into a paragraph, which is a job a chosen number does
/// perfectly well.
pub(crate) const GLOSS_MAX: usize = 120;

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

/// `DeclaredVerdict` behaviour that belongs to this module's layer, not the type's (CLOUD-2793).
pub trait DeclaredVerdictExt: Sized {
    /// Whether this entry is a tombstone, by **either** arm.
    ///
    /// A withdrawn class is as retired as a replaced one — that is the point of
    /// the arm — so the tombstone exemption from the emitted-somewhere half of
    /// registry equality covers both, and a withdrawn token is still wrong to
    /// emit.
    #[must_use]
    fn retired(&self) -> bool;

    /// What a first sighting of this class carries after its pointers: the
    /// gloss, the doc's sections and each override's admissible precondition
    /// (CLOUD-2143). The one text both budget tiers measure.
    #[must_use]
    fn first_sighting(&self) -> String;
}

impl DeclaredVerdictExt for DeclaredVerdict {
    fn retired(&self) -> bool {
        self.successor.is_some() || self.withdrawn.is_some()
    }

    fn first_sighting(&self) -> String {
        let act: Vec<&str> = self.doc.act.iter().map(String::as_str).collect();
        let mut body = self.gloss.trim().to_owned();
        let sections = crate::doc::render(&self.doc, &act);
        if !sections.is_empty() {
            body.push_str(". ");
            body.push_str(&sections);
        }
        for route in &self.routes {
            if let (RouteKind::Override, Some(precondition)) =
                (route.kind, route.precondition.as_deref())
            {
                for part in [" Admissible as '", &route.id, "' when ", precondition, "."] {
                    body.push_str(part);
                }
            }
        }
        body
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

/// A named thing as a subject: how an engine emitter's own words travel on a
/// class's line (CLOUD-2078), the handler-deny precedent of text Batten does
/// not class being a subject of a class Batten does.
#[must_use]
pub fn artifact(name: &str) -> Subject {
    Subject::Artifact {
        artifact: name.to_owned(),
    }
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

    /// The path this subject names, for a `Path` or a `Line`; `None` otherwise.
    #[must_use]
    pub fn path(&self) -> Option<&str> {
        match self {
            Subject::Path { path } | Subject::Line { path, .. } => Some(path),
            Subject::Count { .. } | Subject::Artifact { .. } => None,
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

/// The spelling an admission binds a subject in — the one function both sides
/// of the mediated surface spell through (CLOUD-1826, CLOUD-1997).
///
/// A refusal PRINTS its pointers joined by a space ([`render_subjects`]); a
/// reader copies that line into `override request --subject`. So whitespace is
/// rejoined with `,`, and the binding side (`refusal::admission_bindings`) runs
/// what it prints through this same function — which is what makes a pasted line
/// bind as the refusal does.
///
/// **The `/` exception exists for the TREE surface**: a tree admission is matched
/// against `finding.path` verbatim, and a path like `docs/a b.md` rejoined would
/// name nothing any finding carries. Idempotent: a `/`-bearing text comes back
/// trimmed, and any other text has no whitespace left after the join.
#[must_use]
pub fn bound_subject(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.contains('/') {
        return trimmed.to_owned();
    }
    trimmed.split_whitespace().collect::<Vec<_>>().join(",")
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

/// How a route renders on a first sighting, or `None` where it does not render.
///
/// **An exhaustive match with no wildcard arm, and that is the point** (CLOUD-1637).
/// The mapping is from a remedy SHAPE to the verb that names who acts: `command`
/// is something the agent runs, `document` something it reads, `issue` something
/// it takes to the tracker. A shape whose actor is not the agent must not render
/// as something the agent runs, so a variant added later — CLOUD-1639's repaired
/// arms are the next two — is a COMPILE ERROR here rather than a route silently
/// omitted from every refusal that declares one.
///
/// [`RouteKind::Override`] renders nowhere, for the reason it is already excluded
/// from the `Fix:` slot: a way through that begins by asking to be excused is not
/// an alternative to the action, and `override request` is its own surface. That
/// is an omission this function STATES rather than one a wildcard would hide.
///
/// **The mutation below is CLOUD-1637's declared one**, and it is anchored here
/// rather than in `hook.rs` where §7 named it: the kind mapping is what the row
/// is about, and it lives in this function. Dropping the `document` arm restores
/// the exact defect — a class whose only route is a document renders no way out —
/// so `refusal_ceiling`'s first-sighting case is what must redden.
#[must_use]
pub(crate) fn render_route(route: &Route) -> Option<String> {
    let verb = match route.kind {
        RouteKind::Command => "run",
        RouteKind::Document => "read",
        RouteKind::Issue => "see",
        RouteKind::Override => return None,
    };
    Some(format!("{verb} {}", route.target))
}

/// Every non-override route a class declares, rendered by kind (CLOUD-1637).
///
/// **This replaces [`command_routes`] as the first-sighting projection, and the
/// replacement is the whole row.** That function filters [`RouteKind::Command`],
/// so a class whose routes are all `document` or `issue` resolved to an empty
/// list and `deny_text` fell through to the bare line — on the FIRST sighting as
/// much as on a repeat. Counted over `batten.toml` and this file at the time:
/// 112 of 162 consumer classes and 32 of 39 vendored ones declare no `command`
/// route at all, so 144 of 201 classes never rendered a way out and the gloss
/// rendered on no arm.
///
/// The four classes a session measured on 2026-09-08 are the shape of it — `tool
/// run loose`, `verdict read dropped`, `verdict carry other` and `call name
/// refused` each declare exactly one `document` route, each fired at least once
/// with nothing but its token, and two fired twice because the first firing
/// delivered no definition.
///
/// Overrides are excluded by [`render_route`], which says so in one place rather
/// than at each caller.
#[must_use]
pub fn sighting_routes(registry: &[DeclaredVerdict], token: &str) -> Vec<String> {
    let Some((entry, _)) = resolve(registry, token) else {
        return Vec::new();
    };
    entry.routes.iter().filter_map(render_route).collect()
}

/// The one-line gloss a class declares, for the arm that carries it.
///
/// `None` where the token does not resolve, which is the same answer
/// [`command_routes`] gives and for the same reason: a registry that does not
/// declare the token cannot be made to say what it means.
#[must_use]
pub fn gloss_of<'a>(registry: &'a [DeclaredVerdict], token: &str) -> Option<&'a str> {
    let (entry, _) = resolve(registry, token)?;
    Some(entry.gloss.as_str())
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
    // ARM 1b. `at` opens a finding line's subjects (CLOUD-2145), so a name
    // holding it would end where the reader reads it as starting a pointer.
    if words.contains(&"at") {
        return Err(UsageError::raise(format!(
            "{kind} `{name}`: `at` is the word a finding line opens its subjects with, \
             so a name cannot carry it"
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

/// Normalise a rule id to the space form, accepting the three spellings.
///
/// `-` and `_` are accepted at the boundary and NOWHERE stored: a name has one
/// spelling on every emitted surface, because two spellings of one id is the
/// same two-names-for-one-thing this row exists to remove, one level down.
/// Measured over the declared set (`o200k_base`, leading space): space **3.01**
/// tokens, snake **3.94**, hyphen **4.41** — so the space form is the cheap one
/// as well as the canonical one.
///
/// This does not decide whether the words are declared; [`check_rule_id`] does.
#[must_use]
pub fn normalise_rule_id(id: &str) -> String {
    id.split(['-', '_', ' '])
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// A rule id is three vocabulary words, in the same grammar a class token is
/// (CLOUD-1638).
///
/// **The same checker, deliberately.** A rule id and a class token are two names
/// for things a reader meets in the same line, and a second grammar would be a
/// second thing to learn for no gain — so this is [`check_name`] with the id
/// normalised first, not a fork of it.
///
/// # Errors
///
/// When the id is not exactly [`SLOTS`] words, or a word is not declared in the
/// vocabulary slot its position names.
pub fn check_rule_id(id: &str, vocabulary: &Vocabulary) -> anyhow::Result<String> {
    let normalised = normalise_rule_id(id);
    let mut used = BTreeSet::new();
    check_name("rule", &normalised, vocabulary, &mut used)?;
    Ok(normalised)
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
    // THE GRANT IS THE ONE CLASS THAT NEVER REFUSES (CLOUD-2145): it allows
    // the call, so it asks nothing of its reader and a route would point at
    // nothing. Every other class may refuse, and owes a way out.
    if verdict.routes.is_empty() && id != Native::CallGrantNow.id() {
        return Err(UsageError::raise(format!(
            "verdict `{id}` declares no route — a refusal owes its reader a way out, \
             which is the contract `Fix` has carried since CLOUD-122"
        )));
    }
    // Only a class WITH routes can have an override as its only one: `all`
    // over none is vacuously true, and the grant declares none.
    if !verdict.routes.is_empty()
        && verdict
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
    // A REPAIRING CLASS OWES A ROUTE THAT IS NOT A REPAIR (CLOUD-1639).
    //
    // `retry` and `silent` say the boundary will act, and the whole point of the
    // pair is that the action can FAIL — a `fix` that did not run falls back to
    // this class's ordinary refusal, and at that moment the reader needs the way
    // out every other class owes. The clause above already refuses an empty
    // route list; this refuses the subtler shape, a class whose only route is
    // the repair the boundary was going to run anyway, which leaves the fallback
    // arm pointing at the thing that just failed.
    if verdict.applicability.repairs()
        && verdict
            .routes
            .iter()
            .all(|route| route.kind == RouteKind::Command)
        && verdict.routes.len() == 1
    {
        return Err(UsageError::raise(format!(
            "verdict `{id}` declares `applicability = \"{}\"` and exactly one \
             `command` route — a repair that fails falls back to this class's \
             ordinary refusal, so it owes a way out that is not the repair itself",
            verdict.applicability.as_str()
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
    // THE FIRST SIGHTING'S BUDGET (CLOUD-2143): the gloss, the doc and every
    // admissible precondition together, because that is what a reader is handed
    // once per window. Checked on what IS declared; a class with no doc still
    // loads, and this repository's own registry is held to carrying one by
    // `every_vendored_and_declared_doc_is_within_160_o200k_tokens`.
    if !verdict.retired()
        && let Some(why) = crate::doc::violation(&verdict.doc, &verdict.first_sighting())
    {
        return Err(UsageError::raise(format!("verdict `{id}`'s doc {why}")));
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

// `Native` lives in `crate::error` (CLOUD-2789), which a `UsageError` names
// it from, so the module every other one reports through reaches no higher.
// Its path here is unchanged.
use crate::error::Native;

/// Every token the crate's own refusal sites may raise.
///
/// Read by `policy::load` for the half of registry equality that asks whether a
/// declared token is emitted by ANYTHING: a `[[verdict]]` row covering a native
/// class is not dead vocabulary just because no module raises it.
#[must_use]
pub fn native_tokens() -> BTreeSet<&'static str> {
    Native::ALL.iter().map(|native| native.id()).collect()
}

/// The rule ids the ENGINE raises under, which no `[[rule]]` row declares
/// (CLOUD-2142), each with the one sentence `policy explain` answers for it.
///
/// Every finding line hops to `batten policy explain '<rule>'`, so a rule id
/// nothing resolves is a hop to nowhere. A consumer's ids resolve through its own
/// rows; these are the engine's, declared beside the code that raises them and
/// answered here so they resolve with no config at all — `engine-cannot-adjudicate`
/// fires precisely when the config will not load. Where the line also names a
/// class, the class carries the definition and routes; this says what raised it.
///
/// `tests/it/emission_census.rs` keeps the table whole: every production
/// `Refusal` built from a literal or constant id must resolve, so a new engine id
/// is a red test rather than an unresolvable name.
const NATIVE_RULES: &[(&str, &str)] = &[
    (
        "engine-cannot-adjudicate",
        "This build could not load the rules it is registered to enforce, so nothing judged \
         the call. A Read still answers and an Edit or Write of batten.toml or \
         batten.local.toml still lands: repair the file with those, or run `batten engine \
         update` when the config pins a different engine.",
    ),
    (
        "config-write-unloadable",
        "This write would leave batten.toml unable to load, so every call after it would be \
         refused under engine-cannot-adjudicate. The text it lands was loaded as the hook \
         loads it and refused; write the module a row names before the row, use only declared \
         vocabulary, and make the whole change in one write.",
    ),
    (
        "program-unknown",
        "The mediated-call boundary could not classify the program a shell call names, so \
         it refused rather than guess what the call changes; the class on the line carries \
         the routes.",
    ),
    (
        "history-drop",
        "The destructive-reset gate: this reset would leave the commits the line counts \
         referenced by nothing and on no remote; `git reflog` still holds them, so push or \
         branch them before resetting.",
    ),
    (
        "rule-history-unread",
        "The history gate: a write changes a config row this context has not read the \
         history of at its current digest; `batten policy explain '<id>' --history`, one \
         call naming every row, mints the read.",
    ),
    (
        "repository-reach",
        "The reach gate: this call acts on a repository other than the session's home, which \
         arms the gate; work there in its own session, or request an override to cross.",
    ),
    (
        "budget-call",
        "The budget gate: this write would grow a `[budget.*]` set past a ceiling it \
         declares, measured as `policy budget` measures it; shrink the write, or raise the \
         set's ceiling in a separate change.",
    ),
    (
        "detached-call",
        "The detach gate: a `&` job this call does not wait on returns before its work \
         does, and the session's wake-up with it; set the host's background option on the \
         call, or `wait` for the job in the same call.",
    ),
    (
        "commit-subject",
        "The commit-subject gate: the message this commit names has a subject \
         `[commit].subject_pattern` refuses, judged before the commit exists; reword the \
         subject to match the pattern.",
    ),
    (
        "singleton-held",
        "The singleton gate: a live process already holds this task's lock, and a second run \
         would race it; `batten task alive` reports what the holder is doing.",
    ),
    (
        "stop.unfinished",
        "The stop gate: the turn tried to end while work it declared is still unfinished; \
         the class on the line names what remains.",
    ),
    (
        "ripsecrets",
        "The secret scanner, which the engine declares rather than a row: its `[[provision]]` \
         entry is unpinned or not provisioned, so no scan ran; the class on the line routes \
         the repair.",
    ),
    (
        "init.config-exists",
        "`batten init` found a config already present and refused to overwrite it.",
    ),
    (
        "hk-contract-drift",
        "The committed hk plan artifact the line names no longer matches what this engine \
         generates from the config; regenerate it, as the class on the line routes.",
    ),
];

/// Engine rule ids minted from a prefix and a consumer's name (CLOUD-2142).
const NATIVE_RULE_PREFIXES: &[(&str, &str)] = &[(
    "hook.handler.",
    "A `[[hook.handler]]` row's program refused the call; its own words travel as the \
     line's subject, and its row in batten.toml says what it guards.",
)];

/// The sentence `policy explain` answers for an engine rule id, or `None` where
/// the name is not one (CLOUD-2142).
#[must_use]
pub fn native_definition(name: &str) -> Option<&'static str> {
    NATIVE_RULES
        .iter()
        .find(|(id, _)| *id == name)
        .or_else(|| {
            NATIVE_RULE_PREFIXES
                .iter()
                .find(|(prefix, _)| name.starts_with(prefix) && name.len() > prefix.len())
        })
        .map(|(_, definition)| *definition)
}

fn declares_override(entry: &DeclaredVerdict) -> bool {
    entry
        .routes
        .iter()
        .any(|route| route.kind == RouteKind::Override)
}

/// Every live class whose only ways out end in a path `protects` covers, and
/// that has no admission of its own — empty whenever `path write refused`, the
/// class blocking those paths, declares one (CLOUD-1893).
///
/// A refusal whose only way out is an action another refusal blocks is a
/// deadlock with every gate green; CLOUD-1051/1357 shipped it once. This is the
/// graph edge that names it, computed from the registry and a path set.
///
/// - A `document` route into a protected path is read as asking for a CHANGE,
///   because the kind cannot tell a read from an edit. That reading is safe:
///   this refuses nothing, and its only discharge is an admission that exists.
/// - `command` and `issue` routes count as unblocked — whether running one
///   clears the refusal is a gated-model verdict (rule 3), which
///   `policy/verdict-routes-resolve.rego` disclaims too.
/// - There is no load-time arm. The blocker is vendored and a consumer cannot
///   redeclare it, so the predicate over `consumer ∪ vendored()` is empty
///   exactly when it is empty over `vendored()`; a consumer load refused over
///   the binary's own table would be the wrongly-refusing gate.
/// - One override per class is rejected: it would be one admission in many
///   costumes, the shape CLOUD-680 measured.
#[must_use]
pub fn routed_only_into_protection(
    registry: &[DeclaredVerdict],
    protects: impl Fn(&str) -> bool,
) -> Vec<String> {
    let gate = Native::ProtectedMutation.id();
    if registry
        .iter()
        .any(|entry| entry.id == gate && declares_override(entry))
    {
        return Vec::new();
    }
    #[rustfmt::skip]
    let blocked = |route: &Route| route.kind == RouteKind::Document && protects(&route.target);
    registry
        .iter()
        .filter(|entry| entry.successor.is_none() && entry.withdrawn.is_none())
        .filter(|entry| !declares_override(entry))
        .filter(|entry| {
            let ways: Vec<&Route> = entry
                .routes
                .iter()
                .filter(|route| route.kind != RouteKind::Override)
                .collect();
            !ways.is_empty() && ways.iter().all(|route| blocked(route))
        })
        .map(|entry| entry.id.clone())
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    #[cfg(test)]
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
            doc: crate::doc::Doc::default(),
            class: "the long definition".to_owned(),
            routes: vec![route("do the thing")],
            successor: None,
            withdrawn: None,
            applicability: Applicability::Advice,
        }
    }

    #[test]
    fn a_conforming_entry_validates() {
        validate(&[entry("one probe probe")], &Vocabulary::default())
            .expect("a conforming registry loads");
    }

    #[test]
    fn each_route_kind_and_applicability_has_its_own_token() {
        assert_eq!(RouteKind::Command.as_str(), "command");
        assert_eq!(RouteKind::Document.as_str(), "document");
        assert_eq!(RouteKind::Issue.as_str(), "issue");
        assert_eq!(RouteKind::Override.as_str(), "override");
        assert_eq!(Applicability::Advice.as_str(), "advice");
        assert_eq!(Applicability::Retry.as_str(), "retry");
        assert_eq!(Applicability::Silent.as_str(), "silent");
        assert!(Applicability::Advice.is_default() && !Applicability::Advice.repairs());
        assert!(!Applicability::Retry.is_default() && Applicability::Retry.repairs());
    }

    /// Fails by: a vocabulary declaring one slot only read as empty.
    #[test]
    fn a_vocabulary_is_empty_only_when_every_slot_is() {
        assert!(Vocabulary::default().is_empty());
        let full = vocab();
        for keep in 0..SLOTS {
            let mut one = full.clone();
            for slot in 0..SLOTS {
                if slot != keep {
                    match slot {
                        0 => one.subject.clear(),
                        1 => one.action.clear(),
                        _ => one.condition.clear(),
                    }
                }
            }
            assert!(!one.is_empty(), "slot {keep}");
        }
    }

    #[test]
    fn a_word_with_a_space_is_refused_as_not_a_single_word() {
        let mut spaced = vocab();
        spaced.subject[0].word = "two words".to_owned();
        let err = validate(&[named("task read first")], &spaced).unwrap_err();
        assert!(format!("{err:#}").contains("not a single word"), "{err:#}");
    }

    /// Fails by: a subject's path dropped, a bare-path member decoded as
    /// nothing, or a bound subject spelled other than its refusal printed it.
    #[test]
    fn a_subject_reads_and_binds_as_the_refusal_prints_it() {
        let line = Subject::Line {
            path: "src/a.rs".to_owned(),
            line: 3,
        };
        assert_eq!(line.path(), Some("src/a.rs"));
        assert_eq!(Subject::Count { count: 2 }.path(), None);
        assert_eq!(
            Subject::from_json(&serde_json::json!({"path": "src/a.rs"})),
            Some(Subject::Path {
                path: "src/a.rs".to_owned()
            })
        );
        assert_eq!(bound_subject("  a b  "), "a,b");
        assert_eq!(bound_subject(" docs/a b.md "), "docs/a b.md");
        assert_eq!(
            render_line(&[], "task read first", &[line]),
            "task read first src/a.rs:3"
        );
        assert_eq!(render_line(&[], "task read first", &[]), "task read first");
    }

    /// Fails by: a route of another kind offered as a command, or a class's
    /// routes not resolved at all.
    #[test]
    fn command_routes_are_the_command_kind_only_and_sightings_skip_overrides() {
        let mut class = entry("one probe probe");
        class.routes = vec![
            Route {
                kind: RouteKind::Document,
                target: "rules/a.md".to_owned(),
                ..route("read it")
            },
            route("run it"),
            Route {
                kind: RouteKind::Override,
                target: String::new(),
                ..route("ask")
            },
        ];
        let registry = [class];
        assert_eq!(
            command_routes(&registry, "one probe probe"),
            ["mise run something"]
        );
        assert_eq!(
            first_command_route(&registry, "one probe probe"),
            Some("mise run something")
        );
        assert_eq!(
            sighting_routes(&registry, "one probe probe"),
            ["read rules/a.md", "run mise run something"]
        );
        assert!(command_routes(&registry, "no such class").is_empty());
        assert_eq!(
            declared_tokens(&registry),
            BTreeSet::from(["one probe probe"])
        );
    }

    /// Fails by: a cycle the bound must break spun forever.
    #[test]
    fn resolution_terminates_on_a_successor_cycle() {
        let mut one = entry("one probe probe");
        one.successor = Some("two probe probe".to_owned());
        let mut two = entry("two probe probe");
        two.successor = Some("one probe probe".to_owned());
        assert!(resolve(&[one, two], "one probe probe").is_some());
    }

    /// Fails by: a repairing class with one command route admitted, or one
    /// whose single route is not a command refused.
    #[test]
    fn a_repair_owes_a_route_that_is_not_the_repair_itself() {
        let repairing = |routes: Vec<Route>| {
            let mut class = entry("one probe probe");
            class.applicability = Applicability::Retry;
            class.routes = routes;
            validate(&[class], &Vocabulary::default())
        };
        assert!(repairing(vec![route("run it")]).is_err());
        assert!(repairing(vec![route("run it"), route("or this")]).is_ok());
        assert!(
            repairing(vec![Route {
                kind: RouteKind::Document,
                target: "rules/a.md".to_owned(),
                ..route("read it")
            }])
            .is_ok()
        );
    }

    /// Fails by: any one exclusion of the deadlock edge dropped.
    #[test]
    fn only_a_live_class_whose_every_way_out_is_protected_deadlocks() {
        let protects = |path: &str| path.starts_with("protected/");
        let into = |id: &str, kind: RouteKind, target: &str| {
            let mut class = entry(id);
            class.routes = vec![Route {
                kind,
                target: target.to_owned(),
                ..route("way out")
            }];
            class
        };
        let deadlocked = into("one probe probe", RouteKind::Document, "protected/a.md");
        let runnable = into("two probe probe", RouteKind::Command, "protected/a.md");
        let mut retired = into("three probe probe", RouteKind::Document, "protected/a.md");
        retired.successor = Some("one probe probe".to_owned());
        let mut routeless = entry("four probe probe");
        routeless.routes.clear();
        let mut excused = into("five probe probe", RouteKind::Document, "protected/a.md");
        excused.routes.push(Route {
            kind: RouteKind::Override,
            target: String::new(),
            ..route("ask")
        });
        let gate = into(
            Native::ProtectedMutation.id(),
            RouteKind::Document,
            "rules/a.md",
        );
        let registry = [deadlocked, runnable, retired, routeless, excused, gate];
        assert_eq!(
            routed_only_into_protection(&registry, protects),
            ["one probe probe"]
        );
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

    // --- the rule-id grammar (CLOUD-1638) -----------------------------------

    #[test]
    fn a_rule_id_is_accepted_in_three_spellings_and_stored_in_one() {
        // THE POINT OF NORMALISING RATHER THAN PICKING ONE SPELLING: a rule id
        // reaches this from a `[[rule]] id`, a module's `"rule":` literal, a
        // mutation row and a `policy rule` argument, and those surfaces do not
        // share a house style. Accepting all three at the boundary and storing
        // one is what keeps the id ONE name — two spellings of an id would be
        // the same two-names-for-one-thing this row removes, a level down.
        for spelling in ["task read first", "task-read-first", "task_read_first"] {
            let back = check_rule_id(spelling, &vocab())
                .unwrap_or_else(|error| panic!("`{spelling}` is a legal id: {error}"));
            assert_eq!(
                back, "task read first",
                "every spelling stores as the space form"
            );
        }
    }

    #[test]
    fn a_rule_id_outside_the_vocabulary_is_refused() {
        // The membership arm, which is what makes the id a NAME rather than
        // free-text kebab prose — the defect this row is about.
        assert!(
            check_rule_id("task read undeclared", &vocab()).is_err(),
            "a word no slot declares is refused in an id exactly as in a class"
        );
    }

    #[test]
    fn a_rule_id_of_the_wrong_arity_is_refused() {
        // BOTH directions, because a two-word id and a four-word id fail for the
        // same reason and only one of them is the obvious one.
        for wrong in ["task read", "task read first second", "task"] {
            assert!(
                check_rule_id(wrong, &vocab()).is_err(),
                "`{wrong}` is not three words and must be refused"
            );
        }
    }

    #[test]
    fn normalising_an_id_collapses_repeated_separators_rather_than_minting_empty_words() {
        // A doubled separator would otherwise yield an empty word, which reads
        // as a four-word name and fails the arity arm with a message naming the
        // wrong defect. Cheap to get right, confusing to leave.
        assert_eq!(normalise_rule_id("task--read__first"), "task read first");
        assert_eq!(normalise_rule_id("  task read first  "), "task read first");
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

    /// Every native class is a well-formed token.
    ///
    /// Completeness and uniqueness need no test: `Native::ALL` and the enum are
    /// generated from one declaration (`token_enum!`, CLOUD-2442), and a token
    /// declared twice fails the build. What a declaration can still get wrong is
    /// a token's SHAPE, and that is what this asserts — so adding a class
    /// changes no line here.
    #[test]
    fn every_native_class_is_listed() {
        for native in Native::ALL {
            let named = native.id();
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
    }

    /// The vendored table is held to its own validator.
    ///
    /// Non-negotiable rule 2: the refusals `validate` states are worth nothing
    /// over the one table nobody applies them to, and this is the table that
    /// ships to every consumer.
    #[test]
    fn a_class_with_no_route_is_refused_unless_it_is_the_grant() {
        let stripped = |token: &str| -> Vec<DeclaredVerdict> {
            vendored()
                .into_iter()
                .map(|mut entry| {
                    if entry.id == token {
                        entry.routes.clear();
                    }
                    entry
                })
                .collect()
        };
        validate(&stripped(Native::CallGrantNow.id()), &Vocabulary::default())
            .expect("the grant refuses nothing, so it owes no way out");
        assert!(
            validate(
                &stripped(Native::DrainFitBroken.id()),
                &Vocabulary::default()
            )
            .is_err(),
            "any other class may refuse, and must name a way out"
        );
    }

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
        // Held to the same prose census as a consumer's rows (CLOUD-1642),
        // whatever the vendored count is when a class lands.
        assert_eq!(
            crate::config::text_offenders("verdict", &table),
            Vec::<String>::new(),
            "a vendored class is longer than its column's cap"
        );
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

    /// Fails by: a red head's class routed to the loop's inner gate, so a
    /// stopped lap is followed by a standalone `verify` and then the lap that
    /// runs the same gate again, instead of by the lap alone (CLOUD-2707).
    #[test]
    fn a_red_head_routes_back_to_the_lap_not_its_inner_gate() {
        let registry = vendored();
        for class in ["check run red", "job run red"] {
            assert_eq!(
                command_routes(&registry, class),
                vec!["batten land lap"],
                "{class}"
            );
        }
    }
}
