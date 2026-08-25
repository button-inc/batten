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

/// The prefix every verdict token carries.
///
/// A token has to be recognisable **as a token** in a line of output that also
/// carries a rule id and a path, and a fixed prefix is what makes that free
/// rather than a convention a reader has to know. `R-` is its sibling for
/// routes.
pub const VERDICT_PREFIX: &str = "V-";

/// The prefix every route id carries. See [`VERDICT_PREFIX`].
pub const ROUTE_PREFIX: &str = "R-";

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
    /// The id a rendered refusal names, e.g. `R-DEFINE-THE-TASK`.
    ///
    /// Stable and referenceable: an agent told `R-DEFINE-THE-TASK` twice has
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

/// One declared refusal class.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeclaredVerdict {
    /// The token, e.g. `V-TASK-UNDEFINED`.
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub successor: Option<String>,
}

impl DeclaredVerdict {
    /// Whether this entry is a tombstone.
    #[must_use]
    pub fn retired(&self) -> bool {
        self.successor.is_some()
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

/// What a refusal says on the hot path: the token, its gloss, its pointers
/// (CLOUD-1053).
///
/// ```text
/// V-TASK-UNDEFINED (a command row names a task this tree does not define) batten.toml:1604
/// ```
///
/// **The subject stays inline** rather than being dereferenced through
/// `explain`. Making a reader run a second command to learn WHICH file would
/// make the common case slower, which is the opposite of the point; what moves
/// behind `explain` is the class definition, which the common case does not
/// need.
///
/// A token the registry does not carry renders as itself with the gap stated.
/// `policy::load` refuses that at load, so it is reachable only on the mediated
/// path, where the AST check is skipped for CLOUD-689's budget — and there
/// saying so beats either inventing a gloss or dropping the refusal.
#[must_use]
pub fn render_line(registry: &[DeclaredVerdict], token: &str, subjects: &[Subject]) -> String {
    let gloss = resolve(registry, token).map_or(
        "no `[[verdict]]` row declares this class, so it carries no gloss",
        |(entry, _)| entry.gloss.as_str(),
    );
    let pointers = render_subjects(subjects);
    if pointers.is_empty() {
        format!("{token} ({gloss})")
    } else {
        format!("{token} ({gloss}) {pointers}")
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
pub fn validate(verdicts: &[DeclaredVerdict]) -> anyhow::Result<()> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for verdict in verdicts {
        validate_one(verdict)?;
        if !seen.insert(verdict.id.as_str()) {
            return Err(UsageError::raise(format!(
                "verdict `{}` is declared twice; one class, one token — \
                 `batten policy explain {}` cannot resolve to two definitions",
                verdict.id, verdict.id
            )));
        }
    }
    validate_chains(verdicts, &seen)
}

/// The per-entry half of [`validate`].
fn validate_one(verdict: &DeclaredVerdict) -> anyhow::Result<()> {
    let id = verdict.id.as_str();
    if !id.starts_with(VERDICT_PREFIX) || id.len() <= VERDICT_PREFIX.len() {
        return Err(UsageError::raise(format!(
            "verdict `{id}`: a token is `{VERDICT_PREFIX}` followed by a name — \
             the prefix is what makes it readable as a token beside a rule id and a path"
        )));
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
    let mut route_ids: BTreeSet<&str> = BTreeSet::new();
    for route in &verdict.routes {
        validate_route(id, route)?;
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
fn validate_route(verdict: &str, route: &Route) -> anyhow::Result<()> {
    let id = route.id.as_str();
    if !id.starts_with(ROUTE_PREFIX) || id.len() <= ROUTE_PREFIX.len() {
        return Err(UsageError::raise(format!(
            "verdict `{verdict}`: route `{id}` is not `{ROUTE_PREFIX}`-prefixed"
        )));
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
    ];

    /// The token this class is declared and rendered under.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Native::ProtectedMutation => "V-PROTECTED-MUTATION",
            Native::InitWouldOverwrite => "V-AUTHORITY-EXISTS",
            Native::HandlerDenied => "V-HANDLER-DENIED",
            Native::ScannerUnpinned => "V-SCANNER-UNPINNED",
            Native::ScannerUnprovisioned => "V-SCANNER-UNPROVISIONED",
            Native::SpawningRuleOnReadVerb => "V-SPAWN-ON-READ-VERB",
            Native::StopConditionUnmet => "V-STOP-CONDITION-UNMET",
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
struct VendoredVerdict {
    id: &'static str,
    gloss: &'static str,
    class: &'static str,
    routes: &'static [VendoredRoute],
}

/// One vendored route. See [`VendoredVerdict`].
struct VendoredRoute {
    id: &'static str,
    kind: RouteKind,
    target: &'static str,
    precondition: Option<&'static str>,
}

/// A `command`-kind route, which is most of them.
const fn run(id: &'static str, target: &'static str) -> VendoredRoute {
    VendoredRoute {
        id,
        kind: RouteKind::Command,
        target,
        precondition: None,
    }
}

/// A `document`-kind route.
const fn read(id: &'static str, target: &'static str) -> VendoredRoute {
    VendoredRoute {
        id,
        kind: RouteKind::Document,
        target,
        precondition: None,
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
        id: "V-PROTECTED-MUTATION",
        gloss: "a mutating verb was aimed at a path the config protects",
        class: "The path is in the `protected` set, so a write to it is refused before it \
happens rather than reported after. The set is the consumer's own declaration; what is \
protected is a question about their repository, and the engine only enforces it. A \
narrower remedy may be declared per path class through `[[redirect]]`, which is what the \
refusal names when one exists.",
        routes: &[
            read("R-USE-THE-OWNING-SURFACE", "batten.toml"),
            run("R-RESTORE-IT", "git restore"),
        ],
    },
    VendoredVerdict {
        id: "V-AUTHORITY-EXISTS",
        gloss: "`init` will not overwrite the committed authority",
        class: "House style §8 gives a repository ONE committed authority, and `init` \
writes it. Overwriting an existing one would replace a reviewed policy with a default \
set, silently, in a verb whose whole purpose is that there was nothing there before. \
Edit the file that exists, or move it aside deliberately.",
        routes: &[read("R-EDIT-THE-AUTHORITY", "batten.toml")],
    },
    VendoredVerdict {
        id: "V-HANDLER-DENIED",
        gloss: "a configured hook handler denied the call",
        class: "The refusal is the handler's, not the engine's: a `[hook.handler]` row \
names a program, the program answered deny, and this carries that answer through. The \
handler's own reason is free text the consumer configured, so no remedy is invented here \
— the handler is where a remedy would have to be declared.",
        routes: &[read("R-READ-THE-HANDLER-ROW", "batten.toml")],
    },
    VendoredVerdict {
        id: "V-SCANNER-UNPINNED",
        gloss: "a `secrets` rule needs its scanner pinned and none is declared",
        class: "A `secrets` rule delegates to an external scanner, and which scanner \
decides what the rule means. An unpinned one would resolve to whatever is ambient, so a \
green run would say nothing about the tree — the same defect a bare `cargo` has against \
a pinned toolchain. Declare the scanner as a `[[provision]]` entry.",
        routes: &[
            run("R-PROVISION-THE-SCANNER", "batten provision"),
            read("R-DECLARE-THE-ENTRY", "batten.toml"),
        ],
    },
    VendoredVerdict {
        id: "V-SCANNER-UNPROVISIONED",
        gloss: "the pinned scanner is not in the provision cache, so nothing was scanned",
        class: "The scanner is declared and absent. This is could-not-look rather than a \
clean tree, and it is reported as a refusal precisely so the two are not spelled the \
same way: a secrets rule that scanned no file and reported nothing is the vacuous pass \
this engine argues against everywhere.",
        routes: &[run("R-PROVISION-THE-SCANNER", "batten provision")],
    },
    VendoredVerdict {
        id: "V-SPAWN-ON-READ-VERB",
        gloss: "this rule kind runs a configured command, which a read-effect verb will not do",
        class: "The effect model (house style §5) puts every verb in one class and holds \
it there. A rule kind that spawns is `Effect`, and `check` is `Read`, so reaching one \
through the other would make the read-only allowlist a claim nobody could rely on. The \
rule is not wrong; the verb is.",
        routes: &[run("R-USE-THE-SPAWNING-VERB", "batten enforce")],
    },
    VendoredVerdict {
        id: "V-STOP-CONDITION-UNMET",
        gloss: "the end-of-turn facts do not permit stopping",
        class: "A stop is a completion signal, and this engine's whole subject is keeping \
that signal aligned with landed-and-verified work. The facts the turn ended on say it is \
not, and the refusal names which. Each has its own route; the shared one is to finish \
the thing rather than to re-declare that it is finished.",
        routes: &[
            run("R-LAND-IT", "mise run land"),
            read("R-READ-THE-FACTS", "batten.toml"),
        ],
    },
    // ── vendored presets ────────────────────────────────────────────────────
    VendoredVerdict {
        id: "V-EMPTY-COMMIT",
        gloss: "an empty commit records that somebody wanted a new SHA",
        class: "A commit records a change. The reachable use of an empty one is kicking a \
pipeline, which spends a run to re-ask a question the previous run already answered and \
leaves a commit in the history no reader can act on. If the goal is a fresh run, re-run \
the pipeline.",
        routes: &[run("R-RERUN-THE-PIPELINE", "re-run the pipeline")],
    },
    VendoredVerdict {
        id: "V-FORCE-PUSH-AT-TRUNK",
        gloss: "a force push rewrites a shared branch under whoever already fetched it",
        class: "Rewriting a published branch invalidates every checkout of it that \
already exists, and the holder finds out by having their next pull fail in a way that \
looks like their own mistake. `--force-with-lease` refuses when the remote moved, which \
is the same operation with the one check that makes it safe.",
        routes: &[run("R-LEASE-THE-FORCE", "git push --force-with-lease")],
    },
    VendoredVerdict {
        id: "V-SHEBANG-UNNAMED-LANGUAGE",
        gloss: "the file runs a shell and its name does not say so",
        class: "Every instrument that selects by extension — a formatter, a linter, a \
CI path filter — covers this file silently and exits 0. A green run over it therefore \
means nothing was looked at rather than nothing was found, which is worse than a red \
one. Name the language in the filename, or declare the file's coverage another way.",
        routes: &[run("R-NAME-THE-LANGUAGE", "git mv")],
    },
    VendoredVerdict {
        id: "V-SIBLING-UNRESOLVED",
        gloss: "a run-time sibling path is computed and the tree carries no such file",
        class: "The shape resolves a path beside the running program and then guards it \
with a test that exits 0, so the reference does not fail — it goes silent, and the \
behaviour it was reaching for simply never happens. A path that must exist should be \
asserted rather than tested.",
        routes: &[read("R-ADD-THE-SIBLING", "the computed path")],
    },
];

/// Every class the binary ships, as the registry carries them.
///
/// Unioned with the consumer's `[[verdict]]` rows by `policy::load`. A collision
/// between the two is refused there rather than here: which side is at fault is
/// a question about the pair, and this function knows only one of them.
#[must_use]
pub fn vendored() -> Vec<DeclaredVerdict> {
    VENDORED
        .iter()
        .map(|entry| DeclaredVerdict {
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
        })
        .collect()
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
            routes: vec![route("R-DO-THE-THING")],
            successor: None,
        }
    }

    #[test]
    fn a_conforming_entry_validates() {
        validate(&[entry("V-ONE")]).expect("a conforming registry loads");
    }

    #[test]
    fn a_token_without_the_prefix_is_refused() {
        let mut bad = entry("V-ONE");
        bad.id = "TASK-UNDEFINED".to_owned();
        assert!(validate(&[bad]).is_err());
    }

    #[test]
    fn a_duplicate_token_is_refused() {
        assert!(validate(&[entry("V-ONE"), entry("V-ONE")]).is_err());
    }

    #[test]
    fn a_paragraph_gloss_is_refused() {
        let mut bad = entry("V-ONE");
        bad.gloss = "x".repeat(GLOSS_MAX + 1);
        assert!(validate(&[bad]).is_err());
        let mut wrapped = entry("V-ONE");
        wrapped.gloss = "one\ntwo".to_owned();
        assert!(validate(&[wrapped]).is_err());
    }

    #[test]
    fn a_verdict_with_no_route_is_refused() {
        let mut bad = entry("V-ONE");
        bad.routes.clear();
        assert!(validate(&[bad]).is_err());
    }

    #[test]
    fn an_override_alone_is_refused() {
        let mut bad = entry("V-ONE");
        bad.routes = vec![Route {
            id: "R-ASK".to_owned(),
            kind: RouteKind::Override,
            target: String::new(),
            precondition: Some("you can state why".to_owned()),
        }];
        assert!(validate(&[bad]).is_err());
    }

    #[test]
    fn an_override_with_no_precondition_is_refused() {
        let mut bad = entry("V-ONE");
        bad.routes.push(Route {
            id: "R-ASK".to_owned(),
            kind: RouteKind::Override,
            target: String::new(),
            precondition: None,
        });
        assert!(validate(&[bad]).is_err());
    }

    #[test]
    fn a_command_route_carrying_a_precondition_is_refused() {
        let mut bad = entry("V-ONE");
        bad.routes[0].precondition = Some("something".to_owned());
        assert!(validate(&[bad]).is_err());
    }

    #[test]
    fn a_successor_naming_nothing_is_refused() {
        let mut bad = entry("V-OLD");
        bad.successor = Some("V-GONE".to_owned());
        assert!(validate(&[bad]).is_err());
    }

    #[test]
    fn a_cycling_chain_is_refused() {
        let mut first = entry("V-A");
        first.successor = Some("V-B".to_owned());
        let mut second = entry("V-B");
        second.successor = Some("V-A".to_owned());
        assert!(validate(&[first, second]).is_err());
    }

    #[test]
    fn a_tombstone_resolves_to_its_live_successor() {
        let mut old = entry("V-OLD");
        old.successor = Some("V-NEW".to_owned());
        let new = entry("V-NEW");
        let table = vec![old, new];
        validate(&table).expect("a terminating chain loads");
        let (resolved, retired) = resolve(&table, "V-OLD").expect("the token resolves");
        assert_eq!(resolved.id, "V-NEW");
        assert!(retired, "the token the reader asked for was retired");
        assert_eq!(live_tokens(&table), BTreeSet::from(["V-NEW"]));
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
                | Native::StopConditionUnmet => native.id(),
            };
            assert!(
                named.starts_with(VERDICT_PREFIX),
                "{named} is not a verdict token"
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
        validate(&table).expect("the table this binary ships is well formed");
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
