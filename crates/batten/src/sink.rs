//! Production: the records a rule declares, and the boundary writes (CLOUD-851).
//!
//! # The gap this closes
//!
//! Nothing in the model meant "produces". Every path-shaped `Rule` column is an
//! INPUT selector, `Cost` describes what resolving a fact spends, and
//! [`crate::rules::Rule::fix`] is hard-refused with the honest message that
//! serialised fix execution is not a capability this build has. Meanwhile eleven
//! bash programs write records under the git dir, and the retirement campaign has
//! nowhere to put them.
//!
//! # The decision requests, the boundary performs
//!
//! This module is the boundary half, and the split is the whole design.
//! `hook::adjudicate` is contractually pure and three of the four writing hook
//! bodies are on the mediated path, so a sink that wrote from inside the decision
//! would end that. Instead a rule's decision yields a [`Requested`] — a value,
//! carrying no file handle and no resolved branch — and [`perform`] is what turns
//! it into bytes. The shape is [`crate::refusal::Fix::Run`]'s: state the effect,
//! let the boundary that already owns every other write make it happen.
//!
//! # Rule 4 holds harder here than at a report
//!
//! A finding is read by a person; a sink OUTLIVES the run and is read back by a
//! later one. So a record is a digest, a count or nothing — never matched
//! content. [`Requested`] structurally cannot carry a byte of a file, the way
//! `Finding` has no field a matched byte can occupy. `pr-unsubscribed`'s
//! sha256-of-the-answer is the precedent this inherits.
//!
//! # Byte-stability regardless of completion order
//!
//! Source acquisition is concurrent (CLOUD-850), so two rules producing into one
//! journal in whichever order they finish would be a non-deterministic file.
//! [`perform`] sorts before it writes and writes each key once, so the bytes are a
//! function of the request SET rather than of the schedule. §6 asks for exactly
//! that, and `tests/sinks.rs` runs it enough times for an ordering-dependent
//! fan-in to fail rather than asserting it once.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::Result;
use crate::facts::Production;
use crate::rules::SinkKey;

/// The directory every produced record lives under, relative to the git dir.
///
/// Under `$GIT_DIR` rather than the work tree, for the reason every existing
/// writer already chose it: a produced record is state about this checkout, never
/// a tracked artifact, and a sink that could dirty the working tree would make
/// `batten check` a thing that changes what it is judging.
const STORE: &str = "batten-sinks";

/// One record a rule asked the boundary to write.
///
/// Pointer-only by construction: a rule id, a kind, a key and a digest with a
/// count. There is no field a matched byte can occupy, which is how rule 4 is
/// decided here rather than promised.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Requested {
    /// The rule that asked. First in declaration order because it is the sort
    /// key that makes a fan-in deterministic.
    pub rule: String,
    /// What this record is filed under, UNRESOLVED. A branch is a fact about the
    /// checkout, and resolving one inside the decision is exactly the impurity
    /// this split exists to avoid — so the decision names the key it wants and
    /// [`perform`] is handed the answer.
    pub key: SinkKey,
    /// What kind of record, which decides whether [`perform`] appends, replaces
    /// or merely touches.
    pub kind: Production,
    /// A sha256 over what the rule decided, and the number of findings behind it.
    /// Empty for a [`Production::Marker`], whose only content is its existence.
    pub digest: String,
    /// How many findings the digest covers. A count is a pointer; the findings
    /// themselves are not written.
    pub count: usize,
}

impl Requested {
    /// The one line this record renders as. Byte-stable for a given request.
    #[must_use]
    pub fn render(&self) -> String {
        match self.kind {
            // A marker's content is its existence, so it has none. An empty file
            // rather than a token, because any token would be a second thing a
            // reader could come to depend on.
            Production::Marker => String::new(),
            Production::Journal | Production::Baseline => {
                format!("{} {} {}\n", self.rule, self.digest, self.count)
            }
        }
    }
}

/// What DISTINGUISHES one of a rule's records from another, or `None` when the
/// boundary could not look.
///
/// **It is not the destination, and that distinction is the fix for a real
/// collision.** The first version returned the rule id for [`SinkKey::Rule`] and
/// the branch for [`SinkKey::Branch`], and used it as the whole filename — so two
/// branch-keyed rules of one kind resolved to ONE path and the sorted write order
/// decided which record survived, silently. The read side lost the same
/// information the other way: a map keyed on this string alone collapsed a
/// journal and a baseline that shared a branch.
///
/// [`crate::rules::Rule::produces`] is an `Option`, so a rule has at most one
/// sink and **the rule id is already a unique destination**. Putting it in the
/// path as its own segment makes the collision inexpressible rather than
/// refused — no load-time guard to remember, and nothing for a future key to
/// re-open. What is left here is the narrower question this column was always
/// asking: does the rule keep one record, or one per branch?
///
/// Could-not-look is a skip, never a fallback name. A branch-keyed record filed
/// under some stand-in would be read back by a later run as that run's own
/// record, which is a ratchet silently comparing two different subjects — worse
/// than not writing at all.
#[must_use]
fn discriminator(key: SinkKey, branch: Option<&str>) -> Option<String> {
    match key {
        // A literal, not the rule id: the rule is already a path segment, and
        // repeating it here would read as though the two could differ.
        SinkKey::Rule => Some(String::from("rule")),
        SinkKey::Branch => branch.map(str::to_owned),
    }
}

/// Where one record lives: `<kind>/<rule>/<discriminator>`.
///
/// The rule segment is what makes two rules unable to share a destination. Both
/// remaining segments are escaped rather than allowed to create directories: a
/// branch nests (`claim.<branch>` is the censused case) and a rule id is a
/// consumer's string, so either could otherwise let one record shadow another's
/// prefix — a collision nobody would see.
#[must_use]
pub fn path(git_dir: &Path, kind: Production, rule: &str, discriminator: &str) -> PathBuf {
    git_dir
        .join(STORE)
        .join(kind.as_str())
        .join(rule.replace('/', "%2F"))
        .join(discriminator.replace('/', "%2F"))
}

/// Read the records earlier runs produced, for exactly the keys asked for.
///
/// DECLARED KEYS ONLY, never a directory walk: the acquisition is bounded by the
/// ruleset the way `documents` is bounded by declaration, and a walk would make
/// [`crate::facts::PRODUCED`]'s `read` classification a lie by degrees.
///
/// A key with no record is ABSENT from the map rather than present-and-empty. The
/// two are different answers — "no earlier run produced this" against "an earlier
/// run produced nothing" — and the marker kind is exactly the case where
/// collapsing them would make the presence test decide the opposite thing.
/// KEYED BY RULE, which is both unambiguous and the question a module asks.
/// `input.tree.produced["<rule id>"]` reads "what did that rule record last
/// time" — and because a rule has one sink, the kind and the discriminator are
/// properties of that record rather than parts of its address.
#[must_use]
pub fn store(git_dir: &Path, declared: &BTreeSet<Declared>) -> BTreeMap<String, String> {
    let mut records = BTreeMap::new();
    for entry in declared {
        if let Ok(text) =
            std::fs::read_to_string(path(git_dir, entry.kind, &entry.rule, &entry.discriminator))
        {
            records.insert(entry.rule.clone(), text);
        }
    }
    records
}

/// One record a rule set declares, fully addressed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Declared {
    /// The rule that owns it — the segment that makes the address unique.
    pub rule: String,
    /// Which kind of record.
    pub kind: Production,
    /// Which of that rule's records: the literal `rule`, or a branch.
    pub discriminator: String,
}

/// Every record a rule set's sinks address, for [`store`] to acquire before the
/// run.
///
/// Resolved here, at the boundary, for [`discriminator`]'s reason: the read half
/// has to look under the same address the write half filed it under, and the
/// branch is the caller's answer about the checkout rather than the rule's.
#[must_use]
pub fn declared_records(rules: &[crate::rules::Rule], branch: Option<&str>) -> BTreeSet<Declared> {
    rules
        .iter()
        .filter_map(|rule| {
            let sink = rule.produces.as_ref()?;
            Some(Declared {
                rule: rule.id.clone(),
                kind: sink.kind,
                discriminator: discriminator(sink.key, branch)?,
            })
        })
        .collect()
}

/// Whether any rule in the set declares a sink at all (CLOUD-851).
///
/// **The guard that keeps the common run free.** Acquiring the store means
/// locating the git dir and, for a branch-keyed sink, reading HEAD — and doing
/// that unconditionally cost `check` a measured p50 of 4.76ms -> 10.01ms
/// (2.103x), well past `perf-compare`'s 1.30 threshold, for a question no rule
/// had asked. `receipt::verdicts` states the same rule one channel over: a
/// caller must not pay a git invocation for a question it never asks.
#[must_use]
pub fn any_declared(rules: &[crate::rules::Rule]) -> bool {
    rules.iter().any(|rule| rule.produces.is_some())
}

/// Whether any declared sink is keyed by BRANCH.
///
/// Split from [`any_declared`] for the same economy one step finer: a rule set
/// whose sinks are all rule-keyed needs no branch, and resolving one would be a
/// second read nobody asked for.
#[must_use]
pub fn any_branch_keyed(rules: &[crate::rules::Rule]) -> bool {
    rules
        .iter()
        .filter_map(|rule| rule.produces.as_ref())
        .any(|sink| sink.key == SinkKey::Branch)
}

/// Write every requested record, and answer how many reached disk.
///
/// # Byte-stability
///
/// The requests are sorted and each key is written once per call, so the bytes
/// are a function of the request set rather than of the order the rules finished
/// in. A journal accumulates across CALLS, which is what a journal is; within one
/// call its added lines are ordered by rule id.
///
/// # Errors
///
/// Propagates a failure to create the store or to write a record. A caller on the
/// mediated path treats that as *could not record*: a boundary that cannot write
/// a fact must never become the reason work stops.
pub fn perform(git_dir: &Path, branch: Option<&str>, requested: &[Requested]) -> Result<usize> {
    let mut sorted: Vec<&Requested> = requested.iter().collect();
    sorted.sort();
    sorted.dedup();

    // Grouped by destination so a journal's lines for one call are one write in
    // rule order, rather than an append per request whose interleaving with
    // another process's would depend on timing.
    let mut appended: BTreeMap<PathBuf, String> = BTreeMap::new();
    let mut replaced: BTreeMap<PathBuf, String> = BTreeMap::new();
    for request in sorted {
        let Some(discriminator) = discriminator(request.key, branch) else {
            continue;
        };
        let at = path(git_dir, request.kind, &request.rule, &discriminator);
        match request.kind {
            Production::Journal => appended.entry(at).or_default().push_str(&request.render()),
            Production::Baseline | Production::Marker => {
                replaced.insert(at, request.render());
            }
        }
    }

    let mut written = 0usize;
    for (at, text) in &replaced {
        write_record(at, text, false)?;
        written += 1;
    }
    for (at, text) in &appended {
        write_record(at, text, true)?;
        written += 1;
    }
    Ok(written)
}

/// One record's write, creating the store lazily.
///
/// Lazily because a run whose rules declare no sink must leave no directory
/// behind: an empty store is indistinguishable from a store nothing wrote to, and
/// creating one up front would make every run look like a producer.
fn write_record(at: &Path, text: &str, append: bool) -> Result<()> {
    if let Some(parent) = at.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if append {
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(at)?;
        file.write_all(text.as_bytes())?;
    } else {
        std::fs::write(at, text)?;
    }
    Ok(())
}
