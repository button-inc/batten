//! Issued admissions: an override stops being knowledge and becomes a record
//! (CLOUD-1051).
//!
//! # The defect this replaces
//!
//! `BATTEN_PROSE_ONLY_OVERRIDE=1` and `BATTEN_FILED_HERE_OVERLAP=1` share one
//! property with every other bypass variable: **they are knowledge.** Read the
//! refusal — which prints the name — and you hold the bypass forever, for every
//! subject, in every session. Nothing is issued, nothing is scoped, nothing is
//! spent, so an override costs nothing to reach for. Measured 2026-08-25: an
//! agent hit `prose-only-check`, held the variable name the moment it read the
//! refusal, and put the override to a human over a change that needed no
//! override at all.
//!
//! # The protocol, and what its address does and does not prove
//!
//! ```text
//! admission = SHA-256("batten-admission-v1" ‖ JCS({rule, verdict, subject,
//!                                                  head, epoch, answers,
//!                                                  prev, author}))
//! ```
//!
//! **The serialization is canonical, not concatenation.** Raw `a ‖ b` is
//! ambiguous across field boundaries — two different field splits can hash alike
//! — so the address would not be well-defined at all. One canonical form is what
//! `v1` pins, and [`canonical`] is that form.
//!
//! **Authorization is the RECORD's existence and state, never possession of the
//! name.** The hash's property is BINDING, not unguessability: anyone holding the
//! answers can compute it, so the address is neither a secret nor evidence of who
//! created it. What it proves is that the record is internally consistent with
//! its own fields — editing the reasoning after the fact invalidates it.
//!
//! **The authority is the STORE; the address is integrity.** What restricts who
//! may create a record is the store's write path and nothing else. Under this row
//! that write path is a local filesystem store, so the boundary is: **anyone who
//! can write the store can mint an admission.** That is acceptable against a
//! threat model of honest error, and it is written here so a later reader does not
//! mistake the hash for a signature. If the trust boundary ever widens to a shared
//! or remote store, the scheme needs a MAC or a signature over the record — a
//! separate row, never an inference from this one.
//!
//! Because it authorizes nothing on its own, an admission is safe to print, log,
//! quote in a commit and leave in a transcript. That is what removes the "never
//! print a bearer capability" constraint a PR body would eventually violate.
//!
//! # What content addressing buys that a random token cannot
//!
//! * **The store is self-verifying.** Recomputing the address from the record's
//!   own fields must equal the address, so post-hoc tampering is detectable — and
//!   the corpus is the entire diagnostic point.
//! * **The ordinal disappears.** Re-articulation needs no counter: reusing the
//!   previous answers reproduces the previous address, which is already spent, so
//!   overriding the same situation again requires genuinely different text.
//! * **`prev` makes the per-`(rule, subject)` history tamper-evident** — no
//!   backdating and no reordering.
//! * **One value is capability, record key and audit reference**, so the token
//!   and its record cannot drift apart.
//!
//! # The gate never adjudicates the reason
//!
//! Non-negotiable rule 3. The predicate is **every declared question answered
//! non-emptily ⇒ issue**, never "is this justification good", which is exactly the
//! model verdict a gate may not contain. The forcing function is articulation, not
//! approval — the cost is thinking, not asking.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// The protocol label inside the hash. Changing the construction changes this.
///
/// **Inside** the hashed bytes rather than beside them, deliberately and unlike
/// [`crate::identity`]'s version placement: this label is what makes two
/// constructions unable to collide, so it has to be part of what is hashed. A
/// version recorded next to a digest answers "how do I read this"; this one
/// answers "what was hashed", and only the second must be inside.
pub const PROTOCOL: &str = "batten-admission-v1";

/// The in-toto predicate type an override record carries.
pub const PREDICATE_TYPE: &str = "https://button.is/batten/override/v1";

/// The state a record is in. Two values, and there is no third.
///
/// A crash before the compare-and-set leaves the record [`State::Issued`] and
/// still consumable; a crash after leaves it [`State::Spent`]. There is no
/// intermediate state because the state lives in one record replaced by one
/// atomic rename.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    /// Written and not yet spent.
    Issued,
    /// Consumed. A second consume is a policy refusal, never an error.
    Spent,
}

/// Everything the address binds, and nothing else.
///
/// Field order here is the struct's; the ADDRESS does not depend on it, because
/// [`canonical`] sorts. That independence is the point — a field reordered during
/// a refactor must not change an address already issued.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    /// The rule whose refusal is being overridden.
    pub rule: String,
    /// The declared class (CLOUD-1050) that refusal belongs to. Present in the
    /// binding so an admission minted against one class cannot be presented
    /// against another refusal of the same rule.
    pub verdict: String,
    /// The gate's canonical subject. Each gate owns its own spelling; see
    /// [`crate::admission`]'s consumers.
    pub subject: String,
    /// The HEAD the override was articulated against.
    pub head: String,
    /// The config generation. An admission does not survive the policy change
    /// that would have made it unnecessary.
    pub epoch: String,
    /// The declared questions and the answers given, keyed by question id.
    pub answers: BTreeMap<String, String>,
    /// The previous admission for this `(rule, subject)`, or `None` at the head
    /// of a chain.
    pub prev: Option<String>,
    /// Who articulated it — the git identity, never a model identity
    /// (`.claude/rules/commits.md`).
    pub author: String,
}

/// One override record, as the store holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// The in-toto statement type, shared with [`crate::receipt`].
    #[serde(rename = "_type")]
    pub statement_type: String,
    /// The predicate type, always [`PREDICATE_TYPE`].
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    /// The content address: the record's key, its capability and its audit
    /// reference, which is what keeps the token and its record from drifting.
    pub admission: String,
    /// What the address binds.
    pub binding: Binding,
    /// Issued or spent.
    pub state: State,
}

impl Record {
    /// Build an issued record for `binding`.
    #[must_use]
    pub fn issue(binding: Binding) -> Record {
        Record {
            statement_type: crate::receipt::STATEMENT_TYPE.to_owned(),
            predicate_type: PREDICATE_TYPE.to_owned(),
            admission: address(&binding),
            binding,
            state: State::Issued,
        }
    }

    /// Whether the record still recomputes to its own address.
    ///
    /// This is the self-verification clause: answers edited after issuance no
    /// longer hash to the key they are filed under, so the tamper is a property
    /// of the pair rather than something a reviewer has to notice.
    #[must_use]
    pub fn recomputes(&self) -> bool {
        address(&self.binding) == self.admission
    }
}

/// Why a presented admission was refused.
///
/// Every variant is a **pointer-shaped** answer: which clause failed, never the
/// reasoning, which lives in the record and is the author's own words rather than
/// repository content (rule 4's deliberate inversion, stated on the row).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// No record at that address.
    Unknown,
    /// The record does not hash to its own key: edited after issuance.
    Tampered,
    /// Already consumed.
    Spent,
    /// Bound to a different `(rule, verdict, subject, head, epoch)`.
    Unbound,
    /// The `prev` chain does not terminate — it cycles, or a link is missing.
    ChainBroken,
}

impl Refused {
    /// The stable lowercase token (§6).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Refused::Unknown => "unknown",
            Refused::Tampered => "tampered",
            Refused::Spent => "spent",
            Refused::Unbound => "unbound",
            Refused::ChainBroken => "chain-broken",
        }
    }
}

/// The content address of a binding.
///
/// SHA-256 over [`PROTOCOL`] followed by the canonical serialization. Lowercase
/// hex, so the value is a filename on every platform and is safe to quote
/// anywhere.
#[must_use]
pub fn address(binding: &Binding) -> String {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(PROTOCOL.as_bytes());
    hasher.update(canonical(binding).as_bytes());
    // Hex by hand rather than `{:x}`: the pinned `sha2` returns a `GenericArray`,
    // which does not implement `LowerHex`. Same fold `contract::snapshot_path`
    // uses, and one buffer rather than a `format!` per byte.
    hasher
        .finalize()
        .iter()
        .fold(String::with_capacity(64), |mut hex, byte| {
            use std::fmt::Write as _;
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

/// The canonical serialization of a binding — RFC 8785 (JCS), over the subset
/// this object can contain.
///
/// # The subset is a bound, stated rather than left for a reader to discover
///
/// A [`Binding`] holds strings, string maps, and one nullable string. It holds no
/// numbers and no booleans, which matters because **number formatting is the hard
/// half of JCS** — the ECMAScript `Number::toString` shortest-round-trip rule —
/// and implementing it for fields that cannot occur would be code no test could
/// discriminate. So this canonicalizes the subset and refuses to pretend
/// otherwise; a future field carrying a number needs the number rule written and
/// tested, and `a_binding_carries_no_numeric_field` is what makes that a compile
/// failure rather than a silent wrong address.
///
/// What it does implement is the whole of the rest: object keys sorted by their
/// UTF-16 code units, no insignificant whitespace, and the JSON string escaping
/// JCS pins — the two-character forms where they exist, `\u00XX` for the rest of
/// the control range, and the literal character everywhere else.
#[must_use]
pub fn canonical(binding: &Binding) -> String {
    let mut out = String::from("{");
    // Sorted by key, spelled out rather than derived from the struct's field
    // order: the address must not move when a field is reordered.
    out.push_str(&member("answers", &object(&binding.answers)));
    out.push(',');
    out.push_str(&member("author", &string(&binding.author)));
    out.push(',');
    out.push_str(&member("epoch", &string(&binding.epoch)));
    out.push(',');
    out.push_str(&member("head", &string(&binding.head)));
    out.push(',');
    out.push_str(&member(
        "prev",
        &binding.prev.as_deref().map_or_else(
            // JSON `null`, never the empty string: a chain head and a chain link
            // whose predecessor is named `""` are different facts, and spelling
            // them alike would let one be presented as the other.
            || "null".to_owned(),
            string,
        ),
    ));
    out.push(',');
    out.push_str(&member("rule", &string(&binding.rule)));
    out.push(',');
    out.push_str(&member("subject", &string(&binding.subject)));
    out.push(',');
    out.push_str(&member("verdict", &string(&binding.verdict)));
    out.push('}');
    out
}

/// One canonical object member: `"key":value`.
fn member(key: &str, value: &str) -> String {
    format!("{}:{value}", string(key))
}

/// A canonical object over a sorted string map.
///
/// [`BTreeMap`] already orders by `Ord` on `String`, which is byte order over
/// UTF-8. That agrees with JCS's UTF-16 code-unit order for every code point
/// below U+10000 and disagrees above it (a supplementary character sorts before
/// U+E000..U+FFFF in UTF-16 and after in UTF-8). Question ids are the keys here
/// and they come from `[[verdict]]`'s `override.precondition`, which
/// `verdict::validate` holds to ASCII — so the disagreement is unreachable, and
/// `question_ids_are_ascii` is the assertion that keeps it so.
fn object(map: &BTreeMap<String, String>) -> String {
    let members: Vec<String> = map
        .iter()
        .map(|(key, value)| member(key, &string(value)))
        .collect();
    format!("{{{}}}", members.join(","))
}

/// A canonical JSON string, escaped as JCS pins it.
fn string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // The rest of the C0 range has no two-character form, so it takes
            // the lowercase four-digit escape. Everything else — including every
            // non-ASCII character — is emitted literally, which is what makes the
            // output the shortest valid encoding JCS asks for.
            c if (c as u32) < 0x20 => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The directory the override store lives in.
///
/// The canonical out-of-tree receipt store, beside [`crate::receipt`]'s own
/// records. `$GIT_DIR/batten-receipts/` is never an authority here — it is the
/// grandfathered compatibility path the retired shell adapters wrote to, and this
/// module does not read it.
///
/// # Errors
///
/// Returns an error when the state root cannot be resolved.
pub fn store_dir(repo_root: &Path) -> Result<PathBuf> {
    // CANONICALIZE FIRST, for the reason `secrets::resolve_scanner` records: the
    // anchor is a RELATIVE path (`.`) whenever the config sits in the cwd, and
    // the state directory is keyed by the repository's own directory name, which
    // `state::derive_repo_name` cannot read off `.`. Measured as a hard failure
    // — "cannot derive a repository name from ." — the first time
    // `override request` ran, because that verb anchors at `.` like every other.
    let anchored = repo_root
        .canonicalize()
        .with_context(|| format!("resolve the repository root at {}", repo_root.display()))?;
    Ok(crate::state::repo_state_dir(&anchored)?
        .join("receipts")
        .join("overrides"))
}

/// Where one admission's record lives.
///
/// # Errors
///
/// Returns an error when the store directory cannot be resolved.
pub fn record_path(repo_root: &Path, admission: &str) -> Result<PathBuf> {
    Ok(store_dir(repo_root)?.join(format!("{admission}.json")))
}

/// The lock file guarding the store's state transitions.
fn lock_path(dir: &Path) -> PathBuf {
    dir.join(".lock")
}

/// Take the store's advisory lock for the duration of the returned handle.
///
/// **`fs4`, for the reason `.claude/rules/rust.md` records for the capture lock
/// and no other**: an OS advisory lock is released by the kernel when its holder
/// dies, so a process `SIGKILL`ed mid-write leaves the next reader a defined
/// prefix rather than a lock nobody can release. No in-process primitive offers
/// that, and the argument never depended on the dependency count.
///
/// # Errors
///
/// Returns an error when the store cannot be created or the lock cannot be taken.
fn lock(dir: &Path) -> Result<std::fs::File> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("create the override store at {}", dir.display()))?;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(lock_path(dir))
        .with_context(|| format!("open the override store lock in {}", dir.display()))?;
    // BLOCKING, not `try_lock`, and that is the difference from
    // [`crate::capture`]'s use of the same primitive. A capture that cannot take
    // the lock drops the write and says so, because a missed capture is a missing
    // record; a consume that cannot take the lock must WAIT, because the whole
    // claim is that exactly one concurrent consumer wins — and a `WouldBlock`
    // treated as a refusal would make the loser's verdict depend on scheduling.
    fs4::FileExt::lock(&file)
        .with_context(|| format!("lock the override store in {}", dir.display()))?;
    Ok(file)
}

/// Read one record, or `None` when there is none at that address or it will not
/// parse.
///
/// Fail-closed on an unreadable record, the same posture [`crate::receipt`] takes:
/// a record that cannot be read is never an authorization.
#[must_use]
pub fn load(repo_root: &Path, admission: &str) -> Option<Record> {
    let path = record_path(repo_root, admission).ok()?;
    let bytes = std::fs::read(path).ok()?;
    let record: Record = serde_json::from_slice(&bytes).ok()?;
    (record.predicate_type == PREDICATE_TYPE).then_some(record)
}

/// Write `record` to the store, atomically.
///
/// One temp file and one rename, so a reader never sees a partial record. The
/// caller holds the lock.
fn store(repo_root: &Path, record: &Record) -> Result<()> {
    let path = record_path(repo_root, &record.admission)?;
    let dir = path
        .parent()
        .context("the override record path has a parent")?;
    std::fs::create_dir_all(dir)
        .with_context(|| format!("create the override store at {}", dir.display()))?;
    let temp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(record).context("serialize the override record")?;
    {
        let mut file =
            std::fs::File::create(&temp).with_context(|| format!("write {}", temp.display()))?;
        file.write_all(&bytes)
            .with_context(|| format!("write {}", temp.display()))?;
        file.sync_all()
            .with_context(|| format!("flush {}", temp.display()))?;
    }
    std::fs::rename(&temp, &path).with_context(|| format!("install {}", path.display()))?;
    Ok(())
}

/// Issue an admission for `binding`, returning its address.
///
/// **Idempotent on the binding.** The same articulation yields the same address,
/// so a repeated request is one record rather than one per attempt — and an
/// address already spent stays spent, which is what makes re-articulation forced
/// by construction rather than by a counter.
///
/// # Errors
///
/// Returns an error when the store cannot be locked or written.
pub fn issue(repo_root: &Path, binding: Binding) -> Result<String> {
    let dir = store_dir(repo_root)?;
    let _guard = lock(&dir)?;
    let record = Record::issue(binding);
    if load(repo_root, &record.admission).is_some() {
        // Already articulated in exactly these words. Do not rewrite it — that
        // would reset a spent record to issued, which is the replay this scheme
        // exists to make impossible.
        return Ok(record.admission);
    }
    let admission = record.admission.clone();
    store(repo_root, &record)?;
    Ok(admission)
}

/// Consume `admission` against the situation `expected` describes.
///
/// The whole transition happens under one lock: read, check, write. Exactly one
/// concurrent consumer wins the compare-and-set; every other reads
/// [`Refused::Spent`] and is a policy refusal, never an internal error.
///
/// `expected` carries only the five binding fields — the answers, `prev` and
/// `author` are the record's, and a caller that had to reproduce them would be
/// recomputing the address rather than presenting it.
///
/// # Errors
///
/// Returns an error only for a store failure — an unlockable directory, an
/// unwritable record. A refusal is `Ok(Err(..))`-shaped through [`Refused`]
/// because a rejected capability is a verdict about the request, not a fault.
pub fn consume(
    repo_root: &Path,
    admission: &str,
    expected: &Situation<'_>,
) -> Result<Result<Record, Refused>> {
    let dir = store_dir(repo_root)?;
    let _guard = lock(&dir)?;
    let Some(record) = load(repo_root, admission) else {
        return Ok(Err(Refused::Unknown));
    };
    if !record.recomputes() {
        return Ok(Err(Refused::Tampered));
    }
    if !expected.matches(&record.binding) {
        return Ok(Err(Refused::Unbound));
    }
    if record.state == State::Spent {
        return Ok(Err(Refused::Spent));
    }
    if !chain_terminates(repo_root, &record) {
        return Ok(Err(Refused::ChainBroken));
    }
    let spent = Record {
        state: State::Spent,
        ..record.clone()
    };
    store(repo_root, &spent)?;
    Ok(Ok(spent))
}

/// The five fields a caller can know without holding the record.
#[derive(Debug, Clone, Copy)]
pub struct Situation<'a> {
    /// The rule refusing.
    pub rule: &'a str,
    /// The class it refused under.
    pub verdict: &'a str,
    /// The gate's canonical subject.
    pub subject: &'a str,
    /// The HEAD being judged.
    pub head: &'a str,
    /// The config generation.
    pub epoch: &'a str,
}

impl Situation<'_> {
    /// Whether a binding is for this situation.
    ///
    /// All five, never a subset: dropping any one of them is what would let an
    /// admission be harvested onto a different subject, a different HEAD, or a
    /// policy generation that has since changed.
    #[must_use]
    pub fn matches(&self, binding: &Binding) -> bool {
        binding.rule == self.rule
            && binding.verdict == self.verdict
            && binding.subject == self.subject
            && binding.head == self.head
            && binding.epoch == self.epoch
    }
}

/// Whether `record`'s `prev` chain resolves, terminates, and does not cycle.
///
/// The same predicate [`crate::verdict`]'s tombstone successors need, and one
/// implementation serves both shapes: walk, refuse a revisit, refuse a link that
/// does not resolve. A missing link is refused rather than treated as a terminus,
/// because a chain that ends by pointing at nothing is indistinguishable from one
/// somebody deleted the middle of — which is the tamper-evidence `prev` is here to
/// provide.
fn chain_terminates(repo_root: &Path, record: &Record) -> bool {
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    seen.insert(record.admission.clone());
    let mut cursor = record.binding.prev.clone();
    while let Some(link) = cursor.clone() {
        if !seen.insert(link.clone()) {
            return false;
        }
        let Some(previous) = load(repo_root, &link) else {
            return false;
        };
        cursor.clone_from(&previous.binding.prev);
    }
    true
}

/// The head of the `(rule, subject)` chain, for a caller about to articulate a
/// new admission.
///
/// Scanning the store rather than holding a head pointer file: the store is
/// small, and a pointer file is a second authority that can disagree with the
/// records it points at. The head is the record nothing else names as `prev`.
///
/// # Errors
///
/// Returns an error when the store cannot be read.
pub fn chain_head(repo_root: &Path, rule: &str, subject: &str) -> Result<Option<String>> {
    let dir = store_dir(repo_root)?;
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Ok(None);
    };
    let mut records: Vec<Record> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|ext| ext != "json") {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(record) = serde_json::from_slice::<Record>(&bytes) else {
            continue;
        };
        if record.binding.rule == rule && record.binding.subject == subject {
            records.push(record);
        }
    }
    let claimed: std::collections::BTreeSet<String> = records
        .iter()
        .filter_map(|record| record.binding.prev.clone())
        .collect();
    Ok(records
        .into_iter()
        .map(|record| record.admission)
        .find(|admission| !claimed.contains(admission)))
}

/// The SPENT admission covering one finding, if the store holds it (CLOUD-1120).
///
/// # Why this exists at all
///
/// Issuing and spending an admission changed nothing: `admission::` was reached
/// only by the two `override` verbs, so a record could be minted, bound and
/// consumed while the gate that refused went on refusing. Measured — a `spent`
/// record whose rule, class, subject and HEAD all equalled the refusal's, and
/// four routes on `V-FILED-OVER-OWN-DIFF` of which none was reachable. A remedy
/// nothing consults is the defect CLOUD-1050 made unspellable one level up.
///
/// # Why the store is scanned rather than the address computed
///
/// [`address`] binds `answers`, `prev` and `author` as well, and a finding knows
/// none of them — that asymmetry is deliberate, since a caller able to compute an
/// address from the refusal alone could mint one without articulating anything.
/// So the join runs the other way: read the records, compare the five terms the
/// refusal DOES name. [`chain_head`] scans for the same reason and this mirrors
/// it rather than growing a second traversal.
///
/// # Only `Spent` admits
///
/// [`State::Issued`] does not, and that is the whole economy: articulating costs
/// thinking, and spending is the act that consumes the articulation. A mint that
/// suppressed on its own would restore the bypass-variable it replaced — hold the
/// name, pay nothing, override forever.
///
/// Returns the admission's address so the caller can report WHICH record admitted
/// the finding. A suppression nobody can trace back to its reasoning is the
/// silent bypass again, wearing a record's clothes.
///
/// # Errors
///
/// Returns an error when the store directory cannot be resolved. An unreadable
/// store, an unparseable record and an absent directory are all "no admission" —
/// a store this cannot read must not be able to ADMIT anything, which is the
/// fail-closed direction for a suppression.
pub fn admitted(
    repo_root: &Path,
    rule: &str,
    verdict: &str,
    subject: &str,
    head: &str,
    epoch: &str,
) -> Result<Option<String>> {
    let dir = store_dir(repo_root)?;
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Ok(None);
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|ext| ext != "json") {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(record) = serde_json::from_slice::<Record>(&bytes) else {
            continue;
        };
        if record.state != State::Spent {
            continue;
        }
        let binding = &record.binding;
        // ALL FIVE, and each one is a different way the admission could be the
        // wrong one: another gate, another class of the same gate, another file,
        // a tree that has moved, or a policy that has changed underneath it.
        if binding.rule == rule
            && binding.verdict == verdict
            && binding.subject == subject
            && binding.head == head
            && binding.epoch == epoch
        {
            return Ok(Some(record.admission));
        }
    }
    Ok(None)
}

/// One question the requester must answer.
///
/// **Falsifiable to the writer, or a fluent agent performs the ritual and
/// proceeds.** These three are the ones that would have stopped the measured
/// instance, and each is answerable only by engaging with something specific:
/// the class's own declared precondition, the cost of not overriding, and the
/// routes the class already offered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// The answer key. Stable, ASCII, and part of what the address binds.
    pub id: &'static str,
    /// What to answer, rendered against the class.
    pub prompt: String,
}

/// The question that quotes the class's own declared precondition.
const PRECONDITION: &str = "precondition";
/// The question that prices not overriding.
const LOST: &str = "lost";
/// The question that re-presents the declined routes.
const REJECTED_ROUTE: &str = "rejected-route";

/// The questions a class's override route generates, or `None` when the class
/// declares no override route at all.
///
/// **A class declaring no override route simply cannot be overridden, and that is
/// the right default.** `verdict::validate` already refuses a class whose ONLY
/// route is an override, so the two directions compose: a class either offers a
/// real way out and may additionally be overridden, or it offers a real way out
/// and may not.
///
/// The third question is where re-presenting the declined routes happens — the
/// last cheap moment, and the one that catches the reader who never received
/// route 1. That is not decoration: CLOUD-1050's defect B was measured as exactly
/// this, an agent reaching for the override because the correct route was a
/// clause the caller's paraphrase had dropped.
#[must_use]
pub fn questions_for(entry: &crate::verdict::DeclaredVerdict) -> Option<Vec<Question>> {
    let precondition = entry.routes.iter().find_map(|route| {
        (route.kind == crate::verdict::RouteKind::Override)
            .then_some(route.precondition.as_deref())
            .flatten()
    })?;
    let declined: Vec<&str> = entry
        .routes
        .iter()
        .filter(|route| route.kind != crate::verdict::RouteKind::Override)
        .map(|route| route.id.as_str())
        .collect();
    Some(vec![
        Question {
            id: PRECONDITION,
            prompt: format!(
                "{} declares: \"{precondition}\". State that precondition and the fact \
                 satisfying it here.",
                entry.id
            ),
        },
        Question {
            id: LOST,
            prompt: "Name what is lost if you do not override.".to_owned(),
        },
        Question {
            id: REJECTED_ROUTE,
            prompt: format!(
                "This class declares {}. Name the one you rejected and why it does not \
                 apply.",
                declined.join(" ")
            ),
        },
    ])
}

/// Which declared questions `answers` leaves unanswered.
///
/// **The gate never adjudicates the reason** (non-negotiable rule 3): the
/// predicate is presence and well-formedness, never quality. An answer is
/// well-formed when it is not blank — anything stronger is a model verdict, and a
/// gate containing one would be worse than today's password.
#[must_use]
pub fn unanswered<'a>(
    questions: &'a [Question],
    answers: &BTreeMap<String, String>,
) -> Vec<&'a str> {
    questions
        .iter()
        .filter(|question| {
            answers
                .get(question.id)
                .is_none_or(|answer| answer.trim().is_empty())
        })
        .map(|question| question.id)
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn binding() -> Binding {
        Binding {
            rule: "prose-only".to_owned(),
            verdict: "V-PROSE-ONLY-DIFF".to_owned(),
            subject: "a.rs,b.rs".to_owned(),
            head: "0123456789abcdef".to_owned(),
            epoch: "epoch-1".to_owned(),
            answers: BTreeMap::from([
                (
                    "precondition".to_owned(),
                    "the prose is the deliverable".to_owned(),
                ),
                (
                    "lost".to_owned(),
                    "the release notes miss the window".to_owned(),
                ),
            ]),
            prev: None,
            author: "alec@button.is".to_owned(),
        }
    }

    #[test]
    fn the_address_does_not_depend_on_map_insertion_order() {
        // The property that makes the address well-defined at all. Two maps built
        // in opposite orders are the same object, and a concatenation-based
        // scheme would hash them differently.
        let mut reversed = binding();
        reversed.answers = BTreeMap::new();
        reversed.answers.insert(
            "lost".to_owned(),
            "the release notes miss the window".to_owned(),
        );
        reversed.answers.insert(
            "precondition".to_owned(),
            "the prose is the deliverable".to_owned(),
        );
        assert_eq!(address(&binding()), address(&reversed));
    }

    #[test]
    fn a_field_boundary_cannot_be_moved_without_moving_the_address() {
        // THE DEFECT CANONICALIZATION EXISTS TO KILL. Under `a ‖ b` these two
        // bindings hash identically — `"ab" ‖ ""` and `"a" ‖ "b"` are the same
        // byte string — so an admission for one subject would authorize the
        // other. Under JCS the delimiters are in the encoding.
        let mut left = binding();
        left.rule = "ab".to_owned();
        left.verdict = String::new();
        let mut right = binding();
        right.rule = "a".to_owned();
        right.verdict = "b".to_owned();
        assert_ne!(address(&left), address(&right));
    }

    #[test]
    fn a_chain_head_and_a_link_named_empty_are_different_addresses() {
        // `prev: None` serializes as `null` rather than as `""`, so the head of a
        // chain cannot be presented as a link and vice versa.
        let mut named = binding();
        named.prev = Some(String::new());
        assert_ne!(address(&binding()), address(&named));
    }

    #[test]
    fn editing_an_answer_breaks_the_recomputation() {
        // The self-verification clause, which is what makes the corpus evidence
        // rather than a log somebody could rewrite.
        let mut record = Record::issue(binding());
        record
            .binding
            .answers
            .insert("lost".to_owned(), "actually nothing".to_owned());
        assert!(!record.recomputes());
    }

    #[test]
    fn the_canonical_form_escapes_the_control_range_and_nothing_else() {
        // JCS asks for the shortest valid encoding: two-character forms where
        // they exist, `\u00XX` for the rest of C0, and the literal character
        // everywhere else — including every non-ASCII one, which a naive
        // `\u`-everything escaper would expand and hash differently.
        assert_eq!(
            string("a\"b\\c\nd\u{1}e\u{e9}f"),
            "\"a\\\"b\\\\c\\nd\\u0001e\u{e9}f\""
        );
    }

    #[test]
    fn a_binding_carries_no_numeric_field() {
        // The bound this module's canonicalizer states, held as an assertion
        // rather than as a sentence. JCS's number rule is not implemented, so a
        // field that could carry one must fail here rather than produce a silent
        // wrong address. `serde_json` is the reader because it is the shape any
        // future field would arrive through.
        let value = serde_json::to_value(binding()).unwrap();
        let object = value.as_object().expect("a binding is an object");
        for (key, field) in object {
            assert!(
                !field.is_number() && !field.is_boolean(),
                "`{key}` is neither a string, a string map nor null — write the JCS number rule first"
            );
        }
    }

    #[test]
    fn question_ids_are_ascii() {
        // What keeps `BTreeMap`'s UTF-8 byte order equal to JCS's UTF-16
        // code-unit order. The two disagree only above U+FFFF, and the ids come
        // from `[[verdict]]`'s declared preconditions.
        for id in binding().answers.keys() {
            assert!(id.is_ascii(), "{id} is not an ascii question id");
        }
    }
}
