//! End-to-end: the enforce surface journals, and the secret-identity key has
//! rotation and loss custody (CLOUD-529).
//!
//! # Why this is a separate target
//!
//! Every case here needs the same fixture and it is an expensive one: a git
//! repository, an isolated `HOME`/`XDG_DATA_HOME` so the store and the minted key
//! land somewhere the test owns, and for the secret-class half a provisioned stub
//! scanner. That is `tests/secrets_kind.rs`'s shape and `tests/advisory_drain.rs`'s
//! reason for existing beside `tests/cli.rs` rather than inside it.
//!
//! # What only an end-to-end case can pin
//!
//! The unit suites cover the decisions — the fold, the ratio, the custody
//! refusals. What they structurally cannot reach is the *wiring*: that `enforce`
//! reaches the store at all and `check` does not, that journaling cannot move an
//! exit code, that `state record` still refuses a spawning kind, and that a
//! custody event an operator has to see is actually printed. Each of those is a
//! claim about which surface does what, and a library call proves nothing about it.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use batten::provision::digest;
use common::{Fixture, StateHome, batten, git_in, scratch};

/// A repository plus the out-of-tree state it writes into.
struct Env {
    repo: PathBuf,
    home: PathBuf,
    artifacts: PathBuf,
}

impl Env {
    fn new(name: &str) -> Self {
        let root = scratch(name);
        let repo = Fixture::at(root.join("repo"))
            .file("README.md", "base\n")
            .build();
        git_in(&repo, &["init", "-q"]);
        git_in(&repo, &["add", "-A"]);
        git_in(&repo, &["commit", "-q", "-m", "base"]);
        let artifacts = root.join("artifacts");
        fs::create_dir_all(&artifacts).unwrap();
        Env {
            repo,
            home: root.join("home"),
            artifacts,
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        batten()
            .state_home(&self.home)
            .args(args)
            .current_dir(&self.repo)
            .output()
            .expect("run batten")
    }

    fn file(&self, path: &str, contents: &str) {
        let full = self.repo.join(path);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(full, contents).unwrap();
    }

    /// The state root every out-of-tree write lands under.
    fn state(&self) -> PathBuf {
        self.home.join("data").join("batten")
    }

    /// This repository's state segment, found rather than derived: the segment
    /// carries a checkout digest, and recomputing it here would be a second
    /// implementation of `state::derive_repo_name` that could drift from the one
    /// under test.
    fn segment(&self) -> PathBuf {
        let name = self
            .repo
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        fs::read_dir(self.state())
            .unwrap()
            .flatten()
            .map(|entry| entry.path())
            .find(|path| {
                path.file_name()
                    .is_some_and(|found| found.to_string_lossy().starts_with(&name))
            })
            .expect("the repository's state segment exists once something has written")
    }

    fn key_file(&self) -> PathBuf {
        self.segment().join("identity").join("secret-key")
    }

    fn ledger(&self) -> PathBuf {
        self.segment().join("identity").join("custody.jsonl")
    }

    /// Bind the store, which `state record` is the declared verb for.
    ///
    /// Called with a config carrying **no** spawning kind, because that verb
    /// refuses one — which is the whole reason the journaling had to move to the
    /// enforce surface, and is asserted directly further down.
    fn bind_store(&self) {
        self.file("batten.toml", &forbid_only());
        let recorded = self.run(&["state", "record"]);
        assert_eq!(
            recorded.status.code(),
            Some(0),
            "state record: {}",
            common::stderr(&recorded)
        );
    }

    /// Every stored record, as `state list -J` parses it.
    fn records(&self) -> Vec<serde_json::Value> {
        let listed = self.run(&["state", "list", "-J"]);
        assert_eq!(
            listed.status.code(),
            Some(0),
            "state list: {}",
            common::stderr(&listed)
        );
        serde_json::from_str(&common::stdout(&listed)).expect("state list -J is a document")
    }

    /// One record by rule id, or `None`.
    fn record(&self, rule: &str) -> Option<serde_json::Value> {
        self.records()
            .into_iter()
            .find(|record| record["rule"] == rule)
    }

    /// Settle a finding's disposition by writing the record.
    ///
    /// **No verb sets one yet**, which is why this reaches into the store rather
    /// than driving the CLI: `journal::Entry` has carried a disposition since
    /// CLOUD-78 and the surface that supplies it is still ahead. The cases below
    /// need a *settled* record because that is the state custody has to be able to
    /// keep across a rotation and to undo on a loss, and asserting on a state the
    /// fixture cannot create would be asserting its own premise.
    fn settle(&self, fingerprint: &str, disposition: &str) {
        let path = self
            .segment()
            .join("findings")
            .join(format!("{fingerprint}.json"));
        let mut record: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        record["disposition"] = serde_json::Value::String(disposition.to_owned());
        fs::write(&path, serde_json::to_string(&record).unwrap()).unwrap();
        assert_eq!(
            self.records()
                .iter()
                .find(|found| found["identity"]["fingerprint"] == fingerprint)
                .map(|found| found["disposition"].clone()),
            Some(serde_json::Value::String(disposition.to_owned())),
            "the fixture's premise: the store really does read this record back settled"
        );
    }
}

/// A config with one static rule: what the read surface can compute.
fn forbid_only() -> String {
    "version = 1\n\n\
     [[rule]]\n\
     id = \"no-todo\"\n\
     kind = \"forbid\"\n\
     glob = \"**/*.rs\"\n\
     pattern = \"TODO\"\n\
     severity = \"deny\"\n\
     no_fix_reason = \"delete the marker\"\n"
        .to_owned()
}

/// The same config plus a `command` rule — an enforce-only kind, because it runs a
/// process declared in `batten.toml`.
///
/// `no_fix_reason` rather than `fix`: `run_all` refuses a rule declaring `fix`
/// (CLOUD-215), and the store refuses a finding with no remediation at all, so this
/// is the one column a storable command rule can carry.
fn with_command(check: &str) -> String {
    format!(
        "{}\n\
         [[rule]]\n\
         id = \"gate\"\n\
         kind = \"command\"\n\
         glob = \"**/*.rs\"\n\
         check = '{check}'\n\
         severity = \"deny\"\n\
         no_fix_reason = \"fix what the gate names\"\n",
        forbid_only()
    )
}

/// A repository whose ONLY violation comes from a `policy/*.rego` module
/// (CLOUD-1220).
///
/// `no_fix_reason` is deliberately ABSENT from the row: `RuleKind::Policy`
/// requires only `severity`, and a module's remedy is per PREDICATE rather than
/// per row — one row can carry many (CLOUD-832) — so the registry is the only
/// place it can live. A fixture that put a remedy on the row would test a
/// column no real policy row carries and pass over the defect.
fn policy_only(route: &str) -> String {
    format!(
        "version = 1\n\n\
         [[rule]]\n\
         id = \"probe\"\n\
         kind = \"policy\"\n\
         scope = \"tree\"\n\
         module = \"policy/probe.rego\"\n\
         severity = \"deny\"\n\n\
         [[verdict]]\n\
         id = \"probe read refused\"\n\
         gloss = \"the probe module refused this tree\"\n\
         class = \"A fixture class, raised only by this suite's probe module.\"\n\n\
         {route}"
    )
}

/// A module that always refuses, so the case is about the FINDING rather than
/// about a predicate.
const PROBE_MODULE: &str = r#"package batten.probe

import rego.v1

rules contains "probe"

violation contains {
	"rule": "probe",
	"verdict": "probe read refused",
	"subjects": [{"path": "README.md"}],
} if {
	true
}
"#;

/// **The end-to-end arm CLOUD-1220's §7 names and I skipped**: the `unrecordable`
/// partition reports zero on this repository's own tree.
///
/// Running `enforce` here by hand is NOT this assertion, and confusing the two is
/// how the row nearly shipped unverified: the committed tree is clean, so zero
/// findings fire and "zero unrecordable" is vacuously true. This drives a tree
/// that DOES produce a policy-module finding and asserts the count is still zero,
/// which is the only form of the claim that discriminates.
#[test]
fn no_finding_is_dropped_as_unrecordable_when_a_module_reports_one() {
    let env = Env::new("enforce-journal-none-unrecordable");
    env.bind_store();
    env.file("README.md", "base\n");
    env.file("policy/probe.rego", PROBE_MODULE);
    env.file(
        "batten.toml",
        &policy_only(
            "[[verdict.route]]\n\
             id = \"probe read first\"\n\
             kind = \"document\"\n\
             target = \"README.md\"\n",
        ),
    );
    let run = env.run(&["enforce"]);
    assert_eq!(run.status.code(), Some(2), "{}", common::stderr(&run));
    assert!(
        !common::stderr(&run).contains("carry no remediation"),
        "the partition reports zero over a tree that actually produces one: {}",
        common::stderr(&run)
    );
}

/// **A module-only finding is BASELINEABLE** — CLOUD-1220's fourth acceptance
/// clause, "asserted rather than assumed", and I had assumed it.
///
/// Reaching the store is necessary and not sufficient: `baseline.rs` is the
/// persisted set of identities that already existed, and a finding the baseline
/// cannot take is still invisible to every ratchet built on one. The row lists
/// baseline first among what was blind to policy findings, so this is the arm
/// that shows the blindness actually lifted.
#[test]
fn a_module_only_finding_can_be_baselined() {
    let env = Env::new("enforce-journal-policy-baseline");
    env.bind_store();
    env.file("README.md", "base\n");
    env.file("policy/probe.rego", PROBE_MODULE);
    env.file(
        "batten.toml",
        // A TOP-LEVEL KEY, so it goes before the first table header. Appended
        // after `policy_only`'s output it landed inside `[[verdict.route]]`, an
        // unknown field there, and the config refused with exit 1 — a fixture
        // reporting a config fault while claiming to report about a baseline.
        &policy_only(
            "[[verdict.route]]\n\
             id = \"probe read first\"\n\
             kind = \"document\"\n\
             target = \"README.md\"\n",
        )
        .replace(
            "version = 1\n",
            "version = 1\nmust_land_on = \"refs/remotes/origin/main\"\n",
        ),
    );
    // COMMITTED FIRST, because `baseline` refuses uncommitted state outright —
    // "only landed, committed state may be baselined". That is a precondition of
    // the verb rather than anything about policy findings, and a fixture that
    // tripped it would report a refusal about the tree while claiming to say
    // something about the finding.
    git_in(&env.repo, &["add", "-A"]);
    git_in(&env.repo, &["commit", "-q", "-m", "the fixture"]);
    // AND THE LANDING TARGET, which `Fixture::base_commit` mints and `Env` does
    // not. `baseline` refuses a tree it cannot call landed, and it takes THREE
    // things to call it that: committed paths, the ref itself, and a declared
    // `must_land_on` — without the last, "unlanded" is not-computable rather
    // than false, which refuses just as hard. `baseline.rs`'s own fixtures
    // declare the same key for the same reason.
    //
    // All three are preconditions of the VERB and none says anything about
    // policy findings; a fixture tripping one would report about the tree while
    // claiming to report about the finding. Guessed twice before reading
    // `worktree.rs`, which is what settled it.
    git_in(
        &env.repo,
        &["update-ref", "refs/remotes/origin/main", "HEAD"],
    );
    assert_eq!(env.run(&["enforce"]).status.code(), Some(2));

    let baselined = env.run(&["baseline"]);
    assert_eq!(
        baselined.status.code(),
        Some(0),
        "the module's finding is baselineable: {}",
        common::stderr(&baselined)
    );
    // AND THE BASELINE TOOK IT. A `baseline` that exits 0 having recorded
    // nothing is the vacuous pass this arm exists to rule out.
    let after = env.run(&["enforce"]);
    assert_eq!(
        after.status.code(),
        Some(0),
        "a baselined finding no longer fails the run: {}",
        common::stderr(&after)
    );
}

// --- (a3) an answered finding is no longer undischarged (CLOUD-587) ----------

/// **Red before this row: no verb could mint a `Disposition` at all.**
///
/// CLOUD-78 gave every finding the three-valued field, `journal::merge` folds
/// it, `merge_disposition` joins two by precedence and `stop.rs` reads it —
/// undischarged means `disposition == None`. The only writers anywhere were unit
/// tests, so the field was read by a gate, joined by a merge rule, persisted by
/// a journal, and unreachable from any caller.
#[test]
fn a_stored_finding_can_be_answered_and_stops_being_undischarged() {
    let env = Env::new("state-settle-answers");
    env.bind_store();
    env.file("src/a.rs", "// TODO\n");
    env.file("batten.toml", &forbid_only());
    assert_eq!(env.run(&["enforce"]).status.code(), Some(2));

    let before = env
        .record("no-todo")
        .expect("the finding reached the store");
    assert!(
        before["disposition"].is_null(),
        "a fresh finding is undischarged: {before}"
    );
    let identity = before["identity"]["fingerprint"]
        .as_str()
        .expect("a stored finding carries its identity")
        .to_owned();

    let settled = env.run(&["state", "settle", &identity, "acted"]);
    assert_eq!(
        settled.status.code(),
        Some(0),
        "recording a disposition is bookkeeping, never a verdict: {}",
        common::stderr(&settled)
    );
    // POINTER-ONLY (rule 4): the identity and the token, never the finding's
    // content — these are drawn from a transcript.
    let said = common::stderr(&settled);
    assert!(said.contains(&identity) && said.contains("acted"), "{said}");
    assert!(
        !said.contains("TODO"),
        "the flagged content must not travel: {said}"
    );

    // The merge has to run for the shard to fold into the record, and `enforce`
    // is what runs it — the same path a real session takes.
    env.run(&["enforce"]);
    let after = env.record("no-todo").expect("still stored");
    assert_eq!(
        after["disposition"], "acted",
        "after answering it is no longer undischarged: {after}"
    );
}

/// THE DISCRIMINATOR: two worktrees answering one finding differently converge
/// to the same record whichever order the shards merge in.
///
/// A last-writer-wins implementation passes the single-answer case above and
/// silently loses one answer here. `Disposition` is declared weakest-first so the
/// derived `Ord` IS the precedence and `merge` is `max` — commutative,
/// associative and idempotent — which is what makes this decidable rather than a
/// policy each call site could get subtly wrong.
#[test]
fn two_answers_converge_the_same_way_in_either_order() {
    let mut settled = Vec::new();
    for (name, order) in [
        ("state-settle-order-weak-first", ["rejected-wrong", "acted"]),
        (
            "state-settle-order-strong-first",
            ["acted", "rejected-wrong"],
        ),
    ] {
        let env = Env::new(name);
        env.bind_store();
        env.file("src/a.rs", "// TODO\n");
        env.file("batten.toml", &forbid_only());
        env.run(&["enforce"]);
        let identity = env.record("no-todo").expect("stored")["identity"]["fingerprint"]
            .as_str()
            .expect("identity")
            .to_owned();

        for disposition in order {
            let run = env.run(&["state", "settle", &identity, disposition]);
            assert_eq!(run.status.code(), Some(0), "{}", common::stderr(&run));
        }
        env.run(&["enforce"]);
        settled.push(
            env.record("no-todo").expect("stored")["disposition"]
                .as_str()
                .expect("settled")
                .to_owned(),
        );
    }
    assert_eq!(
        settled[0], settled[1],
        "the join is commutative, so order cannot change the answer"
    );
    assert_eq!(
        settled[0], "acted",
        "and it is the STRONGER of the two, not the last one written"
    );
}

/// **`stop.rs` ACTUALLY OBSERVES IT** — CLOUD-587's other §7 clause, which I had
/// only half-covered by asserting the stored record.
///
/// The row requires that `stop.rs`'s undischarged-denial predicate and CLOUD-79's
/// drain both OBSERVE the field "without either re-typing what settled means".
/// Asserting the record's `disposition` shows the store changed; it does not show
/// the reader changed its answer. `stop::facts` is that reader — `deny-stop` is
/// at-risk work OR an undischarged denial, and undischarged is `disposition ==
/// None` — so this drives it directly and watches the pending list empty.
#[test]
fn the_stop_reader_stops_calling_an_answered_finding_pending() {
    let env = Env::new("state-settle-stop-observes");
    env.bind_store();
    env.file("src/a.rs", "// TODO\n");
    env.file("batten.toml", &forbid_only());
    assert_eq!(env.run(&["enforce"]).status.code(), Some(2));
    let identity = env.record("no-todo").expect("stored")["identity"]["fingerprint"]
        .as_str()
        .expect("identity")
        .to_owned();

    let store = env.segment();
    let before = batten::stop::facts(None, None, Some(&store)).expect("stop facts");
    assert!(
        before.pending.iter().any(|entry| entry.rule == "no-todo"),
        "the reader calls an unanswered finding pending: {:?}",
        before.pending
    );

    let settled = env.run(&["state", "settle", &identity, "acted"]);
    assert_eq!(
        settled.status.code(),
        Some(0),
        "{}",
        common::stderr(&settled)
    );
    env.run(&["enforce"]);

    let after = batten::stop::facts(None, None, Some(&store)).expect("stop facts");
    assert!(
        !after.pending.iter().any(|entry| entry.rule == "no-todo"),
        "and stops once it is answered: {:?}",
        after.pending
    );
}

/// **THE DIRECTION A CARELESS FIX BREAKS** (CLOUD-587's §7, and I skipped it).
///
/// A STATE-anchored finding clears by the condition vanishing — CLOUD-97's is the
/// example, and landing the work clears it with no acknowledgement. Settling one
/// would be a bypass of the work itself rather than an answer to a finding, so a
/// settle must not make the condition-backed finding go away.
///
/// The distinction is why CLOUD-587 exists at all: the gap is specific to the
/// EVENT-anchored class, where re-evaluation keeps finding an immutable fact. A
/// verb that cleared both would have dissolved that boundary while passing every
/// case above.
#[test]
fn settling_does_not_clear_a_finding_whose_condition_still_holds() {
    let env = Env::new("state-settle-state-anchored");
    env.bind_store();
    env.file("src/a.rs", "// TODO\n");
    env.file("batten.toml", &forbid_only());
    assert_eq!(env.run(&["enforce"]).status.code(), Some(2));
    let identity = env.record("no-todo").expect("stored")["identity"]["fingerprint"]
        .as_str()
        .expect("identity")
        .to_owned();

    let settled = env.run(&["state", "settle", &identity, "rejected-by-design"]);
    assert_eq!(
        settled.status.code(),
        Some(0),
        "{}",
        common::stderr(&settled)
    );

    // THE CONDITION STILL HOLDS, so the finding still fires. A settle records
    // what was decided; it does not edit the tree and must not read as though it
    // had.
    let after = env.run(&["enforce"]);
    assert_eq!(
        after.status.code(),
        Some(2),
        "the marker is still in the file, so the finding still fires: {}",
        common::stderr(&after)
    );

    // And the honest converse: removing the condition IS what clears it, with no
    // acknowledgement needed.
    env.file("src/a.rs", "fn main() {}\n");
    assert_eq!(
        env.run(&["enforce"]).status.code(),
        Some(0),
        "a state-anchored finding clears by the condition vanishing"
    );
}

/// Neither argument may be guessed, and an identity nothing stores is refused
/// rather than appended.
///
/// `journal::merge` deliberately KEEPS an entry whose record it cannot find, so
/// an append for an unknown identity would succeed, settle nothing, and be
/// invisible forever — a vacuous pass one surface over from where CLOUD-845
/// found it.
#[test]
fn an_unanswerable_settle_is_refused_rather_than_silently_appended() {
    let env = Env::new("state-settle-refusals");
    env.bind_store();
    env.file("src/a.rs", "// TODO\n");
    env.file("batten.toml", &forbid_only());
    env.run(&["enforce"]);
    let identity = env.record("no-todo").expect("stored")["identity"]["fingerprint"]
        .as_str()
        .expect("identity")
        .to_owned();

    let unknown = env.run(&["state", "settle", &"0".repeat(64), "acted"]);
    assert_eq!(
        unknown.status.code(),
        Some(1),
        "an identity nothing stores is a usage error, never a silent append"
    );

    let malformed = env.run(&["state", "settle", "not-a-fingerprint", "acted"]);
    assert_eq!(malformed.status.code(), Some(1));

    let guessed = env.run(&["state", "settle", &identity, "probably-fine"]);
    assert_eq!(
        guessed.status.code(),
        Some(1),
        "an undeclared token is refused rather than folded to a default"
    );
    let said = common::stderr(&guessed);
    assert!(
        said.contains("acted") && said.contains("rejected-by-design"),
        "the refusal names what IS declared: {said}"
    );

    // AND NONE OF THE THREE MOVED THE RECORD. A refusal that still appended
    // would be the defect this case is really about.
    env.run(&["enforce"]);
    assert!(
        env.record("no-todo").expect("stored")["disposition"].is_null(),
        "a refused settle leaves the finding undischarged"
    );
}

// --- (a2) a policy-module finding reaches the store, with its class's remedy ---

/// **The case CLOUD-1220 was found by, and it was red before the fix.**
///
/// Measured on `main`: `enforce` printed `2 finding(s) carry no remediation:
/// persisted:false` and both were `kind = "policy"` rows whose `[[verdict]]`
/// tokens declared routes. `policy_rule` took `rule.remediation()` — the ROW's
/// `fix`/`no_fix_reason` — and a policy row carries neither, so every module
/// finding was dropped before `findings::record` and the whole findings
/// subsystem was blind to the one rule kind CLOUD-843's campaign ports onto.
///
/// Asserting the store rather than the exit code is the whole point: `enforce`
/// exited 2 and printed the class correctly the entire time. What was lost was
/// persistence, so only a store read can see it.
#[test]
fn a_policy_module_finding_reaches_the_store_carrying_its_classs_remedy() {
    let env = Env::new("enforce-journal-policy-remedy");
    // BEFORE the config, because `bind_store` writes its own `batten.toml`
    // and would otherwise clobber this fixture's — which it did, and the case
    // then measured a tree with no policy row at all.
    env.bind_store();
    env.file("README.md", "base\n");
    env.file("policy/probe.rego", PROBE_MODULE);
    env.file(
        "batten.toml",
        &policy_only(
            "[[verdict.route]]\n\
             id = \"probe run first\"\n\
             kind = \"command\"\n\
             target = \"mise run probe-fix\"\n",
        ),
    );

    let run = env.run(&["enforce"]);
    assert_eq!(
        run.status.code(),
        Some(2),
        "the module refuses, which it always did: {}",
        common::stderr(&run)
    );
    assert!(
        !common::stderr(&run).contains("carry no remediation"),
        "no finding may be dropped as unrecordable: {}",
        common::stderr(&run)
    );

    let found = env
        .record("probe")
        .expect("the policy module's finding reached the store");
    assert_eq!(
        found["remediation"]["fix"],
        serde_json::json!(["mise", "run", "probe-fix"]),
        "a `command` route becomes the runnable fix, taken from the class rather \
         than from the row: {found}"
    );
}

/// The other route shape, and it is NOT "no remedy".
///
/// A document, issue or override route is a remedy a human performs, so it
/// records as a pointer naming the route ids and kinds rather than being dropped.
/// Without this arm, a fix that only handled `command` routes would leave every
/// class whose remedy is a read or an override exactly as broken as before —
/// which is most of this repository's own registry.
#[test]
fn a_class_whose_only_route_is_a_read_still_records_a_remedy() {
    let env = Env::new("enforce-journal-policy-read-route");
    // BEFORE the config, because `bind_store` writes its own `batten.toml`
    // and would otherwise clobber this fixture's — which it did, and the case
    // then measured a tree with no policy row at all.
    env.bind_store();
    env.file("README.md", "base\n");
    env.file("policy/probe.rego", PROBE_MODULE);
    env.file(
        "batten.toml",
        &policy_only(
            "[[verdict.route]]\n\
             id = \"probe read first\"\n\
             kind = \"document\"\n\
             target = \"README.md\"\n",
        ),
    );

    let run = env.run(&["enforce"]);
    assert_eq!(run.status.code(), Some(2), "{}", common::stderr(&run));
    let found = env
        .record("probe")
        .expect("a class with no command route still records");
    let remedy = found["remediation"]["no-fix"]
        .as_str()
        .expect("a non-command route records as `no-fix` (serde kebab-case)");
    assert!(
        remedy.contains("probe read first") && remedy.contains("document"),
        "the remedy names the route id and its kind: {remedy}"
    );
    // POINTER-ONLY (rule 4): the route's target is one hop away through
    // `policy explain`, and must not be copied into the record.
    assert!(
        !remedy.contains("README.md"),
        "a route's target is not a pointer this record carries: {remedy}"
    );
}

// --- (a) an enforce-only kind reaches the store, idempotently -----------------

#[test]
fn an_enforce_only_kinds_finding_reaches_the_store_and_is_idempotent() {
    let env = Env::new("enforce-journal-command");
    env.file("src/a.rs", "fn main() {}\n");
    env.bind_store();
    assert!(
        env.record("gate").is_none(),
        "the read surface cannot compute a command rule's finding at all"
    );

    env.file("batten.toml", &with_command("false"));
    let first = env.run(&["enforce"]);
    assert_eq!(
        first.status.code(),
        Some(2),
        "a deny finding is still a violation: {}",
        common::stderr(&first)
    );
    let gate = env
        .record("gate")
        .expect("the command rule's finding reached the store");
    let fingerprint = gate["identity"]["fingerprint"].as_str().unwrap().to_owned();
    assert_eq!(fingerprint.len(), 64, "a pointer, and the whole pointer");

    // Idempotent on identity: a second run of the same scan is the same finding
    // with the same key, never a second record.
    let second = env.run(&["enforce"]);
    assert_eq!(second.status.code(), Some(2));
    let after = env.record("gate").unwrap();
    assert_eq!(
        after["identity"]["fingerprint"].as_str().unwrap(),
        fingerprint
    );
    assert_eq!(
        env.records().iter().filter(|r| r["rule"] == "gate").count(),
        1
    );
}

// The static half of the same scan keeps the identity the read surface minted, so
// the two surfaces agree about what a finding IS rather than each keying its own.
#[test]
fn the_enforce_surface_keys_a_static_finding_exactly_as_the_read_surface_did() {
    let env = Env::new("enforce-journal-identity");
    env.file("src/a.rs", "// TODO: later\n");
    env.bind_store();
    let recorded = env.record("no-todo").expect("the read surface recorded it")["identity"].clone();

    env.file("batten.toml", &with_command("false"));
    env.run(&["enforce"]);
    assert_eq!(
        env.record("no-todo").unwrap()["identity"],
        recorded,
        "same finding, same identity, whichever surface looked"
    );
}

// --- (b) the recording verb's effect did not move ----------------------------

#[test]
fn state_record_withholds_a_spawning_kind_and_never_runs_it() {
    // The recording verb's effect still has not moved, and this now asserts that
    // DIRECTLY rather than through an exit code. `check` is a command with an
    // observable side effect, so "a recording verb may not execute configured
    // code" is proven by the absence of the marker rather than inferred from a
    // refusal — a stronger statement than the one this case made before.
    //
    // WHAT CHANGED, AND WHY THE OLD ASSERTION HAD TO GO (CLOUD-97's strand).
    // `state record` used to answer a spawning kind by refusing the WHOLE VERB,
    // before any work. The invariant that justified it — no user-supplied code
    // behind a store write — is intact and asserted below; what was never
    // justified is the collateral. The refusal returned before the store write,
    // the ref-death GC, and the transcript detectors, so one `command` or
    // `secrets` row in a config cost the repository all of them. That is why
    // CLOUD-97's `completion.unlanded` had never evaluated once in this
    // repository, which declares sixteen such rules.
    //
    // The rule is now WITHHELD instead: partitioned out before the scan sees it,
    // recorded in `Scan::not_evaluated`, and its findings HOLD in the store
    // rather than resolving. That is not the silent skip `run_static`'s refusal
    // exists to prevent — `check` still refuses, because its silence reaches a
    // human as an exit code and it has no store to hold anything in.
    let env = Env::new("enforce-journal-effect");
    env.file("src/a.rs", "fn main() {}\n");
    env.bind_store();

    let marker = env.repo.join("the-command-ran");
    env.file("batten.toml", &with_command("touch the-command-ran"));
    let recorded = env.run(&["state", "record"]);
    assert_eq!(
        recorded.status.code(),
        Some(0),
        "the verb completes rather than losing its store write to a rule it \
         never wanted to run: {}",
        common::stderr(&recorded)
    );
    assert!(
        !marker.exists(),
        "a recording verb that could execute a configured command is a much larger \
         promise than remembering what the read-only gates found"
    );
    assert!(
        env.record("gate").is_none(),
        "and it recorded nothing from the kind it withheld"
    );
    assert!(
        common::stderr(&recorded).contains("1 rule(s) not evaluated"),
        "withheld loudly, or a clean-looking record is the false green: {}",
        common::stderr(&recorded)
    );
}

// Journaling is a side record of a verdict already reached, so it cannot move the
// exit code in either direction — including the case where the store write itself
// has nowhere to go.
#[test]
fn journaling_never_moves_the_exit_code() {
    let env = Env::new("enforce-journal-exit");
    env.file("src/a.rs", "fn main() {}\n");
    // No `state record`, so there is no bound store: the enforce surface has
    // nothing to journal into and must still render the same verdict.
    env.file("batten.toml", &with_command("false"));
    let unbound = env.run(&["enforce"]);
    assert_eq!(unbound.status.code(), Some(2));
    assert!(
        !common::stderr(&unbound).contains("no bound findings store"),
        "the note is verbose-only; a default run spends nothing on it: {}",
        common::stderr(&unbound)
    );
    let told = env.run(&["-v", "enforce"]);
    assert!(
        common::stderr(&told).contains("not journalled"),
        "and it is available when asked for: {}",
        common::stderr(&told)
    );

    // A clean gate is exit 0 with the store bound, which is the other direction.
    env.bind_store();
    env.file("batten.toml", &with_command("true"));
    let clean = env.run(&["enforce"]);
    assert_eq!(clean.status.code(), Some(0), "{}", common::stderr(&clean));
}

// `check` must reach no store write at all — that is what keeps its `read` effect
// honest, and it is a property of the surface rather than of the kinds configured.
#[test]
fn the_read_surface_journals_nothing() {
    let env = Env::new("enforce-journal-check");
    env.file("src/a.rs", "// TODO: later\n");
    env.bind_store();
    let before = env.records();

    // A config with no spawning kind, so `check` runs rather than refusing.
    env.file("src/b.rs", "// TODO: also later\n");
    let checked = env.run(&["check"]);
    assert_eq!(checked.status.code(), Some(2), "it still finds them");
    assert_eq!(
        env.records(),
        before,
        "and records none of it: the second file's finding is nowhere in the store"
    );
}

// --- the secret class: journaling, then custody -------------------------------

/// The fragments the synthetic credential is assembled from, split so no
/// contiguous token exists in a committed byte — consumer #1's own `no-secrets`
/// rule globs this file.
const TOKEN_PARTS: [&str; 5] = ["AKIA", "6RJ4", "MP2T", "V8QX", "L3ZB"];

fn token() -> String {
    TOKEN_PARTS.concat()
}

/// A stub scanner reporting one match, in ripsecrets' measured output shape.
///
/// The token is reassembled inside the script so it is not a literal there
/// either: `provision` caches the artifact bytes by contract, and a literal would
/// put the token under the state root — which is exactly where a leak would land.
fn stub(path: &str, line: usize) -> String {
    let mut parts = String::new();
    for part in TOKEN_PARTS {
        parts.push('"');
        parts.push_str(part);
        parts.push('"');
    }
    format!("#!/bin/sh\nT={parts}\nprintf '%s\\n' \"{path}:{line}:$T\"\nexit 1\n")
}

/// A config carrying the provisioned stub and a `secrets` rule beside the static
/// one, so a run produces both classes of record.
fn secrets_config(url: &str, sha: &str) -> String {
    // A TOML *literal* string for the url, because it carries a filesystem
    // path: `file://D:\a\batten\...` in a basic string reads `\a` as a
    // control character and rejects `\U`, so the config fails to parse and
    // every case here dies on its own fixture rather than on its subject
    // (CLOUD-113's Windows job). Literal strings process no escapes.
    format!(
        "{}\n\
         [[provision]]\n\
         name = \"ripsecrets\"\n\
         version = \"0.0.0-stub\"\n\
         url = '{url}'\n\
         sha256 = \"{sha}\"\n\
         binary = \"ripsecrets\"\n\n\
         [[rule]]\n\
         id = \"no-secrets\"\n\
         kind = \"secrets\"\n\
         glob = \"**/*.conf\"\n\
         severity = \"deny\"\n\
         scope = \"tree\"\n\
         no_fix_reason = \"rotate the credential and remove it\"\n",
        forbid_only()
    )
}

/// A fixture whose `enforce` produces one secret-class record.
fn secret_env(name: &str) -> Env {
    let env = Env::new(name);
    env.file("src/a.rs", "fn main() {}\n");
    env.file("app.conf", "token = placeholder\n");
    env.bind_store();

    let scanner = env.artifacts.join("ripsecrets");
    fs::write(&scanner, stub("app.conf", 1)).unwrap();
    let sha = digest(&fs::read(&scanner).unwrap());
    env.file(
        "batten.toml",
        &secrets_config(&format!("file://{}", scanner.display()), &sha),
    );
    let applied = env.run(&["provision", "apply"]);
    assert!(
        applied.status.success(),
        "the stub scanner installs: {}",
        common::stderr(&applied)
    );
    let enforced = env.run(&["enforce"]);
    assert_eq!(
        enforced.status.code(),
        Some(2),
        "the planted secret is a deny finding: {}",
        common::stderr(&enforced)
    );
    env
}

// (a) for the other enforce-only kind, plus (e): the class carries no
// `FindingKind`, so nothing may classify it — and the record still has to be
// storable and emittable rather than filtered away for being unclassifiable.
#[test]
fn a_secret_class_finding_reaches_the_store_carrying_no_kind() {
    let env = secret_env("enforce-journal-secret");
    let record = env
        .record("no-secrets")
        .expect("the secrets kind's finding reached the store");
    assert_eq!(
        record["identity"]["version"].as_str().unwrap(),
        "secret:2026-08-13",
        "the version names no kind, which is what makes `kind()` answer None"
    );
    assert_eq!(
        record["identity"]["fingerprint"].as_str().unwrap().len(),
        64
    );
    // Pointer-only, in the channel a consumer actually reads back.
    let listed = common::stdout(&env.run(&["state", "list", "-J"]));
    assert!(!listed.contains(&token()), "the store holds no span");

    // And the unclassifiable record is not scope-filtered away: the drain's own
    // filter reads `kind()`, and `None` must bypass rather than default to `Code`.
    // `state list` shows it whatever the changed scope; the drain's side of this is
    // pinned in `drain.rs`'s own suite over a synthetic future version.
    assert_eq!(
        env.records()
            .iter()
            .filter(|r| r["rule"] == "no-secrets")
            .count(),
        1
    );
}

// (d) key loss: the loud orphan event, and never a silent re-mint.
#[test]
fn a_lost_key_re_opens_its_findings_loudly_and_re_mints_nothing() {
    let env = secret_env("enforce-journal-orphan");
    let before = env.record("no-secrets").unwrap();
    let fingerprint = before["identity"]["fingerprint"]
        .as_str()
        .unwrap()
        .to_owned();

    // The finding is triaged, which is the state a loss has to be able to undo:
    // the decision was reached by looking at evidence that can no longer be
    // reproduced, so keeping it would assert a triage nobody can now check.
    env.settle(&fingerprint, "rejected-by-design");

    // The generation the ledger names goes missing. This is the case the key file
    // ALONE cannot see: absent-and-re-minted is indistinguishable from a first
    // mint, which is why the predicate is ledger-against-file.
    let ledger_before = fs::read_to_string(env.ledger()).unwrap();
    assert!(ledger_before.contains("minted"), "{ledger_before}");
    fs::remove_file(env.key_file()).unwrap();

    let next = env.run(&["enforce"]);
    let told = common::stderr(&next);
    assert!(
        told.contains("re-opened for re-triage"),
        "the event is loud and unladdered: {told}"
    );
    assert!(
        told.contains("nothing has been re-minted"),
        "and says what it did not do: {told}"
    );
    assert!(!told.contains(&token()), "pointer-only: {told}");

    let ledger_after = fs::read_to_string(env.ledger()).unwrap();
    assert!(ledger_after.contains("orphaned"), "{ledger_after}");

    // Re-opened means unsettled, so an operator re-triages rather than inheriting
    // a decision about evidence that is gone.
    let reopened = env
        .records()
        .into_iter()
        .find(|record| record["identity"]["fingerprint"] == fingerprint.as_str())
        .expect("the record is still there — re-opened, not removed");
    assert!(
        reopened["disposition"].is_null(),
        "{}",
        reopened["disposition"]
    );

    // Reported ONCE. A loud event on every subsequent run is a line, not an event,
    // and it would re-open a finding the operator had just re-triaged.
    let again = env.run(&["enforce"]);
    assert!(
        !common::stderr(&again).contains("re-opened for re-triage"),
        "{}",
        common::stderr(&again)
    );
}

// (c) the store side of rotation: a join moves a record onto its new identity
// carrying everything the old one knew, and closing the window is what says the
// rotation finished.
#[test]
fn a_rotation_join_moves_the_record_and_keeps_its_disposition() {
    let env = secret_env("enforce-journal-rotate");
    let old = env.record("no-secrets").unwrap()["identity"]["fingerprint"]
        .as_str()
        .unwrap()
        .to_owned();
    env.settle(&old, "rejected-by-design");

    // A rotation window, opened the way an operator would: two generations in the
    // key file, current first. Written here rather than through a verb because
    // rotation deliberately adds no command and no effect-table row.
    let text = fs::read_to_string(env.key_file()).unwrap();
    let mut lines = text.lines();
    let old_id = lines.next().unwrap().to_owned();
    let old_hex = lines.next().unwrap().to_owned();
    let new_hex = "1".repeat(64);
    fs::write(
        env.key_file(),
        format!("2099-01-01\n{new_hex}\n{old_id}\n{old_hex}\n"),
    )
    .unwrap();

    // The scan mints under the new key and pairs it with the old one while both are
    // held, which is the only moment the pair is computable at all.
    let rotated = env.run(&["enforce"]);
    let told = common::stderr(&rotated);
    assert!(told.contains("re-keyed"), "{told}");

    let ledger = fs::read_to_string(env.ledger()).unwrap();
    assert!(ledger.contains("joined"), "{ledger}");
    assert!(
        !ledger.contains(&old_hex),
        "the ledger carries no key bytes"
    );

    let moved = env.record("no-secrets").unwrap();
    let new = moved["identity"]["fingerprint"].as_str().unwrap();
    assert_ne!(new, old, "the identity moved with the key");
    assert_eq!(
        moved["disposition"].as_str(),
        Some("rejected-by-design"),
        "and the decision travelled: a rotation that dropped it would resurrect \
         every finding a reviewer had already dismissed"
    );
    assert_eq!(
        env.records()
            .iter()
            .filter(|r| r["rule"] == "no-secrets")
            .count(),
        1,
        "one finding, not two — the pre-rotation file is dropped, and it must be, \
         because nothing can re-derive that fingerprint to clear it"
    );

    // Nothing is keyed under the retired generation any more, so the window closes
    // and the key file holds one generation again.
    assert!(told.contains("rotation complete"), "{told}");
    assert_eq!(
        fs::read_to_string(env.key_file()).unwrap().lines().count(),
        2
    );
}

/// The store's own segment is where every custody file lives, out of tree.
///
/// Asserted rather than assumed: the whole containment argument depends on the key
/// never being in the repository, and a test that only checked the state root
/// would pass with a key committed beside `batten.toml`.
#[test]
fn no_custody_file_is_ever_written_into_the_repository() {
    let env = secret_env("enforce-journal-out-of-tree");
    assert!(env.key_file().starts_with(env.state()));
    assert!(env.ledger().starts_with(env.state()));
    let tracked = git_in(&env.repo, &["status", "--porcelain"]);
    assert!(
        !tracked.contains("secret-key") && !tracked.contains("custody"),
        "{tracked}"
    );
    assert!(!in_tree(&env.repo, "secret-key"), "the key is out of tree");
}

/// Whether any path under `root` (excluding `.git`) carries `needle` in its name.
fn in_tree(root: &Path, needle: &str) -> bool {
    let Ok(entries) = fs::read_dir(root) else {
        return false;
    };
    entries.flatten().any(|entry| {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == ".git" {
            return false;
        }
        name.contains(needle) || (path.is_dir() && in_tree(&path, needle))
    })
}
