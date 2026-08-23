//! A policy module can decide over the checkout's git state (CLOUD-907).
//!
//! # What the census changed about this row
//!
//! `bench/gates/RESULTS.md` re-derived the corpus by command-position invocation
//! and the answer is smaller than the bucket: of the 52 git-bucket
//! gate-described tasks, 30 read git only to locate the repository or list
//! tracked files, both of which the engine already resolves. Twenty-two need a
//! variant that did not exist, and they divide 15 head, 11 log, 4 remote, 2
//! status, 1 ancestry.
//!
//! So this suite exercises five facts and NOT a sixth. The one ancestry task is
//! `linear-check`'s `merge-base origin/main HEAD`, and answering it is refused
//! rather than implemented: CLOUD-36 decides merged-ness by patch identity
//! because a rebased landing is invisible to reachability, and
//! `no_ancestry_decides_merged_ness` refused the first draft of `git::ref_facts`
//! for carrying exactly that answer. `git::landing` is where the landing
//! question already lives.
//!
//! # What each case is for
//!
//! * **Both ways per variant.** A fact that only ever decides one way is a
//!   constant with a longer name; each variant here has a fixture that holds
//!   and one that does not.
//! * **Could-not-look asserted DISTINCT from empty**, which is the property this
//!   whole row is named for. Rego reads an undefined path as "does not hold", so
//!   a detached HEAD reported as `branch: ""`, an unresolvable ref reported as a
//!   present-and-false entry, or a range reported as `[]` each ship a gate that
//!   is silently off — CLOUD-845's measured class and CLOUD-251's before it.
//! * **Nothing is acquired that no rule declared.** The negative here is a
//!   perf property with a measured precedent: CLOUD-851 took `check` from a p50
//!   of 4.76ms to 10.01ms by locating the git dir and reading HEAD for a
//!   question no rule had asked.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};

use common::{Fixture, git_in, run, stdout};

/// A tree-scoped `policy` row declaring `declares`.
///
/// The module is the assertion: it raises a finding when the predicate it
/// carries HOLDS, so a case reads its verdict off whether the rule id appears
/// in stdout.
fn config(declares: &str) -> String {
    format!(
        "version = 1\n\
         \n\
         [[rule]]\n\
         id = \"git-probe\"\n\
         kind = \"policy\"\n\
         scope = \"tree\"\n\
         module = \"policy/probe.rego\"\n\
         severity = \"warn\"\n\
         no_fix_reason = \"this row exists to report what the engine emitted\"\n\
         {declares}"
    )
}

/// The Rego module, wrapping `body` as the violation condition.
fn module(body: &str) -> String {
    format!(
        "package batten\n\
         \n\
         rules contains \"git-probe\"\n\
         \n\
         violation contains {{\n\
         \t\"rule\": \"git-probe\",\n\
         \t\"msg\": \"the predicate held\",\n\
         }} if {{\n\
         {body}\n\
         }}\n"
    )
}

/// A fixture whose one rule declares `declares` and whose module asserts `body`.
fn repo(name: &str, declares: &str, body: &str) -> PathBuf {
    Fixture::new(name)
        .config(&config(declares))
        .file("policy/probe.rego", &module(body))
        .file("src/lib.rs", "fn main() {}\n")
        .git()
        .base_commit()
        .build()
}

/// Whether the probe rule fired, with the run asserted to have decided at all.
///
/// THE EXIT STATUS FIRST, and that order is the point: the absence of a rule id
/// in stdout is evidence only if the run reached policy evaluation. A run that
/// died at config load prints nothing and would satisfy every negative case
/// here for the wrong reason.
fn fired(dir: &Path) -> bool {
    let output = run(dir, &["check"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a warn-severity row: the run has to decide for its verdict to mean \
         anything: {}",
        stdout(&output)
    );
    stdout(&output).contains("git-probe")
}

#[test]
fn head_decides_both_ways_over_the_branch_it_names() {
    // The positive: the fixture is on `main`, and the module says so.
    let on_main = repo(
        "git-head-positive",
        "git = [\"head\"]\n",
        "\tinput.tree[\"git-head\"].branch == \"main\"",
    );
    assert!(fired(&on_main), "HEAD is on `main` and the module read it");

    // The negative is CONSTRUCTED rather than assumed (`.claude/rules/rust.md`):
    // the same module over a checkout that is genuinely on another branch, so
    // the case distinguishes "the predicate is false" from "the fact never
    // arrived". Both halves in one suite is what stops a fact that is always
    // null from passing the positive's inverse.
    let elsewhere = repo(
        "git-head-negative",
        "git = [\"head\"]\n",
        "\tinput.tree[\"git-head\"].branch == \"main\"",
    );
    git_in(&elsewhere, &["checkout", "-q", "-b", "some-other-branch"]);
    assert!(
        !fired(&elsewhere),
        "the checkout is not on `main`, so the predicate must not hold"
    );
}

#[test]
fn a_detached_head_has_no_branch_and_says_so_rather_than_reporting_an_empty_one() {
    // THE COULD-NOT-LOOK CASE THE ROW IS NAMED FOR. A detached HEAD is on no
    // branch; reporting `branch: ""` would let `input.tree["git-head"].branch ==
    // ""` and `branch == null` both be writable and mean different things, and
    // a gate asking "is this a protected branch" would answer about a branch
    // that does not exist.
    let dir = repo(
        "git-head-detached",
        "git = [\"head\"]\n",
        "\tinput.tree[\"git-head\"].branch == null",
    );
    assert!(!fired(&dir), "on a branch, `branch` is a name and not null");

    git_in(&dir, &["checkout", "-q", "--detach"]);
    assert!(
        fired(&dir),
        "detached: `branch` must be null, not the empty string and not the \
         literal `HEAD` git prints"
    );

    // AND DETACHEDNESS IS ITS OWN FIELD, not inferred from the null. An empty
    // repository also has no branch, and a gate asking "is this a detached
    // checkout" must not answer yes to it.
    let detachedness = repo(
        "git-head-detached-flag",
        "git = [\"head\"]\n",
        "\tinput.tree[\"git-head\"].detached",
    );
    assert!(!fired(&detachedness), "attached");
    git_in(&detachedness, &["checkout", "-q", "--detach"]);
    assert!(fired(&detachedness), "detached");
}

#[test]
fn status_decides_both_ways_and_a_clean_tree_is_an_answer() {
    let dir = repo(
        "git-status",
        "git = [\"status\"]\n",
        "\tcount(input.tree[\"git-status\"].changed) > 0",
    );
    // Clean is an ANSWER, not an absence: the fixture committed everything, so
    // `changed` is an empty list and the predicate is false — which is a
    // different reading from the fact never arriving, and the case below is
    // what makes the pair discriminating.
    assert!(!fired(&dir), "a committed tree has nothing changed");

    std::fs::write(dir.join("src/lib.rs"), "fn main() { /* edited */ }\n").unwrap();
    assert!(fired(&dir), "an edited file is a changed path");
}

#[test]
fn a_remote_that_does_not_exist_is_null_rather_than_an_empty_upstream() {
    let dir = repo(
        "git-remote",
        "git = [\"remote\"]\n",
        "\tinput.tree[\"git-remote\"].upstream == null",
    );
    // The fixture has no remote at all, so HEAD has no upstream. Null, and the
    // module can say so — where an empty string would be a value a predicate
    // could compare against and get a confident wrong answer.
    assert!(fired(&dir), "no upstream: null");

    let named = repo(
        "git-remote-named",
        "git = [\"remote\"]\n",
        "\tinput.tree[\"git-remote\"].remotes.origin == \"https://example.invalid/r.git\"",
    );
    assert!(!fired(&named), "no remote is configured yet");
    git_in(
        &named,
        &["remote", "add", "origin", "https://example.invalid/r.git"],
    );
    assert!(
        fired(&named),
        "the URL is read from .git/config, never over the network"
    );
}

#[test]
fn an_unresolvable_ref_is_absent_rather_than_present_and_empty() {
    // THE SHARPEST COULD-NOT-LOOK CASE. `origin/main` missing in a shallow or
    // freshly-cloned checkout is not an answer about that ref, and the map is
    // what keeps the two apart: a declared ref that does not resolve is ABSENT,
    // so a module reading it gets undefined rather than a fabricated value.
    let dir = repo(
        "git-ref-absent",
        "refs = [\"refs/heads/nonesuch\"]\n",
        "\tinput.tree[\"git-refs\"][\"refs/heads/nonesuch\"]",
    );
    assert!(
        !fired(&dir),
        "the ref does not resolve, so the key is absent and the body is undefined"
    );

    git_in(&dir, &["branch", "nonesuch"]);
    assert!(
        fired(&dir),
        "once the ref exists it resolves to a commit and the key is present"
    );

    // And a module can tell the two apart EXPLICITLY, which is the property
    // rather than a side effect of the case above.
    let explicit = repo(
        "git-ref-explicit-absence",
        "refs = [\"refs/heads/nonesuch\"]\n",
        "\tnot input.tree[\"git-refs\"][\"refs/heads/nonesuch\"]",
    );
    assert!(fired(&explicit), "absence is readable as absence");
}

#[test]
fn a_range_that_cannot_be_read_is_absent_rather_than_an_empty_commit_list() {
    // "Nothing landed in this range" and "I could not read this range" are the
    // two answers a migration gate most needs kept apart, and an empty list
    // spells the first while meaning the second.
    let unreadable = repo(
        "git-range-unreadable",
        "ranges = [\"refs/heads/nonesuch..HEAD\"]\n",
        "\tnot input.tree[\"git-ranges\"][\"refs/heads/nonesuch..HEAD\"]",
    );
    assert!(
        fired(&unreadable),
        "an endpoint that does not resolve leaves the range absent"
    );

    let readable = repo(
        "git-range-readable",
        "ranges = [\"refs/remotes/origin/main..HEAD\"]\n",
        "\tcount(input.tree[\"git-ranges\"][\"refs/remotes/origin/main..HEAD\"]) > 0",
    );
    // The base commit pinned `origin/main` to HEAD, so the range is EMPTY and
    // READABLE — the state an empty list correctly describes, and the one the
    // case above must not be confused with.
    assert!(
        !fired(&readable),
        "the range resolves and holds no commits: an empty list, not an absence"
    );

    std::fs::write(readable.join("src/lib.rs"), "fn main() { /* work */ }\n").unwrap();
    git_in(&readable, &["add", "-A"]);
    git_in(&readable, &["commit", "-q", "-m", "the work"]);
    assert!(fired(&readable), "one commit is now in the range");
}

#[test]
fn a_commit_reaches_the_input_as_a_pointer_and_never_as_a_message_body() {
    // Non-negotiable rule 4, decided at the ACQUISITION rather than at the
    // report: a range carries a sha and git's `%s`, which is how the log itself
    // points at a commit. A body would put tracked prose on the policy input,
    // and from there a consumer's `msg` could echo it into a finding.
    let dir = Fixture::new("git-range-pointer-only")
        .config(&config("ranges = [\"refs/remotes/origin/main..HEAD\"]\n"))
        .file(
            "policy/probe.rego",
            &module(
                "\tsome entry in input.tree[\"git-ranges\"][\"refs/remotes/origin/main..HEAD\"]\n\
                 \tentry.subject == \"subject line\"",
            ),
        )
        .file("src/lib.rs", "fn main() {}\n")
        .git()
        .base_commit()
        .build();
    std::fs::write(dir.join("src/lib.rs"), "fn main() { /* work */ }\n").unwrap();
    git_in(&dir, &["add", "-A"]);
    git_in(
        &dir,
        &[
            "commit",
            "-q",
            "-m",
            "subject line\n\nBODY-CANARY: this paragraph must reach no input",
        ],
    );

    let output = run(&dir, &["check"]);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
    assert!(
        stdout(&output).contains("git-probe"),
        "the subject reached the module: {}",
        stdout(&output)
    );
    assert!(
        !stdout(&output).contains("BODY-CANARY"),
        "a commit body reached the output: {}",
        stdout(&output)
    );
}

#[test]
fn a_run_whose_rules_declare_no_git_fact_reads_no_git_at_all() {
    // THE PERF PROPERTY, AS A BEHAVIOURAL ONE. CLOUD-851 measured what the other
    // way costs — `check` from a p50 of 4.76ms to 10.01ms, 2.103x, for a
    // question no rule had asked — and a wall-clock assertion discriminates
    // nothing at this scale. So the observable is different: a rule set that
    // declares no git fact decides identically OUTSIDE A REPOSITORY, which it
    // could not do if the family were acquired ambiently.
    let dir = Fixture::new("git-undeclared-no-read")
        .config(
            "version = 1\n\
             \n\
             [[rule]]\n\
             id = \"no-todo\"\n\
             kind = \"forbid\"\n\
             glob = \"**/*.rs\"\n\
             pattern = \"TODO\"\n\
             severity = \"warn\"\n\
             scope = \"tree\"\n\
             no_fix_reason = \"delete the marker\"\n",
        )
        .file("src/lib.rs", "// TODO: something\n")
        .build();

    let output = run(&dir, &["check"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a warn-severity finding, decided with no checkout in sight: {}",
        stdout(&output)
    );
    assert!(
        stdout(&output).contains("no-todo"),
        "the rule still decided: {}",
        stdout(&output)
    );
}

// --- the landing family (CLOUD-880) -----------------------------------------
//
// `Fact::GitRef` deliberately does not answer this. Its own header says why: the
// first version carried reachability beside the sha and
// `no_ancestry_decides_merged_ness` refused it, because CLOUD-36 decides
// merged-ness by PATCH IDENTITY and a rebased landing is invisible to ancestry.
// `git::landing` has computed that answer since; these are the cases that make it
// a fact a rule can ask.

#[test]
fn an_unscannable_target_is_absent_rather_than_reporting_nothing_landed() {
    // THE ARM THAT MATTERS MOST IN THIS FAMILY, and it is not symmetric with the
    // others. A failed scan rendered as `landed: false` reads to a gate as *this
    // work is outstanding* — a refusal reached on ignorance, with full confidence.
    // Absence is the only honest shape, and `not input.tree.landing[...]` is how a
    // module tells the two apart.
    let cannot_look = repo(
        "landing-absent",
        "landing = [\"refs/heads/nonesuch\"]\n",
        "\tnot input.tree.landing[\"refs/heads/nonesuch\"]",
    );
    assert!(
        fired(&cannot_look),
        "a target that does not resolve is absent from the map"
    );

    // The other direction, so the absence above is a real reading rather than a
    // key that is never populated at all: the same predicate over a target that
    // DOES resolve must not hold.
    let can_look = repo(
        "landing-absent-negative",
        "landing = [\"HEAD\"]\n",
        "\tnot input.tree.landing[\"HEAD\"]",
    );
    assert!(
        !fired(&can_look),
        "a target that resolves is present, so the absence predicate stops holding"
    );
}

#[test]
fn a_branch_whose_work_is_on_the_target_is_landed_and_one_ahead_is_not() {
    // The positive and the negative of the verdict itself. `HEAD` against `HEAD`
    // is the degenerate landing — every head-side commit is trivially on the
    // target — and it is the cheapest way to assert the field is populated and
    // true without depending on a fixture's branch topology.
    let landed = repo(
        "landing-landed",
        "landing = [\"HEAD\"]\n",
        "\tinput.tree.landing[\"HEAD\"].landed == true",
    );
    assert!(
        fired(&landed),
        "HEAD against itself has nothing unlanded: {}",
        "the degenerate case, which still has to answer"
    );

    // A commit the target does not carry. The fixture commits on top of the base,
    // and the base is what the target names — so exactly one commit is unlanded,
    // and `unlanded` names it.
    let ahead = Fixture::new("landing-ahead")
        .config(&config("landing = [\"HEAD~1\"]\n"))
        .file(
            "policy/probe.rego",
            &module(
                "\tinput.tree.landing[\"HEAD~1\"].landed == false\n\
             \tcount(input.tree.landing[\"HEAD~1\"].unlanded) == 1",
            ),
        )
        .file("src/lib.rs", "fn main() {}\n")
        .git()
        .base_commit()
        .build();
    common::write(&ahead, "src/added.rs", "fn added() {}\n");
    git_in(&ahead, &["add", "-A"]);
    git_in(&ahead, &["commit", "-q", "-m", "one ahead"]);
    assert!(
        fired(&ahead),
        "a commit the target does not carry is unlanded, and named"
    );
}

#[test]
fn the_landing_fact_carries_shas_and_never_a_subject_or_a_body() {
    // Non-negotiable rule 4, decided at the acquisition rather than at the report.
    // `Fact::GitRange` is where a commit's SUBJECT belongs; this fact answers a
    // yes/no and points at the commits behind a no. A message body or a diff on
    // this input would be tracked content the module could echo into a finding.
    let dir = Fixture::new("landing-pointer-only")
        .config(&config("landing = [\"HEAD~1\"]\n"))
        .file(
            "policy/probe.rego",
            &module(
                "\tsome sha in input.tree.landing[\"HEAD~1\"].unlanded\n\
                 \tcontains(sha, \"a subject nobody should see\")",
            ),
        )
        .file("src/lib.rs", "fn main() {}\n")
        .git()
        .base_commit()
        .build();
    common::write(&dir, "src/added.rs", "fn added() {}\n");
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "a subject nobody should see"]);
    assert!(
        !fired(&dir),
        "the commit subject reached the input, which rule 4 forbids"
    );
}

#[test]
fn a_run_declaring_only_a_landing_target_still_acquires_it() {
    // The declaration bound, from the other side. `git_facts` returns early when
    // NOTHING is declared, and a new column that the early return did not learn
    // about would make every landing rule read an absent key — a rule that is
    // configured, typed, and silently off.
    let dir = repo(
        "landing-only-declaration",
        "landing = [\"HEAD\"]\n",
        "\tinput.tree.landing[\"HEAD\"].verdict != \"\"",
    );
    assert!(
        fired(&dir),
        "a row declaring only `landing` still gets its fact acquired"
    );
}
