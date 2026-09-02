//! One manifest per vendored preset: its identity, the surface it decides, the
//! modules it ships, and the refusal vocabulary they raise (CLOUD-1181).
//!
//! # Why this module exists rather than three tables
//!
//! A preset used to be three unrelated `const`s that nothing tied together: the
//! name-to-modules table in `policy.rs`, its verdict rows sitting inside
//! `verdict.rs`'s `VENDORED` under a comment, and a branch exempting it from the
//! `[[pattern]]` refusal. Nothing declared a preset, so a preset carried no
//! identity beyond its name, no version, and — the load-bearing omission — no
//! SCOPE.
//!
//! Scope is where the silence costs most. `.claude/rules/policy-modules.md`
//! opens on the class: a module reading a key from the wrong surface evaluates,
//! reads undefined, refuses nothing, and *"a dead gate and a clean tree are
//! byte-identical on the decision surface"*. A consumer enabling a preset could
//! not see which surface it decided, so that mistake was theirs to make blind.
//!
//! # The inversion this ends
//!
//! Every place a preset was exempted from a rule a consumer module obeys, it was
//! exempted **because there was nowhere to write the declaration** — not because
//! the rule did not apply. A preset ships to every consumer while a consumer
//! module reaches one, so those exemptions were pointed the wrong way. The
//! manifest is the place, and it turns exemptions into declarations.
//!
//! # THIS DOES NOT OPEN THE NETWORK, AND THE MANIFEST IS NOT PERMISSION TO
//!
//! CLOUD-129 rejected remote policy fetch and that verdict is **unchanged**.
//! Every manifest here is `include_str!`d at build time: no network, no
//! registry, no trust-on-first-use, and the bytes ship inside the binary the
//! operator already trusts, under the same checksum as everything else in it.
//! A manifest is a declaration FORMAT. Whether a preset may arrive from outside
//! the binary is CLOUD-970's question, and a manifest is what makes that
//! question askable — before this, a third-party preset had no shape to arrive
//! in, so the trust question could not even be posed. Read no further permission
//! into it than that.
//!
//! # Rule 1 binds a manifest exactly as it binds a preset source
//!
//! A field may describe a PRACTICE and may never name a path, a task, a tracker
//! key or an entity. This file is under `crates/**`, so `batten.toml`'s rule-1
//! `forbid` rows already scan it on every gate invocation;
//! `manifests_are_inside_the_rule_one_glob` asserts that coverage rather than
//! leaving it true by accident.

use crate::rules::RuleScope;
use crate::verdict::{DeclaredVerdict, VendoredVerdict, admit, read, run};

/// One vendored preset, declared once.
#[derive(Debug)]
#[non_exhaustive]
pub struct Manifest {
    /// The name a consumer enables, and the only thing they could know before.
    pub name: &'static str,
    /// The manifest's own version.
    ///
    /// Separate from the crate version deliberately, and for the reason
    /// `spec::SPEC_VERSION` is separate: a version moving with the binary says
    /// "the binary changed", which the release tag already says. This moves when
    /// what the preset DECIDES changes.
    pub version: u32,
    /// The surface these modules decide.
    ///
    /// The field the absence of which was the silent dead gate. A rule enabling
    /// this preset at the other scope is refused at LOAD rather than evaluating
    /// to an empty violation set — see `policy::load`.
    pub scope: RuleScope,
    /// The modules, as `(pointer, source)`. The pointer is `<preset:name>/…`
    /// rather than a filesystem path: a preset has no path in the consumer's
    /// tree, and printing one sends a reader looking for a file that is not there.
    pub modules: &'static [(&'static str, &'static str)],
    /// The refusal classes these modules raise, with their glosses and remedies.
    ///
    /// Declared HERE rather than in `verdict.rs`'s native table, which is the
    /// change that makes the registry's two directions reachable for a preset:
    /// a token a module raises that no row here declares, and a row here that no
    /// module raises, are both findings a manifest can now express.
    pub verdicts: &'static [VendoredVerdict],
    /// The `[[pattern]]` ids these modules would cite if they could.
    ///
    /// **The declaration site CLOUD-934 needs, and deliberately not its fix.** A
    /// preset reaches a consumer who wrote no `[[pattern]]` rows, so
    /// `data.batten.patterns["x"]` resolves to undefined there and a preset
    /// citing one decides nothing while loading clean — which is why the
    /// exemption exists and why a preset still writes its literal inline.
    /// Listing the ids is what makes the exemption countable instead of
    /// invisible; closing it is CLOUD-934's row and this one does not do its work.
    pub patterns: &'static [&'static str],
}

/// Every vendored preset, in a stable order.
///
/// The ONE authority. `preset_names`, the modules a preset ships, and the
/// presets' half of the vendored verdict registry are all read off this table —
/// never a hand-maintained second list, which is `surface::SURFACE`'s discipline
/// and the reason a preset cannot be enabled that does not exist.
pub const MANIFESTS: &[Manifest] = &[
    Manifest {
        name: "ci-hygiene",
        version: 1,
        scope: RuleScope::Tree,
        modules: &[
            (
                "<preset:ci-hygiene>/spend-is-authorised.rego",
                include_str!("policy/presets/ci-hygiene/spend-is-authorised.rego"),
            ),
            (
                "<preset:ci-hygiene>/wiring-can-be-reached.rego",
                include_str!("policy/presets/ci-hygiene/wiring-can-be-reached.rego"),
            ),
        ],
        verdicts: &[
            VendoredVerdict {
                id: "cache build loose",
                gloss: "a cache-warming build recompiles and writes nothing on every run",
                class: "A build that compiles to fill a cache and runs nothing judges nothing, which is \
why it is exempt from parity rules — and that exemption is what makes it easy to leave running \
for nothing. Measured: two cache entries carrying the same key across five merges, each cycle \
compiling for ~145s and saving nothing, because the restore skips saving when the key already \
exists. One condition reading the restore's hit flag is the whole fix.",
                routes: &[read("source read first", "the compile step")],
            },
            VendoredVerdict {
                id: "cache name unknown",
                gloss: "the cache guard names a step that does not exist, so it admits every run",
                class: "The other direction of the same defect, and it has the same symptom with no \
signal. If the action stops emitting the hit flag the expression is empty, the guard holds, and \
the compile runs — wasteful, but visible in the bill. If the step id is dropped or renamed while \
the guard keeps naming it, the expression is ALSO empty and the build silently reverts to \
compiling every time. So the class names both halves: the guard must be present, and the step it \
reads must exist.",
                routes: &[read("source read first", "the restore step")],
            },
            VendoredVerdict {
                id: "event bind loose",
                gloss: "a comment predicate fires from anywhere in a body anyone can write",
                class: "An unanchored substring test fires from mid-sentence, from inside backticks, from \
a quoted block. That makes the repository's own writing ABOUT a trigger an invocation of it, and \
every artifact that has to name the token in order to be about it a live round. The class is the \
unanchored read of a body anyone can write, not the one token read that way.",
                routes: &[read("source read first", "the job condition")],
            },
            VendoredVerdict {
                id: "event reach dead",
                gloss: "a declared trigger starts a run in which every job skips",
                class: "The trigger exists and does nothing: the run list shows a run, and only the job's \
conclusion says it did not happen. Measured on one lane where a manual trigger was added so it \
could be exercised without waiting on a late cron, and every job's condition still admitted only \
the two original events. Judged only where a condition MENTIONS the event name at all, since a \
workflow that does not discriminate by event answers for every trigger it declares.",
                routes: &[read("source read first", "the job conditions")],
            },
            VendoredVerdict {
                id: "input render dropped",
                gloss: "an unquoted comment truncates a value before it ever reaches the forge",
                class: "YAML opens a comment at an unquoted space-hash, so a value carrying an \
interpolation after one parses to the bare text before it and the rest is discarded. Measured: \
one workflow carried exactly that for a day and 30 consecutive runs reported a title equal to the \
workflow name, so a caller keying on the interpolated value could never match. Linters pass over \
the line because a comment is legal YAML, and review reads it as the thing it was meant to be. \
Read pre-parse, because the parse is what destroys the evidence. Quoting the value is the fix.",
                routes: &[read("source read first", "the truncated line")],
            },
            VendoredVerdict {
                id: "job require unseen",
                gloss: "a fan-in enumerates its own dependencies and has gone stale",
                class: "Branch protection points at one aggregating job so that adding a leg never needs \
a ruleset change — which only holds if that job's assertion follows its dependency list by \
itself. Measured: a fan-in enumerated three of its four dependencies, so a red fourth left green \
the one check the host requires. A set-wide predicate cannot go stale, because it names nothing.",
                routes: &[read("source read first", "the fan-in job")],
            },
            VendoredVerdict {
                id: "job run early",
                gloss: "a job spends a runner on a pull request still being verified locally",
                class: "A draft says the author is still verifying locally, and it is also the lever a \
red run pulls: a lander that re-drafts stops further spend while the failure is diagnosed. A \
single job missing the guard defeats both, and the run it buys is one nobody reads. Measured on \
one repository: a workflow triggered by any pull request touching a workflow file spent a runner \
on every push to a draft for its whole life, and re-drafting did not close the tap.",
                routes: &[read("source read first", "the job's condition")],
            },
            VendoredVerdict {
                id: "job start same",
                gloss: "two scheduled workflows contend for the same runners at the same minute",
                class: "Every scheduled workflow's header tends to claim a staggered slot and nothing \
checks it, so two pairs drifted onto the same minute and the second pair landed after the first \
was found. Compared as LITERAL expressions rather than firing times: an every-30-minutes \
schedule genuinely overlaps every hourly slot, and flagging that would make the class fire \
forever on a workflow doing nothing wrong.",
                routes: &[read("source read first", "the schedule trigger")],
            },
            VendoredVerdict {
                id: "merge run early",
                gloss: "a comment-triggered merge delegates the draft question to the ruleset",
                class: "A draft head grades no checks where every pull-request workflow is draft-gated, \
and a branch ruleset admits that empty set as satisfying required-checks-green. So a merge path \
that never reads the draft state has no draft check at all, and can advance the trunk to a commit \
CI never ran on. Deciding not to ask is not the same as asking.",
                routes: &[read("source read first", "the merge job")],
            },
            VendoredVerdict {
                id: "review watch missing",
                gloss: "a draft-gated workflow can never be superseded once it skips",
                class: "Omitting `types:` defaults to `[opened, synchronize, reopened]`. Where the jobs \
are draft-gated, a pull request created as a draft mints a skipped run on `opened`, and with no \
`ready_for_review` there is no event left that could replace it — a waiter correctly refuses to \
read a skip as an answer and polls forever. Measured as a deadlock across two pull requests at \
once, both fully green but for one such name.",
                routes: &[read(
                    "source read first",
                    "the pull_request trigger's types",
                )],
            },
            VendoredVerdict {
                id: "workflow declare missing",
                gloss: "a workflow can have two runs racing at all",
                class: "Superseding is the pull-request half of this and is not the whole of it: a \
comment- or schedule-triggered workflow never reaches that guard, so the property that matters \
off the landing path — that a workflow cannot race itself — reaches none of them. Measured: N \
concurrent comment invocations ran N concurrent attempts to advance a trunk branch, at 245 \
refusals against 6 merges in half an hour. A scheduled workflow must NOT cancel its own previous \
tick, so declaring a group is all this asks.",
                routes: &[read("source read first", "the workflow")],
            },
            VendoredVerdict {
                id: "workflow run loose",
                gloss: "a branch scope written where filtering is already too late",
                class: "A job condition is evaluated AFTER the run exists, so a branch scope expressed \
only there creates a run and then skips it. Measured on one lane: 1131 inserted-and-skipped runs \
in 25 hours — no runner minutes, which is why it survived, but 46% of every run in the \
repository, enough that paginating the run list stops being stable. The filter belongs on the \
trigger, where it is free.",
                routes: &[read("source read first", "the workflow_run trigger")],
            },
            VendoredVerdict {
                id: "workflow run twice",
                gloss: "a pull-request workflow pays out a run its own next push made obsolete",
                class: "A landing lap rebases and pushes. Without `cancel-in-progress` the superseded \
commit's run is billed in full for a verdict nobody will read, and a lander loses the ability to \
cancel a doomed run by simply pushing the next one. Declaring the group is not enough — the \
value is what does the work, and it is a boolean rather than the string `true`.",
                routes: &[read(
                    "source read first",
                    "the workflow's concurrency block",
                )],
            },
        ],
        patterns: &[],
    },
    Manifest {
        name: "commit-hygiene",
        version: 1,
        scope: RuleScope::MediatedCall,
        modules: &[(
            "<preset:commit-hygiene>/no-empty-commit.rego",
            include_str!("policy/presets/commit-hygiene/no-empty-commit.rego"),
        )],
        verdicts: &[VendoredVerdict {
            id: "commit ship empty",
            gloss: "an empty commit records that somebody wanted a new SHA",
            class: "A commit records a change. The reachable use of an empty one is kicking a \
pipeline, which spends a run to re-ask a question the previous run already answered and \
leaves a commit in the history no reader can act on. If the goal is a fresh run, re-run \
the pipeline.",
            routes: &[run("task run first", "re-run the pipeline")],
        }],
        patterns: &[],
    },
    Manifest {
        name: "landing-loop",
        version: 1,
        scope: RuleScope::Tree,
        modules: &[
            (
                "<preset:landing-loop>/graded-head-is-not-regraded.rego",
                include_str!("policy/presets/landing-loop/graded-head-is-not-regraded.rego"),
            ),
            (
                "<preset:landing-loop>/already-landed-work-is-not-relanded.rego",
                include_str!(
                    "policy/presets/landing-loop/already-landed-work-is-not-relanded.rego"
                ),
            ),
            (
                "<preset:landing-loop>/lease-authorises-the-branch.rego",
                include_str!("policy/presets/landing-loop/lease-authorises-the-branch.rego"),
            ),
            (
                "<preset:landing-loop>/rebase-conflict-stops-the-lap.rego",
                include_str!("policy/presets/landing-loop/rebase-conflict-stops-the-lap.rego"),
            ),
        ],
        verdicts: &[
            VendoredVerdict {
                id: "head grade twice",
                gloss: "the forge already judged this commit and a second run would re-ask it",
                class: "A commit that has not changed cannot get a different verdict, so a second \
run over it buys an answer that is already recorded and spends the metered tier to do it. \
Measured on one consumer's landing bot over a half hour: 400 runs, 248 executed, against 5 \
merges. Read the recorded verdict rather than asking for it again; if the intent was to \
judge different work, the commit is what has to change.",
                routes: &[
                    read("source read first", "the forge record for this commit"),
                    // THE PRECONDITION IS THE WHOLE OF THIS ROUTE. A re-grade is
                    // legitimate when the recorded verdict is about the RUNNER rather
                    // than about the commit — a lost agent, an evicted node, an
                    // infrastructure fault — because that verdict answers a question
                    // nobody asked. It is not legitimate because the answer was
                    // unwelcome, which is the case this condition exists to exclude.
                    admit(
                        "path admit first",
                        "the recorded verdict is about a runner fault rather than about this commit",
                    ),
                ],
            },
            VendoredVerdict {
                id: "lease grant other",
                gloss: "a live landing lease names a different branch, and no reservation names this one",
                class: "A landing lease is how a fleet keeps two branches from buying overlapping CI for \
a trunk only one of them can fast-forward onto. This branch is neither the holder nor the \
successor admitted behind it, so a matrix spent now is a matrix the holder's merge invalidates. \
Wait for the lease to lapse or be released, or reserve the slot behind the holder — the loop that \
does both lives outside the engine, which only reads the answer. Every reading this refusal \
cannot take ALLOWS: an unreadable lease stops every job in the fleet, where waving one matrix \
through costs one matrix.",
                routes: &[
                    read(
                        "lease read first",
                        "the lease grading recorded for this branch",
                    ),
                    // The wedged holder, and it is narrow on purpose. The lease grades
                    // LIVENESS rather than PROGRESS (CLOUD-499), so a holder that beats
                    // steadily while making none holds forever and starves the fleet.
                    // That is the case this admits, and it is not "the wait was
                    // inconvenient" — a holder that is merely slow is the mechanism
                    // working.
                    admit(
                        "lease admit first",
                        "the holder is wedged rather than slow — it is beating without advancing, so waiting for a lapse it keeps renewing starves the fleet indefinitely",
                    ),
                ],
            },
            VendoredVerdict {
                id: "patch ship twice",
                gloss: "the target already carries this branch's changes, so landing them again buys nothing",
                class: "A landing attempt over work the target already has runs a matrix, holds the \
fleet's landing slot while it does, and merges a no-op or a conflict. The answer is decided by \
PATCH IDENTITY rather than by reachability, which is what makes it trustworthy here: a rebased, \
squash-merged or cherry-picked branch leaves the same change on the target under a different \
commit with no ancestry path back, and on a fast-forward trunk that is the ordinary way work \
lands. Close the branch, or rebase onto the target and see what is genuinely left.",
                routes: &[
                    read("record read first", "the landing verdict for this target"),
                    // The one legitimate re-land, and it is narrow on purpose. Patch
                    // identity answers about CONTENT, so deliberately re-applying a
                    // change the target once carried and later reverted is
                    // indistinguishable from never having landed it — the same bytes,
                    // arriving for a different reason. That is the case this admits, and
                    // it is not "the answer was inconvenient".
                    admit(
                        "patch admit first",
                        "the change is being deliberately re-applied after the target reverted it, so identical content is the intent rather than a duplicate",
                    ),
                ],
            },
            VendoredVerdict {
                id: "replay halt conflict",
                gloss: "the lap's replay conflicted, so the head it would push was never completed",
                class: "Landing is a loop and one step of it needs a person: a replay that \
conflicts is two authors having changed the same lines, and choosing between them is a \
judgement no gate makes. What is refused is not the conflict — conflicts are the mechanism \
working, and frequent laps are what keep each one to a single resolvable increment — but a \
lap CONTINUING past one, which pushes, spends a matrix or fast-forwards a head whose replay \
never finished. A merge strategy makes that outcome reachable and reports success while \
doing it, which is why the wrong move here is the one reached for to make the loop always \
succeed. Resolve the conflict, then lap again.",
                routes: &[
                    read("record read first", "the replay outcome this lap recorded"),
                    // The one legitimate continuation, and it is narrow on purpose.
                    // A conflict a LATER lap replayed cleanly is already resolved and
                    // the module reads the last line for exactly that reason — so
                    // this admits only the case where the resolution happened outside
                    // the loop's own record, never "the conflict was inconvenient".
                    admit(
                        "replay admit first",
                        "the conflict was resolved outside this lap's record, so the head being pushed is a completed replay rather than a half-applied one",
                    ),
                ],
            },
        ],
        patterns: &[],
    },
    Manifest {
        name: "pinned-toolchain",
        version: 1,
        scope: RuleScope::MediatedCall,
        modules: &[(
            "<preset:pinned-toolchain>/pinned-program-via-the-pin.rego",
            include_str!("policy/presets/pinned-toolchain/pinned-program-via-the-pin.rego"),
        )],
        verdicts: &[VendoredVerdict {
            id: "pin reach loose",
            gloss: "a program the project's pin provides was reached around the pin",
            class: "The pinned toolchain is what makes one machine's run mean anything about \
another's, and it supplies an ENVIRONMENT as well as a binary. A program reached around \
it runs a different version, or the same version without the variables the project sets \
— and the failure that produces looks like the failure being investigated rather than \
like a wrong invocation. Measured on one consumer: sixty runs of a test suite died on an \
unset variable instead of on the assertion, and the report that followed was published \
as three claims about the tree, all false.",
            routes: &[run(
                "task run first",
                "run the declared task, or invoke the program through the pin",
            )],
        }],
        patterns: &[],
    },
    Manifest {
        name: "shell-hygiene",
        version: 1,
        scope: RuleScope::Tree,
        modules: &[
            (
                "<preset:shell-hygiene>/shebang-names-its-language.rego",
                include_str!("policy/presets/shell-hygiene/shebang-names-its-language.rego"),
            ),
            (
                "<preset:shell-hygiene>/sibling-resolves.rego",
                include_str!("policy/presets/shell-hygiene/sibling-resolves.rego"),
            ),
        ],
        verdicts: &[
            VendoredVerdict {
                id: "program name unnamed",
                gloss: "the file runs a shell and its name does not say so",
                class: "Every instrument that selects by extension — a formatter, a linter, a \
CI path filter — covers this file silently and exits 0. A green run over it therefore \
means nothing was looked at rather than nothing was found, which is worse than a red \
one. Name the language in the filename, or declare the file's coverage another way.",
                routes: &[run("patch run first", "git mv")],
            },
            VendoredVerdict {
                id: "program resolve missing",
                gloss: "a run-time sibling path is computed and the tree carries no such file",
                class: "The shape resolves a path beside the running program and then guards it \
with a test that exits 0, so the reference does not fail — it goes silent, and the \
behaviour it was reaching for simply never happens. A path that must exist should be \
asserted rather than tested.",
                routes: &[read("source read first", "the computed path")],
            },
        ],
        patterns: &[],
    },
    Manifest {
        name: "trunk-based",
        version: 1,
        scope: RuleScope::MediatedCall,
        modules: &[(
            "<preset:trunk-based>/no-force-push.rego",
            include_str!("policy/presets/trunk-based/no-force-push.rego"),
        )],
        verdicts: &[VendoredVerdict {
            id: "trunk push forced",
            gloss: "a force push rewrites a shared branch under whoever already fetched it",
            class: "Rewriting a published branch invalidates every checkout of it that \
already exists, and the holder finds out by having their next pull fail in a way that \
looks like their own mistake. `--force-with-lease` refuses when the remote moved, which \
is the same operation with the one check that makes it safe.",
            routes: &[run("patch run first", "git push --force-with-lease")],
        }],
        patterns: &[],
    },
];

/// Every vendored preset's name, in a stable order.
#[must_use]
pub fn names() -> Vec<&'static str> {
    MANIFESTS.iter().map(|manifest| manifest.name).collect()
}

/// The manifest for a named preset, or `None` when nothing ships under it.
#[must_use]
pub fn find(name: &str) -> Option<&'static Manifest> {
    MANIFESTS.iter().find(|manifest| manifest.name == name)
}

/// Every verdict row the vendored presets declare, as the registry carries them.
///
/// Chained onto the native rows by [`crate::verdict::vendored`]. Derived rather
/// than declared a second time: before this, adding a preset class meant editing
/// a table in another module under a comment, and nothing tied the two together.
#[must_use]
pub fn verdict_rows() -> Vec<DeclaredVerdict> {
    MANIFESTS
        .iter()
        .flat_map(|manifest| manifest.verdicts.iter())
        .map(crate::verdict::declared_from)
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{MANIFESTS, names};

    use std::collections::BTreeSet;

    /// Every class a preset's modules raise is declared by its own manifest.
    ///
    /// The direction a consumer module already gets from `check_verdicts_are_declared`,
    /// now reachable for a preset because there is somewhere to declare it.
    /// Before the manifest a preset's rows lived in another module's table under
    /// a comment, so this question had no side to ask.
    ///
    /// Read from the module SOURCE, which is the only honest reading: the
    /// alternative is to trust that the manifest and the modules agree, which is
    /// the assumption the manifest exists to remove.
    #[test]
    fn every_class_a_preset_raises_is_declared_by_its_own_manifest() {
        for manifest in MANIFESTS {
            let declared: BTreeSet<&str> = manifest.verdicts.iter().map(|entry| entry.id).collect();
            for (pointer, source) in manifest.modules {
                for token in raised_in(source) {
                    assert!(
                        declared.contains(token.as_str()),
                        "`{}` raises `{token}` in `{pointer}`, which its manifest does not \
                         declare — the refusal would carry no gloss and no route",
                        manifest.name
                    );
                }
            }
        }
    }

    /// And the mirror: a class no module raises fails.
    ///
    /// The anti-vacuity direction the `[[verdict]]` registry already enforces
    /// in-tree and which a preset was exempt from, not because the rule did not
    /// apply but because there was nowhere to write the declaration. A class no
    /// gate reaches reads as coverage while its routes have never been walked.
    #[test]
    fn every_class_a_manifest_declares_is_raised_by_one_of_its_modules() {
        for manifest in MANIFESTS {
            let raised: BTreeSet<String> = manifest
                .modules
                .iter()
                .flat_map(|(_, source)| raised_in(source))
                .collect();
            for entry in manifest.verdicts {
                assert!(
                    raised.contains(entry.id),
                    "`{}` declares `{}`, which none of its modules raise",
                    manifest.name,
                    entry.id
                );
            }
        }
    }

    /// One name, one manifest.
    #[test]
    fn no_preset_is_declared_twice() {
        let mut seen = names();
        let before = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(before, seen.len(), "two manifests share a preset name");
    }

    /// A class belongs to exactly one preset.
    ///
    /// Two manifests declaring one token would collide in the registry, and
    /// `policy::registry_for` refuses a collision between the vendored and
    /// consumer halves rather than within the vendored half — so nothing else
    /// asks this.
    #[test]
    fn no_class_is_declared_by_two_presets() {
        let mut seen: Vec<&str> = MANIFESTS
            .iter()
            .flat_map(|manifest| manifest.verdicts.iter().map(|entry| entry.id))
            .collect();
        let before = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(
            before,
            seen.len(),
            "a class is declared by two presets, so the registry cannot say which raises it"
        );
    }

    /// Rule 1 reaches a manifest as it reaches a preset source.
    ///
    /// Asserted rather than assumed, per the row: this file is under `crates/**`
    /// so `batten.toml`'s rule-1 `forbid` rows already scan it, and what is
    /// checked here is that the file is where that glob can see it.
    #[test]
    fn manifests_are_inside_the_rule_one_glob() {
        let here = std::path::Path::new(file!());
        assert!(
            here.starts_with("crates"),
            "the manifests must live where rule 1's glob reaches them, not at {}",
            here.display()
        );
    }

    /// The classes a module raises, read from its source.
    ///
    /// A refusal is `{rule, verdict, subjects}` and its class is a STRING
    /// LITERAL under `verdict` (`.claude/rules/policy-modules.md`), so what is
    /// matched is that SHAPE: a `"rule":` key, then the `"verdict":` that
    /// follows it in the same object.
    ///
    /// AN EARLIER VERSION MATCHED `"verdict":` ANYWHERE AND CLAIMED OVER-READING
    /// WAS THE SAFE DIRECTION. It is not, and the assertion above said so
    /// immediately: `landing-loop`'s own test fixtures build landing records
    /// whose rows carry a `verdict` COLUMN, so `landed` and three siblings read
    /// as raised classes and the manifest was accused of not declaring them.
    /// Over-reading makes the raised-set too big, which fails the first
    /// assertion on inputs that raise nothing — the noisy direction, not the
    /// safe one.
    ///
    /// It also declines to read a COMPOSED verdict (`"verdict": columns[1]`),
    /// and that is correct rather than a gap: the ABI refuses a class composed
    /// at runtime, because a class a reader cannot look up is not a class.
    fn raised_in(source: &str) -> Vec<String> {
        let mut found = Vec::new();
        for rest in source.split("\"rule\":").skip(1) {
            let Some(after) = rest.find("\"verdict\": \"") else {
                continue;
            };
            let tail = &rest[after + "\"verdict\": \"".len()..];
            // Only when the `verdict` key belongs to the SAME object: a later
            // block's key would be past the object's close.
            if rest[..after].contains("\n}") {
                continue;
            }
            if let Some(end) = tail.find('"') {
                found.push(tail[..end].to_owned());
            }
        }
        found
    }
}
