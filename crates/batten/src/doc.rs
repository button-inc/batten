//! A class's interaction doc: how to deal with a refusal, not why it exists
//! (CLOUD-2143).
//!
//! # What a first sighting owes its reader
//!
//! The full arm a context reads once per compaction cycle used to be a 120-char
//! gloss and, where a row declared one, its `reason`. The class paragraph — the
//! actual definition — sat behind `policy explain`, and nothing told the reader
//! what to do or which wrong responses to skip. This is that text, in four fixed
//! sections, the gloss being the first:
//!
//! * `what` — the class's `gloss`, unchanged: one line, at most `GLOSS_MAX`;
//! * `why` — the harm prevented, one sentence;
//! * `do` — the correct next actions, one to three;
//! * `dont` — the wrong responses observed, up to three.
//!
//! An admission's condition is not a section: it is the override route's own
//! `precondition`, rendered from the route so the two cannot drift.
//!
//! # Budgeted, and history-free
//!
//! A rendered doc (the gloss, these sections and the admissible preconditions)
//! is at most [`DOC_BYTES`] at load, which is 160 tokens on `budget.rs`'s
//! bytes/4, and at most 160 `o200k_base` tokens exactly in the test binary —
//! the shipped binary links no tokenizer (CLOUD-1284). 160 is 4,500 tokens of
//! prose per 90k window over a design point of 24 distinct gates. Rationale and
//! precedent are not interaction: they stay in the class paragraph, which
//! `explain` prints, and no section may cite an issue key.
//MUTANT-SUITE crates/batten/tests/it/refusal_ceiling.rs

use serde::{Deserialize, Serialize};

/// The rendered doc's ceiling at load, in bytes: 160 tokens at bytes/4.
pub const DOC_BYTES: usize = 640;

/// The most items a `do` or `dont` list may carry.
pub const ITEMS_MAX: usize = 3;

/// One class's interaction sections, beside its `gloss`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Doc {
    /// The harm the class prevents, in one sentence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    /// The correct next actions, one to three, naming the routes.
    #[serde(default, rename = "do", skip_serializing_if = "Vec::is_empty")]
    pub act: Vec<String>,
    /// The wrong responses observed, up to three.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dont: Vec<String>,
}

impl Doc {
    /// Whether nothing is declared, which serializes as no `doc` at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.why.is_none() && self.act.is_empty() && self.dont.is_empty()
    }
}

/// One vendored doc, keyed by its class's id.
#[derive(Debug)]
pub struct VendoredDoc {
    /// The class token this documents.
    pub id: &'static str,
    /// See [`Doc::why`].
    pub why: Option<&'static str>,
    /// See [`Doc::act`].
    pub act: &'static [&'static str],
    /// See [`Doc::dont`].
    pub dont: &'static [&'static str],
}

impl VendoredDoc {
    /// The owned form a [`crate::verdict::DeclaredVerdict`] carries.
    #[must_use]
    pub fn to_doc(&self) -> Doc {
        Doc {
            why: self.why.map(str::to_owned),
            act: self.act.iter().map(|item| (*item).to_owned()).collect(),
            dont: self.dont.iter().map(|item| (*item).to_owned()).collect(),
        }
    }
}

/// The docs of the engine's own classes, vendored and preset alike, keyed by id.
///
/// A separate table rather than a field on each `VendoredVerdict` literal, so
/// the interaction text is one file to author and review, and
/// `every_vendored_class_has_a_doc` keeps it whole against both tables.
pub const VENDORED_DOCS: &[VendoredDoc] = &[
    // ── native ──────────────────────────────────────────────────────────────
    VendoredDoc {
        id: "path write refused",
        why: Some(
            "This repository declared the path protected, so the write is refused before it lands",
        ),
        act: &[
            "make the change through the surface the line names: its redirect, or the row that owns it",
            "undo an unmeant change with `git restore`",
        ],
        dont: &[
            "reach the path through another program, a redirect or a script",
            "retry the same write",
        ],
    },
    VendoredDoc {
        id: "program name unknown",
        why: Some(
            "The boundary cannot tell what this program does to a protected path, so it will not guess",
        ),
        act: &[
            "run the same work with a program the config declares, or a plain read tool",
            "if the program only reads, declare it in `protected_readers` in `batten.toml`",
        ],
        dont: &["wrap the program in another one to hide it"],
    },
    VendoredDoc {
        id: "rule read missing",
        why: Some(
            "A rule changed by a reader who never saw why it exists loses the reason it was written",
        ),
        act: &[
            "run the `batten policy explain '<id>' --history` the line names, one call with no pipe",
            "then make the same edit",
        ],
        dont: &[
            "edit the row through a shell to get around this",
            "read a different row's history",
        ],
    },
    VendoredDoc {
        id: "task run twice",
        why: Some("A second copy races the first over the same refs, lock and remote"),
        act: &[
            "run `batten task alive` to see what the holder is doing",
            "wait for that run's exit, then act on its result",
        ],
        dont: &[
            "delete the lock file",
            "start the task again under another name",
        ],
    },
    VendoredDoc {
        id: "history drop unpushed",
        why: Some(
            "The reset would discard commits that exist in no other clone, and nothing else holds them",
        ),
        act: &[
            "push or branch the commits first; `git reflog` still holds them",
            "move the ref and keep the work with `git reset --soft`",
            "revert one file with `git checkout -- <path>`",
        ],
        dont: &["reset with a different verb that discards the same commits"],
    },
    VendoredDoc {
        id: "config write refused",
        why: Some(
            "Overwriting the committed authority would replace a reviewed policy with defaults, silently",
        ),
        act: &["edit the `batten.toml` that exists"],
        dont: &["delete it so `init` can write a fresh one"],
    },
    VendoredDoc {
        id: "outcome table refused",
        why: Some(
            "A row that can fire on nothing reads as coverage while its route was never walked",
        ),
        act: &["fix the `[[outcome]]` row and key the refusal names, in `batten.toml`"],
        dont: &["delete the row to make the config load"],
    },
    VendoredDoc {
        id: "plan read stale",
        why: Some("The gate would enforce a step plan nobody reviewed a diff of"),
        act: &["regenerate the projection with `batten hk contract` and review its diff"],
        dont: &["edit the committed projection by hand to match"],
    },
    VendoredDoc {
        id: "handler answer denied",
        why: Some("A program the config registers as a hook handler answered deny for this call"),
        act: &["read that `[hook.handler]` row in `batten.toml` for what it guards, and meet it"],
        dont: &["retry the call unchanged"],
    },
    VendoredDoc {
        id: "scanner pin missing",
        why: Some(
            "An unpinned scanner resolves to whatever is ambient, so its green would say nothing",
        ),
        act: &[
            "declare the scanner as a `[[provision]]` entry in `batten.toml`",
            "then run `batten provision`",
        ],
        dont: &["remove the `secrets` rule"],
    },
    VendoredDoc {
        id: "scanner install missing",
        why: Some("Nothing was scanned, and a scan of nothing must not read as a clean tree"),
        act: &["run `batten provision`, then the check again"],
        dont: &["treat the empty result as a pass"],
    },
    VendoredDoc {
        id: "spawn run refused",
        why: Some("This rule kind runs a command, and `check` is a read-only verb by contract"),
        act: &["run it through `batten enforce`, which may spawn"],
        dont: &["change the rule's kind to get it under `check`"],
    },
    VendoredDoc {
        id: "turn finish unmet",
        why: Some("A stop is a completion claim, and the turn's facts say the work is not landed"),
        act: &[
            "finish what the line names; for unlanded work run `mise run land`",
            "or say in words what blocks it",
        ],
        dont: &[
            "re-declare the work finished",
            "end the turn again unchanged",
        ],
    },
    // ── the mediated composers ──────────────────────────────────────────────
    VendoredDoc {
        id: "receipt read missing",
        why: Some(
            "The check this call depends on has no verdict for what its receipt is keyed to in this checkout",
        ),
        act: &[
            "run the check the row names, backgrounded, and wait for its exit",
            "then make the call again",
        ],
        dont: &[
            "retry the call without running the check",
            "write the receipt by hand",
        ],
    },
    VendoredDoc {
        id: "receipt read late",
        why: Some("The check ran too long ago for its verdict to still be evidence"),
        act: &["re-run the check the row names, then the call"],
        dont: &["retry the call unchanged"],
    },
    VendoredDoc {
        id: "receipt carry other",
        why: Some("The check ran and recorded something the row does not accept"),
        act: &["fix what the check reports, then re-run it"],
        dont: &["re-run the check unchanged; its answer will not move"],
    },
    VendoredDoc {
        id: "receipt read other",
        why: Some(
            "An amend or rebase changed the bytes, so the old verdict is about a commit this branch no longer carries",
        ),
        act: &[
            "re-run the check against this head",
            "if only a write can turn it green, push the head first",
        ],
        dont: &["amend again to dodge the receipt"],
    },
    VendoredDoc {
        id: "receipt read stale",
        why: Some(
            "The branch moved onto a new base, so the receipt is about a different branch with the same name",
        ),
        act: &["re-take the evidence on the branch as it now stands"],
        dont: &["rebase back to make the old receipt match"],
    },
    VendoredDoc {
        id: "tool run loose",
        why: Some(
            "A text utility over a tracked path returns unbounded, unstructured output the structured tools answer better",
        ),
        act: &[
            "Grep for content, Glob for paths, Read with offset and limit for one file",
            "rewrite the same question for those tools; `rules/scanning.md` picks which",
        ],
        dont: &[
            "wrap the utility in `bash -c`, a script or a task",
            "drop the question",
        ],
    },
    VendoredDoc {
        id: "path read routed",
        why: Some(
            "This path's row names the tool that reads it, which survives a move of the tree where the path does not",
        ),
        act: &["read it through the tool the line names after the path"],
        dont: &["read the same path through a shell utility instead"],
    },
    VendoredDoc {
        id: "verdict read dropped",
        why: Some(
            "A pipe into a pager or filter exits with the filter's status, so the command's verdict is lost",
        ),
        act: &[
            "run the command alone with `run_in_background` and read the exit the notification carries",
        ],
        dont: &[
            "redirect it to a file instead",
            "infer pass or fail from its output",
        ],
    },
    VendoredDoc {
        id: "verdict carry other",
        why: Some(
            "After `;`, `||` or a newline only the last command's status survives, so the verdict is the wrong one",
        ),
        act: &["chain with `&&`, or run the verdict-bearing command on its own"],
        dont: &["add `|| true` or a trailing command to quiet it"],
    },
    VendoredDoc {
        id: "turn watch dropped",
        why: Some(
            "`nohup` or a trailing `&` returns at once, so the wake-up on the real exit is lost",
        ),
        act: &["drop the `&`/`nohup` and set `run_in_background` on the tool call"],
        dont: &["poll for the result with `sleep`"],
    },
    VendoredDoc {
        id: "call count over",
        why: Some("The call measures over a ceiling the config declares"),
        act: &[
            "narrow the call under the row's maximum, e.g. fewer named artifacts in a spawn prompt",
        ],
        dont: &["split it into calls that each sneak under the ceiling"],
    },
    VendoredDoc {
        id: "call name refused",
        why: Some("The config refuses this command shape outright and names its replacement"),
        act: &["run the remedy `batten policy explain` prints for the rule on the line"],
        dont: &[
            "respell the same command to get past the shape",
            "run it through another program",
        ],
    },
    VendoredDoc {
        id: "call retry now",
        why: Some("The boundary already repaired what refused this call"),
        act: &["issue the identical call again, unchanged"],
        dont: &["change the call; the repair was for this one"],
    },
    VendoredDoc {
        id: "call fix silent",
        why: Some("The boundary changed something under the call and let it through"),
        act: &["re-read what the row repairs before relying on the tree as you last saw it"],
        dont: &["undo the repair"],
    },
    VendoredDoc {
        id: "input write refused",
        why: Some(
            "The content this write would land matches a shape the config refuses, judged before the bytes land",
        ),
        act: &["change what you write so it no longer matches the row the line names"],
        dont: &["write the same bytes through another tool or path"],
    },
    VendoredDoc {
        id: "issue name missing",
        why: Some("Nothing on the published work says which tracker row it serves"),
        act: &["name the key in the command, the branch, or a commit subject on the range"],
        dont: &["invent a key"],
    },
    // ── the config loader ───────────────────────────────────────────────────
    VendoredDoc {
        id: "config read refused",
        why: Some("The authority is not TOML, so no rule in it is enforced at all"),
        act: &["fix the TOML in `batten.toml` with Read and Edit, which stay open"],
        dont: &["work on until the config loads; nothing else is gated meanwhile"],
    },
    VendoredDoc {
        id: "verb declare refused",
        why: Some("An inert `[[verb]]` row reads as covered while matching nothing"),
        act: &["fix the row and key the refusal names, in `batten.toml`"],
        dont: &["delete the row to make the config load"],
    },
    VendoredDoc {
        id: "pattern declare refused",
        why: Some(
            "A malformed `[[pattern]]` would surface at adjudication, the worst moment and the wrong exit class",
        ),
        act: &["fix the expression the refusal names, in `batten.toml`"],
        dont: &["inline the regex in the module instead"],
    },
    VendoredDoc {
        id: "traversal declare refused",
        why: Some(
            "A half-declared walk would run to exhaustion, or decide nothing, while loading clean",
        ),
        act: &["fix the `[[traversal]]` row and key the refusal names, in `batten.toml`"],
        dont: &["write the walk into a module instead"],
    },
    VendoredDoc {
        id: "register declare refused",
        why: Some(
            "A malformed `[[register]]` row builds a key set that answers about the wrong cells",
        ),
        act: &["fix the row's file, column or key node the refusal names, in `batten.toml`"],
        dont: &["delete the row to make the config load"],
    },
    VendoredDoc {
        id: "verdict declare refused",
        why: Some(
            "Every refusal class lives in this table, so a malformed row breaks what refusals can say",
        ),
        act: &["fix the `[[verdict]]` row and clause the refusal names, in `batten.toml`"],
        dont: &["drop the row's routes or doc to get it under a limit"],
    },
    VendoredDoc {
        id: "redirect declare refused",
        why: Some(
            "The table changes what a refusal says for a class of path, and a redefinition is incoherent",
        ),
        act: &["fix or merge the `[[redirect]]` row the refusal names, in `batten.toml`"],
        dont: &["declare the same glob twice"],
    },
    VendoredDoc {
        id: "deferral declare refused",
        why: Some(
            "A `[[deferral]]` whose `reaches` is not a version can never be compared, so nothing watches it",
        ),
        act: &["give the row a comparable `reaches`, in `batten.toml`"],
        dont: &["delete the deferral to make the config load"],
    },
    VendoredDoc {
        id: "remedy resolve missing",
        why: Some(
            "A remedy naming a command that no longer exists costs the reader a round to find out",
        ),
        act: &["point the remedy at the command's current name, in `batten.toml`"],
        dont: &["delete the remedy"],
    },
    VendoredDoc {
        id: "marker declare refused",
        why: Some("An empty marker token matches every line and reads as coverage"),
        act: &["give the `[[marker]]` row a real token, in `batten.toml`"],
        dont: &["delete the row to make the config load"],
    },
    VendoredDoc {
        id: "rule declare refused",
        why: Some(
            "A malformed `[[rule]]` row loads, matches nothing where it is mediated, and reads as coverage",
        ),
        act: &["fix the `[[rule]]` row and key the refusal names, in `batten.toml`"],
        dont: &["delete the rule to make the config load"],
    },
    VendoredDoc {
        id: "output declare refused",
        why: Some(
            "A duplicate `[[exec_pattern]]` id makes two predicates indistinguishable in their record",
        ),
        act: &["give the row a unique id, in `batten.toml`"],
        dont: &["delete the predicate"],
    },
    VendoredDoc {
        id: "environment declare refused",
        why: Some(
            "A malformed classifier classifies nothing, so machine failures read as tree defects again",
        ),
        act: &["fix the `[[verify_environment_pattern]]` row the refusal names, in `batten.toml`"],
        dont: &["delete the row to make the config load"],
    },
    VendoredDoc {
        id: "waiver declare refused",
        why: Some("A malformed waiver is a hatch whose expiry nobody could read"),
        act: &["give the `[[waiver]]` row its reason and a valid expiry, in `batten.toml`"],
        dont: &["remove the expiry"],
    },
    VendoredDoc {
        id: "fact declare refused",
        why: Some("A fact the engine cannot produce reads undefined and refuses nothing"),
        act: &["name a fact the engine produces, or fix the row, in `batten.toml`"],
        dont: &["delete the rule that reads it"],
    },
    VendoredDoc {
        id: "mint declare refused",
        why: Some("A malformed mint is a receipt nothing can satisfy, or one that answers forever"),
        act: &["fix the `[[mint]]` row and key the refusal names, in `batten.toml`"],
        dont: &["delete the mint to make the config load"],
    },
    VendoredDoc {
        id: "recorder declare refused",
        why: Some("A recorder bound to an unknown pattern records nothing"),
        act: &["bind the `[[recorder]]` row to a declared pattern id, in `batten.toml`"],
        dont: &["delete the recorder"],
    },
    VendoredDoc {
        id: "record declare refused",
        why: Some("A family that can never be written only ever answers could-not-look"),
        act: &["fix the `[[record]]` row's name or writer, in `batten.toml`"],
        dont: &["delete the family"],
    },
    VendoredDoc {
        id: "provision declare refused",
        why: Some("A tool that cannot be provisioned turns its rule into a missing-scanner report"),
        act: &["fix the `[[provision]]` row the refusal names, in `batten.toml`"],
        dont: &["delete the row to make the config load"],
    },
    VendoredDoc {
        id: "startup declare refused",
        why: Some(
            "A row that can never decide reports a broken container every session with no repair",
        ),
        act: &["fix the `[[startup]]` row the refusal names, in `batten.toml`"],
        dont: &["delete the row to make the config load"],
    },
    VendoredDoc {
        id: "step declare refused",
        why: Some("A malformed step receipt attests bytes nobody checked"),
        act: &["give the `[[step]]` row real inputs and tools, in `batten.toml`"],
        dont: &["empty its inputs"],
    },
    // ── commit-msg ──────────────────────────────────────────────────────────
    VendoredDoc {
        id: "commit spelling wrong",
        why: Some("The changelog and version bump are derived from commit subjects"),
        act: &[
            "rewrite the subject to match `[commit] subject_pattern`",
            "commit with `git commit -F <path>`",
        ],
        dont: &["bypass the commit-msg hook"],
    },
    VendoredDoc {
        id: "commit name missing",
        why: Some("A reviewer and a workflow can see a claim only in the commit message"),
        act: &["add the closing keyword or reference trailer for the row this commit serves"],
        dont: &["name a row the commit does not serve"],
    },
    VendoredDoc {
        id: "commit admit missing",
        why: Some(
            "The reasoning that admitted a protected write must travel in the commit that made it",
        ),
        act: &[
            "issue an admission with `batten override request` for the class that refused the write",
            "spend it with `batten override spend` and carry the block it prints",
        ],
        dont: &["write the block by hand"],
    },
    VendoredDoc {
        id: "commit admit other",
        why: Some(
            "A block that does not hash to its address was edited after issue, or assembled by hand",
        ),
        act: &["issue a fresh admission and carry the block it prints verbatim"],
        dont: &["edit the block's text"],
    },
    VendoredDoc {
        id: "commit admit same",
        why: Some("A commit that adds a conserves arm and spends it authorizes itself"),
        act: &[
            "unstage the spend with `git restore --staged <path>`",
            "land the arm first, then spend it in a later commit",
        ],
        dont: &["ask for an override; none exists here"],
    },
    VendoredDoc {
        id: "commit own refused",
        why: Some("The author or committer is an identity the attribution policy denies"),
        act: &[
            "set the accountable identity with `batten attribution identity`",
            "then re-create the commit",
        ],
        dont: &["set a vendor committer because a hook asked for one"],
    },
    VendoredDoc {
        id: "commit carry refused",
        why: Some("The trailer's value is exactly what the policy keeps out of history"),
        act: &["rewrite the message without that trailer and commit with `git commit -F <path>`"],
        dont: &["move the same text into the body"],
    },
    VendoredDoc {
        id: "commit state refused",
        why: Some("A phrasing in the body discloses what a refused trailer would"),
        act: &["rewrite the message without it and commit with `git commit -F <path>`"],
        dont: &["respell the same disclosure"],
    },
    VendoredDoc {
        id: "tag own refused",
        why: Some("A release tag must be cut by the identity the policy names"),
        act: &[
            "delete the tag with `git tag -d <tag>`",
            "cut it again under the accountable identity",
        ],
        dont: &["push the tag as it stands"],
    },
    VendoredDoc {
        id: "tag own unnamed",
        why: Some(
            "A tag with no tagger cannot be judged, and reading that absence as accountable passes anyone",
        ),
        act: &[
            "delete it with `git tag -d <tag>`",
            "replace it with an annotated `git tag -a <tag>`",
        ],
        dont: &["re-cut it as another lightweight tag"],
    },
    VendoredDoc {
        id: "prose declare refused",
        why: Some(
            "Every config string is echoed into every reader's context, so its length is paid each time",
        ),
        act: &[
            "shorten the value the refusal names; put provenance in a TOML comment beside the row",
        ],
        dont: &["split the text across columns to dodge the cap"],
    },
    // ── preset: check-verdict ───────────────────────────────────────────────
    VendoredDoc {
        id: "check grade red",
        why: Some(
            "The check's latest run on this commit objected, and an older success does not answer for it",
        ),
        act: &[
            "read the run's details page for what it objected to",
            "fix it locally and push",
        ],
        dont: &["re-run the check unchanged hoping for green"],
    },
    VendoredDoc {
        id: "check grade early",
        why: Some("A run still in flight, skipped or cancelled has not judged the commit"),
        act: &[
            "re-query the commit's check-runs with `batten record query check-runs` once it has graded",
        ],
        dont: &["read a skip or cancel as a pass"],
    },
    VendoredDoc {
        id: "check read partial",
        why: Some("A part of a commit's check-runs is never judged as all of them"),
        act: &[
            "for a truncated window, raise or narrow the query's page budget and re-query",
            "for a torn or unclosed record, stop the other writer of the family and re-mint it",
        ],
        dont: &["hand-edit the record"],
    },
    // ── preset: ci-hygiene ──────────────────────────────────────────────────
    VendoredDoc {
        id: "workflow parse unseen",
        why: Some(
            "A workflow that will not parse is read by no rule here, so it would report green",
        ),
        act: &["fix the YAML of the workflow the line names"],
        dont: &["delete the workflow to clear the finding"],
    },
    VendoredDoc {
        id: "cache build loose",
        why: Some("A cache-warming build that saves nothing recompiles on every run for nothing"),
        act: &["guard the compile step on the cache restore's hit flag"],
        dont: &["delete the cache step"],
    },
    VendoredDoc {
        id: "cache name unknown",
        why: Some(
            "A guard naming a missing step reads empty, so the build compiles every time with no signal",
        ),
        act: &["point the guard at the restore step's real id"],
        dont: &["drop the guard"],
    },
    VendoredDoc {
        id: "event bind loose",
        why: Some("An unanchored test on a comment body fires whenever anyone writes the token"),
        act: &["anchor the predicate to the whole body or its first line"],
        dont: &["rename the token so this repository's prose stops tripping it"],
    },
    VendoredDoc {
        id: "event reach dead",
        why: Some("A trigger whose every job skips makes a run that did nothing"),
        act: &["admit the event in the job conditions, or drop the trigger"],
        dont: &["leave both"],
    },
    VendoredDoc {
        id: "input render dropped",
        why: Some(
            "YAML opens a comment at an unquoted space-hash, so the value is truncated before the forge sees it",
        ),
        act: &["quote the value on the line the finding names"],
        dont: &["trust that the linter passed it"],
    },
    VendoredDoc {
        id: "job require unseen",
        why: Some(
            "A fan-in that lists its dependencies goes stale, so a red leg can leave the required check green",
        ),
        act: &["make the fan-in assert over all of its needs, not a named list"],
        dont: &["add the missing name to the list"],
    },
    VendoredDoc {
        id: "job run early",
        why: Some(
            "A job without the draft guard spends a runner on a pull request still being verified",
        ),
        act: &["add the draft guard to the job's condition"],
        dont: &["un-draft to get the run"],
    },
    VendoredDoc {
        id: "job start same",
        why: Some("Two schedules on the same minute contend for the same runners"),
        act: &["move one schedule to an unused minute"],
        dont: &["merge the two workflows"],
    },
    VendoredDoc {
        id: "merge run early",
        why: Some(
            "A merge path that never reads the draft state can advance the trunk to a commit CI never ran on",
        ),
        act: &["read the pull request's draft state in the merge job and refuse a draft"],
        dont: &["rely on the ruleset to catch it"],
    },
    VendoredDoc {
        id: "review watch missing",
        why: Some(
            "A draft-gated workflow with no `ready_for_review` can never replace the run it skipped",
        ),
        act: &["add `ready_for_review` to the `pull_request` trigger's `types`"],
        dont: &["read the skipped run as an answer"],
    },
    VendoredDoc {
        id: "workflow declare missing",
        why: Some("A workflow with no concurrency group can race itself"),
        act: &["declare a `concurrency` group; a schedule must not cancel its own previous tick"],
        dont: &["serialise it by hand in a step"],
    },
    VendoredDoc {
        id: "workflow run loose",
        why: Some("A branch scope in a job condition creates a run and then skips it"),
        act: &["move the branch filter onto the `workflow_run` trigger"],
        dont: &["keep the job-level filter as well"],
    },
    VendoredDoc {
        id: "workflow run twice",
        why: Some(
            "Without `cancel-in-progress` a superseded commit's run is billed in full for a verdict nobody reads",
        ),
        act: &["set `cancel-in-progress: true` (a boolean) in the concurrency block"],
        dont: &["write it as the string `\"true\"`"],
    },
    // ── preset: ci-signal ───────────────────────────────────────────────────
    VendoredDoc {
        id: "lane read partial",
        why: Some(
            "A walk that stopped on a capped page read a prefix, so its green covers less than it claims",
        ),
        act: &["narrow the window and re-run `batten record divergence`"],
        dont: &["read the partial count as the whole window"],
    },
    VendoredDoc {
        id: "lane count spent",
        why: Some("Each extra CI matrix per landing is a run whose verdict nobody needed"),
        act: &["find what bought the extra runs in the recorded divergence, and fix that source"],
        dont: &["raise the budget to fit"],
    },
    VendoredDoc {
        id: "lane grade red",
        why: Some("A red CI run means local verification was skipped or disagreed with CI"),
        act: &["run `mise run verify` before readying, and fix where it disagrees with CI"],
        dont: &["push to see if CI goes green"],
    },
    VendoredDoc {
        id: "lane reach late",
        why: Some("A late cancellation bills a matrix for a verdict nobody reads"),
        act: &["make the cancel fire early: a lease precondition or `cancel-in-progress`"],
        dont: &["count cancellations instead of timing them"],
    },
    VendoredDoc {
        id: "lease guard dropped",
        why: Some(
            "Matrices above the lease's bound mean something spends CI without holding the lease",
        ),
        act: &["find the run that started without the lease and route it through `mise run land`"],
        dont: &["raise the admitted bound"],
    },
    VendoredDoc {
        id: "lane measure late",
        why: Some("Runs queueing at p90 means the runner pool is saturating"),
        act: &["reduce concurrent demand on the pool, or add capacity"],
        dont: &["read it as landing contention"],
    },
    VendoredDoc {
        id: "job measure late",
        why: Some("Legs queueing behind their siblings means the matrix is too wide for the pool"),
        act: &["narrow the matrix or stagger its legs"],
        dont: &["read it as a saturated pool"],
    },
    VendoredDoc {
        id: "branch reach stale",
        why: Some(
            "A refused fast-forward means the branch went behind, which the lease exists to prevent",
        ),
        act: &["land through the lease with `mise run land`"],
        dont: &["request the fast-forward by hand"],
    },
    VendoredDoc {
        id: "job read partial",
        why: Some(
            "A scan that read part of its window reports a budget met over nothing in particular",
        ),
        act: &[
            "fix the token or rate limit behind the read failure, then re-run `batten record nonverdict`",
        ],
        dont: &["read the partial scan as clean"],
    },
    VendoredDoc {
        id: "job answer missing",
        why: Some(
            "A required job that failed before any verdict step reds the branch and answers nothing",
        ),
        act: &["fix the setup step that failed (checkout, install, toolchain), then re-run"],
        dont: &["try to reproduce a test failure that never ran"],
    },
    VendoredDoc {
        id: "bound pin loose",
        why: Some("A timeout far above what the job needs lets the budget rot upward"),
        act: &[
            "re-run the writer the `drift-runs` and `drift-jobs` rows name, and commit the re-derived timeout",
        ],
        dont: &["leave the slack because nothing is failing"],
    },
    VendoredDoc {
        id: "bound pin wrong",
        why: Some(
            "The job's p95 with headroom already exceeds its timeout, so healthy runs will start failing",
        ),
        act: &["re-run the drift writer and raise the timeout to the re-derived value"],
        dont: &["wait for it to fail first"],
    },
    VendoredDoc {
        id: "bound pin stale",
        why: Some("A dated debt entry now has enough runs to become a measured budget"),
        act: &["re-run the drift writer and convert the entry in a deliberate commit"],
        dont: &["let a bot re-baseline the number it defends"],
    },
    VendoredDoc {
        id: "bound measure partial",
        why: Some("Too few runs, or a torn record, cannot characterise a job"),
        act: &[
            "re-run the drift writer; a rarely-run job stays a dated debt entry until it has samples",
        ],
        dont: &["tighten its timeout from a handful of runs"],
    },
    VendoredDoc {
        id: "plan write refused",
        why: Some(
            "Plan mode promises nothing changes until the plan is approved, and the host would otherwise halt on a prompt",
        ),
        act: &[
            "call ExitPlanMode, then make the call",
            "keep to reads and the plan file while planning",
        ],
        dont: &["retry the write inside plan mode"],
    },
    VendoredDoc {
        id: "grant spelling wrong",
        why: Some(
            "The host skips an MCP rule whose server segment is a glob, so every call prompts",
        ),
        act: &["name the server literally: `mcp__<server>` or `mcp__<server>__<tool>`"],
        dont: &["glob the server segment or write a bare `*`"],
    },
    VendoredDoc {
        id: "grant name missing",
        why: Some(
            "Enabling a project server grants none of its tools, so every call stops for a human",
        ),
        act: &["add an allow rule naming the server, or stop enabling it"],
        dont: &[],
    },
    VendoredDoc {
        id: "connector deny loose",
        why: Some(
            "A host-supplied connector is renamed per registration, so a deny naming one spelling enforces nothing",
        ),
        act: &["add a `mediated_call` rule keyed on the tool's own suffix"],
        dont: &["deny by one server prefix"],
    },
    VendoredDoc {
        id: "grant read unread",
        why: Some(
            "A settings file that will not parse was never judged, which is not a clean tree",
        ),
        act: &["make the named file parse as JSON, then re-run `batten check`"],
        dont: &["read the silence as no defects"],
    },
    VendoredDoc {
        id: "commit ship empty",
        why: Some(
            "An empty commit records only a wish for a new SHA and re-asks a recorded answer",
        ),
        act: &["re-run the pipeline instead"],
        dont: &["push an empty commit to kick CI"],
    },
    VendoredDoc {
        id: "head grade twice",
        why: Some(
            "An unchanged commit cannot get a different verdict, so a second run spends the metered tier for nothing",
        ),
        act: &[
            "read the forge's recorded verdict for this commit",
            "change the commit if different work is to be judged",
        ],
        dont: &["re-run because the answer was unwelcome"],
    },
    VendoredDoc {
        id: "lease grant other",
        why: Some(
            "Another branch holds the landing lease, so CI bought now is invalidated by its merge",
        ),
        act: &["wait for the lease to lapse or be released, or reserve the slot behind the holder"],
        dont: &["start a matrix while another branch holds the lease"],
    },
    VendoredDoc {
        id: "patch ship twice",
        why: Some(
            "The target already carries these changes by patch identity, so landing again holds the slot for a no-op",
        ),
        act: &["close the branch, or rebase onto the target and see what is left"],
        dont: &["re-land because ancestry differs after a squash or rebase"],
    },
    VendoredDoc {
        id: "replay halt conflict",
        why: Some(
            "A lap that continues past a conflicted replay pushes a head that was never completed",
        ),
        act: &[
            "resolve the conflict with `batten land replay <ref> --resolve <path>`, then lap again",
        ],
        dont: &[
            "pick a merge strategy that makes the conflict vanish",
            "push the half-applied head",
        ],
    },
    VendoredDoc {
        id: "wait read both",
        why: Some(
            "A lap's wait is a race whose loser is voided, and reading both sides spends what the race saves",
        ),
        act: &["act on the answer that arrived first and abandon the other unread"],
        dont: &["cancel the superseded run by hand"],
    },
    VendoredDoc {
        id: "task reach loose",
        why: Some(
            "A task fixes the program, arguments and environment, and calling the program directly drops the environment",
        ),
        act: &["run the task the refusal names through the task runner"],
        dont: &["reproduce the task's argv by hand"],
    },
    VendoredDoc {
        id: "job pin other",
        why: Some(
            "A CI install that resolves its own version runs a toolchain other than the one the tree pins",
        ),
        act: &["declare the pinned version at the install step"],
        dont: &["let the action resolve a version independently"],
    },
    VendoredDoc {
        id: "job pin missing",
        why: Some(
            "An install step with no version makes the toolchain a property of when the job ran",
        ),
        act: &["declare the pinned version at the install step"],
        dont: &[],
    },
    VendoredDoc {
        id: "workflow parse unread",
        why: Some("A workflow that will not parse was never compared, which is not a pass"),
        act: &["fix the named workflow so it parses, then check again"],
        dont: &[],
    },
    VendoredDoc {
        id: "pin reach loose",
        why: Some(
            "A program reached around the pin runs another version or misses the project's environment",
        ),
        act: &["run it as `mise exec -- <program>` or through its task"],
        dont: &["call the bare binary from PATH"],
    },
    VendoredDoc {
        id: "pin probe bare",
        why: Some(
            "A bare-PATH probe answers empty for a pinned tool, which reads wrongly as not installed",
        ),
        act: &["probe inside the pin, such as `mise which <program>`"],
        dont: &["route around a tool because a bare probe found nothing"],
    },
    VendoredDoc {
        id: "release pin broken",
        why: Some(
            "A checksum manifest that disagrees with the release pins nothing a packager can trust",
        ),
        act: &["run `batten release sums <tag> --manifest <name>` and upload what it writes"],
        dont: &["hand-edit the manifest"],
    },
    VendoredDoc {
        id: "release record torn",
        why: Some("A record without a matching census would judge part of a release as all of it"),
        act: &["run `batten record release <tag> --manifest <name>` again"],
        dont: &[],
    },
    VendoredDoc {
        id: "program name unnamed",
        why: Some(
            "Tools that select by extension skip a shell file whose name hides its language, and exit 0",
        ),
        act: &["`git mv` it to a name carrying its language"],
        dont: &[],
    },
    VendoredDoc {
        id: "program resolve missing",
        why: Some("A computed sibling path guarded by a test goes silent when the file is absent"),
        act: &["add the file, or assert the path rather than testing it"],
        dont: &[],
    },
    VendoredDoc {
        id: "task write refused",
        why: Some("This repository declared its manifest shell may only fall"),
        act: &[
            "move the decision into a policy module, the fetch into a recorder, and call a verb",
        ],
        dont: &["relocate the body into another command string"],
    },
    VendoredDoc {
        id: "task add refused",
        why: Some(
            "A unit that carried no shell at the base may not gain some, even if lines fall elsewhere",
        ),
        act: &["put the logic in a verb or module and call it"],
        dont: &["offset it by deleting shell in another unit"],
    },
    VendoredDoc {
        id: "step write refused",
        why: Some("A declared workflow's shell lines may only fall"),
        act: &["move the logic into a declared task or the engine and call it from the step"],
        dont: &[],
    },
    VendoredDoc {
        id: "shell place refused",
        why: Some(
            "Only files that must run where nothing else can are shell, and the census declaration names them",
        ),
        act: &["write it as a verb, module or recorder"],
        dont: &["add a `.sh`, `.bash` or `.bats` file outside the declared set"],
    },
    VendoredDoc {
        id: "diff key missing",
        why: Some(
            "A tracker moves a row only for a closing reference, so a bare mention merges and moves nothing",
        ),
        act: &[
            "write the closing keyword before the key, or a hold marker line",
            "then `batten record derive closing-key`",
        ],
        dont: &[],
    },
    VendoredDoc {
        id: "diff key dropped",
        why: Some("A served key the body does not close never reaches review"),
        act: &[
            "close each served key or name it on a hold line",
            "then `batten record derive closing-key`",
        ],
        dont: &[],
    },
    VendoredDoc {
        id: "diff read partial",
        why: Some("A record missing a reading would decide over part of the answer"),
        act: &["run `batten record derive closing-key` again"],
        dont: &[],
    },
    VendoredDoc {
        id: "prose own unnamed",
        why: Some("A pull-request body is not a durable home, so a deferral there has no owner"),
        act: &[
            "file the owning issue and name its key in that paragraph",
            "then `batten record derive deferral`",
        ],
        dont: &["name the key this pull request already claims as the owner"],
    },
    VendoredDoc {
        id: "prose read partial",
        why: Some("A torn deferral record would judge part of a body as all of it"),
        act: &["run `batten record derive deferral` again"],
        dont: &[],
    },
    VendoredDoc {
        id: "issue ship early",
        why: Some("An issue is done only when every pull request it carries has landed or closed"),
        act: &["land or close the open pull request the refusal names"],
        dont: &["move the row to Done with a draft still open"],
    },
    VendoredDoc {
        id: "issue point missing",
        why: Some("Review already requires a linked pull request, so Done cannot need less"),
        act: &["attach the pull request that did the work"],
        dont: &[],
    },
    VendoredDoc {
        id: "issue list partial",
        why: Some("A torn done-pr record would judge part of a board as all of it"),
        act: &["run `batten record derive done-pr` again"],
        dont: &[],
    },
    VendoredDoc {
        id: "issue ship ahead",
        why: Some("Done means released, and work on the trunk that no tag reaches has not shipped"),
        act: &["move it back to In Review until a release carries it"],
        dont: &[],
    },
    VendoredDoc {
        id: "issue read partial",
        why: Some(
            "A done record whose census is absent or wrong is an unfinished write, not a clean board",
        ),
        act: &["run `batten record derive done` again"],
        dont: &[],
    },
    VendoredDoc {
        id: "issue ship held",
        why: Some("The row's own description holds it open, so shipping it does not finish it"),
        act: &["resolve the hold, or strike the marker, before moving it to Done"],
        dont: &[],
    },
    VendoredDoc {
        id: "issue ship refused",
        why: Some(
            "Done needs the release and an honest board, and the board gate rejects this row's column",
        ),
        act: &["run `batten board check` and fix the rule it names"],
        dont: &[],
    },
    VendoredDoc {
        id: "tag read partial",
        why: Some("A torn released record would judge part of a release as all of it"),
        act: &["run `batten record derive released` again"],
        dont: &[],
    },
    VendoredDoc {
        id: "issue grade twice",
        why: Some(
            "A duplicate close taken in the same second as its target's close was never argued",
        ),
        act: &[
            "argue the duplicate on its own, or reopen it if it says something the survivor does not",
        ],
        dont: &[],
    },
    VendoredDoc {
        id: "issue count partial",
        why: Some("A torn duplicate-close record would judge part of a board as all of it"),
        act: &["run `batten record derive duplicate-close` again"],
        dont: &[],
    },
    VendoredDoc {
        id: "issue state wrong",
        why: Some("A column is a claim about the work that everyone else reads"),
        act: &[
            "move the named row to the column its tree and board support",
            "fix the rule the pointer names",
        ],
        dont: &["leave a note inside the row instead of moving it"],
    },
    VendoredDoc {
        id: "issue judge partial",
        why: Some(
            "A set read only in part cannot be judged, and a re-fetch may surface more refusals",
        ),
        act: &["fetch the named rows again with relations and attachments, then pipe the set"],
        dont: &[],
    },
    VendoredDoc {
        id: "path point missing",
        why: Some("A Ready block citing what the tree does not carry points a reader at nothing"),
        act: &["cite a test the corpus carries and a path that exists, or mark a path prospective"],
        dont: &["cite a fixture that quotes the test"],
    },
    VendoredDoc {
        id: "source point wrong",
        why: Some("A citation of a clause the issue does not carry points at nothing"),
        act: &["cite the clause that holds the content"],
        dont: &[],
    },
    VendoredDoc {
        id: "source point unread",
        why: Some("An unfetched issue looks exactly like a clean one"),
        act: &["fetch the cited issue and pipe the set again"],
        dont: &[],
    },
    VendoredDoc {
        id: "release ship unsafe",
        why: Some("The platform offers attestation and this release's binary carries none"),
        act: &["attest the binary, then `batten record attestation <tag> --binary <name>`"],
        dont: &["attest the archive instead of the executable"],
    },
    VendoredDoc {
        id: "release carry missing",
        why: Some("The archive held no binary of the declared name, which is a packaging fault"),
        act: &["fix the build matrix, then `batten record attestation <tag> --binary <name>`"],
        dont: &["chase a signing identity"],
    },
    VendoredDoc {
        id: "release list empty",
        why: Some("A green verdict over a tag with no archives would be about nothing"),
        act: &["publish the archives, then `batten record attestation <tag> --binary <name>`"],
        dont: &[],
    },
    VendoredDoc {
        id: "config carry unsafe",
        why: Some("A signature from an unverifiable key looks like provenance and carries none"),
        act: &["run `batten attribution signing`"],
        dont: &[],
    },
    VendoredDoc {
        id: "commit carry unsafe",
        why: Some("Commits signed before a config repair still carry the unverifiable signature"),
        act: &["rewrite the range unsigned, or publish the key's public half"],
        dont: &["treat a repaired config as clearing these commits"],
    },
    VendoredDoc {
        id: "cargo list empty",
        why: Some("An inventory of under two crates is an empty document that exits 0"),
        act: &[
            "rebuild through `cargo auditable`, then `batten sbom --binary <binary> --target <triple>`",
        ],
        dont: &[],
    },
    VendoredDoc {
        id: "cargo list wrong",
        why: Some("A crate outside the lockfile means the binary was not built from it"),
        act: &[
            "rebuild from this lockfile, then `batten sbom --binary <binary> --target <triple>`",
        ],
        dont: &[],
    },
    VendoredDoc {
        id: "trunk push forced",
        why: Some("Rewriting a published branch breaks every existing checkout of it"),
        act: &["`git push --force-with-lease=<ref>:<sha>`"],
        dont: &["use a bare `--force-with-lease`, which compares a stale tracking ref"],
    },
    // ── the unclassed emitters' classes ─────────────────────────────────────
    VendoredDoc {
        id: "input parse refused",
        why: Some("A verb that cannot use its input decided nothing about the work"),
        act: &[
            "fix the input the subject names",
            "check the spelling with `batten --help`",
        ],
        dont: &["read the refusal as a verdict on the tree"],
    },
    VendoredDoc {
        id: "verb run broken",
        why: Some("An internal failure means the verb could not look, so it decided nothing"),
        act: &[
            "run `batten doctor` for the environment",
            "file the chain as a Batten defect when it repeats on an unchanged tree",
        ],
        dont: &["read exit 3 as a pass or a refusal", "retry it in a loop"],
    },
    VendoredDoc {
        id: "issue file refused",
        why: Some("A row filed from an unreadable pull request would track the wrong work"),
        act: &["fix what the subject names on the pull request, then derive again"],
        dont: &["file the row by hand"],
    },
    VendoredDoc {
        id: "layer carry refused",
        why: Some("An override that loosens the committed authority is a second authority"),
        act: &["change the committed value instead, in its own reviewed commit"],
        dont: &["split the layer to slip part of it through"],
    },
    VendoredDoc {
        id: "provision pin other",
        why: Some("Bytes that do not match the pin are not the program that was reviewed"),
        act: &[
            "re-pin from the published digest if the release moved",
            "run `batten provision apply` again",
        ],
        dont: &["skip the checksum", "install the artifact by hand"],
    },
    VendoredDoc {
        id: "commit ship missing",
        why: Some("Committed work that never lands is invisible to everyone and lost on reclaim"),
        act: &[
            "land it with `batten land lap`",
            "or say in the turn what blocks it",
        ],
        dont: &["end the turn calling unlanded work done"],
    },
    VendoredDoc {
        id: "issue list unclear",
        why: Some("A row filed mid-task is either new work or this task deferred"),
        act: &[
            "answer each listed row by number",
            "close here the ones that are this task's",
        ],
        dont: &["leave a deferral filed as if it were new work"],
    },
    VendoredDoc {
        id: "hook report now",
        why: Some("A declared handler is the repository speaking about this call"),
        act: &[
            "act on what the subject says",
            "read its `[[hook.handler]]` row for what it guards",
        ],
        dont: &[],
    },
    VendoredDoc {
        id: "hook answer broken",
        why: Some("A handler outside its contract answered nothing the boundary can use"),
        act: &["fix the handler's program, timeout or output the subject names"],
        dont: &["remove the handler row to silence it"],
    },
    VendoredDoc {
        id: "output write missing",
        why: Some("A response nobody captured cannot be handed over later without re-reading it"),
        act: &[
            "re-run the read when its bytes are needed",
            "run `batten doctor` if it recurs",
        ],
        dont: &[],
    },
    VendoredDoc {
        id: "workspace state broken",
        why: Some("A gate whose program, pin or provision is absent cannot run here"),
        act: &[
            "run `batten startup --repair`",
            "then `batten doctor` for what is left",
        ],
        dont: &["work on as if the gates had run"],
    },
    VendoredDoc {
        id: "call grant now",
        why: Some("A call the policy already admits needs no prompt"),
        act: &["proceed with the call"],
        dont: &[],
    },
    VendoredDoc {
        id: "commit port blocked",
        why: Some("A conflict is the one landing step only its author can decide"),
        act: &[
            "merge each listed path in the worktree",
            "run `batten land replay <base> --resolve <path>`",
        ],
        dont: &[
            "reach for `--continue`, which has nothing to act on",
            "cherry-pick around it",
        ],
    },
    VendoredDoc {
        id: "check run red",
        why: Some("A head the declared gate refuses is not one to push"),
        act: &[
            "fix the cause the line names",
            "run `batten land verify` again",
        ],
        dont: &["push around the gate"],
    },
    VendoredDoc {
        id: "job run red",
        why: Some("A head red in CI is not one to land"),
        act: &[
            "reproduce each named check locally and fix it",
            "run `batten land verify` again",
        ],
        dont: &["re-run CI on the same head to see if it passes"],
    },
    VendoredDoc {
        id: "lane run spent",
        why: Some("A loop that never lands spends CI on a target that keeps moving"),
        act: &["run `batten land lap` again once the target settles"],
        dont: &["raise the lap bound to push through"],
    },
    VendoredDoc {
        id: "contract read stale",
        why: Some("A rule read in its old form is one this session is not following"),
        act: &[
            "re-read each `changed` path before the next lifecycle step",
            "read each `added` path before judging it irrelevant",
            "run `batten doctor hooks` when the wiring moved",
        ],
        dont: &["treat an added path as a changed rule"],
    },
    VendoredDoc {
        id: "hook run missing",
        why: Some("An absent gate and a passing one look the same from outside"),
        act: &[
            "install the engine where the host resolves it by bare name",
            "run `batten doctor` to see which binary `PATH` finds",
        ],
        dont: &["assume the calls before this one were checked"],
    },
    VendoredDoc {
        id: "drain fit broken",
        why: Some("A cut drain is a turn that produced more than the delta shape holds"),
        act: &[
            "read the cut rules with `batten state list --rule <id>`",
            "fix the turn's findings before adding more",
        ],
        dont: &["raise the token budget to make the cut go away"],
    },
    VendoredDoc {
        id: "issue grade refused",
        why: Some("An issue that fails a Ready clause is pulled before it can be done"),
        act: &[
            "edit the description at the line the subject names",
            "re-run `batten ready lint` on the edited body",
        ],
        dont: &["move the issue to Todo while a clause fails"],
    },
    VendoredDoc {
        id: "issue grade partial",
        why: Some("A citation judged without relations would pass by not looking"),
        act: &["fetch the issue with its relations and lint it again"],
        dont: &["read the gap as a pass"],
    },
    VendoredDoc {
        id: "claim mint refused",
        why: Some("Two sessions on one issue do the work twice and land neither cleanly"),
        act: &[
            "pick another issue from the ready queue",
            "take it over with `--takeover` only when the holder has stopped",
        ],
        dont: &["start the work without the claim receipt"],
    },
];

/// The vendored doc for `id`, or an empty one where none is declared.
#[must_use]
pub fn vendored(id: &str) -> Doc {
    VENDORED_DOCS
        .iter()
        .find(|entry| entry.id == id)
        .map(VendoredDoc::to_doc)
        .unwrap_or_default()
}

/// The sections after the gloss as the full arm prints them, each a sentence.
///
/// `act` is the class's `do` unless the firing row declared its own remedy,
/// which replaces it (the rule's `reason`, CLOUD-2143).
#[must_use]
pub fn render(doc: &Doc, act: &[&str]) -> String {
    let mut out = String::new();
    if let Some(why) = doc.why.as_deref() {
        push_sentence(&mut out, why);
    }
    if !act.is_empty() {
        push_sentence(&mut out, &format!("Do: {}", act.join("; ")));
    }
    if !doc.dont.is_empty() {
        let dont: Vec<&str> = doc.dont.iter().map(String::as_str).collect();
        push_sentence(&mut out, &format!("Don't: {}", dont.join("; ")));
    }
    out
}

/// Append `text` as one sentence: a space before it, a full stop after it.
fn push_sentence(out: &mut String, text: &str) {
    let text = text.trim().trim_end_matches(['.', ';']);
    if text.is_empty() {
        return;
    }
    if !out.is_empty() {
        out.push(' ');
    }
    out.push_str(text);
    out.push('.');
}

/// Why a doc does not load, or `None` when it does.
///
/// `rendered` is the whole first-sighting body the class produces — gloss, these
/// sections and its admissible preconditions — measured against [`DOC_BYTES`].
//MUTANT doc-cap-unchecked|s@^    if rendered.len() > DOC_BYTES {$@    if false {@|a_class_doc_over_640_bytes_does_not_load
#[must_use]
pub fn violation(doc: &Doc, rendered: &str) -> Option<String> {
    if rendered.len() > DOC_BYTES {
        return Some(format!(
            "renders to {} bytes, over the {DOC_BYTES}-byte (160-token) budget a first \
             sighting may spend; move rationale to `class`",
            rendered.len()
        ));
    }
    if let Some(why) = doc.why.as_deref()
        && !one_sentence(why)
    {
        return Some("`doc.why` is ONE sentence".to_owned());
    }
    for (name, items) in [("do", &doc.act), ("dont", &doc.dont)] {
        if items.len() > ITEMS_MAX {
            return Some(format!(
                "`doc.{name}` carries {} items; at most {ITEMS_MAX}",
                items.len()
            ));
        }
        if items.iter().any(|item| item.trim().is_empty()) {
            return Some(format!("`doc.{name}` has an empty item"));
        }
    }
    let sections = doc.why.iter().chain(&doc.act).chain(&doc.dont);
    for text in sections {
        if cites_issue_key(text) {
            return Some(
                "a doc section cites an issue key; history belongs in `class`, \
                 which `explain` prints"
                    .to_owned(),
            );
        }
    }
    None
}

/// Whether `text` holds no sentence boundary before its end: a terminator, then
/// whitespace, then a capital — so `e.g. this` and `run x.y` stay one sentence.
fn one_sentence(text: &str) -> bool {
    let chars: Vec<char> = text.trim().chars().collect();
    !chars.windows(3).any(|three| {
        matches!(three[0], '.' | '!' | '?') && three[1].is_whitespace() && three[2].is_uppercase()
    })
}

/// Whether `text` names an issue key: an uppercase prefix, a dash, digits.
fn cites_issue_key(text: &str) -> bool {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
        .any(|word| {
            let Some((prefix, number)) = word.split_once('-') else {
                return false;
            };
            prefix.len() >= 2
                && prefix.chars().all(|c| c.is_ascii_uppercase())
                && !number.is_empty()
                && number.chars().all(|c| c.is_ascii_digit())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(why: Option<&str>, act: &[&str], dont: &[&str]) -> Doc {
        Doc {
            why: why.map(str::to_owned),
            act: act.iter().map(|item| (*item).to_owned()).collect(),
            dont: dont.iter().map(|item| (*item).to_owned()).collect(),
        }
    }

    #[test]
    fn the_sections_render_as_sentences_in_order() {
        let rendered = render(
            &doc(Some("A reader loses the file"), &[], &["retry it verbatim"]),
            &["run `x`", "read y"],
        );
        assert_eq!(
            rendered,
            "A reader loses the file. Do: run `x`; read y. Don't: retry it verbatim."
        );
    }

    #[test]
    fn a_why_of_two_sentences_does_not_load() {
        let two = doc(Some("One thing. Another thing."), &["x"], &[]);
        assert!(violation(&two, "short").is_some());
        let one = doc(Some("One thing, e.g. this."), &["x"], &[]);
        assert_eq!(violation(&one, "short"), None);
    }

    #[test]
    fn four_items_do_not_load() {
        let four = doc(None, &["a", "b", "c", "d"], &[]);
        assert!(violation(&four, "short").is_some());
    }

    #[test]
    fn an_issue_key_is_found_and_a_kebab_word_is_not() {
        assert!(cites_issue_key("see CLOUD-2143 for why"));
        assert!(!cites_issue_key("run `land-lock` or check o200k-base"));
    }
}
