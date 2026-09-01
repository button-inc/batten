//! Non-negotiable rule 4, made total and given an exit code (CLOUD-92).
//!
//! "Output is a pointer, never the payload" (house-style §6) was stated as a law
//! and enforced nowhere. Every emitting module vouched for itself in its own doc
//! comment and, at best, in one hand-written case — `outputs.rs` has
//! `a_match_points_at_its_line_and_never_carries_the_bytes`,
//! `extension_surfaces.rs` has one `!stderr.contains(…)`. Those are per-site
//! claims. None of them can answer the question the law actually poses: *is there
//! a remaining check that leaks content?* A rule without a runnable gate is half a
//! change (rule 2), and this is the other half.
//!
//! ## Why this sits at the process boundary rather than at the emitters
//!
//! There is no shared emission path for the data channel. `output.rs` funnels
//! *stderr* through `message`/`error`/`verdict`, but each takes a `&str` the
//! caller already composed; stdout has no funnel at all — ~30 inline
//! `writeln!(out, …)` sites in `lib.rs`, fed by ten independently-named renderers
//! (`line`, `line_text`, `summary`) plus `rules::Finding`, which has none and is
//! formatted inline. Unifying those is real work and a different change
//! (CLOUD-371); it would also not *decide* anything, because no trait can stop a
//! `String` carrying content.
//!
//! So the gate goes where every one of those sites already converges: the bytes
//! the process actually wrote. One mechanism, no call-site edits, and it cannot
//! be routed around by an emitter that spells its renderer a new way.
//!
//! ## What it decides
//!
//! A **corpus** in which every byte a check can read as subject matter is a
//! distinct canary token, crossed with a **census** over every leaf verb of
//! [`batten::surface::SURFACE`]. The census is the totality proof: a verb added
//! tomorrow lands in no bucket and fails [`every_leaf_verb_is_classified`] until
//! somebody says which bucket it is in. That is the property CLOUD-92 asks for —
//! not "the checks we thought of do not leak", but "no check leaks, and a new one
//! cannot quietly join without answering the question".
//!
//! ## Two classes of canary, because rule 4 is about content and not about config
//!
//! * **Content** — bytes a check read as its *subject*: a matched line, a counted
//!   file's body, a transcript's free text, a wrapped child's stream. These are
//!   what the law is about, and **no verb may emit one**.
//! * **Declaration** — bytes the caller *wrote as policy*: a rule's `pattern`, a
//!   waiver's `reason`, a ledger row's `evidence`. Echoing these back is what
//!   `config show` and `generate schema` are *for*, so the law cannot mean them.
//!
//! Collapsing the two would make the gate either vacuous (exempt every verb that
//! prints config) or false (fail `config show` for doing its job).

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::io::Write as _;
use std::path::PathBuf;
use std::process::Stdio;

use batten::surface::SURFACE;
use common::{Fixture, StateHome, batten, scratch};

// -- The canaries ------------------------------------------------------------

/// The canary a corpus seeds for `tag`.
///
/// Assembled from parts rather than written as one literal, so the token a
/// fixture carries appears nowhere in the tree — not even in this file. A gate
/// whose canary is greppable is a gate whose failure could be ordinary repo
/// content, which is the one thing it must never be confusable with.
fn canary(tag: &str) -> String {
    const HEAD: &str = "Q7v";
    const TAIL: &str = "x9nK";
    format!("{HEAD}{tag}{TAIL}")
}

/// One seeded canary: its tag, and where in the corpus those bytes come from.
///
/// The provenance is a **field** rather than a comment beside the tag, because a
/// failure message is the only place anyone reads it — the assertion that fires
/// has to be able to say *what kind of byte* leaked, and a comment cannot travel
/// into a panic. It also cannot be relocated by a formatter onto the wrong entry,
/// which a trailing comment on a short array element demonstrably can.
struct Canary {
    tag: &'static str,
    source: &'static str,
}

/// Bytes a check read as its **subject**. No verb may emit one of these.
const CONTENT: &[Canary] = &[
    Canary {
        tag: "matched",
        // Also the line a declared suppression marker sits on: one line, because
        // a leak of either is the same emitter printing the same bytes.
        source: "the line a `forbid` rule matched",
    },
    Canary {
        tag: "counted",
        source: "the body of a file counted against a declared budget",
    },
    Canary {
        tag: "spoken",
        source: "free text inside a completed-session transcript",
    },
    Canary {
        tag: "childout",
        source: "a wrapped or configured child's own stdout",
    },
    Canary {
        tag: "childerr",
        source: "a wrapped or configured child's own stderr",
    },
    Canary {
        tag: "mediated",
        source: "the operand of a mediated tool call, read from a `hook` payload",
    },
    Canary {
        tag: "briefed",
        source: "free prose inside a delegation brief read by `lint brief`",
    },
    Canary {
        tag: "captured",
        source: "the inline evidence bytes of a design-evidence capture",
    },
    Canary {
        tag: "lineread",
        // CLOUD-846's §5, and the reason the lines fact is safe to have at all:
        // a module may SEE a line, and a finding may not CARRY one. This is the
        // byte that proves it structurally rather than by review — without it,
        // the widest fact on the tree surface would rest on nobody having
        // written the leak yet.
        source: "a line of a file a `policy` row declared under `lines`",
    },
];

/// Bytes the caller wrote **as policy**. Only an `Echoes` verb may emit one.
const DECLARATION: &[Canary] = &[
    Canary {
        tag: "rulepat",
        source: "a `[[rule]]` pattern",
    },
    Canary {
        tag: "markertok",
        source: "a second `[[rule]]` pattern, doubling as a `[[marker]]` token",
    },
    Canary {
        tag: "waived",
        source: "a `[[waiver]]` reason",
    },
    Canary {
        tag: "logged",
        source: "a ledger row's `evidence` pointer",
    },
];

// -- The corpus --------------------------------------------------------------

/// The committed authority every corpus carries.
///
/// Each table exists so some emitter has subject matter to be tempted by: the
/// two `forbid` rules give `check` a finding and the waiver an audit line, the
/// budget is deliberately set to overflow so `policy budget` renders its
/// per-file breakdown rather than staying silent, and the ledger and transcript
/// give `defects query` and `check`'s transcript view something to read.
///
/// The `shape` row is `pattern = "rm"` with `contains = "-rf"` rather than the
/// two-word `pattern = "rm -rf"` it used to be. The matcher compares operand
/// words with every flag already dropped, so the old spelling could never fire
/// — the mediated call below was allowed and the sweep over its output proved
/// nothing. `rules::validate` now refuses that shape at load (CLOUD-401), and
/// this is the spelling it names.
fn authority(spawning: bool) -> String {
    let mut config = format!(
        "version = 1\n\
         scope = [\"**\"]\n\
         protected = [\"batten.toml\"]\n\
         unlanded = [\"subject.txt\"]\n\
         must_land_on = \"refs/heads/main\"\n\
         \n\
         [[rule]]\n\
         id = \"no-canary\"\n\
         kind = \"forbid\"\n\
         glob = \"**/*.txt\"\n\
         pattern = \"{rulepat}\"\n\
         severity = \"warn\"\n\
         scope = \"tree\"\n\
         \n\
         [[rule]]\n\
         id = \"no-canary-waived\"\n\
         kind = \"forbid\"\n\
         glob = \"**/*.txt\"\n\
         pattern = \"{markertok}\"\n\
         severity = \"deny\"\n\
         scope = \"tree\"\n\
         \n\
         [[rule]]\n\
         id = \"switched-off\"\n\
         kind = \"forbid\"\n\
         glob = \"**/*.md\"\n\
         pattern = \"{rulepat}\"\n\
         severity = \"allow\"\n\
         scope = \"tree\"\n\
         \n\
         [[rule]]\n\
         id = \"no-canary-command\"\n\
         kind = \"shape\"\n\
         scope = \"mediated_call\"\n\
         severity = \"deny\"\n\
         pattern = \"rm\"\n\
         contains = \"-rf\"\n\
         reason = \"remove it through the surface that owns it\"\n\
         \n\
         [[rule]]\n\
         id = \"tree-policy\"\n\
         kind = \"policy\"\n\
         scope = \"tree\"\n\
         bundle = \"policy/\"\n\
         lines = [\"lineread.md\"]\n\
         severity = \"deny\"\n\
         \n\
         [[verdict]]\n\
         id = \"a canary line\"\n\
         gloss = \"a canary line reached a declared source\"\n\
         class = \"What the corpus module asserts, at explain length.\"\n\
         \n\
         [[verdict.route]]\n\
         id = \"read the module\"\n\
         kind = \"document\"\n\
         target = \"policy/lines.rego\"\n\
         \n\
         [[waiver]]\n\
         rule = \"no-canary-waived\"\n\
         reason = \"{waived}\"\n\
         expires = \"2099-12-31\"\n\
         \n\
         [[marker]]\n\
         id = \"waved-through\"\n\
         token = \"{markertok}\"\n\
         glob = \"**/*.txt\"\n\
         \n\
         [budget.loaded]\n\
         files = [\"counted.txt\"]\n\
         max_tokens = 1\n\
         \n\
         [defects]\n\
         path = \"defects.jsonl\"\n\
         classes = [\"process\"]\n\
         \n\
         [transcript]\n\
         path = \"transcript.jsonl\"\n\
         \n\
         [epoch]\n\
         tracked = [\"batten.toml\"]\n",
        rulepat = canary("rulepat"),
        markertok = canary("markertok"),
        waived = canary("waived"),
    );
    if spawning {
        // Only `enforce` evaluates a spawning kind — `check` refuses one outright
        // and would then evaluate nothing at all, so seeding this everywhere
        // would make the corpus prove nothing for the verb it matters most for.
        // The child writes a canary to each stream and exits non-zero, so the
        // finding path runs too; `rules.rs` nulls both streams, and this is what
        // pins that it still does.
        //
        // `check` is split on whitespace, so the child is a script rather than an
        // `sh -c` one-liner: a quoted argument would not survive the split.
        config.push_str(
            "\n[[rule]]\n\
             id = \"canary-child\"\n\
             kind = \"command\"\n\
             glob = \"**/*.txt\"\n\
             check = \"sh emit.sh\"\n\
             severity = \"warn\"\n\
             scope = \"tree\"\n",
        );
    }
    config
}

/// The child a spawning corpus runs: a canary on each stream, and a non-zero
/// exit so the finding it produces is rendered rather than skipped.
fn emit_script() -> String {
    format!(
        "echo '{}'\necho '{}' >&2\nexit 1\n",
        canary("childout"),
        canary("childerr"),
    )
}

/// A materialized corpus: the repository, and an isolated data home so the
/// out-of-tree store and capture dirs never touch the developer's own.
struct Corpus {
    repo: PathBuf,
    home: PathBuf,
}

impl Corpus {
    fn build(name: &str, spawning: bool) -> Corpus {
        let root = scratch(name);
        let repo = Fixture::at(root.join("repo"))
            .config(&authority(spawning))
            .file("emit.sh", &emit_script())
            // The subject line carries a declaration canary (the literal both
            // rules match on) and a content canary (the rest of the line) side by
            // side, so an emitter that printed the matched line would leak both
            // and one that printed only its own pattern would leak neither.
            .file(
                "subject.txt",
                &format!(
                    "first line\n{} {} {}\nthird line\n",
                    canary("rulepat"),
                    canary("markertok"),
                    canary("matched"),
                ),
            )
            .file("counted.txt", &format!("{}\n", canary("counted")))
            // A published schema for `config deprecations` to compare against,
            // carrying a CONTENT canary in a description. The verb must name the
            // removed key and never the schema body, so a run that echoed what it
            // read leaks this and fails the census. The key itself is absent from
            // the real surface, so the comparison finds a removal and the verb
            // reaches its reporting path rather than its clean one.
            .file(
                "schema/batten.schema.json",
                &format!(
                    "{{\n  \"properties\": {{\n    \"a_removed_key\": {{\n      \"description\": \"{}\"\n    }}\n  }}\n}}\n",
                    canary("schemabody"),
                ),
            )
            // A file a `policy` row reads as LINES (CLOUD-846). The module below
            // decides over it and denies; the canary is the line's content, so
            // any verb that echoed what the module saw fails the census.
            .file(
                "lineread.md",
                &format!("# heading\n\n{}\n", canary("lineread")),
            )
            .file(
                "policy/lines.rego",
                "package batten\n\
                 import rego.v1\n\
                 rules contains \"no-canary-line\"\n\
                 violation contains {\"rule\": \"no-canary-line\", \"verdict\": \"a canary line\"} if {\n\
                 \tsome line in input.tree.lines[\"lineread.md\"]\n\
                 \tstartswith(line, \"Q7v\")\n\
                 }\n",
            )
            .file(
                "defects.jsonl",
                &format!(
                    "{{\"id\":\"d1\",\"class\":\"process\",\"observed\":\"2026-01-01\",\
                     \"evidence\":\"{}\"}}\n",
                    canary("logged"),
                ),
            )
            .file(
                "transcript.jsonl",
                &format!(
                    "{{\"type\":\"user\",\"message\":{{\"role\":\"user\",\
                     \"content\":\"{}\"}}}}\n",
                    canary("spoken"),
                ),
            )
            .git()
            .base_commit()
            .build();
        let home = Fixture::at(root.join("home")).build();
        Corpus { repo, home }
    }
}

/// The mediated tool call `hook` adjudicates: a command whose operand is a
/// content canary. `hook.rs` states that `input` is never emitted (rule 4); this
/// is what decides it.
fn mediated_call() -> String {
    format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\
         \"tool_input\":{{\"command\":\"rm -rf {}\"}}}}\n",
        canary("mediated"),
    )
}

/// The brief `lint brief` reads. Deliberately incomplete — it carries no
/// required section at all — so the lint reports its maximum rather than staying
/// silent, and there is something to leak in the first place.
///
/// A brief is free prose a caller pastes in, which is the shape most likely to
/// carry something private; `lib.rs` says the report is ids and counts only, and
/// this is what decides it.
fn delegation_brief() -> String {
    format!(
        "Please pick up the work described here: {}\n",
        canary("briefed")
    )
}

/// The claim stream `design audit` reads.
///
/// The sharpest content case on the surface: a `capture` carries its evidence
/// **inline**, in `bytes`, so the audit holds real captured content in hand and
/// its whole job is to judge that content without republishing it. `design.rs`
/// says `source` is a pointer and never the claim text; the digest is
/// deliberately wrong for the bytes, so the mismatch finding fires and the
/// emitter that reports it is actually exercised.
fn design_claims() -> String {
    format!(
        "{{\"id\":\"c1\",\"status\":\"verified\",\"polarity\":\"absence\",\
         \"source\":\"batten.toml:1\",\"claimant\":\"a\",\"verifier\":\"b\",\
         \"capture\":{{\"digest\":{{\"sha256\":\"{}\"}},\"byte_count\":1,\
         \"bytes\":\"{}\"}}}}\n",
        "0".repeat(64),
        canary("captured"),
    )
}

/// The verdict `record tool` reads (CLOUD-1265).
///
/// The sharpest case in this family and the reason the row below is
/// `PointerOnly` rather than `Echoes`: these bytes are a REDUCTION of a
/// third-party validator's report, and `tools.rs`'s own header names a
/// validator's output as the likeliest place in this whole surface for a secret
/// to appear. The recorder's job is to put them in a keyed file under `$GIT_DIR`
/// and say nothing, so a canary reaching either channel is the defect.
fn tool_verdict() -> String {
    format!("status error\n{} hk.pkl:12\n", canary("validated"))
}

/// The verdict `record forge` reads.
///
/// A check NAME and a conclusion, both tokens — but the name comes from the
/// forge, so it is somebody else's string arriving through this repository's
/// producer. Held to the same law as its sibling for the same reason.
fn forge_verdict() -> String {
    format!("{} failure\n", canary("concluded"))
}

/// A ledger row read on stdin by `defects add -n`. The caller wrote it, so its
/// bytes are a declaration.
fn incoming_record() -> String {
    format!(
        "{{\"id\":\"d2\",\"class\":\"process\",\"observed\":\"2026-01-01\",\
         \"evidence\":\"{}\"}}\n",
        canary("logged"),
    )
}

// -- The census --------------------------------------------------------------

/// What a verb is allowed to put on its channels.
enum Disposition {
    /// The law. Neither a content byte nor a declaration byte reaches either
    /// channel. Every verb is this unless a stated reason says otherwise.
    PointerOnly,
    /// The answer **is** the caller's own declaration — a resolved config value,
    /// a schema derived from the config types, a ledger row they wrote. Held to
    /// the content half only, which is the half rule 4 is about.
    Echoes(&'static str),
    /// The verb relays bytes it was handed. Held to a **count**: a canary may
    /// appear exactly as often as the caller's own command wrote it and never
    /// more, so a report that amplified the payload still fails.
    Passthrough(&'static str),
}

/// What the verb reads on stdin. Built at run time because it carries canaries.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stdin {
    Nothing,
    MediatedCall,
    DefectRecord,
    DelegationBrief,
    DesignClaims,
    ToolVerdict,
    ForgeVerdict,
}

struct Verb {
    /// The leaf path, exactly as [`SURFACE`] spells it.
    path: &'static str,
    /// Arguments after the path tokens. Required flags only — this census is
    /// about what a verb *emits*, not about exercising its flag matrix.
    args: &'static [&'static str],
    stdin: Stdin,
    disposition: Disposition,
}

/// The verbs whose honest answer over THIS corpus is could-not-look.
///
/// The sweep refuses exit 3 by default and the reason is sound: a verb that
/// failed internally emitted nothing, so what it did not leak proves nothing.
/// One class is different, and it is named here rather than waved through by a
/// weaker assertion — for a mutation sweep the could-not-look report IS the
/// emission, and it is exactly where a runner is tempted to quote the thing it
/// could not read. The pointer-only assertions below still run over it
/// unchanged; only the exit-code precondition is lifted.
///
/// `mutate sweep` is here because no lighter fixture can give it a verdict: a
/// sweep needs a real gate, a real declaration and a real suite runner, and this
/// corpus deliberately builds none of the three. `mutate census` is NOT here —
/// it answers `names-no-subject` per name, which is a verdict.
///
/// A NAME BELONGS HERE ONLY WHEN NO LIGHTER FIXTURE COULD PRODUCE A VERDICT,
/// never to wave through a verb failing for a reason of its own. Widening it is
/// the vacuous pass this file exists to refuse.
const MAY_ANSWER_COULD_NOT_LOOK: &[&str] = &["mutate sweep"];

/// One entry per leaf verb of [`SURFACE`], asserted total by
/// [`every_leaf_verb_is_classified`] in both directions.
const CENSUS: &[Verb] = &[
    Verb {
        path: "check",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        path: "enforce",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        path: "exec",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::Passthrough(
            "the child's streams are inherited and its exit code returned unchanged — that \
             transparency is the verb's whole contract, so the question here is not whether the \
             caller's own bytes appear but whether Batten's report adds a copy of them",
        ),
    },
    // `exec`'s reader, and it inherits `exec`'s answer for the same reason
    // (CLOUD-121). Handing back bytes the caller's own command already wrote IS
    // the job: the alternative way to see them is re-running that command, which
    // is the cost this verb exists to delete. So `Passthrough`, held to a count —
    // Batten adding a copy of its own still fails.
    //
    // **What this corpus does NOT exercise, stated rather than implied:** the
    // sweep's fixture holds no capture, so `show` answers exit 1 here and the
    // count is 0 against 0. The count that matters is asserted where a capture
    // exists — `widening_the_window_costs_no_second_run_of_the_command` and its
    // siblings in `tests/cli.rs`. This row is the classification, not its proof.
    Verb {
        path: "capture show",
        args: &["stdout:00"],
        stdin: Stdin::Nothing,
        disposition: Disposition::Passthrough(
            "it hands back the bytes the caller's own command wrote, which is the whole point of \
             a handle — the other way to see them is to run that command again",
        ),
    },
    // The KEYED reader (CLOUD-1121), and it takes `show`'s disposition for
    // `show`'s reason rather than the stronger one its default form would earn.
    //
    // Its default output is strictly a pointer — a handle, a byte count and the
    // tool — and so is its refusal, which names the key and the path a caller
    // already typed and nothing about what the store does hold. A "did you mean"
    // over captured bodies would leak exactly what the verb exists to keep out of
    // context, so there is none.
    //
    // But `--raw` is a real route by which a body leaves, into a program's stdin,
    // and that is the whole point of the flag: a board gate consumes the payload
    // without the agent ever seeing it. A `PointerOnly` claim would be false for
    // that form, and the disposition is a property of the VERB rather than of one
    // invocation — so the honest field is `Passthrough`, held to a count, and
    // Batten adding a copy of its own still fails.
    //
    // **What this corpus does not exercise**, stated for `capture show`'s reason:
    // the sweep's fixture holds no capture, so this answers exit 1 here and the
    // count is 0 against 0. That the DEFAULT form carries no byte of a body is
    // asserted where a capture exists — `a_stored_response_is_resolved_by_the_
    // key_it_carries` in `tests/cli.rs`, which seeds a response through the
    // engine and then asserts the pointer contains no substring of it.
    Verb {
        path: "capture find",
        args: &["CLOUD-1", "--tool", "get_issue"],
        stdin: Stdin::Nothing,
        disposition: Disposition::Passthrough(
            "`--raw` hands the stored response to a program's stdin, which is how a gate reads a              payload that never entered context — the default form is a pointer and is asserted              as one where a capture exists",
        ),
    },
    // THE DISPATCHER (CLOUD-1260), and it takes `capture find`'s disposition for
    // `capture find`'s reason rather than the stronger one its pointer line would
    // earn on its own.
    //
    // Its RECORD is strictly a pointer, and deliberately on stderr: a handle, a
    // source id, a disposition and two byte counts, never a byte of what was
    // stored. But its PRODUCT is a reduction on stdout, and a reduction is
    // content — the declared fields of a payload the caller asked for. That is
    // the whole point of the verb, and a `PointerOnly` claim over it would be
    // false.
    //
    // The bound that makes this honest is the DECLARATION rather than this field:
    // a field no `[[mcp.result]]` row names never leaves the store, and the
    // `acknowledge` arm additionally refuses anything past a bounded scalar. So
    // what reaches stdout is what a consumer wrote down, and `Passthrough`'s
    // count still refuses Batten adding a copy of its own.
    //
    // **What this corpus does not exercise**, stated for `capture show`'s reason:
    // the sweep's fixture declares no `[[mcp.source]]`, so this answers exit 3
    // here — could-not-look — and the count is 0 against 0. That the refusal
    // carries no resolved path is asserted where a source exists, in
    // `tests/mcp_dispatch.rs::no_refusal_carries_a_resolved_path`.
    Verb {
        path: "mcp call",
        args: &["a-server", "a-method"],
        stdin: Stdin::Nothing,
        disposition: Disposition::Passthrough(
            "its product is a declared reduction over a payload the caller asked for, which is \
             content by design — the pointer half is the record on stderr, and what may reach \
             stdout is bounded by the `[[mcp.result]]` row rather than by this field",
        ),
    },
    // THE TWO BOARD VERBS ARE POINTER-ONLY BY CONSTRUCTION, and it is the property
    // that lets them run in CI at all: an issue body can carry consumer detail, so
    // a gate that echoed the prose it matched would leak it through the log. Every
    // finding is `<id>:<line> <rule>` and every emission is a key or a bump token
    // — `ready::Finding` carries a line and a rule id and there is no field a body
    // could travel in, which is what makes rule 4 structural here rather than a
    // habit each call site keeps.
    Verb {
        path: "ready lint",
        args: &["--issue", "CLOUD-1"],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        path: "claim check",
        args: &["--issue", "CLOUD-1"],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    // The green verdict (CLOUD-1143), pointer-only on the same structural terms.
    // `checks_green::Finding` carries a check name and a conclusion and has
    // nowhere to put anything else, so a run's log cannot travel even when the
    // caller asked about a failure — which matters because the alternative is a
    // forge's build output in a CI log that a lander reads on every lap.
    //
    // `Stdin::Nothing` is the reading being empty, which is a real state rather
    // than a fixture convenience: a SHA with no check-runs yet answers "not an
    // answer", so this exercises the emission path the poller sees most often.
    Verb {
        path: "checks green",
        args: &["--required", "a", "--answered", "success"],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    // The poll (CLOUD-1143). Driven to its REFUSAL rather than to a verdict: the
    // loop is unbounded by design, so a census entry that reached the network
    // would not be a slow case, it would be one that never returns. An empty
    // roster is refused before the first request, which is exactly the property
    // that makes this entry runnable at all.
    Verb {
        path: "pr watch",
        args: &["--sha", "0", "--required", "", "--answered", "success"],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    // The pointer half of the same noun: handles and byte counts, never a byte of
    // what was captured.
    Verb {
        path: "capture list",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    // Emits a count of what it removed.
    Verb {
        path: "capture prune",
        args: &["-n"],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        path: "config show",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::Echoes(
            "the effective configuration IS the answer; a resolver that reported its own values \
             as counts would answer a question nobody asked",
        ),
    },
    Verb {
        path: "config epoch",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        path: "config lint",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    // Key names and a count, never the schema body or a configured value
    // (CLOUD-360). The remedy for a finding here is declaring a window, so the
    // schema text adds nothing a reader needs and would put the config surface
    // into a log.
    Verb {
        path: "config deprecations",
        args: &["HEAD"],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        path: "spec",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::Echoes(
            "the spec is derived from the command surface and reads no repository content at \
             all; it echoes Batten's own declarations, not the caller's tree",
        ),
    },
    Verb {
        path: "doctor",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    // The sub-verb inherits the parent's promise rather than restating it
    // (CLOUD-777): a `Check`'s reason id is a stable token and a wiring finding's
    // event is a host token, so neither can carry a path — which is what makes
    // CLOUD-525's `$HOME` surface reportable at all. A non-batten sibling is a
    // COUNT here for the same reason; naming one would put a consumer's disk
    // layout in a diagnostic that promises not to.
    Verb {
        path: "doctor hooks",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        // `-n` so the census cannot author into the corpus. It changes nothing
        // about what is emitted here: the corpus already carries a `batten.toml`,
        // so this run takes the refusal path either way, and the refusal names a
        // file name and a command — never a byte the corpus seeded.
        path: "init",
        args: &["-n"],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        // `-n` for the same reason `init` carries it: the census must not author
        // into the corpus. It changes nothing about what is emitted — the mint
        // gate reads the corpus's git state, not the flag, and whichever branch
        // it takes emits rule ids, fingerprint prefixes and `worktree`'s own
        // pointers. The one thing a baseline could leak is the finding it
        // suppresses, and it names that finding by identity digest.
        path: "baseline",
        args: &["-n"],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        path: "generate completions",
        args: &["--shell", "bash"],
        stdin: Stdin::Nothing,
        disposition: Disposition::Echoes(
            "a completion script is the command surface rendered for a shell; same reasoning as \
             `spec`, and it reads no repository content either",
        ),
    },
    Verb {
        path: "generate hooks",
        args: &["--harness", "claude-code"],
        stdin: Stdin::Nothing,
        disposition: Disposition::Echoes(
            "the wiring is derived from the `Harness` enum — a host's config path, its event \
             spellings, and Batten's own command — so every byte is Batten's own declaration. \
             It reads no repository content at all: not the tree, not `batten.toml`, not the \
             committed wiring it is diffed against, which is `hooks-wiring-check`'s to read",
        ),
    },
    Verb {
        path: "generate schema",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::Echoes(
            "the schema is derived from the config TYPES, so it describes the shape a \
             declaration may take and never a value one carries",
        ),
    },
    Verb {
        path: "generate man",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::Echoes(
            "a man page is the command surface rendered as roff; the same reasoning as \
             `generate completions`, and it reads no repository content either",
        ),
    },
    Verb {
        path: "generate markdown",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::Echoes(
            "the CLI reference is the whole command surface rendered as markdown; it echoes \
             Batten's own declarations — including the §5 effect column — and never the \
             caller's tree",
        ),
    },
    Verb {
        path: "lint brief",
        // Reads stdin when the positional is omitted, the same `-` convention
        // `config lint --host-rules` uses.
        args: &[],
        stdin: Stdin::DelegationBrief,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        path: "policy budget",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    // Everything this verb reads is consumer-authored policy and the documents
    // a row declares, so a report carrying either would republish exactly what
    // rule 4 keeps out. Findings are `<bundle> <reason> <module> <name>` and
    // predicate ids (CLOUD-835).
    Verb {
        path: "policy test",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    // The names are SELECTORS out of the committed authority — the consumer's own
    // vocabulary, echoed back — so the whole output is the pointer. There is no
    // payload here to withhold: a row's `reason`, its pattern and every document it
    // declares stay unread by this verb (CLOUD-312 row 4).
    Verb {
        path: "policy tools",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    // THE DELIBERATE, STATED PAYLOAD EXCEPTION (CLOUD-1053). Every other verb
    // here emits a pointer because its answer is ABOUT something in the tree;
    // this one's answer IS the declaration. A `[[verdict]]` row's `class` is the
    // config author's own text — the class `config show` exists to echo — and
    // carrying the paragraph the hot path no longer does is the entire reason
    // the verb exists. A documentation verb that emitted a pointer to its own
    // documentation would be a redirect with extra steps.
    //
    // `Echoes` rather than a fourth disposition, because that is exactly what
    // this is and the variant already carries the argument: the answer is the
    // caller's own declaration, held to the content half, which is the half rule
    // 4 is about. The token asked for is a literal the caller typed.
    Verb {
        path: "policy explain",
        args: &["path write refused"],
        stdin: Stdin::Nothing,
        disposition: Disposition::Echoes(
            "the answer IS a `[[verdict]]` row — its gloss, its class definition and its \
             routes. That is the config author's own declaration rather than content read out \
             of a subject file, and it is the payload the hot path stopped carrying when a \
             refusal became a token plus a pointer",
        ),
    },
    // CLOUD-1051, and it is POINTER-ONLY on the channel this census reads, which
    // is worth stating because the row it serves is the one place rule 4 is
    // deliberately inverted.
    //
    // The inversion is about the RECORD, not this output. The reasoning a caller
    // types is the payload and it belongs in the record, because it is the
    // author's own words rather than repository content. What crosses stdout is
    // one admission — a 64-character hex address — and that is a pointer in the
    // strictest sense available: it authorizes nothing on its own (the record's
    // existence and state do), which is precisely what makes it safe to print,
    // log and quote in a commit.
    //
    // The unanswered path writes the declared questions to STDERR, so the data
    // channel carries the address or nothing at all.
    Verb {
        path: "override request",
        args: &[
            "--rule",
            "prose-only",
            "--verdict",
            "path write refused",
            "--subject",
            "a.rs",
        ],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    // The consuming half (CLOUD-1051), and pointer-only for a sharper reason than
    // its sibling: `request` at least has an author's reasoning passing through
    // it, while this verb reads a record and reports a verdict about it. What
    // crosses stdout is the class token and the address it spent — no answer, no
    // subject content, nothing from the record's body. A spend that echoed the
    // reasoning back would republish, on every gate run, the one payload the
    // record exists to keep in one place.
    Verb {
        path: "override spend",
        args: &[
            "--admission",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "--rule",
            "prose-only",
            "--verdict",
            "path write refused",
            "--subject",
            "a.rs",
        ],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    // Both attribution verbs are the law rather than an exception, and this one
    // has less latitude than most: everything it reads is metadata someone
    // wanted suppressed, so a report carrying the matched text would republish
    // exactly what the gate exists to catch. Findings are `<sha8> author` and
    // `<sha8> trailer:<key>` (CLOUD-274).
    Verb {
        path: "attribution check",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    // The subject convention, same object and same discipline (CLOUD-701). A
    // subject carries whatever its author typed, so echoing it back is the gate
    // republishing arbitrary content — which is exactly what the shell task this
    // replaced did. Findings are `<sha8> subject`.
    Verb {
        path: "commit check",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    // The one write on this surface. It reports which repo-local identity it
    // set or left alone, never a commit's metadata.
    Verb {
        path: "attribution identity",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        path: "worktree status",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    // The one verb whose subject is a file OUTSIDE the repository (CLOUD-893),
    // which makes rule 4 tighter here rather than looser: what it removes is a
    // command line off somebody's home directory, so every byte it reports is a
    // count plus the harness and event to look under — not a path, and not even
    // the offending command's basename. The at-load record it writes obeys the
    // same rule, which `crates/batten/tests/it/wiring_reclaim.rs` asserts over the
    // file itself.
    //
    // Driven with `-n`, which is the only invocation that reads the surfaces and
    // writes nothing: this corpus is a fixture tree, and a verb allowed to repair
    // it would be measuring bytes it had just rewritten.
    Verb {
        path: "wiring reclaim",
        args: &["-n"],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        path: "provision status",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        path: "provision apply",
        args: &["-n"],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        path: "hook",
        args: &["--harness", "exit-code"],
        stdin: Stdin::MediatedCall,
        disposition: Disposition::PointerOnly,
    },
    // THE ONE VERB WHOSE ANSWER IS THE PAYLOAD, and `command` is deliberately the
    // field asked for: it is where `mediated_call` seeds its canary, so any other
    // choice would classify this verb by dodging its own question. It exists so a
    // shell hook can read one field without an unpinned `jq` on the per-turn hot
    // path (CLOUD-479), which means printing the caller's own bytes back is the
    // entire job — `Passthrough` rather than `PointerOnly`, held to a COUNT so
    // Batten adding a second copy in a report of its own still fails.
    Verb {
        path: "payload field",
        args: &["--name", "command"],
        stdin: Stdin::MediatedCall,
        disposition: Disposition::Passthrough(
            "it prints one allowlisted field of the payload the caller piped in",
        ),
    },
    Verb {
        path: "receipt record",
        args: &["final"],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        path: "receipt status",
        args: &["final"],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    // The API-compatibility gate (CLOUD-1050). It reads a delegated analyser's
    // report and a range of commit messages — two of the content-richest inputs
    // on this surface — and emits the failing LINT IDS and a short sha, never a
    // line of the rustdoc it compared or a subject it scanned. In this corpus it
    // answers could-not-look, which is the honest outcome for a fixture with no
    // package to compare; the refusal is a pointer either way, and that is what
    // is being decided here.
    Verb {
        path: "semver check",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    // The paired measurement (CLOUD-875). Its records carry an ARM, a BENCHMARK
    // ID and five numbers — never a command line, never a byte of the fixture it
    // measured, and never the hyperfine output the numbers were read out of, all
    // of which stay in the run's own directory. Its skip line names path PREFIXES
    // the predicate consulted, which is a pointer set by construction: they come
    // from the harness table and the loaded config, not from anybody's diff.
    //
    // In this corpus it answers with the skip, which is the honest outcome for a
    // fixture whose HEAD is its own merge base; the skip is a pointer either way,
    // and that is what is being decided here.
    Verb {
        path: "perf pair",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    // The mutation sweep and its census (CLOUD-1267). Both report a GATE NAME, a
    // mutation id and a case name — never a line of the mutated source, which is
    // the one thing a mutation runner is uniquely placed to leak, and the reason
    // the predecessor's own suite carried a case for it.
    //
    // In this corpus they answer over a fixture that declares no gate at all, so
    // every name resolves to `no-such-gate` and the sweep never stages a tree.
    // That is the honest outcome here and it is a pointer either way: a name the
    // enforced set supplied, echoed back as unresolvable. What is being decided
    // is that the could-not-look report is pointer-only too, which is where a
    // runner is most tempted to quote what it could not read.
    Verb {
        path: "mutate census",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        path: "mutate sweep",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    // The disk-floor reclaim (CLOUD-1030). Its report is a file COUNT, two
    // megabyte figures and the floor in force — never a path listing, which is
    // unbounded and which a caller wanting one can get from `du`. That was the
    // predecessor's own stated posture and it survives the port unchanged.
    //
    // `-n` rather than `-y` here, deliberately: this corpus runs every verb for
    // real, and the dry run is the only arm of a destructive verb a test harness
    // may take. It still exercises the report path, which is the thing being
    // decided.
    Verb {
        path: "target prune",
        args: &["-n"],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        path: "defects query",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::Echoes(
            "the ledger is committed, human-authored and PR-reviewed, and `evidence` is a \
             pointer by the type's own contract; querying it back is reading the caller's file \
             to them, not surfacing content a check went and read",
        ),
    },
    Verb {
        path: "defects add",
        args: &["-n"],
        stdin: Stdin::DefectRecord,
        disposition: Disposition::Echoes(
            "the row being previewed arrived on stdin from the caller; a dry run reporting it \
             back is an echo of their own input",
        ),
    },
    Verb {
        path: "design audit",
        args: &[],
        stdin: Stdin::DesignClaims,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        path: "state adopt",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        path: "state record",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        path: "state migrate",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        path: "state list",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    // `PointerOnly` rather than `Passthrough`, and the distinction is the whole
    // reason these two rows are worth having (CLOUD-1265). A `Passthrough` bound
    // would permit the canary through once; the recorder has no reason to emit it
    // at all, because the verdict's destination is a keyed file under `$GIT_DIR`
    // and the answer to a successful run is silence.
    //
    // So this is the assertion that a validator's report cannot leak back out
    // through the producer — the boundary `tools.rs`'s header puts here rather
    // than at the report, on the grounds that a validator's output is the
    // likeliest place in this family for a secret to appear.
    //
    // Both answer could-not-look in this corpus (the fixture declares no
    // `[[rule.tools]]` row, and `deadbeef` resolves to nothing), which is the
    // honest outcome and still exercises the emitter under judgement: a refusal
    // naming the row id or the ref is a pointer, and a refusal quoting the line it
    // choked on would not be.
    Verb {
        path: "record tool",
        args: &["config-validator"],
        stdin: Stdin::ToolVerdict,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        path: "record forge",
        args: &["deadbeef"],
        stdin: Stdin::ForgeVerdict,
        disposition: Disposition::PointerOnly,
    },
];

/// Every path of [`SURFACE`] that RUNS — the object this census must be total
/// over.
///
/// Derived rather than listed, so a noun that grows a verb changes this set on
/// its own and the census below is forced to keep up.
///
/// **"Runs" is not the same as "is a leaf" since CLOUD-777**, and the predicate
/// is [`batten::surface::is_noun`] rather than a second copy of it here. A noun
/// performs no default action and is excluded; a row that nests AND declares an
/// answer of its own still runs bare and stays in. Today `doctor` is the one such
/// row, because house style §2 spells the verb `doctor <SUB>` while §8 promises
/// what bare `batten doctor` does — so it has to be classified here even though
/// `doctor hooks` sits under it.
fn leaf_paths() -> Vec<&'static str> {
    let mut leaves: Vec<&'static str> = SURFACE
        .iter()
        .filter(|decl| !batten::surface::is_noun(decl))
        .map(|decl| decl.path)
        .collect();
    leaves.sort_unstable();
    leaves
}

/// Whether [`SURFACE`] declares a `-J` data channel for `path`.
fn has_data_channel(path: &str) -> bool {
    SURFACE
        .iter()
        .any(|decl| decl.path == path && decl.data_channel)
}

// -- Running one verb --------------------------------------------------------

/// One verb's captured channels. Bytes, not `String`: a leak in invalid UTF-8 is
/// still a leak, and lossy decoding would rewrite exactly the bytes in question.
struct Run {
    code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl Run {
    /// Both channels concatenated, which is what the law ranges over — rule 4
    /// says nothing about *which* stream may carry the payload.
    fn emitted(&self) -> Vec<u8> {
        let mut all = self.stdout.clone();
        all.extend_from_slice(&self.stderr);
        all
    }
}

fn run_in(corpus: &Corpus, args: &[&str], stdin: Stdin) -> Run {
    let mut command = batten();
    command
        .state_home(&corpus.home)
        .args(args)
        .current_dir(&corpus.repo)
        .env("XDG_CACHE_HOME", corpus.home.join("cache"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn batten");
    let payload = match stdin {
        Stdin::Nothing => String::new(),
        Stdin::MediatedCall => mediated_call(),
        Stdin::DefectRecord => incoming_record(),
        Stdin::DelegationBrief => delegation_brief(),
        Stdin::DesignClaims => design_claims(),
        Stdin::ToolVerdict => tool_verdict(),
        Stdin::ForgeVerdict => forge_verdict(),
    };
    // A BROKEN PIPE HERE IS THE CHILD BEING FAST, NOT A FAILURE. This corpus runs
    // every verb, and a verb that reads no stdin may exit before the write lands —
    // so `expect` made the case fail on a race whose outcome says nothing about
    // what the run emitted. Measured: `write stdin: BrokenPipe` on one lap of the
    // gate and green on the next, over an unrelated diff.
    //
    // Any OTHER error still panics, because it would mean the payload never
    // reached a verb that DOES read it — and the assertions below would then be
    // judging output produced from no input, which is the false green this file
    // exists to prevent.
    if let Err(error) = child
        .stdin
        .as_mut()
        .expect("stdin is piped")
        .write_all(payload.as_bytes())
        && error.kind() != std::io::ErrorKind::BrokenPipe
    {
        panic!("write stdin: {error:?}");
    }
    let output = child.wait_with_output().expect("await batten");
    Run {
        code: output.status.code(),
        stdout: output.stdout,
        stderr: output.stderr,
    }
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    count(haystack, needle) > 0
}

fn count(haystack: &[u8], needle: &str) -> usize {
    let needle = needle.as_bytes();
    if needle.is_empty() || haystack.len() < needle.len() {
        return 0;
    }
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

// -- The gate ----------------------------------------------------------------

#[test]
fn every_leaf_verb_is_classified() {
    // The totality proof, and the reason this suite answers CLOUD-92's question
    // rather than a sample of it. Both directions: a verb that joins the surface
    // has no bucket and fails here, and an entry left behind by a deleted verb
    // fails here too rather than passing vacuously forever.
    let mut declared: Vec<&str> = CENSUS.iter().map(|verb| verb.path).collect();
    declared.sort_unstable();
    let leaves = leaf_paths();
    assert_eq!(
        declared, leaves,
        "every leaf verb needs exactly one pointer-only disposition. A new verb is \
         `PointerOnly` unless there is a reason it is not — and the reason is the field, so it \
         has to be written down rather than assumed."
    );
}

#[test]
fn a_canary_is_searchable_as_written() {
    // The search below is a plain byte scan, which is only sound because a canary
    // survives JSON escaping unchanged. Pinned rather than assumed: a future tag
    // carrying punctuation would silently weaken every assertion in this file to
    // "the escaped form did not appear".
    for seeded in CONTENT.iter().chain(DECLARATION) {
        let token = canary(seeded.tag);
        assert!(
            token.chars().all(char::is_alphanumeric),
            "canary {token} must be alphanumeric, or serde would re-spell it in `-J` and the \
             byte scan would miss the leak it is looking for"
        );
        assert_eq!(
            serde_json::to_string(&token).unwrap(),
            format!("\"{token}\""),
            "a canary must round-trip through JSON unchanged"
        );
    }
}

#[test]
fn the_corpus_is_live_subject_matter() {
    // A canary gate over a corpus no check reads would pass forever while
    // proving nothing. This is the vacuity guard: the seeded content must
    // actually reach the emitters the sweep then judges.
    let corpus = Corpus::build("pointer-only-live", false);

    let checked = run_in(&corpus, &["check"], Stdin::Nothing);
    let stdout = String::from_utf8_lossy(&checked.stdout).into_owned();
    assert!(
        stdout.contains("subject.txt:2 no-canary"),
        "the forbid rule must fire on the seeded line, or `check` is judging nothing: {stdout}"
    );
    assert!(
        stdout.contains("budget.loaded"),
        "the budget must overflow, or its per-file rendering is never reached: {stdout}"
    );
    let stderr = String::from_utf8_lossy(&checked.stderr).into_owned();
    assert!(
        stderr.contains("waived subject.txt:2 no-canary-waived"),
        "the waiver must apply, or its audit line is never rendered: {stderr}"
    );

    let budget = run_in(&corpus, &["policy", "budget"], Stdin::Nothing);
    assert_eq!(
        budget.code,
        Some(2),
        "the budget verb must render a verdict over the seeded files"
    );
    assert!(
        !budget.stdout.is_empty(),
        "an over-budget set renders its per-file breakdown"
    );
}

#[test]
fn no_verb_emits_content_it_merely_read() {
    // The law, swept over the whole surface. Each verb runs on its own corpus so
    // a writer cannot leave state that changes the next verb's answer, and every
    // `-J` verb runs twice — the document and the human rendering are two
    // emitters, and `output.rs` gives the ladder no reach over the first.
    for verb in CENSUS {
        let spawning = verb.path == "enforce";
        // `sweep-` namespaces these away from the hand-written fixtures below.
        // Cargo runs the tests in this file CONCURRENTLY and `scratch` wipes
        // before writing, so a name a second test also derives is not a
        // collision waiting to happen — it is one test deleting another's `.git`
        // mid-run. Measured: the sweep's `exec` corpus and the passthrough
        // case's shared a name, and the loser reported `. is not inside a git
        // repository`. Local timing hid it; CI did not.
        let corpus = Corpus::build(
            &format!("pointer-only-sweep-{}", verb.path.replace(' ', "-")),
            spawning,
        );

        let mut argvs: Vec<Vec<&str>> = Vec::new();
        let base: Vec<&str> = verb
            .path
            .split_whitespace()
            .chain(verb.args.iter().copied())
            .collect();
        argvs.push(base.clone());
        if has_data_channel(verb.path) {
            let mut with_json = base;
            with_json.push("-J");
            argvs.push(with_json);
        }

        for argv in argvs {
            let run = run_in(&corpus, &argv, verb.stdin);
            if !MAY_ANSWER_COULD_NOT_LOOK.contains(&verb.path) {
                assert_ne!(
                    run.code,
                    Some(3),
                    "{argv:?} failed internally, so what it did not emit proves nothing: {}",
                    String::from_utf8_lossy(&run.stderr)
                );
            }
            let emitted = run.emitted();

            match verb.disposition {
                Disposition::PointerOnly => {
                    for seeded in CONTENT.iter().chain(DECLARATION) {
                        assert!(
                            !contains(&emitted, &canary(seeded.tag)),
                            "{argv:?} emitted {}. Output is a pointer, never the payload \
                             (non-negotiable rule 4, house-style §6): report a count, a \
                             `path:line`, or a boolean.",
                            seeded.source,
                        );
                    }
                }
                Disposition::Echoes(reason) => {
                    for seeded in CONTENT {
                        assert!(
                            !contains(&emitted, &canary(seeded.tag)),
                            "{argv:?} is classified as echoing the caller's own declarations \
                             ({reason}) — but it emitted {}, which is content a check READ. That \
                             is the half rule 4 is about, and no disposition exempts it.",
                            seeded.source,
                        );
                    }
                }
                Disposition::Passthrough(reason) => {
                    // Held to a count rather than to absence: the caller's own
                    // bytes are the point of the verb, so what would be a defect
                    // is Batten adding a copy of them to its own report.
                    for seeded in CONTENT {
                        assert!(
                            count(&emitted, &canary(seeded.tag)) <= 1,
                            "{argv:?} relays its child's streams ({reason}), so {} may appear \
                             exactly as often as the child wrote it — once. A second copy is \
                             Batten's own report carrying the payload.",
                            seeded.source,
                        );
                    }
                }
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn a_passthrough_report_points_at_the_child_without_repeating_it() {
    // The `Passthrough` bucket's own case, spelled out rather than left to the
    // sweep: `exec`'s output predicate must render `stream:line <id>` beside a
    // line it will not restate. The child writes to stderr so its bytes and
    // Batten's report share one stream, which is the strongest form of the
    // question.
    let root = scratch("pointer-only-exec-report");
    let repo = Fixture::at(root.join("repo"))
        .config(
            "version = 1\n\n[[exec_pattern]]\nid = \"lying-exit\"\n\
             pattern = \"warning[duplicate]\"\nstream = \"both\"\n\
             reason = \"set the tool's own severity to deny\"\n",
        )
        .git()
        .base_commit()
        .build();
    let home = Fixture::at(root.join("home")).build();
    let corpus = Corpus { repo, home };

    let script = format!("echo 'warning[duplicate] {}' >&2", canary("childerr"));
    // `--tee` on purpose (CLOUD-429). The question is whether Batten RESTATES a
    // line the child already wrote, so the child's line has to reach the stream
    // for the count to mean anything — under the token-kind default it never
    // does, and the case would pass for the wrong reason.
    let run = run_in(
        &corpus,
        &["exec", "--tee", "--", "sh", "-c", &script],
        Stdin::Nothing,
    );

    let stderr = run.stderr.clone();
    assert!(
        contains(&stderr, "stderr:1 lying-exit"),
        "the match must be reported as a pointer: {}",
        String::from_utf8_lossy(&stderr)
    );
    assert_eq!(
        count(&stderr, &canary("childerr")),
        1,
        "the child wrote its line once; Batten's report must not write it again"
    );
}
