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
//! **There IS a shared emission path now, and the placement argument is
//! unchanged — which is the point worth keeping.** This paragraph used to open
//! "there is no shared emission path for the data channel" and give that absence
//! as the reason the gate sits at the boundary: stdout had no funnel, only ~30
//! inline `writeln!(out, …)` sites in `lib.rs` fed by ten independently-named
//! renderers (`line`, `line_text`, `summary`) plus `rules::Finding`, which had
//! none and was formatted inline. CLOUD-371 built the funnel — `output::Line`
//! plus `output::line`/`output::lines` — so that premise is retired rather than
//! left standing.
//!
//! The conclusion survives it because the premise was never load-bearing. The
//! same sentence already said the funnel "would also not *decide* anything,
//! because no trait can stop a `String` carrying content", and that is the whole
//! argument: a trait can make the census of *what emits* a compile-time
//! question, and it cannot make the census of *what those emissions contain* one.
//! CLOUD-371 owns the pointer **shape**; this owns the pointer **content**.
//!
//! So the gate stays where every one of those sites converges — the bytes the
//! process actually wrote. One mechanism, no call-site edits, and it cannot be
//! routed around by an emitter that spells its renderer a new way, nor by one
//! that implements the trait and renders the payload through it.
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
        tag: "declared",
        source: "the subject line of a task in the session's own store",
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
    Canary {
        tag: "boardrow",
        // The board sweep reads a tracker payload, and a tracker row's body is
        // where a consumer's own detail lives — an account number, a client name,
        // an entity path. The sweep's finding is a key, two column names and a
        // reason class, and this is the byte that decides it rather than the doc
        // comment above `run_landed_check` claiming it.
        source: "the description of a tracker row read by `landed check`",
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
         tasks = \"/nonexistent/{{session}}\"\n\
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
            // The session's own task store, where the engine parks its link
            // (CLOUD-1376). A real directory rather than a symlink: `read_dir`
            // follows either, so the reading under test is identical, and this
            // keeps the corpus from depending on how a platform spells a link.
            //
            // IT MUST BE A LIVE READING, NOT AN EXEMPTION. Without a store
            // `doctor session` answers could-not-look — exit 3 — and this census
            // refuses that as evidence by construction: a verb that failed
            // internally proves nothing by not emitting content. Seeding it is
            // what makes `doctor session` actually read prose and then decline to
            // print it, which is the only version of this assertion worth having.
            //
            // The subject is a CONTENT canary because that is exactly what it is:
            // free text an agent wrote. The verb may emit the id `1` and the
            // counts, and must never emit the line beside them.
            .file(
                ".tasks/1.json",
                &format!(
                    "{{\n  \"id\": \"1\",\n  \"subject\": \"{}\",\n  \"status\": \"pending\"\n}}\n",
                    canary("declared"),
                ),
            )
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
            // The merged-pull-request evidence `landed check` reads. It carries
            // no canary because it structurally cannot: the file is a key and a
            // pull request number per line, which are pointers by construction.
            // What it buys is the LIVE READING — without it the verb refuses on
            // absent evidence and the census would be asserting over a run that
            // never reached the finding renderer, which is where a leak would
            // actually happen.
            //
            // `.tsv` is outside every glob `authority` declares (`**/*.txt` and
            // `**/*.md`) and outside the budget's named file list, so seeding it
            // adds subject matter for exactly one verb.
            .file("landed-merged.tsv", "CLOUD-1120\t726\n")
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

/// Plan entries read on stdin by `record plan`. The id carries the canary, so a
/// refusal that echoed an entry back — the one thing this store must never put in
/// a diagnostic, since an id is the agent's own text — fails the census.
fn plan_entries() -> String {
    format!("{} pending\n", canary("entry"))
}

/// A pull request body read on stdin by `record closes`. The body is the largest
/// payload any verb in this census is handed and the one most likely to be echoed
/// by accident — a refusal quoting the line it could not parse would put a whole
/// paragraph of someone's prose into a diagnostic.
fn pr_body() -> String {
    format!("Closes CLOUD-1\n\n{}\n", canary("body"))
}

/// Paired records read on stdin by `perf compare` (CLOUD-1163 unit 10).
///
/// **The canary rides in `mean`, and choosing the field was the whole exercise.**
/// Most of this record is emitted BY DESIGN: `path` is the benchmark id a refusal
/// must name, and the two `p50`s are the measurement the ratio is computed from,
/// so a canary in any of them would assert the opposite of rule 4. `mean` is the
/// field the comparison deliberately never reads — the module states why p50 and
/// not p95, and mean is unused entirely — so it is content the verb was handed and
/// has no business repeating.
///
/// The pair regresses on purpose (3.0 -> 9.0, 3x against a 1.30x threshold), so
/// the verb answers with a VERDICT rather than a could-not-look. A refusal is
/// where a gate is most tempted to quote its input, and it is the only path here
/// worth pointing this census at.
fn paired_records() -> String {
    let canary = canary("mean");
    format!(
        "arm=base path=noop p50=3.0 p95=3.0 mean={canary} runs=100\n\
         arm=head path=noop p50=9.0 p95=9.0 mean={canary} runs=100\n"
    )
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

/// The tracker payload `landed check` sweeps, carrying a body field beside the
/// two fields the sweep is entitled to.
///
/// The row is `In Progress` and `landed-merged.tsv` says a merged pull request
/// closed it, so the verb reaches its FINDING renderer rather than its clean
/// line — which is the only arm where a leak could happen, and therefore the
/// only arm worth asserting over.
fn board_payload() -> String {
    format!(
        "[{{\"id\":\"CLOUD-1120\",\"status\":\"In Progress\",\"description\":\"{}\"}}]",
        canary("boardrow"),
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
    PlanEntries,
    PrBody,
    PairedRecords,
    Board,
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
/// THE FIVE LEASE WRITE ARMS JOIN IT, and the reason is the corpus rather than
/// the verbs. Each reaches `lease::swap`, the compare-and-swap against a remote
/// ref, and this corpus is a repository with no remote configured — so their
/// honest answer here is could-not-look and no lighter fixture changes that
/// without standing up a git server.
///
/// The five READ arms are deliberately NOT here: a clone with no remote is an
/// answer for them, not a failure, so they exit `0` (or `2` for `held`, which
/// asks whether this clone holds a lease and is being told that it does not).
/// That asymmetry is the same effect split the read-only allowlist draws, and
/// keeping it visible here is what stops the whole verb being waved through.
/// THE TWO `hk` ARMS JOIN IT, and the reason is the corpus rather than the verbs
/// (CLOUD-947, CLOUD-949). Both reach the pinned gate runner — the generator to
/// take a plan, the gate to take one and diff it — and this corpus deliberately
/// stands up no runner and commits no contract, so could-not-look is their
/// honest answer here. No lighter fixture changes that without provisioning a
/// third-party binary, which is the same bar `mutate sweep` states one row down.
///
/// The pointer-only assertions still run over both, unchanged, which is the half
/// this file is actually about: what a could-not-look arm emits is a class token
/// and a path, and it is held to that here exactly as a verdict would be.
const MAY_ANSWER_COULD_NOT_LOOK: &[&str] = &[
    "hk contract",
    "hk drift",
    "mutate sweep",
    "lease acquire",
    "lease hold",
    "lease release",
    "lease renew",
    "lease reserve",
    // `land replay` joins them for the same reason one hop earlier: it FETCHES
    // before it replays, so a corpus with no remote configured cannot reach the
    // replay at all and could-not-look is its honest answer here.
    "land replay",
    // `land wait` joins it because the two arms share one preamble: the remote is
    // resolved for BOTH before either reaches its own work, so a corpus with no
    // remote configured stops the wait in the same place it stops the replay. The
    // roster refusal below it — a `Usage` about the invocation — is never reached
    // here, which is why naming that one as the sweep's answer was wrong.
    "land wait",
    // And `land push`, which shares that preamble too and cannot reach the
    // remote at all on a corpus that names none.
    "land push",
];

/// One entry per leaf verb of [`SURFACE`], asserted total by
/// [`every_leaf_verb_is_classified`] in both directions.
const CENSUS: &[Verb] = &[
    // THE LANDING LEASE, ten arms (CLOUD-1274, CLOUD-393). Every one is
    // pointer-only by construction and the construction is the lease BODY: it is
    // a fixed set of tokens — a holder id, an expiry, a branch, two shas, a
    // progress counter and a nonce — with nowhere for prose to travel, and
    // `lease_report` renders a state token plus named fields rather than a
    // message. The one string that could carry anything is the transport's own
    // failure, and that goes to stderr as a diagnostic.
    //
    // THE CREDENTIAL IS THE REASON THIS MATTERS MORE HERE THAN ELSEWHERE. These
    // arms read `GH_TOKEN`/`GITHUB_TOKEN` to authenticate the push, and
    // `lease::credential` deliberately returns it to nobody — it is not a field
    // of `Terms` or of any other value, because a token in a struct is a token in
    // that struct's `Debug`. This census is what keeps that true from the
    // outside.
    Verb {
        path: "lease status",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        path: "lease check",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        path: "lease authorises",
        args: &["--branch", "work"],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        path: "lease peek",
        args: &["--field", "next"],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        path: "lease held",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        path: "lease acquire",
        args: &["--branch", "work"],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        path: "lease renew",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        path: "lease hold",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        path: "lease release",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        path: "lease reserve",
        args: &["--branch", "work"],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    // THE LANDING LAP (CLOUD-1335), pointer-only by construction for the lease
    // subtree's reason: what it reports is a sha, a count and a path, and the one
    // thing a replay could otherwise leak is the CONTENT of a conflict — which is
    // exactly what `gitwrite::rebase` hands back as `{commit, paths}` rather than
    // as hunks, so there is no prose channel for a marker to travel down.
    Verb {
        path: "land replay",
        args: &["refs/heads/main"],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    // `land wait` is pointer-only for a narrower reason than its sibling and it
    // is worth stating, because the verb reaches a forge: what it renders is a
    // sha, a base and an ASK COUNT, and the one string that could carry anything
    // is `checks_green`'s roster verdict — a token per required name, never a
    // check's own output.
    Verb {
        path: "land wait",
        args: &["refs/heads/main"],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    // `land push` reports a branch name and a sha, and the one string that could
    // carry anything — receive-pack's own rejection reason — is dropped at the
    // boundary rather than rendered, because this store is read by a predicate
    // and a fixed-column record is no place for a server's prose.
    Verb {
        path: "land push",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    // `land verify` reports a sha and a token. The gate's own output is the one
    // thing that could carry anything, and it never passes through this verb at
    // all — `exec` writes it to the caller's terminal, and what comes back here
    // is an exit code. On this corpus `$LAND_VERIFY` names nothing, so the verb
    // refuses before running anything, which is `Usage` rather than a
    // could-not-look and needs no entry in the set above.
    Verb {
        path: "land verify",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    // `landed check` (CLOUD-186, CLOUD-1127) reads a tracker payload, which is
    // the widest body on any read surface: a row carries a description an agent
    // wrote and a consumer's own facts sit in it. What it renders is a key, two
    // column names, a reason token and — on the asserted arm — the caller's own
    // ref. `landed::Finding` has no field prose could occupy, the same way
    // `commit-meta` has no body field, and this is what decides that from the
    // outside rather than from the type's doc comment.
    Verb {
        path: "landed check",
        args: &["--merged-prs", "landed-merged.tsv"],
        stdin: Stdin::Board,
        disposition: Disposition::PointerOnly,
    },
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
    // The lane's receipt, driven to the same lane-absent refusal as the five `pr`
    // verbs above and pointer-only on the same structural terms: `bot::Attested`
    // holds a key, a login and a number, and there is no field a body could
    // travel in.
    Verb {
        path: "claim bot",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    // The third board verb, and structurally pointer-only for a reason worth
    // naming because its subject is unusually leaky: the table it judges carries a
    // LICENCE TEXT and a COPYRIGHT HOLDER per row, which is exactly the kind of
    // third-party string rule 4 is about. `carry::Refusal` has nowhere to put one
    // — every variant carries a repo, a path or a line number and there is no
    // field a verdict body could travel in — so a refusal names which row is
    // wrong without ever quoting what it compared.
    Verb {
        path: "claim carry",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    // The duplicate-claim half (CLOUD-1422), and pointer-only STRUCTURALLY rather
    // than by careful rendering: `race::Race` is a key, a pull request number and
    // a head ref, so a title, a body or a commit message has no field to travel
    // in. That matters more here than for most rows, because everything this verb
    // reads is prose somebody else wrote on a pull request that is not ours — the
    // retired shell had to promise the same thing about its own `echo` lines, and
    // a promise is what a type makes unnecessary.
    Verb {
        path: "claim race",
        args: &[],
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
    // The bot lane's five verbs (CLOUD-1295), and every one of them is driven to
    // its LANE-ABSENT refusal rather than to the forge, for `pr watch`'s reason
    // one entry up: a census entry that reached the network would not be a slow
    // case, it would be one whose answer depends on somebody else's server. This
    // corpus declares no `[bot_lane]`, so each refuses before the first request.
    //
    // That is not a weaker question than it looks. What these verbs could leak is
    // a bot pull request's BODY — a release-notes dump for every bumped package —
    // and the structural answer is that `bot::Pull` is the only place a body
    // lives, no refusal formats one, and the emission paths carry a number, a key
    // or a path. `crates/batten/tests/it/bot_lane.rs` drives the same law against
    // a stubbed forge with a canary in the body, which is the half this corpus
    // cannot reach.
    Verb {
        path: "pr derive",
        args: &["7"],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        path: "pr file",
        args: &["7"],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        path: "pr link",
        args: &["7", "KEY-1"],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        path: "pr ensure",
        args: &["7"],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        path: "pr closes",
        args: &["7"],
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
    // POINTER-ONLY OVER AN INPUT THAT LOOKS HARMLESS AND IS NOT (CLOUD-1399).
    // This verb's whole subject is two environment variables, and a `NO_PROXY`
    // list is a consumer's network layout: internal hostnames, CIDR blocks, the
    // proxy's own address. Echoing what it read would put exactly that in a
    // diagnostic that promises not to, and it would defeat §6's byte-stability
    // since the value differs per machine. The remedy is a change to the
    // container's Environment variables field, and the verdict is what says
    // whether to make it.
    Verb {
        path: "doctor egress",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        path: "doctor hooks",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    // Pointer-only for a sharper reason than its siblings, because this verb's
    // whole subject is two absolute paths and two digests (CLOUD-1349) — the
    // shape most likely to leak one into output. It emits neither: the verdict is
    // a stable token, and a digest is deliberately withheld because it is stable
    // per content but varies per machine, so printing one would defeat §6's
    // byte-stability while telling the reader nothing they can act on. The remedy
    // is `mise run install:local`, and the verdict is what says whether to run it.
    Verb {
        path: "doctor mediator",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    // THE SESSION'S OWN DECLARED WORK (CLOUD-1376), and its content class is the
    // reason it belongs here rather than being obvious. What this verb reads is a
    // task store whose members carry a `subject` and a `description` — free prose
    // an agent wrote, which is exactly the CONTENT class above. What it emits is
    // two integers and a list of ids.
    //
    // So the pointer-only promise is load-bearing rather than incidental: an id
    // sends a reader to the task, and a subject line would hand the session its
    // own prose back as input — the mirror a restatement can clear, which is the
    // defect `finding-sink-check` documents at length. The compiled-binary tier
    // asserts the negative directly, and this census is what stops a later
    // revision widening the output without answering the question.
    Verb {
        path: "doctor session",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        // The adopted runner's contract (CLOUD-947, CLOUD-949). Both verbs are
        // `PointerOnly` because both are: the generator emits one path, and the
        // gate emits a class token, a hook and a step NAME per drifted step. The
        // one thing neither carries is what a plan SAYS — no command, no glob, no
        // matched path, no reason prose — which is the exclusion the types
        // enforce rather than the census.
        //
        // In the corpus neither reaches the runner at all, so both take the
        // could-not-look path; the pointer they emit there names the artifact and
        // the verb that regenerates it, which is the same shape.
        path: "hk contract",
        args: &[],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        path: "hk drift",
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
    // The aggregate half of the verb above, and pointer-only for a sharper
    // reason than its own: its subject is a session transcript, which is the
    // richest secret surface this engine can be pointed at. Nothing it emits
    // could carry a byte of one even by accident — `transcript.rs` hashes each
    // hook emission and DROPS it at the parse, so the text does not reach the
    // module that reports, let alone the report (CLOUD-417).
    Verb {
        path: "policy hooks",
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
    // The container's declared preconditions (CLOUD-1324). Pointer-only by
    // construction rather than by care: a row renders as its own `id` and a
    // verdict token, and the command it ran is spawned with both streams
    // discarded, so there is no path by which a check's output could reach the
    // report. What a row MEANS is its `gloss` in the reader's own committed
    // config, which is where the prose lives instead.
    //
    // Driven BARE, without `--repair`, for `wiring reclaim -n`'s reason one noun
    // over: this corpus is a fixture tree, and a verb allowed to repair it would
    // be measuring bytes it had just rewritten.
    Verb {
        path: "startup",
        args: &[],
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
        path: "adjudicate",
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
    // The verdict over a pair, and the composition that takes one (CLOUD-1163
    // unit 10). Both report a BENCHMARK ID, two p50s and a ratio — the same
    // numbers `pair` already emits, rearranged into a comparison. Nothing else
    // reaches the output: not the records that were rejected (a malformed line is
    // reported as `stdin:<n>`, never quoted), and not the hyperfine output behind
    // any of it.
    //
    // The one thing here that IS content is an exemption's `reason`, carried into
    // the `::warning::` line verbatim. That is deliberate rather than an
    // oversight, and it is not a leak: the reason is text the committed authority
    // declares in order to be read at exactly this moment, so suppressing it would
    // make an accepted regression anonymous — which is the failure the loud line
    // exists to prevent. Rule 4 is about not quoting the SUBJECT a check read; a
    // config value that exists to be quoted is the check's own vocabulary.
    //
    // In this corpus both answer over empty stdin, so `compare` is a could-not-look
    // and `gate` skips on a fixture whose HEAD is its own merge base. Both are
    // pointers either way, which is what is being decided.
    Verb {
        path: "perf compare",
        args: &[],
        stdin: Stdin::PairedRecords,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        path: "perf gate",
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
    // CLOUD-587. Pointer-only, and here it is load-bearing rather than routine:
    // the findings this verb answers are drawn from a session transcript, so the
    // content is exactly what must not travel. It emits the identity and the
    // disposition token and nothing else.
    //
    // The args are a real identity's shape and a declared token, because both
    // positionals are required — an omitted identity would have to mean "every
    // finding" and an omitted disposition would have to guess what was decided.
    Verb {
        path: "state settle",
        args: &[
            "0000000000000000000000000000000000000000000000000000000000000000",
            "acted",
        ],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    // CLOUD-1180's recovered `agent` slice. `PointerOnly` and not `Echoes`,
    // which is the load-bearing distinction here: it reports the repository's
    // own gates, and a gate's `pattern` and `glob` are the consumer's policy
    // text. So it emits each gate's id and severity and nothing else — asserted
    // over the emitted bytes in
    // `agent_capabilities::the_verb_reports_this_repositorys_gates_as_pointers`.
    // `spec` is `Echoes` because it echoes Batten's OWN declarations; this one
    // reads the caller's tree, so that exemption does not transfer.
    Verb {
        path: "show agent",
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
    // CLOUD-472. The entry id piped in carries the canary, because an id is the
    // AGENT's own text and is the one thing a refusal here must never echo — a
    // malformed line is reported by its NUMBER and the closed status vocabulary,
    // which is `record tool`'s discipline over a different payload.
    Verb {
        path: "record plan",
        args: &[],
        stdin: Stdin::PlanEntries,
        disposition: Disposition::PointerOnly,
    },
    // The body is prose somebody wrote and the record is a COUNT and a key list,
    // so nothing this verb emits may carry a word of it — which is the same rule
    // `record plan` follows over a smaller payload.
    Verb {
        path: "record closes",
        args: &[],
        stdin: Stdin::PrBody,
        disposition: Disposition::PointerOnly,
    },
    // The task registry's six writers (CLOUD-425). Each answers with silence and
    // an exit code — the record's destination is a keyed file under `$GIT_DIR`,
    // so there is nothing for a successful write to say. `PointerOnly` rather
    // than `Echoes`, deliberately: the value a push carries IS the caller's own
    // declaration, so an echo would be defensible, and refusing it here is what
    // keeps a task's phase string — which the loop composes out of whatever it
    // was reading at the time — off both channels by construction.
    Verb {
        path: "task register",
        args: &["land", "4194304", "starting"],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        path: "task phase",
        args: &["4194304", "rebasing"],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        path: "task tick",
        args: &["4194304", "7"],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        path: "task sig",
        args: &["4194304", "queued"],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        path: "task unregister",
        args: &["4194304"],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    // The one reader, and it answers with a FIELD rather than a layout. Nothing
    // registered in this corpus, so it answers `Violation` and emits nothing —
    // which still exercises the emitter under judgement, because a refusal
    // naming the pid is a pointer and one quoting the record would not be.
    Verb {
        path: "task read",
        args: &["4194304", "phase"],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    // The task registry's reader (CLOUD-425). Pointer-only, and for this verb
    // that is the POINT rather than hygiene: being forced to read a task's log
    // is the defect the registry removes, so a reader emitting log content would
    // reintroduce it through the front door.
    Verb {
        path: "task alive",
        args: &["--program-root", "mise-tasks"],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    // One task per clone (CLOUD-428). The refusal names a pid and, where the
    // registry knows it, the holder's phase — and NOTHING else of the record it
    // read to find that. Both rows are `PointerOnly` for the reader's reason one
    // entry up: the registry exists so nobody has to read a log, and a refusal
    // quoting one would reintroduce that through the front door.
    Verb {
        path: "singleton acquire",
        args: &["land", "4194304"],
        stdin: Stdin::Nothing,
        disposition: Disposition::PointerOnly,
    },
    Verb {
        path: "singleton release",
        args: &["land"],
        stdin: Stdin::Nothing,
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
        Stdin::PlanEntries => plan_entries(),
        Stdin::PrBody => pr_body(),
        Stdin::PairedRecords => paired_records(),
        Stdin::Board => board_payload(),
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
