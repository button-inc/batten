use crate::config_model::{DeclaredVerdict, Route};
use crate::preset_catalog::Applicability;
use crate::preset_catalog::{VendoredRoute, VendoredVerdict};
use crate::preset_catalog::{admit, read, run};

/// CLOUD-1823's route, shared by the two receipt classes a `turn mint ahead`
/// deadlock can carry (CLOUD-1977) so the precondition is written once.
pub(crate) const STALE_RECEIPT_ROUTE: VendoredRoute = admit(
    "articulate the stale receipt",
    "the check this receipt names is red on this head for a reason only a write can repair, so \
re-running it cannot change its answer, and the work the receipt was taken about is already \
pushed",
);

/// CLOUD-1806's route: the recorded way through every plain `shape` row.
pub(crate) const SHAPE_ADMIT_ROUTE: VendoredRoute = admit(
    "articulate the call",
    "the remedy `batten policy explain` prints for this row cannot perform the change this call \
makes, and you can name what the call changes and where a reviewer will see its effect",
);

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
pub(crate) const VENDORED: &[VendoredVerdict] = &[
    // ── native ──────────────────────────────────────────────────────────────
    VendoredVerdict {
        id: "path write refused",
        gloss: "a mutating verb was aimed at a path the config protects",
        class: "The path is in the `protected` set, so a write to it is refused before it \
happens rather than reported after. The set is the consumer's own declaration; what is \
protected is a question about their repository, and the engine only enforces it. A \
narrower remedy may be declared per path class through `[[redirect]]`, which is what the \
refusal names when one exists.",
        routes: &[
            read("config read first", "batten.toml"),
            run("patch run first", "git restore"),
            // THE CLASS COULD NOT BE OVERRIDDEN, AND THAT LEFT ONLY THE PASSWORD.
            //
            // The two routes above are real and are the right first answers, but
            // neither reaches a path whose owning surface IS the protected file —
            // registering a rule, adding a redirect, retiring a gate onto a config
            // row. For that class of change `config read first` names the
            // file being refused, so the remedy is the thing denied.
            //
            // With no override route, `admission::questions_for` returns `None` and
            // `batten override request` answers "declares no `override` route, so
            // it cannot be overridden". The only remaining exit was the general
            // hatch (since retired) — a knowable string the guarded party could
            // set, which recorded nothing and stopped nobody. This repository already ruled
            // on that shape for `issue file same`: *the point of the admission
            // mechanism is that the bare variable stops working*.
            //
            // The precondition is what the asker must be ABLE TO STATE, never a
            // judgement the gate makes (non-negotiable rule 3). It names the owning
            // surface deliberately, so the first question forces the asker to say
            // why the route they were already given does not reach.
            admit(
                "articulate the write",
                "the surface this class names cannot express the change, so writing the \
protected path directly is the only route left, and the write is one a reviewer will see \
in the diff it lands in",
            ),
        ],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "program name unknown",
        gloss: "the boundary cannot classify this program, so it will not guess at a protected path",
        class: "This is an ADMISSION rather than an accusation: nothing here says the \
command mutates. The program appears in neither `[[verb]]`, whose rows encode a program's \
argv grammar, nor `protected_readers`, which declares a program to only read — so what it \
would do to an operand is unknown, and the operand is a protected path. Silence used to \
mean allow, and an allowlist-by-omission's omissions were holes: an interpreter writing a \
protected path went unrefused while a redirect to the same path was denied. The direction \
is inverted, which makes a forgotten reader a false refusal somebody fixes in a minute \
rather than a silent hole. A compiled floor of programs that only ever read their operands \
is consulted first, so the ordinary read tools never reach this class — and note that a \
protected path may be DERIVED rather than declared: registering a policy module protects \
it, so this can fire in a repository whose `protected` set is empty.",
        routes: &[
            read("config read first", "batten.toml"),
            run("readers declared", "batten config show"),
        ],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "rule read missing",
        gloss: "a config row changed by a context that has not read why it exists",
        class: "A rule's reasons live in the comment block above its row, its class \
paragraph and the commits that shaped it, and nothing checked that a context changing the \
row had read any of them -- which is how a gate's prose decays into a gloss nobody can act \
on. So a write to a `[[rule]]` or `[[verdict]]` row of the committed authority needs this \
context to have read that row's history, as it stands at HEAD: a commit to the row voids \
the read, and so does a compaction, because what was read left the window with it. A new \
row has no history and needs none.",
        routes: &[
            run("rule read first", "batten policy explain '<id>' --history"),
            admit(
                "articulate the sweep",
                "the write is one mechanical change applied across many rows, named in full, \
whose every row would need the same history read for no different decision",
            ),
        ],
        applicability: Applicability::Advice,
    },
    // CLOUD-2290. Raised by `rules::ejected_behind`, never by a module.
    VendoredVerdict {
        id: "module pin stale",
        gloss: "a module ejected from a preset was copied at an older preset version than this binary ships",
        class: "`batten preset eject` copies a vendored module into this repository and records \
the preset version it copied, so the copy stops changing when the binary does. That is the \
point of ejecting, and it is also how a copy quietly misses a fix the preset shipped later. \
This is a WARNING and a pointer, never a diff: what changed is the release notes' to say, and \
whether to take it is this repository's call. Take it by hand and raise the recorded version, \
or raise the version alone to say the change was read and declined.",
        routes: &[run("module read first", "batten preset eject --help")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "task run twice",
        gloss: "a live process in this clone already holds this task's lock",
        class: "Some tasks are one-per-clone: a second copy does not do the work \
twice, it races the first over the same refs, the same lock and the same remote. The \
task itself refuses a second copy, and this is the same refusal arriving before a \
process starts rather than a fraction of a second after. A lock naming a DEAD pid is \
not this class -- that is a corpse the acquiring path reclaims. A lock naming NOTHING \
READABLE is this class: a holder caught between its create and its write is a holder, \
which is the reading the acquiring path already takes, and a gate disagreeing with it \
would allow a start that path then refuses.",
        routes: &[read("holder inspected", "batten task alive")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "history drop unpushed",
        gloss: "the reset would discard commits that exist in no other clone",
        class: "`git reset --hard` moves the branch and discards the working tree \
and the index together, with none of the \"you have unstaged changes\" refusals that \
stop git's other destructive verbs. Where every commit in the discarded range is on a \
remote that is the ordinary undo and nothing is lost. Where one is not, the only copy \
of that work is the commit being removed, and it is unreferenced the moment the reflog \
expires. The class fires on the second case only: the verb is not the defect, \
reachability is.",
        routes: &[
            // The two verbs that reach the same outcome without discarding a
            // commit. Named as the FIRST route because a caller who wanted to
            // drop a change usually wanted to drop a change, not a commit.
            //
            // The first draft named the set-aside verb `no_gix_gap_primitive_survives`
            // refuses anywhere in this tree: the primitives built on it retired with
            // the spawn they required (CLOUD-780), and a route naming a retired
            // concept is a remedy nobody here can follow. `--soft` is the better
            // answer anyway — it moves the same ref and leaves both the tree and the
            // index where they were.
            // THE RECOVERY LEADS, per the row's §5: a caller who reads this has
            // not lost anything yet, and what they need first is that the commit
            // is still reachable. It was a `Fix::Run` string at the deny site
            // (`hook::history_drop_refusal`) for its whole life, which rendered
            // only while `Fix` led the routes clause; CLOUD-1637 stopped
            // rendering `Fix`, so the recovery is declared here — on the class,
            // once, beside the other ways out — rather than smuggled through one
            // call site.
            run("commits still reachable", "git reflog"),
            // `run` RATHER THAN `read`, AND THE KIND WAS WRONG BEFORE
            // (CLOUD-1637). Both targets are commands and both were declared
            // `read`, which was inert while `command_routes` filtered the clause:
            // a `document` route rendered nowhere, so nothing read the kind and
            // nothing caught it. Now the kind decides the verb a reader is given,
            // and "read `git reset --soft`" is an instruction nobody can follow.
            run("ref moved, work kept", "git reset --soft"),
            run("file reverted", "git checkout -- <path>"),
            // The way through that leaves a record, which is what keeps this a
            // gate rather than a wall. Its precondition also makes the class
            // non-suppressible by any hatch (CLOUD-1357), which is
            // right for a verb whose subject is gone by the time anyone reads
            // the refusal.
            admit(
                "articulate the loss",
                "the commits this discards are ones you have read and intend to lose, and \
you can name what they contained without consulting them",
            ),
        ],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "config write refused",
        gloss: "`init` will not overwrite the committed authority",
        class: "House style §8 gives a repository ONE committed authority, and `init` \
writes it. Overwriting an existing one would replace a reviewed policy with a default \
set, silently, in a verb whose whole purpose is that there was nothing there before. \
Edit the file that exists, or move it aside deliberately.",
        routes: &[read("config read first", "batten.toml")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "outcome table refused",
        gloss: "an `[[outcome]]` row could not mean anything",
        class: "A post-tool signature names the class it establishes, the exit code that \
anchors it, and the OS family it applies to. A row naming a class the engine cannot resolve, \
a family nobody surveyed, or a code a second row already claims is an arm that fires on \
nothing — and a declared-but-dead arm is worse than an absent one, because it reads as \
coverage while its route has never been walked. The refusal names the row and the key.",
        routes: &[read("config read first", "batten.toml")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "plan read stale",
        gloss: "the committed plan projection no longer matches the pinned runner",
        class: "An adopted runner decides which steps a gate runs, in what order, under \
which profiles and in which parallel group, and the committed projection is the reviewed \
answer to that. A live plan that differs means the gate now enforces something nobody \
read a diff of. Regenerate the projection and review the diff — the difference is the \
decision, and absorbing it silently is what this refuses.",
        routes: &[run("contract run first", "batten hk contract")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "handler answer denied",
        gloss: "a configured hook handler denied the call",
        class: "The refusal is the handler's, not the engine's: a `[hook.handler]` row \
names a program, the program answered deny, and this carries that answer through. The \
handler's own reason is free text the consumer configured, so no remedy is invented here \
— the handler is where a remedy would have to be declared.",
        routes: &[read("config read first", "batten.toml")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "scanner pin missing",
        gloss: "a `secrets` rule needs its scanner pinned and none is declared",
        class: "A `secrets` rule delegates to an external scanner, and which scanner \
decides what the rule means. An unpinned one would resolve to whatever is ambient, so a \
green run would say nothing about the tree — the same defect a bare `cargo` has against \
a pinned toolchain. Declare the scanner as a `[[provision]]` entry.",
        routes: &[
            run("check run first", "batten provision"),
            read("config read first", "batten.toml"),
        ],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "scanner install missing",
        gloss: "the pinned scanner is not in the provision cache, so nothing was scanned",
        class: "The scanner is declared and absent. This is could-not-look rather than a \
clean tree, and it is reported as a refusal precisely so the two are not spelled the \
same way: a secrets rule that scanned no file and reported nothing is the vacuous pass \
this engine argues against everywhere.",
        routes: &[run("check run first", "batten provision")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "spawn run refused",
        gloss: "this rule kind runs a configured command, which a read-effect verb will not do",
        class: "The effect model (house style §5) puts every verb in one class and holds \
it there. A rule kind that spawns is `Effect`, and `check` is `Read`, so reaching one \
through the other would make the read-only allowlist a claim nobody could rely on. The \
rule is not wrong; the verb is.",
        routes: &[run("check run first", "batten enforce")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "turn finish unmet",
        gloss: "the end-of-turn facts do not permit stopping",
        class: "A stop is a completion signal, and this engine's whole subject is keeping \
that signal aligned with landed-and-verified work. The facts the turn ended on say it is \
not, and the refusal names which. Each has its own route; the shared one is to finish \
the thing rather than to re-declare that it is finished.",
        routes: &[
            run("task run first", "mise run land"),
            read("config read first", "batten.toml"),
        ],
        applicability: Applicability::Advice,
    },
    // ── the mediated composers' classes (CLOUD-1285) ────────────────────────
    //
    // The cause each of these carries used to be a hardcoded `format!` in
    // `hook.rs` that `Refusal::new` then dropped the class for. Moving the prose
    // here is what makes it dereferenceable: `batten policy explain <token>`
    // answers with the `class` below, so the hot path can carry the token and the
    // pointers and stop repeating the paragraph on every firing.
    VendoredVerdict {
        id: "receipt read missing",
        gloss: "a declared receipt does not attest the commit this call is made against",
        class: "A `receipt` row names checks whose verdict must already exist for this \
commit, in this checkout. The receipt is missing, older than the row allows, recorded \
against a different head, or records something the row does not accept -- and the refusal \
names which, because the four call for different repairs. Re-running the check is the \
remedy for a missing one and useless for a refuted one.",
        // CLOUD-1823's route, declared where the refusal lands (CLOUD-1977). A red
        // check writes no receipt, so `turn mint ahead` over a red head refuses as
        // MISSING, never as `receipt read other`. The route there alone was
        // unreachable from the deadlock it was written for: `admit_mediated` binds
        // to the class the refusal carries.
        routes: &[
            read("config read first", "batten.toml"),
            STALE_RECEIPT_ROUTE,
        ],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "receipt read late",
        gloss: "the receipt exists and is older than the row allows",
        class: "The step RAN, and not recently enough for its verdict to still be evidence. \
That is a different repair from a missing receipt and is why it is a different class: \
re-run the check. A row declaring a `max_age` is saying the world can move underneath the \
answer, so an old verdict is could-not-look rather than a pass.",
        routes: &[read("config read first", "batten.toml")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "receipt carry other",
        gloss: "the receipt records something this row does not accept",
        class: "The step ran and what it recorded is not what the row requires. This is the \
one receipt class that is a statement about what was READ rather than about the read, so \
re-running the check changes nothing until the thing it reports is fixed. An ABSENT field \
is could-not-look and is not this class.",
        routes: &[read("config read first", "batten.toml")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "receipt read other",
        gloss: "an amend or a rebase replaced the bytes this receipt validated",
        class: "The receipt is keyed to a commit this branch no longer carries. Its verdict \
covered the bytes it read and nothing later, so it is not evidence about this head. Re-run \
the check against what is here now. Kept apart from the trunk case because the two name \
different things that moved, and a refusal that says the wrong one sends the reader after \
the wrong repair.",
        routes: &[
            read("config read first", "batten.toml"),
            // THE RE-RUN IS THE RIGHT FIRST ANSWER AND SOMETIMES CANNOT BE TAKEN
            // (CLOUD-1823), which is the same hole `path write refused` had:
            // a class whose only route is the thing the refusal blocks.
            //
            // Measured twice. `turn mint ahead` is keyed to the head and triggers
            // on WRITE, so where the named check is red for reasons only a write
            // can repair, "re-run the check" prescribes a run that cannot change
            // its answer, and the write that would is the call being refused. The
            // branch has no exit: every edit is denied, and the denial is
            // discharged only by the edits. With no override route
            // `admission::questions_for` returns `None`, so the sole remaining way
            // through was the general hook hatch — a knowable string that records
            // nothing, which this repository already ruled on for `issue file
            // same`: *the point of the admission mechanism is that the bare
            // variable stops working*. The hatch is retired engine-wide now, and
            // `admit_mediated` (`lib.rs`) is what consumes a spent admission.
            //
            // THE ROUTE IS HEAD-BOUND, SO IT IS NOT THE EXIT FOR A LONG EDIT
            // (CLOUD-843): an admission binds `Anchor::Call { head }`, and every
            // commit voids it. `turn mint ahead` escapes the wedge through
            // `while_unpushed` instead — a pushed head is the harm the row names
            // being absent — and this route stays for a head that cannot be pushed.
            //
            // The precondition is what the asker must be ABLE TO STATE, never a
            // judgement the gate makes (non-negotiable rule 3). Both halves are
            // checkable by a reader: whether the check is red on this head, and
            // whether the work the receipt was about is on a remote. The second
            // half is the one that matters — it is the harm the refusing row
            // actually guards, and an asker who cannot state it is being stopped
            // for the right reason.
            STALE_RECEIPT_ROUTE,
        ],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "receipt read stale",
        gloss: "the receipt was taken against a trunk this branch has moved off",
        class: "The branch MOVED FORWARD off the base the receipt was taken against -- \
`git checkout -B <name> origin/main` after a merge, which repoints the name at a new base \
and discards the commits that were the branch, while the receipt survives keyed by that \
name. Re-take the evidence on the branch as it now stands. Distinct from the amend case: \
there the branch's own bytes changed, here the branch is a different branch wearing the \
same name. THE DIRECTION IS THE PREDICATE (CLOUD-1091): a branch merely BEHIND the trunk \
keeps its receipt, because the receipt is then more current than the branch and no amount \
of re-taking it can help -- this text said the opposite for its whole life and prescribed \
the one action guaranteed not to work.",
        routes: &[read("config read first", "batten.toml")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "tool run loose",
        gloss: "a shell text utility stood in for the structured file surface",
        class: "The call reaches for a text utility over a path this repository CONTAINS, as \
its FIRST stage, to answer a question the structured surface answers directly and better: \
a range of one file's contents, a pattern across the tree, paths by glob, or what a name \
resolves to. Which instruments a session carries varies, so the refusal names the question \
classes rather than a product. The same utility DOWNSTREAM of a pipe is untouched, because \
filtering another command's output is not standing in for anything. CONTAINMENT, never the \
INDEX (CLOUD-1109): the boundary resolves the operand against the call's own working \
directory and asks whether the repository contains the result. It does not ask git, because \
a `git ls-files` per mediated call is a spawn `RuleKind::scopes` forbids on this kind and \
`perf-assert` prices out. This text said 'tracks' for its whole life and nothing ever \
checked it -- a class a reader believes is worse than one they cannot look up.",
        routes: &[read("rule read first", "rules/scanning.md")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "path read routed",
        gloss: "this path declares its own read route, named after it",
        class: "A structured READ of a path whose `[[redirect]]` row declares a `read` \
remedy (CLOUD-1258). The row exists because a path read couples the caller to the tree \
layout, and the named tool survives a move of that tree where a hardcoded path does not. \
The refusal names the path and then the declared route, so the way out is on the line \
itself; the tool that read it is the envelope's own and is not repeated, which keeps the \
longest committed memory name within `[refusal] max_tokens`. A row declaring no `read` refuses nothing, \
which is how a consumer whose session does not carry the tool says so. Not `tool run \
loose` (CLOUD-1929): no shell utility was involved, and that class's route sent a memory \
reader to the scanning rules instead of to the tool its own row names.",
        routes: &[run(
            "rule explain first",
            "batten policy explain protected-mutation",
        )],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "verdict read dropped",
        gloss: "piping a verdict-bearing command into a pager or filter discards its status",
        class: "The pipeline exits with the FILTER's status, which is 0 whether the command \
passed or failed. A verdict is read from the harness, never inferred from output. Background \
the command and read the exit code the notification carries; a pager over a FILE is fine, a \
pager over a live task is not. DO NOT REDIRECT INSTEAD -- this text prescribed `> file 2>&1` \
for its whole life, and `redirect write unread` now refuses exactly that, because the harness \
already captures a backgrounded task's output where the human watches.",
        routes: &[read("rule read first", "rules/toolchain.md")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "verdict carry other",
        gloss: "a verdict-bearing command followed by `;`, `||` or a newline has its status replaced",
        class: "Only the last element's status survives, so the compound reports the wrong \
command's verdict. This is the laundered shape: it reads as correct, and backgrounded it is \
worse than a misread, because the completion notification then carries the compound's \
status. `&&` is fine -- it short-circuits, so a failure still propagates.",
        routes: &[read("rule read first", "rules/toolchain.md")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "turn watch dropped",
        gloss: "detaching a command orphans it from the tool call",
        class: "`nohup` or a trailing `&` returns the call at once, the harness records it \
complete, and the session loses the wake-up it would get when the work actually exits. \
Backgrounding the tool call is the supported shape and keeps the notification; detaching \
inside the call throws it away.",
        routes: &[read("rule read first", "rules/toolchain.md")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "call count over",
        gloss: "this call measures over a ceiling the config declares",
        class: "A `ceiling` row counts something about the call and refuses above a declared \
maximum. The count and the maximum are the whole finding -- what was counted is the row's \
subject, and the refusal carries neither the measured content nor the call text, which is \
non-negotiable rule 4 decided at the composer rather than at the report.",
        routes: &[read("config read first", "batten.toml")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "call name refused",
        gloss: "the mediated call matches a command shape the config refuses",
        class: "A `shape` row declares a command spelling that is refused outright. The \
refusal names the row rather than echoing the command, because the command is the caller's \
own text and could carry anything. What to run instead is the row's declared remedy, which \
`batten policy explain` prints; where that remedy cannot perform the change, the class is \
admissible through a recorded admission bound to the row id at the current commit.",
        routes: &[
            run(
                "rule read first",
                batten_core::grammar::RULE_HOP_PLACEHOLDER,
            ),
            SHAPE_ADMIT_ROUTE,
        ],
        applicability: Applicability::Advice,
    },
    // ─── the repaired arms (CLOUD-1639) ──────────────────────────────────────
    //
    // The two classes that say the boundary ACTED rather than advised. Both are
    // vendored rather than consumer-declared for the reason every `Native` class
    // is: the engine raises them from its own code, so a consumer could not
    // decline to declare one without making a refusal site unable to speak.
    //
    // THEIR OWN `applicability` IS `advice`, WHICH IS NOT A CONTRADICTION. The
    // column says what the boundary may do about THIS class, and there is
    // nothing left to repair — the repair already happened and these are how it
    // is reported. A `retry` here would mean "repair the report", which is not
    // a thing.
    VendoredVerdict {
        id: "call retry now",
        gloss: "the boundary repaired what it refused; re-issue the identical call",
        class: "A rule declared a repair for the shape it refuses, the boundary ran it, and it \
succeeded. The call as made did not happen, so this is a refusal rather than an allow — but the \
condition that caused it is gone, and the same call issued again is expected to pass. Nothing \
needs deciding: the token IS the instruction. Re-issuing a call the boundary has just repaired \
for is the one retry that is not a guess, which is why this is its own class rather than the \
original refusal read a second time and puzzled over.",
        routes: &[run("call issue again", "the identical call, unchanged")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "call fix silent",
        gloss: "the boundary repaired the call and let it through, and this is the record",
        class: "A rule declared a repair, the boundary ran it, and the class it raises declares \
that the call proceeds rather than being re-issued. The call was ALLOWED; this is the record that \
something changed underneath it, which is the half no surveyed system omits — a mutating \
admission controller applies silently and still writes an audit annotation. A repair nobody is \
told about leaves a tree that no longer matches what its author last read, and that cost is \
measured rather than assumed. The row owes `no_retry_reason`, so proceeding without a re-issue is \
somebody's stated decision.",
        routes: &[read("config read first", "batten.toml")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "input write refused",
        gloss: "the content this call would write matches a refused shape",
        class: "A `content` row judges what a write would PUT somewhere rather than which \
path it targets, so it fires before the bytes land. The refusal names the row and the \
destination and never the matched content -- this rule reads exactly the text somebody \
wanted checked, which is the likeliest place in the surface for a secret to appear.",
        routes: &[read("config read first", "batten.toml")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "issue name missing",
        gloss: "the work this call publishes names no tracker key",
        class: "A `requires_key` row narrows a refusal from \"this command is banned\" to \
\"this command is banned unless the work is keyed\". Three evidence sources are read and any \
one of them allows: the command itself, the branch name, and the commit subjects on the \
range the row declares. None carried a key, so nothing on the published work says which row \
it serves.",
        routes: &[read("config read first", "batten.toml")],
        applicability: Applicability::Advice,
    },
    // ── the config loader's classes (CLOUD-1313) ────────────────────────────
    //
    // One per `VALIDATED_AT_LOAD` table plus the remedy resolver. Each `class`
    // says what the table is FOR and what a refusal from it therefore means,
    // because the message the loader already carries says which row and key
    // failed and repeating that here would be the payload rule 4 refuses.
    //
    // Every route is the config itself, which is not a placeholder: a config
    // fault is edited in exactly one file, and a `command` route would have to
    // name a task that can run over a config that does not load.
    VendoredVerdict {
        id: "config read refused",
        gloss: "the declaration is not TOML, so no rule in it could be read",
        class: "Every other config fault leaves the rest of the file deciding -- an unknown key \
costs its own row, a table whose validator refuses names that table, and a version this build \
is too old for still says so. Each of those keeps a working gate surface and an agent that can \
be told to repair the broken part. This one has no partial function to preserve: the bytes are \
not TOML, so zero rows are readable and nothing is enforced. That is why it is the one class \
the mediated boundary refuses a call under, rather than reporting and proceeding -- a gate that \
fails open is inert, and an inert gate over an unreadable authority is the false green this \
engine exists to catch.",
        routes: &[read("config read first", "batten.toml")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "verb declare refused",
        gloss: "the verb table would not load",
        class: "`[[verb]]` is how a consumer names the commands their harness mediates and \
what effect each carries. A row that is inert -- declared twice, or read-effect in a table \
named for mutation -- reads as covered while matching nothing, so the table is proven at \
load rather than at the call it would have decided.",
        routes: &[read("config read first", "batten.toml")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "pattern declare refused",
        gloss: "the named-pattern registry would not load",
        class: "`[[pattern]]` gives one concept one spelling, so a module cannot inline a \
regex and duplication becomes unwritable rather than merely detectable. A malformed \
expression here is a config fault, and refusing it at load is what stops a mediated call \
discovering it at adjudication -- the worst moment and the wrong exit class.",
        routes: &[read("config read first", "batten.toml")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "traversal declare refused",
        gloss: "the declared-walk registry would not load",
        class: "`[[traversal]]` is where a graph walk is DECLARED rather than written into a \
module, which is what keeps a consumer's edge vocabulary out of the core and what BOUNDS the \
walk -- the engine cannot traverse what no row asked for. A malformed row here is a config \
fault: a half-declared stop condition would walk to exhaustion while reading as a stop, and a \
zero bound would decide nothing while loading clean. Refusing at load is what stops a gate \
discovering either at adjudication.",
        routes: &[read("config read first", "batten.toml")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "register declare refused",
        gloss: "the declared-key-set registry would not load",
        class: "`[[register]]` is where a key set a `reference` row resolves against is \
DECLARED -- which file, which column, which node -- so a consumer's vocabulary stays out of \
the core and the engine owns the one table grammar. A malformed row here is a config fault: \
a key column past the declared width, or a blank key node, would build a set that answers \
about the wrong cells while loading clean. Refusing at load is what stops a gate discovering \
it at adjudication.",
        routes: &[read("config read first", "batten.toml")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "verdict declare refused",
        gloss: "the refusal vocabulary would not load",
        class: "`[[verdict]]` is the registry every other class in this table belongs to: a \
token's arity, a gloss that is one line, a route list that is not an override alone, a \
tombstone chain that terminates. Each clause is a property of the table, so it is knowable \
without a tree and belongs where a config fault is reported.",
        routes: &[read("config read first", "batten.toml")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "redirect declare refused",
        gloss: "the redirect table would not load",
        class: "`[[redirect]]` changes what a refusal SAYS for a class of path, never \
whether it fires -- which is why it needs no raise-only clamp and why a redefinition is \
refused for coherence with the other append-only tables rather than because it lowers a \
bar.",
        routes: &[read("config read first", "batten.toml")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "deferral declare refused",
        gloss: "the deferral table would not load",
        class: "A `[[deferral]]` row whose `reaches` is not a version could never be \
compared, so it would read as a watched condition while nothing watched it -- which is the \
defect the table exists to close, arriving through the table itself. Refused at load rather \
than at evaluation, because a row that can never fire is a config fault and not a finding.",
        routes: &[read("config read first", "batten.toml")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "remedy resolve missing",
        gloss: "a declared remedy names a command that does not exist",
        class: "A refusal whose remedy points at a verb that was renamed away is worse than \
one carrying no remedy: the reader spends the round finding out. This is the one clause \
needing a THIRD table -- the rule ids -- so it lives at the load rather than inside either \
remedy table's own validator, where a checker reaching past its argument would quietly \
become the config's.",
        routes: &[read("config read first", "batten.toml")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "marker declare refused",
        gloss: "the marker table would not load",
        class: "`[[marker]]` declares the tokens a scan treats as significant. An empty \
`token` matches every line of every file, which loads clean and reads as coverage, so the \
table is proven at load.",
        routes: &[read("config read first", "batten.toml")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "rule declare refused",
        gloss: "the rule table would not load",
        class: "`[[rule]]` is the policy surface itself, and it used to be validated only by \
whichever runner happened to evaluate it. That was defensible with one runner; with a tree \
engine and a mediation boundary, a malformed mediated-call row validated only by the tree \
engine is a row that loads, matches nothing at the mediation channel, and reads as \
coverage.",
        routes: &[read("config read first", "batten.toml")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "output declare refused",
        gloss: "the exec output-predicate table would not load",
        class: "`[[exec_pattern]]` is how a wrapped command's OUTPUT becomes a decidable \
object rather than something a reader skims. A duplicate id makes two predicates \
indistinguishable in the record they write.",
        routes: &[read("config read first", "batten.toml")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "environment declare refused",
        gloss: "the verify-environment classifier table would not load",
        class: "`[[verify_environment_pattern]]` is what tells a gate refusal caused by the \
MACHINE from one caused by this tree, so a malformed row does not fail loudly — it classifies \
nothing and reads as a consumer who declared no classifier at all, and every refusal goes back \
to being reported as a defect to reproduce. A SECOND class over the same type as \
`output declare refused` rather than a shared one, because a refusal has to name which of the \
two tables to edit.",
        routes: &[read("config read first", "batten.toml")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "waiver declare refused",
        gloss: "the waiver table would not load",
        class: "The stakes here are inverted from every other table: a malformed rule fails \
to gate, but a malformed WAIVER is a hatch whose expiry nobody could read. Refusing at load \
is what makes \"every waiver carries an expiry\" true of the resolved config rather than \
aspirational.",
        routes: &[read("config read first", "batten.toml")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "fact declare refused",
        gloss: "the fact table would not load",
        class: "`[[fact]]` declares what the boundary resolves about a call before any rule \
reads it. A row naming a fact the engine cannot produce is a gate that evaluates, reads \
undefined, and refuses nothing -- the silent dead gate, decided at load instead.",
        routes: &[read("config read first", "batten.toml")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "mint declare refused",
        gloss: "the mint table would not load",
        class: "`[[mint]]` declares what a receipt records and how long it answers for. A \
malformed row is a receipt nothing can satisfy or one that answers forever, and both are \
decidable from the table alone.",
        routes: &[read("config read first", "batten.toml")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "recorder declare refused",
        gloss: "the recorder table would not load",
        class: "`[[recorder]]` binds a captured section to a named pattern. It is validated \
AFTER the pattern registry, because a refusal for a missing pattern id is only honest once \
the ids are known to be well formed themselves.",
        routes: &[read("config read first", "batten.toml")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "record declare refused",
        gloss: "the record table would not load",
        class: "`[[record]]` declares a family a producer fills with `batten record named`, so \
that a module may read its store at all. A row whose name could never be written, or whose \
writer is unnamed, is a family that can only ever answer could-not-look -- and the moment to \
say so is at load, not after a green run nobody questioned.",
        routes: &[read("config read first", "batten.toml")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "provision declare refused",
        gloss: "the provision table would not load",
        class: "`[[provision]]` is how a pinned tool reaches the cache a rule will look for \
it in. A row that cannot resolve is a rule that will report a missing scanner at the moment \
it was supposed to decide something.",
        routes: &[read("config read first", "batten.toml")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "startup declare refused",
        gloss: "the startup table would not load",
        class: "`[[startup]]` is how a repository states what its container must be and how that is repaired. A row that could never decide -- an empty check, a repair that runs nothing, an id declared twice -- is a precondition reported as broken every session with no repair reachable, so it is refused here rather than once per session, where the failure would read as a broken container instead of a typo in this file.",
        routes: &[read("config read first", "batten.toml")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "step declare refused",
        gloss: "the step table would not load",
        class: "`[[step]]` declares what keys a step's receipt: the pathspecs whose index \
entries it hashes and the tool argvs whose answers it hashes. A row with no inputs keys no \
file and would answer for any tree; a row with no tools lets a receipt outlive the toolchain \
that earned it; a `:`-magic pathspec selects nothing and reads as a clean set. Each is a \
receipt attesting bytes nobody checked, so it is refused at load rather than trusted at the \
first hit.",
        routes: &[read("config read first", "batten.toml")],
        applicability: Applicability::Advice,
    },
    // ── commit-msg channel ──────────────────────────────────────────────────
    VendoredVerdict {
        id: "commit spelling wrong",
        gloss: "the commit subject does not match the repository's declared commit convention",
        class: "`[commit] subject_pattern` is the one expression every non-merge commit's \
subject must match. A repository that lands by fast-forward derives its changelog and its \
version bump from those subjects, so whether a subject is conventional is a rule about what a \
commit may be. The engine never judges whether a subject is good: it asks whether the \
configured pattern matches the first line, and the type words and scope shape are the \
consumer's own. The finding points at the commit and the field and never echoes the subject, \
which can carry anything its author typed.",
        routes: &[
            read("config read first", "batten.toml"),
            run("commit write now", "git commit -F <path>"),
        ],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "commit name missing",
        gloss: "the commit names no tracker row and no declared exemption covers it",
        class: "`[commit.claims]` asks that every commit in a judged range name the row it \
serves: a closing keyword or the first key of a reference trailer, read through the \
consumer's own key grammar. A claim receipt never leaves the clone, so this is the half of a \
claim a reviewer and a workflow can see. Claiming is stricter than mentioning. An exemption is \
a property of the commit, never of its wording: every path it changed, and where declared its \
author address, must match one `unclaimed` row.",
        routes: &[
            run("commit edit now", "git commit --amend -F <path>"),
            read("config read first", "batten.toml"),
        ],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "commit admit missing",
        gloss: "the commit wrote a protected path and carries no articulation block for it",
        class: "An override makes a protected write admissible, and the articulation it cost \
lives in a store scoped to the container. The block in the commit message is what makes that \
reasoning durable and readable by every reviewer of the change it justifies. This finding is \
the honest omission: the commit wrote the path and no block claims it. Issue and spend an \
admission against the class that refused the write, and carry the block it prints. A path \
whose writes a redirect sanctions owes no block, because nothing was refused and nothing was \
issued.",
        routes: &[
            run(
                "grant ask first",
                "batten override request --rule protected-mutation --verdict 'path write \
refused' --subject <path>",
            ),
            run(
                "grant write now",
                "batten override spend --admission <address> --rule protected-mutation \
--verdict 'path write refused' --subject <path>",
            ),
            read("config read first", "batten.toml"),
        ],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "commit admit other",
        gloss: "an articulation block for this path does not hash to the address it names",
        class: "The graver of the two articulation findings, and the opposite of an omission: \
a block claims this path and does not recompute to the address it carries. Somebody edited the \
reasoning after it was issued, or assembled a block by hand. The check is a pure function of \
the block, so it decides identically on a runner that has never seen the admission store. It \
is still reached on a path a redirect sanctions, because a doctored block is examined even \
where none was owed. Issue a fresh admission and carry the block it prints verbatim.",
        routes: &[
            run(
                "grant ask first",
                "batten override request --rule protected-mutation --verdict 'path write \
refused' --subject <path>",
            ),
            run(
                "grant write now",
                "batten override spend --admission <address> --rule protected-mutation \
--verdict 'path write refused' --subject <path>",
            ),
        ],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "commit admit same",
        gloss: "the commit adds a conserves-ledger arm and spends it in the same change",
        class: "An optional conserves-ledger arm widens what a deletion may claim, so adding \
one wants an independent reader. A commit that both introduces the arm and spends it is \
self-authorizing: the thing that would have refused the deletion was authored by the same \
change. The remedy is sequencing, not permission. Land the arm, let it be reviewed on its \
own, then spend it in a later commit. There is deliberately no override, since an admission \
here would be the author authorizing their own hatch one layer up.",
        routes: &[run("commit ship first", "git restore --staged <path>")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "commit own refused",
        gloss: "the commit's author or committer is an identity the attribution policy denies",
        class: "`[attribution]` governs what a produced commit may carry about the tooling \
that made it, and `identity_deny` is the half that reads the author and committer as git \
stamps them. The committer is judged too, because it is the field a repair reaching only the \
author leaves behind. The finding names the field and never the identity. The declared \
repair sets the repository-local identity to the accountable one the table declares, and \
leaves an identity a contributor set for themselves alone when the policy accepts it.",
        routes: &[run("config fix now", "batten attribution identity")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "commit carry refused",
        gloss: "the commit carries a trailer the attribution policy denies",
        class: "`[attribution] trailer_deny` names trailer shapes a produced commit may not \
carry, and `trailer_allow` is the only carve-out: an empty allow list exempts nothing, which \
is the posture that discloses nothing. The finding names the trailer KEY and never its value, \
because the value is the payload the policy exists to keep out of history. Rewrite the \
message without the trailer.",
        routes: &[run("commit write now", "git commit -F <path>")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "commit state refused",
        gloss: "the commit message body states attribution the policy denies",
        class: "`[attribution] body_deny` names phrasings a produced commit's message may not \
state about the tooling that made it. The whole message is judged, not only the trailers, \
because a formula in the body discloses exactly what a refused trailer would. The finding \
names the field and never the matched text. Rewrite the message without it.",
        routes: &[run("commit write now", "git commit -F <path>")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "tag own refused",
        gloss: "the tag was cut by an identity the attribution policy does not permit",
        class: "`[attribution] tag_identity_allow` is an allow-form: every tagger that is not \
the declared identity is refused, so a release cut by an unexpected credential is caught \
whether or not anyone predicted that credential. `identity_deny` is still consulted, and a \
tagger both permitted and denied is refused. The finding names the tag and never the tagger \
identity. Delete the tag and cut it again under the accountable identity.",
        routes: &[
            run("tag retire now", "git tag -d <tag>"),
            read("config read first", "batten.toml"),
        ],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "tag own unnamed",
        gloss: "the tag carries no tagger identity, so who cut it cannot be judged",
        class: "A lightweight tag is a ref pointing straight at a commit, and an unsigned \
annotated tag carries no tagger header. Either way there is no identity to hold to \
`tag_identity_allow`, and reading that absence as accountable is how a release cut by anyone \
would pass. Replace it with an annotated tag cut under the accountable identity.",
        routes: &[
            run("tag retire now", "git tag -d <tag>"),
            run("tag mint now", "git tag -a <tag>"),
        ],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "prose declare refused",
        gloss: "a config column's text is longer than the cap its column declares",
        class: "Batten echoes config prose back -- `batten policy explain` prints a class \
and a row's reason, and a first sighting renders the reason in full -- \
so the length of every string a config declares is paid in every reader's context. Each \
column is held to a cap at load: one line for a gloss, a sentence for a route, a remedy or a \
note, a paragraph for a class or a reason, and the paragraph ceiling for any column not listed \
tighter. An over-cap value is refused rather than truncated, because a truncated reason is a \
remedy missing its second half. The refusal names the column, the row index, the length and \
the cap, never the text. Shorten the value; provenance and evidence belong in a TOML comment \
beside the row, which is never parsed or emitted.",
        routes: &[read("config read first", "batten.toml")],
        applicability: Applicability::Advice,
    },
    // ── the unclassed emitters' classes (CLOUD-2078) ─────────────────────────
    // One class per emitter FAMILY: the site's own message travels as a subject,
    // so it rides both arms and nothing per-site is withheld.
    VendoredVerdict {
        id: "input parse refused",
        gloss: "the invocation was refused before it ran; the subject says why",
        class: "A verb that refuses its own input -- an unknown flag, a missing argument, a \
value it cannot use -- has decided nothing about the work. The subject is the verb's own \
sentence, and `batten --help` lists every verb and flag this build carries.",
        routes: &[run("verb help first", "batten --help")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "verb run broken",
        gloss: "the verb could not complete; the chain is a diagnosis of Batten, not a verdict",
        class: "An internal failure is exit 3: the verb could not look, so it decided \
nothing. The subjects are the error chain, outermost first. A failure that repeats on an \
unchanged tree is a defect in Batten to file with that chain; `batten doctor` checks the \
environment the verb ran in.",
        routes: &[run("doctor run first", "batten doctor")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "issue file refused",
        gloss: "the row a bot pull request implies cannot be derived, so none is filed",
        class: "`pr derive` files the tracker row a bot's pull request stands for, and \
refuses when the author, the owned manifest or the subject cannot be read as one. The \
subjects name which.",
        routes: &[read("config read first", "batten.toml")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "layer carry refused",
        gloss: "an ingested layer would replace a committed value it may only tighten",
        class: "Configuration is one committed authority plus raise-only overrides. A layer \
that would loosen a committed value is refused whole rather than applied in part; the \
subjects name the first key, the layer and how many keys it touched.",
        routes: &[read("config read first", "batten.toml")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "provision pin other",
        gloss: "the fetched artifact does not match its pin, so nothing was installed",
        class: "A provision is installed only when its bytes hash to the pinned digest. A \
mismatch means the pin is stale or the source changed under it; nothing was installed, and \
the subjects carry both digests.",
        routes: &[run("check run first", "batten provision apply")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "commit ship missing",
        gloss: "the turn declared a stopping point and its commits are not on the landing target",
        class: "Work that is committed and not landed is in no state anyone else can see, \
and a container reclaim loses whatever is not pushed. The subjects count the commits not on \
the landing target. This is said once per claim until the operator speaks again: a landing \
held on purpose is a state, not an omission, and repeating it every turn displaces the \
operator's own words (CLOUD-2332).",
        routes: &[run("land run first", "batten land lap")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "commit ship unknown",
        gloss: "the clone is shallow, so where these commits are cannot be computed",
        class: "A shallow clone stops every history walk at its boundary, so whether the \
turn's commits are on the landing target could not be computed; that is could-not-look, \
never landed. Said once per claim until the operator speaks again (CLOUD-2655).",
        routes: &[run("unshallow run first", "git fetch --unshallow")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "commit push missing",
        gloss: "the claim's commits exist only in this clone",
        class: "This repository declares `landed_by = \"person\"`: a person merges what the \
agent pushed, so the agent's last step is the push. These commits are not on the branch's \
upstream, or the branch tracks none, and a container reclaim loses them. The second subject \
names which (CLOUD-2656).",
        routes: &[
            run("push run first", "git push"),
            run("upstream set first", "git push -u <remote> HEAD"),
        ],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "commit merge held",
        gloss: "the work is pushed and a person merges it",
        class: "This repository declares `landed_by = \"person\"`, and the claim's commits \
are on the branch's upstream: the merge is a person's step, not this session's. Said once; \
the Stop is not refused (CLOUD-2656).",
        routes: &[read("config read first", "batten.toml")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "issue list unclear",
        gloss: "every row this branch filed, for a by-number answer: independent, or a punt",
        class: "A row filed while doing a task is either independent work or part of the \
task deferred. The subjects list every row this branch filed; answer each by number, and \
close the ones that are this task's here.",
        routes: &[run("ready lint first", "batten ready lint")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "hook report now",
        gloss: "a declared hook handler reported on this call; its words are the subject",
        class: "A `[[hook.handler]]` row dispatches a program on an event, and its report \
travels as the subject: `hook.handler.<id>` names the row, the rest is what it said. Its row \
in the config says what it guards.",
        routes: &[read("config read first", "batten.toml")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "hook answer broken",
        gloss: "a declared hook handler broke its contract, so its answer was not used",
        class: "A handler answers by exit status and output within its declared timeout. One \
that could not spawn, timed out, exited outside its contract, said nothing on a refusal, \
died on a signal or wrote a host decision document of its own broke that contract; the \
subjects name the row and which.",
        routes: &[read("config read first", "batten.toml")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "output write missing",
        gloss: "this call's response was not captured; the reason id says why",
        class: "A mediated call's response is captured so a later remedy can hand over its \
bytes without them entering the context. When the capture is skipped, the subject is the \
reason id, and the capture is absent for that call only.",
        routes: &[run("doctor run first", "batten doctor")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "workspace state broken",
        gloss: "this environment does not match what the tree declares",
        class: "A failing doctor check or startup row means a program, pin or provision the \
tree declares is not present or not reachable here, so gates that need it cannot run. The \
subjects name the check or row and its reason. `batten startup --repair` runs the declared \
repairs; `batten doctor` reports what is left.",
        routes: &[
            run("doctor run first", "batten doctor"),
            run("startup repair first", "batten startup --repair"),
        ],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "call grant now",
        gloss: "the call was pre-approved by a declared rule or handler",
        class: "A pre-approval tells the host not to prompt for a call the policy already \
admits. It is never a refusal and never outranks one: a call any gate refuses is not \
pre-approved. The rule or handler that granted it is on the line.",
        // NO ROUTE: a grant asks nothing of its reader, so a way out would be a
        // pointer with nothing to point the reader at (CLOUD-2145).
        routes: &[],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "commit port blocked",
        gloss: "a replay onto the landing target conflicted and stopped",
        class: "The replay is stateless: nothing is half-replayed, so there is no rebase to \
continue or abort. Merge each conflicted path in the worktree, then name it to `land \
replay --resolve`, which re-runs the replay from its base with your bytes for that path.",
        // THE PLAIN REPLAY, NOT ITS `--resolve` SPELLING: a route rides every
        // line, and a pathless conflict has no path to name. The stop's own
        // remedy carries `--resolve <first>` when there is one.
        routes: &[run("replay run first", "batten land replay <base>")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "check run red",
        gloss: "the configured gate refused this head",
        class: "`land` verifies a head before it pushes, with the gate the repository \
declares. A refusal names its cause; nothing was pushed.",
        routes: &[run("land run first", "batten land lap")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "job run red",
        gloss: "a required CI check failed on this head",
        class: "`land` waits on the required checks of the head it pushed, and stops on the \
first failure. The subjects name the head and each failing check; the same checks run \
locally.",
        routes: &[run("land run first", "batten land lap")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "lane run spent",
        gloss: "every lap was spent without a landing",
        class: "`land` bounds its laps so a moving target cannot keep it running forever. \
The subjects count the laps, the CI matrices they spent and the lease waits among them.",
        routes: &[run("land run first", "batten land lap")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "contract read stale",
        gloss: "a declared contract file moved after this session read it",
        class: "The files a repository declares as a session's contract are read once, at \
start. A `changed` subject is one this session holds in its old form, an `added` one is new \
capability it never read, a `removed` one is no longer tracked. A `hook wiring moved` subject \
means what this session runs may differ from what the tree declares.",
        routes: &[read("config read first", "batten.toml")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "directive read missing",
        gloss: "the context was compacted and the operator's directives on this branch are journaled",
        class: "Every operator message on a branch is journaled verbatim as it is given. A \
compaction replaces the window with a summary, which drops what it judges minor, and a dropped \
standing directive is work the session repeats. The branch's design corrections, kept by \
`batten record named corrections`, survive the same way. Each count subject is how many entries \
a record holds and the path subject after it is the record to read.",
        // The journal is per branch, so its exact path is the subject; the route
        // names the store that holds every branch's.
        routes: &[read("directive read first", ".git/batten-receipts")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "hook run missing",
        gloss: "the engine did not run at this session's start, so earlier calls went unmediated",
        class: "Hosts register the engine by bare name, so a session whose start event found no \
binary on `PATH` ran every call before this one unmediated. It is a provisioning failure, not a \
policy one, and which calls preceded this is not answerable from here.",
        routes: &[run("doctor run first", "batten doctor")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "drain fit broken",
        gloss: "a drain's delta did not fit its token budget, so whole rule lines were cut",
        class: "A drain carries what is new since the session was last told, a capped number of \
locations per rule, so its size follows one turn's work and the budget is a relief valve. A cut \
means one turn produced more new findings across more rules than that shape holds; the cut lines \
are in the journal and the subjects count them.",
        routes: &[run("state list first", "batten state list")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "output point now",
        gloss: "a reduced read stored the whole response; each subject is a field and its lines",
        class: "A reduction hands back a few declared fields and stores the response whole. The \
store is one line of JSON, so the read route is the view: the same document laid out field by \
field, each subject naming a field, the view lines holding it and its size. Read only the lines \
you need; the raw connector returns the same bytes into the window again.",
        // THE VIEW, NOT `--field` (CLOUD-2284): `--field` alone prints only a
        // size header, and a spilled leaf is no JSON document at all, so the
        // command never reached the content the note pointed at.
        routes: &[read("output read first", "the view the note names")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "cargo retire now",
        gloss: "free space fell below the declared minimum, so cargo units were removed before this call ran",
        class: "Below `[prune] min_free_mb` the hook collects before admitting: superseded units first, \
then live units least recently used first, until `max_free_mb` is free. A tree a running build holds \
is never touched, and the engine's own unit survives. The subjects are the bytes freed, the units \
removed and the free space after. The call was admitted either way; the next build of a removed unit \
rebuilds it.",
        routes: &[run("space read first", "batten target prune --dry-run")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "call reach loose",
        gloss: "the call acts on a repository other than the session's home, which arms the reach gate",
        class: "A session is homed in the first repository it stood in that carries an authority, and a \
visit never moves the home (CLOUD-2672). Where the home declares a `repository-reach` native row, a \
call whose targets (a structured call's path; a shell call's directories, `cd`/`pushd` operands and \
`git -C`/`--git-dir`/`--work-tree` operands) place in another repository is refused, and so is one \
whose targets cannot be placed at all. A directory in no repository passes. The subjects are the \
home and the root reached, never a file's contents.",
        routes: &[run(
            "override request first",
            "batten override request --rule repository-reach",
        )],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "script run loose",
        gloss: "a script interpreter ran a script file that lives outside the repository",
        class: "A call to an interpreter the row's `interprets` column declares whose script operand \
resolves OUTSIDE the repository (CLOUD-2304). The edit guards are bound to the host's edit tools and to \
the command line, and a script file carries its writes in its own body, where neither looks: \
a protected path, an unrefined filed row, every Edit/Write handler is walked around by moving \
the edit into a scratch script. A script the repository holds is reviewed code and runs; so \
does the same interpreter downstream of a pipe, and an inline `-c`/`-e` program, whose text \
the protected-path scan already reads. CONTAINMENT, never the INDEX, for `tool run loose`'s \
reason: the operand is resolved against the call's own working directory and the repository \
asked whether it holds the result.",
        routes: &[run(
            "edit run first",
            "make the edit with the host's Edit/Write tools; a reusable program is a tracked file under review",
        )],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "issue grade refused",
        gloss: "the issue fails a checkable Ready clause, named in the subject beside its line",
        class: "`ready lint` holds an issue's description to the checkable half of the Definition \
of Ready. Each subject is the issue, the description line, and the clause it fails; the line is \
where the edit goes. Nothing the issue says is echoed.",
        routes: &[run("ready lint first", "batten ready lint")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "issue grade partial",
        gloss: "the issue's relations were not in the fetch, so its citations could not be judged",
        class: "A citation is judged against the issue's relations. A payload fetched without \
them cannot be judged either way, which is could-not-look rather than a pass; the subject is \
the first citation that hit the gap.",
        routes: &[run("ready lint first", "batten ready lint")],
        applicability: Applicability::Advice,
    },
    VendoredVerdict {
        id: "claim mint refused",
        gloss: "the claim was not minted: the issue is held by another, or was not refined first",
        class: "`claim check` mints the claim receipt only for an issue nobody else holds and \
whose refinement came before this session. The subject is the issue and the reason: a holder \
(`assigned`, a competing branch or PR) or the refinement sequence (`not-ready`).",
        routes: &[run("claim check first", "batten claim check")],
        applicability: Applicability::Advice,
    },
];

/// Every class the binary ships, as the registry carries them.
///
/// Unioned with the consumer's `[[verdict]]` rows by `policy::load`. A collision
/// between the two is refused there rather than here: which side is at fault is
/// a question about the pair, and this function knows only one of them.
#[must_use]
pub fn vendored() -> Vec<DeclaredVerdict> {
    // Native rows here, preset rows from their own manifests (CLOUD-1181). The
    // presets' half used to sit in this same table under a comment, so a preset
    // class and the preset that raises it were declared in different modules
    // with nothing tying them together.
    VENDORED
        .iter()
        .map(declared_from)
        .chain(verdict_rows())
        .collect()
}

/// One vendored row, as the registry carries it.
///
/// Shared with [`crate::preset`] so the two halves of the vendored registry
/// cannot be projected differently — which is the same "one authority per fact"
/// reason the manifests exist at all.
#[must_use]
pub fn declared_from(entry: &VendoredVerdict) -> DeclaredVerdict {
    DeclaredVerdict {
        id: entry.id.to_owned(),
        gloss: entry.gloss.to_owned(),
        // Joined by id from the one doc table (CLOUD-2143), so the vendored and
        // preset halves are documented in one place.
        doc: batten_base::doc::vendored(entry.id),
        class: entry.class.to_owned(),
        // Carried rather than defaulted (CLOUD-1639): this is the one projection
        // between the two tables, so a vendored class that declares a repairing
        // posture would silently become `advice` here if the field were dropped
        // — and the arm that reads it is at the boundary, far from this line.
        applicability: entry.applicability,
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
        withdrawn: None,
    }
}

/// Every verdict row the vendored presets declare, as the registry carries them.
///
/// Chained onto the native rows by [`vendored`]. Derived rather
/// than declared a second time: before this, adding a preset class meant editing
/// a table in another module under a comment, and nothing tied the two together.
#[must_use]
pub fn verdict_rows() -> Vec<DeclaredVerdict> {
    crate::preset_catalog::MANIFESTS
        .iter()
        .flat_map(|manifest| manifest.verdicts.iter())
        .map(declared_from)
        .collect()
}
