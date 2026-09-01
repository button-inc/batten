//! The write-shape corpus, over the compiled binary and the committed policy
//! (CLOUD-442).
//!
//! This is the acceptance corpus `tests/memory-guard.bats` carried, translated
//! into the surface that now decides it. That guard's table was the behavioural
//! spec for nine write shapes; CLOUD-312 could express four of them as `[[verb]]`
//! rows, CLOUD-442 adds the qualifier columns the other five needed, and the
//! guard is deleted in the same change — so this file is what keeps the
//! deletion honest. Without it, retiring the bash layer would take its corpus
//! with it and nothing would notice a shape that stopped being refused.
//!
//! **Judged against the committed `batten.toml`, not a fixture.** Every other
//! protected-path test supplies its own policy, which is right for testing the
//! engine and useless for testing the *table*: deleting a `[[verb]]` row or a
//! `protected` entry from the real file would break none of them. The census in
//! `tests/cli.rs` makes that point for the four rows that landed with CLOUD-312;
//! this one makes it for the five that land now, and for the reads each of them
//! must not refuse.
//!
//! **The allows are the load-bearing half.** A suite asserting only the denies
//! passes on a row that refuses everything, which is precisely the false positive
//! the qualifier columns exist to avoid — and a guard that refuses reads is one
//! people switch off, so a false positive here is a policy that stops being
//! enforced at all.
//!
//! A separate target rather than more of `tests/cli.rs`, on
//! `tests/advisory_drain.rs`'s precedent and for its stated reason: that file is
//! the exit-code and output-contract suite, and this is a corpus about one gate.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::PathBuf;

use common::{run, run_with_stdin, stderr};

/// A protected path this repository declares, and one it does not.
///
/// Named here rather than inlined per case so the corpus reads as shapes over a
/// guarded path — the shape is what is under test, and the path is the table's
/// answer.
const GUARDED: &str = ".serena/memories/core.md";
const AUTHORITY: &str = "batten.toml";
const ORDINARY: &str = "target/debug/scratch";

/// The repository root, whose committed `batten.toml` is the policy under test.
fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A Claude Code `PreToolUse` envelope carrying a shell command.
fn bash_payload(command: &str) -> String {
    let escaped = serde_json::to_string(command).expect("a command is encodable");
    format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\
         \"tool_input\":{{\"command\":{escaped}}}}}"
    )
}

/// Adjudicate one command against the committed policy, on the neutral adapter.
///
/// `exit-code` rather than `claude-code`: the code *is* the whole channel there,
/// so a verdict is read from the status without parsing a decision document.
fn verdict(command: &str) -> Option<i32> {
    run_with_stdin(
        &root(),
        &["hook", "--harness", "exit-code"],
        &bash_payload(command),
    )
    .status
    .code()
}

fn assert_denied(command: &str) {
    assert_eq!(
        verdict(command),
        Some(2),
        "the committed policy must refuse: {command}"
    );
}

fn assert_allowed(command: &str) {
    assert_eq!(
        verdict(command),
        Some(0),
        "the committed policy must allow: {command}"
    );
}

/// This command is not refused **as a write to a protected path**.
///
/// Weaker than [`assert_allowed`] on purpose, and only for commands where a
/// SECOND row legitimately fires. `sed -n 1p <memory>` is a read as far as the
/// `[[verb]]` table is concerned — the property these tests exist to pin — and
/// is also, correctly, a `no-tool-substitution` deny, because printing a range
/// of a tracked file is what `Read(offset, limit)` is for (CLOUD-864). Reading
/// the aggregate exit code would make one rule's arrival look like the other
/// rule's regression.
///
/// So the assertion is on WHICH row spoke. Every protected-path refusal carries
/// its `redirect` — the Serena tool to use instead — and those all end in
/// `_memory`; no other row's text does. A caller that stops emitting that token
/// fails this, which is the direction worth protecting.
fn assert_not_refused_as_a_write(command: &str) {
    let refusal = stderr(&run_with_stdin(
        &root(),
        &["hook", "--harness", "exit-code"],
        &bash_payload(command),
    ));
    assert!(
        !refusal.contains("_memory"),
        "the verb table must read this as a read, whatever else refuses it: \
         {command}\n{refusal}"
    );
}

#[test]
fn a_destination_only_copy_denies_the_write_and_allows_the_read() {
    // The bash table's own words: "only the destination is a write; copying a
    // memory OUT is a read." Both directions, because the row is only correct if
    // it distinguishes them — with the default every-operand reading it could not,
    // which is why `cp` stayed in bash through CLOUD-312.
    assert_denied(&format!("cp /tmp/draft.md {GUARDED}"));
    assert_denied(&format!("install -m 644 /tmp/draft.md {GUARDED}"));
    assert_allowed(&format!("cp {GUARDED} /tmp/copy.md"));
    assert_allowed(&format!("install -m 644 {GUARDED} /tmp/copy.md"));
    // The authority itself is guarded the same way, and backing it up is a read.
    assert_denied(&format!("cp /tmp/x.toml {AUTHORITY}"));
    assert_allowed(&format!("cp {AUTHORITY} /tmp/backup.toml"));
}

/// The same repository path spelled absolutely — the spelling a host sends and an
/// agent routinely types (CLOUD-1236).
///
/// Canonicalised, so the string handed to the engine is a real filesystem path
/// rather than one carrying `..`; `root()` is a manifest-relative expression and
/// the point of these cases is the spelling a caller would actually use.
///
/// # Forward slashes, and the `\\?\` prefix removed — this is a COMMAND, not a path
///
/// The result is interpolated into a shell command string, so it must be spelled
/// the way a caller would type one. `Path::display` renders the platform
/// separator, and on Windows `canonicalize` additionally returns an
/// extended-length `\\?\D:\...` prefix — neither of which anybody types, and a
/// backslash inside a command is an ESCAPE. Handed over raw, the quote-aware
/// tokenizer consumes them and the operand reaching the engine is mangled, so the
/// case fails for a reason that has nothing to do with what it is testing.
///
/// Measured: `cp /tmp/draft \\?\D:\a\batten\batten\policy\shell-retirement.rego`
/// exited `0` on the Windows job while every relative arm passed, and 745 further
/// tests were cancelled by fail-fast behind it.
///
/// The engine half needs no such care and already has none —
/// `hook::relative_to` normalises its output to `/` for exactly this reason
/// (CLOUD-1141), having been caught by this same job. This is that lesson one
/// layer out: the fixture has to speak the caller's spelling, not the platform's.
fn absolute(relative: &str) -> String {
    let joined = root()
        .canonicalize()
        .expect("this checkout resolves")
        .join(relative)
        .display()
        .to_string()
        .replace('\\', "/");
    joined.strip_prefix("//?/").unwrap_or(&joined).to_owned()
}

/// THE CASE THAT FAILS AGAINST THE UNFIXED BINARY (CLOUD-1236).
///
/// Measured on `0.0.135` before the fix: the relative arm exits `2` and the
/// absolute arm exits `0`, on every protected class and every mutating verb.
/// `protected` is a set of repo-relative globs and `normalise` stripped only a
/// leading `./`, so an absolute operand matched nothing.
///
/// Both spellings name the same file, so any verdict that distinguishes them is
/// the gate answering a question about typography instead of about the target.
#[test]
fn an_absolute_operand_is_judged_exactly_as_the_relative_one() {
    for target in [GUARDED, AUTHORITY] {
        assert_denied(&format!("cp /tmp/draft {target}"));
        assert_denied(&format!("cp /tmp/draft {}", absolute(target)));
    }
}

/// The maximal weakening, which `protected`'s own comment names: deleting the
/// authority "disarms every gate at once, including this one". It was allowed.
#[test]
fn deleting_the_authority_is_refused_however_it_is_spelled() {
    assert_denied(&format!("rm {AUTHORITY}"));
    assert_denied(&format!("rm {}", absolute(AUTHORITY)));
    // Compound, because a real agent command is compound most of the time — and
    // `cd` elsewhere first is exactly how an absolute path gets typed.
    assert_denied(&format!("cd /tmp && rm {}", absolute(AUTHORITY)));
}

/// The DERIVED half: a registered `[[rule]] module` is protected by derivation
/// rather than by a `protected` entry, and it had the same hole.
#[test]
fn a_derived_module_path_is_protected_at_either_spelling() {
    const MODULE: &str = "policy/shell-retirement.rego";
    assert_denied(&format!("cp /tmp/draft {MODULE}"));
    assert_denied(&format!("cp /tmp/draft {}", absolute(MODULE)));
}

/// CLOUD-1141's arm asks the same membership question, so it inherited the same
/// hole: an unknown program at an absolute protected operand fell through the
/// branch built to refuse it.
#[test]
fn an_unknown_program_is_refused_at_either_spelling() {
    assert_denied(&format!("frobnicate {AUTHORITY}"));
    assert_denied(&format!("frobnicate {}", absolute(AUTHORITY)));
}

/// MIRROR — without this the fix is satisfied by refusing every absolute path,
/// which would make the boundary the reason ordinary work stops (CLOUD-70).
#[test]
fn a_path_outside_the_repository_is_neither_relativized_nor_refused() {
    assert_allowed("cp /tmp/draft /tmp/copy");
    // A tail that matches a protected glob exactly, living somewhere else. This is
    // the case a naive basename comparison would refuse.
    assert_allowed("cp /tmp/draft /tmp/elsewhere/batten.toml");
}

/// MIRROR — the other direction a careless fix breaks: relativising must not
/// widen the set, only resolve the spelling.
#[test]
fn an_unprotected_path_inside_the_repository_is_still_allowed() {
    assert_allowed(&format!("cp /tmp/draft {ORDINARY}"));
    assert_allowed(&format!("cp /tmp/draft {}", absolute(ORDINARY)));
}

#[test]
fn an_in_place_stream_edit_is_a_write_and_every_other_one_is_a_read() {
    assert_denied(&format!("sed -i s/old/new/ {GUARDED}"));
    assert_denied(&format!("sed --in-place s/old/new/ {GUARDED}"));
    // The same switch carrying a backup suffix.
    assert_denied(&format!("sed -i.bak s/old/new/ {GUARDED}"));
    // The read half, which a row without `requires_flag` would have refused:
    // every filtering invocation in the repository.
    assert_allowed("sed --version");
    // A TRANSFORM, and allowed outright: `no-tool-substitution` qualifies its
    // `sed` entry with `-n` precisely so this stays allowed — no first-class
    // tool applies a substitution expression, so refusing it would state a
    // reason that does not hold.
    assert_allowed(&format!("sed s/old/new/ {GUARDED}"));
    // The PRINT form is a read here and a substitution there, and both are
    // right. See `assert_not_refused_as_a_write`.
    assert_not_refused_as_a_write(&format!("sed -n 1p {GUARDED}"));
}

#[test]
fn a_version_control_move_or_remove_is_a_write_and_a_query_is_not() {
    // The rename is the shape worth the most: it is the one that orphans every
    // `mem:` referrer in a single silent step.
    assert_denied(&format!("git mv {GUARDED} .serena/memories/renamed.md"));
    assert_denied(&format!("git rm {GUARDED}"));
    assert_denied(&format!("git rm --cached {AUTHORITY}"));
    // And the reads that share the front-end. A row keyed on the program alone
    // would have refused all of these, which is why the pair waited for the
    // subcommand column.
    for command in [
        "git log --oneline",
        "git status --short",
        "git diff",
        "git show HEAD",
    ] {
        assert_allowed(command);
    }
    // A move outside the guarded set is nobody's business here.
    assert_allowed("git mv crates/batten/src/a.rs crates/batten/src/b.rs");
}

#[test]
fn the_deny_names_the_whole_action_and_the_serena_tool_to_use_instead() {
    // The refusal contract (CLOUD-122) across the retirement: the remedy a reader
    // gets must still name the surface that owns the file, and for a subcommand
    // row it must name the action rather than only the front-end — a refusal
    // saying `git` would read as a ban on every use of version control.
    let refusal = stderr(&run_with_stdin(
        &root(),
        &["hook", "--harness", "exit-code"],
        &bash_payload(&format!("git mv {GUARDED} .serena/memories/renamed.md")),
    ));
    assert!(refusal.contains("git mv"), "names the action: {refusal}");
    assert!(refusal.contains(GUARDED), "names where: {refusal}");

    let edit = stderr(&run_with_stdin(
        &root(),
        &["hook", "--harness", "exit-code"],
        &bash_payload(&format!("sed -i s/a/b/ {GUARDED}")),
    ));
    assert!(
        edit.contains("sed"),
        "an in-place edit names the action too: {edit}"
    );

    // THE ROUTES ARE ONE HOP OFF THE LINE (CLOUD-1286), and this asserts the hop
    // reaches BOTH — the move's and the edit's — because they are different
    // Serena tools and only `rename_memory` rewrites `mem:` referrers. A single
    // assertion here would pass over the two collapsing into one.
    let explained = run(&root(), &["policy", "explain", "protected-mutation"]);
    assert_eq!(explained.status.code(), Some(0), "the gate resolves");
    let routes = String::from_utf8_lossy(&explained.stdout);
    assert!(
        routes.contains("rename_memory"),
        "names the route that rewrites referrers: {routes}"
    );
    assert!(
        routes.contains("edit_memory"),
        "and the one that edits in place: {routes}"
    );
}

/// A registered module's refusal names a route a reader can take (CLOUD-1226).
///
/// # The defect
///
/// Every enabled module and bundle root is a protected path, DERIVED from the
/// rule table rather than listed in `protected`. Those paths matched no
/// `[[redirect]]` glob, so `protected_refusal`'s three tiers fell through to tier
/// two — the verb's own `redirect` — whose text ends "for a memory that is the
/// Serena tool `write_memory`". Editing `policy/shell-retirement.rego` was
/// answered with advice about `edit_memory`, on a file that is not a memory and
/// that no Serena tool can write. That is CLOUD-1050's class: a refusal naming a
/// remedy that does not exist.
///
/// # The mirror is what makes this discriminate
///
/// Asserting only that a module's refusal omits `write_memory` is satisfied by
/// deleting the memory remedy outright, which would break the class it was
/// written for. So the second half asserts a memory write still gets the Serena
/// route. Both directions, or neither means anything — CLOUD-418.
#[test]
fn a_registered_module_gets_its_own_route_and_not_the_memory_one() {
    let module = stderr(&run_with_stdin(
        &root(),
        &["hook", "--harness", "exit-code"],
        &bash_payload("sed -i s/a/b/ policy/shell-retirement.rego"),
    ));
    assert!(
        module.contains("policy/shell-retirement.rego"),
        "names where: {module}"
    );
    assert!(
        !module.contains("write_memory") && !module.contains("edit_memory"),
        "a module must not be sent to a memory tool: {module}"
    );
    // CLOUD-1286: the per-path-class remedy is one hop from the gate id on the
    // line, and this asserts the hop lands rather than that a substring appears.
    // The gate is the DERIVED protected one, so it has no `[[rule]]` row — the
    // hop resolves to the `[[redirect]]` table instead, which is where the
    // per-class answer actually lives.
    let explained = run(&root(), &["policy", "explain", "protected-mutation"]);
    assert_eq!(explained.status.code(), Some(0), "the gate resolves");
    let routes = String::from_utf8_lossy(&explained.stdout);
    assert!(
        routes.contains("policy-test"),
        "names the route that checks a module edit before it lands: {routes}"
    );

    // THE MIRROR. Without it the assertions above pass over a build that simply
    // stopped naming the Serena tools anywhere.
    let memory = stderr(&run_with_stdin(
        &root(),
        &["hook", "--harness", "exit-code"],
        &bash_payload(&format!("sed -i s/a/b/ {GUARDED}")),
    ));
    assert!(
        memory.contains(GUARDED),
        "a memory write still points at the memory it refused: {memory}"
    );
    assert!(
        routes.contains("edit_memory"),
        "and the memory class still declares the Serena route: {routes}"
    );
}

#[test]
fn the_wrapper_form_is_resolved_rather_than_stopped_at() {
    // CLOUD-181's class, and the reason it matters here: in this sandbox the
    // wrapped spelling is often the only working one, so a gate that judges the
    // wrapper token sees none of the calls that matter. The qualifiers must
    // survive the lookthrough — the flag and the subcommand are read from the
    // WRAPPED argv, not the wrapper's.
    assert_denied(&format!("mise exec -- sed -i s/a/b/ {GUARDED}"));
    assert_denied(&format!("env FOO=1 git rm {GUARDED}"));
    assert_allowed("mise exec -- sed --version");
    assert_allowed("env FOO=1 git log");
}

#[test]
fn a_qualified_verb_is_judged_per_segment() {
    // A read in one segment must not be condemned by a write in another, and —
    // the direction that actually matters — a write must not be excused by a
    // read. Every other guard here judges per segment; the new rows are held to
    // it too.
    assert_not_refused_as_a_write(&format!("sed -n 1p {GUARDED}; cp {GUARDED} /tmp/x"));
    assert_denied(&format!("cat /tmp/x; sed -i s/a/b/ {GUARDED}"));
    assert_denied(&format!("git log; git rm {GUARDED}"));
}

#[test]
fn a_command_describing_a_shape_is_not_that_shape() {
    // The bats corpus's last case, and the one a naive substring gate fails: a
    // commit message or a heredoc body that WRITES DOWN one of these shapes is
    // documentation, not an invocation. The parser's quote handling is what makes
    // this hold, and it is worth pinning at this surface because every one of
    // these strings is something this repository's own commits legitimately say.
    assert_allowed(&format!(
        "git commit -m \"explain why cp x {GUARDED} is refused\""
    ));
    assert_allowed(&format!(
        "git commit -m \"note that sed -i over {GUARDED} denies\""
    ));
}

#[test]
fn the_unqualified_rows_still_deny_and_a_read_is_still_allowed() {
    // The regression the qualifier columns could have caused: every column
    // NARROWS, so the rows that carry none must mean exactly what they meant
    // before. Both directions of a move, which is the case the every-operand
    // default exists for.
    assert_denied(&format!("rm {GUARDED}"));
    assert_denied(&format!("mv {GUARDED} /tmp/elsewhere.md"));
    assert_denied(&format!("mv /tmp/draft.md {GUARDED}"));
    assert_denied(&format!("tee {GUARDED}"));
    assert_denied(&format!("cat x > {GUARDED}"));
    // Reads, and still reads to the VERB TABLE — which is what this case is
    // about. `no-tool-substitution` also refuses them now, correctly, since
    // `cat`/`grep` over a tracked path is what `Read` and `Grep` are for; the
    // weaker assertion is what keeps that from reading as a protected-path
    // regression.
    assert_not_refused_as_a_write(&format!("cat {GUARDED}"));
    assert_not_refused_as_a_write(&format!("grep -r mem: {GUARDED}"));
    // `rm` on an ordinary path is untouched by either row, so it stays the
    // strong assertion — the one that proves the protected set is a SET and not
    // "everything".
    assert_allowed(&format!("rm {ORDINARY}"));
}

#[test]
fn no_byte_of_the_mediated_command_reaches_either_stream() {
    // Non-negotiable rule 4 at the surface most likely to leak: the deny names
    // the rule, the action, the path and the remedy — never the command line,
    // which is the caller's own text and could carry anything.
    let canary = "CANARY-SECRET-VALUE";
    let output = run_with_stdin(
        &root(),
        &["hook", "--harness", "exit-code"],
        &bash_payload(&format!("sed -i s/a/{canary}/ {GUARDED}")),
    );
    let both = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(2), "the shape is still refused");
    assert!(
        !both.contains(canary),
        "a mediated command's own text must not be echoed: {both}"
    );
}

// ---------------------------------------------------------------------------
// The WRITE TOOL half, and the spelling the host actually sends (CLOUD-1133).
// ---------------------------------------------------------------------------

/// A Claude Code `PreToolUse` envelope carrying a write tool and its target.
fn write_payload(tool: &str, path: &str) -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": {"file_path": path, "content": "x\n"},
    })
    .to_string()
}

fn write_verdict(tool: &str, path: &str) -> Option<i32> {
    run_with_stdin(
        &root(),
        &["hook", "--harness", "exit-code"],
        &write_payload(tool, path),
    )
    .status
    .code()
}

/// THE DISCRIMINATING PAIR (CLOUD-1133). One protected target, two spellings.
///
/// The measured defect: `Envelope::writes` took the host's `file_path` verbatim,
/// Claude Code sends it ABSOLUTE, and `PathSet::contains` glob-matches the string
/// it is handed against a repo-relative pattern — so the relative spelling was
/// refused and the absolute one was allowed. `memory-guard` retired into this
/// gate, so its write shapes were ungated on the host that sends absolute paths.
///
/// Asserting the two spellings TOGETHER is what makes this discriminate: either
/// alone passes against a gate that answers the same way for everything.
#[test]
fn a_protected_write_is_refused_in_both_spellings_the_host_can_send() {
    let absolute = root()
        .canonicalize()
        .expect("the repository root resolves")
        .join(GUARDED);
    assert_eq!(
        write_verdict("Write", GUARDED),
        Some(2),
        "the relative spelling is refused"
    );
    assert_eq!(
        write_verdict("Write", &absolute.display().to_string()),
        Some(2),
        "and so is the absolute one, which is what the host actually sends"
    );
}

/// Every write tool the harness declares, not only `Write`.
#[test]
fn the_absolute_spelling_is_refused_for_every_write_tool() {
    let absolute = root()
        .canonicalize()
        .expect("the repository root resolves")
        .join(AUTHORITY)
        .display()
        .to_string();
    for tool in ["Write", "Edit", "MultiEdit"] {
        assert_eq!(
            write_verdict(tool, &absolute),
            Some(2),
            "{tool} at an absolute protected path is refused"
        );
    }
}

/// AND ONE DIRECTORY DEEPER THAN THE CASE ABOVE, which is where the first fix
/// still let the bypass through.
///
/// `relative_to` canonicalized `candidate.parent()` and nothing further, so a
/// write that creates its DIRECTORY as well as its file — the ordinary shape for
/// a new memory topic — had no canonical parent either. The hop failed, the
/// target kept the absolute spelling the host sent, and the repo-relative glob
/// missed it exactly as it did before CLOUD-1133. A protected set that holds only
/// for targets whose parent already exists is not a protected set.
#[test]
fn a_protected_write_to_a_missing_nested_directory_is_still_refused() {
    let nested = ".serena/memories/newtopic/note.md";
    assert!(
        !root().join(nested).exists(),
        "the fixture is only meaningful while the directory is absent"
    );
    let absolute = root()
        .canonicalize()
        .expect("the repository root resolves")
        .join(nested)
        .display()
        .to_string();
    assert_eq!(
        write_verdict("Write", nested),
        Some(2),
        "the relative spelling is refused"
    );
    assert_eq!(
        write_verdict("Write", &absolute),
        Some(2),
        "and the absolute one, whose parent directory does not exist yet"
    );
}

/// OUTSIDE THE REPOSITORY STAYS OUTSIDE, and this is the direction a careless
/// fix breaks: a normalisation that stripped a prefix without proving the target
/// is under the root would relativize `/tmp/.serena/memories/x.md` into a match.
#[test]
fn a_write_outside_the_repository_is_neither_relativized_nor_refused() {
    assert_eq!(
        write_verdict("Write", "/tmp/.serena/memories/elsewhere.md"),
        Some(0),
        "a path outside the tree is not this repository's protected set"
    );
}

/// And an unprotected target inside the tree is still allowed, which is what
/// keeps the protected set a SET rather than "every write".
#[test]
fn an_ordinary_write_inside_the_repository_is_allowed() {
    let absolute = root()
        .canonicalize()
        .expect("the repository root resolves")
        .join(ORDINARY)
        .display()
        .to_string();
    assert_eq!(write_verdict("Write", ORDINARY), Some(0));
    assert_eq!(write_verdict("Write", &absolute), Some(0));
}

// ---------------------------------------------------------------------------
// The UNKNOWN program, and the direction its omission fails in (CLOUD-1141).
// ---------------------------------------------------------------------------

/// THE DISCRIMINATING PAIR. One protected path, a named verb and an unnamed one.
///
/// The measured defect: `[[verb]]` enumerates MUTATIONS, so the gate decided by
/// naming the program and a program it did not name wrote the same bytes to the
/// same path unrefused. Measured over the shipped binary before the fix —
/// `echo x >>`, `sed -i` and `tee` denied; `python3 -c "open(…,'w')"` and
/// `perl -pi -e` **allowed**. `memory-guard` was retired into this gate, so its
/// write shapes were covered only for the programs somebody had listed.
///
/// Asserted TOGETHER because either half alone passes against a gate that
/// answers the same way for everything: the named verbs alone were already green
/// before the fix, and the interpreters alone would be green under a gate that
/// simply refused every command naming a protected path.
#[test]
fn a_protected_path_is_refused_for_the_named_verb_and_the_unnamed_program_alike() {
    assert_denied(&format!("echo x >> {AUTHORITY}"));
    assert_denied(&format!("sed -i s/a/b/ {AUTHORITY}"));
    assert_denied(&format!("perl -pi -e s/a/b/ {AUTHORITY}"));
    assert_denied(&format!("python3 write.py {AUTHORITY}"));
    assert_denied(&format!("ruby -e x {GUARDED}"));
}

/// THE RESIDUE, ASSERTED AS ALLOWED SO IT CANNOT BE MISTAKEN FOR COVERAGE.
///
/// `python3 -c "open('p','w')"` writes a protected path and is **not** refused,
/// because the path is a substring of one quoted word rather than an operand.
/// The wider scan that catches it — every word, split on punctuation a path
/// cannot contain — was tried and reverted: it refused a `for` loop whose quoted
/// body merely mentioned the path, and `echo "see batten.toml"` is the same
/// shape. A guard that refuses ordinary mentions gets switched off within a day.
///
/// So this case pins a KNOWN GAP rather than a desired behaviour. It is written
/// down because the alternative is a suite that looks complete over a shape the
/// gate never sees, which is the defect CLOUD-418 names. If a later change gives
/// the mediated surface the prospective content as a fact rather than a string to
/// grep, this case flips and that is the signal it worked.
#[test]
fn an_interpreter_writing_through_its_program_text_is_a_known_gap() {
    assert_allowed(&format!("python3 -c \"open('{AUTHORITY}','w')\""));
}

/// THE DIRECTION A CARELESS FIX BREAKS, and the one that decides whether this
/// gate survives contact with daily use.
///
/// A guard that refuses ordinary reads gets switched off within a day, which is
/// how this class of guard dies. `cat`, `grep` and the repository's own gate
/// tools point at `batten.toml` constantly, so they are declared readers and must
/// stay allowed — and that is the whole reason the remedy was to invert the
/// enumeration rather than lengthen it.
/// NOT `cat` OR `grep`, AND THAT IS THIS REPOSITORY'S OWN CONFIG SPEAKING. Both
/// are declared readers, and both are refused here by a DIFFERENT row —
/// `no-tool-substitution`, which routes a text utility over a tracked path to the
/// structured surface. Asserting them allowed would fail for a reason that has
/// nothing to do with this gate, and asserting them denied would read as evidence
/// about readers when it is evidence about substitution.
#[test]
fn a_declared_reader_may_still_read_a_protected_path() {
    assert_allowed(&format!("taplo lint {AUTHORITY}"));
}

/// A program the verb table names is KNOWN even when its mutating rows do not
/// match, so the new clause must not refuse it.
///
/// `git` is in the table for its move and remove rows. `git add` is neither, and
/// before this clause existed it was allowed because nothing matched. It must
/// still be allowed for the same reason — the table encodes git's argv grammar,
/// so a non-matching invocation is a considered allow rather than an absence.
/// A clause that keyed on "did any row match" instead of "is this program known"
/// would refuse every commit in the repository.
#[test]
fn a_named_program_whose_mutating_rows_do_not_match_is_still_allowed() {
    assert_allowed(&format!("git add {AUTHORITY}"));
    assert_allowed(&format!("git diff {AUTHORITY}"));
}

/// An unknown program on an UNPROTECTED path is untouched.
///
/// The clause is scoped to the protected set, not to unknown programs generally
/// — otherwise it would refuse most of what an agent runs.
#[test]
fn an_unknown_program_is_untouched_away_from_a_protected_path() {
    assert_allowed("python3 -c \"open('target/debug/scratch','w')\"");
    assert_allowed("perl -pi -e s/a/b/ README.md");
}

/// The normalised write target is rendered in GIT's separator, not the host's.
///
/// `Envelope::relativise_writes` strips the repository root off an absolute
/// `file_path`, and `Path::to_str` renders what it strips with the PLATFORM
/// separator. Every reader of the result compares it against a repo-relative
/// glob — `protected` through `PathSet::contains`, a consumer module over
/// `input.call.writes` — and those globs are written in git's spelling, which is
/// `/` on every platform.
///
/// So on Windows the value was `.serena\memories\core.md`, which matches none of
/// them: the normalisation CLOUD-1133 added to fix a silent miss reintroduced the
/// same silent miss one platform over, and the protected gate did not enforce
/// there at all.
///
/// CAUGHT BY CI RATHER THAN BY READING, which is why this case exists rather than
/// a comment. `the_absolute_spelling_the_host_sends_signals_too` was green on
/// Linux and red on the Windows job — exactly the asymmetry a `MAIN_SEPARATOR`
/// path produces. This asserts the property directly so the next reader does not
/// need a second platform to find out, and it is deliberately a DENY assertion:
/// a separator that stops matching turns the gate off, and off is silent.
#[test]
fn the_normalised_write_target_uses_forward_slashes_on_every_platform() {
    let absolute = root()
        .canonicalize()
        .expect("the repository root resolves")
        .join(GUARDED)
        .display()
        .to_string();
    assert_eq!(
        write_verdict("Write", &absolute),
        Some(2),
        "an absolute protected target must refuse whatever separator the host \
         spells it with — a rendered `\\` matches no repo-relative glob"
    );
}

// --- CLOUD-1287: verb/operand attribution stops at a newline ------------------
//
// A newline is whitespace to the tokenizer, so a script written across lines was
// ONE segment and `effective_program` resolved the first line's program for all
// of it. `protected_readers` was therefore unreachable from any script, which is
// the surface it exists for.
//
// Narrow on purpose: segment identity is untouched, so no landed `pipeline`
// verdict moves. Only the mutation walk and the unknown-program walk stop at a
// line.

#[test]
fn a_declared_reader_is_consulted_whatever_precedes_it_on_an_earlier_line() {
    // THE MEASURED PAIR, and it is the whole defect: the same read, once alone
    // and once on line two. Before this the second refused, naming `cd` — a
    // false refusal on a READ, which is the direction that gets a guard switched
    // off rather than the sanctioned one.
    assert_allowed(&format!("stat -c %s {AUTHORITY}"));
    assert_allowed(&format!("cd /tmp\nstat -c %s {AUTHORITY}"));
}

#[test]
fn a_genuine_mutation_on_a_later_line_is_still_refused() {
    // THE DISCRIMINATOR, without which the fix above is a blanket allow for
    // every multi-line call. Line one is innocuous; line two is a declared
    // mutation of a protected path and must still be refused.
    assert_denied(&format!("cd /tmp\nrm {GUARDED}"));
    assert_denied(&format!("echo starting\nsed -i s/a/b/ {AUTHORITY}"));
}

#[test]
fn an_unknown_program_on_a_later_line_is_still_refused() {
    // The other arm the narrowing touches (CLOUD-1141's inversion). A program
    // neither table names, handed a protected path, refuses — and it must keep
    // refusing when the call is written across lines rather than becoming an
    // operand of whatever ran first.
    assert_denied(&format!("echo starting\nperl -pi -e s/a/b/ {AUTHORITY}"));
}

#[test]
fn a_newline_did_not_become_a_separator() {
    // THE BOUND, asserted rather than assumed. Promoting a newline in
    // `segments` would have changed every landed `pipeline` verdict, so the case
    // that would notice is a discard shape written across lines: it is still ONE
    // segment, so the pager still discards the verdict and the call is still
    // refused. A newline-as-separator would have made these two commands and
    // allowed the first.
    assert_denied("mise run verify\n| tail -1");
}

// --- CLOUD-1109: clause 3 resolves against the caller's cwd -------------------
//
// `repo_relative_path` was purely lexical: a token SHAPED like a relative path
// was called "inside the repository". Reproduced twice on 2026-08-28 from a
// scratch directory outside the tree — `cat err.txt` refused while the identical
// file named absolutely was allowed.

/// A mediated call carrying the caller's own working directory.
///
/// The whole defect is that this field existed and nothing read it, so a case
/// that omitted it could not discriminate.
fn bash_payload_in(cwd: &std::path::Path, command: &str) -> String {
    let escaped = serde_json::to_string(command).expect("a command is encodable");
    let dir = serde_json::to_string(&cwd.display().to_string()).expect("a path is encodable");
    format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\"cwd\":{dir},\
         \"tool_input\":{{\"command\":{escaped}}}}}"
    )
}

fn verdict_in(cwd: &std::path::Path, command: &str) -> Option<i32> {
    run_with_stdin(
        &root(),
        &["hook", "--harness", "exit-code"],
        &bash_payload_in(cwd, command),
    )
    .status
    .code()
}

#[test]
fn one_file_outside_the_repository_gets_one_verdict_whichever_way_it_is_spelled() {
    // THE PAIR THAT IS THE WHOLE DEFECT, and it is red against the unfixed
    // binary: the relative spelling refused and the absolute one allowed, for
    // one transient scratch file `git ls-files` has never heard of.
    // OUTSIDE the tree deliberately: `scratch` lives under `target/`, which the
    // repository contains, so the case would be asking the opposite question.
    let dir = common::scratch_outside_tree("cloud-1109", "outside");
    std::fs::write(dir.join("err.txt"), "scratch\n").expect("the scratch file is writable");
    let absolute = dir.join("err.txt").display().to_string();

    assert_eq!(
        verdict_in(&dir, "cat err.txt"),
        verdict_in(&dir, &format!("cat {absolute}")),
        "one file, two spellings, one verdict"
    );
    assert_eq!(
        verdict_in(&dir, "cat err.txt"),
        Some(0),
        "and the verdict is allow: the repository does not contain it"
    );
}

#[test]
fn a_relative_path_inside_the_repository_is_still_refused_from_a_subdirectory() {
    // THE DISCRIMINATOR. Without it the fix above is a blanket allow for every
    // relative operand, which would switch clause 3 off entirely — and a gate
    // that refuses nothing looks exactly like a gate that passed.
    let inside = root().join("crates");
    assert_eq!(
        verdict_in(&inside, "cat batten/Cargo.toml"),
        Some(2),
        "a path the repository contains, reached relatively from a subdirectory"
    );
}

#[test]
fn the_verdict_claims_containment_and_never_the_index() {
    // The second defect, which is independent of the first: the prose asserted
    // that the repository TRACKS the path, and nothing ever asked git. A
    // `git ls-files` per mediated call is a spawn `RuleKind::scopes` forbids on
    // this kind, so the fix is to stop claiming it rather than to check it.
    let explained = run(&root(), &["policy", "explain", "tool run loose"]);
    assert_eq!(explained.status.code(), Some(0), "the class resolves");
    let text = String::from_utf8_lossy(&explained.stdout);
    assert!(
        !text.contains("this repository tracks"),
        "no tracked-ness claim survives: {text}"
    );
    assert!(
        text.contains("CONTAINS") || text.contains("contains"),
        "and the class says what the predicate actually decided: {text}"
    );
}

// --- CLOUD-609: a bare directory destination is inside the protected set ------
//
// `protected` is matched with `literal_separator(true)`, so `dir/**` needs at
// least one component after the separator and `dir` is not a member of it. Every
// mutating verb aimed at a guarded DIRECTORY was therefore allowed while the same
// verb naming a file inside it denied.
//
// A fidelity loss from the CLOUD-312 port rather than a gate designed without it:
// the retiring `memory-guard-check` matched by substring and caught this.

/// The guarded directory itself, in the trailing-slash form a caller types.
const GUARDED_DIR: &str = ".serena/memories/";

#[test]
fn a_mutating_verb_aimed_at_a_guarded_directory_is_refused() {
    // RED AGAINST THE UNFIXED BINARY, and it is the measured case from the row.
    assert_denied(&format!("cp /tmp/draft.md {GUARDED_DIR}"));
    // The other every-operand verbs the gap has covered since CLOUD-96.
    assert_denied(&format!("mv /tmp/draft.md {GUARDED_DIR}"));
    assert_denied(&format!("rm -rf {GUARDED_DIR}"));
}

#[test]
fn the_directory_without_its_trailing_slash_is_refused_too() {
    // Normalisation and containment are two steps and this is what says both
    // landed: strip alone leaves `dir`, which is still not a member of `dir/**`.
    assert_denied(&format!("rm -rf {}", GUARDED_DIR.trim_end_matches('/')));
}

#[test]
fn reading_out_of_a_guarded_directory_still_allows() {
    // THE DIRECTION A CARELESS CONTAINMENT PREDICATE BREAKS. Copying a memory
    // OUT is a read, and this gate is not its business — a guard that refuses
    // reads is one people switch off.
    assert_allowed(&format!("cp {GUARDED_DIR} /tmp/copy.md"));
    assert_allowed(&format!("cp {GUARDED} /tmp/copy.md"));
}

#[test]
fn a_directory_whose_name_merely_starts_the_same_is_not_enclosed() {
    // The separator in the comparison is what buys this: `.serena/memories` is
    // a prefix of `.serena/memoriesx` as a STRING and not as a path. Without
    // this arm the predicate would refuse a sibling directory nobody guarded.
    assert_allowed("cp /tmp/draft.md target/memoriesx/");
}

#[test]
fn a_backslash_continuation_is_one_command_and_is_still_refused() {
    // THE BYPASS CLOUD-1287's SPLIT WOULD HAVE OPENED, caught in review of that
    // change rather than in the field. `rm \` then a path on the next line is
    // ONE command to bash; split naively it hands line one an `rm` with no
    // operands and line two an operand with no program, so the protected path is
    // judged by nothing.
    assert_denied(&format!("rm \\\n{GUARDED}"));
    assert_denied(&format!("cp /tmp/draft.md \\\n{GUARDED}"));
    // And the even case, which is NOT a continuation: two backslashes are an
    // escaped backslash, so the line ends and the next one stands alone.
    assert_denied(&format!("echo done\nrm {GUARDED}"));
}
