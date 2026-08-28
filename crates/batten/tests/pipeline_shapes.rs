//! The discarded-verdict corpus, over the compiled binary (CLOUD-443).
//!
//! `tests/run-shape-guard.bats`'s first family, translated into the surface that
//! now decides it: a `pipeline` row with its `verdict` and `filters` tables. The
//! bash guard keeps only the two families the engine cannot express — a
//! foreground `sleep` and an unsatisfiable `git commit` — so this file is what
//! keeps the split honest.
//!
//! **The allows are the load-bearing half.** Every deny here has a
//! near-identical allow beside it, and that is the whole design of the predicate
//! rather than test hygiene: CLOUD-199 measured that a guard with false positives
//! gets bypassed, and a bypassed guard enforces nothing. A suite asserting only
//! the denies would pass on a rule that refuses every pipeline in the repository.
//!
//! Judged against the **committed** `batten.toml`, because the tables are the
//! consumer's: a fixture-only suite would stay green after someone deleted the
//! `cargo` row, which is exactly the drift the corpus exists to catch.
//!
//! Every `cargo` sample is written `mise exec -- cargo …` since CLOUD-271: the
//! committed `no-bare-cargo` row refuses the unmediated route outright, so a
//! bare spelling would make the allows fail and — worse — make the denies pass
//! for the wrong row, which is coverage that has stopped testing this predicate.
//! The wrapper look-through means the mediated form is still judged as `cargo`,
//! so each case asks exactly what it asked before.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::PathBuf;

use common::{run_with_stdin, stderr};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn payload(command: &str) -> String {
    let encoded = serde_json::to_string(command).expect("a command is encodable");
    format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\
         \"tool_input\":{{\"command\":{encoded}}}}}"
    )
}

fn verdict(command: &str) -> Option<i32> {
    run_with_stdin(
        &root(),
        &["hook", "--harness", "exit-code"],
        &payload(command),
    )
    .status
    .code()
}

fn assert_denied(command: &str) {
    assert_eq!(verdict(command), Some(2), "must refuse: {command}");
}

fn assert_allowed(command: &str) {
    assert_eq!(verdict(command), Some(0), "must allow: {command}");
}

/// The refusal text, for the cases where WHICH operand a deny names is the thing
/// under test rather than the verdict. A free function beside the two above
/// because both families need it now: the discard family asserts that three
/// shapes render three causes, and the substitution family asserts that the
/// cause points at the operand a caller can act on.
fn cause(command: &str) -> String {
    stderr(&run_with_stdin(
        &root(),
        &["hook", "--harness", "exit-code"],
        &payload(command),
    ))
}

#[test]
fn a_verdict_piped_into_a_pager_or_filter_is_refused() {
    // The measured cases, each of which produced a confident "green" report over
    // a run that had failed.
    assert_denied("mise run verify 2>&1 | tail -6");
    assert_denied("mise run verify | head -20");
    assert_denied("git push origin branch | tail -2");
    assert_denied("mise exec -- cargo clippy | grep -E error");
    assert_denied("mise exec -- cargo test -p batten | wc -l");
    assert_denied("gh pr merge 42 | tail -1");
    // A filter two stages down substitutes just as completely as an adjacent one.
    assert_denied("mise run verify | sort | tail -3");
}

#[test]
fn a_read_only_query_carries_no_verdict_and_composes_freely() {
    // The false positive that would make this gate unusable: piping a query is
    // ordinary work, and its output IS its answer.
    assert_allowed("git log --oneline -5 | head -2");
    assert_allowed("git status --short | wc -l");
    assert_allowed("gh pr view 42 | tail -3");
    assert_allowed("mise exec -- cargo metadata | jq .packages");
    // `jq` is composition rather than a verdict substitute, so it is not a filter
    // even downstream of a real verdict.
    assert_allowed("gh pr view 42 --json title | jq -r .title");
}

#[test]
fn a_pager_over_a_file_is_fine_it_is_a_pager_over_a_live_task_that_is_not() {
    // This is the remedy the refusal itself recommends, so refusing it would make
    // the gate self-contradicting.
    assert_allowed("tail -6 /tmp/verify.log");
    assert_allowed("grep -E error /tmp/clippy.log");
}

#[test]
fn a_trailing_list_element_replaces_the_status() {
    // The laundered shape: it reads as correct, and the guard this ports used to
    // recommend it. Backgrounded it is worse than a misread — the completion
    // notification then carries the compound's status, so a failed task arrives
    // as `completed (exit code 0)`.
    assert_denied("mise run verify >log 2>&1; echo \"EXIT=$?\"");
    assert_denied("mise run fmt >log 2>&1 || echo failed");
    assert_denied("mise exec -- cargo test >log 2>&1; ls");
}

#[test]
fn an_and_chain_is_allowed_because_it_cannot_manufacture_a_green() {
    // The deliberate departure from the written acceptance, and the reason is
    // arithmetic rather than taste: `a && b` short-circuits, so a failure in `a`
    // still exits the list non-zero. There is no false green to stop, and
    // `verify`'s own body is built from guarded chains for that property.
    assert_allowed("mise run fmt && mise run verify");
    assert_allowed("git fetch origin main && git rebase origin/main");
    // THE CARGO ARM MOVED, AND WHY IT HAD TO IS WORTH THE LINES (CLOUD-312 row
    // 11). It read `mise exec -- cargo build && mise exec -- cargo test`, which
    // is the shape an author would reach for — and it started failing the moment
    // `run-shape-guard` went behind the door, because these cases drive the REAL
    // `batten.toml` and the handler is now dispatched by `batten hook`. That
    // command is a weaker form of two declared tasks, so the handler denies it
    // (CLOUD-822), correctly and for a reason this row has nothing to say about.
    //
    // This is the substitution `tests/run-shape-guard-door.bats`'s header warns
    // about, running the other way round: there a handler's verdict could be
    // supplied by an engine row, here an engine row's allow was masked by a
    // handler's deny. Both are one config answering for two rules.
    //
    // So the fixture names a cargo subcommand NO task wraps, which is the case
    // that deny message itself calls untouched — the `&&` property is this row's
    // subject and the cargo family is only how it is spelled. If a task ever
    // wraps `doc` or `bench`, this line fails and the fix is to pick another
    // genuine one-off, never to weaken the handler.
    assert_allowed("mise exec -- cargo doc && mise exec -- cargo bench");
}

#[test]
fn detaching_a_verdict_orphans_it_from_the_tool_call() {
    assert_denied("nohup mise run land >/tmp/land.log 2>&1 &");
    assert_denied("mise run ci-wait &");
    assert_denied("nohup mise exec -- cargo test -p batten >/tmp/t.log 2>&1 &");
    // The wrapper is looked through, so the wrapped program is what is judged.
    assert_denied("nohup mise run verify");
}

#[test]
fn the_prescribed_form_is_allowed_including_its_redirection() {
    // THE regression test for the parser change. `2>&1` carries a literal `&`,
    // and the form this engine prescribes contains one — so an `&` test
    // that did not exempt redirections would refuse the exact idiom the refusal
    // recommends, which is the worst failure this gate could have.
    assert_allowed("mise run verify >/tmp/verify.log 2>&1");
    assert_allowed("mise run land >/tmp/land.log 2>&1");
    assert_allowed("mise exec -- cargo test -p batten >/tmp/test.log 2>&1");
    assert_allowed("git push origin branch >/tmp/push.log 2>&1");
    // The other redirection spellings that carry an `&`.
    assert_allowed("mise run verify &>/tmp/verify.log");
    assert_allowed("mise run verify >/tmp/v.log 2>&1 && echo queued");
}

#[test]
fn a_verdict_alone_in_the_call_is_the_prescribed_form() {
    assert_allowed("mise run verify");
    assert_allowed("mise exec -- cargo test -p batten");
    assert_allowed("git push origin branch");
    assert_allowed("bats tests/land.bats");
}

#[test]
fn a_bare_invocation_that_answers_nothing_is_not_a_verdict() {
    // A test runner with no suite, and a build tool with no subcommand, print
    // usage. Piping usage is not discarding a verdict, because there is none.
    assert_allowed("bats --version | head -1");
    assert_allowed("bats --help | tail -5");
    assert_allowed("mise exec -- cargo | head -3");
}

#[test]
fn a_command_describing_the_shape_is_not_the_shape() {
    // A commit message, an issue body, or documentation naming one of these
    // shapes is prose. The parser's quote handling is what makes this hold, and
    // it is pinned here because this repository's own commits say these things.
    assert_allowed("git commit -m \"never run mise run verify | tail -6\"");
    assert_allowed("git commit -m \"the nohup mise run land & shape is refused\"");
    assert_allowed("echo \"mise run verify | tail\" > /tmp/notes.md");
}

#[test]
fn a_pager_on_an_earlier_query_does_not_condemn_a_later_command() {
    // Judged per segment. A pager attached to a read-only first element says
    // nothing about a verdict-bearing second one, and judging the whole string
    // refused exactly that — a correct command using the recommended form.
    assert_allowed("git log --oneline | head -3 && mise run verify >/tmp/v.log 2>&1");
    // And the direction that matters: a write must not be excused by a read.
    assert_denied("git log --oneline | head -3 && mise run verify | tail -2");
}

#[test]
fn the_refusal_states_the_principle_rather_than_naming_one_command() {
    // CLOUD-199's second instance happened because an agent complied with the
    // narrower wording exactly and made the same error on the next command. The
    // cause therefore has to generalise, and the remedy has to be the row's.
    let refusal = stderr(&run_with_stdin(
        &root(),
        &["hook", "--harness", "exit-code"],
        &payload("mise run verify | tail -6"),
    ));
    assert!(
        refusal.contains("verdict-not-discarded"),
        "names the rule: {refusal}"
    );
    assert!(
        refusal.contains("exit status"),
        "states the principle: {refusal}"
    );
    assert!(
        refusal.contains("run_in_background"),
        "names the remedy: {refusal}"
    );
    // Pointer-only: the caller's own command line is never echoed back.
    assert!(
        !refusal.contains("tail -6"),
        "must not echo the mediated command: {refusal}"
    );
}

#[test]
fn each_shape_renders_its_own_cause() {
    // Three causes from one row, in `receipt_refusal`'s idiom. A single generic
    // message would leave the reader to work out which of three structures they
    // wrote.
    assert!(cause("mise run verify | tail -1").contains("pager or filter"));
    assert!(cause("mise run verify >log 2>&1; ls").contains("only the last element"));
    assert!(cause("nohup mise run verify &").contains("orphans it"));
}

// --- the substitution family (CLOUD-864) --------------------------------------
//
// The second predicate this kind carries. Same file as the discard family
// because they are decided over the same parse and by the same row kind, and
// splitting them would hide that the ALLOW half of each is the other's deny:
// a filter downstream of a pipe is refused by `verdict-not-discarded` when its
// producer carries a verdict, and allowed by `no-tool-substitution` always.

#[test]
fn a_text_utility_aimed_at_a_repository_path_is_refused() {
    // The measured shapes, from the transcript that produced the issue: 15
    // `head -N`, 13 `grep`, 12 `ls`, 5 `cat`, 5 `sed -n`, 2 `find -name`.
    assert_denied("sed -n '1,40p' AGENTS.md");
    assert_denied("head -40 batten.toml");
    assert_denied("cat .serena/project.yml");
    assert_denied("grep -rn CLOUD crates/");
    assert_denied("wc -l AGENTS.md");
    // A path that only LOOKS like a path because it has an extension is still a
    // path: the operand names a file this repository tracks.
    assert_denied("tail -5 mise.toml");
}

#[test]
fn the_same_utility_downstream_of_a_pipe_is_a_filter_and_is_untouched() {
    // THE LOAD-BEARING HALF, and the reason this row is a `pipeline` and not a
    // `shape`. `matching_shape_rows` iterates every segment with no index in
    // scope, so a shape row carrying these programs would refuse every line
    // below — ordinary work, and the false-positive class CLOUD-199 measured
    // gets a guard bypassed.
    assert_allowed("git ls-files | grep crates/batten");
    assert_allowed("git status --short | grep '^ M'");
    assert_allowed("git ls-files 'mise-tasks/*' | wc -l");
    assert_allowed("git log --oneline | sed -n '1,3p'");
    // Two stages down is still downstream.
    assert_allowed("git ls-files | sort | head -20");
}

#[test]
fn a_target_outside_the_repository_is_not_a_substitution() {
    // `>/tmp/<task>.log` is the shape `verdict-not-discarded` MANDATES, so a row
    // that refused reading one back would put the two rows in contradiction.
    assert_allowed("cat /tmp/verify.log");
    assert_allowed("tail -20 /tmp/land.log");
    assert_allowed("cat ~/.config/some.conf");
}

#[test]
fn an_operand_that_is_not_a_path_is_not_a_substitution() {
    // A bare pattern, and stdin. `grep CLOUD` with no file is reading its input
    // from somewhere else; refusing it would refuse a pipeline's tail written as
    // two calls.
    assert_allowed("grep -c CLOUD");
    assert_allowed("cat -");
    // A flag's value is not an operand: `-n 40` must not read as a path.
    assert_allowed("head -n 40");
}

// The two defects this row committed against its own author within the hour it
// landed. Both refused CORRECTLY and both named the wrong operand, which is the
// half that matters: the deny text is the only thing the caller can act on, and
// one pointing at `2>/dev/null` teaches nothing. Kept as their literal
// transcript shapes rather than minimised, so a reader can see they were real.

#[test]
fn a_redirection_is_not_an_operand_and_never_the_named_target() {
    // Observed: refused naming `2>/dev/null` "a path in this repository".
    assert!(cause("tail -40 batten.toml 2>/dev/null").contains("batten.toml"));
    // And the scan STOPS there, so a stdin-fed call writing into the tree is not
    // a substitution — nothing was read instead of reaching for a tool.
    assert_allowed("grep -c CLOUD > counts.txt");
    assert_allowed("sort < input.txt");
}

#[test]
fn a_substitutes_entry_may_be_qualified_by_a_flag() {
    // `sed` reads a file two ways and only one of them has a first-class
    // equivalent, so the row spells the entry `sed:-n`. The deny half is already
    // covered above (`sed -n '1,40p' AGENTS.md`); these are the allows that make
    // the qualifier mean something.
    //
    // A TRANSFORM. No tool applies a substitution expression, so refusing this
    // would state a reason that is not true — the defect the qualifier fixes.
    assert_allowed("sed s/old/new/ batten.toml");
    assert_allowed("sed -e s/a/b/ mise.toml");
    // Bundled and value-carrying spellings of the flag still select: a caller
    // does not escape the row by writing `-ne` instead of `-n`.
    assert_denied("sed -ne 1p batten.toml");
    // ...and a LONG option that merely contains the letter does not. `sed
    // --no-autoprint` is `-n`'s own long form, but `--posix` is not, and a
    // `contains` over the whole token would read the `n` in it as the flag.
    assert_allowed("sed --posix s/a/b/ batten.toml");
    // The unqualified entries are unaffected — one program's qualifier must not
    // silently narrow the other eight.
    assert_denied("cat batten.toml");
    assert_denied("head -5 mise.toml");
}

#[test]
fn a_regex_alternation_is_a_pattern_however_much_it_looks_like_a_path() {
    // Observed: `.bats|basename` parsed as an extension, so the PATTERN was
    // named as the target and the real operands never reached the test.
    assert_allowed("grep -E 'mise-tasks|BATS_TEST_FILENAME|%.bats|basename'");
    // With real file operands it still denies — on the files, not the pattern.
    assert!(cause("grep -E 'a|b.bats' tests/land.bats").contains("tests/land.bats"));
    // THE SECOND ESCAPE, which the `|` test alone did not catch: a character
    // class carrying a `/` and no alternation at all.
    assert_allowed(r"grep -oE '\)/[A-Za-z0-9_][A-Za-z0-9._-]*'");
    assert!(
        cause(r"grep -oE '^\s+[a-z]+/' batten.toml").contains("batten.toml"),
        "the file operand is the target, never the anchored pattern"
    );
    // A GLOB IS STILL A PATH, and must stay denied — `Glob` is precisely the
    // tool for it, so excluding `*` along with the regex metacharacters would
    // have opened the hole this row exists to close.
    assert_denied("ls mise-tasks/*.sh");
}
