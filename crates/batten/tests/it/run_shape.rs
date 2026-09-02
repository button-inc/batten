//! `policy/run-shape.rego` decides over the compiled binary (CLOUD-843 track 2).
//!
//! ─── CLOUD-1163 UNIT 9'S RETIREMENT LEDGER ──────────────────────────────────
//!
//! Three governed paths died with that unit, and each names a POLICY SURFACE and
//! a COMPILED-BINARY TEST because either alone is satisfiable by a port that does
//! nothing: a row naming only a module has no evidence it works, and one naming
//! only a test has nothing under test.
//!
//! The guard carried FOUR families and all four had already landed, which is what
//! made it deletable whole rather than piecemeal — `shell-retirement`'s one
//! admitted disposition, and the reason no line of it needed editing to qualify.
//! Three of the four are this module's; the fourth is `task-substitution`'s, so it
//! names that surface and its own tier.

// carried: mise-tasks/run-shape-guard.sh policy/run-shape.rego crates/batten/tests/it/run_shape.rs
// carried: tests/run-shape-guard.bats policy/run-shape.rego crates/batten/tests/it/run_shape.rs
// carried: tests/run-shape-guard-quoting.bats policy/run-shape.rego crates/batten/tests/it/run_shape.rs

// ─── THE CASES INSIDE THOSE SUITES (CLOUD-908) ───────────────────────────────
//
// The rows above conserve the FILES; these conserve the 42 CASES inside them,
// which is the distinction CLOUD-908 exists to make — a retirement that names the
// file and drops its cases is the silent coverage loss that row measured.
//
// Routed by FAMILY rather than by file: three of the guard's four families are
// this module's, and `cargo-substitutes-for-a-task` is `task-substitution`'s, so
// those cases name that surface and its own tier instead. A row naming this file
// for all 42 would claim coverage that is not here.
// carried: "THE MEASURED SHAPE: a sleep in the middle of a compound is denied" policy/run-shape.rego crates/batten/tests/it/run_shape.rs
// carried: "a leading sleep is denied too" policy/run-shape.rego crates/batten/tests/it/run_shape.rs
// carried: "a SHORT sleep is the same shape spending less" policy/run-shape.rego crates/batten/tests/it/run_shape.rs
// carried: "the denial names the remedy: background the wait, act on the exit" policy/run-shape.rego crates/batten/tests/it/run_shape.rs
// carried: "a wrapper does not hide it" policy/run-shape.rego crates/batten/tests/it/run_shape.rs
// carried: "a BACKGROUND sleep is allowed — it is the recommended wait" policy/run-shape.rego crates/batten/tests/it/run_shape.rs
// carried: "THE MEASURED SHAPE: a backgrounded sleep-then-read is a timer, not a wait" policy/run-shape.rego crates/batten/tests/it/run_shape.rs
// carried: "a bare backgrounded sleep waits for nothing and reports nothing" policy/run-shape.rego crates/batten/tests/it/run_shape.rs
// carried: "the timer denial names both affordances: the exit notification and alive" policy/run-shape.rego crates/batten/tests/it/run_shape.rs
// carried: "a backgrounded WHILE loop is a wait and stays allowed" policy/run-shape.rego crates/batten/tests/it/run_shape.rs
// carried: "a backgrounded wait on state nothing notifies you about stays allowed" policy/run-shape.rego crates/batten/tests/it/run_shape.rs
// carried: "a backgrounded long-running command with no sleep is untouched" policy/run-shape.rego crates/batten/tests/it/run_shape.rs
// carried: "a foreground call with no sleep is still none of this rule's business" policy/run-shape.rego crates/batten/tests/it/run_shape.rs
// carried: "a backgrounded sleep described in prose is prose" policy/run-shape.rego crates/batten/tests/it/run_shape.rs
// carried: "a sleep written INSIDE a quoted span or a heredoc is not a call" policy/run-shape.rego crates/batten/tests/it/run_shape.rs
// carried: "a bare command with no sleep and no verdict is still none of this guard's business" policy/run-shape.rego crates/batten/tests/it/run_shape.rs
// carried: "THE MEASURED SHAPE: the heredoc binds to a later element, so git gets nothing" policy/run-shape.rego crates/batten/tests/it/run_shape.rs
// carried: "a bare -F - with no redirect anywhere is denied" policy/run-shape.rego crates/batten/tests/it/run_shape.rs
// carried: "the denial names -F <path>, which is the form that cannot rebind" policy/run-shape.rego crates/batten/tests/it/run_shape.rs
// NO ARM FOR "every form that CAN obtain a message stays allowed": `tests/run-shape.bats`
// retired a case of the same name earlier and its `changed:` row below already
// accounts for it. The ledger keys on the case NAME and admits exactly one arm per
// name, so a second would be refused — and the surviving row is the better of the
// two anyway, because it records that the claim CHANGED rather than merely moved.
// carried: "a heredoc that genuinely binds to this element is a message source" policy/run-shape.rego crates/batten/tests/it/run_shape.rs
// carried: "a file or a here-string redirected into it is a message source too" policy/run-shape.rego crates/batten/tests/it/run_shape.rs
// carried: "a git commit written INSIDE a quoted span or a heredoc is not a call" policy/run-shape.rego crates/batten/tests/it/run_shape.rs
// carried: "THE MEASURED SHAPE: a weaker clippy through the sanctioned escape is refused" policy/task-substitution.rego crates/batten/tests/it/task_receipt.rs
// carried: "the task itself is allowed — this rule is about substitution, not about cargo" policy/task-substitution.rego crates/batten/tests/it/task_receipt.rs
// carried: "a subcommand no task wraps is a genuine one-off and is untouched" policy/task-substitution.rego crates/batten/tests/it/task_receipt.rs
// carried: "a BARE cargo is no-bare-cargo's, so the two never report one command" policy/task-substitution.rego crates/batten/tests/it/task_receipt.rs
// carried: "an EQUAL argv is not weaker, so spelling a task's own line out is allowed" policy/task-substitution.rego crates/batten/tests/it/task_receipt.rs
// carried: "a narrower argv IS weaker, and the task it is weaker than is named" policy/task-substitution.rego crates/batten/tests/it/task_receipt.rs
// carried: "a DIFFERENT program argv is a different command, not a weaker one" policy/task-substitution.rego crates/batten/tests/it/task_receipt.rs
// carried: "the SAME program argv, missing a flag, is a substitution" policy/task-substitution.rego crates/batten/tests/it/task_receipt.rs
// carried: "post-dash-dash LINT flags count as strictness, which is the whole measurement" policy/task-substitution.rego crates/batten/tests/it/task_receipt.rs
// carried: "THE MAPPING IS DERIVED: retitle the task's cargo line and the verdict follows" policy/task-substitution.rego crates/batten/tests/it/task_receipt.rs
// carried: "a description naming a command is prose, never a declaration" policy/task-substitution.rego crates/batten/tests/it/task_receipt.rs
// carried: "the refusal names its bypass, since one that cannot be reached is not a remedy" policy/task-substitution.rego crates/batten/tests/it/task_receipt.rs
// carried: "the bypass actually clears it" policy/task-substitution.rego crates/batten/tests/it/task_receipt.rs
// carried: "a multi-line commit message quoting the shapes is not the shapes" policy/run-shape.rego crates/batten/tests/it/run_shape.rs
// carried: "a single-line quoted mention is still not the shape" policy/run-shape.rego crates/batten/tests/it/run_shape.rs
// carried: "a heredoc body naming the shapes is documentation" policy/run-shape.rego crates/batten/tests/it/run_shape.rs
// carried: "a here-string does not open a skip that swallows the rest" policy/run-shape.rego crates/batten/tests/it/run_shape.rs
// carried: "a real shape after a closed heredoc is still caught" policy/run-shape.rego crates/batten/tests/it/run_shape.rs
// carried: "a real shape after a closed quoted span is still caught" policy/run-shape.rego crates/batten/tests/it/run_shape.rs

//!
//! # Where this came from, and why it is Rust
//!
//! This file is the successor to `tests/run-shape.bats`, retired under
//! CLOUD-1059. The suite's own subject was `policy/run-shape.rego`, which
//! CLOUD-1050 rewrote: the module's refusal stopped being prose and became a
//! declared class. Its cases asserted the prose, so they went red — and
//! `shell-retirement` refuses editing a bats suite in place, which is the whole
//! point of that gate. Both doors shut on an edit; the open one is the
//! migration, and this is it. Every case below carries a `// carried:` arm.
//!
//! # What it keeps, unchanged
//!
//! **It drives the compiled binary over a real envelope**, which is the reason
//! the suite existed at all rather than a convenience. `batten policy test` is
//! established as insufficient evidence (CLOUD-845): `with input as` lets a
//! module's own test fabricate a shape the engine cannot produce, so a module
//! can pass its suite green and gate nothing. Every case here goes in through
//! `batten hook` — the same door a mediated call comes through — and reads the
//! permission decision the host would read.
//!
//! The fixture is a throwaway repository carrying ONE row and a copy of the
//! COMMITTED module, so the predicate is exercised in isolation from this
//! repository's other rules and cannot drift from the module that ships.
//!
//! # The status assertion is load-bearing, and it was a defect once
//!
//! `batten hook` prints NOTHING on an allow — the JSON is emitted only to deny —
//! and exits 0 either way, because the contract is that the harness reads the
//! decision and not the code. So a check of the form "the output does not
//! contain `deny`" is true over an EMPTY string, and every allow case in the
//! retired suite went green on any output at all, including the output of a
//! binary that died before it judged anything. That was CLOUD-251's vacuous pass
//! wearing a test's clothes, suite-wide. Both helpers below assert the status.

// THE FILE-GRANULARITY RETIREMENT ARM (CLOUD-1059). See the sibling note in
// `privileged_lane.rs` for why one marker carries two disjoint ledgers.
//
// carried: tests/run-shape.bats policy/run-shape.rego crates/batten/tests/it/run_shape.rs

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

/// A throwaway repository carrying the committed module and the one row that
/// enables it, plus the `[[pattern]]` and `[[verdict]]` rows it needs.
///
/// The pattern row is not decoration: an inline regex is refused at load, so
/// without it the module's reference is undefined and every allow case flips to
/// a denial — the silent disarm the engine refuses outright (CLOUD-885). The
/// verdict row is its sibling under CLOUD-1050: a token no row declares is
/// refused at load, so a fixture without it would be testing that refusal.
///
/// # One scratch tree PER CASE, and the shared one was a real race
///
/// `name` is not decoration. Every case here built `scratch("run-shape")`, and
/// `nextest` runs each case in its own process concurrently — so one case was
/// recreating the tree while another was reading it, and the reader got a
/// directory with no `batten.toml` in it. It surfaced as
/// `a_git_commit_naming_no_message_source_is_denied` failing on its SECOND
/// assertion with empty output, intermittently, which is exactly what a
/// half-written fixture looks like from the outside. The sibling
/// `privileged_lane.rs` had the per-case shape from the start; this file did not,
/// and the difference is why only this one flaked.
fn fixture(name: &str) -> PathBuf {
    let root = common::scratch(&format!("run-shape-{name}"));
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    let module = common::at_root("policy/run-shape.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::copy(module, root.join("policy/run-shape.rego")).expect("install committed module");
    fs::write(
        root.join("batten.toml"),
        concat!(
            "version = 1\n\n",
            "[[rule]]\n",
            "id = \"commit-message-obtainable\"\n",
            "kind = \"policy\"\n",
            "scope = \"mediated_call\"\n",
            "module = \"policy/run-shape.rego\"\n",
            "severity = \"deny\"\n\n",
            "[[pattern]]\n",
            "id = \"short-message-flag-cluster\"\n",
            "regex = \"^-[A-Za-z]*[mFCc]\"\n\n",
            "[[pattern]]\n",
            "id = \"commit-message-file-flag\"\n",
            "regex = \"^(-[A-Za-z]*F|--file)$\"\n\n",
            "[[verdict]]\n",
            "id = \"commit write missing\"\n",
            "gloss = \"a `git commit` names no message source, so git opens $EDITOR and blocks\"\n",
            "class = \"\"\"\n",
            "No `-m`, `-F`, `-C`, `--no-edit`, `--fixup` or `--squash`. Git opens $EDITOR and \\\n",
            "blocks, AFTER `pre-commit` has already spent the whole gate. Write the message to \\\n",
            "a file and use `git commit -F <path>`, the one form that cannot rebind.\n",
            "\"\"\"\n\n",
            "[[verdict.route]]\n",
            "id = \"patch run first\"\n",
            "kind = \"command\"\n",
            "target = \"git commit -F <path>\"\n\n",
            "[[verdict]]\n",
            "id = \"commit bind missing\"\n",
            "gloss = \"a `git commit -F -` has nothing redirected into the element it is written in\"\n",
            "class = \"\"\"\n",
            "The heredoc binds to the element that WRITES it, so git reads the harness's \\\n",
            "/dev/null — after `pre-commit` has already spent the whole gate.\n",
            "\"\"\"\n\n",
            "[[verdict.route]]\n",
            "id = \"patch run first\"\n",
            "kind = \"command\"\n",
            "target = \"git commit -F <path>\"\n\n",
            "[[verdict]]\n",
            "id = \"sleep run blocked\"\n",
            "gloss = \"a foreground `sleep` spends the session's own turn, and the call is killed at ~2 minutes\"\n",
            "class = \"\"\"\n",
            "A wait longer than about two minutes does not run slowly, it FAILS. Background \\\n",
            "the work and act on its exit notification.\n",
            "\"\"\"\n\n",
            "[[verdict.route]]\n",
            "id = \"task run first\"\n",
            "kind = \"command\"\n",
            "target = \"until <test>; do sleep 1; done\"\n\n",
            "[[verdict]]\n",
            "id = \"timer run refused\"\n",
            "gloss = \"a backgrounded `sleep` with no loop around it is a timer, not a wait\"\n",
            "class = \"\"\"\n",
            "It exits when the clock says so, never when the thing being waited for happens. \\\n",
            "The exit notification already fires.\n",
            "\"\"\"\n\n",
            "[[verdict.route]]\n",
            "id = \"task run first\"\n",
            "kind = \"command\"\n",
            "target = \"until <test>; do sleep 1; done\"\n",
        ),
    )
    .expect("write the fixture authority");
    common::git_in(&root, &["init", "-q", "-b", "main"]);
    root
}

/// Hand `command` to the engine as a Claude Code `PreToolUse` envelope.
///
/// No `run_in_background` key, which is the ordinary case rather than an
/// omission: most hosts send none, the engine projects `null`, and every
/// predicate here has to be correct about a host that said nothing.
fn hook(root: &Path, command: &str) -> (bool, String) {
    decide(root, command, None)
}

/// The same, with the call's backgrounding stated (CLOUD-1094).
fn hook_background(root: &Path, command: &str, background: bool) -> (bool, String) {
    decide(root, command, Some(background))
}

fn decide(root: &Path, command: &str, background: Option<bool>) -> (bool, String) {
    let mut tool_input = serde_json::json!({"command": command});
    if let Some(flag) = background
        && let Some(object) = tool_input.as_object_mut()
    {
        object.insert("run_in_background".to_owned(), flag.into());
    }
    let envelope = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": tool_input,
    })
    .to_string();
    let output = common::run_with_stdin(root, &["hook", "--harness", "claude-code"], &envelope);
    // THE STATUS IS PART OF THE ANSWER. Allow and deny both exit 0, so a
    // non-zero status is exactly and only the crash — and without this check an
    // allow assertion passes over a binary that died before judging anything.
    assert_eq!(
        output.status.code(),
        Some(0),
        "the engine decided rather than crashed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    (text.contains(r#""permissionDecision":"deny""#), text)
}

fn denied(root: &Path, command: &str) {
    let (deny, text) = hook(root, command);
    assert!(deny, "`{command}` should be refused: {text}");
}

fn allowed(root: &Path, command: &str) {
    let (deny, text) = hook(root, command);
    assert!(!deny, "`{command}` should be allowed: {text}");
}

fn denied_background(root: &Path, command: &str, background: bool) {
    let (deny, text) = hook_background(root, command, background);
    assert!(
        deny,
        "`{command}` (background={background}) should be refused: {text}"
    );
}

fn allowed_background(root: &Path, command: &str, background: bool) {
    let (deny, text) = hook_background(root, command, background);
    assert!(
        !deny,
        "`{command}` (background={background}) should be allowed: {text}"
    );
}

// ---------------------------------------------------------------------------
// The predicate.
// ---------------------------------------------------------------------------

// carried: "THE MEASURED SHAPE: a git commit naming no message source is denied" crates/batten/tests/it/run_shape.rs
#[test]
fn a_git_commit_naming_no_message_source_is_denied() {
    // `pre-commit` runs before git asks for a message, so this spends the whole
    // gate and then blocks on $EDITOR with nobody to close it (CLOUD-488).
    let root = fixture("no-message-source");
    denied(&root, "git commit");
    denied(&root, "git commit -a");
}

// changed: "every form that CAN obtain a message stays allowed" crates/batten/tests/it/run_shape.rs a bare `git commit -F -` moved from this list to `a_commit_reading_unbound_stdin_is_refused`, because CLOUD-613 landed the predicate that tells the two apart — the retired case could not, so it asserted the weaker claim
#[test]
fn every_form_that_can_obtain_a_message_stays_allowed() {
    // The load-bearing half. A predicate that only ever denied would satisfy the
    // case above and be useless (CLOUD-418).
    //
    // WHAT LEFT THIS LIST, and why it is not a regression. `git commit -F -` was
    // here because `-F` names a message source and the module could see nothing
    // finer: heredoc binding is a property of the ELEMENT, and until CLOUD-613
    // the module had no element to ask. The bash guard has refused this exact
    // string since 2026-08-12 (`run-shape-guard.sh:372-440`), so what changed is
    // which authority answers, not the answer. `-F -` WITH a redirect bound to
    // its own element is still allowed, below and in the module's own suite.
    let root = fixture("obtainable");
    for command in [
        "git commit -F /tmp/msg.txt",
        "git commit -m \"a message\"",
        "git commit -am \"a message\"",
        "git commit --amend --no-edit",
        "git commit --fixup HEAD",
        "git commit -C HEAD@{1}",
        "git commit --message=hello",
    ] {
        allowed(&root, command);
    }
}

// ---------------------------------------------------------------------------
// CLOUD-613: heredoc BINDING, which needed a parser change to be askable at all.
// ---------------------------------------------------------------------------

#[test]
fn a_commit_reading_unbound_stdin_is_refused() {
    // THE MEASURED SHAPE (CLOUD-488, PR #375). The heredoc binds to the LAST
    // element, so `mise run land` got the message and `git commit -F -` got the
    // harness's /dev/null — about four minutes of gate on a commit git was
    // always going to refuse, and killing it took `kill -9` on the process
    // group.
    //
    // This is the case a command-string predicate cannot decide: the opener is
    // PRESENT in the string and ABSENT from the element that needed it.
    let root = fixture("stdin-unbound");
    denied(
        &root,
        "git add -A && git commit -F - && mise run land <<'EOF'\nmsg\nEOF\n",
    );
    denied(&root, "git commit -F -");
    denied(&root, "git commit --file=-");
    denied(&root, "git commit --file -");
}

#[test]
fn a_redirect_bound_to_the_commits_own_element_is_a_message_source() {
    // The discriminating half, and the pair above is the same four words in the
    // same order — only the BINDING differs. All three spellings of `<`, because
    // one test covers all three in the predicate and a suite that exercised one
    // would not show that.
    let root = fixture("stdin-bound");
    allowed(&root, "git commit -F - <<'EOF'\nmsg\nEOF\n");
    allowed(&root, "git commit -F - < /tmp/msg.txt");
    allowed(&root, "git commit -F - <<< \"$msg\"");
    // A heredoc opened in an EARLIER element does not bind here either, which is
    // the same rule read in the other direction.
    allowed(
        &root,
        "cat <<'EOF' > /tmp/msg.txt\nmsg\nEOF\ngit commit -F /tmp/msg.txt",
    );
}

#[test]
fn a_heredoc_body_is_not_shell() {
    // CLOUD-723, the same parser change read in reverse. `verdict-not-discarded`
    // and every `pipeline` row decide over these segments, so a body carrying a
    // `;` used to split the list and turn a paragraph into its own command —
    // measured twice in one session, both times on the command that was writing
    // this rule down.
    //
    // The body here names `git commit` with no message source AND carries a list
    // separator, so it would fire the first predicate in this file if it were
    // read as shell at all.
    let root = fixture("heredoc-prose");
    allowed(
        &root,
        "cat > notes.md <<'EOF'\nfirst; then git commit && nohup something &\nEOF\n",
    );
    // `<<<` is a here-STRING and opens no body. Reading it as one starts a skip
    // that never terminates, swallowing the rest of the command — so this
    // `git commit` would VANISH rather than be judged, and the suite would go
    // green on a gate that had stopped looking. The bash guard's awk carries the
    // same `!/<<</` guard for the same reason.
    denied(&root, "echo x <<< \"$msg\" && git commit");
}

// ---------------------------------------------------------------------------
// CLOUD-613: waiting, which needed CLOUD-1094's `run_in_background`.
// ---------------------------------------------------------------------------

#[test]
fn a_foreground_sleep_is_refused() {
    // The harness kills a foreground call at ~2 minutes, so a poll meant to be
    // patient FAILS instead — measured at exit 143 and 144 over a hung commit,
    // after which the container was reclaimed with the work uncommitted.
    let root = fixture("foreground-sleep");
    denied_background(&root, "sleep 90", false);
    // Judged per segment: the measured shape had the sleep in the middle.
    denied_background(&root, "cd /tmp; sleep 90; git log --oneline -1", false);
    // A HOST THAT SAID NOTHING is judged as foreground, which is the strict
    // direction and matches the bash's `[[ "$background" != true ]]`. Most hosts
    // send no such key, so this is the ordinary path rather than an edge.
    denied(&root, "sleep 90");
}

#[test]
fn a_backgrounded_bare_sleep_is_a_timer() {
    // CLOUD-821, measured 2026-08-21: 490 calls of `sleep 590; tail -6 land.log`
    // in one session against 523 of 524 backgrounded tasks re-invoking their
    // caller on exit. Two of the 490 changed a decision.
    denied_background(
        &fixture("background-timer"),
        "sleep 590; tail -6 /tmp/land.log",
        true,
    );
}

#[test]
fn a_backgrounded_wait_on_a_condition_is_allowed() {
    // THE ALLOW THIS WHOLE FAMILY IS SHAPED AROUND. It is the form both refusals
    // recommend, and denying it is the pure false positive that gets a guard
    // bypassed (CLOUD-199). The keyword is in a DIFFERENT segment from the
    // sleep, which is why the loop test is over the whole call.
    let root = fixture("conditional-wait");
    allowed_background(&root, "until [ -f /tmp/done ]; do sleep 1; done", true);
    allowed_background(
        &root,
        "while ! grep -q ready /tmp/log; do sleep 5; done",
        true,
    );
}

#[test]
fn a_loop_body_is_reached_and_the_exemption_decides_it() {
    // THE PAIR THAT MAKES THE EXEMPTION LOAD-BEARING (CLOUD-1112). One command,
    // twice, differing only in posture — so `waits_on_condition` is what decides
    // it, which is what CLOUD-613's acceptance always claimed.
    //
    // Reaching it needed a keyword look-through. `do sleep 1` resolves to the
    // program `do` without one, and `run-shape-guard.sh`'s `resolve()` still
    // does: the wrapper table covers `env`/`timeout`/`sudo`/… and no keyword. So
    // in the bash BOTH postures pass, for want of a resolvable sleep rather than
    // for any reason about waiting, and its comment that an element-scoped test
    // "would deny every correct wait" presumes an element it never reaches.
    // Porting that would have satisfied the acceptance vacuously.
    //
    // This is the one place the two authorities deliberately disagree while both
    // are live, and it is in the DENYING direction — no call gets a weaker
    // answer than it had.
    //
    // `for` is not a wait: it counts iterations, so it exits on the clock like
    // any timer. The guard calls that a deliberate non-catch "because narrowing
    // it costs a real parser"; it costs none now.
    let root = fixture("loop-body");
    denied_background(&root, "until [ -f /tmp/done ]; do sleep 1; done", false);
    allowed_background(&root, "until [ -f /tmp/done ]; do sleep 1; done", true);
    denied_background(&root, "for i in $(seq 60); do sleep 10; done", true);
}

#[test]
fn a_backgrounded_bare_sleep_raises_the_timer_and_not_the_foreground_rule() {
    // THE DISCRIMINATING CASE for `run-in-background`, and it has to read the
    // verdict rather than the decision: both rules deny, so an exit-code
    // assertion passes over a `foreground-sleep` that ignored the flag entirely.
    let (deny, text) = hook_background(
        &fixture("timer-not-foreground"),
        "sleep 590; tail -6 /tmp/land.log",
        true,
    );
    assert!(deny, "{text}");
    assert!(text.contains("timer run refused"), "{text}");
    assert!(
        !text.contains("sleep run blocked"),
        "the call IS backgrounded, so the foreground rule must not fire: {text}"
    );
}

#[test]
fn a_bare_sleep_beside_a_condition_loop_is_exempt() {
    // The one shape `waits_on_condition` actually decides, and therefore the
    // only case that can discriminate the `loop-is-not-an-exemption` mutation:
    // a resolvable bare `sleep` AND a loop keyword in the same backgrounded
    // call. Drop the conjunct and this denies.
    allowed_background(
        &fixture("mixed-wait"),
        "sleep 5; until [ -f /tmp/done ]; do :; done",
        true,
    );
}

#[test]
fn a_mention_of_sleep_is_not_a_call() {
    // The anchoring, without which `echo sleep 90` reads as a wait — and so does
    // every commit message and issue body describing this rule.
    let root = fixture("sleep-mention");
    allowed_background(&root, "echo sleep 90", false);
    allowed_background(&root, "git commit -m \"stop using sleep 90\"", false);
}

// carried: "THE MEASURED SHAPE: a token carrying an m is not a flag cluster" crates/batten/tests/it/run_shape.rs
#[test]
fn a_token_carrying_an_m_is_not_a_flag_cluster() {
    // CLOUD-885. The rule reads "one `-`, then LETTERS, at least one of which
    // selects a message source". Before `regex.match` it was spelled as
    // `contains` over the flag's tail, which cannot say "letters" — so `-x=mfoo`
    // carried an `m`, read as naming a message source, and a commit that still
    // blocks on $EDITOR went through.
    //
    // This is the discriminating case rather than another `-m`: the suite as it
    // stood covered `-m`, `-am`, `-F`, `-C` and the long forms, and every one of
    // them passes under BOTH spellings.
    let root = fixture("short-cluster");
    denied(&root, "git commit -x=mfoo");
    // The other direction, so the anchor is proven and not just the class: a
    // message flag must be reached from the START of the cluster. `-vm` is one.
    allowed(&root, "git commit -vm \"a message\"");
}

// ---------------------------------------------------------------------------
// The list, which is where a raw-string module goes silent.
// ---------------------------------------------------------------------------

// carried: "a compound list is judged per element, not by its first word" crates/batten/tests/it/run_shape.rs
#[test]
fn a_compound_list_is_judged_per_element() {
    // THE SHAPE A RAW-STRING MODULE MISSES. The vendored `no-force-push` preset
    // anchors on `words[0] == "git"` over the whole command, so `cd /tmp && git
    // push --force` reaches it as `cd` and is allowed — green tests, silent
    // gate. Every element is a command here.
    let root = fixture("list-element");
    denied(&root, "cd /tmp && git commit");
    allowed(&root, "git add -A && git commit -m x");
}

// carried: "a pipe stage is judged too" crates/batten/tests/it/run_shape.rs
#[test]
fn a_pipe_stage_is_judged_too() {
    denied(&fixture("pipe-stage"), "echo hi | git commit");
}

// carried: "a wrapper is looked through to the program it runs" crates/batten/tests/it/run_shape.rs
#[test]
fn a_wrapper_is_looked_through_to_the_program_it_runs() {
    let root = fixture("wrapper");
    denied(&root, "timeout 300 git commit");
    allowed(&root, "timeout 300 git commit -m x");
}

// ---------------------------------------------------------------------------
// Scrubbing: prose is not a call.
// ---------------------------------------------------------------------------

// carried: "a git commit inside a quoted span is prose, not a call" crates/batten/tests/it/run_shape.rs
#[test]
fn a_git_commit_inside_a_quoted_span_is_prose() {
    // This repository writes the shape down constantly — in commit messages, in
    // issue bodies, in this file. A module judging the raw string would refuse
    // its own documentation.
    let root = fixture("quoted-span");
    allowed(&root, "echo \"git commit\"");
    allowed(&root, "echo 'git commit'");
}

// carried: "a quoted span carrying a list separator is not a list" crates/batten/tests/it/run_shape.rs
#[test]
fn a_quoted_span_carrying_a_list_separator_is_not_a_list() {
    // THE CASE THAT DISCRIMINATES the quote scrub. A quoted mention with no
    // separator in it is already safe by the program anchoring above; what needs
    // the scrub is a message that carries a `;` or `&&`, because the list split
    // would otherwise turn the tail of a commit message into its own command.
    // Both quote characters, because they are two passes.
    let root = fixture("quoted-separator");
    allowed(&root, "echo \"step one; git commit -x\"");
    allowed(&root, "echo 'step one; git commit -x'");
}

// carried: "a git commit inside a heredoc body is prose, not a call" crates/batten/tests/it/run_shape.rs
#[test]
fn a_git_commit_inside_a_heredoc_body_is_prose() {
    allowed(
        &fixture("heredoc-body"),
        "cat > t.bats <<BATS\ngit commit\nBATS\n",
    );
}

// carried: "an unquoted mention does not resolve to git" crates/batten/tests/it/run_shape.rs
#[test]
fn an_unquoted_mention_does_not_resolve_to_git() {
    // The anchoring, without which `echo git commit` reads as a call.
    allowed(&fixture("unquoted-mention"), "echo git commit");
}

// carried: "a heredoc or redirect bound to this element is a message source" crates/batten/tests/it/run_shape.rs
#[test]
fn a_heredoc_or_redirect_bound_to_this_element_is_a_message_source() {
    let root = fixture("bound-source");
    allowed(&root, "git commit -F - <<'EOF'\nmsg\nEOF\n");
    allowed(&root, "git commit -F - < /tmp/msg.txt");
}

// ---------------------------------------------------------------------------
// The refusal itself.
// ---------------------------------------------------------------------------

// changed: "the refusal names its predicate and the remedy that cannot rebind" crates/batten/tests/it/run_shape.rs the remedy moved from the module's prose into the declared class, so the assertion is over the token and the route rather than over three substrings of a sentence (CLOUD-1050)
#[test]
fn the_refusal_names_its_predicate_its_class_and_the_route_out() {
    // A migrated gate keeps its remedy (CLOUD-437): a refusal that lost it in
    // translation is a regression no `policy test` would catch. What CHANGED is
    // where the remedy lives. It used to be three substrings of the module's own
    // prose — `-F <path>`, `pre-commit`, the predicate id — and a policy deny
    // carried `Fix::None`, so the module had to remember to write them.
    //
    // Now the class is declared: `Fix` comes off the class's first `command`
    // route, so "a refusal names a way out" holds by construction rather than by
    // each module's care, and `verdict::validate` refuses a class that declares
    // none. So this asserts the token, the gloss and the route — the three
    // things a reader acts on — rather than a sentence that may be reworded.
    let root = fixture("refusal-class");
    let (deny, text) = hook(&root, "git commit");
    assert!(deny, "the shape is still refused: {text}");
    assert!(
        text.contains("commit-names-no-message-source"),
        "the predicate id: {text}"
    );
    assert!(
        text.contains("commit write missing"),
        "the declared class: {text}"
    );
    // The route is one hop from the class on the line (CLOUD-1286), and this
    // still asserts it comes off the CLASS rather than out of the module's
    // prose — which is what the `changed:` arm above records.
    let explained = common::run(&root, &["policy", "explain", "commit write missing"]);
    assert_eq!(explained.status.code(), Some(0), "the class resolves");
    assert!(
        String::from_utf8_lossy(&explained.stdout).contains("git commit -F <path>"),
        "the route out, taken off the class rather than out of the module: {text}"
    );
}

// carried: "git -C <path> commit is a deliberate false negative, carried over" crates/batten/tests/it/run_shape.rs
#[test]
fn git_c_path_commit_is_a_deliberate_false_negative() {
    // The bash guard resolved `sub1` to the path and let it through, because a
    // guard with false positives gets bypassed (CLOUD-199) and this repository
    // commits from its own root. A migration that silently fixed it would be
    // changing the predicate, not moving it.
    allowed(&fixture("dash-c"), "git -C /some/path commit");
}

// carried: "a command with no git commit in it at all is untouched" crates/batten/tests/it/run_shape.rs
#[test]
fn a_command_with_no_git_commit_in_it_is_untouched() {
    let root = fixture("untouched");
    allowed(&root, "ls -la");
    allowed(&root, "hg commit");
}
