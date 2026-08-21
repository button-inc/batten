#!/usr/bin/env bats
# subject: mise-tasks/run-shape-guard
# The two shapes the engine cannot express, and what is NOT here is the point.
#
# This suite used to cover five predicates. The three that discard a verdict — a
# pager or filter pipe, a trailing list element, `nohup`/`&` — moved into
# `batten hook` with CLOUD-443, and their corpus moved with them to
# `crates/batten/tests/pipeline_shapes.rs`. Leaving copies here would be two
# suites asserting one predicate, which is how the two come to disagree.
#
# What remains is a foreground `sleep`, whose predicate is over the CALL's
# `run_in_background` rather than over the command string; a `git commit` that
# can never obtain a message, whose predicate is over heredoc binding; and a
# mediated `cargo` that is a weaker form of a task's own argv (CLOUD-822), whose
# predicate is over a file — `mise.toml`'s task bodies — that no rule kind on the
# mediated call may read, since none of them may spawn and a `shape` pattern is a
# literal.

setup() {
	GUARD="$BATS_TEST_DIRNAME/../mise-tasks/run-shape-guard"
	# THE DECODER IS STUBBED, through `payload-field`'s own documented seam, and
	# it is not a convenience — it is what makes this suite runnable under
	# `mutant` at all. That task copies TRACKED FILES ONLY into a temp tree and
	# runs the suite there, so there is no `target/` and `payload-field` resolves
	# no binary. The guard then fails OPEN on every call, so every DENY case is
	# red before any mutation and every mutation aimed at one reads as caught by a
	# case that could not have passed. Measured: four of this file's rows reported
	# `case-already-red`/`names-no-case` for exactly that reason, three of them
	# for their whole life. `tests/fanout-guard.bats` stubs it for the same reason
	# and says so in the same words.
	#
	# The two fields this guard reads, and nothing else: a stub answering more
	# would assert a vocabulary the real allowlist owns.
	cat >"$BATS_TEST_TMPDIR/batten" <<'STUB'
#!/usr/bin/env bash
set -uo pipefail
name=""
while [ $# -gt 0 ]; do
	case "$1" in
	--name) name="$2" && shift 2 ;;
	*) shift ;;
	esac
done
raw=$(cat)
case "$name" in
command) jq -r 'if (.tool_input.command | type) == "string" then .tool_input.command else empty end' <<<"$raw" 2>/dev/null ;;
run-in-background) jq -r 'if (.tool_input.run_in_background | type) == "boolean" then .tool_input.run_in_background else empty end' <<<"$raw" 2>/dev/null ;;
esac
exit 0
STUB
	chmod +x "$BATS_TEST_TMPDIR/batten"
	export BATTEN_BIN="$BATS_TEST_TMPDIR/batten"
	cd "$BATS_TEST_DIRNAME/.." || return 1
}

guard() {
	jq -nc --arg c "$1" '{tool_input: {command: $c}}' | "$GUARD"
}

denied() {
	[[ "$1" == *'"deny"'* ]]
}

# --- foreground-sleep ---------------------------------------------------------
#
# The fourth shape, and the one that destroys the session rather than a verdict.
# Measured 2026-08-12: a session polled a hung `git commit` with `sleep 90`,
# `sleep 100` and `sleep 180` in the foreground; the harness kills a foreground
# call at ~2 minutes, so the last two failed at exit 143 and 144, and the
# container was reclaimed with the fix uncommitted. AGENTS.md had forbidden this
# in prose for as long as it had forbidden the other three, and nothing enforced
# it — this guard named `sleep` only inside a comment's example.

bg_guard() { # the same call, marked run_in_background
	jq -nc --arg c "$1" '{tool_input: {command: $c, run_in_background: true}}' | "$GUARD"
}

@test "THE MEASURED SHAPE: a sleep in the middle of a compound is denied" {
	run guard 'cd /home/user/batten; sleep 90; git log --oneline -1'
	denied "$output"
	[[ "$output" == *"foreground"* ]]
}

@test "a leading sleep is denied too" {
	run guard 'sleep 45; echo done'
	denied "$output"
}

@test "a SHORT sleep is the same shape spending less" {
	# The predicate is the call's shape, not the duration: 2 seconds still waits
	# inside the call, and it is what the measured session reached for next.
	run guard 'pkill -f hk; sleep 2; git status --short'
	denied "$output"
}

@test "the denial names the remedy: background the wait, act on the exit" {
	run guard 'sleep 60'
	[[ "$output" == *"run_in_background"* ]]
	[[ "$output" == *"exit"* ]]
}

@test "a wrapper does not hide it" {
	run guard 'timeout 300 sleep 120'
	denied "$output"
}

@test "a BACKGROUND sleep is allowed — it is the recommended wait" {
	# `until <test>; do sleep 1; done` backgrounded is the documented form for
	# waiting on a condition, so denying it would be a pure false positive, and
	# a guard with false positives gets bypassed.
	run bg_guard 'until [ -f /tmp/done ]; do sleep 1; done'
	[[ "$output" != *'"deny"'* ]]
}

# --- the background TIMER (CLOUD-821) ----------------------------------------
#
# The rows above pin the carve-out; these pin its edge. Until CLOUD-821 the
# `run_in_background` flag skipped this family outright, and what it let through
# was not a wait at all — a wall clock standing in for an event, in a session
# that already had the event. The guard's own remedy sentence had said so since
# it shipped: what makes a wait correct is a command that EXITS when the
# condition holds.

@test "THE MEASURED SHAPE: a backgrounded sleep-then-read is a timer, not a wait" {
	# Measured 2026-08-21, landing CLOUD-776: 490 of these in one session, 2 of
	# which changed a decision, while the completion notification they duplicated
	# fired 523 times unread.
	run bg_guard 'sleep 590; tail -6 /tmp/land.log'
	denied "$output"
	[[ "$output" == *"TIMER"* ]]
}

@test "a bare backgrounded sleep waits for nothing and reports nothing" {
	run bg_guard 'sleep 300'
	denied "$output"
}

@test "the timer denial names both affordances: the exit notification and alive" {
	# A refusal that does not say what to do instead buys a differently-spelled
	# poll. `mise run alive` answers "is it still going" in one push-based call;
	# the notification answers "has it finished" with no call at all.
	run bg_guard 'sleep 120; cat /tmp/x.log'
	[[ "$output" == *"mise run alive"* ]]
	[[ "$output" == *"exit notification"* ]]
}

@test "a backgrounded WHILE loop is a wait and stays allowed" {
	# `while`, not just `until`: both are condition-driven and both exit when the
	# condition says so. Only the keyword differs.
	run bg_guard 'while ! mise run alive | grep -q land; do sleep 5; done'
	[[ "$output" != *'"deny"'* ]]
}

@test "a backgrounded wait on state nothing notifies you about stays allowed" {
	# The case the carve-out exists for: a remote queue is not a task this
	# session started, so no completion notification covers it.
	run bg_guard 'until curl -sf https://example.invalid/ready; do sleep 5; done'
	[[ "$output" != *'"deny"'* ]]
}

@test "a backgrounded long-running command with no sleep is untouched" {
	# The overwhelmingly common background call. If this reddened, the rule would
	# be bypassed within a session and would then be worse than nothing.
	run bg_guard 'mise run verify'
	[[ "$output" != *'"deny"'* ]]
}

@test "a foreground call with no sleep is still none of this rule's business" {
	run guard 'git rebase origin/main'
	[[ "$output" != *'"deny"'* ]]
}

@test "a backgrounded sleep described in prose is prose" {
	# The scrubbing the other rules depend on, asserted on this one: a commit
	# message documenting the refused shape must not be refused as one.
	run bg_guard 'git commit -m "refuse a backgrounded sleep 590 that polls a log"'
	[[ "$output" != *'"deny"'* ]]
}

@test "a sleep written INSIDE a quoted span or a heredoc is not a call" {
	# A commit message or a task body describing the shape is prose, not the
	# shape — the same scrubbing the other three rules depend on.
	run guard 'git commit -m "never use a foreground sleep 90 to poll"'
	[[ "$output" != *'"deny"'* ]]
	run guard "$(printf 'cat > t.bats <<%s\nrun sleep 5\n%s\n' BATS BATS)"
	[[ "$output" != *'"deny"'* ]]
}

@test "a bare command with no sleep and no verdict is still none of this guard's business" {
	run guard 'ls -la'
	[[ "$output" != *'"deny"'* ]]
}

# --- unsatisfiable-commit (CLOUD-488) ----------------------------------------
#
# `git commit` is not verdict-bearing, so these rows also pin that the rule runs
# BEFORE the `last_verdict` early exit — a bare `git commit` reaches it at all.

@test "THE MEASURED SHAPE: the heredoc binds to a later element, so git gets nothing" {
	# `git add -A && git commit -F - … && mise run land … <<EOF` — the opener is
	# in the command string and absent from the element that needed it. ~4
	# minutes of gate on a commit git was always going to refuse.
	run guard "$(printf 'git add -A && git commit -F - >log 2>&1 && mise run land >l2 2>&1 <<%s\nmsg\n%s\n' "'EOF'" EOF)"
	denied "$output"
}

@test "a bare -F - with no redirect anywhere is denied" {
	run guard 'git commit -F -'
	denied "$output"
	run guard 'git commit --file=- >log'
	denied "$output"
}

# The `no message source at all` case is gone with its subject: that family is
# `policy/run-shape.rego` now, and its negative controls are in
# `tests/run-shape.bats`, which drives the compiled binary rather than this
# file's stub. The rows below still assert this guard does not OVER-fire on the
# same shapes, which is a property of what remains.

@test "the denial names -F <path>, which is the form that cannot rebind" {
	# A message that only says "this is wrong" reproduces the error: the author
	# writes another heredoc. The remedy has to be the heredoc-free form.
	run guard 'git commit -F -'
	[[ "$output" == *'-F <path>'* ]]
	[[ "$output" == *"pre-commit"* ]]
}

@test "every form that CAN obtain a message stays allowed" {
	local c
	for c in 'git commit -F /tmp/msg.txt' \
		'git commit -m "a message"' \
		'git commit -am "a message"' \
		'git commit --amend --no-edit' \
		'git commit --fixup HEAD' \
		'git commit -C HEAD@{1}'; do
		run guard "$c"
		[[ "$output" != *'"deny"'* ]]
	done
}

@test "a heredoc that genuinely binds to this element is a message source" {
	# The whole point of judging per element: the same `-F -` is correct here.
	run guard "$(printf 'git commit -F - <<%s\nmsg\n%s\n' "'EOF'" EOF)"
	[[ "$output" != *'"deny"'* ]]
}

@test "a file or a here-string redirected into it is a message source too" {
	run guard 'git commit -F - < /tmp/msg.txt'
	[[ "$output" != *'"deny"'* ]]
	run guard 'git commit -F - <<< "$msg"'
	[[ "$output" != *'"deny"'* ]]
}

@test "a git commit written INSIDE a quoted span or a heredoc is not a call" {
	# Same scrubbing every other rule depends on — and this file's own commit
	# message is the most likely place to write the shape down.
	run guard 'echo "git commit -F - hangs the gate"'
	[[ "$output" != *'"deny"'* ]]
	run guard "$(printf 'cat > t.bats <<%s\nrun git commit -F -\n%s\n' BATS BATS)"
	[[ "$output" != *'"deny"'* ]]
}

# --- cargo-substitutes-for-a-task (CLOUD-822) --------------------------------
#
# `no-bare-cargo` gates the toolchain and not the strictness, and its own refusal
# text hands out the gap. Measured 2026-08-21: `mise exec -- cargo clippy -p
# batten --all-targets` reported clean over 10 `expect_used` errors, and that
# exit 0 was then quoted as verification in a commit message and a summary.
#
# The semantic rows below run against a FIXTURE `mise.toml`, because what they
# assert is the DERIVATION — which shapes are weaker, which are merely different
# — and pinning that to whichever tasks this repo happens to declare today would
# make them a test of `mise.toml` rather than of the rule. The two rows that do
# use the real tree are the ones CLOUD-822 measured, and they should track it.

# A copy of the guard beside a fixture `mise.toml`, which is where it resolves
# the task table from. `payload-field` travels with it: the guard reads every
# payload through that helper rather than `jq`, because a by-path registration
# does not get mise's env (`hook-pin-check`).
fixture_guard() { # fixture_guard <mise.toml body>
	FIXTURE="$BATS_TEST_TMPDIR/tree"
	mkdir -p "$FIXTURE/mise-tasks"
	cp "$BATS_TEST_DIRNAME/../mise-tasks/run-shape-guard" \
		"$BATS_TEST_DIRNAME/../mise-tasks/payload-field" "$FIXTURE/mise-tasks/"
	printf '%s\n' "$1" >"$FIXTURE/mise.toml"
}

# The same stubbed decoder `setup` exports, which the guard copy beside the
# fixture inherits: `payload-field` resolves the binary from its OWN location, so
# a copy anywhere but the real checkout finds no `target/` — under `mutant` there
# is none to find at all. These rows vary the task table and nothing else.
fguard() { # fguard <command>
	jq -nc --arg c "$1" '{tool_input: {command: $c}}' |
		"$FIXTURE/mise-tasks/run-shape-guard"
}

TASKS='[tasks."lint:clippy"]
description = "Clippy with warnings denied"
run = """
if ! cargo clippy --all-targets --all-features -- -D warnings; then exit 1; fi
"""

[tasks.batten-check]
run = """
if ! cargo run --quiet -p batten -- provision apply; then exit 1; fi
"""

[tasks.deny]
run = "cargo deny check"'

@test "THE MEASURED SHAPE: a weaker clippy through the sanctioned escape is refused" {
	run guard 'mise exec -- cargo clippy -p batten --all-targets'
	denied "$output"
	[[ "$output" == *"lint:clippy"* ]]
	# Pointer-only: the subcommand and the task names, never the tree or a diff.
	[[ "$output" == *'`cargo clippy`'* ]]
}

@test "the task itself is allowed — this rule is about substitution, not about cargo" {
	run guard 'mise run lint:clippy'
	[[ "$output" != *'"deny"'* ]]
}

@test "a subcommand no task wraps is a genuine one-off and is untouched" {
	run guard 'mise exec -- cargo tree'
	[[ "$output" != *'"deny"'* ]]
}

@test "a BARE cargo is no-bare-cargo's, so the two never report one command" {
	# The engine's row already denies it, on the toolchain axis. Two rules
	# reporting one command is the drift this file's header refuses, and
	# `RESOLVED_VIA` is what tells the mediated form from the bare one.
	run guard 'cargo clippy --all-targets'
	[[ "$output" != *'"deny"'* ]]
}

@test "an EQUAL argv is not weaker, so spelling a task's own line out is allowed" {
	fixture_guard "$TASKS"
	run fguard 'mise exec -- cargo deny check'
	[[ "$output" != *'"deny"'* ]]
}

@test "a narrower argv IS weaker, and the task it is weaker than is named" {
	fixture_guard "$TASKS"
	run fguard 'mise exec -- cargo clippy -p batten --all-targets'
	denied "$output"
	[[ "$output" == *"lint:clippy"* ]]
}

@test "a DIFFERENT program argv is a different command, not a weaker one" {
	# The `--` separator means two things. After `cargo clippy --` come more lint
	# flags; after `cargo run --` comes another program's argv. Without that
	# split, `cargo run -p batten -- check` reads as a weaker `cargo run --quiet
	# -p batten -- provision apply`, and denying it is the pure false positive
	# CLOUD-199 measured getting a guard switched off.
	fixture_guard "$TASKS"
	run fguard 'mise exec -- cargo run -p batten -- check'
	[[ "$output" != *'"deny"'* ]]
}

@test "the SAME program argv, missing a flag, is a substitution" {
	# The complement of the row above: same argv past `--`, and the task carries
	# `--quiet` this invocation omits.
	fixture_guard "$TASKS"
	run fguard 'mise exec -- cargo run -p batten -- provision apply'
	denied "$output"
	[[ "$output" == *"batten-check"* ]]
}

@test "post-dash-dash LINT flags count as strictness, which is the whole measurement" {
	# `-D warnings` is what `mise run lint:clippy` adds and the escape omits. If
	# the tail past `--` were always read as a program argv, the one flag this
	# row exists for would be invisible.
	fixture_guard "$TASKS"
	run fguard 'mise exec -- cargo clippy --all-targets --all-features'
	denied "$output"
	[[ "$output" == *"lint:clippy"* ]]
}

@test "THE MAPPING IS DERIVED: retitle the task's cargo line and the verdict follows" {
	# §1's whole point. `mise.toml` already holds the real command lines, so
	# nothing here restates them — and a task that stops wrapping a subcommand
	# stops the refusal with no edit to the guard. Measured live while this
	# landed: `test:cargo` moved from `cargo test` to `cargo nextest run` on
	# main, and `cargo test` became a one-off the same instant.
	fixture_guard '[tasks."test:cargo"]
run = "cargo nextest run --workspace"'
	run fguard 'mise exec -- cargo test -p batten'
	[[ "$output" != *'"deny"'* ]]
	run fguard 'mise exec -- cargo nextest run -p batten'
	denied "$output"
	[[ "$output" == *"test:cargo"* ]]
}

@test "a description naming a command is prose, never a declaration" {
	# Only `run` bodies are read. Reading descriptions registered `test:bats` as
	# wrapping `cargo test` while this was being written — a task whose body runs
	# no cargo at all, so the refusal named a task that could not have helped.
	fixture_guard '[tasks."test:bats"]
description = "Run the shell suite — cargo test for the mise-tasks/ programs"
run = "./tests/bats/bin/bats tests/*.bats"'
	run fguard 'mise exec -- cargo test -p batten'
	[[ "$output" != *'"deny"'* ]]
}

@test "the refusal names its bypass, since one that cannot be reached is not a remedy" {
	run guard 'mise exec -- cargo clippy -p batten'
	denied "$output"
	[[ "$output" == *"BATTEN_RUN_SHAPE_BYPASS=1"* ]]
	[[ "$output" == *"mise run"* ]]
}

@test "the bypass actually clears it" {
	run bash -c "jq -nc --arg c 'mise exec -- cargo clippy -p batten' '{tool_input: {command: \$c}}' | BATTEN_RUN_SHAPE_BYPASS=1 '$GUARD'"
	[[ "$output" != *'"deny"'* ]]
}
