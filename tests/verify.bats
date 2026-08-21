#!/usr/bin/env bats
# subject: mise.toml
# CLOUD-407. `verify`'s exit code is a two-valued question with one narrow
# answer: 2 means "main moved under this branch, lap and try again", and every
# other failure means "stop, something about this tree is wrong". `land` is
# hard-wired to that reading (`mise-tasks/land.sh`, the lap-on-2 arm), so a second
# way to produce a 2 is not a cosmetic defect — it is `land` lapping to its
# backstop over a real refusal it was built to stop on.
#
# The escape route was `depends`. mise runs a dependency before the body and
# propagates its code VERBATIM, so `batten check`'s policy verdict of 2 (through
# `hooks` -> `ci`) and `tree-clean`/`semver`'s "could not look" 2 all left
# `verify` without ever passing the body's guards. Measured on PR #322: eight
# laps, ~13 minutes, three `path:line` pointers nobody surfaced.
#
# The fix is structural rather than defensive — `verify` carries no `depends` at
# all, and everything that can fail for a content reason reaches it through one
# guarded call to `verify:gated` that flattens whatever code it carried. So this
# suite asserts BOTH halves: the structure that removes the escape route, and the
# behaviour over a stubbed decision table.
#
# tests/task-fail-closed.bats is the sibling: it holds the fail-closed shape of
# both bodies. This one holds the exit-code contract.

setup() {
	cd "$BATS_TEST_DIRNAME/.." || return 1
	MAPPER=$(awk '/^\[tasks\.verify\]/{f=1} f&&/^run = .{3}$/{c=1;next} c&&/^'"'''"'$/{exit} c' mise.toml)
	GATED=$(awk '/^\[tasks\."verify:gated"\]/{f=1} f&&/^run = .{3}$/{c=1;next} c&&/^'"'''"'$/{exit} c' mise.toml)

	STUB="$BATS_TEST_TMPDIR/bin"
	mkdir -p "$STUB"
	BODY_FILE="$BATS_TEST_TMPDIR/verify-body"
	printf '%s\n' "$MAPPER" >"$BODY_FILE"

	FAKE_BRANCH="work"
	FAKE_GIT_DIR="$BATS_TEST_TMPDIR/gitdir"
	mkdir -p "$FAKE_GIT_DIR/batten-receipts"
	claim_receipt
}

# The stub stands in for the whole task runner. Each task's exit code is read
# from a file the case writes, so a case names only the codes it cares about and
# everything else answers 0 — the same shape `tests/land.bats` uses, for the same
# reason: the subject here is the mapping, not the tasks being mapped.
stub_mise() {
	cat >"$STUB/mise" <<-'EOF'
		#!/usr/bin/env bash
		if [ "$1" = "run" ]; then
			echo "$2" >>"$MISE_STUB_CALLS"
			rc_file="$MISE_STUB_DIR/rc.$2"
			[ -f "$rc_file" ] && exit "$(cat "$rc_file")"
		fi
		exit 0
	EOF
	chmod +x "$STUB/mise"
}

# `git` answers the three questions the mapper asks: which branch this is, where
# the git dir lives, and (inside `verify:gated`, which this suite does not run)
# a couple of rev-parses. Stubbed so no case can reach the real repository —
# without it the claim-receipt check below would read the DEVELOPER's branch and
# the developer's receipt, and the suite would pass or fail on the state of
# whatever clone it happened to run in.
stub_git() {
	cat >"$STUB/git" <<-EOF
		#!/usr/bin/env bash
		case "\$1 \$2" in
		  "symbolic-ref --quiet") echo "$FAKE_BRANCH" ;;
		  "rev-parse --git-dir")  echo "$FAKE_GIT_DIR" ;;
		  *) echo 0000000 ;;
		esac
	EOF
	chmod +x "$STUB/git"
}

# CLOUD-741: the receipt question is no longer a file test in this body — it is
# `batten receipt status --key branch`, so the ENGINE decides and this suite
# stubs its answer. That is the point of the change: a presence test could not
# tell `missing` from `stale-main`, so a branch restarted out from under its
# receipt passed `verify` while the hook refused the same tree.
#
# `cargo` rather than a `batten` binary, because the body invokes it the way
# every other gate does — `cargo run --quiet -p batten -- …` — so the gate judges
# the working tree's engine rather than whatever was built last.
stub_cargo() {
	cat >"$STUB/cargo" <<-'EOF'
		#!/usr/bin/env bash
		# cargo run --quiet -p batten -- receipt status <check> --key branch
		check="${8:-}"
		answer="$MISE_STUB_DIR/receipt.$check"
		if [ -f "$answer" ]; then
			read -r rc verdict <"$answer"
			echo "$check work $verdict"
			exit "$rc"
		fi
		echo "$check work missing"
		exit 2
	EOF
	chmod +x "$STUB/cargo"
}

# What `receipt status` answers for one check: an exit code and the verdict word
# its pointer line carries. Valid by default for `claim`, because every case
# below is about the EXIT-CODE contract and would otherwise stop at a refusal
# that is not its subject.
receipt_says() { printf '%s %s\n' "$2" "$3" >"$BATS_TEST_TMPDIR/receipt.$1"; }
claim_receipt() { receipt_says claim 0 valid; }
no_claim_receipt() { receipt_says claim 2 missing; }
# The state a presence test could not see, and the reason this issue exists: a
# receipt EXISTS and is void, so the remedy is re-claim rather than claim.
stale_claim_receipt() { receipt_says claim 2 stale-main; }
# CLOUD-693's second kind, minted by `mise run bot-issue receipt` on a bot branch.
bot_receipt() { receipt_says bot 0 valid; }
no_bot_receipt() { receipt_says bot 2 missing; }

task_exits() { printf '%s\n' "$2" >"$BATS_TEST_TMPDIR/rc.$1"; }

run_verify() {
	stub_mise
	stub_git
	stub_cargo
	MISE_STUB_DIR="$BATS_TEST_TMPDIR" \
		MISE_STUB_CALLS="$BATS_TEST_TMPDIR/calls" \
		PATH="$STUB:$PATH" \
		run bash "$BODY_FILE"
}

# `grep -c` prints 0 AND exits 1 when it matches nothing, so the obvious
# `grep -c … || echo 0` emits TWO lines and every comparison against it is a
# syntax error rather than a failure. Capture, then default.
called() {
	local seen
	seen=$(grep -c "^$1\$" "$BATS_TEST_TMPDIR/calls" 2>/dev/null) || seen=0
	printf '%s\n' "$seen"
}

@test "the mapper body was found at all — this suite is not passing vacuously" {
	[ -n "$MAPPER" ]
	[[ "$MAPPER" == *"linear-check"* ]]
	[[ "$MAPPER" == *"verify:gated"* ]]
}

@test "verify declares no depends, which is the escape route CLOUD-407 closed" {
	# The load-bearing structural assertion. A `depends` on `verify` would let a
	# dependency's exit code reach a caller without passing a single guard in the
	# body below, which is the entire defect — and it would do so silently, since
	# nothing in the body would have to change for it to happen.
	local depends
	depends=$(awk '/^\[tasks\.verify\]/{f=1} f&&/^\[tasks\."verify:gated"\]/{exit} f&&/^depends = /{print}' mise.toml)
	[ -z "$depends" ] || {
		echo "verify grew a depends, so a dependency's exit code escapes unmapped: $depends"
		false
	}
}

@test "verify:gated carries the depends verify gave up" {
	local depends
	depends=$(awk '/^\[tasks\."verify:gated"\]/{f=1} f&&/^depends = /{print; exit}' mise.toml)
	[[ "$depends" == *"tree-clean"* ]]
	[[ "$depends" == *"ci"* ]]
	[[ "$depends" == *"cross-check"* ]]
}

@test "the mapper mints exactly one exit 2, and it is the behind-verdict arm" {
	# A count, not a search. Two `exit 2`s would each be defensible in isolation
	# and together would restore the collision, so the assertion has to be that
	# there is one — the same reason `tests/land.bats` counts its stops.
	local twos
	twos=$(grep -c '^[[:space:]]*exit 2[[:space:]]*$' <<<"$MAPPER")
	[ "$twos" -eq 1 ]
	# And it is reachable only from linear-check's code, never from anything else.
	[[ "$MAPPER" == *'if [ "$linear_rc" = 2 ]; then'* ]]
}

@test "verify:gated mints no exit 2 at all — a content failure is a stop" {
	local twos
	twos=$(grep -c '^[[:space:]]*exit 2[[:space:]]*$' <<<"$GATED" || true)
	[ "$twos" -eq 0 ]
}

# --- the decision table ------------------------------------------------------

@test "a clean run exits 0 and reaches the gate set" {
	run_verify
	[ "$status" -eq 0 ]
	[ "$(called linear-check)" -eq 1 ]
	[ "$(called verify:gated)" -eq 1 ]
}

@test "linear-check's behind-verdict is the one thing that exits 2" {
	task_exits linear-check 2
	run_verify
	[ "$status" -eq 2 ]
	[[ "$output" == *"main moved under this branch"* ]]
	# And it stops BEFORE spending the gate set, which is the economy the
	# reordering bought: a branch that is behind will lap regardless.
	[ "$(called verify:gated)" -eq 0 ]
}

@test "linear-check's environment refusal is a stop, not a lap" {
	task_exits linear-check 1
	run_verify
	[ "$status" -eq 1 ]
	[ "$(called verify:gated)" -eq 0 ]
}

@test "A POLICY VERDICT REACHING verify IS A STOP: gated's 2 leaves as 1" {
	# The headline case. `batten check` exits 2 for a violation and reaches
	# `verify` through `hooks` -> `ci` -> `verify:gated`'s depends. Before the
	# split that 2 arrived at `land` indistinguishable from "main moved", and
	# `land` lapped on it eight times over a tree that was genuinely refused.
	task_exits verify:gated 2
	run_verify
	[ "$status" -eq 1 ]
	[[ "$output" == *"this is not a rebase"* ]]
}

@test "a code outside the table is flattened too, not passed through" {
	# Measured in the wild: a clippy failure inside `ci` made `mise run verify`
	# exit 101. Whatever a dependency carries, it is a content failure and it
	# leaves as 1 — the mapping is over the CONDITION, never over the code.
	for code in 3 101 137 255; do
		rm -f "$BATS_TEST_TMPDIR/calls"
		task_exits verify:gated "$code"
		run_verify
		[ "$status" -eq 1 ] || {
			echo "verify:gated exiting $code left verify as $status, not 1"
			false
		}
	done
}

@test "the two conditions are told apart by the code, never by parsing prose" {
	# CLOUD-407's third acceptance clause. A fix that read `land`'s decision out
	# of a log line would pass every case above and still be the defect, so the
	# absence of that shape is asserted rather than assumed.
	[[ "$MAPPER" != *"grep"* ]]
	[[ "$MAPPER" != *"awk"* ]]
}

# --- the claim receipt (CLOUD-431) -------------------------------------------
#
# `batten hook`'s claim row is the fast feedback for this and it is a HOOK, which can be
# unloaded — today it is not even registered in `.claude/settings.json`. So the
# load-bearing half sits here, in the one task every landing path runs, and these
# cases are what make that a guarantee rather than an intention.

@test "a branch with no claim receipt cannot pass verify" {
	no_claim_receipt
	run_verify
	[ "$status" -eq 1 ]
	[[ "$output" == *"no VALID claim receipt"* ]]
	# It stops BEFORE spending anything: the question "should this branch exist"
	# is cheaper than every question below it, and different in kind.
	[ "$(called linear-check)" -eq 0 ]
	[ "$(called verify:gated)" -eq 0 ]
}

@test "the refusal names the remedy rather than only the rule" {
	no_claim_receipt
	run_verify
	[[ "$output" == *"claim-check"* ]]
	[[ "$output" == *"bot-issue receipt"* ]]
	[[ "$output" == *"No receipt written."* ]]
}

@test "A BOT RECEIPT SATISFIES IT TOO, and it is a SECOND kind rather than a wider one" {
	# CLOUD-693. Nothing on a bot branch can honestly claim "an agent read a
	# refined issue in a session that postdates the refinement" — there was no
	# session. So the bot lane mints its own receipt attesting what IS true there,
	# and `verify` accepts either. Widening the agent receipt to cover bots would
	# have made it mean less on every branch, which is what CLOUD-431 exists to
	# prevent.
	no_claim_receipt
	bot_receipt CLOUD-999
	run_verify
	[ "$status" -eq 0 ]
	[[ "$output" != *"no VALID claim receipt"* ]]
}

@test "neither receipt is still a refusal — the pair is an OR, not an escape hatch" {
	no_claim_receipt
	no_bot_receipt
	run_verify
	[ "$status" -eq 1 ]
	[[ "$output" == *"no VALID claim receipt"* ]]
}

@test "A STALE RECEIPT IS REFUSED — the row a presence test could not hold" {
	# CLOUD-741, and the reason this stopped being `[ -f "$claim_receipt" ]`.
	#
	# `git checkout -B <name> origin/main` after a PR merges is the documented
	# remedy, and it repoints the name at a new base while the receipt, keyed by
	# the name, survives on disk. The engine has called that `stale-main` since
	# CLOUD-516 — but the file was still THERE, so `verify` passed it, and a
	# branch could be verified, readied and landed carrying a claim for an
	# unrelated issue. Measured on CLOUD-516: a receipt naming CLOUD-230
	# authorised every edit behind four unrelated stories.
	stale_claim_receipt
	no_bot_receipt
	run_verify
	[ "$status" -eq 1 ]
	[[ "$output" == *"no VALID claim receipt"* ]]
	# It still stops before spending anything.
	[ "$(called linear-check)" -eq 0 ]
	[ "$(called verify:gated)" -eq 0 ]
}

@test "the refusal tells a re-claim apart from a first claim" {
	# The two states carry different remedies — mint one, versus yours went void
	# and must be re-made — and a refusal that named only one would send half its
	# readers to the wrong fix. The pointer line is what distinguishes them, so
	# it is echoed rather than swallowed.
	stale_claim_receipt
	no_bot_receipt
	run_verify
	[[ "$output" == *"stale-main"* ]]
	[[ "$output" == *"re-claimed"* ]]
}

@test "a valid receipt that is merely present is not enough — the verdict decides" {
	# The inverse assertion, and the one that shows the body reads the ENGINE
	# rather than the filesystem: nothing here writes a receipt file at all, and
	# `verify` passes purely on the stubbed verdict.
	receipt_says claim 0 valid
	rm -f "$FAKE_GIT_DIR/batten-receipts/claim.$FAKE_BRANCH"
	run_verify
	[ "$status" -eq 0 ]
	[[ "$output" != *"no VALID claim receipt"* ]]
}

@test "a bot receipt is judged by the same predicate, not merely counted" {
	# CLOUD-693's lane records a `base` line too, so it gets CLOUD-516's staleness
	# rule here rather than needing its own — a restarted bot branch is refused
	# exactly as an agent branch is.
	no_claim_receipt
	receipt_says bot 2 stale-main
	run_verify
	[ "$status" -eq 1 ]
	[[ "$output" == *"no VALID claim receipt"* ]]
}

@test "a detached HEAD is exempt, because a rebase detaches" {
	# The same carve-out the engine's claim row makes deliberately. Refusing here would
	# fail every lap of `land`, which detaches to rebase — a state that is not a
	# defect and that no claim receipt could describe.
	cat >"$STUB/git" <<-EOF
		#!/usr/bin/env bash
		case "\$1 \$2" in
		  "symbolic-ref --quiet") exit 1 ;;
		  "rev-parse --git-dir")  echo "$FAKE_GIT_DIR" ;;
		  *) echo 0000000 ;;
		esac
	EOF
	chmod +x "$STUB/git"
	no_claim_receipt
	# `stub_mise` and `stub_cargo` explicitly, because this case cannot use
	# `run_verify` — that helper reinstalls the git stub and would undo the
	# detached HEAD.
	stub_mise
	stub_cargo
	MISE_STUB_DIR="$BATS_TEST_TMPDIR" \
		MISE_STUB_CALLS="$BATS_TEST_TMPDIR/calls" \
		PATH="$STUB:$PATH" \
		run bash "$BODY_FILE"
	[ "$status" -eq 0 ]
	[[ "$output" != *"no VALID claim receipt"* ]]
}

@test "RECLAIM RUNS, and runs before the claim receipt is even looked at" {
	# CLOUD-766. `target/deps` grows ~1.5-2 GB per lap and cargo reclaims nothing,
	# so a multi-lap session runs the volume out — measured twice in one session.
	# This is the only guard in the body whose failure the others cannot survive:
	# with no disk, every question below answers "failed" for a reason that has
	# nothing to do with the tree.
	run_verify
	[ "$status" -eq 0 ]
	[ "$(called target-prune)" -eq 1 ]
}

@test "a volume that cannot be recovered is a STOP, not a lap" {
	# `land` reads exit 2 as "main moved, try again", and nothing about a full
	# volume improves by rebasing. Exit 1 is what stops it.
	task_exits target-prune 1
	run_verify
	[ "$status" -eq 1 ]
	[[ "$output" == *"not enough disk"* ]]
	# And it stops before spending anything below it.
	[ "$(called linear-check)" -eq 0 ]
	[ "$(called verify:gated)" -eq 0 ]
}

@test "the reclaim precedes the claim receipt in the mapper" {
	# Ordering asserted textually as well as behaviourally: a later reader moving
	# it below the receipt check would still pass the rows above, and would make
	# the cheapest recoverable failure in the body answerable only after a
	# question that cannot be answered without disk.
	local prune_line claim_line
	prune_line=$(grep -n 'mise run target-prune' <<<"$MAPPER" | head -1 | cut -d: -f1)
	claim_line=$(grep -n 'receipt status claim' <<<"$MAPPER" | head -1 | cut -d: -f1)
	[ -n "$prune_line" ]
	[ -n "$claim_line" ]
	[ "$prune_line" -lt "$claim_line" ]
}

@test "the receipt check precedes every other question in the mapper" {
	# Ordering asserted textually as well as behaviourally: a later reader moving
	# it below `linear-check` would still pass the cases above (both refuse), and
	# would quietly start paying for a fetch to answer a question that does not
	# need one.
	# Matched on the CALLS, not on prose: the body's opening comment discusses
	# linear-check several lines above any code, so grepping the bare name would
	# compare a comment against a command and always fail.
	local claim_line linear_line
	claim_line=$(grep -n 'receipt status claim' <<<"$MAPPER" | head -1 | cut -d: -f1)
	linear_line=$(grep -n '^mise run linear-check' <<<"$MAPPER" | head -1 | cut -d: -f1)
	[ -n "$claim_line" ]
	[ "$claim_line" -lt "$linear_line" ]
}
