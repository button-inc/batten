#!/usr/bin/env bash
#MISE description="Evidence: a migrated gate answers the way the bash it replaced did, per carried case (CLOUD-909)"
#
# `batten policy test` gives a migrated module somewhere to put its tests. It
# cannot say the module answers the way the bash did — only that the module
# agrees with itself, and CLOUD-845 measured the sharp end of that: a module
# copied from `policy.rs`'s own doc passed its suite green and gated nothing,
# because `with input as` lets an author fabricate the shape the engine cannot
# produce. 845 closed that class. It did not establish FIDELITY.
#
# Fidelity is a doc comment today. That is not a criticism of the one port that
# exists — its header is the best evidence available — it is an argument that the
# evidence has to be produced by a command, because the next twenty gates will be
# authored in one PR and will not get twenty careful humans.
#
# ─── THE HAZARD IS NOT THE OBVIOUS ONE ──────────────────────────────────────
#
# The obvious harness is "run both, assert the same exit code", and it is WRONG
# here. `crates/batten/tests/contract_drift.rs`'s own header records why: the
# shell tasks spell `1 = violation` and batten's contract is the inverse
# (house-style §7). A carried-over `assert_equal $status 1` asserts "unreadable
# input" while meaning "violation" — and it PASSES. So an equality assertion
# would demand the migration preserve the very contract it exists to fix, and the
# naive carry-over satisfies it.
#
# Hence a DECLARED TRANSLATION, never a raw equality, and hence the translation
# being refused when it is spelled as an identity: `1=1` is the naive carry-over
# written down, and this task exists to catch it rather than to run under it.
#
# ─── THE FIXTURE COMES FROM THE THING BEING DELETED ─────────────────────────
#
# Not from a fixture written for this harness. A fixture authored here would be
# the migration's author asserting their own reading of what the old gate did,
# which is the claim under test. So the dying suite is RUN, at the base rev,
# against the base rev's program, with a shim on PATH in the program's place. Per
# invocation the shim copies the fixture directory aside, runs the real program,
# and records its stdout and exit status. `$BATS_TEST_DESCRIPTION` is exported
# into a case's environment, so each capture knows which case produced it — which
# is what makes this per-CASE rather than per-suite, and what lets it consume
# CLOUD-908's `carried` arm rather than a second list.
#
# Then the head tree's row runs over a copy of each captured fixture, and the two
# answers are compared. Only CARRIED cases are replayed: a `subsumed` case is
# discharged by its named successor and a `changed` case is expected to diverge —
# and a divergence on a case NOT marked `changed` is the failure this reports.
#
# OFF THE LANDING PATH, the way `mutant` is. It spawns the base rev's bash in a
# fixture directory, so it is `effect`, and it is evidence for a migration rather
# than a property of a commit. Not in the `hk` gate, not in `verify`, nothing
# added to the hot path — the same split `lock-complete` and `lock-currency` were
# separated along.
#
# Output is pointer-only (non-negotiable rule 4), and here that is load-bearing
# rather than formal: this task holds two findings from two revs of a gate over
# tracked content, and printing them side by side would put a diff of that
# content on stdout. It reports THAT they differ, the case, and a `path:line`.
#
# Exit 0 every carried case replayed faithfully / 1 one did not / 2 could not look.
set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || exit 2

fail_input() {
	echo "::error:: replay: $*" >&2
	exit 2
}

report() { # report <case> <reason>
	echo "$1 $2"
}

# Resolved rather than assumed, so a fixture repository can borrow the real
# submodule instead of vendoring a second copy of the runner.
bats_bin="${BATTEN_REPLAY_BATS:-tests/bats/bin/bats}"
[[ -x "$bats_bin" ]] ||
	fail_input "no bats runner at $bats_bin; run \`mise run doctor\`. A harness that cannot run the dying suite cannot produce its fixtures."
bats_bin="$(cd "$(dirname "$bats_bin")" && pwd)/$(basename "$bats_bin")"

# The pointer extractor, resolved beside this task rather than assumed on PATH.
rule_pointers="$(dirname "$0")/replay-pointers.py"
[[ -x "$rule_pointers" ]] ||
	fail_input "no pointer extractor at $rule_pointers — this task cannot read the head side's answer without it, and a run that skipped the comparison would report a fidelity nobody checked."

binary=""
for candidate in \
	"${BATTEN_BIN:-}" \
	"target/release/batten" \
	"target/debug/batten"; do
	[[ -n "$candidate" && -x "$candidate" ]] || continue
	binary="$(cd "$(dirname "$candidate")" && pwd)/$(basename "$candidate")"
	break
done
[[ -n "$binary" ]] || binary="$(command -v batten || true)"
[[ -n "$binary" ]] ||
	fail_input "no batten binary to drive — run \`mise run build\`. The head side of a replay is the COMPILED binary, because a module's own suite is what this task exists not to trust."

# ─── the declaration ────────────────────────────────────────────────────────
#
# Beside the mapping (CLOUD-908's ledger), because the two describe one migration
# and a translation in a second file is a second authority that drifts. One
# `# replay:` row per retired suite, in a `declared_in` file:
#
#   replay: <suite> <base-rev> <program> <rule-id> <shell>=<batten>...
#
# The translation is per suite rather than global for the reason §1 gives: a gate
# that genuinely does not follow the shell convention can SAY so instead of being
# silently mistranslated. Every pair is stated; a code the old gate produced and
# the row does not name is a refusal, never a pass.
# INJECTABLE, for the reason `board-payloads` gives about its transcript root: a
# live tree carries exactly one set of these files, so a suite that could not vary
# them would ship as coverage while exercising a single row (CLOUD-418). The
# default is where CLOUD-908's ledger lives.
read -r -a declared_in <<<"${BATTEN_REPLAY_DECLARED_IN:-crates/batten/tests/*.rs policy/*.rego}"

declarations=$(git grep -h -E '^[[:space:]]*(//|#)[[:space:]]*replay:' -- "${declared_in[@]}" 2>/dev/null)

[[ -n "${declarations//[[:space:]]/}" ]] || {
	echo "replay: no migration declares a replay yet — nothing to prove"
	exit 0
}

work="$(mktemp -d)"
# EVERY WORKTREE, NOT THE LAST ONE (CLOUD-480, found on review of #660). The
# trap used to be reassigned inside the loop below, each replacement naming only
# the current tree — so with two or more `replay:` rows, `rm -rf "$work"` removed
# every directory while the administrative entries under `.git/worktrees` for all
# but the last stayed in the real repository, accumulating across runs and
# visible in `git worktree list` until somebody ran `git worktree prune`. One
# trap, set once, over a list every iteration appends to.
trees=()
cleanup() {
	local tree
	for tree in ${trees[@]+"${trees[@]}"}; do
		git worktree remove --force "$tree" >/dev/null 2>&1 || true
	done
	rm -rf "$work"
}
trap cleanup EXIT

failures=0
replayed=0
suites=0

while read -r line; do
	[[ -n "${line//[[:space:]]/}" ]] || continue
	# Strip the comment leader and the keyword, whichever language wrote it.
	spec="${line#*replay:}"
	# shellcheck disable=SC2206 # deliberate word splitting: the row is fields
	fields=($spec)
	(("${#fields[@]}" >= 5)) ||
		fail_input "a replay row needs <suite> <base-rev> <program> <rule-id> and at least one <shell>=<batten> pair; got: ${#fields[@]} field(s)"

	suite="${fields[0]}"
	base="${fields[1]}"
	program="${fields[2]}"
	rule="${fields[3]}"
	translation=("${fields[@]:4}")
	suites=$((suites + 1))

	# THE TRANSLATION IS REFUSED BEFORE ANYTHING RUNS, and the identity pair is
	# the one this task was written for. `1=1` is the naive carry-over stated
	# out loud: it asserts the migration preserved the inverted contract, and a
	# harness that ran under it would certify exactly the false green CLOUD-909
	# names. Checked here rather than at comparison time so a declaration that
	# could only ever mislead never reaches a fixture.
	for pair in "${translation[@]}"; do
		[[ "$pair" == *=* ]] ||
			fail_input "$suite: '$pair' is not a <shell>=<batten> pair"
		shell_code="${pair%%=*}"
		batten_code="${pair##*=}"
		[[ "$shell_code" =~ ^[0-9]+$ && "$batten_code" =~ ^[0-9]+$ ]] ||
			fail_input "$suite: '$pair' names something that is not an exit code"
		# 0 -> 0 is the one honest identity: silence means silence in both
		# contracts, and nothing is inverted about it. Every other identity
		# claims a code survived a translation that exists because it does not.
		if [[ "$shell_code" == "$batten_code" && "$shell_code" != "0" ]]; then
			echo "$suite translation-is-an-identity:$pair"
			echo "::error:: replay: $suite declares $pair, which asserts the exit code was CARRIED where the contract says it is TRANSLATED. The shell tasks spell 1 = violation and batten's is the inverse (house-style §7), so this is the carry-over that reports a fidelity nobody checked. State the real pair." >&2
			failures=$((failures + 1))
			continue 2
		fi
	done

	# ─── the base side ──────────────────────────────────────────────────────
	#
	# A worktree at the base rev, because the dying suite and the dying program
	# both have to be the versions the migration is replacing. `git show` alone
	# would give the program without the helpers its suite sources.
	tree="$work/base-$suites"
	git worktree add --quiet --detach "$tree" "$base" 2>/dev/null ||
		fail_input "$suite: could not check out $base — the base rev is where the dying program still exists, so a shallow clone that lacks it cannot produce this evidence. Deepen it (\`git fetch --unshallow\`) rather than skipping, which would read as a pass."
	# Registered in this repo's .git; removed on the way out so a failed run does
	# not leave the next one refusing an existing path. Appended to the list the
	# one EXIT trap reads, never installed as a trap of its own — see `cleanup`.
	trees+=("$tree")

	[[ -f "$tree/$suite" ]] ||
		fail_input "$suite: not present at $base, so there is no dying suite to take fixtures from"
	[[ -f "$tree/$program" ]] ||
		fail_input "$program: not present at $base, so there is no dying program to replay against"

	rm -rf "${tree:?}/tests/bats"
	mkdir -p "$tree/tests"
	ln -s "$(dirname "$(dirname "$bats_bin")")" "$tree/tests/bats" ||
		fail_input "$suite: could not provide the bats runner to the base tree"

	captures="$work/captures-$suites"
	mkdir -p "$captures"

	# THE SHIM, and it is what makes the fixture the case's own. It stands where
	# the program stands, copies the fixture directory aside, runs the real base-rev
	# program, and records the answer. It then exits with the real status so the
	# dying suite proceeds exactly as it would have — a shim that changed the
	# suite's behaviour would be taking its fixtures from a different run than the
	# one it observed.
	shim="$work/shim-$suites"
	mkdir -p "$shim"
	real="$tree/$program"
	cat >"$shim/$(basename "$program")" <<SHIM
#!/usr/bin/env bash
# Written by mise-tasks/replay.sh. Records one invocation of the dying program.
n=1
while [[ -e "$captures/\$n" ]]; do n=\$((n + 1)); done
dir="$captures/\$n"
mkdir -p "\$dir"
# The case that produced this invocation. bats exports the description into the
# test environment, which is what makes a capture attributable to a CASE rather
# than to a position in the run.
printf '%s' "\${BATS_TEST_DESCRIPTION:-}" >"\$dir/case"
printf '%s' "\$PWD" >"\$dir/cwd"
# The fixture, copied rather than referenced: bats tears its tmpdir down at the
# end of the case, and the head side runs after the suite has finished.
mkdir -p "\$dir/fixture"
cp -a "\$PWD/." "\$dir/fixture/" 2>/dev/null || true
"$real" "\$@" >"\$dir/out" 2>"\$dir/err"
status=\$?
printf '%s' "\$status" >"\$dir/code"
cat "\$dir/out"
cat "\$dir/err" >&2
exit \$status
SHIM
	chmod +x "$shim/$(basename "$program")"

	# The suite runs with the shim ahead of everything. Its own verdict is not
	# read: a dying suite that fails at its base rev is a fact about that rev and
	# not about this migration, and the fixtures it produced on the way are still
	# the fixtures the old gate was judged over.
	(
		cd "$tree" || exit 2
		PATH="$shim:$PATH" BATTEN_REPLAY_CAPTURE="$captures" \
			"$bats_bin" --tap "$suite" >"$work/suite-$suites.log" 2>&1
	)

	captured=$(find "$captures" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)
	((captured > 0)) || {
		echo "$suite no-invocation-captured"
		echo "::error:: replay: $suite ran and never invoked $program through the shim, so no fixture was produced. A replay over zero fixtures is a pass that proves nothing, which is why it is a refusal here. Check that the suite calls the program by name rather than by an absolute path the shim cannot stand in front of." >&2
		failures=$((failures + 1))
		continue
	}

	# ─── the head side, per carried case ────────────────────────────────────
	for capture in "$captures"/*; do
		[[ -d "$capture" ]] || continue
		case_name="$(cat "$capture/case" 2>/dev/null)"
		[[ -n "$case_name" ]] || continue

		# CLOUD-908's arms decide which cases are replayed. `carried` means the
		# same assertion moved and is the only arm whose fidelity is checkable
		# here: `subsumed` is discharged by its named successor, and `changed` is
		# expected to diverge — reading a `changed` case as a replay failure would
		# make a declared divergence unlandable.
		arm=""
		for candidate in carried subsumed changed; do
			if git grep -q -F -- "$candidate: \"$case_name\"" -- "${declared_in[@]}" 2>/dev/null; then
				arm="$candidate"
				break
			fi
		done
		[[ "$arm" == "carried" ]] || continue

		replayed=$((replayed + 1))
		shell_status="$(cat "$capture/code" 2>/dev/null)"
		shell_out="$capture/out"

		# The head tree's row over the SAME fixture. A copy, so the head side
		# cannot alter what a later comparison reads.
		head_dir="$capture/head"
		cp -a "$capture/fixture" "$head_dir" 2>/dev/null || true
		cp batten.toml "$head_dir/batten.toml" 2>/dev/null
		mkdir -p "$head_dir/policy"
		cp policy/*.rego "$head_dir/policy/" 2>/dev/null
		(cd "$head_dir" && "$binary" check -J >"$capture/head-json" 2>"$capture/head-err")
		head_status=$?

		# 1. THE POINTER SET, and what "byte for byte" means had to be settled
		#    before anything could be compared: it is the POINTERS that are
		#    identical, never the two stdouts. The old gate writes `path:line
		#    <prose>` and the engine writes its own line shape, so a `cmp` over
		#    raw output would compare two rendering conventions and fail on every
		#    faithful migration — a harness that cannot be satisfied, which is the
		#    failure `mutant`'s header warns about one level up.
		#
		#    What both sides DO share is house-style §6: a finding's first field is
		#    `path:line` or `path`, and rule 4 forbids either side carrying
		#    anything else that could vary. So the pointer is the first field on
		#    both sides, sorted and deduplicated — and THAT comparison is exact.
		#
		#    The head side reads `-J` and filters by rule id rather than taking the
		#    pointer lines whole, because the fixture carries the entire head
		#    config and only this row's findings are the migration's business.
		#    That filter is what a `check --rule` flag would give; `check` has
		#    none, and widening the published surface for a task that runs off the
		#    landing path would be the tail wagging the dog.
		awk 'NF { print $1 }' "$shell_out" | LC_ALL=C sort -u >"$capture/shell-pointers"
		if ! "$rule_pointers" "$capture/head-json" "$rule" >"$capture/head-pointers"; then
			report "$case_name" "head-answer-unreadable:$suite"
			failures=$((failures + 1))
			continue
		fi
		if ! cmp -s "$capture/shell-pointers" "$capture/head-pointers"; then
			# NEVER the two sets side by side. Both are pointers into tracked
			# content, and printing them together is a diff of that content on
			# stdout — the one thing this task must not do.
			report "$case_name" "pointer-set-differs:$suite"
			failures=$((failures + 1))
			continue
		fi

		# 2. The exit code, through the declared translation. Never an equality.
		admitted=1
		for pair in "${translation[@]}"; do
			[[ "${pair%%=*}" == "$shell_status" ]] || continue
			if [[ "${pair##*=}" == "$head_status" ]]; then
				admitted=0
			fi
			break
		done
		if ((admitted != 0)); then
			report "$case_name" "exit-untranslated:$shell_status->$head_status"
			failures=$((failures + 1))
			continue
		fi

		# 3. The remedy survives (CLOUD-437). A `msg` that lost its remedy in
		#    translation is a regression the pointer comparison structurally
		#    cannot see, because a pointer is a path and a line and the remedy is
		#    prose. Only asked of a refusal: an allow has nothing to remedy.
		#
		#    READ FROM THE DECLARATION, not from the refusal text, and that was a
		#    finding rather than a shortcut. Measured: `batten check` renders
		#    exactly `path:line rule` for a tree-scoped row and no remedy at all,
		#    because rule 4 IS its output contract — so grepping the output for
		#    remedy prose would report every faithful migration of a tree gate as
		#    having lost one. The remedy for such a row lives in its columns, and
		#    for a policy row in the module's own `msg`; both are read.
		#    COULD-NOT-LOOK IS NOT A LOST REMEDY (CLOUD-480, found on review of
		#    #660). The extractor answers three codes and its docstring says so:
		#    0 a remedy is present, 1 the row names none, 3 it could not look —
		#    an unreadable `batten.toml`, a module this tree does not have, or no
		#    such row at all. Testing only for non-zero mapped 1 and 3 together,
		#    so a typo in a `replay:` row's rule name, or a policy row whose
		#    `module` path is wrong at head, was reported as a lost remedy and
		#    counted toward the exit-1 fidelity verdict. The pointer path above
		#    already keeps the distinction as `head-answer-unreadable`.
		if [[ "$head_status" != "0" ]]; then
			remedy_status=0
			"$rule_pointers" --remedy "$head_dir" "$rule" || remedy_status=$?
			case "$remedy_status" in
			0) ;;
			1)
				report "$case_name" "remedy-lost:$suite"
				failures=$((failures + 1))
				continue
				;;
			*)
				report "$case_name" "remedy-unreadable:$suite"
				failures=$((failures + 1))
				continue
				;;
			esac
		fi
	done
done <<<"$declarations"

if ((failures > 0)); then
	echo "::error:: replay: $failures of $replayed carried case(s) did not replay faithfully across $suites suite(s). Each line above names the case and how it diverged; the two answers are deliberately not printed side by side (non-negotiable rule 4)." >&2
	exit 1
fi

echo "replay: $replayed carried case(s) across $suites suite(s) answer as the bash they replaced did"
