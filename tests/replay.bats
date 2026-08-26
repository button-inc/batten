#!/usr/bin/env bats
# subject: mise-tasks/replay.sh mise-tasks/replay-pointers.py
#
# The discrimination suite for the differential replay (CLOUD-909).
#
# THIS HARNESS HAS NO LIVE CONSUMER YET, and that is exactly why its own arms are
# the deliverable. Bundle 2 retires up to twenty gates in one PR; the one
# retirement that has already happened deleted its suite long ago, so there is no
# real migration in this tree for the replay to judge. What CAN be proven now is
# that the harness reports a divergence rather than admitting one — and a harness
# nobody has watched fail is not evidence, it is a claim (CLOUD-418).
#
# So every case here builds a whole migration in miniature: a bash gate and its
# bats suite at a base rev, then a head tree where both are gone and a `forbid`
# row stands in their place. The fixture the replay runs over is produced by the
# dying suite itself, through the shim, which is the property that makes this a
# replay rather than a re-implementation.

setup() {
	load helpers

	REPLAY="$BATS_TEST_DIRNAME/../mise-tasks/replay.sh"
	POINTERS="$BATS_TEST_DIRNAME/../mise-tasks/replay-pointers.py"

	# The compiled binary, resolved the way `run-shape.bats` resolves it and for
	# the reason recorded there: there is no release build when `test:bats` runs
	# in CI, and a shorter chain aborts setup before a skip can fire.
	# `batten_binary` rather than a release-first chain: `test:bats` builds DEBUG,
	# so a leftover release binary shadowed it and this suite would report on a
	# build older than the code under test (CLOUD-859).
	# Absolute already — `batten_binary` canonicalises on every branch, which is
	# why the hand-rolled `cd`/`pwd` this suite carried is gone rather than kept
	# beside it.
	BIN=$(batten_binary "$BATS_TEST_DIRNAME/..") || skip "no batten binary to drive"

	BATS_RUNNER="$BATS_TEST_DIRNAME/bats/bin/bats"
	[ -x "$BATS_RUNNER" ] || skip "no bats runner to hand the base tree"

	FIX="$BATS_TEST_TMPDIR/migration"
	mkdir -p "$FIX"
}

# Build the base rev: a bash gate, its suite, and the files they judge.
#
# The gate prints `path:line` per hit and exits 1 — the SHELL convention, where 1
# means violation. That inversion against batten's contract is the whole reason
# the translation is declared rather than compared, so the fixture has to actually
# have it or the suite would prove nothing about the hazard.
seed_base() {
	mkdir -p "$FIX/mise-tasks" "$FIX/tests"
	cat >"$FIX/mise-tasks/demo.sh" <<'GATE'
#!/usr/bin/env bash
# Gate: no BADTOKEN in a tracked note.
set -uo pipefail
hits=0
for file in *.txt; do
	[[ -e "$file" ]] || continue
	while IFS=: read -r line _; do
		echo "$file:$line"
		hits=$((hits + 1))
	done < <(grep -n BADTOKEN "$file" 2>/dev/null)
done
((hits == 0)) || exit 1
exit 0
GATE
	chmod +x "$FIX/mise-tasks/demo.sh"

	# The suite invokes the gate BY NAME, which is what lets the shim stand in
	# front of it. A suite calling an absolute path could not be replayed, and
	# `replay.sh` says so rather than passing over zero fixtures.
	#
	# THE CASE KEYWORD IS ASSEMBLED, NEVER WRITTEN AT COLUMN ZERO. bats rewrites
	# every line of its own source that starts with the keyword, heredoc or not, so
	# a literal here would be preprocessed out of the fixture. Worse, and this is
	# what made it a real defect rather than a curiosity: `test:bats` counts the
	# keyword across `tests/*.bats` to compute the total it judges the run against,
	# so three literals in this file's fixtures inflated that total by three and
	# the whole suite failed its own anti-vacuity assertion (`2704 of 2696`).
	local case="@te"'st'
	{
		echo "#!/usr/bin/env bats"
		echo "# subject: mise-tasks/demo.sh"
		echo
		echo "$case \"a note carrying the token is a violation\" {"
		echo '	cd "$BATS_TEST_TMPDIR"'
		echo "	printf 'fine\\nBADTOKEN here\\n' >note.txt"
		echo "	run demo.sh"
		echo '	[ "$status" -eq 1 ]'
		echo "}"
		echo
		echo "$case \"a clean note is silent\" {"
		echo '	cd "$BATS_TEST_TMPDIR"'
		echo "	printf 'all fine\\n' >clean.txt"
		echo "	run demo.sh"
		echo '	[ "$status" -eq 0 ]'
		echo "}"
	} >"$FIX/tests/demo.bats"

	(
		cd "$FIX" || exit 1
		GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null git init -q -b main .
		git config user.email t@example.com
		git config user.name t
		git add -A
		git commit -qm base
	)
	BASE="$(cd "$FIX" && git rev-parse HEAD)"
}

# Build the head tree: both bash halves gone, a `forbid` row in their place, and
# the ledger CLOUD-908 and CLOUD-909 both read.
#
# `regex` is the row's predicate and `glob` its scope, so a caller can make the
# head answer differ from the bash by changing either — which is how the
# divergence arms below are produced without hand-editing a captured fixture.
seed_head() { # seed_head <arm> <glob> <translation...> [--no-remedy]
	local arm="$1" glob="$2"
	shift 2
	local remedy='no_fix_reason = "drop the token, or waive it deliberately"'
	local translation=()
	local field
	for field in "$@"; do
		if [[ "$field" == "--no-remedy" ]]; then
			remedy=""
			continue
		fi
		translation+=("$field")
	done

	rm -f "$FIX/mise-tasks/demo.sh" "$FIX/tests/demo.bats"
	{
		echo "version = 1"
		echo
		echo "[[rule]]"
		echo 'id = "demo-no-badtoken"'
		echo 'kind = "forbid"'
		echo "glob = \"$glob\""
		echo 'regex = "BADTOKEN"'
		echo 'severity = "deny"'
		echo 'scope = "tree"'
		[[ -z "$remedy" ]] || echo "$remedy"
	} >"$FIX/batten.toml"

	# The ledger, tracked so `git grep` can see it. One arm per case and one
	# replay row for the suite — the same block CLOUD-908 writes, which is the
	# point: the replay consumes that mapping rather than a second list.
	{
		echo "// the successor's ledger"
		echo "// $arm: \"a note carrying the token is a violation\" batten.toml"
		echo "// carried: \"a clean note is silent\" batten.toml"
		echo "// replay: tests/demo.bats $BASE mise-tasks/demo.sh demo-no-badtoken ${translation[*]}"
	} >"$FIX/ledger.rs"

	(cd "$FIX" && git add -A)
}

# Run the replay inside the fixture, with the declaration source pointed at it.
replay() {
	(
		cd "$FIX" || exit 2
		BATTEN_BIN="$BIN" \
			BATTEN_REPLAY_BATS="$BATS_RUNNER" \
			BATTEN_REPLAY_DECLARED_IN="ledger.rs" \
			"$REPLAY"
	)
}

# --- the positive arm, without which the rest admits everything -------------

@test "a faithful migration replays green across every carried case" {
	# Arm (e). The head row asks what the bash asked, over the same files, and
	# answers through the declared translation. Without this case every assertion
	# below would be satisfied by a harness that reported every migration as
	# divergent, which is the mirror of the false green it exists to catch.
	seed_base
	seed_head carried '*.txt' 1=2 0=0 2=1
	run replay
	[ "$status" -eq 0 ]
	[[ "$output" == *"answer as the bash they replaced did"* ]]
}

# --- arm (a): the pointer set ----------------------------------------------

@test "a module whose pointer set differs is reported, naming the case" {
	# The row's scope is narrowed to a file class the fixture does not have, so
	# the head side finds nothing where the bash found a line. That is the shape a
	# migration takes when a glob is transcribed wrong — the predicate looks
	# right, the scope is empty, and `policy test` over the module's own fixtures
	# would never notice.
	seed_base
	seed_head carried '*.md' 1=2 0=0 2=1
	run replay
	[ "$status" -eq 1 ]
	[[ "$output" == *"pointer-set-differs"* ]]
	[[ "$output" == *"a note carrying the token is a violation"* ]]
}

@test "the refusal does not print the two pointer sets side by side" {
	# Non-negotiable rule 4, and load-bearing here rather than formal: both sides
	# are pointers into tracked content, so printing them together is a diff of
	# that content on stdout. The case name and the reason travel; the paths the
	# two sides disagreed about do not.
	seed_base
	seed_head carried '*.md' 1=2 0=0 2=1
	run replay
	[ "$status" -eq 1 ]
	[[ "$output" != *"note.txt:2"* ]]
}

# --- arm (b): the naive carry-over ----------------------------------------

@test "a translation declared as an identity is refused" {
	# THE HAZARD THIS TASK EXISTS FOR. `1=1` asserts the exit code was carried
	# where the contract says it is translated: the shell tasks spell 1 =
	# violation and batten's is the inverse, so a carried-over `assert_equal
	# $status 1` means "unreadable input" and passes. A human stepped around this
	# by hand once; twenty gates in one PR will not.
	seed_base
	seed_head carried '*.txt' 1=1 0=0
	run replay
	[ "$status" -eq 1 ]
	[[ "$output" == *"translation-is-an-identity:1=1"* ]]
}

@test "0=0 is the one identity that is not a carry-over" {
	# The other direction, so the refusal above is about the INVERSION and not
	# about identities in general. Silence means silence in both contracts and
	# nothing is translated about it — refusing it would make every honest
	# declaration unlandable, which is how a gate gets switched off.
	seed_base
	seed_head carried '*.txt' 1=2 0=0
	run replay
	[ "$status" -eq 0 ]
	[[ "$output" != *"translation-is-an-identity"* ]]
}

@test "an exit code the translation does not name is a refusal, never a pass" {
	# A declaration that covers the violating code and forgets the clean one. The
	# tempting reading is "no rule for this code, so nothing to check"; that is a
	# gate with a hole exactly where a migration is least examined.
	seed_base
	seed_head carried '*.txt' 1=2
	run replay
	[ "$status" -eq 1 ]
	[[ "$output" == *"exit-untranslated"* ]]
}

# --- arm (c): changed is exempt, and only changed --------------------------

@test "a divergence on a case marked changed passes, and the same one otherwise fails" {
	# Both halves in one case, because the property IS the difference between
	# them. A `changed` case is expected to diverge — reading it as a failure
	# would make a declared behaviour change unlandable — and a case not so
	# marked diverging is the failure this instrument reports.
	seed_base
	seed_head changed '*.md' 1=2 0=0 2=1
	run replay
	[ "$status" -eq 0 ]

	seed_head carried '*.md' 1=2 0=0 2=1
	run replay
	[ "$status" -eq 1 ]
	[[ "$output" == *"pointer-set-differs"* ]]
}

# --- arm (d): the remedy --------------------------------------------------

@test "a migrated refusal that dropped its remedy is reported" {
	# CLOUD-437's clause. The pointer comparison structurally cannot see this: a
	# pointer is a path and a line, and a remedy is prose, so a faithful port that
	# lost its remedy text passes every other assertion here.
	seed_base
	seed_head carried '*.txt' 1=2 0=0 2=1 --no-remedy
	run replay
	[ "$status" -eq 1 ]
	[[ "$output" == *"remedy-lost"* ]]
}

# --- could-not-look, kept distinct from an empty answer -------------------

@test "an unreadable head answer is could-not-look, not an empty pointer set" {
	# The reading CLOUD-907 settled for the fact model, applied here: an engine
	# that crashed and a rule that found nothing produce the same empty output,
	# and collapsing them would make a broken binary look like a faithful
	# migration. Asserted at the extractor, because that is where the two are told
	# apart.
	printf 'not json at all' >"$BATS_TEST_TMPDIR/broken.json"
	run "$POINTERS" "$BATS_TEST_TMPDIR/broken.json" demo-no-badtoken
	[ "$status" -eq 3 ]

	printf '{"findings":[]}' >"$BATS_TEST_TMPDIR/empty.json"
	run "$POINTERS" "$BATS_TEST_TMPDIR/empty.json" demo-no-badtoken
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "a document with no findings key is could-not-look too" {
	# A shape this cannot read, which is not the same as an answer of "nothing".
	printf '{"version":1}' >"$BATS_TEST_TMPDIR/shapeless.json"
	run "$POINTERS" "$BATS_TEST_TMPDIR/shapeless.json" demo-no-badtoken
	[ "$status" -eq 3 ]
}

@test "the extractor reports only the rule it was asked about" {
	# The filter that stands in for a `check --rule` flag. Without it a fixture
	# carrying the whole head config would compare another row's findings against
	# the dying gate's, and every migration would read as divergent.
	cat >"$BATS_TEST_TMPDIR/two.json" <<'JSON'
{"findings":[
  {"rule":"demo-no-badtoken","path":"note.txt","line":2,"remediation":"drop it"},
  {"rule":"someone-else","path":"other.txt","line":9,"remediation":"not mine"}
]}
JSON
	run "$POINTERS" "$BATS_TEST_TMPDIR/two.json" demo-no-badtoken
	[ "$status" -eq 0 ]
	[ "$output" = "note.txt:2" ]
}

@test "the remedy is read from the declaration, and a policy row from its module" {
	# WHERE the remedy is read from was a finding rather than a detail. The
	# obvious place is the refusal text, and measured, `batten check` renders
	# exactly `path:line rule` for a tree-scoped row and no remedy at all —
	# because rule 4 IS its output contract. So a harness grepping the output for
	# remedy prose would report every faithful migration of a tree gate as having
	# lost one, which is a gate that cannot be satisfied.
	#
	# Both shapes are covered because a migration produces both: a `forbid` row
	# carries its remedy in a column, and a policy row carries it in the module's
	# own `msg`, which is the only place a Rego refusal can put it.
	local root="$BATS_TEST_TMPDIR/remedy"
	mkdir -p "$root/policy"

	printf 'version = 1\n\n[[rule]]\nid = "r"\nkind = "forbid"\nglob = "*.txt"\nregex = "X"\nseverity = "deny"\nscope = "tree"\nno_fix_reason = "restore it"\n' >"$root/batten.toml"
	run "$POINTERS" --remedy "$root" r
	[ "$status" -eq 0 ]

	printf 'version = 1\n\n[[rule]]\nid = "r"\nkind = "forbid"\nglob = "*.txt"\nregex = "X"\nseverity = "deny"\nscope = "tree"\n' >"$root/batten.toml"
	run "$POINTERS" --remedy "$root" r
	[ "$status" -eq 1 ]

	# A policy row's remedy lives in the module. `msg` assigned something
	# non-empty is the remedy surviving; an empty one is the regression CLOUD-437
	# names, and neither is visible in the row's own columns.
	printf 'version = 1\n\n[[rule]]\nid = "r"\nkind = "policy"\nscope = "tree"\nmodule = "policy/r.rego"\nseverity = "deny"\n' >"$root/batten.toml"
	printf 'package r\n\ndeny contains msg if {\n\tmsg := "restore it, or waive the reduction"\n}\n' >"$root/policy/r.rego"
	run "$POINTERS" --remedy "$root" r
	[ "$status" -eq 0 ]

	printf 'package r\n\ndeny contains msg if {\n\tmsg := ""\n}\n' >"$root/policy/r.rego"
	run "$POINTERS" --remedy "$root" r
	[ "$status" -eq 1 ]
}

@test "a rule the head config does not carry is could-not-look" {
	# A broken declaration, not a missing remedy. Reading it as "no remedy" would
	# blame the migration for a typo in the row that describes it.
	local root="$BATS_TEST_TMPDIR/absent"
	mkdir -p "$root"
	printf 'version = 1\n' >"$root/batten.toml"
	run "$POINTERS" --remedy "$root" nobody
	[ "$status" -eq 3 ]
}

# --- the declaration itself ----------------------------------------------

@test "a suite that never invokes the program is a refusal, not a silent pass" {
	# A replay over zero fixtures proves nothing, and would report success while
	# doing it — the vacuous pass this repository has measured four times.
	seed_base
	# A suite that judges nothing: the shim is never reached. Same assembled
	# keyword as `seed_base`, for the same two reasons.
	local case="@te"'st'
	{
		echo "#!/usr/bin/env bats"
		echo "# subject: mise-tasks/demo.sh"
		echo
		echo "$case \"a note carrying the token is a violation\" {"
		echo "	[ 1 -eq 1 ]"
		echo "}"
	} >"$FIX/tests/demo.bats"
	(cd "$FIX" && git add -A && git commit -qm "inert suite")
	BASE="$(cd "$FIX" && git rev-parse HEAD)"
	seed_head carried '*.txt' 1=2 0=0 2=1
	run replay
	[ "$status" -eq 1 ]
	[[ "$output" == *"no-invocation-captured"* ]]
}

@test "no declared replay at all is not a failure" {
	# A tree mid-campaign has suites yet to be retired, and reporting that as a
	# refusal would make the task useless before its first consumer exists.
	seed_base
	printf '// nothing declared here\n' >"$FIX/ledger.rs"
	(cd "$FIX" && git add -A)
	run replay
	[ "$status" -eq 0 ]
	[[ "$output" == *"nothing to prove"* ]]
}
