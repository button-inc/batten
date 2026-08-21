#!/usr/bin/env bats
# subject: mise-tasks/doctor.sh
# CLOUD-201's remaining half: doctor's two REPAIRS, run concurrently.
#
# `verify` reaches doctor twice from one invocation — through `cross-check`, and
# again through `ci` -> `hooks` -> `hk check --all`, whose `test:bats` step
# shells out to `mise run test:bats` in a separate mise process that the outer
# run's dependency dedup never sees. The rustup half of that collision was
# closed by CLOUD-220's `target-ensure` lock and is covered by
# `tests/target-race.bats`. These are the writers that were left:
#
#   * `git submodule update --init` — two of them race git's index lock;
#   * the torn-install repair — one doctor `rm -rf`s the version directory the
#     other's `mise install` is populating, MANUFACTURING the CLOUD-182 tear
#     this task exists to repair.
#
# Hermetic: stub `git`, `mise` and a fixture repo, so nothing here touches the
# real checkout or the real installs tree. The assertion in both cases is a
# count — the repair ran exactly once — because "both exited 0" alone would pass
# even if both had repaired.

setup() {
	DOCTOR="$BATS_TEST_DIRNAME/../mise-tasks/doctor.sh"
	STUB="$BATS_TEST_TMPDIR/bin"
	REPO="$BATS_TEST_TMPDIR/repo"
	DATA="$BATS_TEST_TMPDIR/mise"
	CALLS="$BATS_TEST_TMPDIR/calls"
	mkdir -p "$STUB" "$REPO" "$DATA/installs"

	# The git-hook half (CLOUD-476) reads this clone's hooks directory, so the
	# fixture gets its own probe-honouring pair — the shape
	# `.claude/hooks/git-hook.sh` installs. Without them doctor's hook check would
	# set `status=1` and every assertion below would fail for a reason that has
	# nothing to do with the repairs under test. `CI` is unset for the mirror of
	# that reason: doctor SKIPS the hook check under CI, so the runner's own
	# `CI=true` would have these cases grading a skip.
	unset CI
	mkdir -p "$REPO/.git/hooks"
	local name
	for name in pre-commit commit-msg; do
		cat >"$REPO/.git/hooks/$name" <<-'HOOK'
			#!/usr/bin/env bash
			[ -n "${BATTEN_HOOK_PROBE:-}" ] && exit 0
			exit 0
		HOOK
		chmod +x "$REPO/.git/hooks/$name"
	done

	# `rev-parse --show-toplevel` and `rev-parse --git-path` are the reads doctor
	# makes before any repair; `submodule update` is the write under test, slowed
	# so a second doctor would overlap it if the lock were absent.
	cat >"$STUB/git" <<EOF
#!/usr/bin/env bash
case "\$1 \$2" in
"rev-parse --show-toplevel") echo "$REPO"; exit 0 ;;
"rev-parse --git-path") echo "$REPO/.git/\$3"; exit 0 ;;
"submodule update")
	echo "submodule-update" >>"$CALLS"
	sleep 0.4
	mkdir -p "$REPO/tests/bats/bin"
	printf '#!/usr/bin/env bash\n' >"$REPO/tests/bats/bin/bats"
	chmod +x "$REPO/tests/bats/bin/bats"
	exit 0 ;;
esac
exit 0
EOF

	# `mise install` is the second write. It also repopulates the version dir,
	# so a second unguarded repair would find nothing torn and pass silently —
	# which is why the count, not the end state, is what these tests assert.
	cat >"$STUB/mise" <<EOF
#!/usr/bin/env bash
if [ "\$1" = "install" ]; then
	echo "mise-install" >>"$CALLS"
	sleep 0.4
	mkdir -p "$DATA/installs/pipx-thing/2.0/venv/bin"
	printf 'real\n' >"$DATA/installs/pipx-thing/2.0/venv/bin/thing"
fi
exit 0
EOF
	chmod +x "$STUB/git" "$STUB/mise"
	PATH="$STUB:$PATH"
	# No rust targets: the rustup half has its own suite, and pulling it in here
	# would test target-ensure's lock a third time instead of doctor's.
	export PATH MISE_DATA_DIR="$DATA" DOCTOR_TARGETS=""
	cd "$REPO" || return 1
}

torn_tool() {
	mkdir -p "$DATA/installs/pipx-thing/2.0/bin"
	ln -s "$DATA/installs/pipx-thing/2.0/venv/bin/thing" \
		"$DATA/installs/pipx-thing/2.0/bin/thing"
}

# Two doctors started as close together as bash allows, both waited on.
run_two() {
	local a b
	"$DOCTOR" >"$BATS_TEST_TMPDIR/out-a" 2>&1 &
	a=$!
	"$DOCTOR" >"$BATS_TEST_TMPDIR/out-b" 2>&1 &
	b=$!
	wait "$a"
	A_STATUS=$?
	wait "$b"
	B_STATUS=$?
}

@test "harness self-test: the fixture really does need the submodule repair" {
	# Without this a green suite could mean the repair was never reachable.
	run "$DOCTOR"
	[ "$status" -eq 0 ]
	[ "$(grep -c submodule-update "$CALLS")" -eq 1 ]
}

@test "two concurrent doctors run the submodule repair exactly once" {
	run_two
	[ "$A_STATUS" -eq 0 ]
	[ "$B_STATUS" -eq 0 ]
	[ "$(grep -c submodule-update "$CALLS")" -eq 1 ]
}

@test "the doctor that queued still reports the submodule as checked out" {
	# A queued doctor must not report a repair it did not perform, and must not
	# report the environment as broken either: it re-checks inside the critical
	# section and prints the ordinary verdict line (§5 — verdicts unchanged).
	run_two
	grep -q "bats submodule checked out" "$BATS_TEST_TMPDIR/out-a"
	grep -q "bats submodule checked out" "$BATS_TEST_TMPDIR/out-b"
}

@test "two concurrent doctors run the torn-install repair exactly once" {
	# The unguarded version is worse than wasteful: the second doctor's `rm -rf`
	# lands inside the first's `mise install`, which is the CLOUD-182 tear.
	torn_tool
	run_two
	[ "$A_STATUS" -eq 0 ]
	[ "$B_STATUS" -eq 0 ]
	[ "$(grep -c mise-install "$CALLS")" -eq 1 ]
	[ -f "$DATA/installs/pipx-thing/2.0/venv/bin/thing" ]
}

@test "an intact installs tree takes the lock never — the healthy path is free" {
	# Locking unconditionally would serialise every doctor in the graph behind
	# the slowest one for no benefit. The scan runs outside the lock; only a
	# tree that looks torn queues.
	mkdir -p "$DATA/installs/ok/3.0/bin" "$DATA/installs/ok/3.0/venv/bin"
	echo real >"$DATA/installs/ok/3.0/venv/bin/ok"
	ln -s "$DATA/installs/ok/3.0/venv/bin/ok" "$DATA/installs/ok/3.0/bin/ok"
	mkdir -p "$REPO/tests/bats/bin"
	printf '#!/usr/bin/env bash\n' >"$REPO/tests/bats/bin/bats"
	chmod +x "$REPO/tests/bats/bin/bats"
	run "$DOCTOR"
	[ "$status" -eq 0 ]
	[[ "$output" == *"installs intact"* ]]
	[ ! -e "$DATA/.batten-doctor-lock" ]
}

@test "the lock never lands in the working tree, where tree-clean would see it" {
	# CLOUD-277 makes an untracked file in the tree a refusal for `verify`, and
	# `verify` runs doctor. A lock directory under the repo would therefore fail
	# every run — so the lock lives beside the installs tree it guards.
	torn_tool
	run "$DOCTOR"
	[ "$status" -eq 0 ]
	[ -z "$(find "$REPO" -name '.batten-*lock*' -print -quit)" ]
	[ ! -e "$DATA/.batten-doctor-lock" ]
}
