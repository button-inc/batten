#!/usr/bin/env bats
# The pre-commit hook's staging contract (CLOUD-250): a fixer may rewrite what
# you STAGED, and must not touch what you did not.
#
# The defect, measured 2026-08-08: two changesets in the tree, one staged, and
# the commit captured all five files — so the second issue got no `Refs:`
# trailer, no board transition, and landed anonymously. `hk`'s pre-commit runs
# the gate in FIX mode, and this repo's fixers are whole-tree by nature
# (`cargo fmt --all` ignores the file list it is handed), so a dirty tree at
# commit time is enough. AGENTS.md tells agents to commit early and often, which
# makes a dirty tree the normal case rather than an edge one.
#
# `hk.pkl` carries the fix — `stash = "patch-file"` on the pre-commit hook —
# and it arrived incidentally, in `0a1851f`, a commit about something else.
# Nothing asserted it. That is the CLOUD-216 shape (a mechanism wired to
# nothing) and the CLOUD-435 shape (six guards unwired while all six suites
# stayed green): an unasserted setting is one refactor from silently reverting,
# and the first symptom would again be an issue landing with no trailer.
#
# WHAT THE SETTING ACTUALLY BUYS, measured here rather than assumed. Under hk
# 1.54 the discriminating outcome is not that unstaged work gets *staged* — it
# is that a whole-tree fixer REWRITES it in place. With the setting, `b.txt`
# comes out of the gate byte-identical; without it, the fixer has stamped the
# file the author never staged. Both are the same defect wearing different
# clothes: work the author did not offer to the gate was changed by it.
#
# Every case drives a THROWAWAY repository with its own minimal `hk.pkl`. Using
# this repo's gate would cost a cargo build per case and would assert about
# whichever fixers happen to be configured; a one-step `sed` fixer isolates the
# property. The negative-control case is what makes the rest non-vacuous: it
# runs the identical fixture with the setting removed and shows the clobber.

setup() {
	REPO="$BATS_TEST_DIRNAME/.."
	# Resolved once, and directly rather than through `mise exec`: a fixture repo
	# has no mise config, so `mise exec -- hk` inside one cannot find the tool.
	# The `mise exec` indirection belongs to the installed hook body and is
	# asserted in tests/git-hook.bats; what this suite needs is hk itself.
	HK=$(cd "$REPO" && mise which hk)
	[ -x "$HK" ] || skip "hk is not installed in this clone"
}

# Build a fixture repo whose pre-commit gate has one whole-tree fixer.
#
# `$1` is `stashing` or `bare` — the only difference is the one line under test.
# The fixer deliberately globs `*.txt` rather than using hk's `{{files}}`: that
# is the shape of this repo's real fixers, and a fixer confined to the staged
# list cannot exhibit the defect at all.
fixture() {
	local mode=$1 dir="$BATS_TEST_TMPDIR/$mode"
	mkdir -p "$dir"
	git init -q -b main "$dir"
	git -C "$dir" config user.name "Fixture"
	git -C "$dir" config user.email "fixture@example.test"
	{
		echo 'amends "package://github.com/jdx/hk/releases/download/v1.54.0/hk@1.54.0#/Config.pkl"'
		echo ''
		echo 'hooks {'
		echo '  ["pre-commit"] {'
		[ "$mode" = stashing ] && echo '    stash = "patch-file"'
		echo '    fix = true'
		echo '    steps {'
		echo '      ["stamp"] {'
		echo '        glob = List("*.txt")'
		echo '        check = "! grep -L STAMPED *.txt | grep -q ."'
		echo '        fix = "sed -i s/^/STAMPED\\ /  *.txt"'
		echo '      }'
		echo '    }'
		echo '  }'
		echo '}'
	} >"$dir/hk.pkl"
	printf 'a\n' >"$dir/a.txt"
	printf 'b\n' >"$dir/b.txt"
	git -C "$dir" add -A
	git -C "$dir" commit -q -m "chore: base" --no-verify
	echo "$dir"
}

# Run the fixture's pre-commit gate.
#
# `BATTEN_GATE_PID` is cleared deliberately. This suite runs INSIDE the real
# gate, and the installed hook body refuses to re-enter one that is already
# running (exit 9) — a guard that exists because `doctor` runs inside the gate
# and would recurse. The fixture's gate is one `sed` and reaches nothing of this
# repo's, so there is no recursion to guard against here; leaving the marker set
# would make every case below refuse rather than measure.
run_gate() {
	# A subshell `cd`: hk resolves hk.pkl from the working directory and offers no
	# flag to point it elsewhere, so the fixture has to be the cwd.
	(cd "$1" && env -u BATTEN_GATE_PID "$HK" run pre-commit)
}

# What the next commit would contain, as `path:content` lines.
staged() {
	local dir=$1 path
	for path in $(git -C "$dir" diff --cached --name-only); do
		printf '%s:%s\n' "$path" "$(git -C "$dir" show ":$path")"
	done
}

# --- §7(a) one staged, one dirty -----------------------------------------------

@test "a commit contains only what was staged, with another change dirty in the tree" {
	local dir
	dir=$(fixture stashing)
	printf 'a-changed\n' >"$dir/a.txt"
	printf 'b-changed\n' >"$dir/b.txt"
	git -C "$dir" add a.txt

	run_gate "$dir"
	run git -C "$dir" diff --cached --name-only
	[ "$output" = "a.txt" ]
}

# --- §7(b) the dirty file survives, unstaged AND unmodified --------------------

@test "THE DEFECT: the unstaged change survives the fixer byte-for-byte" {
	# The discriminating case. A fix that ate the second changeset would be worse
	# than the sweep it replaced, so "survives" means both halves: still unstaged,
	# and still exactly what the author wrote.
	local dir
	dir=$(fixture stashing)
	printf 'a-changed\n' >"$dir/a.txt"
	printf 'b-changed\n' >"$dir/b.txt"
	git -C "$dir" add a.txt

	run_gate "$dir"

	[ "$(cat "$dir/b.txt")" = "b-changed" ]
	run git -C "$dir" diff --name-only
	[ "$output" = "b.txt" ]
}

@test "SHOWN ABLE TO FAIL: without the setting, the fixer clobbers the unstaged change" {
	# The negative control, and the reason the case above is not vacuous. Identical
	# fixture, one line removed. If hk ever stops honouring `stash`, this case goes
	# green and its neighbour goes red — which is the pair saying the same thing
	# from both sides.
	local dir
	dir=$(fixture bare)
	printf 'a-changed\n' >"$dir/a.txt"
	printf 'b-changed\n' >"$dir/b.txt"
	git -C "$dir" add a.txt

	run_gate "$dir"

	[ "$(cat "$dir/b.txt")" = "STAMPED b-changed" ]
}

# --- §7(c) a fixer's change to a STAGED file is still committed ----------------

@test "the fixer's own change to a staged file reaches the commit" {
	# The behaviour worth keeping. A change that disabled formatting-on-commit
	# would satisfy every other case here and defeat the point of the hook.
	local dir
	dir=$(fixture stashing)
	printf 'a-changed\n' >"$dir/a.txt"
	git -C "$dir" add a.txt

	run_gate "$dir"
	run staged "$dir"
	[ "$output" = "a.txt:STAMPED a-changed" ]
}

# --- §7(d) the common path does not regress ------------------------------------

@test "an all-staged commit is unchanged in shape: every path still staged, fixes applied" {
	local dir
	dir=$(fixture stashing)
	printf 'a-changed\n' >"$dir/a.txt"
	printf 'b-changed\n' >"$dir/b.txt"
	git -C "$dir" add -A

	run_gate "$dir"
	run staged "$dir"
	[ "${lines[0]}" = "a.txt:STAMPED a-changed" ]
	[ "${lines[1]}" = "b.txt:STAMPED b-changed" ]
	run git -C "$dir" diff --name-only
	[ -z "$output" ]
}

@test "a clean tree with nothing staged commits nothing and rewrites nothing" {
	local dir
	dir=$(fixture stashing)
	run_gate "$dir"
	run git -C "$dir" status --porcelain
	[ -z "$output" ]
}

# --- the setting itself, in the committed bytes --------------------------------

@test "hk.pkl declares stash on the pre-commit hook" {
	# The behavioural cases above run a FIXTURE config, so they would all stay
	# green if this repo's own hk.pkl dropped the line — the exact gap that let
	# the setting arrive unasserted. This is the half that reads the real bytes.
	cd "$REPO" || return 1
	run awk '/^  \["pre-commit"\] \{$/ { found = 1; next }
	         found && /^    stash = "patch-file"$/ { print "declared"; exit }
	         found && /^  \}$/ { exit }' hk.pkl
	[ "$status" -eq 0 ]
	[ "$output" = "declared" ]
}
