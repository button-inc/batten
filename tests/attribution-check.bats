#!/usr/bin/env bats
# The gate that ships with the attribution rule (mem:prior-art-and-issue-hygiene).
#
# Both directions are load-bearing. Catching the appeal is the point; letting a
# coordinate through is what keeps the gate usable, since every tool pin in
# mise.toml names the project that publishes it.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/attribution-check"
	cd "$BATS_TEST_DIRNAME/.." || return 1
}

@test "the repo as it stands passes" {
	run "$CHECK"
	[ "$status" -eq 0 ]
}

@test "the gate is wired: hk.pkl declares a step that runs this task" {
	# The defect this suite could not see (CLOUD-216): every case below passed
	# while nothing invoked the task, so the suite measured itself and the rule
	# stayed prose. Asserted on the step block rather than a bare grep, because
	# the surrounding comment names the task too — a comment is not a call site.
	run awk '/^  \["attribution-check"\] \{$/ { found = 1; next }
	         found && /mise run attribution-check/ { print "wired"; exit }
	         found && /^  \}$/ { exit }' hk.pkl
	[ "$status" -eq 0 ]
	[ "$output" = "wired" ]
}

@test "a tool pin naming its publisher is a coordinate, not an appeal" {
	# A surveyed source is also a dependency we address by name. If these tripped
	# the gate it would fire on every workflow and pin, and be turned off within a
	# day — which is how this list got narrowed: the first draft flagged every
	# `uses:` line and every tool pin in the repo.
	for line in \
		'hk.pkl:14:amends "package://github.com/jdx/hk/releases/download/v1.54.0/hk@1.54.0"' \
		'AGENTS.md:9:Toolchain pinned with [`mise`](https://mise.jdx.dev)' \
		'.github/workflows/ci.yml:37:      - uses: jdx/mise-action@7e36c90d9ab29c415a2384db3006f3ec8a8cc654'; do
		run bash -c "printf '%s\n' '$line' | grep -qE 'https?://|package://|aqua:|ubi:|npm:|pipx:|github\.com|\.dev|submodule|amends|uses:|@[0-9a-f]{40}'"
		[ "$status" -eq 0 ]
	done
}

@test "a bare appeal in prose is not a coordinate" {
	for line in \
		'mise.toml:37:# puts it on PATH — the same shape jdx uses' \
		'AGENTS.md:12:// we follow jdx here'; do
		run bash -c "printf '%s\n' '$line' | grep -qE 'https?://|package://|aqua:|ubi:|npm:|pipx:|github\.com|\.dev|submodule|amends|uses:|@[0-9a-f]{40}'"
		[ "$status" -ne 0 ]
	done
}

@test "an appeal introduced into a tracked file fails the gate" {
	# End-to-end: write the violation, run the real gate, read the verdict.
	#
	# In a throwaway repo, never in this one (CLOUD-386). The gate reads `git
	# ls-files` from the working directory, so it judges whatever tree it is
	# pointed at — and the earlier form of this case pointed it at the real
	# checkout, planting a tracked violation and mutating the real index for the
	# duration. Serially that was invisible. Under `bats --jobs` it is a race:
	# the sibling case above ("the repo as it stands passes") reads the same
	# tracked set and would flip red, and every concurrent case shelling out to
	# git contends on .git/index.lock. The suite's own convention already had
	# the answer — issue-guard.bats builds a fresh repo per case for exactly
	# this reason.
	local repo="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$repo"
	git -C "$repo" init -q
	printf '%s\n' 'We do it this way because jdx does.' >"$repo/note.md"
	# A second, clean file so the tree has more than one tracked path. The gate
	# pipes `git ls-files -z` into `xargs -0 grep -n`, and grep prefixes the
	# filename only when it is given more than one — a single-file fixture would
	# assert a pointer shape the real invocation never emits.
	printf '%s\n' 'Nothing to see here.' >"$repo/clean.md"
	git -C "$repo" add -N note.md clean.md
	cd "$repo" || return 1
	run "$CHECK"
	[ "$status" -eq 1 ]
	# Pointer, never payload: the gate names the coordinate, and the line it
	# quotes is the offending line itself rather than the file's contents.
	[[ "$output" == *"note.md:1:"* ]]
}
