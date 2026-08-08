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
	# End-to-end: write the violation, run the real gate, then restore.
	local victim="tests/.attribution-fixture.md"
	printf '%s\n' 'We do it this way because jdx does.' >"$victim"
	git add -N "$victim"
	run "$CHECK"
	local status_seen="$status"
	git rm -q --cached "$victim" >/dev/null 2>&1 || true
	rm -f "$victim"
	[ "$status_seen" -eq 1 ]
}
