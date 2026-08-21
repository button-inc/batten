#!/usr/bin/env bats
# subject: .claude/hooks/session-start.sh
# The SessionStart hook's load-bearing properties (CLOUD-196). The hook's effect
# — a provisioned toolchain — is not assertable in a unit test, so these pin the
# two properties whose loss would silently restore the defect: that it is
# synchronous, and that it fails loudly rather than exiting 0 on a broken setup.

setup() {
	HOOK="$BATS_TEST_DIRNAME/../.claude/hooks/session-start.sh"
	SETTINGS="$BATS_TEST_DIRNAME/../.claude/settings.json"

	# The hook now ends in `mise run container-preflight`, whose verdict is about
	# the CONTAINER — its egress policy and its credential — not about this code
	# (CLOUD-261). Letting that verdict decide these tests would make `mise run
	# test:bats` a container-health check, and the fix for a broken container
	# could then never be landed from one. So the preflight alone is neutralised
	# here, and every other `mise` call — `mise install` above all — still runs
	# for real, which is what keeps the lockfile assertion below non-vacuous.
	#
	# The preflight's own behaviour is asserted in tests/container-preflight.bats,
	# where the GitHub half is stubbed and every verdict is reachable.
	#
	# `doctor` is neutralised for the same reason and one more (CLOUD-218). Its
	# rustup half reaches the network to install cross targets, so an offline
	# container would decide these tests; and `[tasks."test:bats"]` already
	# `depends = ["doctor --no-targets"]`, so letting each hook-running test
	# invoke a FULL doctor would hang a cross-target install off every one of
	# them. Its own behaviour is asserted in tests/doctor-check.bats and
	# tests/target-race.bats.
	#
	# The stub RECORDS every invocation, which is what makes the wiring assertion
	# below a real observation of the hook's behaviour rather than a grep of its
	# source.
	#
	# `install` IS INTERCEPTED TOO, and opted back in per case (CLOUD-406). It
	# used to exec the real binary unconditionally, on the argument that this is
	# what keeps the lockfile assertions non-vacuous — half true, and the half
	# that was false cost a red required check on a branch that changed nothing.
	# Measured on run 31538830648: Sigstore's TUF metadata endpoint was down,
	# `mise install` failed, and two cases whose properties are ORDER and OUTPUT
	# went red through their `[ "$status" -eq 0 ]` line. Neither was asserting
	# anything about the install succeeding; the hook records the call either way,
	# because `step` sets `fail=1` and CONTINUES rather than aborting.
	#
	# Of the two lockfile assertions the old rationale named, only one needs a
	# real install: the `grep` over the hook's source text does not touch a
	# toolchain. That one, and the two other genuinely end-to-end cases, set
	# `SESSION_START_REAL_INSTALL` and establish the precondition first — so a
	# container that cannot provision SKIPS with a reason instead of reporting a
	# hook defect, which is the `lock-check` split applied one layer down.
	STUB="$BATS_TEST_TMPDIR/bin"
	CALLS="$BATS_TEST_TMPDIR/mise-calls"
	mkdir -p "$STUB"
	REAL_MISE="$(command -v mise)"
	cat >"$STUB/mise" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >>"$CALLS"
if [ "\$1" = run ] && { [ "\$2" = container-preflight ] || [ "\$2" = doctor ]; }; then exit 0; fi
if [ "\$1" = install ] && [ -z "\${SESSION_START_REAL_INSTALL:-}" ]; then exit 0; fi
exec "$REAL_MISE" "\$@"
EOF
	chmod +x "$STUB/mise"
	PATH="$STUB:$PATH"
	export PATH
}

# ESTABLISH THE PRECONDITION, NEVER RETRY THE MEASUREMENT (CLOUD-406). A case
# that needs a real install asks for one HERE, directly, before the hook runs. A
# failure at this line is a statement about the container's egress, not about the
# hook — so it skips with a reason rather than reddening a branch. It is also the
# discriminator that makes the opt-in honest: past it, the hook's own install
# cannot fail for a provisioning reason, so a red from the case that follows is a
# real defect. Idempotent and warm, so the second install costs milliseconds.
real_install_or_skip() {
	env MISE_LOCKFILE=false "$REAL_MISE" install >/dev/null 2>&1 ||
		skip "this container cannot provision — \`mise install\` failed, which is a verdict about egress and not about the hook (CLOUD-406)"
	export SESSION_START_REAL_INSTALL=1
}

@test "the hook is executable" {
	[ -x "$HOOK" ]
}

@test "the hook is synchronous — async would restore the race it closes" {
	# `{"async": true}` on stdout tells the client to start the session while
	# this still runs, which is exactly the window the MCP handshake lost. The
	# property is what the hook EMITS, not whether the word appears — the
	# rationale comment names async precisely to explain why it is absent, and
	# an earlier version of this test failed on that comment.
	run env CLAUDE_PROJECT_DIR="$BATS_TEST_DIRNAME/.." "$HOOK"
	[ "$status" -eq 0 ]
	[[ "$output" != *"async"* ]]

	# Belt and braces: no executable (non-comment) line declares it either.
	run bash -c "grep -v '^[[:space:]]*#' '$HOOK' | grep -c '\"async\"' || true"
	[ "$output" -eq 0 ]
}

@test "mise install runs — the step whose absence was the defect" {
	# `mise exec` in .mcp.json installs on demand; this is what makes that a
	# pure exec instead of a 24-second install inside the MCP startup window.
	run grep -q "mise install" "$HOOK"
	[ "$status" -eq 0 ]
}

@test "doctor runs inside the synchronous window — after install, before the preflight" {
	# CLOUD-218. `mise install` returning is not "the toolchain is settled": the
	# rustup cross targets are doctor's to provision, and outside this window
	# they land inside the first `mise run verify`, where a concurrent writer
	# turns the install into a `detected conflict` rollback that names
	# cross-compilation. Ordering is the whole property — after `mise install`
	# because doctor's rustup half needs the provisioned toolchain, before the
	# preflight because the preflight is a halt and provisioning must be done
	# by then.
	run env CLAUDE_PROJECT_DIR="$BATS_TEST_DIRNAME/.." "$HOOK"
	[ "$status" -eq 0 ]

	local install doctor preflight
	install=$(grep -nx 'install' "$CALLS" | head -1 | cut -d: -f1)
	doctor=$(grep -nx 'run doctor' "$CALLS" | head -1 | cut -d: -f1)
	preflight=$(grep -n '^run container-preflight' "$CALLS" | head -1 | cut -d: -f1)
	[ -n "$install" ]
	[ -n "$doctor" ]
	[ -n "$preflight" ]
	[ "$install" -lt "$doctor" ]
	[ "$doctor" -lt "$preflight" ]
}

@test "a failed step exits non-zero — absence must never be silent" {
	run grep -q "exit 1" "$HOOK"
	[ "$status" -eq 0 ]
}

@test "the hook is registered as a SessionStart hook" {
	run python3 -c "
import json
d = json.load(open('$SETTINGS'))
hooks = d['hooks']['SessionStart']
cmds = [h['command'] for g in hooks for h in g['hooks']]
assert any('session-start.sh' in c for c in cmds), cmds
print('registered')
"
	[ "$status" -eq 0 ]
	[[ "$output" == *"registered"* ]]
}

@test "the hook runs green on this checkout" {
	# Idempotent by construction, so running it here is safe and is the only
	# end-to-end assertion available: the steps are all already satisfied.
	real_install_or_skip
	run env CLAUDE_PROJECT_DIR="$BATS_TEST_DIRNAME/.." "$HOOK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"toolchain provisioned"* ]]
}

@test "the install is lockfile-free — provisioning must not dirty the tracked lock" {
	# CLOUD-223: `[settings] lockfile = true` plus a cold ubi install appends a
	# platform key `mise lock` cannot produce and `lock-complete` rejects, so
	# every session began dirty and the residue was committed twice. Currency is
	# lock-currency.yml's job, on a schedule; provisioning is a pure install.
	run grep -qE 'MISE_LOCKFILE=false[[:space:]]+mise install' "$HOOK"
	[ "$status" -eq 0 ]
}

@test "running the hook leaves the tracked lockfile untouched" {
	# The end-to-end version of the assertion above, and the one that would have
	# caught the original defect: the suite itself runs this hook.
	# The one case the real install is genuinely load-bearing for: a stubbed
	# install writes no lockfile, so it could not observe the residue CLOUD-223
	# was about.
	real_install_or_skip
	local before after
	before=$(git -C "$BATS_TEST_DIRNAME/.." status --porcelain -- mise.lock)
	run env CLAUDE_PROJECT_DIR="$BATS_TEST_DIRNAME/.." "$HOOK"
	[ "$status" -eq 0 ]
	after=$(git -C "$BATS_TEST_DIRNAME/.." status --porcelain -- mise.lock)
	[ "$before" = "$after" ]
}

@test "the git hooks are installed — the per-clone step that was absent" {
	# CLOUD-476: `hk install` was named in two prose files, performed by nothing
	# and asserted by nothing, so 24 commits in one container went through no
	# gate. This is the end-to-end half; `doctor` decides the same state on every
	# later run, and tests/git-hook.bats owns what the installed body does.
	#
	# Idempotent, and it installs into THIS clone — which is the point: the suite
	# that asserts the step is also the thing that performs it here.
	run env CLAUDE_PROJECT_DIR="$BATS_TEST_DIRNAME/.." "$HOOK"
	[ "$status" -eq 0 ]

	local root hooks name
	root=$(cd "$BATS_TEST_DIRNAME/.." && pwd)
	hooks=$(git -C "$root" rev-parse --git-path hooks)
	for name in pre-commit commit-msg; do
		[ -x "$hooks/$name" ]
		# A symlink, not a copy: a copy is a second authority that goes stale the
		# moment the checked-in body changes, and doctor would keep passing over it.
		[ -L "$hooks/$name" ]
		[ "$(readlink "$hooks/$name")" = "$root/.claude/hooks/git-hook" ]
	done
}
