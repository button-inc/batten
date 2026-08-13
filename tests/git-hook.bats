#!/usr/bin/env bats
# The installed git hook body (CLOUD-476), which is checked in precisely so it
# can be asserted here rather than only through an installation.
#
# Two properties carry the whole design, and each has a measured failure behind
# it: `hk` is resolved through mise (bare `hk` is not on PATH in a cloud
# container, and that is why no hook was installed at all for months), and the
# gate refuses to re-enter itself (`doctor` runs inside the gate, so a hook run
# from in there recurses — measured as a hung `git commit`, 2026-08-12).

setup() {
	HOOK="$BATS_TEST_DIRNAME/../.claude/hooks/git-hook"
	STUB="$BATS_TEST_TMPDIR/bin"
	CALLS="$BATS_TEST_TMPDIR/mise-calls"
	mkdir -p "$STUB"
	# Records the argv it was called with AND the marker the hook exported, so
	# the re-entrancy assertions observe behaviour rather than grep the source.
	cat >"$STUB/mise" <<EOF
#!/usr/bin/env bash
# The marker's liveness is only meaningful WHILE the gate runs, so it is read
# here — from inside the call the hook made — not afterwards from the log.
if [ -n "\${BATTEN_GATE_PID:-}" ] && kill -0 "\$BATTEN_GATE_PID" 2>/dev/null; then
	marker="\$BATTEN_GATE_PID alive"
else
	marker="\${BATTEN_GATE_PID:-none} not-alive"
fi
printf '%s | marker=%s\n' "\$*" "\$marker" >>"$CALLS"
EOF
	chmod +x "$STUB/mise"
	PATH="$STUB:$PATH"
	export PATH
	unset BATTEN_GATE_PID BATTEN_HOOK_PROBE

	# Git invokes a hook BY ITS HOOK NAME, and the body dispatches on that name,
	# so every case goes through a link named like the real installation rather
	# than through the file's own path.
	HOOK="$BATS_TEST_TMPDIR/pre-commit"
	ln -s "$BATS_TEST_DIRNAME/../.claude/hooks/git-hook" "$HOOK"
}

# A pid that is certainly not live: the shell that printed it has exited.
dead_pid() { bash -c 'echo $$'; }

@test "the hook body is executable and checked in" {
	[ -x "$BATS_TEST_DIRNAME/../.claude/hooks/git-hook" ]
}

@test "hk is resolved through mise, never bare — the failure that blocked installing a hook at all" {
	run "$HOOK"
	[ "$status" -eq 0 ]
	grep -q '^exec -- hk run pre-commit' "$CALLS"
}

@test "probe mode asks the runner, and does NOT run the gate" {
	# The narrow question doctor needs answered from inside the gate. Running the
	# gate to answer it is the recursion this exists to avoid.
	run env BATTEN_HOOK_PROBE=1 "$HOOK"
	[ "$status" -eq 0 ]
	grep -q '^exec -- hk --version' "$CALLS"
	run grep -c 'hk run' "$CALLS"
	[ "$status" -ne 0 ]
}

@test "a live gate marker is refused with exit 9, and spends nothing" {
	run env BATTEN_GATE_PID=$$ "$HOOK"
	[ "$status" -eq 9 ]
	[[ "$output" == *"gate is already running"* ]]
	[[ "$output" == *"$$"* ]]
	[ ! -e "$CALLS" ]
}

@test "a DEAD gate marker does not refuse — a stale marker must not disarm a real commit" {
	# The reason the marker is a pid rather than a boolean: a gate run that died
	# leaves its variable behind in every orphan, and refusing there would block
	# ordinary commits with no way to tell why.
	run env BATTEN_GATE_PID="$(dead_pid)" "$HOOK"
	[ "$status" -eq 0 ]
	grep -q 'hk run pre-commit' "$CALLS"
}

@test "the gate run exports a LIVE pid as the marker" {
	run "$HOOK"
	[ "$status" -eq 0 ]
	# Read by the stub AS THE GATE RAN: the marker names a process that is alive
	# for the whole run, which is what makes the refusal below trustworthy.
	grep -q 'marker=[0-9][0-9]* alive' "$CALLS"
}

@test "the hook dispatches on the name it is invoked as" {
	# One body, two hooks: hk.pkl defines pre-commit and commit-msg, and the
	# installation symlinks both to this file.
	ln -s "$BATS_TEST_DIRNAME/../.claude/hooks/git-hook" "$BATS_TEST_TMPDIR/commit-msg"
	run "$BATS_TEST_TMPDIR/commit-msg" .git/COMMIT_EDITMSG
	[ "$status" -eq 0 ]
	# The hook's own arguments still reach hk, after the profile flag the two-tier
	# gate adds (CLOUD-509). Asserted as two facts rather than one literal argv,
	# so adding a flag does not red a case about dispatch.
	grep -q 'hk run commit-msg' "$CALLS"
	grep -q '\.git/COMMIT_EDITMSG' "$CALLS"
}

@test "the hook disables the slow profile, which is what makes a commit fast" {
	# The other half of CLOUD-509's split, at its only switch-off point. hk.pkl
	# enables `slow` at the config layer so every other entry point runs the full
	# gate; if this flag stops being passed, every commit pays the whole 275s
	# again. `hook-profile-check` gates the same property from the other side.
	run "$HOOK"
	[ "$status" -eq 0 ]
	grep -q -- "--profile" "$CALLS"
	grep -q -- '!slow' "$CALLS"
}

@test "the gate's exit status is the hook's" {
	cat >"$STUB/mise" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
	chmod +x "$STUB/mise"
	run "$HOOK"
	[ "$status" -eq 1 ]
}
