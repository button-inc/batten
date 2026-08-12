#!/usr/bin/env bats
# doctor's torn-install check (CLOUD-182): a mise tool version whose bin
# symlinks point at a payload that no longer exists must be detected from the
# ARTIFACTS — mise's own record says "installed" and `mise install` no-ops on
# it, which is how a missing venv surfaced as "the MCP server never connected".
#
# The fixture installs tree and a stub `mise` isolate the check: DOCTOR_TARGETS
# is set empty so the rustup half no-ops (that is what the `-` default exists
# for), and the bats submodule half runs against the real checkout.

setup() {
	DOCTOR="$BATS_TEST_DIRNAME/../mise-tasks/doctor"
	STUB="$BATS_TEST_TMPDIR/bin"
	DATA="$BATS_TEST_TMPDIR/mise"
	mkdir -p "$STUB" "$DATA/installs"
	cat >"$STUB/mise" <<EOF
#!/usr/bin/env bash
echo "\$@" >>"$BATS_TEST_TMPDIR/mise-calls"
EOF
	chmod +x "$STUB/mise"
	PATH="$STUB:$PATH"
	export PATH MISE_DATA_DIR="$DATA" DOCTOR_TARGETS=""

	# The git-hook half (CLOUD-476) reads THIS clone's hooks directory, so every
	# case gets its own: a scratch repo whose GIT_DIR doctor resolves through
	# `git rev-parse --git-path`. Without it these cases would grade whatever the
	# developer's checkout happens to have installed, and the suite would be a
	# report on the machine rather than on the task.
	git init -q "$BATS_TEST_TMPDIR/clone"
	export GIT_DIR="$BATS_TEST_TMPDIR/clone/.git"
	HOOKS="$GIT_DIR/hooks"
	mkdir -p "$HOOKS"
	healthy_hooks
}

# A hook that honours the probe and answers it successfully — the shape
# .claude/hooks/git-hook installs.
healthy_hooks() {
	local name
	for name in pre-commit commit-msg; do
		cat >"$HOOKS/$name" <<-'EOF'
			#!/usr/bin/env bash
			[ -n "${BATTEN_HOOK_PROBE:-}" ] && exit 0
			exit 0
		EOF
		chmod +x "$HOOKS/$name"
	done
}

healthy_tool() {
	mkdir -p "$DATA/installs/some-tool/1.0/bin"
	echo real >"$DATA/installs/some-tool/1.0/bin/tool"
}

torn_tool() {
	mkdir -p "$DATA/installs/pipx-thing/2.0/bin"
	ln -s "$DATA/installs/pipx-thing/2.0/venv/bin/thing" \
		"$DATA/installs/pipx-thing/2.0/bin/thing"
}

@test "a healthy installs tree passes untouched" {
	healthy_tool
	run "$DOCTOR"
	[ "$status" -eq 0 ]
	[[ "$output" == *"installs intact"* ]]
	[ ! -e "$BATS_TEST_TMPDIR/mise-calls" ]
}

@test "a broken bin symlink is torn: version dir removed, mise install re-run" {
	healthy_tool
	torn_tool
	run "$DOCTOR"
	[ "$status" -eq 0 ]
	[[ "$output" == *"torn install"*"pipx-thing/2.0"* ]]
	[ ! -d "$DATA/installs/pipx-thing/2.0" ]
	# The healthy tool is untouched; only the torn version dir is removed.
	[ -f "$DATA/installs/some-tool/1.0/bin/tool" ]
	grep -qx "install" "$BATS_TEST_TMPDIR/mise-calls"
}

@test "a working symlink is not torn" {
	mkdir -p "$DATA/installs/ok/3.0/bin" "$DATA/installs/ok/3.0/venv/bin"
	echo real >"$DATA/installs/ok/3.0/venv/bin/ok"
	ln -s "$DATA/installs/ok/3.0/venv/bin/ok" "$DATA/installs/ok/3.0/bin/ok"
	run "$DOCTOR"
	[ "$status" -eq 0 ]
	[[ "$output" == *"installs intact"* ]]
	[ -L "$DATA/installs/ok/3.0/bin/ok" ]
}

@test "--no-targets is the CLI spelling of an empty DOCTOR_TARGETS: rustup untouched" {
	# test:bats depends on `doctor --no-targets` (mise.toml): the child mise
	# process needs only the submodule half, and a full doctor there raced the
	# outer DAG's inside `rustup target add` (CLOUD-220). Assert the flag keeps
	# doctor entirely off the toolchain even when the env asks for targets.
	cat >"$STUB/rustup" <<EOF
#!/usr/bin/env bash
echo "\$@" >>"$BATS_TEST_TMPDIR/rustup-calls"
EOF
	chmod +x "$STUB/rustup"
	healthy_tool
	run env DOCTOR_TARGETS=ignored "$DOCTOR" --no-targets
	[ "$status" -eq 0 ]
	[[ "$output" == *"bats submodule checked out"* ]]
	[ ! -e "$BATS_TEST_TMPDIR/rustup-calls" ]
}

@test "a repair that leaves the tree broken exits non-zero" {
	torn_tool
	# A stub whose `install` recreates the torn state — reprovisioning failed.
	cat >"$STUB/mise" <<EOF
#!/usr/bin/env bash
mkdir -p "$DATA/installs/pipx-thing/2.0/bin"
ln -sf "$DATA/installs/pipx-thing/2.0/venv/bin/thing" \
	"$DATA/installs/pipx-thing/2.0/bin/thing"
EOF
	chmod +x "$STUB/mise"
	run "$DOCTOR"
	[ "$status" -eq 1 ]
	[[ "$output" == *"torn install remains after repair"* ]]
}

# --- the git hooks (CLOUD-476) ------------------------------------------------
#
# The measured defect: no pre-commit hook existed in a cloud clone, 24 commits
# went through no gate, and nothing said so. The measured hazard in fixing it:
# doctor runs INSIDE the gate, so a check that executes a gate-running hook
# recurses — it hung a `git commit` on 2026-08-12 and cost a session.

@test "an installed, probe-honouring hook is reported runnable" {
	run "$DOCTOR"
	[ "$status" -eq 0 ]
	[[ "$output" == *"pre-commit hook installed and runnable"* ]]
	[[ "$output" == *"commit-msg hook installed and runnable"* ]]
}

@test "a missing hook fails and names the remedy" {
	rm "$HOOKS/pre-commit"
	run "$DOCTOR"
	[ "$status" -eq 1 ]
	[[ "$output" == *"no executable pre-commit hook"* ]]
	[[ "$output" == *"session-start.sh"* ]]
	# Pointer-only: a path and a command, never a byte of any hook body.
	[[ "$output" != *"#!/usr/bin/env bash"* ]]
}

@test "a present but non-executable hook is not counted as installed" {
	chmod -x "$HOOKS/pre-commit"
	run "$DOCTOR"
	[ "$status" -eq 1 ]
	[[ "$output" == *"no executable pre-commit hook"* ]]
}

@test "a hook that does not honour the probe is REPORTED, never executed" {
	# This is the case a file-existence check passes and a naive "run it" check
	# hangs on: hk's own generated hook runs the whole gate, and running it from
	# inside the gate is the recursion. Distinguishable from absent, and the
	# proof it was not run is that the hook's own side effect never happens.
	cat >"$HOOKS/pre-commit" <<-EOF
		#!/usr/bin/env bash
		touch "$BATS_TEST_TMPDIR/hook-ran"
		exit 0
	EOF
	chmod +x "$HOOKS/pre-commit"
	run "$DOCTOR"
	[ "$status" -eq 1 ]
	[[ "$output" == *"does not honour BATTEN_HOOK_PROBE"* ]]
	[[ "$output" == *"NOT run"* ]]
	[ ! -e "$BATS_TEST_TMPDIR/hook-ran" ]
}

@test "a hook that cannot resolve its runner fails distinguishably from an absent one" {
	# "Present but cannot resolve hk" is the exact failure the old deferral was
	# written to avoid, and the reason the check runs the hook at all.
	cat >"$HOOKS/pre-commit" <<-'EOF'
		#!/usr/bin/env bash
		[ -n "${BATTEN_HOOK_PROBE:-}" ] && exit 127
		exit 0
	EOF
	chmod +x "$HOOKS/pre-commit"
	run "$DOCTOR"
	[ "$status" -eq 1 ]
	[[ "$output" == *"cannot resolve its runner"* ]]
	[[ "$output" != *"no executable pre-commit hook"* ]]
}

@test "doctor inside a probe says nothing about hooks — the other half of the recursion" {
	# `doctor` reached from a hook that is itself being probed must not turn
	# round and probe the hook again. The outer caller owns that verdict.
	rm "$HOOKS/pre-commit" "$HOOKS/commit-msg"
	run env BATTEN_HOOK_PROBE=1 "$DOCTOR"
	[ "$status" -eq 0 ]
	[[ "$output" != *"pre-commit"* ]]
}

@test "CI has no commit path, so the hook check does not run there" {
	# A CI checkout runs the gate directly (`mise run ci`) and never commits, so
	# failing every job over a missing hook would be a gate reporting on an
	# object that job does not have.
	rm "$HOOKS/pre-commit" "$HOOKS/commit-msg"
	run env CI=true "$DOCTOR"
	[ "$status" -eq 0 ]
	[[ "$output" != *"pre-commit"* ]]
}
