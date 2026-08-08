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
