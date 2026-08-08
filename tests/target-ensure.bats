#!/usr/bin/env bats
# target-ensure: the single locked effect through which every rustup target
# install flows (CLOUD-220). The decision half (ok/missing/stale) is
# doctor-check's and has its own suite; these tests pin the effect half — the
# lock discipline, the purge, the pointer-only failure line — against a stub
# toolchain, plus the sweep that keeps this the ONLY live `rustup target add`.

setup() {
	ENSURE="$BATS_TEST_DIRNAME/../mise-tasks/target-ensure"
	STUB="$BATS_TEST_TMPDIR/bin"
	SYSROOT="$BATS_TEST_TMPDIR/sysroot"
	STATE="$BATS_TEST_TMPDIR/state"
	mkdir -p "$STUB" "$SYSROOT/lib/rustlib" "$STATE"
	: >"$STATE/installed"

	cat >"$STUB/rustc" <<EOF
#!/usr/bin/env bash
[ "\$1" = "--print" ] && [ "\$2" = "sysroot" ] && { echo "$SYSROOT"; exit 0; }
exit 0
EOF
	cat >"$STUB/rustup" <<EOF
#!/usr/bin/env bash
STATE="$STATE"
case "\$1 \$2" in
"target list") cat "\$STATE/installed" ;;
"target add")
	echo "add \$3" >>"\$STATE/calls"
	echo "\$3" >>"\$STATE/installed" ;;
"target remove")
	echo "remove \$3" >>"\$STATE/calls"
	grep -vxF "\$3" "\$STATE/installed" >"\$STATE/i.n" || true
	mv "\$STATE/i.n" "\$STATE/installed" ;;
esac
exit 0
EOF
	chmod +x "$STUB/rustc" "$STUB/rustup"
	PATH="$STUB:$PATH"
	export PATH
	T=x86_64-pc-windows-gnu
}

@test "missing target: installs, reports the triple, exit 0" {
	run "$ENSURE" "$T"
	[ "$status" -eq 0 ]
	[[ "$output" == *"rust target $T installed"* ]]
	grep -qxF "$T" "$STATE/installed"
}

@test "already-installed target: no-op, no add call" {
	echo "$T" >>"$STATE/installed"
	run "$ENSURE" "$T"
	[ "$status" -eq 0 ]
	[[ "$output" == *"already installed"* ]]
	[ ! -e "$STATE/calls" ]
}

@test "stale residue: purged, then installed" {
	mkdir -p "$SYSROOT/lib/rustlib/$T/lib"
	echo junk >"$SYSROOT/lib/rustlib/$T/lib/libold.rlib"
	run "$ENSURE" "$T"
	[ "$status" -eq 0 ]
	[[ "$output" == *"half-installed"* ]]
	[[ "$output" == *"rust target $T installed"* ]]
	[ ! -e "$SYSROOT/lib/rustlib/$T/lib/libold.rlib" ]
	grep -qxF "$T" "$STATE/installed"
}

@test "a failing add is one ::error:: pointer line, not the rustup spew" {
	cat >"$STUB/rustup" <<'EOF'
#!/usr/bin/env bash
case "$1 $2" in
"target list") exit 0 ;;
"target add")
	echo "info: downloading component 'rust-std'" >&2
	echo "info: retrying download" >&2
	echo "error: failed to install component: detected conflict" >&2
	exit 1 ;;
esac
exit 0
EOF
	chmod +x "$STUB/rustup"
	run "$ENSURE" "$T"
	[ "$status" -eq 1 ]
	[[ "$output" == *"::error:: target-ensure: could not install rust target $T"* ]]
	# Pointer-only: rustup's last line rides the pointer; the spew above it must not.
	[[ "$output" != *"downloading component"* ]]
	[[ "$output" != *"retrying download"* ]]
}

@test "a queued caller waits for the lock holder, then proceeds" {
	mkdir -p "$SYSROOT/lib/rustlib"
	flock "$SYSROOT/lib/rustlib/.batten-target-lock" sleep 0.4 &
	holder=$!
	run "$ENSURE" "$T"
	wait "$holder"
	[ "$status" -eq 0 ]
	grep -qxF "$T" "$STATE/installed"
}

@test "a held lock past the timeout is a loud failure, not a hang" {
	mkdir -p "$SYSROOT/lib/rustlib"
	flock "$SYSROOT/lib/rustlib/.batten-target-lock" sleep 5 &
	holder=$!
	run env TARGET_LOCK_TIMEOUT=1 "$ENSURE" "$T"
	kill "$holder" 2>/dev/null || true
	wait "$holder" 2>/dev/null || true
	[ "$status" -eq 1 ]
	[[ "$output" == *"timed out waiting for the toolchain lock"* ]]
}

@test "target-ensure is the only live rustup-target-add in the task layer" {
	# The race cannot silently return via a new bare call site: every mutation
	# routes through this script's lock. Comments are excluded — prose citing
	# the command is how the rule is explained, not a violation of it — and so
	# are `<target>`-placeholder lines: a placeholder cannot execute, it is
	# usage text (dist's help), the same exemption shape attribution-check
	# gives coordinate lines.
	run bash -c "grep -v '^[[:space:]]*#' '$BATS_TEST_DIRNAME/../mise-tasks/'* | grep -v '<target>' | grep -c 'rustup target add'"
	[ "$output" = "1" ]
	run bash -c "grep -v '^[[:space:]]*#' '$BATS_TEST_DIRNAME/../mise.toml' | grep -c 'rustup target add'"
	[ "$output" = "0" ]
}
