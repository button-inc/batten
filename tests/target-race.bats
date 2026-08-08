#!/usr/bin/env bats
# The CLOUD-220 reproduction: two processes mutating one rustup toolchain must
# converge, not mutually roll back. Hermetic — a stub toolchain models rustup's
# documented non-atomicity deterministically (a real-toolchain race would be
# flaky by the very defect under test), so the real sysroot is never touched.
#
# The stub's `target add` writes a partial rlib plus a writer marker, then
# holds the install open long enough to observe any concurrent writer. Overlap
# means BOTH callers report "detected conflict" and roll back — exactly the
# measured behavior — while a lone caller commits. The harness self-test below
# proves the model can represent the bug, so a green suite is never vacuous.

setup() {
	REPO="$BATS_TEST_DIRNAME/.."
	DOCTOR="$REPO/mise-tasks/doctor"
	LINK="$REPO/mise-tasks/darwin-link"
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

	# The model: add = write partial artifacts, wait a window for a concurrent
	# writer, conflict-and-rollback on overlap, commit when alone. Rollback
	# leaves EMPTY target dirs, matching the issue's post-mortem ("both target
	# directories under the sysroot are empty").
	cat >"$STUB/rustup" <<EOF
#!/usr/bin/env bash
STATE="$STATE"; RL="$SYSROOT/lib/rustlib"
case "\$1 \$2" in
"target list")
	cat "\$STATE/installed"; exit 0 ;;
"target remove")
	t="\$3"
	grep -vxF "\$t" "\$STATE/installed" >"\$STATE/installed.n" || true
	mv "\$STATE/installed.n" "\$STATE/installed"
	rm -rf "\$RL/\$t"; exit 0 ;;
"target add")
	t="\$3"
	echo "add \$t pid=\$\$" >>"\$STATE/add-log"
	if grep -qxF "\$t" "\$STATE/installed"; then exit 0; fi
	d="\$RL/\$t/lib"; mkdir -p "\$d"
	m="\$RL/\$t/.writer.\$\$"; : >"\$m"
	echo x >"\$d/libaddr2line-\$\$.rlib"
	conflict=no
	for i in \$(seq 1 15); do
		sleep 0.1
		if ls "\$RL/\$t"/.writer.* 2>/dev/null | grep -qv "\.writer\.\$\$\$"; then
			# Sighting is racy (the other writer may roll back and vanish
			# before we look again), so persist it: a tombstone makes the
			# conflict STICKY — both writers lose however their windows skew,
			# which is what a slow 2-core runner needs to stay deterministic.
			: >"\$RL/\$t/.conflict"
			conflict=yes; break
		fi
	done
	[ -e "\$RL/\$t/.conflict" ] && conflict=yes
	if [ "\$conflict" = yes ]; then
		echo "error: failed to install component: 'rust-std-\$t', detected conflict: 'lib/rustlib/\$t/lib/libaddr2line.rlib'" >&2
		echo "info: rolling back changes" >&2
		rm -f "\$m" "\$d/libaddr2line-\$\$.rlib"
		exit 1
	fi
	echo "\$t" >>"\$STATE/installed"
	echo "installed \$t" >>"\$STATE/add-log"
	rm -f "\$m"
	exit 0 ;;
esac
exit 0
EOF

	cat >"$STUB/cargo" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
	cat >"$STUB/mise" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
	chmod +x "$STUB"/rustc "$STUB"/rustup "$STUB"/cargo "$STUB"/mise
	PATH="$STUB:$PATH"
	# MISE_DATA_DIR points at an empty fixture so doctor's torn-install half
	# no-ops; the submodule half runs against the real checkout, which is fast.
	export PATH MISE_DATA_DIR="$BATS_TEST_TMPDIR/mise-data"
	T=aarch64-apple-darwin
}

@test "harness self-test: two raw concurrent adds both roll back (the model can represent the bug)" {
	rustup target add "$T" &
	p1=$!
	rustup target add "$T" &
	p2=$!
	s1=0 s2=0
	wait "$p1" || s1=$?
	wait "$p2" || s2=$?
	[ "$s1" -ne 0 ]
	[ "$s2" -ne 0 ]
	run grep -cxF "$T" "$STATE/installed"
	[ "$output" = "0" ]
}

@test "harness self-test: skewed writers still both roll back (CI spawn-skew shape)" {
	# The first CI run of this suite falsified the back-to-back self-test on a
	# 2-core runner: process spawn skew let the late writer start after the
	# early one had sighted, rolled back, and removed its marker — one add
	# succeeded. The tombstone makes the conflict sticky; this pins the skewed
	# interleaving so the harness cannot regress to live-marker detection.
	rustup target add "$T" &
	p1=$!
	sleep 0.4
	rustup target add "$T" &
	p2=$!
	s1=0 s2=0
	wait "$p1" || s1=$?
	wait "$p2" || s2=$?
	[ "$s1" -ne 0 ]
	[ "$s2" -ne 0 ]
	run grep -cxF "$T" "$STATE/installed"
	[ "$output" = "0" ]
}

@test "doctor and darwin-link converge when concurrent: both succeed, target installed" {
	DOCTOR_TARGETS="$T" "$DOCTOR" >"$STATE/doctor.out" 2>&1 &
	pd=$!
	"$LINK" "$T" >"$STATE/link.out" 2>&1 &
	pl=$!
	sd=0 sl=0
	wait "$pd" || sd=$?
	wait "$pl" || sl=$?
	cat "$STATE/doctor.out" "$STATE/link.out"
	[ "$sd" -eq 0 ]
	[ "$sl" -eq 0 ]
	grep -qxF "$T" "$STATE/installed"
	! grep -q "detected conflict" "$STATE/doctor.out" "$STATE/link.out"
	! grep -q "rolling back" "$STATE/doctor.out" "$STATE/link.out"
}

@test "doctor is idempotent under concurrency: two doctors, one real install" {
	DOCTOR_TARGETS="$T" "$DOCTOR" >"$STATE/d1.out" 2>&1 &
	p1=$!
	DOCTOR_TARGETS="$T" "$DOCTOR" >"$STATE/d2.out" 2>&1 &
	p2=$!
	s1=0 s2=0
	wait "$p1" || s1=$?
	wait "$p2" || s2=$?
	cat "$STATE/d1.out" "$STATE/d2.out"
	[ "$s1" -eq 0 ]
	[ "$s2" -eq 0 ]
	grep -qxF "$T" "$STATE/installed"
	run grep -c '^installed ' "$STATE/add-log"
	[ "$output" = "1" ]
}

@test "stale residue is purged inside the critical section, then installed" {
	mkdir -p "$SYSROOT/lib/rustlib/$T/lib"
	echo junk >"$SYSROOT/lib/rustlib/$T/lib/libold.rlib"
	run env DOCTOR_TARGETS="$T" "$DOCTOR"
	[ "$status" -eq 0 ]
	grep -qxF "$T" "$STATE/installed"
}
