#!/usr/bin/env bats
# subject: mise-tasks/sbom-check.sh
# sbom-check's decision table (CLOUD-262): does the derived inventory describe the
# tree it claims to, and is it a function of the source rather than of the clock?
#
# Driven against a stubbed `syft` rather than the real one, for a reason the real
# tool cannot satisfy: two genuine scans of one tree always agree, so nothing would
# prove the normalizer is merely stripping the four volatile fields rather than
# stripping enough to make any two documents look identical. The stub can make two
# runs differ in a package NAME, which is exactly the case a too-wide normalizer
# would wave through. That is the negative self-test the acceptance asks for.
#
# The final case drops the stub and runs against the real repository, so the suite
# also asserts the committed toolchain and the real tree still satisfy the gate.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/sbom-check.sh"
	STUB="$BATS_TEST_TMPDIR/bin"
	mkdir -p "$STUB"
	PATH="$STUB:$PATH"
	export PATH

	# A minimal tree with the two files the gate reads: a manifest to take the
	# version from, and a lockfile whose `[[package]]` count is the expectation.
	ROOT="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$ROOT"
	printf 'version = "9.9.9"\n' >"$ROOT/Cargo.toml"
	lockfile 1
	export SBOM_ROOT="$ROOT"
	stub_syft
}

# A Cargo.lock declaring $1 packages — the number the cargo purl count must equal.
lockfile() {
	local n=$1 i
	: >"$ROOT/Cargo.lock"
	for ((i = 0; i < n; i++)); do
		printf '[[package]]\nname = "crate%d"\n\n' "$i" >>"$ROOT/Cargo.lock"
	done
}

# A `syft` that writes both documents, varying the four volatile fields on every
# call the way the real one does. Sentinels drive the failure shapes:
#   syft.fails  exit non-zero, so the gate cannot look
#   syft.empty  catalog nothing
#   syft.drift  alternate the package name per call — a REAL content change, and
#               alternating rather than latching so that EVERY consecutive pair
#               differs; latching from call 2 would leave a second gate run
#               comparing two already-renamed documents and agreeing honestly
stub_syft() {
	cat >"$STUB/syft" <<EOF
#!/usr/bin/env bash
set -euo pipefail
[ ! -f "$BATS_TEST_TMPDIR/syft.fails" ] || exit 1

n=1
[ ! -f "$BATS_TEST_TMPDIR/calls" ] || n=\$((\$(cat "$BATS_TEST_TMPDIR/calls") + 1))
echo "\$n" >"$BATS_TEST_TMPDIR/calls"

spdx=""
cdx=""
want=0
for arg in "\$@"; do
	if [ "\$want" = 1 ]; then
		case "\$arg" in
		spdx-json=*) spdx="\${arg#spdx-json=}" ;;
		cyclonedx-json=*) cdx="\${arg#cyclonedx-json=}" ;;
		esac
		want=0
		continue
	fi
	[ "\$arg" = "--output" ] && want=1
done

name=crate0
if [ -f "$BATS_TEST_TMPDIR/syft.drift" ] && [ \$((n % 2)) -eq 0 ]; then
	name=renamed
fi

packages='{"name":"'\$name'","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:cargo/'\$name'@1.0.0"}]}'
components='{"name":"'\$name'","purl":"pkg:cargo/'\$name'@1.0.0"}'
if [ -f "$BATS_TEST_TMPDIR/syft.empty" ]; then
	packages=""
	components=""
fi

mkdir -p "\$(dirname "\$spdx")" "\$(dirname "\$cdx")"
cat >"\$spdx" <<JSON
{"SPDXID":"SPDXRef-DOCUMENT","name":"batten",
 "documentNamespace":"https://example.invalid/syft/\$n",
 "creationInfo":{"created":"2026-08-10T00:00:0\${n}Z"},
 "packages":[\$packages]}
JSON
cat >"\$cdx" <<JSON
{"serialNumber":"urn:uuid:0000-\$n",
 "metadata":{"timestamp":"2026-08-10T00:00:0\${n}Z",
             "component":{"name":"batten","version":"9.9.9"}},
 "components":[\$components]}
JSON
EOF
	chmod +x "$STUB/syft"
}

@test "a matching, stable inventory passes — and that IS the normalizer working" {
	# The stub stamps a different namespace, creation time, serial number and
	# timestamp on each of the gate's two runs. Passing therefore proves the
	# normalizer strips exactly those; the drift case below proves it strips no
	# more. Neither case means anything without the other.
	run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"1 cargo package(s) in both formats"* ]]
}

@test "THE NEGATIVE SELF-TEST: a renamed package still fails after normalization" {
	# A normalizer widened until everything passes would swallow this. It is the
	# one case that distinguishes "stable" from "compared nothing".
	: >"$BATS_TEST_TMPDIR/syft.drift"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"sbom-unstable"* ]]
}

@test "a cargo count that disagrees with Cargo.lock fails, naming both numbers" {
	lockfile 3
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"sbom-package-drift"* ]]
	[[ "$output" == *"1 vs 3"* ]]
}

@test "an SBOM that catalogs nothing must not report green" {
	# Two empty documents agree perfectly, so every equality check below would
	# pass. This is the vacuous green the gate has to refuse on its own.
	: >"$BATS_TEST_TMPDIR/syft.empty"
	lockfile 0
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"sbom-empty"* ]]
}

@test "output is pointer-only — no document body reaches the log" {
	# rule 4. An SBOM is 300+ KB of dependency detail; the remedy is one command,
	# so the body adds nothing and would bury the verdict.
	: >"$BATS_TEST_TMPDIR/syft.drift"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" != *"referenceLocator"* ]]
	[[ "$output" != *"pkg:cargo/"* ]]
}

@test "the failure names an asset, not a scratch path" {
	# The gate scans into mktemp dirs, and a pointer at one of those is noise a
	# reader cannot act on. It points at the published asset name instead.
	: >"$BATS_TEST_TMPDIR/syft.drift"
	run "$CHECK"
	[[ "$output" == *"batten.spdx.json:0"* ]]
	[[ "$output" != *"$BATS_TEST_TMPDIR"* ]]
}

@test "the gate leaves the tree it judges unmodified, and fails twice" {
	# A gate that writes what it judges cannot fail twice: the second run would
	# pass, laundering the drift into a clean result.
	: >"$BATS_TEST_TMPDIR/syft.drift"
	before="$(find "$ROOT" -type f | sort)"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[ "$(find "$ROOT" -type f | sort)" = "$before" ]
	run "$CHECK"
	[ "$status" -eq 1 ]
}

@test "a syft that cannot run exits 2 — could not look is not a verdict" {
	: >"$BATS_TEST_TMPDIR/syft.fails"
	run "$CHECK"
	[ "$status" -eq 2 ]
	[[ "$output" == *"unverified"* ]]
}

@test "a missing Cargo.lock exits 2 rather than passing vacuously" {
	rm -f "$ROOT/Cargo.lock"
	run "$CHECK"
	[ "$status" -eq 2 ]
	[[ "$output" == *"must not report green"* ]]
}

@test "this repo's real tree satisfies the gate — with the real syft" {
	# The self-consumption case. The stub proves the logic; this proves the logic
	# is pointed at a tree and a toolchain that actually satisfy it, which is the
	# only way the suite can also assert the committed pin works.
	unset SBOM_ROOT
	PATH="${PATH#"$STUB":}"
	export PATH
	cd "$BATS_TEST_DIRNAME/.." || return 1
	run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"matching Cargo.lock"* ]]
}
