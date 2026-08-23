#!/usr/bin/env bats
# subject: mise-tasks/ntia-check.sh
# ntia-check's decision table (CLOUD-580): does the derived SBOM meet the NTIA/CISA
# minimum elements, and — the half that can rot silently — is the verdict really the
# checker's exit code rather than its report?
#
# Driven against a stubbed `sbomcheck` and a stubbed `syft`, for two reasons the
# real tools cannot serve. The real checker cannot be made to PASS over this
# repository today (the missing supplier and license fields do not exist in a cargo
# lockfile), so the conformant branch and the receipt it writes would be untestable
# — and the negative self-test needs a checker whose report and whose exit code
# DISAGREE, which no honest tool will produce.
#
# The real path is covered where it can be: `tests/sbom-check.bats`' final case
# already runs the real syft over the real tree, and `mise run ntia-check` is a
# `[[rule]]` row in batten.toml, so `mise run batten-check` exercises the real
# checker on every gate run.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/ntia-check.sh"
	STUB="$BATS_TEST_TMPDIR/bin"
	mkdir -p "$STUB"
	PATH="$STUB:$PATH"
	export PATH

	# The tree `mise-tasks/sbom.sh` scans: a manifest to read the version from is all
	# it needs, since the catalog comes from the stubbed syft.
	ROOT="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$ROOT"
	printf 'version = "9.9.9"\n' >"$ROOT/Cargo.toml"
	export NTIA_CHECK_ROOT="$ROOT"
	# `sbom` resolves its own root independently, so both are set: unset, it would
	# scan the real repository with the stub on PATH.
	export SBOM_ROOT="$ROOT"
	# One standard by default, so a case that means "the checker refused" does not
	# have to reason about two identical refusals.
	export NTIA_STANDARDS="ntia"
	export BATTEN_BIN="$STUB/batten"
	# The checker is named explicitly rather than shadowed on PATH: `sbomcheck` is
	# a mise shim, so a stub earlier in PATH cannot make it absent, and the
	# could-not-look case below has to be able to.
	export SBOMCHECK="$STUB/sbomcheck"
	stub_syft
	stub_sbomcheck
	stub_batten
}

# A `syft` that writes the two documents `mise-tasks/sbom.sh` asks for. Sentinels:
#   syft.fails      exit non-zero, so no document can be derived
#   syft.spdxver    the `spdxVersion` to declare (default SPDX-2.3, matching what
#                   the real `spdx-json` output carries); the literal string
#                   `NONE` omits the key, so the could-not-look arm is reachable
stub_syft() {
	cat >"$STUB/syft" <<EOF
#!/usr/bin/env bash
set -euo pipefail
[ ! -f "$BATS_TEST_TMPDIR/syft.fails" ] || exit 1

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

mkdir -p "\$(dirname "\$spdx")" "\$(dirname "\$cdx")"
ver="SPDX-2.3"
[ ! -f "$BATS_TEST_TMPDIR/syft.spdxver" ] || ver="\$(cat "$BATS_TEST_TMPDIR/syft.spdxver")"
verkey="\"spdxVersion\":\"\$ver\","
[ "\$ver" != "NONE" ] || verkey=""
echo "{\$verkey\"SPDXID\":\"SPDXRef-DOCUMENT\",\"name\":\"batten\",\"packages\":[{\"name\":\"crate0\",\"externalRefs\":[{\"referenceType\":\"purl\",\"referenceLocator\":\"pkg:cargo/crate0@1.0.0\"}]}]}" >"\$spdx"
echo '{"components":[{"name":"crate0","purl":"pkg:cargo/crate0@1.0.0"}]}' >"\$cdx"
EOF
	chmod +x "$STUB/syft"
}

# An `sbomcheck` whose exit code and whose report are set INDEPENDENTLY, which is
# what makes the negative self-test possible. Sentinels:
#   check.<standard>.fails  exit 1 for that standard
#   check.noversion         present, but --version fails
#   check.noreport          exit 1 and write no report at all
#   check.liesconformant    write a fully conformant report AND exit 1
stub_sbomcheck() {
	cat >"$STUB/sbomcheck" <<EOF
#!/usr/bin/env bash
set -euo pipefail
if [ "\${1:-}" = "--version" ]; then
	[ ! -f "$BATS_TEST_TMPDIR/check.noversion" ] || exit 1
	echo "sbomcheck 5.0.3"
	exit 0
fi

standard="ntia"
out=""
want=""
for arg in "\$@"; do
	case "\$want" in
	comply)
		standard="\$arg"
		want=""
		continue
		;;
	out)
		out="\$arg"
		want=""
		continue
		;;
	esac
	case "\$arg" in
	--comply) want=comply ;;
	--output-file) want=out ;;
	esac
done

fail=0
[ ! -f "$BATS_TEST_TMPDIR/check.\$standard.fails" ] || fail=1

# The report is written first and independently of the exit code below: a real
# checker agrees with itself, and this one is allowed not to.
if [ -n "\$out" ] && [ ! -f "$BATS_TEST_TMPDIR/check.noreport" ]; then
	if [ "\$fail" = 0 ] || [ -f "$BATS_TEST_TMPDIR/check.liesconformant" ]; then
		cat >"\$out" <<JSON
{"isConformant":true,"totalNumberComponents":3,
 "componentSuppliers":{"nonconformantComponents":[],"allProvided":true},
 "componentConcludedLicenses":{"nonconformantComponents":[],"allProvided":true},
 "componentCopyrightTexts":{"nonconformantComponents":[],"allProvided":true}}
JSON
	else
		cat >"\$out" <<JSON
{"isConformant":false,"totalNumberComponents":3,
 "componentSuppliers":{"nonconformantComponents":["crate0","crate1"]},
 "componentConcludedLicenses":{"nonconformantComponents":["crate0","crate1","crate2"]},
 "componentCopyrightTexts":{"nonconformantComponents":["crate0","crate1","crate2"]}}
JSON
	fi
fi
# The human report the real tool prints by default names every nonconformant
# component. It is emitted here so the pointer-only case has something to catch if
# the gate ever stops redirecting it.
echo "crate0: no supplier; pkg:cargo/crate0@1.0.0"
exit "\$fail"
EOF
	chmod +x "$STUB/sbomcheck"
}

# A `batten` that records the receipt call instead of taking one, so the suite
# never builds the workspace (hk serialises the cargo target-dir lock).
stub_batten() {
	cat >"$STUB/batten" <<EOF
#!/usr/bin/env bash
echo "\$*" >>"$BATS_TEST_TMPDIR/receipts"
EOF
	chmod +x "$STUB/batten"
}

@test "a conformant document passes and records the SHA-keyed receipt" {
	run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"conforms to ntia"* ]]
	[ "$(cat "$BATS_TEST_TMPDIR/receipts")" = "receipt record sbom-ntia" ]
}

@test "a nonconformant document fails, and leaves NO receipt" {
	: >"$BATS_TEST_TMPDIR/check.ntia.fails"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"sbom-ntia-nonconformant (ntia"* ]]
	[ ! -f "$BATS_TEST_TMPDIR/receipts" ]
}

@test "THE NEGATIVE SELF-TEST: a conformant-looking report with a non-zero exit still fails" {
	# The verdict is the exit code (CLOUD-93). A gate that read the report would
	# pass here, and would then pass anything a checker's own formatter got wrong.
	: >"$BATS_TEST_TMPDIR/check.ntia.fails"
	: >"$BATS_TEST_TMPDIR/check.liesconformant"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"sbom-ntia-nonconformant"* ]]
	[ ! -f "$BATS_TEST_TMPDIR/receipts" ]
}

@test "the failure carries counts, which are the message and not the decision" {
	: >"$BATS_TEST_TMPDIR/check.ntia.fails"
	run "$CHECK"
	[[ "$output" == *"components=3"* ]]
	[[ "$output" == *"no-supplier=2"* ]]
	[[ "$output" == *"no-license=3"* ]]
	[[ "$output" == *"no-copyright=3"* ]]
}

@test "a checker that writes no report still reports its exit code" {
	# The counts are read from a file the checker may not have written. Dying on
	# that would turn a verdict into a crash.
	: >"$BATS_TEST_TMPDIR/check.ntia.fails"
	: >"$BATS_TEST_TMPDIR/check.noreport"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"exit=1"* ]]
}

@test "output is pointer-only — no component name and no purl reach the log" {
	# rule 4: the checker's own report names every nonconformant component, and
	# this gate must never pass one on.
	: >"$BATS_TEST_TMPDIR/check.ntia.fails"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" != *"crate0"* ]]
	[[ "$output" != *"pkg:cargo/"* ]]
	[[ "$output" != *"nonconformantComponents"* ]]
}

@test "the failure names the published asset, not a scratch path" {
	: >"$BATS_TEST_TMPDIR/check.ntia.fails"
	run "$CHECK"
	[[ "$output" == *"batten.spdx.json:0"* ]]
	[[ "$output" != *"$BATS_TEST_TMPDIR"* ]]
}

@test "one refusing standard of two fails the whole run" {
	# Both published expectations are checked, so a regression in either lands as
	# a failure rather than being averaged away by the other passing.
	export NTIA_STANDARDS="ntia fsct3-min"
	: >"$BATS_TEST_TMPDIR/check.fsct3-min.fails"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"(fsct3-min"* ]]
	[[ "$output" != *"(ntia "* ]]
}

@test "an absent checker exits 2 — could not look is not a verdict" {
	export SBOMCHECK="$BATS_TEST_TMPDIR/no-such-checker"
	run "$CHECK"
	[ "$status" -eq 2 ]
	[[ "$output" == *"unverified"* ]]
	[ ! -f "$BATS_TEST_TMPDIR/receipts" ]
}

@test "a checker that cannot answer --version exits 2 in precondition mode" {
	: >"$BATS_TEST_TMPDIR/check.noversion"
	run "$CHECK" --precondition
	[ "$status" -eq 2 ]
	[[ "$output" == *"--version"* ]]
}

@test "a syft that cannot run exits 2 — the document, not the verdict, is missing" {
	: >"$BATS_TEST_TMPDIR/syft.fails"
	run "$CHECK"
	[ "$status" -eq 2 ]
	[[ "$output" == *"unverified"* ]]
}

@test "THE SEVERITY SPLIT: the precondition passes over a nonconformant document" {
	# This is the whole premise of the `deny` precondition row beside the `warn`
	# conformance row in batten.toml. If this case ever failed, the deny row would
	# be enforcing the conformance verdict and every landing in the repo would
	# stop.
	: >"$BATS_TEST_TMPDIR/check.ntia.fails"
	: >"$BATS_TEST_TMPDIR/check.fsct3-min.fails"
	run "$CHECK" --precondition
	[ "$status" -eq 0 ]
	[[ "$output" == *"precondition holds"* ]]
}

@test "the precondition records no receipt — it attests the mechanism, not the SBOM" {
	run "$CHECK" --precondition
	[ "$status" -eq 0 ]
	[ ! -f "$BATS_TEST_TMPDIR/receipts" ]
}

@test "the gate leaves the tree it judges unmodified" {
	# It derives into a scratch directory: a gate that writes what it judges
	# cannot fail twice.
	: >"$BATS_TEST_TMPDIR/check.ntia.fails"
	before="$(find "$ROOT" -type f | sort)"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[ "$(find "$ROOT" -type f | sort)" = "$before" ]
	run "$CHECK"
	[ "$status" -eq 1 ]
}

# ─── CLOUD-666: the standards set, and the precondition that keeps it honest ───

@test "the DEFAULT standards set is satisfiable: a conformant document exits 0" {
	# The case that could not pass before this row. `fsct3-min` was in the default
	# set and is unsatisfiable for every document syft can emit, so the gate was
	# guaranteed non-zero whatever the SBOM said — and the `warn` row could never
	# clear. `NTIA_STANDARDS` is unset here deliberately: the point is the DEFAULT,
	# not a set the suite chose.
	unset NTIA_STANDARDS
	run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"conforms to ntia"* ]]
	[[ "$output" != *"fsct3-min"* ]]
	[ "$(cat "$BATS_TEST_TMPDIR/receipts")" = "receipt record sbom-ntia" ]
}

@test "dropping the unsatisfiable standard does not disarm the gate" {
	# The other half of the same change: a document missing a required field must
	# still fail under the narrowed default. A green gate is only worth having if
	# it can still go red.
	unset NTIA_STANDARDS
	: >"$BATS_TEST_TMPDIR/check.ntia.fails"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"sbom-ntia-nonconformant (ntia"* ]]
	[ ! -f "$BATS_TEST_TMPDIR/receipts" ]
}

@test "THE DURABLE HALF: an spdx3-only standard over an spdx2 document is a PRECONDITION refusal" {
	# The failure mode this row closes is a standard nobody could satisfy being
	# read as a document nobody had fixed. Those are different answers and only a
	# precondition tells them apart: exit 2 ("could not ask"), never exit 1
	# ("this tree is nonconformant").
	export NTIA_STANDARDS="ntia fsct3-min"
	run "$CHECK" --precondition
	[ "$status" -eq 2 ]
	[[ "$output" == *"fsct3-min"* ]]
	[[ "$output" == *"requires an spdx3 document"* ]]
}

@test "the same standard over an spdx3 document is NOT refused" {
	# The refusal is a property of the document's spec, not a blocklist on a name:
	# if the producer ever emits SPDX 3, the standard becomes askable again with no
	# edit to this gate.
	export NTIA_STANDARDS="ntia fsct3-min"
	echo "SPDX-3.0.1" >"$BATS_TEST_TMPDIR/syft.spdxver"
	run "$CHECK" --precondition
	[ "$status" -eq 0 ]
	[[ "$output" == *"precondition holds"* ]]
	[[ "$output" == *"spdx3"* ]]
}

@test "a document declaring no spdxVersion is could-not-look, never a pass" {
	# A precondition that clears every standard it cannot classify is the silent
	# return this row exists to close.
	export NTIA_STANDARDS="ntia fsct3-min"
	echo "NONE" >"$BATS_TEST_TMPDIR/syft.spdxver"
	run "$CHECK" --precondition
	[ "$status" -eq 2 ]
	[[ "$output" == *"no spdxVersion"* ]]
}

@test "an unclassifiable spdxVersion is could-not-look too" {
	export NTIA_STANDARDS="ntia fsct3-min"
	echo "SPDX-9.9" >"$BATS_TEST_TMPDIR/syft.spdxver"
	run "$CHECK" --precondition
	[ "$status" -eq 2 ]
	[[ "$output" == *"cannot classify"* ]]
}

@test "the nonconformance summary names the standards that refused and asserts no cause" {
	# CLOUD-198's class. The old summary blamed the cargo lockfile for every
	# standard, which was true of `ntia` and false of the other — and stated in the
	# one place a reader debugging the gate stops.
	: >"$BATS_TEST_TMPDIR/check.ntia.fails"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"refused this document: ntia"* ]]
	[[ "$output" != *"what a cargo lockfile can supply"* ]]
}
