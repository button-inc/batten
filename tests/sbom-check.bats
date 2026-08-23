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
	# `authors` as well as `version`: the workspace supplier is read from here
	# (CLOUD-630), and a manifest declaring none leaves the document's own subject
	# at NOASSERTION — which the supplier clause correctly refuses.
	printf 'version = "9.9.9"\nauthors = ["Button Inc."]\n' >"$ROOT/Cargo.toml"
	lockfile 1
	export SBOM_ROOT="$ROOT"
	stub_syft
	stub_cargo
}

# `sbom.sh` reads `cargo metadata` for supplier and originator, and this gate
# re-runs it — so the synthetic tree needs an answer even though no case here
# asserts on those fields. It reports the one crate the syft stub catalogs, with an
# author, so the gate's originator-agreement clause is satisfied rather than
# bypassed. `renamed` is the drift fixture's alternate name and is declared too, or
# the drift case would fail the agreement clause instead of the stability one.
stub_cargo() {
	cat >"$STUB/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# `fetch` is a no-op here: this synthetic tree has no crates to fetch.
[ "${1:-}" != "fetch" ] || exit 0
[ "${1:-}" = "metadata" ] || exit 1
cat <<'JSON'
{"packages":[
  {"name":"crate0","version":"1.0.0","source":"registry+https://github.com/rust-lang/crates.io-index","authors":["Someone"],"license":"Apache-2.0 OR MIT"},
  {"name":"renamed","version":"1.0.0","source":"registry+https://github.com/rust-lang/crates.io-index","authors":["Someone"],"license":"Apache-2.0 OR MIT"},
  {"name":"batten","version":"9.9.9","source":null,"authors":["Button Inc."],"license":"Apache-2.0"}
]}
JSON
EOF
	chmod +x "$STUB/cargo"
	# An unpacked registry cache for each package the stub declares. `sbom.sh`
	# refuses to produce a document when a package the lockfile names has no
	# unpacked source, so without this every case here would exercise that refusal
	# instead of what it means to test. Empty directories, which yield `NONE` — no
	# case in this suite asserts on a copyright value.
	export CARGO_HOME="$BATS_TEST_TMPDIR/cargo"
	mkdir -p "$CARGO_HOME/registry/src/index.crates.io-fixture"
	mkdir -p "$CARGO_HOME/registry/src/index.crates.io-fixture/crate0-1.0.0"
	mkdir -p "$CARGO_HOME/registry/src/index.crates.io-fixture/renamed-1.0.0"
	mkdir -p "$CARGO_HOME/registry/src/index.crates.io-fixture/mystery-UNKNOWN"
}

# A Cargo.lock declaring $1 SOURCED packages — the number the cargo purl count must
# equal (CLOUD-664). Every entry carries a `source`, because that is what makes it a
# registry dependency and so what predicts a purl in the document. A second
# argument adds one entry WITHOUT a source: a local workspace member, which syft
# 1.50.0+ deliberately gives no registry purl (anchore/syft#5105), so it must count
# toward `[[package]]` and not toward the expected purls.
lockfile() {
	local n=$1 local_member="${2:-}" i
	: >"$ROOT/Cargo.lock"
	for ((i = 0; i < n; i++)); do
		printf '[[package]]\nname = "crate%d"\nversion = "1.0.0"\nsource = "registry+https://example.invalid/index"\n\n' "$i" >>"$ROOT/Cargo.lock"
	done
	if [ -n "$local_member" ]; then
		printf '[[package]]\nname = "batten"\nversion = "9.9.9"\n\n' >>"$ROOT/Cargo.lock"
	fi
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

packages='{"SPDXID":"SPDXRef-Package-a","name":"'\$name'","versionInfo":"1.0.0","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:cargo/'\$name'@1.0.0"}]}'
components='{"bom-ref":"ref-a","name":"'\$name'","version":"1.0.0","purl":"pkg:cargo/'\$name'@1.0.0"}'

# The three inflated shapes CLOUD-664 measured, each reachable on its own so a
# case can name which condition it means. They are appended as EXTRA components,
# because that is how syft produced them: a second entry for something already
# inventoried, or an entry for something that was never a dependency.
if [ -f "$BATS_TEST_TMPDIR/syft.duplicate" ]; then
	packages="\$packages,"'{"SPDXID":"SPDXRef-Package-a-again","name":"'\$name'","versionInfo":"1.0.0","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:cargo/'\$name'@1.0.0"}]}'
	components="\$components,"'{"bom-ref":"ref-a-again","name":"'\$name'","version":"1.0.0","purl":"pkg:cargo/'\$name'@1.0.0"}'
fi
if [ -f "$BATS_TEST_TMPDIR/syft.pathlike" ]; then
	packages="\$packages,"'{"SPDXID":"SPDXRef-Package-local","name":"./action","versionInfo":"UNKNOWN","supplier":"Organization: ."}'
	components="\$components,"'{"bom-ref":"ref-local","name":"./action","version":"UNKNOWN"}'
fi
if [ -f "$BATS_TEST_TMPDIR/syft.unversioned" ]; then
	packages="\$packages,"'{"SPDXID":"SPDXRef-Package-nover","name":"mystery","versionInfo":"UNKNOWN"}'
	components="\$components,"'{"bom-ref":"ref-nover","name":"mystery","version":"UNKNOWN"}'
fi

# The document's own subject, and the relationship that identifies it. Present in
# every fixture because it is present in every real syft document, and because the
# gate reads it to decide what to EXEMPT: the subject shares its triple with the
# workspace member and must not be read as a duplicate of it.
subject='{"SPDXID":"SPDXRef-DocumentRoot-Directory-batten","name":"batten","versionInfo":"9.9.9"}'
relationships='{"spdxElementId":"SPDXRef-DOCUMENT","relatedSpdxElement":"SPDXRef-DocumentRoot-Directory-batten","relationshipType":"DESCRIBES"}'
if [ -f "$BATS_TEST_TMPDIR/syft.nodescribes" ]; then
	relationships=""
fi

if [ -f "$BATS_TEST_TMPDIR/syft.empty" ]; then
	packages=""
	components=""
fi
if [ -n "\$packages" ]; then
	packages="\$subject,\$packages"
else
	packages="\$subject"
fi

mkdir -p "\$(dirname "\$spdx")" "\$(dirname "\$cdx")"
cat >"\$spdx" <<JSON
{"SPDXID":"SPDXRef-DOCUMENT","name":"batten",
 "documentNamespace":"https://example.invalid/syft/\$n",
 "creationInfo":{"created":"2026-08-10T00:00:0\${n}Z"},
 "packages":[\$packages],
 "relationships":[\$relationships]}
JSON
cat >"\$cdx" <<JSON
{"serialNumber":"urn:uuid:0000-\$n",
 "metadata":{"timestamp":"2026-08-10T00:00:0\${n}Z",
             "component":{"bom-ref":"ref-root","name":"batten","version":"9.9.9"}},
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

@test "a lockfile whose local member has no source still matches: 1 purl, 1 sourced of 2" {
	# CLOUD-664. syft 1.50.0 stopped emitting a registry purl for a local workspace
	# package (anchore/syft#5105), so the count this clause compares against is the
	# lockfile's SOURCED entries, not all of them. Comparing against all of them is
	# the off-by-one that made #572's CI red.
	lockfile 1 local
	run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"1 sourced entries of 2"* ]]
}

@test "the inflated shapes syft produces are all absorbed before the gate judges" {
	# The three shapes CLOUD-664 measured, driven through the whole path at once:
	# a second entry for something already inventoried, a relative-path component
	# that was never a dependency, and an entry with no usable version. The gate
	# passes because `sbom.sh` normalises them — which is the integration this
	# suite can assert and `tests/sbom.bats` asserts component by component.
	#
	# This case cannot show the clause FIRING, and that is a property of the design
	# rather than a gap: the clause and the normaliser share one identity rule, so
	# after a successful normalisation there is nothing left to find. The firing
	# proof is the `#MUTANT` row on the normalise call in `sbom.sh`.
	: >"$BATS_TEST_TMPDIR/syft.duplicate"
	: >"$BATS_TEST_TMPDIR/syft.pathlike"
	: >"$BATS_TEST_TMPDIR/syft.unversioned"
	run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"each a distinct thing"* ]]
}

@test "a document that DESCRIBES nothing is could-not-look, not a clean inventory" {
	# The subject is what the identity clause exempts, so without it every count is
	# measured over the wrong set. Reporting green there would be a verdict reached
	# by not looking — exit 2, the same answer this gate gives for a missing
	# Cargo.lock.
	: >"$BATS_TEST_TMPDIR/syft.nodescribes"
	run "$CHECK"
	[ "$status" -eq 2 ]
	[[ "$output" == *"no DESCRIBES"* ]]
}

@test "THE DRIFT DETECTOR: a pin with no table row fails, which is how a bump arrives" {
	# The reason a committed table is defensible at all. A pinned action's license
	# is immutable, so recording it is a property of this commit — but only while
	# the table still describes the pins the workflows carry. This fires on the one
	# event that breaks that, and it is the direction it will actually be hit: a
	# renovate bump moves a sha, and the row that named the old one no longer
	# matches.
	mkdir -p "$ROOT/.github/workflows"
	printf 'jobs:\n  a:\n    steps:\n      - uses: some/action@%040d\n' 1 >"$ROOT/.github/workflows/w.yml"
	printf 'some/action\t%040d\tMIT\tCopyright (c) 2020 Someone\n' 2 >"$ROOT/actions.tsv"
	SBOM_ACTIONS_TABLE="$ROOT/actions.tsv" run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"sbom-action-unmapped"* ]]
	# Pointer-only: the workflow file and line, never a license or a holder.
	[[ "$output" == *".github/workflows/w.yml"* ]]
	[[ "$output" != *"Copyright (c) 2020"* ]]
}

@test "this repo's real tree satisfies the gate — with the real syft" {
	# The self-consumption case. The stub proves the logic; this proves the logic
	# is pointed at a tree and a toolchain that actually satisfy it, which is the
	# only way the suite can also assert the committed pin works.
	unset SBOM_ROOT
	# And the real registry cache: `setup` points CARGO_HOME at a fixture holding
	# only the stub's crates, which for the real tree would be an absent-source
	# refusal rather than a verdict about the document.
	unset CARGO_HOME
	PATH="${PATH#"$STUB":}"
	export PATH
	cd "$BATS_TEST_DIRNAME/.." || return 1
	run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"matching Cargo.lock"* ]]
}
