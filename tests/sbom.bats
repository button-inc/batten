#!/usr/bin/env bats
# subject: mise-tasks/sbom.sh
# sbom's component-identity normalization (CLOUD-664): does the produced inventory
# carry one entry per thing this repository depends on, rather than one per place
# that thing is referenced?
#
# This suite exists because `sbom.sh` had none. Its output was covered only through
# `sbom-check`, which re-runs it — and that is exactly the wrong instrument for the
# normalizer, because the gate's inflation clause and the normalizer share one
# identity rule. Post-normalization the clause cannot fire, so a suite driving the
# gate can only ever observe agreement. Asserting on `sbom.sh`'s own output is what
# distinguishes "normalized" from "compared against itself"; the clause's own
# firing proof is the `#MUTANT` row on the call this suite covers.
#
# Driven against a stubbed `syft`, which is the only way to produce the inflated
# shapes on demand: the real cataloger's output depends on how many times a
# workflow happens to reference an action, so a fixture built from it would assert
# whatever this repository's workflows looked like that week.

setup() {
	SBOM="$BATS_TEST_DIRNAME/../mise-tasks/sbom.sh"
	STUB="$BATS_TEST_TMPDIR/bin"
	mkdir -p "$STUB"
	PATH="$STUB:$PATH"
	export PATH

	ROOT="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$ROOT"
	printf 'version = "9.9.9"\n' >"$ROOT/Cargo.toml"
	export SBOM_ROOT="$ROOT"
	export SBOM_OUT_DIR="$BATS_TEST_TMPDIR/out"
	stub_syft
	# The supplier/originator pass reads `cargo metadata`, so every case needs one
	# — including the identity cases below, which care about nothing it returns. It
	# answers for exactly the packages the default syft fixture catalogs.
	stub_cargo '[{"name":"batten","version":"9.9.9","source":null,"authors":["Button Inc."]},{"name":"crate0","version":"1.0.0","source":"registry+https://github.com/rust-lang/crates.io-index","authors":["Someone"]}]'
}

# A `syft` reproducing the three shapes CLOUD-664 measured, plus the two roles that
# must survive normalization.
#
# The document's own subject and the workspace member share a triple — `(batten,
# 9.9.9, "")` — and that is not a fixture convenience: syft 1.50.0 stopped emitting
# a registry purl for a local workspace package (anchore/syft#5105), so on the real
# tree they are genuinely indistinguishable by triple. A normalizer that deduped
# them would delete the thing `DESCRIBES` points at.
stub_syft() {
	cat >"$STUB/syft" <<EOF
#!/usr/bin/env bash
set -euo pipefail

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

# Two references to ONE action, the shape that produced 57 entries for 9 actions;
# one real crate; a relative-path component that was never a dependency; the
# workspace member; and the document subject that shares its triple.
cat >"\$spdx" <<'JSON'
{"SPDXID":"SPDXRef-DOCUMENT","name":"batten",
 "documentNamespace":"https://example.invalid/syft/1",
 "creationInfo":{"created":"2026-08-10T00:00:00Z"},
 "packages":[
   {"SPDXID":"SPDXRef-DocumentRoot-Directory-batten","name":"batten","versionInfo":"9.9.9"},
   {"SPDXID":"SPDXRef-Package-rust-crate-batten-aaa","name":"batten","versionInfo":"9.9.9"},
   {"SPDXID":"SPDXRef-Package-crate0","name":"crate0","versionInfo":"1.0.0",
    "externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:cargo/crate0@1.0.0"}]},
   {"SPDXID":"SPDXRef-Package-action-bbb","name":"actions/checkout","versionInfo":"v7",
    "externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:github/actions/checkout@v7"}]},
   {"SPDXID":"SPDXRef-Package-action-aaa","name":"actions/checkout","versionInfo":"v7",
    "externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:github/actions/checkout@v7"}]},
   {"SPDXID":"SPDXRef-Package-local","name":"./action","versionInfo":"UNKNOWN",
    "supplier":"Organization: ."}
 ],
 "relationships":[
   {"spdxElementId":"SPDXRef-DOCUMENT","relatedSpdxElement":"SPDXRef-DocumentRoot-Directory-batten","relationshipType":"DESCRIBES"},
   {"spdxElementId":"SPDXRef-DocumentRoot-Directory-batten","relatedSpdxElement":"SPDXRef-Package-crate0","relationshipType":"CONTAINS"},
   {"spdxElementId":"SPDXRef-DocumentRoot-Directory-batten","relatedSpdxElement":"SPDXRef-Package-action-aaa","relationshipType":"CONTAINS"},
   {"spdxElementId":"SPDXRef-DocumentRoot-Directory-batten","relatedSpdxElement":"SPDXRef-Package-action-bbb","relationshipType":"CONTAINS"},
   {"spdxElementId":"SPDXRef-DocumentRoot-Directory-batten","relatedSpdxElement":"SPDXRef-Package-local","relationshipType":"CONTAINS"},
   {"spdxElementId":"SPDXRef-Package-crate0","relatedSpdxElement":"SPDXRef-Package-rust-crate-batten-aaa","relationshipType":"DEPENDENCY_OF"}
 ]}
JSON
cat >"\$cdx" <<'JSON'
{"serialNumber":"urn:uuid:0000-1",
 "metadata":{"timestamp":"2026-08-10T00:00:00Z",
             "component":{"bom-ref":"ref-root","name":"batten","version":"9.9.9"}},
 "components":[
   {"bom-ref":"ref-crate0","name":"crate0","version":"1.0.0","purl":"pkg:cargo/crate0@1.0.0"},
   {"bom-ref":"ref-action-bbb","name":"actions/checkout","version":"v7","purl":"pkg:github/actions/checkout@v7"},
   {"bom-ref":"ref-action-aaa","name":"actions/checkout","version":"v7","purl":"pkg:github/actions/checkout@v7"},
   {"bom-ref":"ref-local","name":"./action","version":"UNKNOWN"}
 ],
 "dependencies":[
   {"ref":"ref-root","dependsOn":["ref-crate0","ref-action-aaa","ref-action-bbb","ref-local"]},
   {"ref":"ref-action-bbb","dependsOn":[]}
 ]}
JSON
EOF
	chmod +x "$STUB/syft"
}

spdx_path() { echo "$BATS_TEST_TMPDIR/out/batten.spdx.json"; }
cdx_path() { echo "$BATS_TEST_TMPDIR/out/batten.cdx.json"; }

@test "one action referenced twice yields ONE component" {
	# The shape that produced 57 entries for 9 unique actions. Fails on raw syft
	# output, which yields one component per reference site.
	run "$SBOM"
	[ "$status" -eq 0 ]
	[ "$(jq '[.packages[] | select(.name == "actions/checkout")] | length' "$(spdx_path)")" -eq 1 ]
	[ "$(jq '[.components[] | select(.name == "actions/checkout")] | length' "$(cdx_path)")" -eq 1 ]
}

@test "the relative-path component is gone — it was never a dependency" {
	run "$SBOM"
	[ "$status" -eq 0 ]
	[ "$(jq '[.packages[] | select((.name // "") | startswith("./"))] | length' "$(spdx_path)")" -eq 0 ]
	[ "$(jq '[.components[] | select((.name // "") | startswith("./"))] | length' "$(cdx_path)")" -eq 0 ]
}

@test "THE GUARD: the document still DESCRIBES its subject, which shares a triple with the workspace member" {
	# The case that stops this being a corruption. Both `batten` entries are real
	# and are two ROLES — the document's subject and the dependency-graph node —
	# and since syft stopped emitting a workspace purl they are identical by
	# triple. A dedupe without the exemption eats whichever one sorts second, and
	# if that is the subject the document describes nothing at all.
	run "$SBOM"
	[ "$status" -eq 0 ]
	local subject
	subject=$(jq -r '[.relationships[] | select(.relationshipType == "DESCRIBES") | .relatedSpdxElement] | first' "$(spdx_path)")
	[ "$subject" = "SPDXRef-DocumentRoot-Directory-batten" ]
	[ "$(jq --arg s "$subject" '[.packages[] | select(.SPDXID == $s)] | length' "$(spdx_path)")" -eq 1 ]
	# And the graph node survives beside it, so its DEPENDENCY_OF edge still lands.
	[ "$(jq '[.packages[] | select(.SPDXID == "SPDXRef-Package-rust-crate-batten-aaa")] | length' "$(spdx_path)")" -eq 1 ]
	[ "$(jq '[.packages[] | select(.name == "batten")] | length' "$(spdx_path)")" -eq 2 ]
}

@test "no relationship is left dangling, and none is duplicated" {
	# Merging and dropping components rewrites the graph. A document whose edges
	# point at SPDXIDs it no longer carries is not a smaller inventory, it is an
	# invalid one — and the merge collapses two CONTAINS edges into one, which must
	# be deduplicated rather than left as a repeated edge.
	run "$SBOM"
	[ "$status" -eq 0 ]
	local dangling
	dangling=$(jq '
      ([.packages[].SPDXID] + [(.files // [])[].SPDXID] + ["SPDXRef-DOCUMENT"]) as $ids
      | [.relationships[]
         | select((([.spdxElementId] | inside($ids)) | not)
                  or (([.relatedSpdxElement] | inside($ids)) | not))] | length' "$(spdx_path)")
	[ "$dangling" -eq 0 ]
	[ "$(jq '.relationships | length' "$(spdx_path)")" -eq "$(jq '.relationships | unique | length' "$(spdx_path)")" ]
	# The fixture's four CONTAINS edges — crate0, both action reference sites, and
	# the relative path — become two: the relative path's edge goes with it, and
	# the two action edges collapse into one.
	[ "$(jq '[.relationships[] | select(.relationshipType == "CONTAINS")] | length' "$(spdx_path)")" -eq 2 ]
}

@test "the CycloneDX graph is rewritten too, not just its component list" {
	# `dependencies[].ref` and `.dependsOn` are that format's edges. A dropped or
	# merged bom-ref left inside them is the same invalidity as a dangling SPDX
	# relationship, in the format nothing else in this suite would catch.
	run "$SBOM"
	[ "$status" -eq 0 ]
	local refs
	refs=$(jq -c '[.components[]."bom-ref"] + [.metadata.component."bom-ref"]' "$(cdx_path)")
	[ "$(jq --argjson r "$refs" '[.dependencies[] | select(([.ref] | inside($r)) | not)] | length' "$(cdx_path)")" -eq 0 ]
	[ "$(jq --argjson r "$refs" '[.dependencies[] | (.dependsOn // [])[] | select(([.] | inside($r)) | not)] | length' "$(cdx_path)")" -eq 0 ]
	# The dropped `./action` left the root's dependsOn, and the two action refs
	# collapsed to one, so the root depends on two things rather than four.
	[ "$(jq '[.dependencies[] | select(.ref == "ref-root") | .dependsOn[]] | length' "$(cdx_path)")" -eq 2 ]
}

@test "every remaining component is a distinct thing" {
	# The invariant `sbom-check`'s clause reads, asserted here over the producer's
	# own output: entries equal distinct triples, once the subject is set aside.
	run "$SBOM"
	[ "$status" -eq 0 ]
	local counts
	counts=$(jq -r '
      ([.relationships[] | select(.relationshipType == "DESCRIBES") | .relatedSpdxElement] | first) as $subject
      | [.packages[] | select(.SPDXID != $subject)] as $c
      | "\($c | length) \($c | map([(.name // ""), (.versionInfo // ""),
            ([.externalRefs[]? | select(.referenceType == "purl") | .referenceLocator] | first // "")]) | unique | length)"' "$(spdx_path)")
	local entries distinct
	read -r entries distinct <<<"$counts"
	[ "$entries" -eq "$distinct" ]
}

@test "normalization is deterministic — two runs produce identical documents" {
	# `sbom-check` compares two scans byte for byte after stripping four volatile
	# fields. A normalizer that picked its canonical entry non-deterministically
	# would make that clause flap, so the canonical choice is the lexicographically
	# first SPDXID rather than whichever one came first out of the map.
	run "$SBOM"
	[ "$status" -eq 0 ]
	cp "$(spdx_path)" "$BATS_TEST_TMPDIR/first.json"
	run "$SBOM"
	[ "$status" -eq 0 ]
	run diff -q "$BATS_TEST_TMPDIR/first.json" "$(spdx_path)"
	[ "$status" -eq 0 ]
}

@test "--names answers without scanning, and reports the normalized asset paths" {
	# The release workflow and `release-assets-check` read the names from here. The
	# normalization must not have moved them.
	run "$SBOM" --names
	[ "$status" -eq 0 ]
	[[ "$output" == *"batten.spdx.json"* ]]
	[[ "$output" == *"batten.cdx.json"* ]]
	[ ! -f "$(spdx_path)" ]
}

# ─── CLOUD-630: supplier and originator are two fields with two authorities ───
#
# These drive a stubbed `cargo` as well as a stubbed `syft`, because the whole
# point is the mapping between what a manifest says and what the document claims,
# and the real workspace can only ever exercise one row of that table: every
# package here resolves to crates.io and 226 of 281 declare an author. A synthetic
# metadata fixture is the only way to reach a git source or an empty author list.

# A `cargo` whose `metadata` answers with the packages named in $1 (a JSON array),
# AND an unpacked registry cache holding a directory for each of them.
#
# The cache half is not a convenience: `sbom.sh` refuses to produce a document when
# a package the lockfile names has no unpacked source, deliberately, so a fixture
# declaring a dependency it does not materialise is testing that refusal rather
# than whatever it meant to test. Directories are created empty, which yields
# `NONE` — the cases that want a holder write one with `fake_crate`, and the case
# that wants the refusal uses `stub_cargo_uncached`.
stub_cargo() {
	stub_cargo_uncached "$1"
	local nv
	while read -r nv; do
		[ -n "$nv" ] || continue
		mkdir -p "$BATS_TEST_TMPDIR/cargo/registry/src/index.crates.io-fixture/$nv"
	done < <(jq -r '.[] | select(.source != null) | "\(.name)-\(.version)"' <<<"$1")
	export CARGO_HOME="$BATS_TEST_TMPDIR/cargo"
}

# The same stub with NO cache entries, so the absent-source refusal is reachable.
stub_cargo_uncached() {
	export CARGO_HOME="$BATS_TEST_TMPDIR/cargo"
	mkdir -p "$CARGO_HOME/registry/src/index.crates.io-fixture"
	cat >"$STUB/cargo" <<EOF
#!/usr/bin/env bash
set -euo pipefail
# A fetch is a no-op here: the fixture cache is already unpacked on disk.
[ "\${1:-}" != "fetch" ] || exit 0
if [ "\${1:-}" = "metadata" ]; then
	cat <<'JSON'
{"packages": $1}
JSON
	exit 0
fi
exit 1
EOF
	chmod +x "$STUB/cargo"
}

# A syft writing one cargo component per (name, version) given, so a metadata
# fixture and a document fixture can be varied together.
stub_syft_cargo() {
	cat >"$STUB/syft" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
spdx=""
want=0
for arg in "$@"; do
	if [ "$want" = 1 ]; then
		case "$arg" in
		spdx-json=*) spdx="${arg#spdx-json=}" ;;
		cyclonedx-json=*) cdx="${arg#cyclonedx-json=}" ;;
		esac
		want=0
		continue
	fi
	[ "$arg" = "--output" ] && want=1
done
mkdir -p "$(dirname "$spdx")"
cat "$SYFT_SPDX_FIXTURE" >"$spdx"
cat "$SYFT_CDX_FIXTURE" >"$cdx"
EOF
	chmod +x "$STUB/syft"
}

# One SPDX document carrying the named cargo components, plus the subject.
write_fixtures() {
	local pkgs="$1" comps="$2"
	cat >"$BATS_TEST_TMPDIR/spdx.fixture" <<JSON
{"SPDXID":"SPDXRef-DOCUMENT","name":"batten",
 "documentNamespace":"https://example.invalid/1",
 "creationInfo":{"created":"2026-08-10T00:00:00Z"},
 "packages":[{"SPDXID":"SPDXRef-DocumentRoot-Directory-batten","name":"batten","versionInfo":"9.9.9"},$pkgs],
 "relationships":[{"spdxElementId":"SPDXRef-DOCUMENT","relatedSpdxElement":"SPDXRef-DocumentRoot-Directory-batten","relationshipType":"DESCRIBES"}]}
JSON
	cat >"$BATS_TEST_TMPDIR/cdx.fixture" <<JSON
{"serialNumber":"urn:uuid:1","metadata":{"timestamp":"2026-08-10T00:00:00Z",
 "component":{"bom-ref":"ref-root","name":"batten","version":"9.9.9"}},
 "components":[$comps]}
JSON
	export SYFT_SPDX_FIXTURE="$BATS_TEST_TMPDIR/spdx.fixture"
	export SYFT_CDX_FIXTURE="$BATS_TEST_TMPDIR/cdx.fixture"
	stub_syft_cargo
}

# The document's own subject and the workspace member, which is the one package
# with no `source` at all.
supplier_of() { jq -r --arg n "$1" '[.packages[] | select(.name == $n) | .supplier // "ABSENT"] | first' "$(spdx_path)"; }
originator_of() { jq -r --arg n "$1" '[.packages[] | select(.name == $n) | .originator // "ABSENT"] | first' "$(spdx_path)"; }

@test "the document's own subject carries the workspace supplier, not NOASSERTION" {
	# CLOUD-630 §7's first case, and the gap a reader notices before any of the
	# hundreds of dependencies: the document said NOASSERTION about itself.
	printf 'version = "9.9.9"\nauthors = ["Button Inc."]\n' >"$ROOT/Cargo.toml"
	write_fixtures '{"SPDXID":"SPDXRef-P-a","name":"crate0","versionInfo":"1.0.0","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:cargo/crate0@1.0.0"}]}' '{"bom-ref":"r-a","name":"crate0","version":"1.0.0","purl":"pkg:cargo/crate0@1.0.0"}'
	stub_cargo '[{"name":"batten","version":"9.9.9","source":null,"authors":["Button Inc."]},{"name":"crate0","version":"1.0.0","source":"registry+https://github.com/rust-lang/crates.io-index","authors":["Someone"]}]'
	run "$SBOM"
	[ "$status" -eq 0 ]
	[ "$(supplier_of batten)" = "Organization: Button Inc." ]
}

@test "THE FIELD SPLIT: an empty authors array still gets a supplier, and NOASSERTION for originator" {
	# The case that fails under the design CLOUD-630 was filed against, where
	# `authors` was pushed into the supplier slot: 55 of 281 packages here declare
	# none, and every one of them would have gone supplier-less for a reason that
	# has nothing to do with who distributed it.
	printf 'version = "9.9.9"\nauthors = ["Button Inc."]\n' >"$ROOT/Cargo.toml"
	write_fixtures '{"SPDXID":"SPDXRef-P-a","name":"anon","versionInfo":"1.0.0","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:cargo/anon@1.0.0"}]}' '{"bom-ref":"r-a","name":"anon","version":"1.0.0","purl":"pkg:cargo/anon@1.0.0"}'
	stub_cargo '[{"name":"anon","version":"1.0.0","source":"registry+https://github.com/rust-lang/crates.io-index","authors":[]}]'
	run "$SBOM"
	[ "$status" -eq 0 ]
	[ "$(supplier_of anon)" = "Organization: crates.io" ]
	[ "$(originator_of anon)" = "NOASSERTION" ]
}

@test "a crate with authors gets both, and the originator is the author rather than the registry" {
	printf 'version = "9.9.9"\nauthors = ["Button Inc."]\n' >"$ROOT/Cargo.toml"
	write_fixtures '{"SPDXID":"SPDXRef-P-a","name":"written","versionInfo":"2.0.0","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:cargo/written@2.0.0"}]}' '{"bom-ref":"r-a","name":"written","version":"2.0.0","purl":"pkg:cargo/written@2.0.0"}'
	stub_cargo '[{"name":"written","version":"2.0.0","source":"registry+https://github.com/rust-lang/crates.io-index","authors":["A Real Author"]}]'
	run "$SBOM"
	[ "$status" -eq 0 ]
	[ "$(supplier_of written)" = "Organization: crates.io" ]
	[ "$(originator_of written)" = "Organization: A Real Author" ]
	[ "$(originator_of written)" != "$(supplier_of written)" ]
}

@test "a package whose source is NOT crates.io is never labelled crates.io" {
	# Every package in this tree resolves to crates.io today, so a git or path
	# dependency would be mislabelled and nothing would notice. Written now rather
	# than when someone adds one — which is the only moment it would otherwise be
	# discovered, in a published release.
	printf 'version = "9.9.9"\nauthors = ["Button Inc."]\n' >"$ROOT/Cargo.toml"
	write_fixtures '{"SPDXID":"SPDXRef-P-a","name":"forked","versionInfo":"3.0.0","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:cargo/forked@3.0.0"}]}' '{"bom-ref":"r-a","name":"forked","version":"3.0.0","purl":"pkg:cargo/forked@3.0.0"}'
	stub_cargo '[{"name":"forked","version":"3.0.0","source":"git+https://example.invalid/forked?rev=deadbeef","authors":["Forker"]}]'
	run "$SBOM"
	[ "$status" -eq 0 ]
	[ "$(supplier_of forked)" != "Organization: crates.io" ]
	[ "$(supplier_of forked)" = "NOASSERTION" ]
	# The originator is still known — who wrote it does not depend on who shipped it.
	[ "$(originator_of forked)" = "Organization: Forker" ]
}

@test "a semver build-metadata version still resolves, despite the purl encoding it" {
	# `toml 1.1.4+spec-1.1.0` reaches the document as
	# `pkg:cargo/toml@1.1.4%2Bspec-1.1.0`. A purl-keyed lookup missed all five such
	# packages in this tree and left them NOASSERTION, silently.
	printf 'version = "9.9.9"\nauthors = ["Button Inc."]\n' >"$ROOT/Cargo.toml"
	write_fixtures '{"SPDXID":"SPDXRef-P-a","name":"toml","versionInfo":"1.1.4+spec-1.1.0","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:cargo/toml@1.1.4%2Bspec-1.1.0"}]}' '{"bom-ref":"r-a","name":"toml","version":"1.1.4+spec-1.1.0","purl":"pkg:cargo/toml@1.1.4%2Bspec-1.1.0"}'
	stub_cargo '[{"name":"toml","version":"1.1.4+spec-1.1.0","source":"registry+https://github.com/rust-lang/crates.io-index","authors":["Toml Author"]}]'
	run "$SBOM"
	[ "$status" -eq 0 ]
	[ "$(supplier_of toml)" = "Organization: crates.io" ]
}

@test "an action's own supplier is never overwritten by the cargo pass" {
	# syft derives supplier and originator for a `pkg:github` entry from the
	# action's namespace owner, which is more specific than anything the cargo pass
	# knows. Replacing it would be a regression dressed as enrichment.
	printf 'version = "9.9.9"\nauthors = ["Button Inc."]\n' >"$ROOT/Cargo.toml"
	write_fixtures '{"SPDXID":"SPDXRef-P-a","name":"actions/checkout","versionInfo":"v7","supplier":"Organization: GitHub","originator":"Organization: GitHub","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:github/actions/checkout@v7"}]}' '{"bom-ref":"r-a","name":"actions/checkout","version":"v7","purl":"pkg:github/actions/checkout@v7"}'
	stub_cargo '[{"name":"actions/checkout","version":"v7","source":"registry+https://github.com/rust-lang/crates.io-index","authors":["Wrong"]}]'
	run "$SBOM"
	[ "$status" -eq 0 ]
	[ "$(supplier_of actions/checkout)" = "Organization: GitHub" ]
	[ "$(originator_of actions/checkout)" = "Organization: GitHub" ]
}

# ─── CLOUD-629: copyright, read from the bytes the lockfile pins ──────────────
#
# These point `CARGO_HOME` at a synthetic registry cache, which is the only way to
# reach the cases that matter: the real cache contains whatever crates this tree
# happens to depend on, so a fixture built from it would assert this week's
# dependency set rather than the rule.

# An unpacked crate source under a fake CARGO_HOME, with $2 as the contents of the
# file named $3 (default LICENSE).
fake_crate() {
	local nameversion="$1" body="$2" file="${3:-LICENSE}"
	local dir="$BATS_TEST_TMPDIR/cargo/registry/src/index.crates.io-fixture/$nameversion"
	mkdir -p "$dir/$(dirname "$file")"
	printf '%s' "$body" >"$dir/$file"
	export CARGO_HOME="$BATS_TEST_TMPDIR/cargo"
}

copyright_of() { jq -r --arg n "$1" '[.packages[] | select(.name == $n) | .copyrightText // "ABSENT"] | first' "$(spdx_path)"; }

@test "THE BOILERPLATE TRAP: an Apache-2.0 LICENSE yields NONE, never the license prose" {
	# Two distinct failures meet in this one case. A loose extractor greps for the
	# word and writes `copyright notice that is included in or attached to the work`
	# — a fragment of the Apache-2.0 text — into the field, asserting license prose
	# as a copyright statement. A timid one writes NOASSERTION and forfeits
	# conformance for data it actually read. Neither is acceptable and only this
	# fixture separates them.
	printf 'version = "9.9.9"\nauthors = ["Button Inc."]\n' >"$ROOT/Cargo.toml"
	fake_crate "boiler-1.0.0" '   Apache License
   Version 2.0, January 2004

   4. Redistribution. You may reproduce and distribute copies of the Work
      provided that You retain, in the Source form of any Derivative Works
      that You distribute, all copyright, patent, trademark, and attribution
      notices from the Source form of the Work, and You must include a
      copyright notice that is included in or attached to the work.
'
	write_fixtures '{"SPDXID":"SPDXRef-P-a","name":"boiler","versionInfo":"1.0.0","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:cargo/boiler@1.0.0"}]}' '{"bom-ref":"r-a","name":"boiler","version":"1.0.0","purl":"pkg:cargo/boiler@1.0.0"}'
	stub_cargo '[{"name":"boiler","version":"1.0.0","source":"registry+https://github.com/rust-lang/crates.io-index","authors":["Someone"]}]'
	run "$SBOM"
	[ "$status" -eq 0 ]
	[ "$(copyright_of boiler)" = "NONE" ]
	[[ "$(copyright_of boiler)" != *"notice that is included in or attached"* ]]
}

@test "an MIT-style LICENSE yields exactly its holder line" {
	printf 'version = "9.9.9"\nauthors = ["Button Inc."]\n' >"$ROOT/Cargo.toml"
	fake_crate "aho-1.1.5" 'Copyright (c) 2015 Andrew Gallant

Permission is hereby granted, free of charge, to any person obtaining a copy
'
	write_fixtures '{"SPDXID":"SPDXRef-P-a","name":"aho","versionInfo":"1.1.5","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:cargo/aho@1.1.5"}]}' '{"bom-ref":"r-a","name":"aho","version":"1.1.5","purl":"pkg:cargo/aho@1.1.5"}'
	stub_cargo '[{"name":"aho","version":"1.1.5","source":"registry+https://github.com/rust-lang/crates.io-index","authors":["Andrew Gallant"]}]'
	run "$SBOM"
	[ "$status" -eq 0 ]
	[ "$(copyright_of aho)" = "Copyright (c) 2015 Andrew Gallant" ]
}

@test "a holder outside the license files is still found, and a comment marker is stripped" {
	# Measured 2026-08-23: 4 of the 11 crates shipping no license file at all do
	# state a holder elsewhere in their pinned tree. A license-files-only rule
	# writes NONE over data the checksum-pinned bytes actually carry, which is the
	# timid failure in its other form.
	printf 'version = "9.9.9"\nauthors = ["Button Inc."]\n' >"$ROOT/Cargo.toml"
	fake_crate "headered-1.0.0" '// Copyright 2015, Yuheng Chen.
// Licensed under whatever.
fn main() {}
' "src/lib.rs"
	write_fixtures '{"SPDXID":"SPDXRef-P-a","name":"headered","versionInfo":"1.0.0","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:cargo/headered@1.0.0"}]}' '{"bom-ref":"r-a","name":"headered","version":"1.0.0","purl":"pkg:cargo/headered@1.0.0"}'
	stub_cargo '[{"name":"headered","version":"1.0.0","source":"registry+https://github.com/rust-lang/crates.io-index","authors":["Chen"]}]'
	run "$SBOM"
	[ "$status" -eq 0 ]
	[ "$(copyright_of headered)" = "Copyright 2015, Yuheng Chen." ]
}

@test "a lockfile package absent from the cache is a HARD FAILURE, not a NOASSERTION" {
	# Availability is the one thing about the registry cache that really is machine
	# state, and this is the mechanism that keeps it from leaking into the document.
	# Emitting NOASSERTION here would make the artifact's contents depend on how
	# warm this machine's cache is — the property-of-the-world failure the whole
	# admissibility argument turns on.
	printf 'version = "9.9.9"\nauthors = ["Button Inc."]\n' >"$ROOT/Cargo.toml"
	fake_crate "present-1.0.0" 'Copyright (c) 2020 Someone'
	write_fixtures '{"SPDXID":"SPDXRef-P-a","name":"absent","versionInfo":"2.0.0","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:cargo/absent@2.0.0"}]}' '{"bom-ref":"r-a","name":"absent","version":"2.0.0","purl":"pkg:cargo/absent@2.0.0"}'
	stub_cargo_uncached '[{"name":"absent","version":"2.0.0","source":"registry+https://github.com/rust-lang/crates.io-index","authors":["Nobody"]}]'
	run "$SBOM"
	[ "$status" -eq 1 ]
	[[ "$output" == *"no unpacked source"* ]]
	# Pointer-only: a count, never the crate name.
	[[ "$output" != *"absent-2.0.0"* ]]
}

@test "the copyright pass is deterministic across two runs" {
	# The most-frequent-line rule breaks ties on the sorted line precisely so that
	# `sbom-check`'s byte comparison of two scans holds.
	printf 'version = "9.9.9"\nauthors = ["Button Inc."]\n' >"$ROOT/Cargo.toml"
	fake_crate "multi-1.0.0" 'Copyright (c) 2020 First Holder
Copyright (c) 2021 Second Holder
Copyright (c) 2021 Second Holder
'
	write_fixtures '{"SPDXID":"SPDXRef-P-a","name":"multi","versionInfo":"1.0.0","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:cargo/multi@1.0.0"}]}' '{"bom-ref":"r-a","name":"multi","version":"1.0.0","purl":"pkg:cargo/multi@1.0.0"}'
	stub_cargo '[{"name":"multi","version":"1.0.0","source":"registry+https://github.com/rust-lang/crates.io-index","authors":["Someone"]}]'
	run "$SBOM"
	[ "$status" -eq 0 ]
	local first
	first="$(copyright_of multi)"
	run "$SBOM"
	[ "$status" -eq 0 ]
	[ "$(copyright_of multi)" = "$first" ]
	# The license file is authoritative, so its FIRST anchored line wins there —
	# the frequency rule is the fallback for crates whose license files carry none.
	[ "$first" = "Copyright (c) 2020 First Holder" ]
}

# ─── CLOUD-628: license, from the one source already trusted here ─────────────

license_of() { jq -r --arg n "$1" '[.packages[] | select(.name == $n) | .licenseConcluded // "ABSENT"] | first' "$(spdx_path)"; }
declared_of() { jq -r --arg n "$1" '[.packages[] | select(.name == $n) | .licenseDeclared // "ABSENT"] | first' "$(spdx_path)"; }

@test "a manifest license reaches BOTH SPDX license fields" {
	# `licenseDeclared` is what the package states and `licenseConcluded` is the
	# conclusion drawn from it. Concluding the declaration is defensible precisely
	# because `deny.toml` already gates on the same expression; withholding the
	# conclusion while the declaration sits beside it would be a document declining
	# to say what the repository acts on everywhere else.
	printf 'version = "9.9.9"\nauthors = ["Button Inc."]\n' >"$ROOT/Cargo.toml"
	write_fixtures '{"SPDXID":"SPDXRef-P-a","name":"licensed","versionInfo":"1.0.0","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:cargo/licensed@1.0.0"}]}' '{"bom-ref":"r-a","name":"licensed","version":"1.0.0","purl":"pkg:cargo/licensed@1.0.0"}'
	stub_cargo '[{"name":"licensed","version":"1.0.0","source":"registry+https://github.com/rust-lang/crates.io-index","authors":["Someone"],"license":"Apache-2.0 OR MIT"}]'
	run "$SBOM"
	[ "$status" -eq 0 ]
	[ "$(license_of licensed)" = "Apache-2.0 OR MIT" ]
	[ "$(declared_of licensed)" = "Apache-2.0 OR MIT" ]
	[ "$(jq -r '[.components[] | select(.name == "licensed") | .licenses[0].expression] | first' "$(cdx_path)")" = "Apache-2.0 OR MIT" ]
}

@test "the deprecated slash spelling is rewritten to OR, because it is not valid SPDX" {
	# Measured 2026-08-23: 10 packages in this tree still use it. `Apache-2.0/MIT`
	# is not a parseable SPDX license expression, so writing it verbatim would put
	# an unreadable value in a field whose entire purpose is to be read. The
	# rewrite is a documented equivalence — the cargo manifest reference defines the
	# slash as the deprecated spelling of OR — rather than an interpretation.
	printf 'version = "9.9.9"\nauthors = ["Button Inc."]\n' >"$ROOT/Cargo.toml"
	write_fixtures '{"SPDXID":"SPDXRef-P-a","name":"slashy","versionInfo":"1.0.0","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:cargo/slashy@1.0.0"}]}' '{"bom-ref":"r-a","name":"slashy","version":"1.0.0","purl":"pkg:cargo/slashy@1.0.0"}'
	stub_cargo '[{"name":"slashy","version":"1.0.0","source":"registry+https://github.com/rust-lang/crates.io-index","authors":["Someone"],"license":"Apache-2.0 / MIT"}]'
	run "$SBOM"
	[ "$status" -eq 0 ]
	[ "$(license_of slashy)" = "Apache-2.0 OR MIT" ]
	[[ "$(license_of slashy)" != *"/"* ]]
}

@test "HONEST ABSENCE: an empty manifest license leaves NOASSERTION rather than guessing" {
	# 0 of 281 packages in this tree have an empty `license`, so nothing real
	# exercises this path and only a synthetic fixture can reach it — which is
	# exactly the guessing this row exists not to do.
	printf 'version = "9.9.9"\nauthors = ["Button Inc."]\n' >"$ROOT/Cargo.toml"
	write_fixtures '{"SPDXID":"SPDXRef-P-a","name":"unlicensed","versionInfo":"1.0.0","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:cargo/unlicensed@1.0.0"}]}' '{"bom-ref":"r-a","name":"unlicensed","version":"1.0.0","purl":"pkg:cargo/unlicensed@1.0.0"}'
	stub_cargo '[{"name":"unlicensed","version":"1.0.0","source":"registry+https://github.com/rust-lang/crates.io-index","authors":["Someone"]}]'
	run "$SBOM"
	[ "$status" -eq 0 ]
	[ "$(license_of unlicensed)" = "NOASSERTION" ]
	# And CycloneDX carries no licenses entry at all rather than an empty one.
	[ "$(jq -r '[.components[] | select(.name == "unlicensed") | .licenses] | first // "ABSENT"' "$(cdx_path)")" = "ABSENT" ]
}

@test "an action keeps whatever license syft gave it — the cargo pass does not reach it" {
	printf 'version = "9.9.9"\nauthors = ["Button Inc."]\n' >"$ROOT/Cargo.toml"
	write_fixtures '{"SPDXID":"SPDXRef-P-a","name":"actions/checkout","versionInfo":"v7","licenseConcluded":"NOASSERTION","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:github/actions/checkout@v7"}]}' '{"bom-ref":"r-a","name":"actions/checkout","version":"v7","purl":"pkg:github/actions/checkout@v7"}'
	stub_cargo '[{"name":"actions/checkout","version":"v7","source":"registry+https://github.com/rust-lang/crates.io-index","authors":["Wrong"],"license":"WRONG-LICENSE"}]'
	run "$SBOM"
	[ "$status" -eq 0 ]
	[ "$(license_of actions/checkout)" = "NOASSERTION" ]
}

@test "a cargo metadata that cannot run fails rather than shipping NOASSERTION" {
	printf 'version = "9.9.9"\nauthors = ["Button Inc."]\n' >"$ROOT/Cargo.toml"
	write_fixtures '{"SPDXID":"SPDXRef-P-a","name":"crate0","versionInfo":"1.0.0","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:cargo/crate0@1.0.0"}]}' '{"bom-ref":"r-a","name":"crate0","version":"1.0.0","purl":"pkg:cargo/crate0@1.0.0"}'
	# `fetch` succeeds and `metadata` does not, because the fetch runs first: a
	# stub that failed both would exercise the fetch refusal and assert the
	# metadata one, which is a case that passes for the wrong reason.
	cat >"$STUB/cargo" <<'EOF'
#!/usr/bin/env bash
[ "${1:-}" != "fetch" ] || exit 0
exit 1
EOF
	chmod +x "$STUB/cargo"
	run "$SBOM"
	[ "$status" -eq 1 ]
	[[ "$output" == *"could not read cargo metadata"* ]]
}

@test "a syft that cannot run produces no document and fails" {
	cat >"$STUB/syft" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
	chmod +x "$STUB/syft"
	run "$SBOM"
	[ "$status" -eq 1 ]
	[[ "$output" == *"could not scan"* ]]
}
