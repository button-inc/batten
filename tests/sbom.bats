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
