#!/usr/bin/env bash
#MISE description="Effect: derive the SPDX and CycloneDX inventories of this tree, under the names the release assets carry"
#
# CLOUD-262. Batten publishes seven archives plus `batten.schema.json` per release
# and, before this, no inventory of any kind — no SPDX, no CycloneDX, no checksum
# file. A policy engine whose thesis is verifiable claims about what shipped cannot
# answer "what is in v0.0.38", so the inventory ships as an artifact of record: cut
# from the tagged source at release time and attached to the release.
#
# `deny.toml` already judges this dependency tree — licenses, advisories, yanked
# crates. A verdict is not an inventory: "does it pass" and "what is in it" are
# different questions, and only the first had an answer here.
#
# ONE definition of the invocation, the exclude list and the asset names, the way
# `mise-tasks/dist.sh` owns archive naming. `release-artifacts.yml` owns only the
# upload, and `sbom-check` re-runs THIS script rather than restating the flags — so
# the bytes a gate judges are the bytes a release publishes.
#
# The exclude list is load-bearing, not tidiness. Measured 2026-08-10 on this tree:
# a bare `dir:` scan finds 43 github-action packages, but 23 of them come from the
# vendored `tests/bats` submodule, which `actions/checkout` in the release job does
# not fetch. Without the exclude, a regenerate-and-compare gate passes locally and
# publishes a different tree — the defect this must not ship.
#
# Both `--source-name` and `--source-version` are required for the artifact to
# describe itself. With neither, both formats label their subject `.` — the scan
# directory — and an inventory that cannot say what it inventories is not one. The
# version is read from the manifest, never passed in, for the reason `dist`'s
# `crate_version` records: an artifact whose label disagrees with its contents is
# worse than one with no label.
#
# Scope of the claim, stated because overclaiming here is the failure mode: this
# describes the REPOSITORY at the tag, not the shipped binary. A binary-level
# inventory needs the compiler's own record, and is CLOUD-263.
#
# The normalization is where this file can silently stop doing its job, and it is
# the one thing `sbom-check`'s own inflation clause cannot prove: that clause and
# the normalizer share an identity rule, so after a successful normalization the
# clause has nothing to find and agreement means nothing. Removing each call is
# what shows the suite discriminates.
#MUTANT sbom-skips-spdx-normalization|s@^\tif ! normalize "\$spdx" "\$SPDX_NORMALIZE"; then@\tif false; then@|one action referenced twice yields ONE component
#MUTANT sbom-skips-cdx-normalization|s@^\tif ! normalize "\$cdx" "\$CDX_NORMALIZE"; then@\tif false; then@|the CycloneDX graph is rewritten too
# And the guard that keeps the dedupe from corrupting the document: with the
# subject no longer exempt it shares a triple with the workspace member and one of
# them is deleted, which for the subject means the document describes nothing.
#MUTANT sbom-dedupes-the-subject|s@select(.relationshipType == "DESCRIBES")@select(false)@|THE GUARD
set -euo pipefail

cd "${SBOM_ROOT:-$(git rev-parse --show-toplevel)}"

readonly BIN=batten

# Where the documents land. Overridable so `sbom-check` can run this twice into two
# scratch directories without ever writing the tree it judges.
OUT_DIR="${SBOM_OUT_DIR:-sbom}"

# Paths the scan must not descend: a vendored submodule the release checkout does
# not fetch, build output that is not part of the source, and the fuzz harness.
#
# `./fuzz` is a DETACHED workspace with its own Cargo.lock (CLOUD-112), and both
# halves of that matter here. Nothing in it is published — it is a development
# harness, no more part of the shipped artifact than `tests/` is — so cataloging
# it would make the inventory overstate what a consumer receives, which is the
# false claim this document exists not to make. It would also break the
# `sbom-package-drift` invariant by construction: that clause compares the
# cargo count against the ROOT `Cargo.lock`, and a second lockfile in scope adds
# packages no root lockfile names (measured: 175 -> 281).
readonly EXCLUDES=(--exclude ./tests/bats --exclude ./target --exclude ./fuzz)

# Read with awk rather than `sed | head`, which under `pipefail` can report the
# producer's SIGPIPE as the pipeline's status (mem:toolchain-and-hooks). `exit`
# after the first match does the same job with no pipe to lose a status through.
crate_version() {
	local version
	version=$(awk -F'"' '/^version = "/ { print $2; exit }' Cargo.toml)
	if [[ -z "$version" ]]; then
		echo "::error:: sbom: could not read a version from Cargo.toml" >&2
		return 1
	fi
	printf '%s' "$version"
}

# --- component identity: one entry per thing this repository depends on --------
#
# CLOUD-664. syft emits a component per REFERENCE SITE, not per dependency, so
# the document overstated what this repository depends on: measured 2026-08-23 on
# syft 1.51.0, 340 entries for 290 distinct things — 57 `pkg:github` entries for 9
# unique actions (`actions/checkout` alone appearing 22 times), plus a `./action`
# component that is a relative path in this repository rather than a dependency of
# it. The denominator every conformance count is computed over was the inflated
# number, so a reader could not answer the one question an inventory exists to
# answer.
#
# Identity is the triple `(name, versionInfo, purl)`. A post-process rather than a
# syft setting because syft has no configuration for this — the github-actions
# cataloger's per-site emission is not a flag — and it runs HERE so that one
# script still decides what the documents contain (§1), which is what lets
# `sbom-check` and `ntia-check` re-run this and judge the bytes a release
# publishes.
#
# ─── THE SUBJECT IS NEVER MERGED, AND THIS GUARD IS THE WHOLE CORRECTNESS ARGUMENT
#
# CLOUD-664's body reads "the root package is listed twice" and asks for one
# entry. Both entries are real and they are not duplicates — they are two ROLES:
#
#   SPDXRef-DocumentRoot-Directory-batten     the document's SUBJECT. `DESCRIBES`
#                                             targets it, and it is the sole
#                                             source of all 339 `CONTAINS` edges.
#   SPDXRef-Package-rust-crate-batten-…       the workspace member as a node in
#                                             the dependency graph, carrying 27
#                                             `DEPENDENCY_OF` edges.
#
# Deleting either corrupts the document: without the subject it describes
# nothing, and without the graph node 27 edges dangle. And they are now
# INDISTINGUISHABLE BY TRIPLE — syft 1.50.0 stopped emitting a registry purl for a
# local workspace package (anchore/syft#5105, correctly: `batten` is
# `publish = false` and is in no registry), so both are `(batten, 0.0.106, "")`.
# A naive dedupe therefore silently eats the subject. The subject is resolved from
# the document's own `DESCRIBES` edge and excluded, rather than matched by name or
# by SPDXID shape, so this keeps holding if syft renames either one.
#
# No purl is synthesised for the workspace member. It is in no registry, so a
# registry coordinate would be a claim about the world that is false — the exact
# thing this document exists not to do. `sbom-check`'s cargo-count clause accounts
# for it instead.
#
# Removal is confined to entries that can never be enriched because there is
# nothing to enrich: a relative-path name, or `versionInfo: UNKNOWN`. Nothing that
# resolves to a real dependency leaves the inventory, which is the line CLOUD-608
# drew when it declined to buy conformance by narrowing scope.
# shellcheck disable=SC2016  # a jq program: `$subject` and friends are jq bindings, not shell
readonly SPDX_NORMALIZE='
  # The subject, from the document rather than by name: never merged, never dropped.
  ([.relationships[]? | select(.relationshipType == "DESCRIBES") | .relatedSpdxElement] | first) as $subject
  | def ident: [(.name // ""), (.versionInfo // ""),
                ([.externalRefs[]? | select(.referenceType == "purl") | .referenceLocator] | first // "")];
    # An entry with no SPDXID is left strictly alone: nothing can reference it, so
    # merging it would rewrite no edge, and it cannot be a key in the rename map at
    # all. Guarded rather than assumed — a package without one crashed this
    # program, and "the real cataloger always emits SPDXID" is exactly the kind of
    # assumption a cataloger release breaks.
    def rid: (.SPDXID // "");
    # Entries with nothing to enrich. The subject is exempt: it is the document,
    # not a dependency, whatever its version string looks like.
    [.packages[]? | select(rid != "") | select(rid != $subject)
     | select(((.name // "") | startswith("./")) or ((.versionInfo // "") == "UNKNOWN"))
     | rid] as $dropped
  | (reduce (.packages[]?
      | select(rid != "") | select(rid != $subject)
      | select([rid] | inside($dropped) | not))
      as $p ({}; .[($p | ident | tojson)] += [$p | rid])) as $by_ident
    # Canonical = the lexicographically first SPDXID of the group, so two runs of
    # syft over one tree normalise identically — `sbom-check` compares the bytes.
  | (reduce ($by_ident | to_entries[]) as $g ({};
      ($g.value | sort) as $ids | reduce $ids[1:][] as $id (.; .[$id] = $ids[0]))) as $merged
  | ($dropped | map({(.): true}) | add // {}) as $gone
  | .packages = [.packages[]? | select(($gone[rid] // false) | not)
                              | select(($merged[rid] // rid) == rid)]
  | .relationships = ([.relationships[]?
      | select((($gone[.spdxElementId] // false) or ($gone[.relatedSpdxElement] // false)) | not)
      | .spdxElementId = ($merged[.spdxElementId] // .spdxElementId)
      | .relatedSpdxElement = ($merged[.relatedSpdxElement] // .relatedSpdxElement)]
      | unique)
'

# The same identity rule over CycloneDX, whose graph is `dependencies[].ref` and
# `.dependsOn` rather than SPDX relationships. `metadata.component` is this
# format's subject and is not in `.components` at all, so it needs no exemption.
# shellcheck disable=SC2016  # a jq program: `$subject` and friends are jq bindings, not shell
readonly CDX_NORMALIZE='
  def ident: [(.name // ""), (.version // ""), (.purl // "")];
    # Same guard as the SPDX arm: a component with no `bom-ref` is referenced by
    # nothing and is left alone rather than keyed by null.
    def rid: (."bom-ref" // "");
    [.components[]? | select(rid != "")
     | select(((.name // "") | startswith("./")) or ((.version // "") == "UNKNOWN"))
     | rid] as $dropped
  | (reduce (.components[]? | select(rid != "") | select([rid] | inside($dropped) | not))
      as $c ({}; .[($c | ident | tojson)] += [$c | rid])) as $by_ident
  | (reduce ($by_ident | to_entries[]) as $g ({};
      ($g.value | sort) as $ids | reduce $ids[1:][] as $id (.; .[$id] = $ids[0]))) as $merged
  | ($dropped | map({(.): true}) | add // {}) as $gone
  | .components = [.components[]? | select(($gone[rid] // false) | not)
                                  | select(($merged[rid] // rid) == rid)]
  | if has("dependencies") then
      .dependencies = ([.dependencies[]?
        | select(($gone[.ref] // false) | not)
        | .ref = ($merged[.ref] // .ref)
        | if has("dependsOn") then
            .dependsOn = ([.dependsOn[]? | select(($gone[.] // false) | not)
                                         | ($merged[.] // .)] | unique)
          else . end]
        | group_by(.ref) | map(.[0] + {dependsOn: ([.[].dependsOn // []] | add | unique)}))
    else . end
'

# Applied in place, via a temporary file: a partial write must not leave a
# truncated document where a valid one was, since `sbom-check` re-runs this and
# would report an unparseable file rather than a normalisation defect.
normalize() {
	local doc="$1" program="$2" tmp
	tmp="${doc}.normalizing"
	if ! jq "$program" "$doc" >"$tmp"; then
		rm -f "$tmp"
		echo "::error:: sbom: could not normalise component identity in ${doc##*/}, so the inventory would overstate what this repository depends on" >&2
		return 1
	fi
	mv "$tmp" "$doc"
}

main() {
	local version spdx cdx

	# Named without the version, so `releases/latest/download/<name>` resolves —
	# the `batten.schema.json` precedent `.taplo.toml` already depends on. The
	# version travels inside the document instead, via --source-version.
	spdx="${OUT_DIR}/${BIN}.spdx.json"
	cdx="${OUT_DIR}/${BIN}.cdx.json"

	# `--names` answers "what does a release call these?" without paying for a
	# scan, so `release-assets-check` derives the names from the one file that
	# decides them rather than restating them. Before the manifest read, so it
	# answers from any directory.
	if [[ "${1:-}" = "--names" ]]; then
		echo "spdx=$spdx"
		echo "cdx=$cdx"
		return 0
	fi

	version=$(crate_version)
	mkdir -p "$OUT_DIR"

	# One scan, both formats: the catalogers run once and each output is a
	# rendering of that one result, so the second format costs nothing.
	if ! syft scan "dir:." "${EXCLUDES[@]}" \
		--source-name "$BIN" --source-version "$version" \
		--output "spdx-json=${spdx}" --output "cyclonedx-json=${cdx}" --quiet; then
		echo "::error:: sbom: syft could not scan the tree, so no inventory was produced" >&2
		return 1
	fi

	# One entry per thing depended on, not one per reference site (CLOUD-664).
	# Guarded rather than called bare: a task body does not run under `set -e`
	# where it is invoked through mise, and a failed normalisation must not leave
	# an inflated document behind a success.
	if ! normalize "$spdx" "$SPDX_NORMALIZE"; then
		return 1
	fi
	if ! normalize "$cdx" "$CDX_NORMALIZE"; then
		return 1
	fi

	# stdout is the answer: pointers to the artifacts, never their bytes (rule 4).
	# KEY=VALUE so the release workflow appends it to $GITHUB_OUTPUT unchanged, and
	# `sbom-check` reads the paths from here rather than rebuilding the names.
	echo "spdx=$spdx"
	echo "cdx=$cdx"
}

main "$@"
