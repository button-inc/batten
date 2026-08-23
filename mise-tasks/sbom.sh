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
# And the supplier/originator pass (CLOUD-630). Skipping it returns every cargo
# component to NOASSERTION, which is the state the row was filed about; collapsing
# the two fields into one is the design the row rejected, where `authors` was asked
# to fill the supplier slot and 55 packages went supplier-less for a reason that
# has nothing to do with who distributed them.
#MUTANT sbom-skips-entity-enrichment|s@^\tif ! enrich "\$spdx" "\$SPDX_ENTITIES" "\$entities"; then@\tif false; then@|the document's own subject carries the workspace supplier
#MUTANT sbom-conflates-supplier-and-originator|s@else "Organization: " + .\[0\] end)@else $own end)@|the originator is the author rather than the registry
# And the two decisions CLOUD-629 makes. The residue must be `NONE` rather than
# `NOASSERTION` — measured against sbomcheck 5.0.3, one is conformant and the other
# is not, and writing the timid value forfeits conformance for data we actually
# read. And an absent unpacked source must be a hard failure, because emitting
# anything for it would make the document depend on how warm this machine's cache
# is rather than on the lockfile.
#MUTANT sbom-copyright-residue-is-noassertion|s@== "" then "NONE"@== "" then "NOASSERTION"@|THE BOILERPLATE TRAP
#MUTANT sbom-tolerates-an-absent-source|s@^\tif \[\[ "\$missing" -ne 0 \]\]; then$@\tif false; then@|a lockfile package absent from the cache is a HARD FAILURE
# And CLOUD-628. The deprecated slash spelling reaching the document unrewritten
# is an unparseable SPDX expression in a field whose purpose is to be parsed; a
# manifest with no license must stay NOASSERTION rather than borrow a neighbour.
#MUTANT sbom-keeps-the-slash-license-form|s@gsub("\[\[:space:\]\]\*/\[\[:space:\]\]\*"; " OR ")@.@|the deprecated slash spelling is rewritten to OR
#MUTANT sbom-invents-a-missing-license|s@if . == "" then "NOASSERTION"@if . == "" then "Apache-2.0"@|HONEST ABSENCE
# And CLOUD-667. Skipping the actions pass returns all 9 to NOASSERTION, which is
# the gap that made the promotion impossible; a short table row must be refused
# rather than writing an empty license into a published document.
#MUTANT sbom-skips-the-actions-table|s@^\tif ! enrich_actions "\$spdx" "\$SPDX_ACTIONS" "\$actions"; then@\tif false; then@|a mapped action carries its license and copyright
#MUTANT sbom-accepts-a-short-action-row|s@if (NF < 4)@if (NF < 0)@|a table row with fewer than four fields is refused
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

# --- supplier and originator: two fields, two authorities ---------------------
#
# CLOUD-630. `supplier` was `NOASSERTION` on every cargo component, and the issue
# was filed believing the field unreachable: `authors` is empty on 55 of 281
# packages, is self-asserted where present, and `repository` is a URL rather than
# an entity. All true, and all about the wrong field.
#
# SPDX distinguishes `PackageSupplier` — who DISTRIBUTED the package — from
# `PackageOriginator` — who CREATED it. Measured 2026-08-23: the lockfile resolves
# every dependency to exactly one distinct source,
# `registry+https://github.com/rust-lang/crates.io-index`, so the distributor is
# a fact the resolution states rather than something inferred. That is the
# supplier. `authors` answers the other question, and where it is empty
# `NOASSERTION` is the correct and honest value — 55 packages assert nothing about
# authorship and the document should not either.
#
# READ FROM `cargo metadata`, WHOSE `source` IS THE LOCKFILE'S. CLOUD-630 §1 names
# `Cargo.lock`'s per-package `source` key as the authority, and this reads the same
# datum through the tool that resolves it: `cargo metadata` reports the resolved
# source per package, and `authors` besides, so one subprocess answers both
# questions where parsing the lockfile by hand would answer one and still need the
# other. `--offline`, so this adds no network call.
#
# NO SOURCE IS EVER LABELLED crates.io ON A GUESS. Only the crates.io index URL
# maps to `Organization: crates.io`. A git or path dependency gets `NOASSERTION`,
# because its distributor is not stated anywhere this can read and a plausible
# guess is exactly the overclaim CLOUD-608 refused. Every package in the tree
# resolves to crates.io today, so nothing here exercises that branch — which is
# why `tests/sbom.bats` drives it from a synthetic fixture rather than waiting for
# someone to add a git dependency and discover the mislabelling in a release.
#
# `Organization:` FOR THE ORIGINATOR, and it is a formatting choice rather than a
# claim. SPDX requires a kind prefix; a manifest's `authors` entry does not state
# whether it names a person or a group, and "The Rust Project Developers" and a
# named individual arrive in the same field. `Organization:` is the convention the
# document already uses — syft writes `Organization: <namespace owner>` for both
# fields on every `pkg:github` entry — so following it keeps one convention in one
# document instead of two. SPDX's originator is single-valued, so the first author
# is recorded and the full list stays in `cargo metadata`.
readonly CRATES_IO_SOURCE='registry+https://github.com/rust-lang/crates.io-index'

# --- copyright: read from the bytes the lockfile pins ------------------------
#
# CLOUD-629, and it is the row's DECISION rather than only its implementation.
# `copyrightText` was `NOASSERTION` on every component, and unlike license or
# supplier the field has no source in `cargo metadata` at all.
#
# THE REGISTRY CACHE IS ADMISSIBLE, AND THE REASON IS THE CHECKSUM. The cache
# looks like machine state, which would make it inadmissible — `.claude/rules/
# toolchain.md` draws exactly that line between a property of the commit and a
# property of the world, and a document whose contents depend on cache warmth
# would break `sbom-check`'s stability clause. But `Cargo.lock` carries a
# `checksum` for every external package and cargo verifies the unpacked tree
# against it, so the content of `<CARGO_HOME>/registry/src/<registry>/<name>-
# <version>/` is a FUNCTION OF THE LOCKFILE. What is machine state is
# AVAILABILITY, not content — and availability gets a mechanism rather than a
# judgement: a package the lockfile names and the cache lacks is a hard failure,
# never a silent `NOASSERTION`. `cargo fetch --locked` is run first so a cold
# container is a fetch rather than a refusal.
#
# ONLY AN ANCHORED HOLDER LINE COUNTS, AND THE LOOSE READING IS MEASURABLY WRONG.
# A first-match search for the word "copyright" returns, on `ahash`, `anstream`,
# `serde` and `regex` alike, the string `copyright notice that is included in or
# attached to the work` — a fragment of the Apache-2.0 text itself. So the loose
# reading does not merely miss a holder; it writes license prose into
# `copyrightText` and asserts it as a copyright statement. The pattern therefore
# anchors at the start of a line, allows a comment marker, and requires a year
# followed by a name.
#
# TWO STAGES, because one stage was wrong in both directions. License-shaped files
# are authoritative and are read first. Where they carry no anchored line, the
# whole pinned tree is searched and the MOST FREQUENT anchored line wins — measured
# 2026-08-23, 4 of the 11 crates shipping no license file at all do state a holder
# elsewhere (`json5`, `r-efi` twice, `yaml-rust2`), so a license-files-only rule
# writes `NONE` over data the pinned bytes actually carry. Most-frequent rather
# than first-in-order because a vendored fixture contributes one line while a
# crate's own headers contribute many, which makes mis-attribution unlikely rather
# than merely bounded; ties break on the sorted line, so two runs agree.
#
# AND THE RESIDUE IS `NONE`, NOT `NOASSERTION` — the distinction that moves the
# ceiling from partial to complete. SPDX separates them: `NOASSERTION` means we did
# not determine, `NONE` means we determined there is nothing. Measured against
# `sbomcheck` 5.0.3, `NONE` is conformant and `NOASSERTION` is not. Because both
# stages search every pinned byte, `NONE` is a claim this can stand behind rather
# than a nicer word for unknown.
#
# Measured on this tree, 280 external crates: **162 carry a holder, 118 are
# `NONE`**, and zero Apache-2.0 boilerplate reaches the field.
readonly COPYRIGHT_RE='^[[:space:]]*(#|//|\*|;)?[[:space:]]*Copyright[[:space:]]*(\(c\)|©)?[[:space:]]*[0-9][0-9,[:space:]-]*[[:alpha:]].*'
# Strips leading whitespace and one comment marker, so the same statement found in
# a `LICENSE` file and in a source header normalises to one string.
readonly COPYRIGHT_TIDY='s/^[[:space:]]*//; s/^\(#\|\/\/\|\*\|;\)[[:space:]]*//'

# The unpacked source root. Several registries can be present; each package is
# looked up under all of them, so a vendored or alternate registry resolves too.
cargo_src_roots() {
	local home="${CARGO_HOME:-$HOME/.cargo}"
	printf '%s\n' "$home"/registry/src/*/
}

# `<holder line>` or the empty string, for one `<name>-<version>` directory.
copyright_of() {
	local dir="$1" line="" files=()
	shopt -s nullglob nocaseglob
	files=("$dir"/LICENSE* "$dir"/COPYING* "$dir"/COPYRIGHT* "$dir"/NOTICE*)
	shopt -u nocaseglob
	if [[ "${#files[@]}" -gt 0 ]]; then
		line=$(grep -hoiE "$COPYRIGHT_RE" "${files[@]}" 2>/dev/null | sed "$COPYRIGHT_TIDY" | head -1) || line=""
	fi
	if [[ -z "$line" ]]; then
		line=$(grep -rhoiE "$COPYRIGHT_RE" "$dir" 2>/dev/null | sed "$COPYRIGHT_TIDY" |
			sort | uniq -c | sort -k1,1nr -k2 | head -1 | sed 's/^ *[0-9]* //') || line=""
	fi
	printf '%s' "$line"
}

# --- the actions table (CLOUD-667) -------------------------------------------
#
# The 9 SHA-pinned GitHub Actions were the last conformance gap: they already
# carry `supplier` and `originator` (syft derives both from the namespace owner),
# so only license and copyright were missing. The values live in one committed
# table beside this file, whose own header records how each row was sourced and
# which four needed care.
#
# MATCHED ON THE REPO, NOT THE SHA, and that is forced rather than chosen: syft
# keys these components by the `# vX` comment beside the pin, not by the pin
# itself — `pkg:github/actions/checkout@v7` for a component whose `uses:` line
# resolves to `3d3c42e5…`. The sha in the table is what `sbom-action-unmapped`
# compares against the workflows, so drift is still caught at the pin; using it
# here would match nothing.
ACTIONS_TABLE="${SBOM_ACTIONS_TABLE:-$(cd "$(dirname "$0")" && pwd)/sbom-actions.tsv}"

# `{"<owner>/<repo>": {license, copyright}}` from the committed table.
action_entities() {
	if [[ ! -r "$ACTIONS_TABLE" ]]; then
		echo "::error:: sbom: cannot read ${ACTIONS_TABLE##*/}, so no pinned action can be given its license or copyright" >&2
		return 1
	fi
	# Comments and blank lines skipped by shape. A row short of four fields is a
	# malformed table rather than a missing row, and is refused: a partial row
	# would silently write an empty license into the document.
	local out
	if ! out=$(awk -F'\t' '
		/^[[:space:]]*#/ { next }
		/^[[:space:]]*$/ { next }
		{
			if (NF < 4) { print "MALFORMED:" NR > "/dev/stderr"; bad = 1; next }
			printf "%s\t%s\t%s\n", $1, $3, $4
		}
		END { if (bad) exit 1 }
	' "$ACTIONS_TABLE"); then
		echo "::error:: sbom: ${ACTIONS_TABLE##*/} carries a row with fewer than four tab-separated fields, so an action would be given an empty license" >&2
		return 1
	fi
	jq -Rn '[inputs
	   | select(length > 0)
	   | split("\t")
	   | {key: .[0], value: {license: .[1], copyright: .[2]}}]
	  | from_entries' <<<"$out"
}

# Only `pkg:github` components, and only the two fields syft leaves NOASSERTION —
# its supplier and originator are derived from the namespace owner and are more
# specific than anything this table knows.
# shellcheck disable=SC2016  # a jq program: `$actions` is a jq binding, not shell
readonly SPDX_ACTIONS='
  .packages = [.packages[]?
    | ([.externalRefs[]? | select(.referenceType == "purl") | .referenceLocator] | first // "") as $purl
    | if ($purl | startswith("pkg:github/")) and $actions[(.name // "")]
      then .licenseDeclared = $actions[(.name // "")].license
        | .licenseConcluded = $actions[(.name // "")].license
        | .copyrightText = $actions[(.name // "")].copyright
      else . end]
'

# shellcheck disable=SC2016  # a jq program: `$actions` is a jq binding, not shell
readonly CDX_ACTIONS='
  .components = [.components[]?
    | (.purl // "") as $purl
    | if ($purl | startswith("pkg:github/")) and $actions[(.name // "")]
      then .licenses = [{expression: $actions[(.name // "")].license}]
        | (if $actions[(.name // "")].copyright == "NONE" then .
           else .copyright = $actions[(.name // "")].copyright end)
      else . end]
'

# The map the enrichment reads:
# `{"<name>@<version>": {supplier, originator, copyright}}`. Built once, from one
# `cargo metadata` call plus one pass over the pinned sources.
cargo_entities() {
	local meta
	if ! cargo fetch --locked >/dev/null 2>&1; then
		echo "::error:: sbom: \`cargo fetch --locked\` failed, so the pinned sources the copyright statements are read from are not present" >&2
		return 1
	fi
	if ! meta=$(cargo metadata --format-version 1 --locked --offline 2>/dev/null); then
		echo "::error:: sbom: could not read cargo metadata, so supplier and originator are unknown for every cargo component" >&2
		return 1
	fi

	# One line per external package, resolved against the cache. A package the
	# lockfile names and no registry root holds is a HARD FAILURE: emitting
	# `NOASSERTION` for it would make the document's contents depend on how warm
	# this machine's cache is, which is the property-of-the-world failure the
	# admissibility argument above turns on.
	# `mapfile` would read this in one line and is bash 4 only, which
	# `no-bash4-mapfile` refuses: these programs run on a Mac's bash 3.2.
	local -a roots=()
	local root_line
	while IFS= read -r root_line; do
		roots+=("$root_line")
	done < <(cargo_src_roots)
	local copyrights="{}" missing=0 name version dir found
	while IFS=$'\t' read -r name version; do
		found=""
		for root in "${roots[@]}"; do
			dir="${root%/}/${name}-${version}"
			if [[ -d "$dir" ]]; then
				found="$dir"
				break
			fi
		done
		if [[ -z "$found" ]]; then
			missing=$((missing + 1))
			continue
		fi
		copyrights=$(jq -c --arg k "${name}@${version}" --arg v "$(copyright_of "$found")" \
			'.[$k] = $v' <<<"$copyrights") || return 1
	done < <(jq -r '.packages[] | select(.source != null) | "\(.name)\t\(.version)"' <<<"$meta")
	if [[ "$missing" -ne 0 ]]; then
		# Pointer-only: a count, never the crate names, matching this file's siblings.
		echo "::error:: sbom: $missing lockfile package(s) have no unpacked source under \$CARGO_HOME/registry/src, so their copyright statements could not be read. Run \`cargo fetch --locked\`; a document that reported NOASSERTION here would depend on this machine's cache rather than on the lockfile." >&2
		return 1
	fi
	# The workspace's own packages have no `source` — they are not distributed by a
	# registry at all — so their supplier is this repository's own manifest
	# identity, passed in rather than re-read here.
	jq -c --arg crates "$CRATES_IO_SOURCE" --arg own "$WORKSPACE_SUPPLIER" \
		--arg owncopyright "$WORKSPACE_COPYRIGHT" \
		--argjson copyrights "$copyrights" '
	  [.packages[]
	   | "\(.name)@\(.version)" as $key
	   | {key: $key,
	      value: {
	        supplier:
	          (if .source == $crates then "Organization: crates.io"
	           elif .source == null then $own
	           else "NOASSERTION" end),
	        originator:
	          ((.authors // []) | if length == 0 then "NOASSERTION"
	                              else "Organization: " + .[0] end),
	        # `NONE` rather than `NOASSERTION` where the pinned bytes carry no
	        # statement: we looked at all of them, so "there is none" is what we
	        # actually determined. The workspace member has no pinned source to read
	        # and its own statement is not asserted here.
	        # CLOUD-628. `cargo metadata` reports a license for every package in
	        # this tree (281 of 281, none falling back to `license-file`), and
	        # `cargo-deny` already judges these same expressions, so the data is
	        # authoritative here today and was merely unused by the document.
	        #
	        # Written to BOTH SPDX fields, and the pair is the honest reading:
	        # `licenseDeclared` is what the package states, which is exactly what a
	        # manifest is, and `licenseConcluded` is the conclusion drawn by
	        # whoever authored the document. Concluding the declaration is defensible precisely because
	        # `deny.toml` already gates on it; leaving `licenseConcluded` at
	        # NOASSERTION while the declaration sits beside it would be a document
	        # withholding a conclusion it acts on everywhere else.
	        #
	        # THE DEPRECATED SLASH FORM IS REWRITTEN, and that is a documented
	        # equivalence rather than a guess: the cargo manifest reference says
	        # `/` is the deprecated spelling of OR. Measured on this tree, 10
	        # packages still use it (`Apache-2.0/MIT`, `Apache-2.0 / MIT`), and it is
	        # not a valid SPDX license expression — writing it verbatim would put an
	        # unparseable expression in a field whose whole purpose is to be parsed.
	        license:
	          ((.license // "")
	           | if . == "" then "NOASSERTION"
	             else gsub("[[:space:]]*/[[:space:]]*"; " OR ") end),
	        copyright:
	          (if .source == null then $owncopyright
	           elif ($copyrights[$key] // "") == "" then "NONE"
	           else $copyrights[$key] end)
      }}]
	  | from_entries' <<<"$meta"
}

# The workspace member has no pinned registry source, so its copyright is read
# from THIS repository's own license-shaped files — the same anchored pattern, over
# the tree being scanned. Restricted to the root rather than recursive, unlike the
# registry-cache reader: a repository's own tree contains test fixtures and
# vendored material whose copyright lines are not this package's, and the fallback
# that is safe for an unpacked crate is not safe here.
#
# On this tree the answer is `NONE`, and it is the right one rather than a
# shortfall: the only license file is `LICENSE-APACHE`, whose sole mentions of the
# word are the Apache-2.0 boilerplate the pattern is built to reject. We read the
# bytes and there is no copyright statement in them.
workspace_copyright() {
	local line="" files=()
	shopt -s nullglob nocaseglob
	files=(LICENSE* COPYING* COPYRIGHT* NOTICE*)
	shopt -u nocaseglob
	if [[ "${#files[@]}" -gt 0 ]]; then
		line=$(grep -hoiE "$COPYRIGHT_RE" "${files[@]}" 2>/dev/null | sed "$COPYRIGHT_TIDY" | head -1) || line=""
	fi
	if [[ -z "$line" ]]; then
		printf 'NONE'
		return 0
	fi
	printf '%s' "$line"
}

# Read from the workspace manifest rather than written here, for the reason
# `crate_version` gives about the version: a label this file invents can disagree
# with what the package actually declares.
workspace_supplier() {
	local authors
	authors=$(awk -F'"' '/^authors = \[/ { print $2; exit }' Cargo.toml)
	if [[ -z "$authors" ]]; then
		printf 'NOASSERTION'
		return 0
	fi
	printf 'Organization: %s' "$authors"
}

# Only `pkg:cargo` components are touched: the `pkg:github` entries already carry
# a supplier and an originator syft derived from the action's namespace owner, and
# overwriting those would replace a real answer with a less specific one.
# KEYED ON THE COMPONENT'S OWN name AND version, NOT ON ITS PURL, and both reasons
# are things a purl-keyed version got wrong on this tree:
#
#   * A purl PERCENT-ENCODES semver build metadata, so `toml 1.1.4+spec-1.1.0`
#     arrives as `pkg:cargo/toml@1.1.4%2Bspec-1.1.0` and matches no `cargo
#     metadata` key. Five packages here carry a `+` and all five silently kept
#     `NOASSERTION` — the shape of failure that is invisible without a count.
#   * The workspace member has NO purl at all since syft 1.50.0, so a purl-keyed
#     pass cannot reach the one component CLOUD-630 §7 names first: the document's
#     own subject reading `NOASSERTION` is the gap a reader notices before any of
#     the 280 others.
#
# `pkg:github` entries are excluded by their purl rather than selected by absence
# of one, because absence is exactly what the two `batten` entries have. Those
# already carry a supplier and originator syft derived from the action's namespace
# owner, and overwriting them would replace a specific answer with a general one.
# shellcheck disable=SC2016  # a jq program: `$entities` is a jq binding, not shell
readonly SPDX_ENTITIES='
  .packages = [.packages[]?
    | ([.externalRefs[]? | select(.referenceType == "purl") | .referenceLocator] | first // "") as $purl
    | "\(.name // "")@\(.versionInfo // "")" as $key
    | if ($purl | startswith("pkg:github/")) then .
      elif $entities[$key] then
        .supplier = $entities[$key].supplier
        | .originator = $entities[$key].originator
        | .copyrightText = $entities[$key].copyright
        | .licenseDeclared = $entities[$key].license
        | .licenseConcluded = $entities[$key].license
      else . end]
'

# shellcheck disable=SC2016  # a jq program: `$entities` is a jq binding, not shell
readonly CDX_ENTITIES='
  .components = [.components[]?
    | (.purl // "") as $purl
    | "\(.name // "")@\(.version // "")" as $key
    | if ($purl | startswith("pkg:github/")) then .
      elif $entities[$key] then
        .publisher = $entities[$key].supplier
        | (if $entities[$key].originator == "NOASSERTION" then .
           else .author = ($entities[$key].originator | ltrimstr("Organization: ")) end)
        | (if $entities[$key].copyright == "NONE" or $entities[$key].copyright == "NOASSERTION" then .
           else .copyright = $entities[$key].copyright end)
        | (if $entities[$key].license == "NOASSERTION" then .
           else .licenses = [{expression: $entities[$key].license}] end)
      else . end]
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

# Same shape as `enrich`, with the table bound as `$actions`. A separate binding
# name rather than reusing `$entities`, so a jq program cannot silently read the
# wrong map if the two calls are ever reordered.
enrich_actions() {
	local doc="$1" program="$2" actions="$3" tmp
	tmp="${doc}.enriching"
	if ! jq --argjson actions "$actions" "$program" "$doc" >"$tmp"; then
		rm -f "$tmp"
		echo "::error:: sbom: could not write the pinned actions into ${doc##*/}, so they would claim NOASSERTION over data this repository has committed" >&2
		return 1
	fi
	mv "$tmp" "$doc"
}

# Same in-place discipline as `normalize`, with the entity map bound as `$entities`.
enrich() {
	local doc="$1" program="$2" entities="$3" tmp
	tmp="${doc}.enriching"
	if ! jq --argjson entities "$entities" "$program" "$doc" >"$tmp"; then
		rm -f "$tmp"
		echo "::error:: sbom: could not write supplier and originator into ${doc##*/}, so its cargo components would claim NOASSERTION over data this tree states" >&2
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
	# Bound before the scan so a manifest this file cannot read fails before syft
	# spends a minute cataloguing a tree whose subject it could not name.
	WORKSPACE_SUPPLIER=$(workspace_supplier)
	export WORKSPACE_SUPPLIER
	WORKSPACE_COPYRIGHT=$(workspace_copyright)
	export WORKSPACE_COPYRIGHT
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

	# Who distributed each cargo component, and who wrote it (CLOUD-630). After
	# normalisation, so the map is applied once per surviving component rather than
	# once per reference site.
	local entities
	if ! entities=$(cargo_entities); then
		return 1
	fi
	if ! enrich "$spdx" "$SPDX_ENTITIES" "$entities"; then
		return 1
	fi
	if ! enrich "$cdx" "$CDX_ENTITIES" "$entities"; then
		return 1
	fi

	# The pinned actions (CLOUD-667), from the committed table.
	local actions
	if ! actions=$(action_entities); then
		return 1
	fi
	if ! enrich_actions "$spdx" "$SPDX_ACTIONS" "$actions"; then
		return 1
	fi
	if ! enrich_actions "$cdx" "$CDX_ACTIONS" "$actions"; then
		return 1
	fi

	# stdout is the answer: pointers to the artifacts, never their bytes (rule 4).
	# KEY=VALUE so the release workflow appends it to $GITHUB_OUTPUT unchanged, and
	# `sbom-check` reads the paths from here rather than rebuilding the names.
	echo "spdx=$spdx"
	echo "cdx=$cdx"
}

main "$@"
