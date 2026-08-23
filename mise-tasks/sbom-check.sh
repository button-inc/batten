#!/usr/bin/env bash
#MISE description="Gate: the SBOM inventories the tree it claims to — the cargo count matches Cargo.lock, and two scans agree once the volatile fields are removed"
#
# CLOUD-262. The inventory is published, which is what makes it worth gating: a
# wrong SBOM is not merely unused, it is a false claim about what shipped, and it
# is read by whoever is doing vendor review rather than by anyone here who could
# notice. Nothing in the Rust build reads these documents, so only this can.
#
# Three properties, because each fails a different way:
#
#   sbom-empty          An SBOM that catalogs nothing must not report green. A scan
#                       whose catalogers all missed would otherwise pass every
#                       equality check below trivially — two empty documents agree.
#   sbom-package-drift  The cargo count must equal `grep -c '^\[\[package\]\]'
#                       Cargo.lock`. COMPUTED, never hardcoded: the issue that
#                       specified this recorded 156 cargo and 175 total, and the
#                       total had already moved by 2 a day later as the workflow
#                       actions changed. A pinned total would fail on a true tree;
#                       a pinned cargo count would rot the first time a dependency
#                       lands. The relation is the invariant, not the number.
#   sbom-unstable       Two scans of one tree must produce identical bytes once the
#                       four fields that legitimately vary are removed. This is what
#                       makes the published document a function of the source rather
#                       than of when it was cut.
#
# The normalizer is the part that can go quietly wrong, so it is held two ways: it
# names exactly four leaves, and `tests/sbom-check.bats` drives a `syft` stub whose
# two runs differ in a package NAME and asserts this still fails. Widening it to
# make something pass would break that test first.
#
# It re-runs `mise-tasks/sbom.sh` rather than restating the flags — one definition of
# the invocation (§1), so this cannot certify bytes a release would not publish.
# Both runs go to scratch directories: a gate that rewrites the tree it judges
# cannot fail twice, and would launder drift into a clean second run.
#
# Exit 0 pass / 1 fail / 2 could-not-look, matching the other `*-check` programs.
# A gate listed in $MUTANT_GATES with no row here fails `mise run mutant`.
#MUTANT count-disagreement-passes|s/^\texit 1$/\texit 0/|a cargo count that disagrees with Cargo.lock fails

set -euo pipefail

# Resolved BEFORE the cd: `$0` may be relative, and moving first would leave this
# pointing at a sibling of whatever tree is being judged rather than of this file.
SBOM="$(cd "$(dirname "$0")" && pwd)/sbom.sh"

cd "${SBOM_ROOT:-$(git rev-parse --show-toplevel)}"

if [[ ! -x "$SBOM" ]]; then
	echo "::error:: sbom-check: cannot execute $SBOM, so the inventory is unverified. That is a checkout problem, not a drifted SBOM." >&2
	exit 2
fi

# The expected count's source. Absent, there is no invariant to check against, and
# reporting green over that would be the vacuous pass this gate exists to prevent.
if [[ ! -f Cargo.lock ]]; then
	echo "::error:: sbom-check: no Cargo.lock, so the expected package count is unknown. A gate that checks nothing must not report green." >&2
	exit 2
fi

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

violations=0
report() { # pointer-only (rule 4): asset:line rule-id, never document contents
	echo "$1 $2" >&2
	violations=$((violations + 1))
}

# THE EXPECTED CARGO COUNT IS THE LOCKFILE'S *SOURCED* PACKAGES, NOT ALL OF THEM
# (CLOUD-664). This clause compared against every `[[package]]` entry, which was
# right for as long as syft gave the local workspace member a registry purl. It
# stopped being right at syft 1.50.0, which deliberately does not
# (anchore/syft#5105): `batten` is `publish = false` and is in no registry, so a
# `pkg:cargo/batten@…` coordinate would assert a registry presence that does not
# exist. Measured 2026-08-23 at v0.0.106: 281 `[[package]]` entries, 280 carrying
# a `source`, and 280 cargo purls in the document — the one without a source is
# the workspace member, and it is the one with no purl.
#
# So the invariant is stated over the thing that actually predicts a purl: a
# lockfile entry with a `source` key is a registry or git dependency and gets one;
# an entry without is local to this workspace and does not. That also keeps
# holding if the workspace grows a second member, where subtracting a hardcoded 1
# would not.
#
# `|| true` on the total for the reason it was always there — `grep -c` exits 1 on
# a zero count, which is a real answer here rather than a failure, and
# `sbom-empty` is what judges it.
lock_packages=$(grep -c '^\[\[package\]\]' Cargo.lock || true)
declared=$(grep -c '^source = ' Cargo.lock || true)

if ! first=$(SBOM_OUT_DIR="$scratch/one" "$SBOM"); then
	echo "::error:: sbom-check: could not derive the SBOM, so its contents are unverified." >&2
	exit 2
fi
if ! second=$(SBOM_OUT_DIR="$scratch/two" "$SBOM"); then
	echo "::error:: sbom-check: could not derive the SBOM a second time, so its stability is unverified." >&2
	exit 2
fi

# The asset paths come from `sbom`'s own KEY=VALUE output, so the names stay owned
# by the one script that decides them.
path_of() { # $1 = key, $2 = the KEY=VALUE block
	sed -n "s/^$1=//p" <<<"$2"
}

spdx_one=$(path_of spdx "$first")
cdx_one=$(path_of cdx "$first")
spdx_two=$(path_of spdx "$second")
cdx_two=$(path_of cdx "$second")

for path in "$spdx_one" "$cdx_one" "$spdx_two" "$cdx_two"; do
	if [[ -z "$path" ]] || [[ ! -f "$path" ]]; then
		echo "::error:: sbom-check: sbom did not report a readable document path, so there is nothing to judge." >&2
		exit 2
	fi
done

# Each format renders purls differently, so both are counted: a regression in one
# renderer is invisible if the gate only ever reads the other.
spdx_cargo=$(jq '[.packages[]? | .externalRefs[]?
	| select(.referenceType == "purl")
	| .referenceLocator
	| select(startswith("pkg:cargo/"))] | length' "$spdx_one")
cdx_cargo=$(jq '[.components[]? | (.purl // "")
	| select(startswith("pkg:cargo/"))] | length' "$cdx_one")

if [[ "$spdx_cargo" -eq 0 ]] || [[ "$cdx_cargo" -eq 0 ]]; then
	report "${spdx_one##*/}:0" "sbom-empty"
else
	[[ "$spdx_cargo" -eq "$declared" ]] || report "${spdx_one##*/}:0" "sbom-package-drift ($spdx_cargo vs $declared)"
	[[ "$cdx_cargo" -eq "$declared" ]] || report "${cdx_one##*/}:0" "sbom-package-drift ($cdx_cargo vs $declared)"
fi

# The four leaves two scans of one tree legitimately differ in: SPDX stamps a fresh
# document namespace and creation time, CycloneDX a fresh serial number and
# timestamp. Deleting an absent key is a no-op in jq, so one expression serves both
# formats without asking which it is holding.
normalize() {
	jq -S 'del(.documentNamespace, .creationInfo.created, .serialNumber, .metadata.timestamp)' "$1"
}

compare() { # $1 = label, $2 = first run's document, $3 = second run's
	if ! normalize "$2" >"$scratch/$1.a" || ! normalize "$3" >"$scratch/$1.b"; then
		echo "::error:: sbom-check: could not normalize the $1 document, so its stability is unverified." >&2
		exit 2
	fi
	cmp -s "$scratch/$1.a" "$scratch/$1.b" || report "${2##*/}:0" "sbom-unstable"
}

compare spdx "$spdx_one" "$spdx_two"
compare cdx "$cdx_one" "$cdx_two"

# --- one entry per thing depended on (CLOUD-664) -----------------------------
#
# syft emits a component per REFERENCE SITE, so the document claimed 340 entries
# for 290 distinct things: 57 `pkg:github` entries for 9 unique actions, plus a
# `./action` component that is a relative path in this repository rather than a
# dependency of it. `sbom.sh` normalises that now; this is the clause that keeps
# it normalised, and it is deliberately a property of the DOCUMENT rather than of
# the normaliser — a cataloger that starts emitting a new inflated shape is caught
# without anyone having predicted which shape.
#
# THE SUBJECT IS EXEMPT, for the reason `sbom.sh` records at length: the document
# root and the workspace member are two roles, not two entries for one thing, and
# since syft stopped emitting a workspace purl they are indistinguishable by
# triple. Resolved from the document's own `DESCRIBES` edge, so a rename upstream
# does not turn this clause into a demand to corrupt the document.
#
# Pointer-only per rule 4: counts and the asset path, never a component name.
inflated=$(jq '
  ([.relationships[]? | select(.relationshipType == "DESCRIBES") | .relatedSpdxElement] | first) as $subject
  | [.packages[]? | select(.SPDXID != $subject)] as $components
  | {
      entries: ($components | length),
      distinct: ($components
                 | map([(.name // ""), (.versionInfo // ""),
                        ([.externalRefs[]? | select(.referenceType == "purl") | .referenceLocator] | first // "")])
                 | unique | length),
      pathlike: ($components | map(select((.name // "") | startswith("./"))) | length),
      unversioned: ($components | map(select((.versionInfo // "") == "UNKNOWN")) | length),
      subject: (if $subject == null then 0 else 1 end)
    }
  | "\(.entries) \(.distinct) \(.pathlike) \(.unversioned) \(.subject)"
' -r "$spdx_one") || inflated=""
if [[ -z "$inflated" ]]; then
	echo "::error:: sbom-check: could not read component identity from ${spdx_one##*/}, so whether the inventory is inflated is unverified." >&2
	exit 2
fi
read -r entries distinct pathlike unversioned subject <<<"$inflated"
# A document that DESCRIBES nothing is could-not-look, not a clean inventory: the
# subject is what the exemption above is computed from, so without it every
# following count is measured over the wrong set.
if [[ "$subject" -eq 0 ]]; then
	echo "::error:: sbom-check: ${spdx_one##*/} carries no DESCRIBES relationship, so the document's own subject cannot be identified and component identity is unverified." >&2
	exit 2
fi
if [[ "$entries" -ne "$distinct" ]] || [[ "$pathlike" -ne 0 ]] || [[ "$unversioned" -ne 0 ]]; then
	report "${spdx_one##*/}:0" "sbom-components-inflated (entries=$entries distinct=$distinct pathlike=$pathlike unversioned=$unversioned)"
fi

# --- supplier and originator (CLOUD-630) -------------------------------------
#
# `supplier` was `NOASSERTION` on every cargo component. It is reachable with zero
# inference once the SPDX distinction is respected — `PackageSupplier` is who
# DISTRIBUTED the package, which the lockfile's resolution states, and
# `PackageOriginator` is who WROTE it, which `cargo metadata`'s `authors` answers
# or honestly does not.
#
# Both halves are checked, and the second is why this reads `cargo metadata`
# rather than only the document: a supplier count alone cannot tell an originator
# that agrees with the manifest from one that was copied from the supplier field.
# The agreement is what makes the two fields mean different things.
if ! meta=$(cargo metadata --format-version 1 --offline 2>/dev/null); then
	echo "::error:: sbom-check: could not read cargo metadata, so whether the document's originators agree with the manifests is unverified." >&2
	exit 2
fi
# `{"<name>@<version>": true}` for every package declaring at least one author.
authored=$(jq -c '[.packages[] | select((.authors // []) | length > 0)
	| {key: "\(.name)@\(.version)", value: true}] | from_entries' <<<"$meta") || authored=""
if [[ -z "$authored" ]]; then
	echo "::error:: sbom-check: could not read authorship from cargo metadata, so originator agreement is unverified." >&2
	exit 2
fi
entities=$(jq -r --argjson authored "$authored" '
  ([.relationships[]? | select(.relationshipType == "DESCRIBES") | .relatedSpdxElement] | first) as $subject
  | [.packages[]?
     | select(.SPDXID != $subject)
     | select(([.externalRefs[]? | select(.referenceType == "purl") | .referenceLocator] | first // "")
              | startswith("pkg:github/") | not)] as $cargo
  | {
      cargo: ($cargo | length),
      # The subject is not a cargo dependency and is excluded from that count —
      # but it is the one component whose supplier a reader checks first, so it is
      # asserted on its own rather than left unjudged by the exclusion.
      subjectunset: ([.packages[]? | select(.SPDXID == $subject)
                      | select((.supplier // "NOASSERTION") == "NOASSERTION")] | length),
      nosupplier: ($cargo | map(select((.supplier // "NOASSERTION") == "NOASSERTION")) | length),
      # An originator is expected exactly where the manifest declares an author,
      # and `NOASSERTION` exactly where it does not. Both directions count as a
      # disagreement: a missing one loses data the tree states, and an invented one
      # asserts authorship nobody claimed.
      disagrees: ($cargo | map(
          "\(.name // "")@\(.versionInfo // "")" as $key
          | ((.originator // "NOASSERTION") != "NOASSERTION") as $set
          | select($set != (($authored[$key] // false)))) | length),
      # The three-way split CLOUD-629 asks for, which is the useful pointer here: a
      # holder we read, an absence we determined, and the state this clause
      # refuses. NONE is conformant and NOASSERTION is not, so counting them
      # together would hide the only difference that matters. (No apostrophes in
      # here: this program is a single-quoted shell string, and one ends it.)
      holder: ($cargo | map(select(((.copyrightText // "NOASSERTION") | test("^Copyright"; "i")))) | length),
      none: ($cargo | map(select((.copyrightText // "NOASSERTION") == "NONE")) | length),
      unset: ($cargo | map(select(((.copyrightText // "NOASSERTION") == "NOASSERTION")
                                  or ((.copyrightText // "") == ""))) | length),
      # CLOUD-628. A cargo component whose license the manifest states and the
      # document does not is the whole finding; one the manifest leaves empty is
      # honest absence and is counted separately rather than refused, because
      # guessing is what this must not do. The slash count is the second half: the
      # deprecated cargo spelling is not a valid SPDX expression, so one reaching
      # the document unrewritten is an unparseable field rather than a missing one.
      nolicense: ($cargo | map(select(((.licenseConcluded // "NOASSERTION") == "NOASSERTION")
                                      or ((.licenseConcluded // "") == ""))) | length),
      slashed: ($cargo | map(select(((.licenseConcluded // "") | test("/")))) | length)
    }
  | "\(.cargo) \(.nosupplier) \(.disagrees) \(.subjectunset) \(.holder) \(.none) \(.unset) \(.nolicense) \(.slashed)"
' "$spdx_one") || entities=""
if [[ -z "$entities" ]]; then
	echo "::error:: sbom-check: could not read supplier and originator from ${spdx_one##*/}, so those fields are unverified." >&2
	exit 2
fi
read -r cargo_components nosupplier disagrees subjectunset holder none unset nolicense slashed <<<"$entities"
# Pointer-only per rule 4, and it matters more here than elsewhere in this file:
# an `authors` entry is a personal name and often an email address, so the finding
# carries counts and never a value.
if [[ "$nosupplier" -ne 0 ]] || [[ "$disagrees" -ne 0 ]] || [[ "$subjectunset" -ne 0 ]]; then
	report "${spdx_one##*/}:0" "sbom-supplier-unset (cargo=$cargo_components no-supplier=$nosupplier originator-disagrees=$disagrees subject-unset=$subjectunset)"
fi

# --- copyright (CLOUD-629) ---------------------------------------------------
#
# `copyrightText` was NOASSERTION on every component, and the field has no source
# in `cargo metadata` at all — it is read from the bytes `Cargo.lock` pins by
# checksum. The producer writes one of exactly two values and never NOASSERTION:
# the anchored holder line where the pinned sources carry one, and `NONE` where
# every pinned byte was searched and none does. Measured against `sbomcheck`
# 5.0.3, `NONE` is conformant and `NOASSERTION` is not, so this clause refuses
# only the third state — which the producer's own hard failure on an absent
# unpacked source has already made unreachable.
#
# Pointer-only, and this field needs it more than any other in the document: a
# copyright statement is a personal name, so echoing the value would publish names
# into every CI log that reads this gate.
if [[ "$unset" -ne 0 ]]; then
	report "${spdx_one##*/}:0" "sbom-copyright-unenriched (cargo=$cargo_components holder=$holder none=$none unset=$unset)"
fi

# --- license (CLOUD-628) -----------------------------------------------------
#
# `cargo metadata` reports a license for every package in this tree and
# `cargo-deny` already gates on those same expressions, so this is the one field
# whose data was authoritative here all along and simply unused by the document.
# The clause refuses a component the manifest describes and the document does not,
# and separately refuses the deprecated slash spelling, which is not a valid SPDX
# expression — an unparseable value in a field whose purpose is to be parsed is
# worse than an honest NOASSERTION.
#
# Pointer-only: counts, never an expression or a package name.
if [[ "$nolicense" -ne 0 ]] || [[ "$slashed" -ne 0 ]]; then
	report "${spdx_one##*/}:0" "sbom-license-unenriched (cargo=$cargo_components no-license=$nolicense slash-form=$slashed)"
fi

# --- the pinned actions (CLOUD-667) ------------------------------------------
#
# The 9 SHA-pinned actions were the last conformance gap. Two clauses, and the
# second is what keeps a committed table from rotting into a list nobody updates.
ACTIONS_TABLE="${SBOM_ACTIONS_TABLE:-}"
if [[ -z "$ACTIONS_TABLE" ]]; then
	ACTIONS_TABLE="$(cd "$(dirname "$0")" && pwd)/sbom-actions.tsv"
fi
readonly ACTIONS_TABLE

# 1. Every `pkg:github` component carries both fields.
actions=$(jq -r '
  [.packages[]?
   | select(([.externalRefs[]? | select(.referenceType == "purl") | .referenceLocator] | first // "")
            | startswith("pkg:github/"))] as $gh
  | {
      total: ($gh | length),
      unset: ($gh | map(select(((.licenseConcluded // "NOASSERTION") == "NOASSERTION")
                               or ((.copyrightText // "NOASSERTION") == "NOASSERTION"))) | length)
    }
  | "\(.total) \(.unset)"
' "$spdx_one") || actions=""
if [[ -z "$actions" ]]; then
	echo "::error:: sbom-check: could not read the action components from ${spdx_one##*/}, so their license and copyright are unverified." >&2
	exit 2
fi
read -r action_total action_unset <<<"$actions"
if [[ "$action_unset" -ne 0 ]]; then
	report "${spdx_one##*/}:0" "sbom-action-unenriched (actions=$action_total unset=$action_unset)"
fi

# 2. THE DRIFT DETECTOR, and the reason a committed table is defensible at all.
# A pinned action's license is immutable, so recording it is a property of this
# commit — but only while the table still describes the pins the workflows carry.
# This fires on the one event that breaks that: a pin moving. A renovate bump that
# does not record the new commit's license fails the gate rather than silently
# degrading the document.
#
# Matched on repo AND sha together: a table row whose sha is stale is exactly the
# drift, so comparing the pair is the check. Pointer-only — the workflow file and
# line, never a license or a holder.
if [[ ! -r "$ACTIONS_TABLE" ]]; then
	echo "::error:: sbom-check: cannot read ${ACTIONS_TABLE##*/}, so whether every pinned action is mapped is unverified." >&2
	exit 2
fi
unmapped=0
while IFS= read -r pin; do
	[[ -n "$pin" ]] || continue
	# `<file>:<line>:<repo>@<sha>`
	ref="${pin##*:}"
	where="${pin%:*}"
	repo="${ref%@*}"
	# The table's key column is spelled exactly as this `uses:` line spells it,
	# so the comparison is the whole reference against a key followed by a tab.
	if ! grep -qF "$(printf '%s	' "$ref")" "$ACTIONS_TABLE"; then
		echo "$where sbom-action-unmapped ($repo)" >&2
		unmapped=$((unmapped + 1))
	fi
done < <(grep -rnoE 'uses:[[:space:]]+[^[:space:]]+@[0-9a-f]{40}' .github/workflows/ 2>/dev/null |
	sed -E 's@uses:[[:space:]]+@@' | sort -u)
if [[ "$unmapped" -ne 0 ]]; then
	violations=$((violations + 1))
	echo "${ACTIONS_TABLE##*/}:0 sbom-action-unmapped (unmapped=$unmapped)" >&2
fi

if [[ "$violations" -ne 0 ]]; then
	echo "::error:: sbom-check: $violations violation(s). Re-run 'mise run sbom' and inspect the documents; a count mismatch means a cataloger missed something, an unstable one means a field varies that the normalizer does not cover." >&2
	exit 1
fi

echo "sbom-check: $spdx_cargo cargo package(s) in both formats, matching Cargo.lock's $declared sourced entries of $lock_packages, $entries component(s) each a distinct thing, every one carrying a supplier and a license, $holder with a copyright holder and $none determined to have none, $action_total pinned action(s) all mapped, and two scans agree"
