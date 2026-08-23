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

# `|| true` because `grep -c` exits 1 on a zero count, which is a real answer here
# rather than a failure — `sbom-empty` is what judges it.
declared=$(grep -c '^\[\[package\]\]' Cargo.lock || true)

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

if [[ "$violations" -ne 0 ]]; then
	echo "::error:: sbom-check: $violations violation(s). Re-run 'mise run sbom' and inspect the documents; a count mismatch means a cataloger missed something, an unstable one means a field varies that the normalizer does not cover." >&2
	exit 1
fi

echo "sbom-check: $spdx_cargo cargo package(s) in both formats, matching Cargo.lock, and two scans agree"
