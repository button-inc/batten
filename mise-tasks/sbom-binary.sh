#!/usr/bin/env bash
#MISE description="Effect+gate: inventory a built binary from its own bytes, and refuse an inventory that catalogs nothing"
#
# CLOUD-263, the follow-on `mise-tasks/sbom.sh`'s header names. That script inventories
# the REPOSITORY at the tag; this one inventories what is inside an archive a user
# downloads, which is a different claim and the one a consumer of a binary needs.
#
# WHY THE PLAIN BINARY CANNOT ANSWER IT. Measured 2026-08-14: syft against a
# `--profile dist` binary built by plain cargo recovers **0** rust-crate packages.
# A Rust binary carries no dependency metadata unless something puts it there, so
# a scan of one is not an inventory — it is an empty document that exits 0, the
# vacuous-green shape CLOUD-258 taught this repo to distrust. `mise-tasks/dist.sh`
# builds through `cargo auditable` on the legs where that is proven, which embeds
# a `dep-v0` section syft reads back; the same measurement recovered **85**
# packages from the stripped binary, so `strip = true` does not remove it.
#
# TWO PROPERTIES, and each fails a different way:
#
#   sbom-binary-vacuous   fewer than 2 rust-crate packages. 0 is an unwrapped
#                         build, 1 is the binary cataloging only itself, and both
#                         must fail — a gate that checks nothing must not report
#                         green.
#   sbom-binary-foreign   a recovered purl naming a crate that is not in
#                         `Cargo.lock`. SUBSET, never equality: the lockfile spans
#                         build- and dev-dependencies for every target (189 entries
#                         measured) while the audit section records only what was
#                         linked for the one target built (85), so equality would
#                         be wrong on every leg.
#
# The count is read from the SAME scan the document is rendered from, deliberately
# unlike `sbom-check`, which re-runs `mise-tasks/sbom.sh` twice to ask a stability
# question about a tree walk. There is no such question here: the input is a fixed
# file, and a second scan of the same bytes could only prove syft deterministic.
#
#   mise run sbom-binary <binary> <target>   scan, verify, write the asset
#   mise run sbom-binary --names <target>    the asset name, without scanning
#
# Pointer-only (rule 4): counts and asset names, never a package name or a
# document byte. Exit 0 pass / 1 refused / 2 could-not-look, matching the other
# `*-check` programs.
set -euo pipefail

cd "${SBOM_BINARY_ROOT:-$(git rev-parse --show-toplevel)}"

readonly BIN=batten
OUT_DIR="${SBOM_BINARY_OUT_DIR:-dist}"

# The asset name comes from `dist`'s own stem rule, never re-derived here: seven
# legs upload seven distinct names, and a second spelling of that contract is how
# two legs end up racing for one asset (CLOUD-262 keeps its single document
# outside the matrix for exactly this reason).
DIST="$(cd "$(dirname "$0")" && pwd)/dist.sh"

# Resolved BEFORE any cd, like `sbom-check`'s: `$0` may be relative.
if [ ! -x "$DIST" ]; then
	echo "::error:: sbom-binary: cannot execute $DIST, so the asset name cannot be derived. That is a checkout problem." >&2
	exit 2
fi

usage() {
	cat >&2 <<-EOF
		usage: mise run sbom-binary <binary> <target>
		       mise run sbom-binary --names <target>
	EOF
}

crate_version() {
	local version
	version=$(awk -F'"' '/^version = "/ { print $2; exit }' Cargo.toml)
	if [ -z "$version" ]; then
		echo "::error:: sbom-binary: could not read a version from Cargo.toml" >&2
		return 1
	fi
	printf '%s' "$version"
}

asset_for() { # $1 = target
	local stem
	stem=$("$DIST" --stem "$1") || return 1
	[ -n "$stem" ] || return 1
	printf '%s/%s.spdx.json' "$OUT_DIR" "$stem"
}

if [ "${1:-}" = "--names" ]; then
	[ -n "${2:-}" ] || {
		usage
		exit 2
	}
	echo "sbom=$(asset_for "$2")"
	exit 0
fi

binary="${1:-}"
target="${2:-}"
if [ -z "$binary" ] || [ -z "$target" ]; then
	usage
	exit 2
fi
if [ ! -f "$binary" ]; then
	echo "::error:: sbom-binary: no binary at $binary, so there is nothing to inventory." >&2
	exit 2
fi
if [ ! -f Cargo.lock ]; then
	echo "::error:: sbom-binary: no Cargo.lock, so the recovered crates cannot be held against anything. A gate that checks nothing must not report green." >&2
	exit 2
fi

asset=$(asset_for "$target")
mkdir -p "$(dirname "$asset")"

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

version=$(crate_version)

# ONE scan, rendered to the asset and read for the verdict. `--source-name` and
# `--source-version` for the reason `sbom` records: with neither, the document
# labels its own subject `.` and an inventory that cannot say what it inventories
# is not one.
if ! syft scan "file:$binary" \
	--source-name "$BIN" --source-version "$version" \
	--output "spdx-json=$asset" --output "syft-json=$scratch/scan.json" --quiet; then
	echo "::error:: sbom-binary: syft could not scan $binary, so its contents are unverified." >&2
	exit 2
fi

# `rust-crate` artifacts only. The type matters: syft reports the FILE itself as an
# artifact on some inputs, so an unfiltered count reads 1 on a binary carrying no
# dependency data at all — the vacuous case wearing a passing number.
if ! recovered=$(jq -r '[.artifacts[]? | select(.type == "rust-crate")
	| "\(.name) \(.version)"] | .[]' "$scratch/scan.json" 2>/dev/null); then
	echo "::error:: sbom-binary: could not read the scan's artifact list, so the inventory is unverified." >&2
	exit 2
fi

count=$(printf '%s' "$recovered" | grep -c . || true)

violations=0
report() { # pointer-only (rule 4): the asset name, the rule id, and counts
	echo "$1 $2" >&2
	violations=$((violations + 1))
}

if [ "$count" -lt 2 ]; then
	report "${asset##*/}:0" "sbom-binary-vacuous ($count rust-crate package(s); a build that lost the auditable wrapper recovers 0)"
else
	# The lockfile's own `[[package]]` set, as `name version` pairs. Read with awk
	# rather than a TOML parser for the same reason `sbom` reads the version that
	# way: this is the only field needed, and the shape is fixed.
	declared=$(awk '/^\[\[package\]\]/ { n = ""; v = "" }
		/^name = / { gsub(/"/, "", $3); n = $3 }
		/^version = / { gsub(/"/, "", $3); v = $3; if (n != "") print n, v }' Cargo.lock | sort -u)
	foreign=$(comm -23 <(printf '%s\n' "$recovered" | sort -u) <(printf '%s\n' "$declared") | grep -c . || true)
	[ "$foreign" -eq 0 ] || report "${asset##*/}:0" "sbom-binary-foreign ($foreign of $count recovered crate(s) are absent from Cargo.lock)"
fi

if [ "$violations" -ne 0 ]; then
	echo "::error:: sbom-binary: $violations violation(s) on $target. A vacuous count means the build lost its \`cargo auditable\` wrapper; a foreign crate means the binary was not built from this lockfile." >&2
	rm -f "$asset"
	exit 1
fi

# stdout is the answer: a pointer to the artifact, never its bytes. KEY=VALUE so
# the release workflow appends it to $GITHUB_OUTPUT unchanged, the same contract
# `dist` and `sbom` already use.
echo "sbom=$asset"
echo "packages=$count"
