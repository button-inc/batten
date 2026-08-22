#!/usr/bin/env bash
#MISE description="Gate: the rendered CLI reference and the command spec name exactly the same flags, in both directions (CLOUD-171)"
#
# CLOUD-171's coverage clause: "every flag in the spec appears in the reference
# and vice versa."
#
# WHY A GATE AT ALL, when the renderer walks the spec and coverage therefore
# holds by construction. Because "by construction" is a claim about today's
# renderer, not a property of the artifact. `render::markdown` walks
# `spec::CommandSpec` and emits a table row per flag — but it emits a NODE at a
# time, and a node the walk skips, a table the writer drops on an empty-flags
# branch, or a future renderer that summarises rather than enumerates all
# produce a reference that is well-formed, non-empty, byte-stable, and quietly
# missing a flag. Every other check this repository has over that file would
# pass. This is the one that would not.
#
# BOTH DIRECTIONS, because they catch opposite failures and only one of them is
# obvious:
#
#   spec \ reference   a flag the surface declares that the reference omits —
#                      the reader is told a flag does not exist.
#   reference \ spec   a flag the reference names that the surface does not have
#                      — the reader is told to type something that will not
#                      parse. This is the direction a "did we document
#                      everything" check misses entirely.
#
# THE SPEC IS THE AUTHORITY FOR WHAT A FLAG IS, never a regex over the surface
# source: `batten spec --format json` is the derivation house-style §11 already
# makes canonical, and the reference is rendered from the same tree, so both
# sides of this comparison come from the binary rather than from a second
# reading of `surface.rs`.
#
# Pointer-only (rule 4): flag names and a count, never a line of the reference.
# The flag NAME is the pointer here — it is Batten's own declaration, not
# caller content, the same reasoning `pointer_only.rs` records for why
# `generate markdown` is `Echoes` rather than `PointerOnly`.
#
# Exit 0 covered / 1 a flag is missing from one side / 2 could not look — the
# `*-check` convention, which is the INVERSE of batten's own contract
# (mem:toolchain-and-hooks, "The shell tasks' exit convention").
set -euo pipefail

cd "${REFERENCE_ROOT:-$(git rev-parse --show-toplevel)}"

# The path is the render task's to decide, asked rather than restated — the same
# `--names` handshake `release-assets-check` uses for `sbom` and `checksums`.
RENDER="$(cd "$(dirname "$0")" && pwd)/render/cli.sh"
if [[ ! -x "$RENDER" ]]; then
	echo "::error:: reference-check: cannot run $RENDER, so the reference's path is unknown. A gate that checks nothing must not report green." >&2
	exit 2
fi
if ! names=$("$RENDER" --names) || [[ -z "$names" ]]; then
	echo "::error:: reference-check: could not read the reference's name from '$RENDER --names'" >&2
	exit 2
fi
reference=${names#reference=}

# Rendered fresh rather than read from wherever a previous run left it: the
# artifact is not committed, so there is no "current copy" to trust, and a gate
# judging a stale render would answer about a surface that no longer exists.
#
# Into a scratch dir, not over the real path: a gate that writes the tree it
# judges is the shape `derived-check`'s header refuses, and this one has no
# business leaving an artifact behind at all.
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
if ! RENDER_CLI_OUT_DIR="$scratch" "$RENDER" >/dev/null; then
	echo "::error:: reference-check: the reference could not be rendered, so its coverage is unknown" >&2
	exit 2
fi
rendered="$scratch/$(basename "$reference")"

# Read the producer into a variable before parsing it. `jq` consumes all of its
# input so it is not itself the hazard, but the shape is the one that has cost
# this repository two silent false verdicts, and a here-string has no upstream
# process whose SIGPIPE `pipefail` could promote (mem:toolchain-and-hooks).
if ! spec=$(cargo run --quiet -p batten -- spec --format json); then
	echo "::error:: reference-check: the binary could not emit its spec, so there is nothing to compare against" >&2
	exit 2
fi

# Every flag id the surface declares, at every depth, sorted and de-duplicated.
# Ids rather than long names: a positional has no `--long`, and a reference that
# omitted one would otherwise be invisible to this gate.
declared=$(jq -r '[recurse(.subcommands[]?) | .flags[]?.name] | unique | .[]' <<<"$spec")
if [[ -z "$declared" ]]; then
	echo "::error:: reference-check: the spec declares no flags at all. That is not a covered reference, it is a reading that failed." >&2
	exit 2
fi

# Every flag the reference names. The renderer writes each as a leading code span
# in the table's first column, so the anchor is that column and not a bare
# backtick run — which would also match the effect tokens, the command paths and
# any prose. One authority for the row shape: `render::flag_table`.
# shellcheck disable=SC2016 # the backticks are the markdown code span this
# matches, not a subshell — and the pattern must stay single-quoted for that.
named=$(sed -nE 's/^\| `([^`]+)` \|.*/\1/p' "$rendered" | sort -u)
if [[ -z "$named" ]]; then
	echo "::error:: reference-check: the reference names no flags at all, so this parser is pointed at the wrong shape — and a gate that checks nothing must not report green." >&2
	exit 2
fi

violations=0
report() { # pointer-only (rule 4): the flag id and the rule id
	echo "$1 $2" >&2
	violations=$((violations + 1))
}

while IFS= read -r flag; do
	[[ -n "$flag" ]] || continue
	report "$flag" "reference-omits-flag"
done <<<"$(comm -23 <(printf '%s\n' "$declared") <(printf '%s\n' "$named"))"

while IFS= read -r flag; do
	[[ -n "$flag" ]] || continue
	report "$flag" "reference-invents-flag"
done <<<"$(comm -13 <(printf '%s\n' "$declared") <(printf '%s\n' "$named"))"

if [[ "$violations" -ne 0 ]]; then
	echo "::error:: reference-check: $violations flag(s) differ between the spec and the reference; the reference is derived, so this is a renderer defect rather than a document to edit" >&2
	exit 1
fi

echo "reference-check: the reference and the spec name the same $(printf '%s\n' "$declared" | wc -l | tr -d ' ') flag(s)"
