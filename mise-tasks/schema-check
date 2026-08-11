#!/usr/bin/env bash
#MISE description="Gate: the committed JSON Schema matches the one the binary derives from the config types (CLOUD-33)"
#
# DoR §1 names the Rust config types as the one authority behind `batten.toml`,
# and the JSON Schema as *derived* from them. A derivation nothing diffs is a
# hand-authored copy wearing a generator's name: the moment a config key is
# added, renamed or made required, the committed schema keeps describing the old
# surface — and it keeps doing so silently, because nothing in the Rust build
# reads it.
#
# That failure is worse here than for most artifacts, because the schema is
# *published* (a released asset, and the `.taplo.toml` binding an editor
# resolves). A stale one does not merely go unused; it actively tells a consumer
# their valid config is invalid, or waves through one `batten check` will refuse.
#
# The regeneration is the same command `mise run schema` runs, so a green gate
# proves re-running the documented refresh is a no-op — not merely that two
# files happen to agree.
set -euo pipefail

cd "${SCHEMA_ROOT:-$(git rev-parse --show-toplevel)}"

# Emit into a scratch file rather than over the committed one: a gate that
# rewrites the tree it is judging cannot fail twice, and would launder drift
# into a "clean" second run.
scratch=$(mktemp)
trap 'rm -f "$scratch"' EXIT

# Both surfaces, judged the same way (CLOUD-239). `batten.toml` is the committed
# authority and `batten.local.toml` is the raise-only override, which accepts a
# strict subset — two types, so two derivations. Checking only the first is how
# the published schema came to vouch for override keys the loader drops.
check_surface() {
	surface=$1
	committed=$2

	if [ ! -f "$committed" ]; then
		echo "$committed:0 schema-missing" >&2
		echo "::error:: schema-check: no committed $surface schema; run 'mise run schema'" >&2
		return 1
	fi

	if ! cargo run --quiet -p batten -- generate schema --surface "$surface" >"$scratch"; then
		echo "::error:: schema-check: the binary could not derive the $surface schema" >&2
		return 1
	fi

	# Pointer-only (rule 4): the gate names the file that drifted, never the diff
	# body — the remedy is always the same one command, and a schema diff would put
	# the config surface itself in the log.
	if ! cmp -s "$committed" "$scratch"; then
		echo "$committed:0 schema-drift" >&2
		echo "::error:: schema-check: the committed $surface schema differs from the config types; run 'mise run schema'" >&2
		return 1
	fi
}

# Both are checked before exiting, so one run names every drifted artifact
# rather than only the first.
failed=0
check_surface authority schema/batten.schema.json || failed=1
check_surface override schema/batten.local.schema.json || failed=1
[ "$failed" -eq 0 ] || exit 1
echo "schema-check: both committed schemas match the config types"
