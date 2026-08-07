#!/usr/bin/env bash
#MISE description="Gate: every crate source module appears in the mem:core module map (CLOUD-194)"
#
# `.claude/rules/rust.md` does not carry a module tree; it defers outright —
# "the full per-module map ... is `mem:core`, which is kept current instead of
# this tree." That makes mem:core the single authority on what each module owns,
# and an authority nothing checks is prose (rule 2). A module added without its
# row leaves the map silently incomplete and the rule pointing at it untrue.
#
# Measured: `severity.rs` (CLOUD-168) landed with no row, past a green gate.
# `memories-check` did not catch it and is not meant to — it gates the graph's
# *edges* (mem: references resolve, names are addressable), a different property
# that holds fine while the map is missing half its rows.
#
# A pure function of the tracked tree: no tool dependency, so it gates the gap
# no matter how the module was added — Serena, a direct write, or a bypass.
set -euo pipefail

cd "${MODMAP_ROOT:-$(git rev-parse --show-toplevel)}"
map=".serena/memories/core.md"

violations=0
report() { # pointer-only (rule 4): file:line rule-id (name)
	echo "$1 $2" >&2
	violations=$((violations + 1))
}

# The map is the graph root `memories-check` already requires; if it is gone
# that gate reports it, so this one states the dependency and stops rather than
# reporting every module as missing.
if [ ! -f "$map" ]; then
	report "$map:0" "module-map-missing"
	echo "::error:: module-map-check: $violations violation(s)" >&2
	exit 1
fi

# Every tracked crate source file must be named in the map. The row format is
# prose, so this asks only that the filename appears somewhere in it —
# the weakest claim that still catches an absent module, and the one that does
# not dictate how a row is worded.
while IFS= read -r f; do
	base="${f##*/}"
	grep -qF "\`$base\`" "$map" || report "$f:0" "module-map-missing-row ($base)"
done < <(git ls-files 'crates/*/src/*.rs' | sort -u)

if [ "$violations" -ne 0 ]; then
	echo "::error:: module-map-check: $violations module(s) absent from $map" >&2
	exit 1
fi
echo "module-map-check: every module has a map row"
