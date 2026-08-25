#!/usr/bin/env bash
#MISE description="Gate: no config key left the published schema without a deprecation window (CLOUD-360)"
#
# stays-bash: CLOUD-910 this file resolves WHICH ref the published schema is read
# at -- the latest release tag in version order -- and hands it to the engine.
# The predicate is already `batten config deprecations`, so what stays here is a
# tag-ordering question, and no rule kind expresses one: `ratchet`'s `base` names
# a single ref literally, and a `command` row would spawn the same shell one layer
# down. It grows the surface by one and is declared rather than hidden; CLOUD-910
# is the row that retires it along with the rest of the `mise-tasks/` census.
#
# The contract half of `expand -> migrate -> contract`. A key vanishing from the
# published schema is a silent break for every consumer whose `batten.toml` still
# carries it: their config stops loading, with an unknown-key error that names no
# successor and no date. The grammar's promise is that removal is always preceded
# by a window, and this is what holds it.
#
# THE PREDICATE IS THE BINARY'S, not this script's. `batten config deprecations`
# reads the schema published at a ref, derives the current one, and compares the
# top-level key sets against `DEPRECATED_KEYS` and `RETIRED_KEYS`. This file
# resolves WHICH ref and nothing else — a shell re-derivation would be a second
# answer to a question the engine already answers, which is the defect the
# `git.rs` migration spent four slices removing.
#
# WHY A TAG AND NOT `origin/main`. The promise is made to a consumer who INSTALLED
# a release, so the baseline is the last released surface. Comparing against
# `main` would let a key be added and removed between releases and count as a
# break, which it is not — nobody could have configured it.
#
# REPLAY EVIDENCE, run before this was given deny severity (§7, 2026-08-25).
# `config deprecations` was run against all 112 release tags on this tree:
#
#   exit 0  85 tags — no unannounced removal
#   exit 2   0 tags — the gate would never have fired against a past release
#   exit 3  27 tags — v0.0.26 and older, which predate the committed schema
#
# Zero exit 2 over 85 comparable releases is what justifies `deny` here: a
# predicate that would have refused past releases is one that fires on work
# nobody can now fix. The exit-3 cluster is the could-not-look path answering
# honestly rather than passing, and it is bounded — v0.0.27 is the oldest tag
# carrying `schema/batten.schema.json`, and this gate always asks the LATEST tag.
# A gate listed in $MUTANT_GATES with no row here fails `mise run mutant`.
#MUTANT unannounced-removal-passes|s/^exit "\$code"/exit 0/|an unannounced removal is reported rather than passed

set -euo pipefail

cd "${SCHEMA_ROOT:-$(git rev-parse --show-toplevel)}"

# The latest release tag by version order, never by creation date: a re-cut tag
# would otherwise reorder the baseline.
if ! baseline=$(git tag --list 'v*' --sort=-v:refname | head -n 1) || [[ -z "$baseline" ]]; then
	# NO TAGS IS COULD-NOT-LOOK, exit 3, never a pass. A fresh clone with no tags
	# fetched has no baseline, and reporting "nothing was removed" having compared
	# nothing is the vacuous pass CLOUD-251 names.
	echo "::error:: config-deprecations: no release tag to compare against; fetch tags" >&2
	exit 3
fi

set +e
cargo run --quiet -p batten -- config deprecations "$baseline"
code=$?
set -e

# The engine's own contract, read rather than reinterpreted: 0 clean, 2 the
# verdict, 3 could not look. Anything else is this script's bug and is surfaced
# as one rather than folded into a pass.
case "$code" in
0) echo "config-deprecations: no key left the schema unannounced since $baseline" ;;
2) echo "::error:: config-deprecations: a key left the published schema with no deprecation window; add a row to config::DEPRECATED_KEYS naming its replacement and expiry" >&2 ;;
3) echo "::error:: config-deprecations: no published schema at $baseline, so no removal could be judged" >&2 ;;
*) echo "::error:: config-deprecations: unexpected exit $code from the engine" >&2 ;;
esac

# ONE exit, carrying the engine's own code through unchanged. Two guarded exits
# stood here first and the mutation runner caught them: neutering the `-eq 2`
# branch changed nothing, because the fallthrough exited 2 as well. Redundant
# branches mean neither is load-bearing, and a gate whose refusal has two
# independent causes cannot be shown to depend on either.
exit "$code"
