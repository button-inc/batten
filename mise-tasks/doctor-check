#!/usr/bin/env bash
#MISE description="The pure decision behind doctor: classify one rustup target as ok / missing / stale from the toolchain's on-disk bookkeeping"
#
# `rustup target add` is documented as idempotent and is not. A toolchain can
# carry a target's FILES (lib dir, per-component manifest, an entry in
# `components`) while `rustup target list --installed` still omits it — the shape
# a prebaked container image leaves behind. In that state `add` neither succeeds
# nor no-ops: it downloads, hits "detected conflict:
# lib/rustlib/<target>/lib/lib<x>.rlib", and rolls back. Every task that opens
# with `rustup target add` — cross-check, darwin-link — then fails for a reason
# that has nothing to do with the code under test.
#
# Split from `doctor` for the same reason gh-guard-check is split from gh-guard:
# the decision is the part worth testing, and it tests only if it is callable
# without the thing it decides about. `installed` is an ARGUMENT, not a rustup
# call, so the suite can drive every combination against a fixture directory.
#
# The truth of "is this target usable" is rustup's own answer, never the files:
# the files are what lie. Residue is any on-disk trace. The three verdicts:
#
#   ok       rustup has it. Nothing to do.
#   missing  no residue, rustup does not have it. A plain `add` works.
#   stale    residue WITHOUT rustup having it — the conflict state. The residue
#            must be purged before `add` can succeed.
#
# Residue WITH rustup having it is `ok`: that is simply an installed target.
set -uo pipefail

usage() {
	echo "usage: doctor-check <rustlib-dir> <target> <yes|no installed>" >&2
	exit 2
}

rustlib="${1:-}"
target="${2:-}"
installed="${3:-}"
[ -n "$rustlib" ] && [ -n "$target" ] || usage

case "$installed" in
yes | no) ;;
*) usage ;;
esac

if [ "$installed" = "yes" ]; then
	echo "ok"
	exit 0
fi

# Not installed as far as rustup is concerned — so any trace on disk is residue
# that will collide with the next `add`.
residue=no
[ -d "$rustlib/$target" ] && residue=yes
[ -e "$rustlib/manifest-rust-std-$target" ] && residue=yes
if [ -f "$rustlib/components" ] && grep -qxF "rust-std-$target" "$rustlib/components"; then
	residue=yes
fi

[ "$residue" = yes ] && echo "stale" || echo "missing"
exit 0
