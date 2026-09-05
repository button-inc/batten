#!/usr/bin/env bash
#MISE description="Decide whether a diff can move the hk slow tier, so a diff that cannot does not pay for it (CLOUD-398)"
#
# THE SHAPE, AND WHY IT IS A DENY-LIST RATHER THAN AN ALLOW-LIST. `rust-paths-check`
# judges an allow-list: `rust.yml` names the paths that MUST select its jobs. That
# is correct there because those four jobs decide a pure function of the Rust tree
# and the inputs are enumerable. The hk slow tier is not enumerable the same way:
# `cargo-clippy` declares no glob at all and `batten-check` declares `**`, so any
# attempt to list "what the slow tier reads" is a list that is wrong the moment
# someone adds a step.
#
# So this inverts the default. The slow tier runs unless EVERY changed path is on
# a short list of paths proven inert to it. A wrong entry on that list is the only
# way to lose a verdict, which makes the list the whole review surface — and it is
# five lines rather than a derivation nobody can check.
#
# WHAT MAKES AN ENTRY ADMISSIBLE, measured 2026-08-21 rather than argued. The six
# slow steps and the hk globs that select them:
#
#   token-bench-check  bench/tokens/*, bench/tokens/fixtures/**, mise-tasks/token-bench*,
#                      and four crates/batten/src/*.rs files. Regenerates from COMMITTED
#                      fixtures, so it never reads the live tree.
#   sbom-check         Cargo.lock, .github/workflows/*
#   test:bats          mise-tasks/**, tests/*.bats
#   test               **/*.rs, **/Cargo.toml, Cargo.lock, crates/batten/tests/fixtures/**, batten.toml
#   cargo-clippy       no glob, but a pure-Rust verdict
#   batten-check       `**` — reaches everything, INCLUDING the entries below
#
# That last row is why `batten-check` is not in the slow tier as far as CI is
# concerned any more: `batten.toml`'s `no-secrets` rule is `kind = "secrets"`,
# `glob = "**"`, `scope = "tree"`, `severity = "deny"` — the repository's only
# secrets scan. Skipping it on a memories-only diff would let a credential in a
# memory file land with every required check green. The `ci` job therefore runs
# `mise run batten-check` unconditionally, and it costs 259ms warm (measured; the
# `slow` tag on it is about the `cargo run` build it depends on, not the check).
#
# Exit 0 the slow tier is needed / 1 it is not / 2 could not look.
set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || exit 2

# PATHS PROVEN INERT TO THE SLOW TIER. Every entry needs the argument above made
# for it before it is added. Prefix match, `/`-terminated for a directory.
readonly INERT=(
	".serena/memories/"
	".coderabbit.yaml"
)

inert() { # $1 = path — 0 when some INERT entry covers it
	local path="$1" entry
	for entry in "${INERT[@]}"; do
		case "$entry" in
		*/) [[ "${path#"$entry"}" != "$path" ]] && return 0 ;;
		*) [[ "$path" = "$entry" ]] && return 0 ;;
		esac
	done
	return 1
}

# THE PROBE MODE IS THE GATE. `rust-paths-check` is a separate program because the
# thing it judges is a YAML list it does not own. This program owns its own list,
# so a second program asserting things about it would be the second authority
# non-negotiable 6 condemns. Instead the claims are probes here, run by
# `tests/ci-slow-needed.bats` and by `verify`.
#MUTANT inert-may-swallow-everything|s@^\treturn 1$@\treturn 0@|a crates change still needs the slow tier
#MUTANT inert-entry-may-stop-matching|s@\t".serena/memories/"@\t".never-matches/"@|a memories-only diff does not need the slow tier
if [[ "${1:-}" = "--probe" ]]; then
	status=0
	# MUST NEED IT: a path a change to which can move one of the six.
	for probe in \
		crates/batten/src/lib.rs \
		Cargo.lock \
		batten.toml \
		mise.toml \
		bench/tokens/fixtures/x \
		.github/workflows/ci.yml \
		.claude/hooks/git-hook.sh \
		AGENTS.md; do
		if inert "$probe"; then
			echo "::error:: ci-slow-needed: '$probe' is treated as inert, but a change to it can move the slow tier — the verdict would be silently not taken." >&2
			status=1
		fi
	done
	# MUST NOT NEED IT: the half that pays for the split, and the half that erodes
	# silently, since a narrowing here is invisible except as a bill.
	for probe in \
		.serena/memories/core.md \
		.coderabbit.yaml; do
		if ! inert "$probe"; then
			echo "::error:: ci-slow-needed: '$probe' is not treated as inert, so a diff that cannot move the slow tier still pays for it." >&2
			status=1
		fi
	done
	[[ "$status" -eq 0 ]] && echo "ci-slow-needed: every probe honoured — $((${#INERT[@]})) inert prefix(es)"
	exit "$status"
fi

base="${1:-}"
head="${2:-HEAD}"
if [[ -z "$base" ]]; then
	echo "::error:: ci-slow-needed: no base revision given, so there is no diff to judge." >&2
	exit 2
fi

files=$(git diff --name-only "$base" "$head" 2>/dev/null) || {
	echo "::error:: ci-slow-needed: could not diff $base..$head." >&2
	exit 2
}

# NO CHANGED FILES IS NOT "NOTHING TO DO". An empty diff means the comparison did
# not look — a wrong base, a shallow clone — and answering "skip the slow tier"
# there would be the false-absent this program exists to avoid.
if [[ -z "${files//[[:space:]]/}" ]]; then
	echo "::error:: ci-slow-needed: $base..$head reports no changed files, which is could-not-look rather than a clean diff." >&2
	exit 2
fi

while IFS= read -r path; do
	[[ -n "$path" ]] || continue
	if ! inert "$path"; then
		echo "ci-slow-needed: '$path' can move the slow tier"
		exit 0
	fi
done <<<"$files"

echo "ci-slow-needed: every changed path is inert to the slow tier"
exit 1
