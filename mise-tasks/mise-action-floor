#!/usr/bin/env bash
#MISE description="Gate: no workflow pins a toolchain-install action commit known to predate its download retry (CLOUD-404)"
#
# CLOUD-404. The toolchain install action fetched its own mise binary with a bare
# `curl -fsSL` and no retry, so a transient release-asset error (curl 22/503,
# curl 60/TLS) killed a job in provisioning — spending its minutes, redding the
# branch, and answering nothing. Three occurrences in two days. Upstream fixed it
# in `9dda3952d` (`retryDownload`, 5 attempts at 2s, wrapping both download tools
# and retrying on any thrown error) after our report, and we adopted that commit
# directly because it ships its own built `dist/`.
#
# WHY THIS GATE EXISTS, AND IT IS NOT ABOUT HUMANS FORGETTING. We adopted an
# UNRELEASED commit, so the pin no longer corresponds to a release tag. The pin
# comment used to name the major version alone, and `renovate.json5`
# tracks the `github-actions` ecosystem while `auto-bot-land.yml` lands bot
# bumps **with no human in the loop** — every check green is the only condition.
# A bot resolving that major back to the pre-retry commit would therefore be a
# silent DOWNGRADE to the un-retried install, auto-landed. That is strictly worse
# than the transient it reverts, because nothing announces it and the next
# occurrence reads as fresh.
#
# So the rule "do not slide back behind the retry" ships with its mechanism
# (non-negotiable 2): this gate reds such a pin at check time, the bot's PR
# cannot go green, and `auto-bot-land` cannot land it. The accepted cost is
# that such a PR then sits open and red until somebody closes it — stated here
# rather than discovered later.
#
# A DENYLIST OF KNOWN-BAD PINS, NOT A REQUIRED SHA. An "equals the expected
# commit" gate would fail every legitimate forward bump and demand a hand edit in
# lockstep with the bot — which is how a gate earns a bypass and then gets
# switched off. A denylist is silent on the next release and every one after it,
# and speaks only for the backslide. It also cannot answer "is this pin new
# enough", which is the honest limit: ancestry needs the network, so it lives on
# the issue as a checkable acceptance line rather than being faked offline here.
#
# WHICH BYTES: the INDEX (`git show :<path>`), the `timeout-check` and
# `lock-complete` idiom — exactly the bytes a commit would carry, identical in CI
# and in a sandbox, immune to whatever an editor left in the tree. Explicit path
# arguments win, which is how the bats suite drives fixtures without a git repo.
#
# Exit 0 pass, 1 a denylisted pin, 2 could-not-look. `2` is the `lock-complete`
# doctrine — "the gate could not read what it was asked to judge" — and a gate
# reporting green over bytes it failed to read is what gets a gate switched off.
set -euo pipefail

# ONE COORDINATE, and both the action name and the denylist are derived from it.
# Written as a real pinned coordinate rather than a bare vendor string on purpose:
# `attribution-check` exempts a line that NAMES a dependency (`uses:`, `@<40 hex>`)
# and flags the same name in prose as an appeal to authority — and the exemption is
# per LINE, so the spelling has to live where it reads as a coordinate. Deriving
# also means the sha appears once, so the name and the denylisted pin cannot drift.
#
# This is the pin that predates the retry: the latest release and the floating
# major tag both resolve to it, which is exactly what makes it the reachable
# backslide rather than a hypothetical one.
PRE_RETRY_COORDINATES="
uses: jdx/mise-action@7e36c90d9ab29c415a2384db3006f3ec8a8cc654
"

# The action every message and pattern below expands, taken from the first
# coordinate: everything left of the `@`, with the `uses: ` prefix dropped.
# `<<<` rather than a pipe into `grep -m1`: an early-exiting grep SIGPIPEs its
# producer, and under `pipefail` that makes a MATCH report failure — the inversion
# `pipefail-grep-check` gates, which caught exactly this line.
first_coordinate=$(grep -m1 '@' <<<"$PRE_RETRY_COORDINATES" || true)
if [ -z "$first_coordinate" ]; then
	echo "::error:: mise-action-floor: PRE_RETRY_COORDINATES declares no pinned coordinate, so this gate has nothing to judge against." >&2
	exit 2
fi
ACTION=${first_coordinate#*: }
ACTION=${ACTION%@*}

# The shas themselves. Add a coordinate above when a pin is found to predate a fix
# we depend on; never remove one, because a commit does not stop being pre-retry.
PRE_RETRY_PINS=$(sed -n 's/.*@//p' <<<"$PRE_RETRY_COORDINATES")

# Pointer-only per non-negotiable rule 4: the workflow, the line number and a
# short sha. Never a line of workflow content.
violations=0
report() {
	echo "::error:: $1" >&2
	violations=$((violations + 1))
}

# The files to judge. With arguments, those paths; without, every workflow in the
# index. Fixture mode is the argument form.
declare -a labels=()
declare -a sources=()
scratch=""
cleanup() { [ -z "$scratch" ] || rm -rf "$scratch"; }
trap cleanup EXIT

if [ "$#" -gt 0 ]; then
	for path in "$@"; do
		if [ ! -f "$path" ]; then
			echo "::error:: mise-action-floor: $path not found" >&2
			exit 2
		fi
		labels+=("$path")
		sources+=("$path")
	done
else
	scratch="$(mktemp -d)"
	tracked="$(git ls-files '.github/workflows/*.yml')"
	if [ -z "$tracked" ]; then
		echo "::error:: mise-action-floor: no tracked .github/workflows/*.yml — run from the repo, or pass paths" >&2
		exit 2
	fi
	while IFS= read -r path; do
		[ -n "$path" ] || continue
		blob="$scratch/$(basename "$path")"
		if ! git show ":$path" >"$blob" 2>/dev/null; then
			echo "::error:: mise-action-floor: $path is not in the index — stage it, or pass a path" >&2
			exit 2
		fi
		labels+=("$path")
		sources+=("$blob")
	done <<<"$tracked"
fi

# Every 40-hex pin of the action, as `<label>:<line>\t<sha>`. Scoped to this one
# action deliberately: the same sha prefix appearing in another coordinate, or in
# prose, is not this defect, and a gate that fires on a lookalike is a gate whose
# failures stop being read.
pins=""
for i in "${!labels[@]}"; do
	found=$(grep -nEo "$ACTION@[0-9a-f]{40}" "${sources[$i]}" 2>/dev/null || true)
	[ -n "$found" ] || continue
	while IFS= read -r hit; do
		[ -n "$hit" ] || continue
		line="${hit%%:*}"
		sha="${hit##*@}"
		pins+="${labels[$i]}:$line	$sha"$'\n'
	done <<<"$found"
done

# ANTI-VACUITY, and the precedent is explicit: `ci-tools-check`'s "no install_args
# lists found" refusal exists precisely so the thing under test cannot quietly
# vanish. A tree with no pin of this action at all is not a clean tree — it is a
# question this gate could not ask, so it is exit 2 rather than a pass.
if [ -z "${pins//[[:space:]]/}" ]; then
	echo "::error:: mise-action-floor: no \`$ACTION@<sha>\` pin found in the workflows judged — the install step is what this gate exists to hold, so its absence is unreadable, not clean." >&2
	exit 2
fi

total=0
while IFS=$'\t' read -r where sha; do
	[ -n "$sha" ] || continue
	total=$((total + 1))
	for bad in $PRE_RETRY_PINS; do
		[ "$sha" = "$bad" ] || continue
		report "mise-action-floor: $where pins $ACTION@${sha:0:9}, which predates the download retry (CLOUD-404). A bump to this commit is a silent downgrade to the un-retried install; \`auto-bot-land\` lands bot bumps unreviewed, which is why this is a gate and not a note."
	done
done <<<"$pins"

if [ "$violations" -gt 0 ]; then
	echo "::error:: mise-action-floor: $violations of $total pin(s) predate the download retry." >&2
	exit 1
fi

echo "mise-action-floor: $total pin(s), none predating the download retry"
