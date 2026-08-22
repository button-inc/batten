#!/usr/bin/env bash
#MISE description="Print one field of a hook payload on stdin, via the compiled binary — the jq-free reader the by-path hooks use"
#
# CLOUD-479. Three hook registrations paid ~203ms of `mise` startup each, per
# turn, to do single-digit milliseconds of work. `mise --version` alone measured
# 203ms against 15-19ms for a by-path invocation of the same script, and the
# per-turn bill was ~180ms at `Stop` plus ~275ms at `UserPromptSubmit` — on the
# one path where an agent cannot background anything.
#
# The obvious fix — register them by path — was blocked by exactly one thing, and
# it is worth stating because it is the whole reason this file exists rather than
# a one-line settings edit. Those hooks shell out to `jq`; `mise.toml` pins
# `"aqua:jqlang/jq"`; a by-path invocation does not get mise's env, so it would
# resolve an unpinned `/usr/bin/jq`. Every one of those reads is guarded
# `|| exit 0` per the fail-open posture, so on a container with NO system `jq`
# the guard would not error — it would silently allow. A latency fix that turns a
# pinned dependency into a silent fail-open is a worse defect than the latency.
#
# So the parse moves into the binary that is already on this path, which parses
# this exact payload today: `batten payload field`, over `hook::decode`, with the
# BOM strip and the per-harness aliases it already carries. No new parser, no new
# dependency, and nothing duplicated from mise or hk — provisioning the toolchain
# is mise's job, and being on the per-turn hot path is not.
#
# ONE AUTHORITY FOR "WHERE IS THE BINARY", which is why this is a file rather
# than a copied loop. Three callers resolving it independently is three chances
# to disagree about the fallback order, and the loud-when-missing posture below
# only works if it is stated once.
#
# LOUD, BUT STILL OPEN. A missing extractor writes an `::error::` line and exits
# non-zero with nothing on stdout, so a caller's `|| exit 0` still fails open —
# the turn is never blocked by this — while the reason reaches a channel a human
# reads. The alternative, silence, is precisely the fail-open-by-accident this
# issue refuses for `jq`, and it would be worse here because it would be OUR
# doing rather than the environment's.
#
# Usage: printf '%s' "$raw" | payload-field <field-name> [<harness>]
#
# Exit 0 with the value (or with nothing, for an absent field or an undecodable
# payload — the two a caller cannot act on differently anyway, matching the
# `jq -r '.x // empty'` spelling this replaces). Exit 1 only when the extractor
# itself could not be found or run.
set -uo pipefail

field="${1:-}"
harness="${2:-claude-code}"
if [[ -z "$field" ]]; then
	echo "::error:: payload-field: no field named — usage: payload-field <field-name> [<harness>]" >&2
	exit 1
fi

# ANCHORED ON THIS FILE, never on cwd. `.claude/hooks/batten-hook.sh` resolves
# from cwd because it is the launcher and needs the repository root for config
# anyway; this only needs to find a binary, and its own location is the one
# thing that cannot be wrong. Anchoring on cwd made it fail wherever a caller was
# invoked against a different repository — which is every `contract-drift` case
# in `tests/contract-drift.bats`, whose fixture clone has no `target/`, and would
# equally be a hook fired with cwd inside a submodule or a worktree.
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)" || {
	echo "::error:: payload-field: cannot resolve the repository root from $0" >&2
	exit 1
}

# First executable wins, in the same order and with the same documented override
# as `.claude/hooks/batten-hook.sh`. BATTEN_BIN exists so a bats suite can point
# this at a stub without a rebuild.
bin=""
for candidate in \
	"${BATTEN_BIN:-}" \
	"$root/target/release/batten" \
	"$root/target/debug/batten" \
	"$(command -v batten 2>/dev/null || true)"; do
	if [[ -n "$candidate" ]] && [[ -x "$candidate" ]]; then
		bin="$candidate"
		break
	fi
done

if [[ -z "$bin" ]]; then
	echo "::error:: payload-field: no batten binary (looked at \$BATTEN_BIN, target/release/batten, target/debug/batten, PATH) — the hook that called this is reading nothing. Run: mise run build:release" >&2
	exit 1
fi

exec "$bin" payload field --harness "$harness" --name "$field"
