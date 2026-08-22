#!/usr/bin/env bash
#MISE description="Gate: the turn declared a stopping point with work not landed, as CLOUD-97's detector already decided it (reads the findings store; pointer-only)"
#
# CLOUD-97's verdict, finally read by something. The engine has carried
# `completion.unlanded` — *declared done with work not landed* — since it
# shipped: a conjunction of a completion marker in the session transcript and
# `git::landing` finding no patch-id-equivalent commit on the landing target.
# It is the machine form of the one question a human kept having to ask by hand.
#
# THIS FILE DECIDES NOTHING, and that is the whole design. It computes no
# landedness, parses no git output, and knows no landing target. `batten state
# record` evaluates the predicate and mints the finding; this reads the store
# and points at what is already there. `stop.rs`'s own rule — "both inputs are
# consumed, never re-derived" — applies with more force here than there, because
# a second bash answer to "is this landed" is exactly the drift the engine
# exists to refuse (non-negotiable 3), and bash would answer it by ancestry
# where the engine answers by PATCH IDENTITY. A rebased-and-landed branch is
# clean to the engine and dirty to any reachability test.
#
# WHY THE PLAIN LISTING RATHER THAN `-J`. `batten state list` emits
# `<fingerprint> <rule> <ref> <count>` — pointer-only by the engine's own
# contract, and parseable with the shell alone. The JSON form would need `jq`,
# which this path deliberately does not have: CLOUD-479 moved the whole Stop
# registration to by-path invocation, and a by-path call does not get mise's
# env, so the pinned `jq` silently becomes an unpinned `/usr/bin/jq` or nothing.
# `payload-field` exists for exactly that reason on the payload side; here the
# engine already emits a shell-shaped answer, so no parser is needed at all.
#
# NO DISPOSITION FILTER, and it is a decision rather than an omission. `stop.rs`
# consults dispositions because it BLOCKS, and a denial the agent already
# answered must not wedge a turn. This only asks a question, and the finding
# self-clears the moment the work lands — `Observed(0)` next scan, no
# acknowledgement from anybody — so the state that would need discharging
# resolves itself. Reading dispositions would buy a `jq` dependency for a
# distinction nothing here acts on.
#
# ONCE PER HEAD, which is what keeps it a nudge rather than a nag. The finding
# holds for as long as the work is unlanded, so an unsuppressed rule would
# repeat the same pointer at every turn end for the rest of the session — and
# `stop-guard`'s own header records where that ends: "two nudges on one turn is
# how a channel stops being read". A new commit is a new answer to "is this
# landed yet", so the receipt is keyed on the HEAD sha and a fresh commit earns
# a fresh pointer.
#
# Fails OPEN on everything — no binary, no repo, no store, an unreadable receipt
# — and on BATTEN_UNLANDED_CHECK_BYPASS. It runs inside a Stop hook, and no
# failure this can produce may be the reason a turn cannot end.
#
# Exit 0 clean or could-not-look, 1 the predicate fired (pointer on stdout).
#
# MUTATION COVERAGE (CLOUD-418). `<slug>|<sed script>|<case name>`: applying
# the script to a throwaway copy of this file must turn the named case RED.
# NO `|` IN A SCRIPT FIELD: the row is split on it, so a `||` inside a sed
# expression silently eats the case name and the harness reports the wrong
# defect. Deleting the guard line is the cleaner mutation anyway — it removes the
# predicate rather than rewriting it into a tautology.
#MUTANT ref-never-matched|s@^\t\[\[ "\$ref" = "\$context".*@@|another branch's finding is not this turn's
#MUTANT suppression-removed|s@^\tseen_file="\$git_dir.*@\tseen_file=""@|it asks once per HEAD, then goes quiet
set -uo pipefail

[[ -n "${BATTEN_UNLANDED_CHECK_BYPASS:-}" ]] && exit 0

RULE_ID="completion.unlanded"

cd "${CLAUDE_PROJECT_DIR:-$(git rev-parse --show-toplevel 2>/dev/null)}" 2>/dev/null || exit 0

# The resolution chain `.claude/hooks/batten-hook.sh` used before CLOUD-824
# deleted it, kept here for the reason that launcher had one: a `cargo run` per
# turn end would contend for the target-dir lock `hk.pkl` deliberately
# serialises. `mise run install:local` now puts `batten` on PATH, so the last
# candidate is the ordinary answer and the two before it are the fallback for a
# clone that has built but not installed.
bin=""
for candidate in \
	"${BATTEN_BIN:-}" \
	"target/release/batten" \
	"target/debug/batten" \
	"$(command -v batten 2>/dev/null || true)"; do
	if [[ -n "$candidate" ]] && [[ -x "$candidate" ]]; then
		bin="$candidate"
		break
	fi
done
[[ -n "$bin" ]] || exit 0

branch=$(git symbolic-ref --quiet --short HEAD 2>/dev/null) || exit 0
[[ -n "$branch" ]] || exit 0
context="refs/heads/$branch"
head=$(git rev-parse HEAD 2>/dev/null) || exit 0

listing=$("$bin" state list 2>/dev/null) || exit 0
[[ -n "$listing" ]] || exit 0

# The receipt lives beside the lease and board-write records, in the git dir —
# out of the tree, so a nudge never dirties the worktree it is asking about.
seen_file=""
if git_dir=$(git rev-parse --git-dir 2>/dev/null) &&
	[[ -n "$git_dir" ]] &&
	mkdir -p "$git_dir/batten-receipts" 2>/dev/null; then
	seen_file="$git_dir/batten-receipts/unlanded-nudged.${branch//\//-}"
fi

pointer=""
while read -r _fingerprint rule ref count; do
	[[ "$rule" = "$RULE_ID" ]] || continue
	[[ "$ref" = "$context" ]] || continue
	# `skipped`/`errored` are the engine's words for "did not look", and a
	# question asked on the strength of a scan that never ran is the false
	# green in nudge form. Only an observed, positive count is a finding.
	case "$count" in
	'' | *[!0-9]*) continue ;;
	0) continue ;;
	esac
	pointer="unlanded: $count commit(s) not on the landing target ($rule)"
done <<<"$listing"

[[ -n "$pointer" ]] || exit 0

if [[ -n "$seen_file" ]] && [[ -f "$seen_file" ]] && grep -qxF "$head" "$seen_file" 2>/dev/null; then
	exit 0
fi
[[ -z "$seen_file" ]] || printf '%s\n' "$head" >>"$seen_file" 2>/dev/null || true

printf '%s\n' "$pointer"
exit 1
