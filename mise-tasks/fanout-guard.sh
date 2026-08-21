#!/usr/bin/env bash
#MISE description="PreToolUse hook body: bound a subagent spawn's reading manifest and prompt budget, at the one tool call nothing inspected (CLOUD-287)"
#
# CLOUD-287. `.claude/settings.json` mediates `Bash`, the edit tools, `*save_issue`
# and three connector verbs. No matcher named `Task`, so the one call that commits
# a whole fresh context window to a fresh agent was the only unmediated call in
# the wiring — and AGENTS.md's workflow contract had just been taught to price a
# spawn ("a token-consuming model call is metered in the same category, a subagent
# spawn above all", CLOUD-288) with no mechanism behind it. Non-negotiable 2: a
# rule without a runnable gate is half a change.
#
# WHAT IT MEASURED. Eight sibling agents were launched with prompts that each
# named the same eight artifacts as required reading — two specs, three memories,
# a gate script, an exemplar, the brief. The fixed per-agent cost was therefore
# paid eight times before any agent wrote a line, and the one that finished
# anything spent 63,848 tokens to fetch one issue and run one lint.
#
# WIDTH IS THE MULTIPLIER, THE MANIFEST IS THE MULTIPLICAND, and the multiplicand
# is the larger term: three agents reading twenty artifacts each costs more than
# twenty agents reading one. It is also the only term a hook can see. `PreToolUse`
# fires once per call and carries `tool_input`, so a spawn's prompt is in the
# envelope before the agent exists. Width is not: hooks fire per call, and
# counting siblings would mean inventing per-session state — which `stop-guard`
# declined for the same reason, documenting "no state file, no cursor".
#
# THE BLINDNESS, STATED RATHER THAN IMPLIED. This sees what a prompt INSTRUCTS,
# never what the agent then reads on its own initiative. A spawn told to read one
# file that goes on to read forty passes here and always will. Capping what is
# written into the prompt is not a claim about what the agent does with it.
#
# TWO CONJUNCTS, both pure functions of the envelope — no network, no state, no
# transcript:
#
#   reading-manifest  the deduped artifacts the prompt names, over
#                     BATTEN_FANOUT_READING_CAP (default 3; the failure named 8).
#   prompt-budget     the prompt's own size, over BATTEN_FANOUT_PROMPT_BUDGET
#                     (default 1500 tokens).
#
# A TOKEN COUNTS ONLY IF IT NAMES SOMETHING THAT EXISTS. The manifest is not "what
# looks like a path" — it is path-shaped tokens INTERSECTED WITH THE TRACKED TREE,
# plus `mem:` references resolved against the memories directory. That is what
# makes this decidable rather than a guess: `origin/main`, a URL, and a prose
# slash name no tracked file and drop out by construction, with no allowlist to
# tune and no false positive to appeal. It costs one `git ls-files` and no
# network. `memories-check` is the precedent for both the enumeration and the
# `mem:` charset.
#
# THE COUNTING CONVENTION IS THE ENGINE'S, not a second one. `budget.rs` estimates
# bytes over four, over what actually loads — frontmatter and block comments
# stripped first. A prompt carries neither, so characters over four here is the
# same arithmetic rather than a rival convention. Shelling out to `batten policy
# budget` for it would make a fail-open hook depend on a built binary and a config
# file, which is the direction this must never take.
#
# PAYLOAD READS GO THROUGH `payload-field`, never `jq` (CLOUD-479): this is
# registered BY PATH, so it does not get mise's env, and a `jq` that resolved to
# nothing would turn every fail-open read into a silent allow. `hook-pin-check`
# refuses that pairing.
#
# Pointer-only per non-negotiable 4: the count, the cap, and the deduped repo
# PATHS. Never a byte of the prompt, which is the likeliest place in this whole
# wiring for consumer detail to appear.
#
# Exit 0 ALWAYS — a guard renders its verdict in the JSON, never in the status.
# Fails OPEN on everything it cannot establish: no payload, no extractor, an
# absent prompt, a tree it cannot enumerate, and BATTEN_FANOUT_GUARD_BYPASS.
#
# The mutation drops the manifest conjunct's refusal, so an eight-artifact spawn
# is allowed and only the manifest cases can catch it.
#MUTANT manifest-not-capped|s@^READING_CAP_DEFAULT=.*@READING_CAP_DEFAULT=100000@|a manifest over the cap is refused
set -uo pipefail

READING_CAP_DEFAULT=3
PROMPT_BUDGET_DEFAULT=1500

[ -n "${BATTEN_FANOUT_GUARD_BYPASS:-}" ] && exit 0

cap="${BATTEN_FANOUT_READING_CAP:-$READING_CAP_DEFAULT}"
budget="${BATTEN_FANOUT_PROMPT_BUDGET:-$PROMPT_BUDGET_DEFAULT}"

raw=$(cat) || exit 0
[ -n "$raw" ] || exit 0

here="$(dirname -- "${BASH_SOURCE[0]}")"
field="$here/payload-field.sh"
[ -x "$field" ] || exit 0

tool=$(printf '%s' "$raw" | "$field" tool-name) || exit 0
case "$tool" in
Task | *__Task) ;;
*) exit 0 ;;
esac

prompt=$(printf '%s' "$raw" | "$field" prompt) || exit 0
[ -n "$prompt" ] || exit 0

# A deny document on stdout with exit 0 — the in-band channel this host reads and
# the shape every guard here emits. The reason is built by the caller; this only
# escapes it, since a prompt-derived path could carry a quote.
decide() {
	local reason="$1" escaped
	escaped=${reason//\\/\\\\}
	escaped=${escaped//\"/\\\"}
	escaped=${escaped//$'\n'/\\n}
	printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"%s"}}\n' "$escaped"
	exit 0
}

# --- conjunct 1: the reading manifest ----------------------------------------
#
# Tracked paths and resolvable `mem:` names, deduped. `git ls-files` is the one
# enumeration; a spawn naming a file that is not tracked is naming nothing this
# repo can be made to read, so it does not count against the cap.
tracked=$(git ls-files 2>/dev/null) || tracked=""
memories=".serena/memories"

manifest=""
if [ -n "$tracked" ]; then
	# Path-shaped candidates first, then the intersection. Splitting on anything
	# that cannot appear in a repo path keeps prose punctuation out of the token.
	candidates=$(printf '%s' "$prompt" |
		tr -c 'A-Za-z0-9_./-' '\n' |
		grep -E '^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$' |
		sort -u) || candidates=""
	for candidate in $candidates; do
		# `<<<`, never a pipe: `grep -q` exits on the first match, and under
		# pipefail that SIGPIPEs the producer so a MATCH reports failure
		# (`pipefail-grep-check`).
		grep -qxF "$candidate" <<<"$tracked" && manifest+="$candidate"$'\n'
	done
fi

# `mem:NAME` resolves against the memories tree, the same charset `memories-check`
# restates from the reference matcher.
refs=$(printf '%s' "$prompt" | grep -oE 'mem:[A-Za-z0-9_/-]+' | sort -u) || refs=""
for ref in $refs; do
	name="${ref#mem:}"
	[ -f "$memories/$name.md" ] && manifest+="$memories/$name.md"$'\n'
done

manifest=$(printf '%s' "$manifest" | grep -v '^$' | sort -u) || manifest=""
count=0
[ -n "$manifest" ] && count=$(printf '%s\n' "$manifest" | grep -c '^')

if [ "$count" -gt "$cap" ]; then
	decide "fanout-guard: this spawn names $count required-reading artifacts, over the cap of $cap. The fixed cost of reading them is paid once PER AGENT before any of them writes a line — the manifest is the multiplicand and it dominates the fleet width. Cheaper shapes: compute one digest ONCE and pass that, or name only the artifacts this agent must read to do its own step. Paths: $(printf '%s' "$manifest" | tr '\n' ' '). Raise deliberately with BATTEN_FANOUT_READING_CAP, or bypass with BATTEN_FANOUT_GUARD_BYPASS=1."
fi

# --- conjunct 2: the prompt budget -------------------------------------------
#
# Characters over four, `budget.rs`'s estimate over a body that carries no
# frontmatter and no block comments to strip.
tokens=$((${#prompt} / 4))
if [ "$tokens" -gt "$budget" ]; then
	decide "fanout-guard: this spawn's prompt is about $tokens tokens, over the budget of $budget. Every token here is spent before the agent begins, and again for each sibling. Put the standing context where it is read once — a memory, a rule file, the always-loaded surface — and let the prompt name the step. Raise deliberately with BATTEN_FANOUT_PROMPT_BUDGET, or bypass with BATTEN_FANOUT_GUARD_BYPASS=1."
fi

exit 0
