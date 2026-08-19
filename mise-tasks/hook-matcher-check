#!/usr/bin/env bash
#MISE description="Gate: every [[verb]] batten.toml declares actually reaches the engine — the PreToolUse matcher delivers the call it judges"
#
# CLOUD-471. The `matcher` on the `PreToolUse` entry in `.claude/settings.json`
# decides which tool calls the host spawns the hook for AT ALL. It is a coverage
# boundary on the whole engine, and it lives in a file `batten` never reads.
#
# So a `[[verb]]` row can load, validate, and gate nothing. `verbs::validate`
# refuses an inert verb by EFFECT — a non-mutating entry in the mutating table —
# and refuses a duplicate declaration; neither predicate can see a verb the host
# will never deliver, because the matcher is not an input to it. `adjudicate`
# classifies through `verbs::classify(&policy.verbs, &envelope.tool)`, so a row
# naming a tool outside the matcher is unreachable: the process is not spawned,
# no envelope is decoded, and the symptom is an allow indistinguishable from a
# pass.
#
# THE SAME SILENCE ALREADY EARNS A GATE ONE TABLE OVER. `mcp-allow-check` exists
# because "a permission rule that grants nothing is silent by construction". That
# gate owns the `permissions` half of this file; this owns the `hooks` half, and
# `hooks-wiring-check` owns neither — it compares the EVENT and the COMMAND of
# each registration and says so out loud ("THE MATCHER IS NOT COMPARED"), on the
# correct reasoning that a matcher derived from the `Harness` enum would be the
# repo-agnostic core asserting a consumer's tool vocabulary. Which is why the
# question lands here, in a consumer's own gate, rather than in the derivation.
#
# ONE PREDICATE, NOT TWO, and this is the whole design. Every verb reaches the
# engine by exactly one of two routes, and the route decides which token the
# matcher has to carry:
#
#   a TOOL name   arrives as `envelope.tool`, so the matcher must cover the
#                 verb's own name. `Harness::ClaudeCode::write_tools()` is the
#                 tool-name set the engine itself declares, and it is READ from
#                 there rather than restated here — a second copy is a second
#                 authority, and this repo has paid for one of those.
#
#   a PROGRAM     arrives inside `envelope.command`, which only a `Bash` call
#                 carries, so the matcher must cover `Bash` and nothing else.
#                 `rm`, `mv`, `>`, `>>`, `tee`, `sponge`, `truncate`, `shred`,
#                 `sed`, `cp`, `install` and `git <sub>` are all this shape.
#
# So: required token = the verb itself when the engine calls it a write TOOL,
# `Bash` otherwise. Uncovered means no `PreToolUse` matcher that invokes the
# engine matches that token. Stating it as one rule over a routing fact is what
# keeps a new verb from needing a new branch here.
#
# THE HONEST LIMIT, stated rather than left to be rediscovered: a verb naming a
# host tool the engine does NOT declare as a write tool reads here as a shell
# program and is judged against `Bash`. Telling `Task` from `rm` needs the host's
# whole tool inventory, which no committed file carries, and guessing would fail
# in the direction that reports a gap where there is none — the false positive
# that gets a gate switched off. It under-denies, the sanctioned direction
# (house-style §5).
#
# AN EMPTY OR ABSENT `matcher` IS COVERAGE, NOT A GAP. The host reads it as
# match-all, which is broader than any enumeration, so reporting it as a miss
# would fail a wiring that gates strictly more than the one this gate wants.
# A literal `*` is the same claim written out.
#
# WHICH ENTRIES COUNT: only those whose hooks actually invoke the engine — the
# `batten-hook.sh` launcher or `batten hook` itself. The other `PreToolUse`
# entries in this file register `mise-tasks/*` guards with their own matchers,
# and reading one of those as coverage would be this gate answering about a
# process the engine never runs.
#
# Pointer-only per non-negotiable rule 4: the verb name, the token it needed, the
# line that declares it, and a count. Never a byte of either file's contents.
#
# Exit 0 covered / 2 an uncovered verb (a verdict about the wiring) / 1 an input
# that cannot be read. A file that cannot be read fails OPEN in `mcp-allow-check`'s
# shape — loud, and never a `2`, because "I could not look" must not reach a
# reader as "the wiring is wrong".
#
# The mutation judges every verb against its own name, so the eight shell
# programs stop being satisfied by `Bash` and the committed tree — whose matcher
# names none of them, correctly — reads as eight uncovered rows.
#MUTANT matcher-ignores-the-route|s/required="Bash"/required="$verb"/|the committed tree is covered
set -euo pipefail

# Guarded rather than `cd "$(git ...)"`: an unguarded one swallows the failure —
# the substitution is empty, `cd ""` succeeds, and the defaults below then resolve
# against whatever directory the caller happened to be in. Outside a checkout the
# defaults simply do not exist, which the file checks report as "could not look".
if root=$(git rev-parse --show-toplevel 2>/dev/null) && [ -n "$root" ]; then
	cd "$root"
fi

# All three inputs are ARGUMENTS defaulting to the real files, for the reason
# `batten-glob-check` takes both of its: the decision is the part worth testing,
# and it only tests if the suite can point it at fixtures carrying a gap the real
# tree must never have.
SETTINGS="${1:-.claude/settings.json}"
CONFIG="${2:-batten.toml}"
SOURCE="${3:-crates/batten/src/hook.rs}"

cannot_look() {
	echo "::error:: hook-matcher-check: $*" >&2
	exit 1
}

[ -f "$SETTINGS" ] ||
	cannot_look "$SETTINGS does not exist, so the coverage boundary cannot be read at all"
[ -f "$CONFIG" ] ||
	cannot_look "$CONFIG does not exist, so there is no [[verb]] table to judge"
[ -f "$SOURCE" ] ||
	cannot_look "$SOURCE does not exist, so the engine's own write-tool set cannot be read"

# --- what the engine calls a write TOOL --------------------------------------
#
# The `Harness::ClaudeCode` arm of `write_tools()`, read out of the source rather
# than restated. Bounded by the function header on one side and the arm's own
# closing `]` on the other, so a neighbouring arm's spellings cannot be read as
# this host's — `Harness::GeminiCli` names `WriteFile`, which this host does not
# have.
tools=$(awk '
	/fn write_tools/ { in_fn = 1; next }
	!in_fn           { next }
	/Harness::ClaudeCode/ { arm = 1 }
	arm {
		rest = $0
		while (match(rest, /"[^"]*"/)) {
			print substr(rest, RSTART + 1, RLENGTH - 2)
			rest = substr(rest, RSTART + RLENGTH)
		}
		if (index($0, "]") > 0) { arm = 0; in_fn = 0 }
	}
' "$SOURCE")

# A parse that found nothing is not a host with no write tools. Every verb would
# route to `Bash` and the whole tool half of the predicate would silently stop
# being asked — green, and checking exactly nothing.
[ -n "$tools" ] ||
	cannot_look "read no tool name out of write_tools()'s Harness::ClaudeCode arm in $SOURCE — a parse that found nothing is not a host that declares nothing"

# --- what the config declares -------------------------------------------------
#
# `<verb>\t<line>` per `[[verb]]` row, so a finding can point at the line that
# declares it. One front-end declaring two mutating subcommands is two rows and
# one coverage question, so the first line wins and the second is dropped.
verbs=$(awk '
	/^\[\[verb\]\]/ { table = 1; next }
	/^\[/           { table = 0; next }
	table && /^verb = "/ {
		line = $0
		sub(/^verb = "/, "", line)
		sub(/".*$/, "", line)
		print line "\t" NR
	}
' "$CONFIG" | awk -F'\t' '!seen[$1]++')

# Absent and unparseable are different answers, and collapsing them is how a
# containment check goes vacuously green. A config declaring no verbs has nothing
# to cover; a config whose rows this gate could not read is a parse that failed.
declared=$(grep -c '^\[\[verb\]\]' "$CONFIG" || true)
if [ -z "$verbs" ]; then
	[ "$declared" = 0 ] ||
		cannot_look "read no verb name out of $declared [[verb]] row(s) in $CONFIG — a parse that found nothing is not a table with nothing in it"
	echo "hook-matcher-check: $CONFIG declares no [[verb]] rows — nothing to cover"
	exit 0
fi

# --- what the wiring delivers -------------------------------------------------
#
# Selected on "does this entry invoke the engine", which is the same launcher
# indirection `hooks-wiring-check` resolves: the committed wiring runs
# `.claude/hooks/batten-hook.sh`, never `batten hook` directly.
readonly ENGINE='batten-hook\.sh|batten hook'

if ! entries=$(jq -r --arg engine "$ENGINE" '
    [ (.hooks.PreToolUse // [])[]
      | select([ (.hooks // [])[] | .command // "" ] | any(test($engine)))
    ] | length' "$SETTINGS" 2>/dev/null); then
	cannot_look "$SETTINGS is not readable JSON, so which calls the host delivers cannot be decided"
fi

# The matcher of each such entry, with an absent one collapsed to the empty
# string the host already reads as match-all. Meaningful only alongside the count
# above: an empty LIST and a list holding one empty MATCHER are opposite answers
# and look identical here.
matchers=$(jq -r --arg engine "$ENGINE" '
    (.hooks.PreToolUse // [])[]
    | select([ (.hooks // [])[] | .command // "" ] | any(test($engine)))
    | .matcher // ""' "$SETTINGS")

# Does this matcher deliver this token? The host applies the matcher as a regular
# expression against the tool name, so this does too — an anchored reading would
# report `MultiEdit` uncovered under a matcher of `Edit` that in fact delivers it,
# and a false gap is what gets a gate switched off.
delivers() { # $1 = required token, $2 = matcher
	local rc=0
	# Absent, empty, or a literal `*`: the host's match-all, which is broader
	# than any enumeration and therefore coverage rather than a gap.
	if [ -z "$2" ] || [ "$2" = "*" ]; then
		return 0
	fi
	grep -qE -- "$2" <<<"$1" || rc=$?
	# Exit 1 is "no match"; anything above it is "could not compile", which is a
	# question this gate cannot answer either way.
	if [ "$rc" -gt 1 ]; then
		cannot_look "$SETTINGS carries a PreToolUse matcher that is not a regular expression this gate can compile, so coverage cannot be decided"
	fi
	return "$rc"
}

fail=0
uncovered=0
report() {
	[ "$uncovered" = 0 ] &&
		echo "::error:: a [[verb]] in $CONFIG names a call the host never delivers, so the row loads, validates and gates nothing (CLOUD-471):" >&2
	printf '  %s\n' "$1" >&2
	uncovered=$((uncovered + 1))
	fail=2
}

checked=0
while IFS=$'\t' read -r verb line; do
	[ -n "$verb" ] || continue
	checked=$((checked + 1))

	# The route decides the token: a write tool arrives as `envelope.tool` and
	# needs its own name; everything else arrives inside `envelope.command`,
	# which only a `Bash` call carries.
	required="Bash"
	if grep -qxF -- "$verb" <<<"$tools"; then
		required="$verb"
	fi

	covered=0
	if [ "$entries" -gt 0 ]; then
		while IFS= read -r matcher; do
			if delivers "$required" "$matcher"; then
				covered=1
				break
			fi
		done <<<"$matchers"
	fi

	[ "$covered" = 1 ] ||
		report "$CONFIG:$line: \`$verb\` needs \`$required\` — no PreToolUse matcher invoking the engine covers it, so the host never spawns the hook and the row is dead config"
done <<<"$verbs"

if [ "$fail" = 0 ]; then
	echo "hook-matcher-check: all $checked declared verb(s) in $CONFIG reach the engine — every required matcher token is covered by one of the $entries PreToolUse entries that invoke it"
else
	echo "  $uncovered of $checked declared verb(s) are uncovered; $entries PreToolUse entries invoke the engine" >&2
fi
exit "$fail"
