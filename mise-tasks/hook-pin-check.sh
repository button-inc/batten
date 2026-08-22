#!/usr/bin/env bash
#MISE description="Gate: no hook registered BY PATH may shell out to a mise-pinned tool, because a by-path invocation does not get mise's env"
#
# CLOUD-479's own trap, made computable rather than remembered.
#
# A hook registered as `mise run -q <task>` pays ~203ms of task-runner startup
# per call — measured, against 15-19ms for the same script invoked by path, on
# the one path where an agent cannot background anything. Registering by path is
# therefore the obvious fix, and it has one non-obvious cost: **a by-path
# invocation does not get mise's env**, so every tool the script assumes is the
# pinned one resolves to whatever the ambient PATH offers, or to nothing.
#
# That is not a latency question, it is a correctness one. Every hook here is
# fail-open by design — `|| exit 0`, `2>/dev/null`, an empty read that means
# "allow" — so a missing parser does not error. It silently allows. A gate that
# reports a clean session while checking nothing is strictly worse than the
# 203ms it saved, and it is invisible: nothing turns red.
#
# So the pairing is refused: registered by path AND shelling out to a tool
# `mise.toml` pins. Either invoke it through `mise run` and pay the startup, or
# stop depending on the pinned tool — which is what `stop-guard` and
# `contract-drift` did, moving their payload reads to `payload-field` and the
# compiled binary that is already on this path.
#
# ONE EXEMPTION, declared IN THE SCRIPT rather than listed here: a task may carry
# a `#PIN-OK: <tool>` line stating that it asserts the tool's presence itself.
# `mcp-attach-check` is the case that forced it — its two `jq` calls read a
# settings file and an MCP log, neither of which is a hook payload, so no
# extraction surface can serve them. It checks `command -v jq` and exits 2,
# loudly, rather than reading nothing. The exemption lives beside the assertion
# it describes so the two cannot drift apart; a list here would be a second
# authority on a fact the file already states.
#
# Not judged: `mise run` registrations. They get mise's env by construction, and
# this gate has nothing to say about them.
#
# Pointer-only per non-negotiable rule 4: the task name and the tool name, never
# a line of either file.
#
# Exit 0 clean / 1 a by-path registration depends on a pinned tool / 2 could not
# look (no settings file, no manifest).
#
# The mutation drops the by-path filter, so `mise run` registrations are judged
# too and the fixture that pairs `mise run` with a pinned tool reddens — a gate
# that cannot tell the two invocation shapes apart is not this gate.
#MUTANT pin-check-ignores-invocation-shape|s/case "\$command" in/case "mise run x" in/|a check blind to how a hook is invoked cannot refuse the pairing
set -uo pipefail

settings="${HOOK_PIN_SETTINGS:-.claude/settings.json}"
manifest="${HOOK_PIN_MANIFEST:-mise.toml}"
tasks_dir="${HOOK_PIN_TASKS:-mise-tasks}"

if [[ ! -f "$settings" ]]; then
	echo "::error:: hook-pin-check: no $settings — nothing to judge" >&2
	exit 2
fi
if [[ ! -f "$manifest" ]]; then
	echo "::error:: hook-pin-check: no $manifest — cannot tell which tools are pinned" >&2
	exit 2
fi

# The pinned set, read from `[tools]` and nothing else. A key is either bare
# (`zizmor`, `node`) or a backend coordinate (`"aqua:jqlang/jq"`), and it is the
# LAST path segment that names the executable — `aqua:jqlang/jq` is `jq`. Read
# from the manifest rather than restated, so pinning a tool enrols it here with
# no second edit.
pinned=$(awk '
	/^\[tools\]/ { in_tools = 1; next }
	/^\[/ { in_tools = 0 }
	in_tools && /^["a-zA-Z0-9]/ {
		key = $1
		gsub(/"/, "", key)
		n = split(key, parts, "/")
		print parts[n]
	}
' "$manifest" | sort -u)

if [[ -z "$pinned" ]]; then
	echo "::error:: hook-pin-check: no [tools] entries in $manifest — cannot tell which tools are pinned" >&2
	exit 2
fi

fail=0
judged=0

# Every registered hook command, one per line. `grep`+`sed` rather than `jq`,
# deliberately: a gate about depending on a pinned tool must not itself depend on
# one. It reads the committed text, which is the only thing it judges.
while IFS= read -r command; do
	[[ -n "$command" ]] || continue

	# BY PATH is the case this judges: a command naming a file under the tasks
	# directory. A `mise run` registration gets mise's env and is not this gate's
	# business.
	#
	# Matched on the tasks directory's BASENAME, not on `$tasks_dir` itself. The
	# two are the same in this repository and are not the same under test, where
	# the fixture directory is an absolute path — and a registration always names
	# the repo-relative segment. Conflating "where do I read the script" with
	# "what does the registration look like" made every fixture silently skip,
	# which is the shape of a gate that judges nothing while reporting clean.
	segment="${tasks_dir##*/}"
	case "$command" in
	*"/$segment/"*) ;;
	*) continue ;;
	esac

	task="${command##*/}"
	script="$tasks_dir/$task"
	[[ -f "$script" ]] || continue
	judged=$((judged + 1))

	# Comments stripped ONCE, into a variable, and deliberately not piped into
	# the `grep -q` below. `grep -q` exits on its first match, which SIGPIPEs the
	# producer, and under `pipefail` that makes the pipeline report failure —
	# so a MATCH would read as "no match" and the violation would vanish, the
	# more reliably the larger the file. `pipefail-grep-check` refuses that shape
	# and refused this one while it was being written.
	stripped=$(sed -e 's/#.*//' "$script")

	while IFS= read -r tool; do
		[[ -n "$tool" ]] || continue
		# A call to the tool, not a mention of it: the word at the start of a
		# command position. Comments are stripped first, so the paragraphs
		# explaining why a tool was dropped do not read as a dependency on it —
		# which is exactly what `stop-guard` and `contract-drift` now contain.
		if grep -qE "(^|[;&|(]|\\\$\\()[[:space:]]*${tool}[[:space:]]" <<<"$stripped" 2>/dev/null; then
			# The declared exemption, beside the assertion it describes.
			if grep -qE "^#PIN-OK:.*\\b${tool}\\b" "$script"; then
				continue
			fi
			echo "$task $tool" >&2
			fail=1
		fi
	done <<<"$pinned"
done <<<"$(grep -o '"command"[[:space:]]*:[[:space:]]*"[^"]*"' "$settings" | sed 's/.*"command"[[:space:]]*:[[:space:]]*"//; s/"$//')"

# A gate that judged nothing must not look like one that found nothing
# (CLOUD-418's class). Every registration being `mise run` is a legitimate state;
# a settings file this could not parse at all is not.
if [[ "$judged" -eq 0 ]]; then
	echo "hook-pin-check: no by-path hook registrations to judge" >&2
fi

if [[ "$fail" -ne 0 ]]; then
	echo "::error:: hook-pin-check: a hook registered BY PATH shells out to a mise-pinned tool, named above. By-path invocation does not get mise's env, so that tool resolves unpinned or not at all — and every hook here fails OPEN, so an absent one allows silently instead of erroring. Either register it as \`mise run -q <task>\`, or drop the dependency (see \`mise-tasks/payload-field.sh\`), or assert the tool yourself and declare \`#PIN-OK: <tool>\`." >&2
	exit 1
fi

echo "hook-pin-check: $judged by-path hook registration(s), none depending on a mise-pinned tool"
