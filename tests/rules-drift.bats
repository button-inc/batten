#!/usr/bin/env bats
# subject: mise-tasks/rules-drift
# CLOUD-506. Each case builds a fixture rules tree, a fixture settings file and a
# fixture task, so the predicate is exercised over text the gate has never seen —
# and two cases run it over this repo's real files, which is the only assertion
# that can catch the gate drifting away from what it guards.
#
# The gate exists to fail a restated value that is WRONG. The false-positive
# direction is load-bearing here in a way it usually is not: the file this gates
# tells its reader not to restate values at all, so a gate that pushed toward
# completeness would enforce the opposite of the rule. Three cases hold that.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/rules-drift"
	ROOT="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$ROOT/rules" "$ROOT/tasks"
	# `git ls-files` is the file list, so the fixture is a real repo — the same
	# tracked-not-globbed discipline `contract-drift` uses for its surface.
	git -C "$ROOT" init -q
	git -C "$ROOT" config user.email t@example.com
	git -C "$ROOT" config user.name t
	export RULES_DRIFT_ROOT="$ROOT" \
		RULES_DRIFT_RULES="rules" \
		RULES_DRIFT_MEMORIES="memories" \
		RULES_DRIFT_SETTINGS="settings.json" \
		RULES_DRIFT_TASKS="tasks"
	printf '{"hooks":{"SessionStart":[{"hooks":[{"command":"mise run -q contract-drift"}]}]}}\n' >"$ROOT/settings.json"
	printf '#!/usr/bin/env bash\nmax_laps="${LAND_MAX_LAPS:-2}"\n' >"$ROOT/tasks/land"
}

# `rules <body>` — one tracked rules file, then everything staged so ls-files
# sees it.
rules() {
	printf '%s\n' "$1" >"$ROOT/rules/toolchain.md"
	git -C "$ROOT" add -A
}

# `memory <relative-path> <body>` — one tracked memory, at whatever depth the
# case needs. Separate from `rules()` because the point of these cases is the
# SECOND surface, and sharing a helper would hide which root found the file.
memory() {
	mkdir -p "$ROOT/memories/$(dirname "$1")"
	printf '%s\n' "$2" >"$ROOT/memories/$1"
	git -C "$ROOT" add -A
}

@test "a restated default that disagrees with the mechanism fails, and names both values" {
	# The measured drift: the runaway lap backstop quoted as 8 where `land`
	# defaults to 2 — a 4x error in the number an agent consults when deciding
	# whether a landing is looping.
	rules 'The lap count is bounded: `LAND_MAX_LAPS` (8) is a runaway backstop.'
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"rules/toolchain.md:1 (LAND_MAX_LAPS)"* ]]
	[[ "$output" == *"says 8"* ]]
	[[ "$output" == *"defaults to 2"* ]]
}

@test "the same claim with the right value passes" {
	rules 'The lap count is bounded: `LAND_MAX_LAPS` (2) is a runaway backstop.'
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"1 restated default(s)"* ]]
}

@test "PROSE THAT NAMES A KNOB WITHOUT QUOTING A VALUE PASSES" {
	# The case that keeps the gate from inverting the rule it enforces. The file
	# must stay able to name `LAND_MAX_LAPS` and send the reader to the task for
	# its value — which is what the rule actually asks for.
	rules 'The lap count is bounded by `LAND_MAX_LAPS`; the task header is the authority.'
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"0 restated default(s)"* ]]
}

@test "a variable no mechanism defaults is not judged" {
	# There is nothing to disagree with. Inventing a violation here would be the
	# same completeness pressure, arriving from the other side.
	rules 'A knob nothing reads: `NEVER_READ_ANYWHERE` (7).'
	run "$GATE"
	[ "$status" -eq 0 ]
}

# --- predicate 2: a named hook event must be wired ----------------------------

@test "a paragraph claiming a task runs on an unwired event fails, and names the event" {
	# The second measured drift, and the more expensive one: `contract-drift` is
	# what tells a session its instruction surface changed under it, and the file
	# that would tell you it only fires at session start said the opposite.
	rules 'So `contract-drift` runs on `SessionStart` and on `PostToolBatch`, whose
documented additionalContext fires once per batch.'
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"(PostToolBatch)"* ]]
	[[ "$output" == *"does not wire"* ]]
}

@test "the pointer names the line the event is on, not the paragraph's first line" {
	# A bullet list wraps into one paragraph here, and its start can sit dozens of
	# lines above the token — a pointer to the wrong line is a pointer a reader
	# has to search from.
	rules 'So `contract-drift` runs on `SessionStart`,
seeding the snapshot before any tool does,
and on `PostToolBatch` as well.'
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"toolchain.md:3 (PostToolBatch)"* ]]
}

@test "the same paragraph naming only wired events passes" {
	rules 'So `contract-drift` runs on `SessionStart`, seeding the snapshot first.'
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"1 named hook event(s)"* ]]
}

@test "A PARAGRAPH SAYING AN EVENT IS ABSENT IS NOT A CLAIM THAT IT RUNS" {
	# CLOUD-461 records that the `PostToolBatch` entry stays absent until `batten
	# hook` grows an advisory channel. A sentence saying exactly that is correct
	# prose, and a gate keyed on the event NAME rather than on the assertion would
	# forbid the repo from writing down its own accepted gap.
	rules 'It runs on `SessionStart`. The per-batch entry it was designed for stays
absent, and CLOUD-461 is why: `batten hook` has no advisory channel, so a
once-per-batch `PostToolBatch` reminder has nowhere to land.'
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "an event named outside any runs-on paragraph is not judged" {
	rules 'The `PostToolBatch` event has documented additionalContext semantics.'
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"0 named hook event(s)"* ]]
}

@test "a backticked word that is not an event is left alone" {
	# The gate judges event names. It cannot be made to judge every capitalised
	# token that happens to sit in a runs-on paragraph.
	rules 'It runs on `SessionStart`, wrapping `PostToolThing` which is not an event.'
	run "$GATE"
	[ "$status" -eq 0 ]
}

# --- the walk itself ----------------------------------------------------------

@test "a rules file with no restated value does not stop the walk at the drifted one" {
	# Under `pipefail` a grep that matches nothing fails its pipeline, and under
	# `set -e` that aborts the loop — reporting a clean tree by dying quietly.
	# commits.md sorts before toolchain.md, so this is the real ordering.
	printf 'Nothing restated here at all.\n' >"$ROOT/rules/commits.md"
	rules 'The lap count: `LAND_MAX_LAPS` (8).'
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"LAND_MAX_LAPS"* ]]
}

@test "an empty rules directory is refused rather than silently green" {
	# A gate that cannot fire must not be indistinguishable from one that found
	# nothing — this repo has been bitten by that twice.
	rm -f "$ROOT"/rules/*.md
	git -C "$ROOT" add -A
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"no tracked markdown"* ]]
}

@test "unreadable wiring is refused rather than reporting every event unwired" {
	rules 'It runs on `SessionStart`.'
	printf 'not json\n' >"$ROOT/settings.json"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"no hook events readable"* ]]
}

@test "output is pointer-only — the sentence is never echoed" {
	# Non-negotiable 4. A rules file quotes command lines and env names, so the
	# finding carries path:line, the name, and the two values, and nothing else.
	rules 'The lap count is bounded: `LAND_MAX_LAPS` (8) is a runaway backstop.'
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" != *"runaway backstop"* ]]
}

# --- the real tree ------------------------------------------------------------

@test "A DRIFTED VALUE IN A MEMORY FAILS — the second prose surface is walked" {
	# CLOUD-770. The memory tree is the largest prose surface in the repo and was
	# subject to neither predicate; `memories-check` gates the graph's edges and
	# deliberately not its content.
	rules 'The lap count is bounded by `LAND_MAX_LAPS`.'
	memory "core.md" 'The runaway backstop `LAND_MAX_LAPS` (8) bounds a landing.'
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"memories/core.md:1 (LAND_MAX_LAPS)"* ]]
	[[ "$output" == *"says 8"* ]]
	[[ "$output" == *"defaults to 2"* ]]
}

@test "A MEMORY IN A SUBDIRECTORY IS REACHED — proven, not assumed from the glob" {
	# The assertion that exists because the reasoning was wrong once: CLOUD-770's
	# issue body claimed a `<root>/*.md` pathspec does not recurse, and that a
	# `workflow/` memory was therefore never read. It does recurse. This case is
	# what makes the walk's depth a fact rather than a belief about fnmatch.
	rules 'The lap count is bounded by `LAND_MAX_LAPS`.'
	memory "workflow/board-states.md" 'The backstop `LAND_MAX_LAPS` (8) bounds it.'
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"memories/workflow/board-states.md:1 (LAND_MAX_LAPS)"* ]]
}

@test "a memory naming a knob without quoting a value passes" {
	# The false-positive direction, on the new surface. A memory must stay able to
	# point at the owner — that is the form CLOUD-769 converted the budget to.
	rules 'The lap count is bounded by `LAND_MAX_LAPS`.'
	memory "workflow/landing-loop.md" 'Laps are bounded by `LAND_MAX_LAPS`; the task header is the authority.'
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "AN ABSENT MEMORY TREE IS NOT A FAILURE, unlike an absent rules directory" {
	# The asymmetry is deliberate and this pins it. A missing rules directory means
	# a wrong path in a repo that must have one; a consumer repo with no memories
	# is ordinary, and turning red for it would be a gate nobody can adopt.
	rules 'The lap count is bounded: `LAND_MAX_LAPS` (2) is a runaway backstop.'
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"1 restated default(s)"* ]]
}

@test "this repository's own rules files agree with their mechanisms" {
	unset RULES_DRIFT_ROOT RULES_DRIFT_RULES RULES_DRIFT_SETTINGS RULES_DRIFT_TASKS
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "the gate is wired into the hk gate, so a drift reddens a commit" {
	# Non-negotiable 2: a rule without a runnable gate is half a change, and a
	# gate nothing runs is the same half.
	run grep -c 'mise run rules-drift' "$BATS_TEST_DIRNAME/../hk.pkl"
	[ "$output" = "1" ]
}
