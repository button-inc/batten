#!/usr/bin/env bats
# subject: mise-tasks/skill-check.sh
# skill-check's decision table (CLOUD-213): the shipped skill's budget, its verb
# vocabulary, and the exit table it restates, as exit codes.
#
# Every case builds a MINIMAL skill rather than copying the real one. A fixture
# that starts as the real document tests the document; these test the gate, and
# the difference shows up the day the real skill is edited — a suite built on a
# copy of it goes red for reasons that have nothing to do with the predicate
# under test.
#
# The binary is read once, not per case: `batten spec` and `--help` are the two
# authorities the gate consults, and building them here would put a cargo
# invocation inside every assertion.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/skill-check.sh"
	ROOT="$BATS_TEST_TMPDIR/repo"
	SKILL="$ROOT/skills/batten/SKILL.md"
	VENDOR="$ROOT/.claude/skills/batten/SKILL.md"
	mkdir -p "$ROOT/skills/batten" "$ROOT/.claude/skills/batten"
	git init -q "$ROOT"
	export SKILL_CHECK_ROOT="$ROOT"
	# Prefer an already-built binary; fall back to building one once.
	if [ -z "${BATTEN_BIN:-}" ]; then
		BATTEN_BIN="$BATS_TEST_DIRNAME/../target/debug/batten"
		[ -x "$BATTEN_BIN" ] || BATTEN_BIN=""
	fi
	export BATTEN_BIN
	write_skill
	link_vendor
}

# A minimal skill that satisfies every predicate: one real verb, the whole exit
# table as the binary renders it.
write_skill() {
	cat >"$SKILL" <<'EOF'
# Skill

Run `batten check` and read the status.

| Code | Meaning                                                 |
| ---- | ------------------------------------------------------- |
| `0`  | clean — nothing to report; a mediated call is allowed   |
| `1`  | config or usage error — fail loud, do not block         |
| `2`  | policy verdict — a violation, or a mediated call denied |
| `3`  | internal error — fail loud, do not block                |
EOF
}

link_vendor() {
	ln -sfn ../../../skills/batten/SKILL.md "$VENDOR"
}

@test "a skill inside budget, naming only declared verbs, exits 0" {
	run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"names only declared verbs"* ]]
}

@test "a verb the binary does not declare is reported with a file:line pointer" {
	echo 'then run `batten nonesuch`' >>"$SKILL"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"skill-unknown-verb (nonesuch)"* ]]
}

@test "a subcommand the binary does not declare is caught, not just a bare verb" {
	# The trap this closes: `receipt` IS a declared row, so a gate that merely
	# shortened the phrase until something resolved would accept `receipt invent`
	# by falling back to its parent — fiction hiding behind a real noun.
	echo 'try `batten receipt invent`' >>"$SKILL"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"skill-unknown-subcommand (receipt invent)"* ]]
}

@test "a positional argument does not read as an undeclared subcommand" {
	# `receipt status verify` is `receipt status` plus a positional. The gate
	# shortens the phrase until it resolves; without that, every documented
	# invocation carrying an argument would be reported as fiction.
	echo 'run `batten receipt status verify`' >>"$SKILL"
	run "$CHECK"
	[ "$status" -eq 0 ]
}

@test "flags do not read as subcommands" {
	echo 'run `batten check -J --silent`' >>"$SKILL"
	run "$CHECK"
	[ "$status" -eq 0 ]
}

@test "a console block is judged as well as an inline span" {
	printf '\n```console\n$ batten alsofake\n```\n' >>"$SKILL"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"skill-unknown-verb (alsofake)"* ]]
}

@test "prose naming the product is not read as a verb" {
	# "Batten is a completion gate" and "batten.toml" are English and a
	# filename. A scan loose enough to read those as commands would report the
	# prose, which is the false-positive rate that gets a gate bypassed.
	printf '\nBatten is a gate, configured by batten.toml in the repo root.\n' >>"$SKILL"
	run "$CHECK"
	[ "$status" -eq 0 ]
}

@test "a skill over the line budget is refused, and the count is named" {
	for _ in $(seq 1 300); do echo "filler" >>"$SKILL"; done
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"skill-over-budget"* ]]
}

@test "the budget is a boundary, not a suggestion" {
	# Exactly at the ceiling passes; one past it does not.
	SKILL_MAX_LINES=9 run "$CHECK"
	[ "$status" -eq 1 ]
	SKILL_MAX_LINES=10 run "$CHECK"
	[ "$status" -eq 0 ]
}

@test "an exit meaning that drifts from the binary's rendering is caught" {
	sed -i 's/internal error — fail loud, do not block/internal oopsie/' "$SKILL"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"skill-exit-meaning-missing (3)"* ]]
}

@test "a code the skill never names is caught even when its meaning is present" {
	sed -i 's/| `2`  |/| two  |/' "$SKILL"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"skill-exit-code-unnamed (2)"* ]]
}

@test "a vendor path that is a copy rather than a symlink is refused" {
	rm "$VENDOR"
	cp "$SKILL" "$VENDOR"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"skill-vendor-path-not-a-symlink"* ]]
}

@test "a symlink pointing at some other file is refused" {
	echo "decoy" >"$ROOT/skills/batten/OTHER.md"
	ln -sfn ../../../skills/batten/OTHER.md "$VENDOR"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"skill-vendor-path-resolves-elsewhere"* ]]
}

@test "a missing skill is exit 2 — could not look, not a clean tree" {
	rm "$SKILL"
	run "$CHECK"
	[ "$status" -eq 2 ]
}

@test "an unreadable spec is exit 2, never a pass over an unjudged vocabulary" {
	BATTEN_BIN=/nonexistent/batten run "$CHECK"
	[ "$status" -eq 2 ]
}

@test "the repo as it stands passes" {
	unset SKILL_CHECK_ROOT
	run "$CHECK"
	[ "$status" -eq 0 ]
}

@test "the gate is wired: hk.pkl declares a step that runs this task" {
	run grep -q 'mise run skill-check' "$BATS_TEST_DIRNAME/../hk.pkl"
	[ "$status" -eq 0 ]
}

# --- every skill, not just the default one (CLOUD-864) -------------------------
#
# The hk step globs `skills/**` and invokes the task with no arguments, so before
# the discovery loop a SECOND skill fired the step and was then never read. These
# three cases are the discriminating set: the first shows a second skill's
# violation is now seen, the second shows discovery does not depend on the file
# being tracked (the defect the first version of the loop shipped with), and the
# third shows a well-formed second skill is still clean — without it, a loop that
# reported on everything would satisfy the other two.

second_skill() { # a minimal skill that names no batten verb, as a real one would not
	mkdir -p "$ROOT/skills/other" "$ROOT/.claude/skills/other"
	printf '# Other\n\nNothing about the binary here.\n' >"$ROOT/skills/other/SKILL.md"
}

@test "a second skill with no vendor symlink is a violation" {
	second_skill
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"skills/other/SKILL.md:0 skill-vendor-path-not-a-symlink"* ]]
}

@test "a second skill is discovered while UNTRACKED — presence is the predicate" {
	# `git ls-files` returns nothing here: the fixture repo is `git init`-ed and
	# nothing is ever staged. A git-sourced discovery passes this case, which is
	# exactly how the first version of the loop shipped a gate that skipped the
	# newest skill in the tree.
	second_skill
	run git -C "$ROOT" ls-files 'skills/*/SKILL.md'
	[ -z "$output" ]
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"skills/other/SKILL.md"* ]]
}

@test "a well-formed second skill leaves the run clean" {
	second_skill
	ln -sfn ../../../skills/other/SKILL.md "$ROOT/.claude/skills/other/SKILL.md"
	run "$CHECK"
	[ "$status" -eq 0 ]
}

@test "a second skill over budget is reported against its own path" {
	second_skill
	ln -sfn ../../../skills/other/SKILL.md "$ROOT/.claude/skills/other/SKILL.md"
	SKILL_MAX_LINES=1 run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"skills/other/SKILL.md:"* ]]
	[[ "$output" == *"skill-over-budget"* ]]
}
