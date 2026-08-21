#!/usr/bin/env bats
# subject: mise-tasks/hook-matcher-check
# CLOUD-471. A `[[verb]]` naming a tool the `PreToolUse` matcher does not deliver
# is dead config: the row loads, `verbs::validate` accepts it, and the host never
# spawns the hook, so the symptom is an allow indistinguishable from a pass.
#
# Every case drives the real script against fixture files, because the gate's
# whole job is reading two committed files and there is nothing else to stub. The
# cases that matter are the ones where a coverage check can pass for the wrong
# reason — a parse that found nothing, a match-all read as a gap, a shell program
# judged against its own name — not the happy path.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/hook-matcher-check"
	SETTINGS="$BATS_TEST_TMPDIR/settings.json"
	CONFIG="$BATS_TEST_TMPDIR/batten.toml"
	# The engine's own declaration of which tools write. Read from the real
	# source by default; a fixture copy keeps the suite from re-typing the set
	# and from breaking when a host adapter legitimately gains a spelling.
	SOURCE="$BATS_TEST_DIRNAME/../crates/batten/src/hook.rs"
}

# A settings file whose one PreToolUse entry invokes the engine through the
# committed launcher, with the given matcher.
wired_with() {
	printf '{"hooks":{"PreToolUse":[{"matcher":"%s","hooks":[{"type":"command","command":"$CLAUDE_PROJECT_DIR/.claude/hooks/batten-hook.sh"}]}]}}\n' \
		"$1" >"$SETTINGS"
}

# The same, with no `matcher` key at all — which the host reads as match-all.
wired_with_no_matcher() {
	printf '{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"$CLAUDE_PROJECT_DIR/.claude/hooks/batten-hook.sh"}]}]}}\n' \
		>"$SETTINGS"
}

# A batten.toml declaring exactly the named verbs and nothing else this gate
# reads.
declares() {
	: >"$CONFIG"
	local v
	for v in "$@"; do
		printf '[[verb]]\nverb = "%s"\neffect = "write"\n\n' "$v" >>"$CONFIG"
	done
}

gate() { run "$GATE" "$SETTINGS" "$CONFIG" "$SOURCE"; }

@test "the committed tree is covered" {
	# The self-test, run against the real pair with no arguments at all. It is
	# what makes every fixture case below evidence about this repository rather
	# than about a tmpdir.
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "a tool-name verb outside the matcher is caught, and named with the token it needed" {
	wired_with "Bash"
	declares Write

	gate
	[ "$status" -eq 2 ]
	[[ "$output" == *"\`Write\` needs \`Write\`"* ]]
	# Pointer: the line that declares it, never a byte of either file.
	[[ "$output" == *"$CONFIG:2:"* ]]
	[[ "$output" == *"1 of 1"* ]]
}

@test "a shell-program verb is satisfied by Bash alone — the route decides the token" {
	# The negative self-test, and the one that makes this gate discriminate.
	# `rm` never arrives as `envelope.tool`; it arrives inside `envelope.command`,
	# which only a Bash call carries. A check that demanded `rm` in the matcher
	# would be a different and wrong rule, and it would fail the committed tree.
	wired_with "Bash"
	declares rm mv ">" ">>" tee sponge truncate shred sed cp install git

	gate
	[ "$status" -eq 0 ]
}

@test "a shell-program verb with no Bash in the matcher is uncovered too" {
	# The same silence from the other end: the row is equally undeliverable, and
	# the report names the token it needed rather than the verb twice.
	wired_with "Write|Edit"
	declares rm

	gate
	[ "$status" -eq 2 ]
	[[ "$output" == *"\`rm\` needs \`Bash\`"* ]]
}

@test "an absent matcher is coverage, not a gap" {
	# The host reads it as match-all, which is broader than any enumeration.
	# Reporting it would fail a wiring that gates strictly more than this gate
	# asks for — the false positive that gets a gate switched off.
	wired_with_no_matcher
	declares Write Edit MultiEdit NotebookEdit rm

	gate
	[ "$status" -eq 0 ]
}

@test "an empty matcher is coverage, and so is a literal star" {
	wired_with ""
	declares Write rm
	gate
	[ "$status" -eq 0 ]

	wired_with "*"
	declares Write rm
	gate
	[ "$status" -eq 0 ]
}

@test "the matcher is read as a regex, so an alternation covers each of its arms" {
	wired_with "Bash|Write|Edit|MultiEdit|NotebookEdit"
	declares Write Edit MultiEdit NotebookEdit rm

	gate
	[ "$status" -eq 0 ]
}

@test "coverage is unanchored, matching the host — Edit delivers MultiEdit" {
	# Measured against the host's own reading rather than a tidier one: it tests
	# the matcher as a regular expression against the tool name, so `Edit` does
	# deliver a `MultiEdit` call. An anchored gate would report a gap that is not
	# there, which is the direction a coverage check must not fail in.
	wired_with "Edit"
	declares MultiEdit

	gate
	[ "$status" -eq 0 ]
}

@test "an entry that does not invoke the engine lends no coverage" {
	# The other PreToolUse entries in the committed file register `mise-tasks/*`
	# guards with their own matchers. Reading one of those as coverage would be
	# this gate answering about a process the engine never runs.
	printf '{"hooks":{"PreToolUse":[{"matcher":"Bash|Write","hooks":[{"type":"command","command":"$CLAUDE_PROJECT_DIR/mise-tasks/issue-read-guard"}]}]}}\n' >"$SETTINGS"
	declares Write

	gate
	[ "$status" -eq 2 ]
	[[ "$output" == *"0 PreToolUse entries invoke the engine"* ]]
}

@test "a direct 'batten hook' registration counts, not only the launcher" {
	# A consumer that drops this repo's launcher indirection is still wired, and
	# a gate keyed on the launcher's filename alone would call that no coverage.
	printf '{"hooks":{"PreToolUse":[{"matcher":"Bash|Write","hooks":[{"type":"command","command":"batten hook --harness claude-code"}]}]}}\n' >"$SETTINGS"
	declares Write rm

	gate
	[ "$status" -eq 0 ]
}

@test "a config declaring no verbs is nothing to cover, and says so" {
	wired_with "Bash"
	: >"$CONFIG"

	gate
	[ "$status" -eq 0 ]
	[[ "$output" == *"declares no [[verb]] rows"* ]]
}

@test "a [[verb]] table this gate cannot parse is could-not-look, never a pass" {
	# The anti-vacuity term. A parse that found nothing is not a table with
	# nothing in it, and passing on it is the vacuous green a coverage check can
	# most easily produce.
	wired_with "Bash"
	printf '[[verb]]\nname = "rm"\neffect = "write"\n' >"$CONFIG"

	gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"a parse that found nothing is not a table with nothing in it"* ]]
}

@test "an engine source with no readable write_tools arm is could-not-look" {
	# The same anti-vacuity term on the other input. With no tool names read,
	# every verb would route to `Bash` and the tool half of the predicate would
	# silently stop being asked — green, and checking exactly nothing.
	wired_with "Bash"
	declares Write
	printf 'fn something_else() {}\n' >"$BATS_TEST_TMPDIR/hook.rs"

	run "$GATE" "$SETTINGS" "$CONFIG" "$BATS_TEST_TMPDIR/hook.rs"
	[ "$status" -eq 1 ]
	[[ "$output" == *"write_tools()"* ]]
}

@test "a neighbouring harness arm is not read as this host's tool set" {
	# `Harness::GeminiCli` declares `WriteFile`, which Claude Code does not have.
	# A parse that ran past its own arm would call a `WriteFile` row a tool name
	# and demand it in the matcher — a gap invented out of another host's facts.
	cat >"$BATS_TEST_TMPDIR/hook.rs" <<'RUST'
    pub const fn write_tools(self) -> &'static [&'static str] {
        match self {
            Harness::ClaudeCode | Harness::CodexCli => {
                &["Write", "Edit"]
            }
            Harness::GeminiCli => &["WriteFile", "Edit"],
        }
    }
RUST
	wired_with "Bash"
	declares WriteFile

	run "$GATE" "$SETTINGS" "$CONFIG" "$BATS_TEST_TMPDIR/hook.rs"
	[ "$status" -eq 0 ]
}

@test "a settings file that cannot be read fails open, loudly, and never as a verdict" {
	# Never a `2`: "I could not look" must not reach a reader as "the wiring is
	# wrong". That file's validity is `pkl-check`'s object, not this gate's.
	declares Write
	printf 'not json at all\n' >"$SETTINGS"

	gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"not readable JSON"* ]]
}

@test "a settings file that does not exist fails open, loudly" {
	declares Write

	run "$GATE" "$BATS_TEST_TMPDIR/absent.json" "$CONFIG" "$SOURCE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"does not exist"* ]]
}

@test "a matcher that is not a compilable regex is could-not-look" {
	wired_with "Bash|Write|["
	declares Write

	gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"coverage cannot be decided"* ]]
}

@test "one front-end declared under two subcommands is one coverage question" {
	# `git mv` and `git rm` are two rows and two remedies, and exactly one
	# question about whether the host delivers `Bash`. Reporting it twice would
	# make the count say more rows are broken than are.
	wired_with "Write"
	printf '[[verb]]\nverb = "git"\nsubcommand = "mv"\neffect = "destructive"\n\n' >"$CONFIG"
	printf '[[verb]]\nverb = "git"\nsubcommand = "rm"\neffect = "destructive"\n' >>"$CONFIG"

	gate
	[ "$status" -eq 2 ]
	[[ "$output" == *"1 of 1"* ]]
}
