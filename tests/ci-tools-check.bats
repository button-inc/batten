#!/usr/bin/env bats
# subject: mise-tasks/ci-tools-check
# The gate that ships with the narrowed CI tool sets (AGENTS.md non-negotiable
# 2). ci.yml installs a per-job `install_args` list instead of the whole
# toolchain, which is the single biggest CI speed-up available — and it buys
# that with a second place tool names are written down.
#
# The failure it exists to catch is silent: `mise install` does not error on an
# unknown tool name, so a rename in mise.toml that misses ci.yml produces a job
# that installs one fewer tool and dies much later as "command not found" in
# whichever step needed it. Nothing before this check turns that into a
# non-zero exit at the moment the drift is introduced.
#
# Driven against fixture files rather than the real pair, so the suite can hold
# drift the committed tree must never contain. The committed pair is asserted
# too — that one is the regression test for the workflow itself.

setup() {
	# tests/helpers.bash: `sed_i` / `run_timeout`, standing in for GNU
	# tools a stock macOS does not ship (CLOUD-282).
	load helpers
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/ci-tools-check"
	WORKFLOW="$BATS_TEST_TMPDIR/ci.yml"
	CONFIG="$BATS_TEST_TMPDIR/mise.toml"

	cat >"$CONFIG" <<-'EOF'
		[tools]
		rust = { version = "1.85.0", components = "rustfmt,clippy" }
		hk = "1.54.0"                        # a trailing comment
		"aqua:koalaman/shellcheck" = "0.11.0"
		"npm:prettier" = "3.6.2"
		zig = "0.16"

		[env]
		zig = "not-a-tool"
	EOF

	cat >"$WORKFLOW" <<-'EOF'
		jobs:
		  ci:
		    steps:
		      - uses: jdx/mise-action@abc
		        with:
		          install_args: rust hk aqua:koalaman/shellcheck npm:prettier
		  darwin-link:
		    steps:
		      - uses: jdx/mise-action@abc
		        with:
		          install_args: rust zig
	EOF
}

# --- the committed tree ------------------------------------------------------

@test "the real ci.yml and mise.toml agree" {
	run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"are declared in"* ]]
}

# --- pass --------------------------------------------------------------------

@test "every requested tool declared is a pass" {
	run "$CHECK" "$WORKFLOW" "$CONFIG"
	[ "$status" -eq 0 ]
}

@test "quoted and backend-prefixed names resolve" {
	# aqua:/npm: keys are quoted in mise.toml and unquoted in install_args; the
	# check has to strip the quotes or every backend tool reads as drift.
	run "$CHECK" "$WORKFLOW" "$CONFIG"
	[ "$status" -eq 0 ]
	# 5, not 6: `rust` appears in both jobs and the count is of unique tools.
	[[ "$output" == *"all 5 tools"* ]]
}

@test "a tool declared but never installed by CI is not a failure" {
	# mise.toml is the dev superset on purpose: gh, release-plz, serena and
	# friends exist for local and release work. Only the reverse direction —
	# CI naming something undeclared — is drift.
	printf '"aqua:cli/cli" = "2.97"\n' >>"$CONFIG"
	run "$CHECK" "$WORKFLOW" "$CONFIG"
	[ "$status" -eq 0 ]
}

# --- fail: the drift this gate exists for ------------------------------------

@test "a renamed tool leaves install_args naming something undeclared" {
	sed_i 's/^zig = .*/zig-lang = "0.16"/' "$CONFIG"
	run "$CHECK" "$WORKFLOW" "$CONFIG"
	[ "$status" -eq 1 ]
	[[ "$output" == *"::error::"* ]]
	[[ "$output" == *"zig"* ]]
}

@test "the error names the tool and both files, not the file contents" {
	# Output is a pointer, never a payload (non-negotiable 4).
	sed_i 's|^"npm:prettier" = .*||' "$CONFIG"
	run "$CHECK" "$WORKFLOW" "$CONFIG"
	[ "$status" -eq 1 ]
	[[ "$output" == *"npm:prettier"* ]]
	[[ "$output" == *"ci.yml"* ]]
	[[ "$output" == *"mise.toml"* ]]
	[[ "$output" != *"3.6.2"* ]]
}

@test "a key from another table does not count as declared" {
	# `zig` appears under [env] too; only the [tools] table declares tools.
	sed_i 's/^zig = "0.16"$//' "$CONFIG"
	run "$CHECK" "$WORKFLOW" "$CONFIG"
	[ "$status" -eq 1 ]
	[[ "$output" == *"zig"* ]]
}

# --- fail: the check cannot silently pass on nothing --------------------------

@test "a workflow with no install_args lists fails rather than passing" {
	# The lists disappearing means CI went back to installing everything. A
	# check that reads zero tools and exits 0 would call that green.
	printf 'jobs:\n  ci:\n    steps:\n      - run: mise run ci\n' >"$WORKFLOW"
	run "$CHECK" "$WORKFLOW" "$CONFIG"
	[ "$status" -eq 1 ]
	[[ "$output" == *"install the whole toolchain"* ]]
}

@test "a config with no [tools] table fails rather than passing" {
	printf '[env]\nFOO = "bar"\n' >"$CONFIG"
	run "$CHECK" "$WORKFLOW" "$CONFIG"
	[ "$status" -eq 1 ]
	[[ "$output" == *"no [tools] entries"* ]]
}

@test "a missing file is an error, not a pass" {
	run "$CHECK" "$BATS_TEST_TMPDIR/nope.yml" "$CONFIG"
	[ "$status" -eq 1 ]
	[[ "$output" == *"not found"* ]]
}

# --- the absence direction (CLOUD-812) ---------------------------------------
#
# Everything above judges the names IN a list, so a workflow declaring no list
# has nothing to judge and passes. That is not a hole in the predicate but in
# the trigger, and it is why `commit-lint.yml` and `zizmor.yml` installed all 28
# pinned tools on every PR push for as long as they did with nothing red.
#
# These fixtures live in the tmpdir and carry a `pull_request:` trigger, which
# is what brings them into the second pass's scope; the suite's other fixtures
# have no trigger and are therefore untouched by it.

pr_workflow() {
	# $1: install_args line (empty for none) — $2: the auto-install env block.
	cat >"$BATS_TEST_TMPDIR/pr.yml" <<-EOF
		on:
		  pull_request:
		env:
		  MISE_LOCKFILE: "true"
		$2
		jobs:
		  lint:
		    steps:
		      - uses: jdx/mise-action@abc
		$1
		      - run: mise run lint
	EOF
}

binding_env() {
	printf '  MISE_TASK_RUN_AUTO_INSTALL: "false"\n  MISE_EXEC_AUTO_INSTALL: "false"'
}

@test "a PR workflow with a narrowed, binding list passes" {
	pr_workflow "        with:
          install_args: rust" "$(binding_env)"
	run "$CHECK" "$WORKFLOW" "$CONFIG" "$BATS_TEST_TMPDIR"
	[ "$status" -eq 0 ]
}

@test "a PR workflow running mise-action with no install_args fails" {
	# The case that passes against the gate as it stood: nothing to judge is
	# not the same as nothing wrong, and this is the whole of CLOUD-812.
	pr_workflow "" "$(binding_env)"
	run "$CHECK" "$WORKFLOW" "$CONFIG" "$BATS_TEST_TMPDIR"
	[ "$status" -eq 1 ]
	[[ "$output" == *"declares 0 install_args list(s)"* ]]
	[[ "$output" == *"pr.yml"* ]]
}

@test "a declared list without the auto-install variables fails" {
	# The non-binding case CLOUD-180 measured: mise re-installs the rest at task
	# time, so the list moves the cost instead of removing it and the workflow
	# reads as fixed. Indistinguishable from a fix without this row.
	pr_workflow "        with:
          install_args: rust" ""
	run "$CHECK" "$WORKFLOW" "$CONFIG" "$BATS_TEST_TMPDIR"
	[ "$status" -eq 1 ]
	[[ "$output" == *"decides nothing"* ]]
}

@test "an auto-install variable set to true is not binding either" {
	# A substring search for the variable name would call this fixed. The
	# predicate is the assignment and its value, not the mention.
	pr_workflow "        with:
          install_args: rust" '  MISE_TASK_RUN_AUTO_INSTALL: "false"
  MISE_EXEC_AUTO_INSTALL: "true"'
	run "$CHECK" "$WORKFLOW" "$CONFIG" "$BATS_TEST_TMPDIR"
	[ "$status" -eq 1 ]
	[[ "$output" == *"decides nothing"* ]]
}

@test "a workflow with no pull_request trigger is out of scope" {
	# Scheduled and workflow_run lanes are deliberately not judged here: they
	# are not on the PR path and widening to them is a different cost decision.
	cat >"$BATS_TEST_TMPDIR/pr.yml" <<-'EOF'
		on:
		  schedule:
		    - cron: "0 * * * *"
		jobs:
		  nightly:
		    steps:
		      - uses: jdx/mise-action@abc
		      - run: mise run drift
	EOF
	run "$CHECK" "$WORKFLOW" "$CONFIG" "$BATS_TEST_TMPDIR"
	[ "$status" -eq 0 ]
}

@test "a PR workflow that never runs mise-action is out of scope" {
	# test.yml is exactly this shape: a pull_request trigger and no toolchain.
	cat >"$BATS_TEST_TMPDIR/pr.yml" <<-'EOF'
		on:
		  pull_request:
		jobs:
		  noop:
		    steps:
		      - run: echo hi
	EOF
	run "$CHECK" "$WORKFLOW" "$CONFIG" "$BATS_TEST_TMPDIR"
	[ "$status" -eq 0 ]
}

@test "the committed PR workflows all carry a binding list" {
	# The regression test for the two workflows CLOUD-180's scope missed.
	run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"carries a binding install_args list"* ]]
}

@test "a tool name that resolves nowhere fails in a PR workflow other than the first argument" {
	# CLOUD-398 moved four jobs into rust.yml with their install_args, so the
	# single-file name pass stopped covering them. Same predicate, every file.
	pr_workflow "        with:
          install_args: rustlang" "$(binding_env)"
	run "$CHECK" "$WORKFLOW" "$CONFIG" "$BATS_TEST_TMPDIR"
	[ "$status" -eq 1 ]
	[[ "$output" == *"rustlang"* ]]
	[[ "$output" == *"command not found"* ]]
}
